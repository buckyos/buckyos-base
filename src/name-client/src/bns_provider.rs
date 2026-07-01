/*
实现基于bns合约的NsProvider实现
从接口上是对https_provider的封装
1. 通过输入machine_config的web3网桥配置，得到正确的查询URL
2. 只处理 did method是bns和dev的请求，其它一概返回不支持

resolve_published_state 不是 https_provider 的薄封装：它有自己独立的状态解析逻辑
（见 BnsResolveTransport），只有普通的候选文档拉取（query_did / self-signed candidate）
才复用 https_provider。参见 doc/resolve_did重构.md 第 11.3 节。
*/

use crate::{
    DocumentBody, DocumentRef, DocumentStatus, HttpsProvider, MethodMatcher, NameInfo, NameStatus,
    NsProvider, OwnerSource, PublishedState, RecordType, ResolverCaps,
};
use async_trait::async_trait;
use buckyos_kit::BuckyOSMachineConfig;
use log::info;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

/// BNS 权威发布状态查询的传输层抽象。
///
/// 现状（见 doc/resolve_did重构_TODO.md Phase 3 的开放问题）：bns-server 会实现一个
/// 符合 did-resolver 协议的 did-document 查询接口，但这一版扩展了语义（
/// document_status / effective_owner / authority_seq 等字段），具体的公共 HTTP 端点
/// 还没有最终定稿。因此这里先把 `resolve_published_state` 的状态机映射逻辑和接口定下来，
/// 用可注入的 mock transport 跑通单测；等真实端点确定后，只需要新写一个实现了
/// `BnsResolveTransport` 的类型并在构造 `BnsProvider` 时传入，不需要改动映射逻辑。
///
/// 不能为了"能跑通"就让默认实现返回一个伪造的 Active/Missing 状态——真实端点接入前，
/// `BnsProvider::new()` 不配置 transport，`resolve_published_state` 老实返回 `Ok(None)`，
/// 上层会按既有行为退回到 self-signed candidate 路径。
#[async_trait]
pub trait BnsResolveTransport: Send + Sync {
    async fn resolve_document(
        &self,
        canonical_name: &str,
        doc_type: &str,
    ) -> NSResult<BnsResolveResponse>;
}

/// 权威源对 `resolveDocument(name, docType)` 查询的原始响应，比 `PublishedState` 更贴近
/// wire format，方便未来替换成真实 HTTP/RPC 响应时只改这一层的解析代码。
#[derive(Debug, Clone)]
pub enum BnsResolveResponse {
    Active(BnsActiveRecord),
    Expired(BnsActiveRecord),
    Missing,
    Revoked,
    Tombstoned,
    Migrated { target: DID },
    /// 权威源明确表示它对该 (name, doc_type) 没有意见（不是负状态，只是没有配置这个
    /// doc_type），不应映射成 Missing。
    NotApplicable,
}

#[derive(Debug, Clone, Default)]
pub struct BnsActiveRecord {
    pub document_ref: Option<DocumentRef>,
    pub version: Option<u64>,
    pub previous_version: Option<u64>,
    pub next_version: Option<u64>,
    pub effective_owner: Option<DID>,
    pub authority_root: Option<String>,
    pub authority_seq: Option<u64>,
    pub lineage_epoch: Option<u64>,
    pub canonical_id: Option<DID>,
    pub equivalent_ids: Vec<DID>,
}

/// 基于 web3 bridge 的 BNS/DEV DID 解析器，内部复用 `HttpsProvider` 做候选文档拉取；
/// 发布状态查询走独立的 `BnsResolveTransport`。
pub struct BnsProvider {
    inner: HttpsProvider,
    transport: Option<Arc<dyn BnsResolveTransport>>,
}

impl BnsProvider {
    /// 使用全局 `KNOWN_WEB3_BRIDGE_CONFIG` 的 bns 网关作为 resolver host。
    /// 若未初始化全局配置，则回退读取 machine.json，再回退默认配置。
    pub fn new() -> NSResult<Self> {
        let host_from_global = name_lib::KNOWN_WEB3_BRIDGE_CONFIG
            .get()
            .and_then(|m| m.get("bns"))
            .cloned();

        let resolver_host = host_from_global
            .or_else(|| {
                BuckyOSMachineConfig::load_machine_config()
                    .and_then(|mc| mc.web3_bridge.get("bns").cloned())
            })
            .or_else(|| {
                BuckyOSMachineConfig::default()
                    .web3_bridge
                    .get("bns")
                    .cloned()
            })
            .ok_or_else(|| NSError::Failed("web3_bridge.bns not set".to_string()))?;

        info!("bns provider using resolver host: {}", resolver_host);

        Ok(Self {
            inner: HttpsProvider::new(resolver_host.as_str()),
            transport: None,
        })
    }

    /// 便捷构造：接收 JSON 配置，允许外部显式指定 web3 bridge。
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let mc = serde_json::from_value::<BuckyOSMachineConfig>(config).unwrap_or_default();
        let host = mc
            .web3_bridge
            .get("bns")
            .cloned()
            .ok_or_else(|| NSError::Failed("web3_bridge.bns not set".to_string()))?;
        Ok(Self {
            inner: HttpsProvider::new(host.as_str()),
            transport: None,
        })
    }

    /// 注入 published-state 查询的传输层实现（真实 BNS RPC/HTTP 客户端或测试 mock）。
    pub fn with_transport(mut self, transport: Arc<dyn BnsResolveTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    fn map_active_record(
        did: &DID,
        doc_type: &str,
        status: DocumentStatus,
        record: BnsActiveRecord,
    ) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            name_status: NameStatus::Active,
            document_status: status,
            document_ref: record.document_ref,
            document_version: record.version,
            previous_version: record.previous_version,
            next_version: record.next_version,
            effective_owner: record.effective_owner,
            owner_source: OwnerSource::MethodAuthority,
            authority_root: record.authority_root,
            authority_seq: record.authority_seq,
            lineage_epoch: record.lineage_epoch,
            canonical_id: record.canonical_id,
            equivalent_ids: record.equivalent_ids,
            migration_target: None,
        }
    }

    fn map_negative(did: &DID, doc_type: &str, status: DocumentStatus) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            name_status: match status {
                DocumentStatus::Tombstoned => NameStatus::Tombstoned,
                DocumentStatus::Missing => NameStatus::Missing,
                _ => NameStatus::Active,
            },
            document_status: status,
            document_ref: None,
            document_version: None,
            previous_version: None,
            next_version: None,
            effective_owner: None,
            owner_source: OwnerSource::Unknown,
            authority_root: None,
            authority_seq: None,
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: None,
        }
    }

    /// 把 transport 返回的 wire-level 响应映射成解析引擎使用的 `PublishedState`。
    /// `NotApplicable` 映射成 `None`（表示这个 resolver 对此 (did, doc_type) 没有
    /// 意见，继续尝试更低 trust_level 的来源），其它分支都是权威源的明确判定，
    /// 必须原样保留，不能在这里"降级"成更宽松的状态。
    fn map_response(
        did: &DID,
        doc_type: &str,
        response: BnsResolveResponse,
    ) -> Option<PublishedState> {
        match response {
            BnsResolveResponse::NotApplicable => None,
            BnsResolveResponse::Missing => {
                Some(Self::map_negative(did, doc_type, DocumentStatus::Missing))
            }
            BnsResolveResponse::Revoked => {
                Some(Self::map_negative(did, doc_type, DocumentStatus::Revoked))
            }
            BnsResolveResponse::Tombstoned => Some(Self::map_negative(
                did,
                doc_type,
                DocumentStatus::Tombstoned,
            )),
            BnsResolveResponse::Migrated { target } => {
                let mut state = Self::map_negative(did, doc_type, DocumentStatus::Migrated);
                state.migration_target = Some(target);
                Some(state)
            }
            BnsResolveResponse::Active(record) => Some(Self::map_active_record(
                did,
                doc_type,
                DocumentStatus::Active,
                record,
            )),
            BnsResolveResponse::Expired(record) => Some(Self::map_active_record(
                did,
                doc_type,
                DocumentStatus::Expired,
                record,
            )),
        }
    }
}

#[async_trait]
impl NsProvider for BnsProvider {
    fn get_id(&self) -> String {
        "bns-provider".to_string()
    }

    fn methods(&self) -> MethodMatcher {
        MethodMatcher::exact(["bns", "dev"])
    }

    fn caps(&self) -> ResolverCaps {
        ResolverCaps {
            published_state: true,
            document_body: true,
            self_signed_candidate: true,
            unauthenticated_info: true,
            negative_state: true,
        }
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "bns provider does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        if did.method != "bns" && did.method != "dev" {
            return Err(NSError::NotFound(format!(
                "unsupported did method: {}",
                did.to_string()
            )));
        }

        info!(
            "bns provider forwarding to https resolver for {}",
            did.to_string()
        );
        self.inner.query_did(did, doc_type, None).await
    }

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Option<PublishedState>> {
        if did.method != "bns" && did.method != "dev" {
            return Ok(None);
        }

        let Some(transport) = self.transport.as_ref() else {
            // 真实 BNS resolveDocument 接口尚未接入（见模块文档），明确放弃而不是
            // 伪造一个状态；上层会继续走 self-signed candidate fallback。
            return Ok(None);
        };

        let response = transport.resolve_document(&did.id, doc_type).await?;
        Ok(Self::map_response(did, doc_type, response))
    }

    async fn fetch_document_body(
        &self,
        doc_ref: &DocumentRef,
    ) -> NSResult<Option<DocumentBody>> {
        // Active/Expired 状态下的 inline document 走通用默认实现即可；外链 document_ref
        // 的拉取要等 BNS 的 uri schema 定稿后再补，避免在这里猜测协议细节。
        Ok(doc_ref
            .inline_document
            .as_ref()
            .map(|doc| DocumentBody::anchored(doc.clone(), Some(self.get_id()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reject_unsupported_method() {
        let provider = BnsProvider::new().unwrap();
        let did = DID::from_str("did:web:example.com").unwrap();
        let err = provider.query_did(&did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn published_state_is_none_without_transport() {
        let provider = BnsProvider::new().unwrap();
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let state = provider
            .resolve_published_state(&did, "zone")
            .await
            .unwrap();
        assert!(state.is_none());
    }

    struct MockTransport {
        response: BnsResolveResponse,
    }

    #[async_trait]
    impl BnsResolveTransport for MockTransport {
        async fn resolve_document(
            &self,
            _canonical_name: &str,
            _doc_type: &str,
        ) -> NSResult<BnsResolveResponse> {
            Ok(self.response.clone())
        }
    }

    struct FailingTransport;

    #[async_trait]
    impl BnsResolveTransport for FailingTransport {
        async fn resolve_document(
            &self,
            _canonical_name: &str,
            _doc_type: &str,
        ) -> NSResult<BnsResolveResponse> {
            Err(NSError::Failed("connection refused".to_string()))
        }
    }

    fn provider_with(response: BnsResolveResponse) -> BnsProvider {
        BnsProvider::new()
            .unwrap()
            .with_transport(Arc::new(MockTransport { response }))
    }

    #[tokio::test]
    async fn active_state_maps_document_ref_and_owner() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let owner_did = DID::new("bns", "waterflier-owner");
        let doc = EncodedDocument::JsonLd(serde_json::json!({"marker": "active"}));
        let provider = provider_with(BnsResolveResponse::Active(BnsActiveRecord {
            document_ref: Some(DocumentRef::inline(doc.clone())),
            version: Some(3),
            previous_version: Some(2),
            next_version: None,
            effective_owner: Some(owner_did.clone()),
            authority_root: Some("0xroot".to_string()),
            authority_seq: Some(9),
            lineage_epoch: Some(1),
            canonical_id: None,
            equivalent_ids: Vec::new(),
        }));

        let state = provider
            .resolve_published_state(&did, "zone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Active);
        assert_eq!(state.document_version, Some(3));
        assert_eq!(state.effective_owner, Some(owner_did));
        assert_eq!(
            state.document_ref.unwrap().inline_document.unwrap(),
            doc
        );
    }

    #[tokio::test]
    async fn missing_tombstoned_revoked_and_migrated_map_to_terminal_states() {
        let did = DID::from_str("did:bns:waterflier").unwrap();

        let missing = provider_with(BnsResolveResponse::Missing)
            .resolve_published_state(&did, "zone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(missing.document_status, DocumentStatus::Missing);

        let revoked = provider_with(BnsResolveResponse::Revoked)
            .resolve_published_state(&did, "zone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.document_status, DocumentStatus::Revoked);

        let tombstoned = provider_with(BnsResolveResponse::Tombstoned)
            .resolve_published_state(&did, "zone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tombstoned.document_status, DocumentStatus::Tombstoned);

        let target = DID::new("bns", "waterflier-v2");
        let migrated = provider_with(BnsResolveResponse::Migrated {
            target: target.clone(),
        })
        .resolve_published_state(&did, "zone")
        .await
        .unwrap()
        .unwrap();
        assert_eq!(migrated.document_status, DocumentStatus::Migrated);
        assert_eq!(migrated.migration_target, Some(target));
    }

    #[tokio::test]
    async fn expired_state_maps_and_preserves_record_fields() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let provider = provider_with(BnsResolveResponse::Expired(BnsActiveRecord {
            version: Some(5),
            ..Default::default()
        }));

        let state = provider
            .resolve_published_state(&did, "zone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Expired);
        assert_eq!(state.document_version, Some(5));
    }

    #[tokio::test]
    async fn not_applicable_response_yields_no_state() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let state = provider_with(BnsResolveResponse::NotApplicable)
            .resolve_published_state(&did, "zone")
            .await
            .unwrap();
        assert!(state.is_none());
    }

    // T3.2: transport 错误（连接被拒绝等）必须原样冒泡成 Err，不能被误判成
    // Missing/Revoked 之类的强负状态。
    #[tokio::test]
    async fn transport_error_is_not_interpreted_as_negative_state() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let provider = BnsProvider::new()
            .unwrap()
            .with_transport(Arc::new(FailingTransport));

        let err = provider
            .resolve_published_state(&did, "zone")
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    // 一个只提供 published_state（不提供 self-signed candidate）的最小 mock，
    // 用来在不触碰真实网络请求（BnsProvider::query_did 会转发到 HttpsProvider）的
    // 前提下，验证完整 query_did_ex 路径对 transport error 的处理。
    struct PublishedStateOnlyProvider {
        transport: FailingTransport,
    }

    #[async_trait]
    impl NsProvider for PublishedStateOnlyProvider {
        fn get_id(&self) -> String {
            "published-state-only".to_string()
        }

        fn caps(&self) -> ResolverCaps {
            ResolverCaps {
                published_state: true,
                document_body: false,
                self_signed_candidate: false,
                unauthenticated_info: false,
                negative_state: true,
            }
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            _doc_type: Option<&str>,
            _from_ip: Option<IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Err(NSError::NotFound("published-state only".into()))
        }

        async fn resolve_published_state(
            &self,
            did: &DID,
            doc_type: &str,
        ) -> NSResult<Option<PublishedState>> {
            self.transport
                .resolve_document(&did.id, doc_type)
                .await
                .map(|_| None)
        }
    }

    #[tokio::test]
    async fn resolve_from_published_state_treats_transport_error_as_abstain_not_negative() {
        // 通过 name_query 的完整解析路径确认：published_state provider 报错时，
        // 上层把它当成"这个 provider 没查到"继续往下走 fallback，而不是把
        // transport error 误解释成 Missing/Revoked 直接拒绝（Disabled）。
        use crate::{NameQuery, ResolvePolicy};

        let q = NameQuery::new();
        let did = DID::from_str("did:bns:waterflier").unwrap();

        q.add_provider(
            Box::new(PublishedStateOnlyProvider {
                transport: FailingTransport,
            }),
            0,
        )
        .await;

        let err = q
            .query_did_ex(&did, Some("zone"), None, ResolvePolicy::default())
            .await
            .unwrap_err();
        assert!(!matches!(err, NSError::Disabled(_)));
    }
}
