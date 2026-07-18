/*
Zone Resolver cache 客户端(简化文档第 3 节第 0 步、介绍文档第 5 节)。

zone_resolver 使用标准 resolver HTTP 接口,但它**不是** resolver-provider:
它是 cluster-level shared cache / control-plane cache("伪装成 resolver 的
zone 内权威 cache")。因此这里不实现 `NsProvider`,而是一个独立的 cache 层
客户端,由 `NameClient::resolve_did_ex` 在进入本机 cache 与 resolver core
之前查询。cache 分两级:Zone Resolver 是 L1,本机 did_cache 是 L2。

- 明确命中时,它的回答就是本次解析的结果(`CacheStatus::ZoneHit`),
  本机 cache、local override、method authority、supplements 都不参与;
- `Missing / Revoked / Tombstoned` 是明确回答,不是 cache miss;
- `Unknown` 表示 L1 cache 没有答案,继续走本机 cache 快路径和 resolver core;
- 不做 `did_in_zone` 客户端过滤:哪些 DID 属于本 Zone、哪些短路、哪些允许
  出 Zone,由 Zone Resolver 服务内部策略决定;
- 管理面(cluster override、Zone 内吊销等)是 Zone Resolver 的私有接口,
  `name-client` 只消费解析接口。
*/

use crate::{
    BodyEvidence, CacheStatus, DidDocType, DocumentRef, DocumentStatus, PublishedState,
    ResolvedDocument,
};
use log::debug;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

/// 默认的 zone 内 resolver cache 服务地址(介绍文档第 5 节)。
pub const DEFAULT_ZONE_RESOLVER_ENDPOINT: &str = "http://127.0.0.1:3180";

/// Zone Resolver 客户端配置。默认 endpoint 是本机服务;timeout 必须很短,
/// 保证非 BuckyOS 环境下默认启用不引入明显延迟(连接被拒绝是即时返回的,
/// timeout 只兜防火墙丢包这类极端情况)。
#[derive(Debug, Clone)]
pub struct ZoneResolverConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    /// 整个请求(含读取)的超时。超时视为 Zone L1 cache unknown。
    pub request_timeout: Duration,
}

impl Default for ZoneResolverConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ZONE_RESOLVER_ENDPOINT.to_string(),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// 一次 Zone Resolver 查询的产出。`Answered` 是 L1 cache 的明确结果
/// (包含 Missing / Revoked / Tombstoned 这类负状态);`Unknown` 是 L1
/// cache 没有答案,允许继续落回本机 cache 与 resolver core。
pub enum ZoneLookup {
    Answered(ZoneAnswer),
    Unknown(NSError),
}

/// Zone 的明确回答:`result` 是 resolve 路径直接返回的结果;`state` 是 wire
/// `didDocumentMetadata.buckyos` 块解析出的完整发布状态(docHash /
/// effectiveOwner / migrationTarget / checkedAt / validUntil 等),供
/// `build_verify_context` 构建 Zone scope snapshot 使用——客户端不再丢弃
/// wire 已定义的字段(TODO Phase 1)。负状态回答同样携带 state。
pub struct ZoneAnswer {
    pub result: NSResult<ResolvedDocument>,
    pub state: Option<PublishedState>,
}

pub struct ZoneResolverClient {
    config: ZoneResolverConfig,
    client: Client,
}

impl ZoneResolverClient {
    pub fn new(config: ZoneResolverConfig) -> Self {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .unwrap_or_else(|err| {
                debug!(
                    "build zone resolver http client with timeouts failed ({}), using default",
                    err
                );
                Client::new()
            });
        Self { config, client }
    }

    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    fn resolver_id(&self) -> String {
        format!("zone-resolver:{}", self.config.endpoint)
    }

    fn build_url(&self, did: &DID, doc_type: &DidDocType) -> String {
        format!(
            "{}/1.0/identifiers/{}?type={}",
            self.config.endpoint.trim_end_matches('/'),
            did.to_string(),
            doc_type.as_str()
        )
    }

    /// 查询 Zone Resolver。`no_proof` 是该 (method, doc_type) 的 Info 契约判定,
    /// 只影响结果的证据打标(UnproofInfo / Anchored),不影响查询本身。
    pub async fn lookup(&self, did: &DID, doc_type: &DidDocType, no_proof: bool) -> ZoneLookup {
        let url = self.build_url(did, doc_type);
        let response = match self.client.get(&url).send().await {
            Ok(response) => response,
            // 传输层失败(refused / 超时 / 连接中断)= L1 cache unknown。
            Err(err) => {
                return ZoneLookup::Unknown(NSError::Failed(format!(
                    "zone resolver {} unknown: {}",
                    self.config.endpoint, err
                )));
            }
        };
        let status = response.status();
        let body = match response.text().await {
            Ok(body) => body,
            Err(err) => {
                return ZoneLookup::Unknown(NSError::Failed(format!(
                    "read zone resolver {} response unknown: {}",
                    self.config.endpoint, err
                )));
            }
        };
        Self::interpret_response(did, doc_type, no_proof, &self.resolver_id(), status, &body)
    }

    /// 把 HTTP 响应解释成 Zone 明确回答或 L1 unknown。纯函数,便于用字面量
    /// status/body 写单测。响应信封与 resolver 接口一致
    /// (doc/http_did_resolver_api.md):`didDocument` + `didDocumentMetadata.buckyos`。
    fn interpret_response(
        did: &DID,
        doc_type: &DidDocType,
        no_proof: bool,
        resolver_id: &str,
        status: StatusCode,
        body: &str,
    ) -> ZoneLookup {
        // 网关层的"服务不可用"与传输失败同档:它们是 Zone L1 cache
        // 的 unknown,允许继续查本机 cache。
        if status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::BAD_GATEWAY
            || status == StatusCode::GATEWAY_TIMEOUT
        {
            return ZoneLookup::Unknown(NSError::Failed(format!(
                "zone resolver {} unknown: {}",
                resolver_id, status
            )));
        }

        let envelope = serde_json::from_str::<Value>(body).ok();
        let state = envelope
            .as_ref()
            .and_then(|value| Self::published_state_from_envelope(did, doc_type, value));

        // 信封里的发布状态与 deactivated 标记优先于 HTTP 状态码:它们是
        // Zone 的语义回答。
        if let Some(value) = envelope.as_ref() {
            let metadata = value.get("didDocumentMetadata");
            let document_status = metadata
                .and_then(|meta| meta.get("buckyos"))
                .and_then(|buckyos| buckyos.get("documentStatus"))
                .and_then(|status| status.as_str());
            let deactivated = metadata
                .and_then(|meta| meta.get("deactivated"))
                .and_then(|flag| flag.as_bool())
                == Some(true);

            match document_status {
                Some("revoked") | Some("tombstoned") | Some("migrated") => {
                    return ZoneLookup::Answered(ZoneAnswer {
                        result: Err(NSError::Disabled(format!(
                            "zone resolver answered: {}#{} is {}",
                            did.to_string(),
                            doc_type,
                            document_status.unwrap()
                        ))),
                        state,
                    });
                }
                Some("missing") | Some("expired") => {
                    return ZoneLookup::Answered(ZoneAnswer {
                        result: Err(NSError::NotFound(format!(
                            "zone resolver answered: {}#{} is {}",
                            did.to_string(),
                            doc_type,
                            document_status.unwrap()
                        ))),
                        state,
                    });
                }
                _ => {}
            }
            if deactivated {
                return ZoneLookup::Answered(ZoneAnswer {
                    result: Err(NSError::Disabled(format!(
                        "zone resolver answered: {}#{} deactivated",
                        did.to_string(),
                        doc_type
                    ))),
                    state,
                });
            }

            let resolution_error = value
                .get("didResolutionMetadata")
                .and_then(|meta| meta.get("error"))
                .filter(|err| !err.is_null());
            if let Some(error) = resolution_error {
                return ZoneLookup::Unknown(NSError::Failed(format!(
                    "zone resolver answered unknown for {}#{}: {}",
                    did.to_string(),
                    doc_type,
                    error
                )));
            }
        }

        match status {
            StatusCode::OK => ZoneLookup::Answered(ZoneAnswer {
                result: Self::document_answer(
                    did,
                    doc_type,
                    no_proof,
                    resolver_id,
                    envelope,
                    body,
                    state.as_ref(),
                ),
                state,
            }),
            // 裸 404 表示 Zone L1 cache 没有答案;明确 Missing 必须由
            // didDocumentMetadata.buckyos.documentStatus = "missing" 表达。
            StatusCode::NOT_FOUND | StatusCode::NO_CONTENT => {
                ZoneLookup::Unknown(NSError::NotFound(format!(
                    "zone resolver answered unknown for {}#{}: status {}",
                    did.to_string(),
                    doc_type,
                    status
                )))
            }
            StatusCode::GONE => ZoneLookup::Answered(ZoneAnswer {
                result: Err(NSError::Disabled(format!(
                    "zone resolver answered: {}#{} is gone",
                    did.to_string(),
                    doc_type
                ))),
                state,
            }),
            // 其余状态码(500 等):服务可达但没给出明确 cache 结果,视为
            // Zone L1 unknown,继续走本机 cache。
            other => ZoneLookup::Unknown(NSError::Failed(format!(
                "zone resolver answered unknown for {}#{}: status {}",
                did.to_string(),
                doc_type,
                other
            ))),
        }
    }

    /// 200 回答的文档提取与结果组装。
    fn document_answer(
        did: &DID,
        doc_type: &DidDocType,
        no_proof: bool,
        resolver_id: &str,
        envelope: Option<Value>,
        body: &str,
        state: Option<&PublishedState>,
    ) -> NSResult<ResolvedDocument> {
        let document = match envelope.as_ref() {
            Some(value) => {
                // resolver 信封:didDocument 字段;非信封的裸 JSON 文档整体即文档。
                let doc_value = value
                    .get("didDocument")
                    .cloned()
                    .unwrap_or_else(|| value.clone());
                match doc_value {
                    Value::String(jwt) => EncodedDocument::Jwt(jwt),
                    Value::Null => {
                        return Err(NSError::Failed(format!(
                            "zone resolver answered 200 for {}#{} without a document",
                            did.to_string(),
                            doc_type
                        )));
                    }
                    other => EncodedDocument::JsonLd(other),
                }
            }
            // 非 JSON body:只可能是裸 JWT 文档(三段式);其余内容是坏响应
            // (`EncodedDocument::from_str` 会把任意文本宽松地当作 Jwt,这里
            // 需要自己把关)。
            None => {
                let trimmed = body.trim();
                let mut segments = trimmed.split('.');
                let jwt_shaped = segments.by_ref().take(3).filter(|s| !s.is_empty()).count() == 3
                    && segments.next().is_none();
                if !jwt_shaped {
                    return Err(NSError::Failed(format!(
                        "zone resolver answered malformed document for {}#{}",
                        did.to_string(),
                        doc_type
                    )));
                }
                EncodedDocument::Jwt(trimmed.to_string())
            }
        };

        let evidence = if no_proof {
            BodyEvidence::UnproofInfo
        } else {
            BodyEvidence::Anchored
        };

        Ok(ResolvedDocument::from_document(
            document,
            did,
            doc_type,
            Some(resolver_id.to_string()),
            evidence,
            state,
        )
        .with_cache_status(CacheStatus::ZoneHit))
    }

    /// 信封携带 buckyos 扩展时,解析完整发布状态:documentStatus / docType /
    /// documentVersion(= 当前发布文档的 iat)/ authoritySeq / effectiveOwner /
    /// docHash / migrationTarget / checkedAt / validUntil。resolve 结果 metadata
    /// 与 snapshot 构建共用这一份;客户端不再丢弃 wire 已定义的字段。
    fn published_state_from_envelope(
        did: &DID,
        doc_type: &DidDocType,
        envelope: &Value,
    ) -> Option<PublishedState> {
        let buckyos = envelope.get("didDocumentMetadata")?.get("buckyos")?;
        let document_status = match buckyos.get("documentStatus").and_then(|s| s.as_str()) {
            Some("active") | None => DocumentStatus::Active,
            Some("missing") => DocumentStatus::Missing,
            Some("expired") => DocumentStatus::Expired,
            Some("migrated") => DocumentStatus::Migrated,
            Some("revoked") => DocumentStatus::Revoked,
            Some("tombstoned") => DocumentStatus::Tombstoned,
            Some(_) => return None,
        };
        let doc_hash = buckyos
            .get("docHash")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());
        let document_ref = doc_hash.map(|content_hash| DocumentRef {
            uri: None,
            content_hash: Some(content_hash),
            inline_document: None,
        });
        Some(PublishedState {
            did: did.clone(),
            doc_type: buckyos
                .get("docType")
                .and_then(|s| s.as_str())
                .unwrap_or(doc_type.as_str())
                .to_string(),
            document_status,
            document_ref,
            document_version: buckyos.get("documentVersion").and_then(|v| v.as_u64()),
            effective_owner: buckyos
                .get("effectiveOwner")
                .and_then(|s| s.as_str())
                .and_then(|s| DID::from_str(s).ok()),
            authority_seq: buckyos.get("authoritySeq").and_then(|v| v.as_u64()),
            migration_target: buckyos
                .get("migrationTarget")
                .and_then(|s| s.as_str())
                .and_then(|s| DID::from_str(s).ok()),
            checked_at: buckyos.get("checkedAt").and_then(|v| v.as_u64()),
            valid_until: buckyos.get("validUntil").and_then(|v| v.as_u64()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn did() -> DID {
        DID::new("web", "ood1.example.com")
    }

    fn interpret(status: StatusCode, body: &str) -> ZoneLookup {
        ZoneResolverClient::interpret_response(
            &did(),
            &DidDocType::Zone,
            false,
            "zone-resolver:test",
            status,
            body,
        )
    }

    /// 测试辅助:把 Answered 的 ZoneAnswer 摊平成 result(state 单测另行断言)。
    enum FlatLookup {
        Answered(NSResult<ResolvedDocument>),
        Unknown(NSError),
    }

    fn flat(lookup: ZoneLookup) -> FlatLookup {
        match lookup {
            ZoneLookup::Answered(answer) => FlatLookup::Answered(answer.result),
            ZoneLookup::Unknown(err) => FlatLookup::Unknown(err),
        }
    }

    #[test]
    fn ok_with_envelope_document_is_zone_hit() {
        let body = json!({
            "didDocument": {"marker": "zone-doc"},
            "didDocumentMetadata": {
                "buckyos": {"documentStatus": "active", "documentVersion": 7}
            }
        })
        .to_string();
        let FlatLookup::Answered(Ok(resolved)) = flat(interpret(StatusCode::OK, &body)) else {
            panic!("expected answered ok");
        };
        assert_eq!(
            resolved.document,
            EncodedDocument::JsonLd(json!({"marker": "zone-doc"}))
        );
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::Anchored)
        );
        assert_eq!(resolved.document_metadata.buckyos.document_version, Some(7));
    }

    #[test]
    fn ok_with_bare_document_is_zone_hit() {
        let body = json!({"marker": "bare-doc"}).to_string();
        let FlatLookup::Answered(Ok(resolved)) = flat(interpret(StatusCode::OK, &body)) else {
            panic!("expected answered ok");
        };
        assert_eq!(
            resolved.document,
            EncodedDocument::JsonLd(json!({"marker": "bare-doc"}))
        );
    }

    #[test]
    fn info_doc_type_is_marked_unproof() {
        let body = json!({"didDocument": {"info": 1}}).to_string();
        let FlatLookup::Answered(Ok(resolved)) = flat(ZoneResolverClient::interpret_response(
            &did(),
            &DidDocType::Info,
            true,
            "zone-resolver:test",
            StatusCode::OK,
            &body,
        )) else {
            panic!("expected answered ok");
        };
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::UnproofInfo)
        );
    }

    #[test]
    fn missing_status_is_an_answer_but_bare_404_is_unknown() {
        // 明确 Missing 必须由 buckyos documentStatus 表达;裸 404 表示
        // Zone L1 cache 不知道,允许 fallback 到本机 cache。
        let body = json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let FlatLookup::Answered(Err(NSError::NotFound(_))) = flat(interpret(StatusCode::OK, &body))
        else {
            panic!("expected answered not-found");
        };

        let FlatLookup::Unknown(NSError::NotFound(msg)) = flat(interpret(StatusCode::NOT_FOUND, ""))
        else {
            panic!("expected unknown not-found");
        };
        assert!(msg.contains("unknown"));

        let body = json!({
            "didResolutionMetadata": {"error": "notFound"},
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let FlatLookup::Answered(Err(NSError::NotFound(_))) =
            flat(interpret(StatusCode::NOT_FOUND, &body))
        else {
            panic!("expected answered not-found");
        };
    }

    #[test]
    fn negative_states_are_answers() {
        let body = json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "revoked"}}
        })
        .to_string();
        let FlatLookup::Answered(Err(NSError::Disabled(msg))) = flat(interpret(StatusCode::GONE, &body))
        else {
            panic!("expected answered disabled");
        };
        assert!(msg.contains("zone resolver"));

        // 裸 410 同样是负状态回答。
        let FlatLookup::Answered(Err(NSError::Disabled(_))) = flat(interpret(StatusCode::GONE, ""))
        else {
            panic!("expected answered disabled");
        };
    }

    #[test]
    fn server_error_is_zone_unknown_and_falls_back() {
        let FlatLookup::Unknown(NSError::Failed(msg)) =
            flat(interpret(StatusCode::INTERNAL_SERVER_ERROR, "boom"))
        else {
            panic!("expected unknown failed");
        };
        assert!(msg.contains("unknown"));
    }

    #[test]
    fn resolution_metadata_error_is_zone_unknown() {
        let body = json!({
            "didResolutionMetadata": {"error": "notFound"}
        })
        .to_string();
        let FlatLookup::Unknown(NSError::Failed(msg)) = flat(interpret(StatusCode::OK, &body)) else {
            panic!("expected unknown failed");
        };
        assert!(msg.contains("notFound"));
    }

    #[test]
    fn service_unavailable_status_is_unknown() {
        assert!(matches!(
            flat(interpret(StatusCode::SERVICE_UNAVAILABLE, "")),
            FlatLookup::Unknown(_)
        ));
        assert!(matches!(
            flat(interpret(StatusCode::BAD_GATEWAY, "")),
            FlatLookup::Unknown(_)
        ));
        assert!(matches!(
            flat(interpret(StatusCode::GATEWAY_TIMEOUT, "")),
            FlatLookup::Unknown(_)
        ));
    }

    #[test]
    fn ok_with_unparsable_body_is_zone_answer_error() {
        // 200 但响应坏掉:服务声称给出了文档,这是坏回答,不是 cache miss。
        let FlatLookup::Answered(Err(NSError::Failed(_))) =
            flat(interpret(StatusCode::OK, "not json and not jwt"))
        else {
            panic!("expected answered failed");
        };
    }

    #[test]
    fn build_url_matches_resolver_api() {
        let client = ZoneResolverClient::new(ZoneResolverConfig::default());
        assert_eq!(
            client.build_url(&DID::new("bns", "alice"), &DidDocType::Owner),
            "http://127.0.0.1:3180/1.0/identifiers/did:bns:alice?type=owner"
        );
    }
}
