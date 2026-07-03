/*
Zone Resolver cache 客户端(简化文档第 3 节第 0 步、介绍文档第 5 节)。

zone_resolver 使用标准 resolver HTTP 接口,但它**不是** resolver-provider:
它是 cluster-level shared cache / control-plane cache("伪装成 resolver 的
zone 内权威 cache")。因此这里不实现 `NsProvider`,而是一个独立的 cache 层
客户端,由 `NameClient::resolve_did_ex` 在进入本机 cache 与 resolver core
之前查询:

- 服务可用时,它的回答就是本次解析的结果(`CacheStatus::ZoneHit`),
  本机 cache、local override、method authority、supplements 都不参与;
- `Missing / Revoked / Tombstoned / Unknown` 都是回答,不是 cache miss,
  不触发任何 fallback;Zone 实现若希望"没有命中时继续向外查",应由服务
  自己完成外部查询后作为 resolver 结果返回;
- 只有服务不可用(连接失败、超时、明确的 service unavailable)才落回
  本机 cache 快路径和 resolver core;
- 不做 `did_in_zone` 客户端过滤:哪些 DID 属于本 Zone、哪些短路、哪些允许
  出 Zone,由 Zone Resolver 服务内部策略决定;
- 管理面(cluster override、Zone 内吊销等)是 Zone Resolver 的私有接口,
  `name-client` 只消费解析接口。
*/

use crate::{
    BodyEvidence, CacheStatus, DidDocType, DocumentStatus, PublishedState, ResolvedDocument,
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
    /// 整个请求(含读取)的超时。Zone Resolver 可能代理外部查询,给出比
    /// connect_timeout 宽松的预算;超时视为服务不可用。
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

/// 一次 Zone Resolver 查询的产出。界线是**服务可用性**,不是"有没有拿到文档":
/// 服务给出的 `Missing / Revoked / Tombstoned / Unknown` 都落在 `Answered`
/// (以对应的 NSError 表达),只有传输层失败与明确的 unavailable 才是
/// `Unavailable`——那才允许落回本机 cache 与 resolver core。
pub enum ZoneLookup {
    Answered(NSResult<ResolvedDocument>),
    Unavailable(NSError),
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
            // 传输层失败(refused / 超时 / 连接中断)= 服务不可用。
            Err(err) => {
                return ZoneLookup::Unavailable(NSError::Failed(format!(
                    "zone resolver {} unreachable: {}",
                    self.config.endpoint, err
                )));
            }
        };
        let status = response.status();
        let body = match response.text().await {
            Ok(body) => body,
            Err(err) => {
                return ZoneLookup::Unavailable(NSError::Failed(format!(
                    "read zone resolver {} response failed: {}",
                    self.config.endpoint, err
                )));
            }
        };
        Self::interpret_response(did, doc_type, no_proof, &self.resolver_id(), status, &body)
    }

    /// 把 HTTP 响应解释成 Zone 回答或"服务不可用"。纯函数,便于用字面量
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
        // 网关层的"服务不可用"与传输失败同档:这是 T5.1 列表里唯一由
        // HTTP 状态码表达的 unavailable。
        if status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::BAD_GATEWAY
            || status == StatusCode::GATEWAY_TIMEOUT
        {
            return ZoneLookup::Unavailable(NSError::Failed(format!(
                "zone resolver {} unavailable: {}",
                resolver_id, status
            )));
        }

        let envelope = serde_json::from_str::<Value>(body).ok();

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
                    return ZoneLookup::Answered(Err(NSError::Disabled(format!(
                        "zone resolver answered: {}#{} is {}",
                        did.to_string(),
                        doc_type,
                        document_status.unwrap()
                    ))));
                }
                Some("missing") | Some("expired") => {
                    return ZoneLookup::Answered(Err(NSError::NotFound(format!(
                        "zone resolver answered: {}#{} is {}",
                        did.to_string(),
                        doc_type,
                        document_status.unwrap()
                    ))));
                }
                _ => {}
            }
            if deactivated {
                return ZoneLookup::Answered(Err(NSError::Disabled(format!(
                    "zone resolver answered: {}#{} deactivated",
                    did.to_string(),
                    doc_type
                ))));
            }
        }

        match status {
            StatusCode::OK => {
                ZoneLookup::Answered(Self::document_answer(
                    did, doc_type, no_proof, resolver_id, envelope, body,
                ))
            }
            // Missing 是回答:Zone 明确说不存在,不落回本机 cache 或外部 resolver。
            StatusCode::NOT_FOUND => ZoneLookup::Answered(Err(NSError::NotFound(format!(
                "zone resolver answered: {}#{} not found",
                did.to_string(),
                doc_type
            )))),
            StatusCode::GONE => ZoneLookup::Answered(Err(NSError::Disabled(format!(
                "zone resolver answered: {}#{} is gone",
                did.to_string(),
                doc_type
            )))),
            // 其余状态码(500 等):服务可达但没能给出解析结果,是 Zone 的
            // "unknown"回答——同样独占本次解析,不允许绕过 Zone 向外查。
            other => ZoneLookup::Answered(Err(NSError::Failed(format!(
                "zone resolver answered unknown for {}#{}: status {}",
                did.to_string(),
                doc_type,
                other
            )))),
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
    ) -> NSResult<ResolvedDocument> {
        let document = match envelope.as_ref() {
            Some(value) => {
                // resolver 信封:didDocument 字段;非信封的裸 JSON 文档整体即文档。
                let doc_value = value.get("didDocument").cloned().unwrap_or_else(|| value.clone());
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
                let jwt_shaped = segments.by_ref().take(3).filter(|s| !s.is_empty()).count()
                    == 3
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

        let published = envelope
            .as_ref()
            .and_then(|value| Self::published_state_from_envelope(did, doc_type, value));

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
            published.as_ref(),
        )
        .with_cache_status(CacheStatus::ZoneHit))
    }

    /// 信封携带 buckyos 扩展时,把发布状态透传进结果 metadata
    /// (document_version 等);门禁语义已在 `interpret_response` 处理完。
    fn published_state_from_envelope(
        did: &DID,
        doc_type: &DidDocType,
        envelope: &Value,
    ) -> Option<PublishedState> {
        let buckyos = envelope.get("didDocumentMetadata")?.get("buckyos")?;
        let document_status = match buckyos.get("documentStatus").and_then(|s| s.as_str()) {
            Some("active") | None => DocumentStatus::Active,
            // 非 Active 状态在 interpret_response 已经拦下,这里防御性兜底。
            _ => return None,
        };
        Some(PublishedState {
            did: did.clone(),
            doc_type: buckyos
                .get("docType")
                .and_then(|s| s.as_str())
                .unwrap_or(doc_type.as_str())
                .to_string(),
            document_status,
            document_ref: None,
            document_version: buckyos.get("documentVersion").and_then(|v| v.as_u64()),
            effective_owner: buckyos
                .get("effectiveOwner")
                .and_then(|s| s.as_str())
                .and_then(|s| DID::from_str(s).ok()),
            authority_seq: buckyos.get("authoritySeq").and_then(|v| v.as_u64()),
            migration_target: None,
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

    #[test]
    fn ok_with_envelope_document_is_zone_hit() {
        let body = json!({
            "didDocument": {"marker": "zone-doc"},
            "didDocumentMetadata": {
                "buckyos": {"documentStatus": "active", "documentVersion": 7}
            }
        })
        .to_string();
        let ZoneLookup::Answered(Ok(resolved)) = interpret(StatusCode::OK, &body) else {
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
        assert_eq!(
            resolved.document_metadata.buckyos.document_version,
            Some(7)
        );
    }

    #[test]
    fn ok_with_bare_document_is_zone_hit() {
        let body = json!({"marker": "bare-doc"}).to_string();
        let ZoneLookup::Answered(Ok(resolved)) = interpret(StatusCode::OK, &body) else {
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
        let ZoneLookup::Answered(Ok(resolved)) = ZoneResolverClient::interpret_response(
            &did(),
            &DidDocType::Info,
            true,
            "zone-resolver:test",
            StatusCode::OK,
            &body,
        ) else {
            panic!("expected answered ok");
        };
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::UnproofInfo)
        );
    }

    #[test]
    fn missing_is_an_answer_not_unavailable() {
        // 裸 404 与带信封 missing 都是回答(NotFound),不允许 fallback。
        let ZoneLookup::Answered(Err(NSError::NotFound(msg))) = interpret(StatusCode::NOT_FOUND, "")
        else {
            panic!("expected answered not-found");
        };
        assert!(msg.contains("zone resolver"));

        let body = json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let ZoneLookup::Answered(Err(NSError::NotFound(_))) = interpret(StatusCode::OK, &body)
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
        let ZoneLookup::Answered(Err(NSError::Disabled(msg))) = interpret(StatusCode::GONE, &body)
        else {
            panic!("expected answered disabled");
        };
        assert!(msg.contains("zone resolver"));

        // 裸 410 同样是负状态回答。
        let ZoneLookup::Answered(Err(NSError::Disabled(_))) = interpret(StatusCode::GONE, "")
        else {
            panic!("expected answered disabled");
        };
    }

    #[test]
    fn server_error_is_zone_unknown_answer_not_fallback() {
        let ZoneLookup::Answered(Err(NSError::Failed(msg))) =
            interpret(StatusCode::INTERNAL_SERVER_ERROR, "boom")
        else {
            panic!("expected answered failed");
        };
        assert!(msg.contains("zone resolver"));
    }

    #[test]
    fn service_unavailable_status_falls_back() {
        assert!(matches!(
            interpret(StatusCode::SERVICE_UNAVAILABLE, ""),
            ZoneLookup::Unavailable(_)
        ));
        assert!(matches!(
            interpret(StatusCode::BAD_GATEWAY, ""),
            ZoneLookup::Unavailable(_)
        ));
        assert!(matches!(
            interpret(StatusCode::GATEWAY_TIMEOUT, ""),
            ZoneLookup::Unavailable(_)
        ));
    }

    #[test]
    fn ok_with_unparsable_body_is_zone_answer_error() {
        // 服务可达但响应坏掉:是 Zone 的回答(错误),不是 unavailable——
        // 不允许因服务 bug 绕过 Zone 控制面向外查询。
        let ZoneLookup::Answered(Err(NSError::Failed(_))) =
            interpret(StatusCode::OK, "not json and not jwt")
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
