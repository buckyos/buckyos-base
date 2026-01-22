use buckyos_kit::buckyos_get_unix_timestamp;
use log::{error, info};
use name_lib::*;
use name_lib::DEFAULT_EXPIRE_TIME;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{NameInfo, NsProvider, RecordType};

pub struct NameQuery {
    providers: Arc<RwLock<Vec<(Box<dyn NsProvider>, i32)>>>,
}

impl NameQuery {
    pub fn new() -> NameQuery {
        NameQuery {
            providers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add_provider(&self, provider: Box<dyn NsProvider>, trust_level: i32) {
        let mut providers = self.providers.write().await;
        // 使用二分查找找到正确的插入位置，保持有序
        // 按 trust_level 从小到大排序（类似 RING 级别，数字越小优先级越高）
        // 0 以下是纯本地配置（非外部系统）
        let pos = providers
            .binary_search_by_key(&trust_level, |(_, level)| *level)
            .unwrap_or_else(|pos| pos);
        providers.insert(pos, (provider, trust_level));
    }

    pub async fn query(&self, name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
        let providers = self.providers.read().await;
        if providers.len() == 0 {
            let msg = format!("No provider found for {}", name);
            error!("{}", msg);
            return Err(NSError::Failed(msg));
        }

        let record_type = record_type.unwrap_or_default();

        for (provider, _) in providers.iter() {
            match provider.query(name, Some(record_type), None).await {
                Ok(info) => {
                    info!("Resolved {} to {:?}", name, info);
                    return Ok(info);
                }
                Err(_e) => {
                    //log::error!("query err {}", e);
                    continue;
                }
            }
        }
        Err(NSError::NotFound(String::from(name)))
    }

    pub async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        max_trust_level: Option<i32>,
    ) -> NSResult<(EncodedDocument, u64, i32)> {
        let providers = self.providers.read().await;
        if providers.len() == 0 {
            return Err(NSError::Failed(format!(
                "no provider for {}",
                did.to_host_name()
            )));
        }

        let allowed_max_trust = max_trust_level.unwrap_or(i32::MAX);

        // 按 trust_level 分组，相同优先级的 provider 并发请求
        let mut current_level: Option<i32> = None;
        let mut level_providers = Vec::new();
        
        for (provider, level) in providers.iter() {
            if *level >= allowed_max_trust {
                break;
            }
            if current_level.is_none() {
                current_level = Some(*level);
            }
            
            // 如果遇到不同的优先级，处理当前优先级组
            if current_level != Some(*level) {
                match self
                    .query_did_from_providers(&level_providers, did, doc_type)
                    .await
                {
                    Ok(Some(result)) => {
                        return Ok((result.0, result.1, current_level.unwrap()));
                    }
                    Err(NSError::Disabled(msg)) => {
                        return Err(NSError::Disabled(msg));
                    }
                    _ => {}
                }
                // 清空并开始新的优先级组
                level_providers.clear();
                current_level = Some(*level);
            }
            
            level_providers.push(provider);
        }
        
        // 处理最后一组
        if !level_providers.is_empty() {
            match self
                .query_did_from_providers(&level_providers, did, doc_type)
                .await
            {
                Ok(Some(result)) => {
                    return Ok((result.0, result.1, current_level.unwrap()));
                }
                Err(NSError::Disabled(msg)) => {
                    return Err(NSError::Disabled(msg));
                }
                _ => {}
            }
        }
        
        Err(NSError::NotFound(did.to_host_name()))
    }
    
    // 从一组相同优先级的 provider 中并发查询，返回 iat 最大的结果
    async fn query_did_from_providers(
        &self,
        providers: &[&Box<dyn NsProvider>],
        did: &DID,
        doc_type: Option<&str>,
    ) -> Result<Option<(EncodedDocument, u64)>, NSError> {
        if providers.is_empty() {
            return Ok(None);
        }
        
        use futures::future::join_all;
        
        // 收集所有的 futures（不立即 await，保持并发）
        let futures: Vec<_> = providers
            .iter()
            .map(|provider| provider.query_did(did, doc_type, None))
            .collect();
        
        // 并发等待所有 futures 完成
        let results = join_all(futures).await;
        
        // 从所有成功的结果中选择 iat 最大的
        let mut best_doc: Option<EncodedDocument> = None;
        let mut best_iat: Option<u64> = None;
        let mut best_exp: Option<u64> = None;
        
        for result in results {
            match result {
                Ok(doc) => {
                    // 先 clone 一份用于提取 iat
                    let doc_for_iat = doc.clone();
                    
                    // 提取 iat 字段
                    let iat = Self::extract_timestamp(&doc_for_iat, "iat");
                    let exp = Self::extract_timestamp(&doc_for_iat, "exp")
                        .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);

                    if let Some(iat_value) = iat {
                        if best_iat.is_none() || iat_value > best_iat.unwrap() {
                            best_iat = Some(iat_value);
                            best_exp = Some(exp);
                            best_doc = Some(doc);
                        }
                    } else if best_doc.is_none() {
                        // 如果没有 iat 字段，至少保留一个结果
                        best_doc = Some(doc);
                        best_exp = Some(exp);
                    }
                }
                Err(NSError::Disabled(msg)) => {
                    return Err(NSError::Disabled(msg));
                }
                Err(_) => {
                    continue;
                }
            }
        }
        
        Ok(best_doc.map(|doc| (doc, best_exp.unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME))))
    }

    fn extract_timestamp(doc: &EncodedDocument, field: &str) -> Option<u64> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| value.get(field).and_then(|ts| ts.as_u64()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use name_lib::NSError;
    use serde_json::json;

    fn make_doc(iat: u64, exp: u64, marker: &str) -> EncodedDocument {
        EncodedDocument::JsonLd(json!({
            "iat": iat,
            "exp": exp,
            "marker": marker
        }))
    }

    #[derive(Clone, Copy)]
    enum MockErr {
        NotFound,
        Disabled,
    }

    struct MockProvider {
        id: String,
        doc: Option<EncodedDocument>,
        err: Option<MockErr>,
    }

    impl MockProvider {
        fn ok(id: &str, doc: EncodedDocument) -> Self {
            Self {
                id: id.to_string(),
                doc: Some(doc),
                err: None,
            }
        }

        fn err(id: &str, err: MockErr) -> Self {
            Self {
                id: id.to_string(),
                doc: None,
                err: Some(err),
            }
        }
    }

    #[async_trait]
    impl NsProvider for MockProvider {
        fn get_id(&self) -> String {
            self.id.clone()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            _doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if let Some(err) = self.err {
                let e = match err {
                    MockErr::NotFound => NSError::NotFound("mock notfound".into()),
                    MockErr::Disabled => NSError::Disabled("mock disabled".into()),
                };
                Err(e)
            } else {
                Ok(self.doc.as_ref().unwrap().clone())
            }
        }
    }

    #[tokio::test]
    async fn choose_latest_iat_within_same_level() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        let doc_old = make_doc(100, 200, "old");
        let doc_new = make_doc(200, 300, "new");

        q.add_provider(Box::new(MockProvider::ok("p1", doc_old.clone())), 10)
            .await;
        q.add_provider(Box::new(MockProvider::ok("p2", doc_new.clone())), 10)
            .await;

        let (doc, exp, trust) = q.query_did(&did, None, None).await.unwrap();
        assert_eq!(doc, doc_new);
        assert_eq!(exp, 300);
        assert_eq!(trust, 10);
    }

    #[tokio::test]
    async fn prefer_higher_priority_level_even_if_iat_lower() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        let doc_high_priority = make_doc(10, 20, "high");
        let doc_low_priority = make_doc(1_000, 2_000, "low");

        // trust level 数字越小优先级越高
        q.add_provider(Box::new(MockProvider::ok("high", doc_high_priority.clone())), 5)
            .await;
        q.add_provider(Box::new(MockProvider::ok("low", doc_low_priority.clone())), 50)
            .await;

        let (doc, exp, trust) = q.query_did(&did, None, None).await.unwrap();
        assert_eq!(doc, doc_high_priority);
        assert_eq!(exp, 20);
        assert_eq!(trust, 5);
    }

    #[tokio::test]
    async fn respect_max_trust_level_filter() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        let doc_lower_priority = make_doc(50, 100, "low");

        // 高优先级 provider 返回错误
        q.add_provider(
            Box::new(MockProvider::err("high", MockErr::NotFound)),
            5,
        )
        .await;
        // 低优先级 provider 有结果
        q.add_provider(Box::new(MockProvider::ok("low", doc_lower_priority.clone())), 50)
            .await;

        // 限制最大 trust_level = 10，应当直接 NotFound，而不会落到低优先级
        let result = q.query_did(&did, None, Some(10)).await;
        assert!(result.is_err());

        // 不限制时应当拿到低优先级结果
        let (doc, exp, trust) = q.query_did(&did, None, None).await.unwrap();
        assert_eq!(doc, doc_lower_priority);
        assert_eq!(exp, 100);
        assert_eq!(trust, 50);
    }

    #[tokio::test]
    async fn stop_on_disabled_error() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        q.add_provider(
            Box::new(MockProvider::err("high", MockErr::Disabled)),
            5,
        )
        .await;
        q.add_provider(
            Box::new(MockProvider::ok("low", make_doc(1, 2, "low"))),
            50,
        )
        .await;

        let result = q.query_did(&did, None, None).await;
        assert!(matches!(result, Err(NSError::Disabled(_))));
    }

    #[tokio::test]
    async fn disabled_within_same_level_blocks_success() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        // 同一优先级：一个 Disabled，一个成功
        q.add_provider(
            Box::new(MockProvider::err("p1", MockErr::Disabled)),
            10,
        )
        .await;
        q.add_provider(
            Box::new(MockProvider::ok("p2", make_doc(5, 10, "ok"))),
            10,
        )
        .await;

        let result = q.query_did(&did, None, None).await;
        assert!(matches!(result, Err(NSError::Disabled(_))));
    }

    #[tokio::test]
    async fn error_when_no_providers_configured() {
        let q = NameQuery::new();
        let err = q.query("example.com", None).await.unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));

        let did = DID::from_str("did:web:example.com").unwrap();
        let err = q.query_did(&did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }
    
}
