//! 普通名字解析(DNS 语义)的有序 provider 列表,与 DID 解析管线相互独立。

use log::{error, info};
use name_lib::*;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{NameInfo, NsProvider, RecordType};

pub struct NameQuery {
    dns_providers: Arc<RwLock<Vec<Box<dyn NsProvider>>>>,
}

impl Default for NameQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl NameQuery {
    pub fn new() -> NameQuery {
        NameQuery {
            dns_providers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 注册普通名字解析(DNS 语义)的 provider。
    pub async fn add_dns_provider(&self, provider: Box<dyn NsProvider>) {
        self.dns_providers.write().await.push(provider);
    }

    pub async fn query(&self, name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
        let providers = self.dns_providers.read().await;
        if providers.is_empty() {
            let msg = format!("No provider found for {}", name);
            error!("{}", msg);
            return Err(NSError::Failed(msg));
        }

        let record_type = record_type.unwrap_or_default();

        for provider in providers.iter() {
            match provider.query(name, Some(record_type), None).await {
                Ok(info) => {
                    info!("Resolved {} to {:?}", name, info);
                    return Ok(info);
                }
                Err(_e) => {
                    continue;
                }
            }
        }
        Err(NSError::NotFound(String::from(name)))
    }
}
