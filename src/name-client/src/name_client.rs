#![allow(unused)]

use crate::dns_provider::DnsProvider;
use crate::doc_cache::DIDDocumentCache;
use crate::name_query::NameQuery;
use crate::provider::RecordType;
use crate::{NameInfo, NsProvider};
use buckyos_kit::get_buckyos_system_etc_dir;
use core::error;
use name_lib::*;

use log::*;
use std::path::PathBuf;

pub struct NameClientConfig {
    pub enable_cache: bool,
    pub local_cache_dir: Option<String>,
}

impl Default for NameClientConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            local_cache_dir:None,
        }
    }
}

pub struct NameClient {
    name_query: NameQuery,
    config: NameClientConfig,
    doc_cache: DIDDocumentCache,
}

impl NameClient {
    pub fn new(config: NameClientConfig) -> Self {
        let mut name_query = NameQuery::new();
        //name_query.add_provider(Box::new(DnsProvider::new(None)));
        //name_query.add_provider(Box::new(ZoneProvider::new()));

        let doc_cache_dir = config
            .local_cache_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir));

        Self {
            name_query,
            config: config,
            doc_cache: DIDDocumentCache::new(doc_cache_dir),
        }
    }

    pub async fn add_provider(&self, provider: Box<dyn NsProvider>) {
        self.name_query.add_provider(provider).await;
    }

    pub fn update_did_cache(&self, did: DID, doc: EncodedDocument) -> NSResult<()> {
        self.doc_cache.update(did, doc);
        Ok(())
    }

    pub fn add_nameinfo_cache(&self, name: &str, info: NameInfo) -> NSResult<()> {
        Ok(())
    }

    pub async fn resolve(&self, name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
        let mut real_name = name.to_string();
        if name.starts_with("did") {
            let name_did = DID::from_str(name);
            if name_did.is_ok() {
                let name_did = name_did.unwrap();
                if name_did.method.as_str() == "web" {
                    info!(
                        "resolve did:web is some as resolve host: {}",
                        name_did.id.as_str()
                    );
                    real_name = name_did.id.clone();
                }
            }
        }

        let name_info = self
            .name_query
            .query(real_name.as_str(), record_type)
            .await?;
        return Ok(name_info);
    }

    pub async fn resolve_did(
        &self,
        did: &DID,
        fragment: Option<&str>,
    ) -> NSResult<EncodedDocument> {
        if self.config.enable_cache {
            if let Some(doc) = self.doc_cache.get(did) {
                return Ok(doc);
            }
        }

        let did_doc = self.name_query.query_did(did).await?;
        //！ 这里不对did_doc进行验证，因为did_doc是来自name_query，name_query已经进行了验证
        if self.config.enable_cache {
            self.doc_cache.update(did.clone(), did_doc.clone());
        }
        return Ok(did_doc);
    }
}
