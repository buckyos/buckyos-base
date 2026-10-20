//! 来源注册:每个 method 至多一个 authority,有序的 trust / normal 来源。
//! 免验证 doc_type(Info)是 method 契约,不由来源运行时协商。

use super::opts::{ResolveOpts, Scope};
use super::source::{RegisteredSource, Source, SourceTier};
use log::warn;
use name_lib::{DidDocType, DID};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Default)]
pub struct MethodSources {
    pub authority: Option<RegisteredSource>,
    pub trust: Vec<RegisteredSource>,
    pub normal: Vec<RegisteredSource>,
    pub no_proof_doc_types: HashSet<DidDocType>,
}

impl MethodSources {
    fn new() -> Self {
        let mut no_proof_doc_types = HashSet::new();
        no_proof_doc_types.insert(DidDocType::Info);
        Self {
            authority: None,
            trust: Vec::new(),
            normal: Vec::new(),
            no_proof_doc_types,
        }
    }
}

#[derive(Default)]
pub struct SourceRegistry {
    methods: RwLock<HashMap<String, MethodSources>>,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, method: impl Into<String>, registered: RegisteredSource) {
        let method = method.into();
        let mut methods = self.methods.write().unwrap();
        let entry = methods
            .entry(method.clone())
            .or_insert_with(MethodSources::new);
        match registered.sref.tier {
            SourceTier::Authority => {
                if entry.authority.is_some() {
                    warn!(
                        "method {} already has an authority source, ignoring {}",
                        method, registered.sref.id
                    );
                    return;
                }
                entry.authority = Some(registered);
            }
            SourceTier::Trust => entry.trust.push(registered),
            SourceTier::Normal => entry.normal.push(registered),
        }
    }

    pub fn set_method_authority(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.register(method, RegisteredSource::new(source, SourceTier::Authority));
    }

    pub fn add_method_trust(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.register(method, RegisteredSource::new(source, SourceTier::Trust));
    }

    pub fn add_method_normal(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.register(method, RegisteredSource::new(source, SourceTier::Normal));
    }

    /// 只在 current-zone 自举时可用的 normal 来源(DNS TXT 等)。
    pub fn add_zone_bootstrap_normal(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.register(
            method,
            RegisteredSource::new(source, SourceTier::Normal).zone_bootstrap(),
        );
    }

    pub fn set_no_proof_doc_types(&self, method: &str, doc_types: HashSet<DidDocType>) {
        let mut methods = self.methods.write().unwrap();
        methods
            .entry(method.to_string())
            .or_insert_with(MethodSources::new)
            .no_proof_doc_types = doc_types;
    }

    pub fn is_no_proof_doc_type(&self, method: &str, doc_type: &DidDocType) -> bool {
        let methods = self.methods.read().unwrap();
        match methods.get(method) {
            Some(entry) => entry.no_proof_doc_types.contains(doc_type),
            None => *doc_type == DidDocType::Info,
        }
    }

    pub fn has_method(&self, method: &str) -> bool {
        self.methods.read().unwrap().contains_key(method)
    }

    pub fn authority(&self, method: &str) -> Option<RegisteredSource> {
        self.methods
            .read()
            .unwrap()
            .get(method)
            .and_then(|entry| entry.authority.clone())
    }

    /// 顺序:authority > trust > normal;owner 只查询 authority。
    /// `network_sources` 不过滤已有来源缓存,过滤发生在 `request_source`。
    pub fn providers_for(&self, did: &DID, doc_type: &DidDocType, opts: &ResolveOpts) -> Vec<RegisteredSource> {
        let methods = self.methods.read().unwrap();
        let Some(entry) = methods.get(&did.method) else {
            return Vec::new();
        };
        let mut providers = Vec::new();
        if let Some(authority) = entry.authority.as_ref() {
            providers.push(authority.clone());
        }
        if *doc_type == DidDocType::Owner {
            return providers;
        }
        providers.extend(entry.trust.iter().cloned());
        for normal in entry.normal.iter() {
            if normal.zone_bootstrap_only {
                let allowed = match &opts.scope {
                    Scope::Zone(zone) => zone == did,
                    Scope::Host => false,
                };
                if !allowed {
                    continue;
                }
            }
            providers.push(normal.clone());
        }
        providers
    }

    pub fn all_sources(&self) -> Vec<(String, RegisteredSource)> {
        let methods = self.methods.read().unwrap();
        let mut all = Vec::new();
        for (method, entry) in methods.iter() {
            if let Some(authority) = entry.authority.as_ref() {
                all.push((method.clone(), authority.clone()));
            }
            for source in entry.trust.iter().chain(entry.normal.iter()) {
                all.push((method.clone(), source.clone()));
            }
        }
        all
    }
}
