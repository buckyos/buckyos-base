use buckyos_kit::buckyos_get_unix_timestamp;
use log::{error, info};
use name_lib::DEFAULT_EXPIRE_TIME;
use name_lib::*;
use std::cmp::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    CacheStatus, DocumentBody, DocumentRef, DocumentStatus, EvidenceKind, NameInfo, NsProvider,
    PublishedState, RecordType, ResolvePolicy, ResolvedDocument, DEFAULT_DID_DOC_TYPE,
};

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
        let resolved = self
            .query_did_ex(did, doc_type, max_trust_level, ResolvePolicy::default())
            .await?;
        let exp = Self::extract_timestamp(&resolved.document, "exp")
            .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);
        let trust_level = resolved
            .resolution_metadata
            .authority_rank
            .unwrap_or(i32::MAX);
        Ok((resolved.document, exp, trust_level))
    }

    pub async fn query_did_ex(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        max_trust_level: Option<i32>,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        let providers = self.providers.read().await;
        if providers.is_empty() {
            return Err(NSError::Failed(format!(
                "no provider for {}",
                did.to_host_name()
            )));
        }

        let doc_type = doc_type.unwrap_or(DEFAULT_DID_DOC_TYPE);
        let allowed_max_trust = max_trust_level.unwrap_or(i32::MAX);
        let matched = providers
            .iter()
            .filter(|(provider, trust_level)| {
                *trust_level < allowed_max_trust
                    && Self::provider_supports_did(provider.as_ref())
                    && provider.methods().matches(&did.method)
            })
            .map(|(provider, trust_level)| (provider, *trust_level))
            .collect::<Vec<_>>();

        if matched.is_empty() {
            let method_is_known = providers.iter().any(|(provider, _)| {
                Self::provider_supports_did(provider.as_ref())
                    && provider.methods().is_exact_match(&did.method)
            });
            if method_is_known {
                return Err(NSError::NotFound(format!(
                    "no resolver under trust level {} for {}#{}",
                    allowed_max_trust,
                    did.to_string(),
                    doc_type
                )));
            }
            return Err(NSError::NotFound(format!(
                "DID method not supported: {}",
                did.method
            )));
        }

        let needs_verification = matched
            .iter()
            .all(|(provider, _)| provider.requires_verification(doc_type));

        if !needs_verification {
            return self
                .resolve_unauthenticated_info(did, doc_type, &matched, &policy)
                .await;
        }

        if let Some(resolved) = self
            .resolve_from_published_state(did, doc_type, &matched, &policy)
            .await?
        {
            return Ok(resolved);
        }

        self.resolve_from_document_candidates(did, doc_type, &matched, None, &policy)
            .await
    }

    fn provider_supports_did(provider: &dyn NsProvider) -> bool {
        let caps = provider.caps();
        caps.published_state
            || caps.document_body
            || caps.self_signed_candidate
            || caps.unauthenticated_info
            || caps.negative_state
    }

    async fn resolve_from_published_state(
        &self,
        did: &DID,
        doc_type: &str,
        providers: &[(&Box<dyn NsProvider>, i32)],
        policy: &ResolvePolicy,
    ) -> NSResult<Option<ResolvedDocument>> {
        let mut cursor = 0;
        while cursor < providers.len() {
            let level = providers[cursor].1;
            let start = cursor;
            while cursor < providers.len() && providers[cursor].1 == level {
                cursor += 1;
            }
            let group = &providers[start..cursor];
            let published_group = group
                .iter()
                .copied()
                .filter(|(provider, _)| provider.caps().published_state)
                .collect::<Vec<_>>();

            if published_group.is_empty() {
                continue;
            }

            let states = self
                .query_published_state_group(&published_group, did, doc_type)
                .await?;
            let Some(state) = Self::choose_published_state(states) else {
                continue;
            };

            match state.document_status {
                DocumentStatus::Revoked | DocumentStatus::Tombstoned => {
                    return Err(NSError::Disabled(format!(
                        "{}#{} is {:?}",
                        did.to_string(),
                        doc_type,
                        state.document_status
                    )));
                }
                DocumentStatus::Migrated => {
                    if policy.follow_migration {
                        if let Some(target) = state.migration_target.as_ref() {
                            return Err(NSError::Failed(format!(
                                "{}#{} migrated to {}",
                                did.to_string(),
                                doc_type,
                                target.to_string()
                            )));
                        }
                    }
                    return Err(NSError::Disabled(format!(
                        "{}#{} is migrated",
                        did.to_string(),
                        doc_type
                    )));
                }
                DocumentStatus::Missing => {
                    if !policy.allow_self_signed_when_missing {
                        return Err(NSError::NotFound(format!(
                            "{}#{} missing in method authority",
                            did.to_string(),
                            doc_type
                        )));
                    }
                    return Ok(None);
                }
                DocumentStatus::Expired => {
                    if !policy.allow_cache_when_authority_unavailable {
                        return Err(NSError::NotFound(format!(
                            "{}#{} expired in method authority",
                            did.to_string(),
                            doc_type
                        )));
                    }
                    return Ok(None);
                }
                DocumentStatus::Active => {
                    let bodies = self
                        .fetch_published_bodies(group, state.document_ref.as_ref())
                        .await?;
                    let Some(body) = Self::choose_best_body(bodies, true) else {
                        return Err(NSError::NotFound(format!(
                            "{}#{} has no valid published body",
                            did.to_string(),
                            doc_type
                        )));
                    };

                    return Ok(Some(ResolvedDocument::from_document(
                        body.document,
                        did,
                        doc_type,
                        Some(level),
                        body.resolver_id,
                        body.evidence_kind,
                        Some(&state),
                    )));
                }
            }
        }

        Ok(None)
    }

    async fn query_published_state_group(
        &self,
        providers: &[(&Box<dyn NsProvider>, i32)],
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<PublishedState>> {
        use futures::future::join_all;

        let futures = providers
            .iter()
            .map(|(provider, _)| provider.resolve_published_state(did, doc_type))
            .collect::<Vec<_>>();
        let results = join_all(futures).await;

        let mut states = Vec::new();
        for result in results {
            match result {
                Ok(Some(state)) => states.push(state),
                Ok(None) => {}
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(_) => {}
            }
        }
        Ok(states)
    }

    async fn fetch_published_bodies(
        &self,
        providers: &[(&Box<dyn NsProvider>, i32)],
        doc_ref: Option<&DocumentRef>,
    ) -> NSResult<Vec<DocumentBody>> {
        let Some(doc_ref) = doc_ref else {
            return Ok(Vec::new());
        };

        use futures::future::join_all;

        let body_providers = providers
            .iter()
            .copied()
            .filter(|(provider, _)| provider.caps().document_body)
            .collect::<Vec<_>>();
        let futures = body_providers
            .iter()
            .map(|(provider, _)| provider.fetch_document_body(doc_ref))
            .collect::<Vec<_>>();
        let results = join_all(futures).await;

        let mut bodies = Vec::new();
        for result in results {
            match result {
                Ok(Some(body)) => bodies.push(body),
                Ok(None) => {}
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(_) => {}
            }
        }

        if bodies.is_empty() {
            if let Some(document) = doc_ref.inline_document.as_ref() {
                bodies.push(DocumentBody::anchored(document.clone(), None));
            }
        }
        Ok(bodies)
    }

    async fn resolve_from_document_candidates(
        &self,
        did: &DID,
        doc_type: &str,
        providers: &[(&Box<dyn NsProvider>, i32)],
        published: Option<&PublishedState>,
        _policy: &ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        let mut cursor = 0;
        let mut last_error = None;
        while cursor < providers.len() {
            let level = providers[cursor].1;
            let start = cursor;
            while cursor < providers.len() && providers[cursor].1 == level {
                cursor += 1;
            }
            let group = providers[start..cursor]
                .iter()
                .copied()
                .filter(|(provider, _)| provider.caps().self_signed_candidate)
                .collect::<Vec<_>>();

            if group.is_empty() {
                continue;
            }

            match self.query_candidate_group(&group, did, doc_type).await {
                Ok(bodies) => {
                    if let Some(body) = Self::choose_best_body(bodies, true) {
                        return Ok(ResolvedDocument::from_document(
                            body.document,
                            did,
                            doc_type,
                            Some(level),
                            body.resolver_id,
                            body.evidence_kind,
                            published,
                        ));
                    }
                }
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| NSError::NotFound(did.to_host_name())))
    }

    async fn resolve_unauthenticated_info(
        &self,
        did: &DID,
        doc_type: &str,
        providers: &[(&Box<dyn NsProvider>, i32)],
        _policy: &ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        let mut cursor = 0;
        while cursor < providers.len() {
            let level = providers[cursor].1;
            let start = cursor;
            while cursor < providers.len() && providers[cursor].1 == level {
                cursor += 1;
            }
            let group = providers[start..cursor]
                .iter()
                .copied()
                .filter(|(provider, _)| provider.caps().unauthenticated_info)
                .collect::<Vec<_>>();
            if group.is_empty() {
                continue;
            }

            let bodies = self
                .query_unauthenticated_group(&group, did, doc_type)
                .await?;
            if let Some(body) = Self::choose_best_body(bodies, false) {
                return Ok(ResolvedDocument::from_document(
                    body.document,
                    did,
                    doc_type,
                    Some(level),
                    body.resolver_id,
                    EvidenceKind::UnauthenticatedInfo,
                    None,
                )
                .with_cache_status(CacheStatus::Miss));
            }
        }

        Err(NSError::NotFound(format!(
            "unauthenticated info not found: {}#{}",
            did.to_string(),
            doc_type
        )))
    }

    async fn query_candidate_group(
        &self,
        providers: &[(&Box<dyn NsProvider>, i32)],
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>> {
        use futures::future::join_all;

        let futures = providers
            .iter()
            .map(|(provider, _)| provider.query_self_signed_candidates(did, doc_type))
            .collect::<Vec<_>>();
        let results = join_all(futures).await;

        let mut bodies = Vec::new();
        for result in results {
            match result {
                Ok(mut provider_bodies) => bodies.append(&mut provider_bodies),
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(_) => {}
            }
        }
        Ok(bodies)
    }

    async fn query_unauthenticated_group(
        &self,
        providers: &[(&Box<dyn NsProvider>, i32)],
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>> {
        use futures::future::join_all;

        let futures = providers
            .iter()
            .map(|(provider, _)| provider.query_unauthenticated_info(did, doc_type))
            .collect::<Vec<_>>();
        let results = join_all(futures).await;

        let mut bodies = Vec::new();
        for result in results {
            match result {
                Ok(mut provider_bodies) => bodies.append(&mut provider_bodies),
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(_) => {}
            }
        }
        Ok(bodies)
    }

    fn choose_published_state(states: Vec<PublishedState>) -> Option<PublishedState> {
        states.into_iter().max_by(|left, right| {
            let left_version = left.document_version.unwrap_or_default();
            let right_version = right.document_version.unwrap_or_default();
            left_version.cmp(&right_version).then_with(|| {
                left.authority_seq
                    .unwrap_or_default()
                    .cmp(&right.authority_seq.unwrap_or_default())
            })
        })
    }

    fn choose_best_body(
        bodies: Vec<DocumentBody>,
        requires_verification: bool,
    ) -> Option<DocumentBody> {
        bodies
            .into_iter()
            .filter(|body| {
                if requires_verification && body.evidence_kind == EvidenceKind::UnauthenticatedInfo
                {
                    return false;
                }
                if body.evidence_kind == EvidenceKind::SelfSignedCandidate
                    && !body.document.is_proof()
                {
                    return false;
                }
                if !requires_verification && body.evidence_kind != EvidenceKind::UnauthenticatedInfo
                {
                    return false;
                }
                true
            })
            .max_by(Self::compare_document_body)
    }

    fn compare_document_body(left: &DocumentBody, right: &DocumentBody) -> Ordering {
        Self::compare_evidence_kind(left.evidence_kind, right.evidence_kind)
            .then_with(|| {
                Self::extract_timestamp(&left.document, "version_seq")
                    .unwrap_or_default()
                    .cmp(
                        &Self::extract_timestamp(&right.document, "version_seq")
                            .unwrap_or_default(),
                    )
            })
            .then_with(|| {
                Self::extract_timestamp(&left.document, "iat")
                    .unwrap_or_default()
                    .cmp(&Self::extract_timestamp(&right.document, "iat").unwrap_or_default())
            })
            .then_with(|| left.document.to_string().cmp(&right.document.to_string()))
    }

    fn compare_evidence_kind(left: EvidenceKind, right: EvidenceKind) -> Ordering {
        match left.rank().cmp(&right.rank()) {
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
            Ordering::Equal => Ordering::Equal,
        }
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

        Ok(best_doc.map(|doc| {
            (
                doc,
                best_exp.unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME),
            )
        }))
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
    use crate::{DocumentBody, MethodMatcher, ResolverCaps};
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

    struct ScopedProvider {
        id: String,
        methods: MethodMatcher,
        doc: EncodedDocument,
    }

    #[async_trait]
    impl NsProvider for ScopedProvider {
        fn get_id(&self) -> String {
            self.id.clone()
        }

        fn methods(&self) -> MethodMatcher {
            self.methods.clone()
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
            Ok(self.doc.clone())
        }
    }

    struct SelfSignedJsonLdProvider {
        doc: EncodedDocument,
    }

    #[async_trait]
    impl NsProvider for SelfSignedJsonLdProvider {
        fn get_id(&self) -> String {
            "self-signed-jsonld".to_string()
        }

        fn caps(&self) -> ResolverCaps {
            ResolverCaps {
                published_state: false,
                document_body: false,
                self_signed_candidate: true,
                unauthenticated_info: false,
                negative_state: true,
            }
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
            Ok(self.doc.clone())
        }

        async fn query_self_signed_candidates(
            &self,
            _did: &DID,
            _doc_type: &str,
        ) -> NSResult<Vec<DocumentBody>> {
            Ok(vec![DocumentBody::self_signed(
                self.doc.clone(),
                Some(self.get_id()),
            )])
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
        q.add_provider(
            Box::new(MockProvider::ok("high", doc_high_priority.clone())),
            5,
        )
        .await;
        q.add_provider(
            Box::new(MockProvider::ok("low", doc_low_priority.clone())),
            50,
        )
        .await;

        let (doc, exp, trust) = q.query_did(&did, None, None).await.unwrap();
        assert_eq!(doc, doc_high_priority);
        assert_eq!(exp, 20);
        assert_eq!(trust, 5);
    }

    #[tokio::test]
    async fn method_scoped_resolver_filters_wrong_method_even_with_higher_priority() {
        let q = NameQuery::new();
        let did = DID::from_str("did:bns:alice").unwrap();

        let web_doc = make_doc(300, 400, "web");
        let bns_doc = make_doc(100, 200, "bns");

        q.add_provider(
            Box::new(ScopedProvider {
                id: "web".to_string(),
                methods: MethodMatcher::exact(["web"]),
                doc: web_doc,
            }),
            0,
        )
        .await;
        q.add_provider(
            Box::new(ScopedProvider {
                id: "bns".to_string(),
                methods: MethodMatcher::exact(["bns"]),
                doc: bns_doc.clone(),
            }),
            50,
        )
        .await;

        let (doc, exp, trust) = q.query_did(&did, None, None).await.unwrap();
        assert_eq!(doc, bns_doc);
        assert_eq!(exp, 200);
        assert_eq!(trust, 50);
    }

    #[tokio::test]
    async fn info_doc_type_uses_unauthenticated_path_for_jsonld() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:device.example").unwrap();
        let info_doc = EncodedDocument::JsonLd(json!({
            "iat": 100,
            "exp": 200,
            "info": true
        }));

        q.add_provider(Box::new(MockProvider::ok("info", info_doc.clone())), 10)
            .await;

        let resolved = q
            .query_did_ex(&did, Some("info"), None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, info_doc);
        assert_eq!(resolved.document_metadata.buckyos.doc_type, "info");
        assert_eq!(resolved.resolution_metadata.authority_rank, Some(10));
    }

    #[tokio::test]
    async fn self_signed_candidate_rejects_unsigned_jsonld_for_verified_doc() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();
        let doc = make_doc(100, 200, "unsigned");

        q.add_provider(Box::new(SelfSignedJsonLdProvider { doc }), 10)
            .await;

        let err = q.query_did(&did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn respect_max_trust_level_filter() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        let doc_lower_priority = make_doc(50, 100, "low");

        // 高优先级 provider 返回错误
        q.add_provider(Box::new(MockProvider::err("high", MockErr::NotFound)), 5)
            .await;
        // 低优先级 provider 有结果
        q.add_provider(
            Box::new(MockProvider::ok("low", doc_lower_priority.clone())),
            50,
        )
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

        q.add_provider(Box::new(MockProvider::err("high", MockErr::Disabled)), 5)
            .await;
        q.add_provider(Box::new(MockProvider::ok("low", make_doc(1, 2, "low"))), 50)
            .await;

        let result = q.query_did(&did, None, None).await;
        assert!(matches!(result, Err(NSError::Disabled(_))));
    }

    #[tokio::test]
    async fn disabled_within_same_level_blocks_success() {
        let q = NameQuery::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        // 同一优先级：一个 Disabled，一个成功
        q.add_provider(Box::new(MockProvider::err("p1", MockErr::Disabled)), 10)
            .await;
        q.add_provider(Box::new(MockProvider::ok("p2", make_doc(5, 10, "ok"))), 10)
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
