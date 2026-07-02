use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use log::{error, info};
use name_lib::DEFAULT_EXPIRE_TIME;
use name_lib::*;
use std::cmp::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    CacheStatus, DidDocType, DocumentBody, DocumentRef, DocumentStatus, EvidenceKind, NameInfo,
    NsProvider, OwnerDocumentPolicy, PublishedState, RecordType, ResolvePolicy, ResolveWarning,
    ResolvedDocument,
};

/// 候选文档在验证阶段被拒绝的原因。契约违规会被记录为 warning 并静默丢弃该候选，
/// 其它候选仍可能验证成功；`Failed` 是具体的验证/递归失败原因，当所有候选都失败时
/// 会把最后一个 `Failed` 原因作为整体解析错误返回，而不是笼统的 NotFound。
enum CandidateRejection {
    ContractViolation(ResolveWarning),
    Failed(NSError),
}

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
        doc_type: Option<DidDocType>,
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
        doc_type: Option<DidDocType>,
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

        let doc_type = doc_type.unwrap_or_default();
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

        // 契约假设：同一 doc_type 在同一 DID method 内的所有 resolver 必须对
        // "是否需要验证" 达成一致（这是 method 的显式声明，不是运行时协商）。
        // 用 .any() 而不是 .all()：任一 provider 认为该 doc_type 需要验证，就必须
        // 走验证路径，避免一个不严谨的 provider 把所有 provider 一起拖到
        // unauthenticated 路径，造成本该验证的 Document 绕过 owner 验签。
        let needs_verification = matched
            .iter()
            .any(|(provider, _)| provider.requires_verification(&doc_type));

        if !needs_verification {
            return self
                .resolve_unauthenticated_info(did, &doc_type, &matched, &policy)
                .await;
        }

        // 0. 本地测试/运维覆盖，语义类似 hosts 文件。只对需要验证的 Document 路径
        // 生效（不用于 Info 轻量路径），在查 PublishedState 之前生效，owner 递归
        // 复用同一个 policy 时同样会命中。
        if let Some(store) = policy.local_authority_override.as_ref() {
            if let Some(document) = store.get(did, &doc_type) {
                return Ok(ResolvedDocument::from_document(
                    document,
                    did,
                    &doc_type,
                    None,
                    Some("local-authority-override".to_string()),
                    EvidenceKind::AnchoredDocumentBody,
                    None,
                )
                .with_warning(ResolveWarning::LocalAuthorityOverride));
            }
        }

        if let Some(resolved) = self
            .resolve_from_published_state(did, &doc_type, &matched, &policy)
            .await?
        {
            return Ok(resolved);
        }

        self.resolve_from_document_candidates(did, &doc_type, &matched, None, &policy)
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
        doc_type: &DidDocType,
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
                        if let Some(target) = state.migration_target.clone() {
                            let next_policy = policy.descend(&target, doc_type)?;
                            let resolved = Box::pin(self.query_did_ex(
                                &target,
                                Some(doc_type.clone()),
                                None,
                                next_policy,
                            ))
                            .await?;
                            return Ok(Some(resolved));
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
                    let (body, warnings) = self
                        .verify_and_select_document(
                            did,
                            doc_type,
                            group,
                            bodies,
                            Some(&state),
                            policy,
                        )
                        .await?;

                    let mut resolved = ResolvedDocument::from_document(
                        body.document,
                        did,
                        doc_type,
                        Some(level),
                        body.resolver_id,
                        body.evidence_kind,
                        Some(&state),
                    );
                    for warning in warnings {
                        resolved = resolved.with_warning(warning);
                    }
                    return Ok(Some(resolved));
                }
            }
        }

        Ok(None)
    }

    async fn query_published_state_group(
        &self,
        providers: &[(&Box<dyn NsProvider>, i32)],
        did: &DID,
        doc_type: &DidDocType,
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
        doc_type: &DidDocType,
        providers: &[(&Box<dyn NsProvider>, i32)],
        published: Option<&PublishedState>,
        policy: &ResolvePolicy,
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
                    match self
                        .verify_and_select_document(
                            did, doc_type, &group, bodies, published, policy,
                        )
                        .await
                    {
                        Ok((body, warnings)) => {
                            let mut resolved = ResolvedDocument::from_document(
                                body.document,
                                did,
                                doc_type,
                                Some(level),
                                body.resolver_id,
                                body.evidence_kind,
                                published,
                            );
                            for warning in warnings {
                                resolved = resolved.with_warning(warning);
                            }
                            return Ok(resolved);
                        }
                        Err(err) => last_error = Some(err),
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
        doc_type: &DidDocType,
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
            if let Some(body) = Self::choose_best_unauthenticated_body(bodies) {
                return Ok(ResolvedDocument::from_unauthenticated_info(
                    body.document,
                    did,
                    doc_type,
                    Some(level),
                    body.resolver_id,
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
        doc_type: &DidDocType,
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
        doc_type: &DidDocType,
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

    fn choose_best_unauthenticated_body(bodies: Vec<DocumentBody>) -> Option<DocumentBody> {
        bodies
            .into_iter()
            .filter(|body| body.evidence_kind == EvidenceKind::UnauthenticatedInfo)
            .max_by(Self::compare_document_body)
    }

    /// 对一组候选文档做验证并选出最优者（设计文档第 6/9 节）。owner 是递归基：
    /// 当 (did, doc_type) 本身就是 owner 递归基时，验证根落到 method authority
    /// （文档自证的 key）；否则递归解析文档自声明 owner 的 "owner" 文档作为验证根。
    /// 只有通过验证的候选才参与 `compare_document_body` 排序；契约违规的候选记录
    /// warning 后静默丢弃，其它候选仍可能验证成功；全部候选都失败时，返回最后一个
    /// 具体的失败原因，而不是笼统的 NotFound。
    async fn verify_and_select_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        providers: &[(&Box<dyn NsProvider>, i32)],
        bodies: Vec<DocumentBody>,
        published: Option<&PublishedState>,
        policy: &ResolvePolicy,
    ) -> NSResult<(DocumentBody, Vec<ResolveWarning>)> {
        let is_owner_root = providers
            .iter()
            .any(|(provider, _)| provider.is_owner_root(did, doc_type, published));

        let mut verified: Vec<(DocumentBody, Vec<ResolveWarning>)> = Vec::new();
        let mut warnings: Vec<ResolveWarning> = Vec::new();
        let mut last_err: Option<NSError> = None;

        for body in bodies {
            match self
                .verify_document_candidate(did, doc_type, &body, is_owner_root, published, policy)
                .await
            {
                Ok(candidate_warnings) => verified.push((body, candidate_warnings)),
                Err(CandidateRejection::ContractViolation(warning)) => warnings.push(warning),
                Err(CandidateRejection::Failed(err)) => last_err = Some(err),
            }
        }

        match verified
            .into_iter()
            .max_by(|(a, _), (b, _)| Self::compare_document_body(a, b))
        {
            Some((body, mut candidate_warnings)) => {
                candidate_warnings.extend(warnings);
                Ok((body, candidate_warnings))
            }
            None => Err(last_err.unwrap_or_else(|| {
                NSError::NotFound(format!(
                    "{}#{} has no verifiable document body",
                    did.to_string(),
                    doc_type
                ))
            })),
        }
    }

    async fn verify_document_candidate(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        body: &DocumentBody,
        is_owner_root: bool,
        published: Option<&PublishedState>,
        policy: &ResolvePolicy,
    ) -> Result<Vec<ResolveWarning>, CandidateRejection> {
        if body.evidence_kind == EvidenceKind::UnauthenticatedInfo {
            return Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: EvidenceKind::UnauthenticatedInfo.as_str().to_string(),
                    reason: "doc_type requires verification".to_string(),
                },
            ));
        }
        // self-signed 语义上必须能验证，即 doc.is_proof() == true；JsonLd 结构上
        // 不可能携带签名，属于证据契约违规（设计文档第 13 节第 11 条）。
        if body.evidence_kind == EvidenceKind::SelfSignedCandidate && !body.document.is_proof() {
            return Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: EvidenceKind::SelfSignedCandidate.as_str().to_string(),
                    reason: "unsigned JsonLd body".to_string(),
                },
            ));
        }

        if is_owner_root {
            self.verify_owner_root_candidate(did, body, published).await
        } else {
            self.verify_owned_candidate(did, doc_type, body, published, policy)
                .await
        }
    }

    /// 递归基：验证根是 method authority，即文档自证的 key（例如 owner 文档自己
    /// 声明的 verificationMethod）。
    async fn verify_owner_root_candidate(
        &self,
        did: &DID,
        body: &DocumentBody,
        _published: Option<&PublishedState>,
    ) -> Result<Vec<ResolveWarning>, CandidateRejection> {
        // 结构上无法识别成任何已知 DID Document 类型的证据，属于契约违规而不是
        // "验证失败"（设计文档第 13 节第 11 条的精神）：静默丢弃并记 warning，让其它
        // 候选仍有机会验证成功，而不是让一个格式不认识的候选直接中断整体解析。
        let parsed = parse_did_doc(body.document.clone()).map_err(|err| {
            CandidateRejection::ContractViolation(ResolveWarning::EvidenceContractViolation {
                evidence: body.evidence_kind.as_str().to_string(),
                reason: format!("not a recognizable document: {}", err),
            })
        })?;
        let (decoding_key, _jwk) = parsed.get_auth_key(None).ok_or_else(|| {
            CandidateRejection::Failed(NSError::Failed(format!(
                "{} owner-root candidate has no usable auth key",
                did.to_string()
            )))
        })?;

        if body.document.is_proof() {
            let EncodedDocument::Jwt(jwt) = &body.document else {
                unreachable!("is_proof() only true for Jwt documents");
            };
            decode_json_from_jwt_with_pk(jwt, &decoding_key).map_err(|err| {
                CandidateRejection::Failed(NSError::Failed(format!(
                    "{} owner-root candidate signature verification failed: {}",
                    did.to_string(),
                    err
                )))
            })?;
        } else if body.evidence_kind != EvidenceKind::AnchoredDocumentBody {
            // 非 JWT 且不是 AnchoredDocumentBody（例如错误地混进来的
            // UnauthenticatedInfo），无法建立信任。AnchoredDocumentBody 本身的信任
            // 来自获取它的 resolver 的写入权限保证（did:web canonical endpoint、
            // BNS content_hash 锚定等，设计文档第 9 节），是否额外要求签名是
            // policy 决定的事，不是这里的硬性门槛。
            return Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: body.evidence_kind.as_str().to_string(),
                    reason: "unsigned owner-root body with untrusted evidence kind".to_string(),
                },
            ));
        }

        Ok(Vec::new())
    }

    /// 递归步：验证根来自递归解析出的 owner 文档。
    async fn verify_owned_candidate(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        body: &DocumentBody,
        published: Option<&PublishedState>,
        policy: &ResolvePolicy,
    ) -> Result<Vec<ResolveWarning>, CandidateRejection> {
        // 同上：结构上无法识别的候选是契约违规，静默丢弃而不是中断整体解析。
        let parsed = parse_did_doc(body.document.clone()).map_err(|err| {
            CandidateRejection::ContractViolation(ResolveWarning::EvidenceContractViolation {
                evidence: body.evidence_kind.as_str().to_string(),
                reason: format!("not a recognizable document: {}", err),
            })
        })?;

        let declared_owner_str = parsed.get_iss().ok_or_else(|| {
            CandidateRejection::ContractViolation(ResolveWarning::EvidenceContractViolation {
                evidence: body.evidence_kind.as_str().to_string(),
                reason: "document declares no owner/issuer".to_string(),
            })
        })?;
        let declared_owner = DID::from_str(&declared_owner_str).map_err(|err| {
            CandidateRejection::Failed(NSError::Failed(format!(
                "{}#{} declared owner {} is not a valid DID: {}",
                did.to_string(),
                doc_type,
                declared_owner_str,
                err
            )))
        })?;

        // T1.3: 文档自声明的 owner 必须与权威发布源记录的 effective_owner 一致；
        // 不能让文档内部声明反向改变 Registry owner（设计文档第 13 节第 5 条）。
        if let Some(state) = published {
            if let Some(authority_owner) = state.effective_owner.as_ref() {
                if authority_owner != &declared_owner {
                    return Err(CandidateRejection::Failed(NSError::OwnerConflict(format!(
                        "{}#{} declares owner {} but authority records owner {}",
                        did.to_string(),
                        doc_type,
                        declared_owner.to_string(),
                        authority_owner.to_string()
                    ))));
                }
            }
        }

        // 递归解析 owner 的 "owner" 文档：owner 是递归基，这里必须用
        // for_authority_lookup() 收紧后的 policy（关闭 self-signed/gossip fallback），
        // 并用 descend() 做环路/深度检查。
        let next_policy = policy
            .for_authority_lookup()
            .descend(&declared_owner, &DidDocType::Owner)
            .map_err(CandidateRejection::Failed)?;
        let owner_resolved = Box::pin(self.query_did_ex(
            &declared_owner,
            Some(DidDocType::Owner),
            None,
            next_policy,
        ))
        .await
        .map_err(|err| {
            CandidateRejection::Failed(NSError::Failed(format!(
                "resolve owner {} for {}#{} failed: {}",
                declared_owner.to_string(),
                did.to_string(),
                doc_type,
                err
            )))
        })?;

        let owner_document =
            OwnerDocument::decode(&owner_resolved.document, None).map_err(|err| {
                CandidateRejection::Failed(NSError::Failed(format!(
                    "owner document {} is not a valid OwnerDocument: {}",
                    declared_owner.to_string(),
                    err
                )))
            })?;
        let (decoding_key, _jwk) = owner_document.get_auth_key(None).ok_or_else(|| {
            CandidateRejection::Failed(NSError::Failed(format!(
                "owner document {} has no usable auth key",
                declared_owner.to_string()
            )))
        })?;

        // T2.1: owner 声明的 revoke_before_iat 门槛，在验签通过之前先做（拒绝比签名
        // 校验更早失败没有安全意义上的差别，但能在候选明显过期时更快拒绝）。
        let owner_policy = OwnerDocumentPolicy::from_owner_document(&owner_document);
        if let Some(revoke_before_iat) = owner_policy.revoke_before_iat {
            let iat = body
                .document
                .clone()
                .to_json_value()
                .ok()
                .and_then(|value| value.get("iat").and_then(|ts| ts.as_u64()));
            if let Some(iat) = iat {
                if iat <= revoke_before_iat {
                    return Err(CandidateRejection::Failed(NSError::Disabled(format!(
                        "{}#{} iat {} is not after owner revoke_before_iat {}",
                        did.to_string(),
                        doc_type,
                        iat,
                        revoke_before_iat
                    ))));
                }
            }
        }

        // T1.2: 真正用 owner key 验证 JWT 签名。默认 key 失败时，回退尝试 owner 的
        // 历史 key（例如刚发生过 key rotation，旧文档仍然用旧 key 签名）；用历史 key
        // 验证成功时记一条 SignedByHistoricalKey warning，而不是直接判定验证失败
        // （owner 正常 key rotation 不会自动否决旧 key 历史上合法签发的文档，
        // 设计文档第 6 节第 3 条）。
        let mut warnings = Vec::new();
        if body.document.is_proof() {
            let EncodedDocument::Jwt(jwt) = &body.document else {
                unreachable!("is_proof() only true for Jwt documents");
            };
            if decode_json_from_jwt_with_pk(jwt, &decoding_key).is_err() {
                let verified_with_historical_key = owner_document
                    .get_historical_keys()
                    .into_iter()
                    .any(|(_kid, jwk)| match DecodingKey::from_jwk(&jwk) {
                        Ok(historical_key) => {
                            decode_json_from_jwt_with_pk(jwt, &historical_key).is_ok()
                        }
                        Err(_) => false,
                    });
                if !verified_with_historical_key {
                    return Err(CandidateRejection::Failed(NSError::Failed(format!(
                        "{}#{} signature verification failed against owner {}",
                        did.to_string(),
                        doc_type,
                        declared_owner.to_string(),
                    ))));
                }
                warnings.push(ResolveWarning::SignedByHistoricalKey);
            }
        } else if body.evidence_kind != EvidenceKind::AnchoredDocumentBody {
            // 非 JWT 且不是 AnchoredDocumentBody，无法建立信任。AnchoredDocumentBody
            // 的信任来自获取它的 resolver 的写入权限保证（did:web canonical
            // endpoint、BNS content_hash 锚定等），是否额外要求签名是 policy 决定的
            //事（设计文档第 9 节 Active 分支注释），不是这里的硬性门槛；owner 链路
            // 已经在上面被递归解析和校验过，是不变的信任来源。
            return Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: body.evidence_kind.as_str().to_string(),
                    reason: "unsigned body with untrusted evidence kind".to_string(),
                },
            ));
        }

        Ok(warnings)
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
        doc_type: Option<DidDocType>,
    ) -> Result<Option<(EncodedDocument, u64)>, NSError> {
        if providers.is_empty() {
            return Ok(None);
        }

        use futures::future::join_all;

        // 收集所有的 futures（不立即 await，保持并发）
        let futures: Vec<_> = providers
            .iter()
            .map(|provider| provider.query_did(did, doc_type.clone(), None))
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
    use crate::{DocumentBody, MethodMatcher, NameStatus, OwnerSource, ResolverCaps};
    use async_trait::async_trait;
    use jsonwebtoken::{jwk::Jwk, EncodingKey};
    use name_lib::NSError;
    use serde_json::json;

    // 固定的测试用 Ed25519 keypair（owner key）。
    const OWNER_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
    const OWNER_PUBLIC_JWK_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
    // 另一把不同的 Ed25519 keypair，用来构造"用错误私钥签名"的场景。
    const OTHER_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----";
    const OTHER_PUBLIC_JWK_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";

    fn owner_signing_key() -> (EncodingKey, Jwk) {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": OWNER_PUBLIC_JWK_X
        }))
        .unwrap();
        (
            EncodingKey::from_ed_pem(OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
            jwk,
        )
    }

    fn other_signing_key() -> EncodingKey {
        EncodingKey::from_ed_pem(OTHER_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn other_signing_key_jwk() -> Jwk {
        serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": OTHER_PUBLIC_JWK_X
        }))
        .unwrap()
    }

    /// 相对当前真实时间的偏移量，避免 JWT 的 `exp` 校验把测试用的小整数 iat
    /// 当成"很久以前过期"。
    fn ts(offset_secs: i64) -> u64 {
        (buckyos_get_unix_timestamp() as i64 + offset_secs) as u64
    }

    fn build_owner_doc(owner_did: &DID, valid_iat: Option<u64>) -> EncodedDocument {
        let (key, jwk) = owner_signing_key();
        let mut owner = OwnerDocument::new(
            owner_did.clone(),
            "owner".to_string(),
            "owner@test".to_string(),
            jwk,
        );
        owner.version_seq = Some(0);
        owner.valid_iat = valid_iat;
        owner.encode(Some(&key)).unwrap()
    }

    /// 构造一个刚发生过 key rotation 的 owner 文档：`#main_key` 是新 key（owner
    /// signing key），另外保留一个 `#legacy_key` 历史条目（"other" key）。
    /// `OwnerDocument::new` 只会生成单个 verification method，`VerificationMethodNode`
    /// 又是 crate-private 类型，所以这里绕过构造函数直接拼 JSON 再反序列化。
    fn build_owner_doc_with_legacy_key(owner_did: &DID, new_key: &EncodingKey) -> EncodedDocument {
        let (_, new_jwk) = owner_signing_key();
        let legacy_jwk = other_signing_key_jwk();
        let now = ts(0);
        let json_doc = json!({
            "id": owner_did.to_string(),
            "verificationMethod": [
                {
                    "type": "Ed25519VerificationKey2020",
                    "id": "#main_key",
                    "controller": owner_did.to_string(),
                    "publicKeyJwk": new_jwk,
                },
                {
                    "type": "Ed25519VerificationKey2020",
                    "id": "#legacy_key",
                    "controller": owner_did.to_string(),
                    "publicKeyJwk": legacy_jwk,
                },
            ],
            "authentication": ["#main_key"],
            "exp": now + 3600 * 24 * 365,
            "iat": now,
            "version_seq": 0,
            "name": "owner",
            "display_name": "owner@test",
        });
        let owner: OwnerDocument = serde_json::from_value(json_doc).unwrap();
        owner.encode(Some(new_key)).unwrap()
    }

    fn build_zone_doc_signed_by(
        zone_did: &DID,
        owner_did: &DID,
        iat: u64,
        marker: &str,
        key: &EncodingKey,
    ) -> EncodedDocument {
        let (_, owner_jwk) = owner_signing_key();
        let mut zone = ZoneDocument::new(zone_did.clone(), owner_did.clone(), owner_jwk);
        zone.iat = iat;
        zone.exp = iat + 3600 * 24 * 365;
        zone.version_seq = Some(1);
        zone.extra_info.insert("marker".to_string(), json!(marker));
        zone.encode(Some(key)).unwrap()
    }

    fn build_zone_doc(zone_did: &DID, owner_did: &DID, iat: u64, marker: &str) -> EncodedDocument {
        let (key, _) = owner_signing_key();
        build_zone_doc_signed_by(zone_did, owner_did, iat, marker, &key)
    }

    /// 通用 mock provider：按 (did, doc_type) 精确匹配返回预先注册好的文档，
    /// 用来搭建 owner -> 子文档 这样的多层递归链路。
    struct DidDocProvider {
        id: String,
        caps: ResolverCaps,
        docs: Vec<(DID, String, EncodedDocument)>,
        is_owner_root_override: Option<bool>,
        requires_verification_override: Option<bool>,
    }

    impl DidDocProvider {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                caps: ResolverCaps::default(),
                docs: Vec::new(),
                is_owner_root_override: None,
                requires_verification_override: None,
            }
        }

        fn with_doc(mut self, did: DID, doc_type: &str, doc: EncodedDocument) -> Self {
            self.docs.push((did, doc_type.to_string(), doc));
            self
        }

        fn with_caps(mut self, caps: ResolverCaps) -> Self {
            self.caps = caps;
            self
        }

        fn with_is_owner_root_override(mut self, value: bool) -> Self {
            self.is_owner_root_override = Some(value);
            self
        }

        fn with_requires_verification(mut self, value: bool) -> Self {
            self.requires_verification_override = Some(value);
            self
        }
    }

    #[async_trait]
    impl NsProvider for DidDocProvider {
        fn get_id(&self) -> String {
            self.id.clone()
        }

        fn caps(&self) -> ResolverCaps {
            self.caps
        }

        fn is_owner_root(
            &self,
            _did: &DID,
            doc_type: &DidDocType,
            _published: Option<&PublishedState>,
        ) -> bool {
            self.is_owner_root_override
                .unwrap_or(doc_type == &DidDocType::Owner)
        }

        fn requires_verification(&self, doc_type: &DidDocType) -> bool {
            self.requires_verification_override
                .unwrap_or(doc_type != &DidDocType::Info)
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
            did: &DID,
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            let wanted = doc_type.unwrap_or_default();
            self.docs
                .iter()
                .find(|(d, t, _)| d == did && t == wanted.as_str())
                .map(|(_, _, doc)| doc.clone())
                .ok_or_else(|| NSError::NotFound("no matching doc".into()))
        }
    }

    /// mock 一个只提供 PublishedState（不提供 self-signed candidate）的权威发布源。
    struct PublishedStateProvider {
        state: PublishedState,
    }

    #[async_trait]
    impl NsProvider for PublishedStateProvider {
        fn get_id(&self) -> String {
            "published-state-provider".to_string()
        }

        fn caps(&self) -> ResolverCaps {
            ResolverCaps {
                published_state: true,
                document_body: true,
                self_signed_candidate: false,
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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Err(NSError::NotFound("published-state only".into()))
        }

        async fn resolve_published_state(
            &self,
            did: &DID,
            doc_type: &DidDocType,
        ) -> NSResult<Option<PublishedState>> {
            // 只对自己配置的 (did, doc_type) 生效，避免在递归解析其它 (did, doc_type)
            // 时（例如递归解析 owner 文档）被这个 mock 错误地"抢答"。
            if did == &self.state.did && doc_type.as_str() == self.state.doc_type {
                Ok(Some(self.state.clone()))
            } else {
                Ok(None)
            }
        }
    }

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
            _doc_type: Option<DidDocType>,
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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Ok(self.doc.clone())
        }

        async fn query_self_signed_candidates(
            &self,
            _did: &DID,
            _doc_type: &DidDocType,
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
            _doc_type: Option<DidDocType>,
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

    // 这几个测试验证的是 trust_level 分组、method 过滤、iat 排序这些与文档验证无关
    // 的通用选择机制，用 doc_type = "info" 走免验证的轻量路径，避免为每个用例都
    // 搭建一条完整的 owner 签名链（那条链由下面 owner 递归相关的测试覆盖）。
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

        let (doc, exp, trust) = q
            .query_did(&did, Some(DidDocType::Info), None)
            .await
            .unwrap();
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

        let (doc, exp, trust) = q
            .query_did(&did, Some(DidDocType::Info), None)
            .await
            .unwrap();
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

        let (doc, exp, trust) = q
            .query_did(&did, Some(DidDocType::Info), None)
            .await
            .unwrap();
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
            .query_did_ex(&did, Some(DidDocType::Info), None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, info_doc);
        assert_eq!(resolved.document_metadata.buckyos.doc_type, "info");
        assert_eq!(resolved.document_metadata.buckyos.document_status, None);
        assert_eq!(resolved.document_metadata.deactivated, None);
        assert_eq!(resolved.resolution_metadata.authority_rank, Some(10));
    }

    struct MixedCapsProvider {
        id: String,
        doc: EncodedDocument,
        caps: ResolverCaps,
        requires_verification: bool,
    }

    #[async_trait]
    impl NsProvider for MixedCapsProvider {
        fn get_id(&self) -> String {
            self.id.clone()
        }

        fn caps(&self) -> ResolverCaps {
            self.caps
        }

        fn requires_verification(&self, _doc_type: &DidDocType) -> bool {
            self.requires_verification
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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Ok(self.doc.clone())
        }
    }

    #[tokio::test]
    async fn requires_verification_any_provider_forces_verified_path() {
        let q = NameQuery::new();
        let zone_did = DID::from_str("did:web:mixed.example").unwrap();
        let owner_did = DID::new("bns", "mixed-owner");

        // 同一 method 下两个 provider 对同一 doc_type 的 requires_verification 声明不一致：
        // 一个认为免验证（lenient），一个认为需要验证（strict）。修复后应按 .any() 走验证路径，
        // 而不是被 lenient provider 拖到 unauthenticated 路径。lenient 的文档内容和真正的
        // owner 签名链完全无关，如果解析结果拿到它，说明错误地走了 unauthenticated 路径。
        let lenient_doc = make_doc(100, 200, "unauth-declared-no-verify");
        let owner_doc = build_owner_doc(&owner_did, None);
        let zone_doc = build_zone_doc(
            &zone_did,
            &owner_did,
            ts(50),
            "verified-declared-needs-verify",
        );

        q.add_provider(
            Box::new(MixedCapsProvider {
                id: "lenient".to_string(),
                doc: lenient_doc.clone(),
                caps: ResolverCaps {
                    published_state: false,
                    document_body: false,
                    self_signed_candidate: false,
                    unauthenticated_info: true,
                    negative_state: false,
                },
                requires_verification: false,
            }),
            10,
        )
        .await;

        q.add_provider(
            Box::new(
                DidDocProvider::new("strict")
                    .with_doc(zone_did.clone(), "zone", zone_doc.clone())
                    .with_doc(owner_did.clone(), "owner", owner_doc)
                    .with_requires_verification(true),
            ),
            20,
        )
        .await;

        let resolved = q
            .query_did_ex(
                &zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
    }

    #[tokio::test]
    async fn owner_recursion_resolves_zone_via_owner_document() {
        // T1.1: 两层递归 —— 普通 zone 文档递归解析其 owner 文档，owner 文档的验证根
        // 落到 method authority（自证 key）。
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "zone1");
        let owner_did = DID::new("bns", "owner1");

        let owner_doc = build_owner_doc(&owner_did, None);
        let zone_doc = build_zone_doc(&zone_did, &owner_did, ts(1000), "zone-v1");

        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(zone_did.clone(), "zone", zone_doc.clone())
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
            10,
        )
        .await;

        let resolved = q
            .query_did_ex(
                &zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
    }

    #[tokio::test]
    async fn contract_violating_candidate_recorded_as_warning_while_valid_one_wins() {
        // T5.1: 一个不可验证的候选（unsigned self-signed JsonLd）不应该让整体解析
        // 失败——它只是被丢弃并记一条 EvidenceContractViolation warning，真正可验证
        // 的候选仍然胜出。
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "zone-with-bad-candidate");
        let owner_did = DID::new("bns", "owner-with-bad-candidate");

        let owner_doc = build_owner_doc(&owner_did, None);
        let zone_doc = build_zone_doc(&zone_did, &owner_did, ts(1000), "good-candidate");
        let unsigned_doc = make_doc(ts(2000), ts(2000) + 1000, "unsigned-candidate");

        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(zone_did.clone(), "zone", zone_doc.clone())
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
            10,
        )
        .await;
        // 同一 trust level 下再注册一个只会返回未签名 JsonLd 的 self-signed candidate
        // provider，制造一个必然契约违规的候选。
        q.add_provider(Box::new(SelfSignedJsonLdProvider { doc: unsigned_doc }), 10)
            .await;

        let resolved = q
            .query_did_ex(
                &zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .iter()
            .any(|warning| matches!(warning, ResolveWarning::EvidenceContractViolation { .. })));
    }

    #[tokio::test]
    async fn wrong_signature_candidate_is_rejected_correct_one_succeeds() {
        // T1.2: 用错误私钥签名的候选文档不能通过 owner 验签；用正确私钥签名的能通过。
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "owner-sig");
        let good_zone_did = DID::new("bns", "zone-good-sig");
        let bad_zone_did = DID::new("bns", "zone-bad-sig");

        let owner_doc = build_owner_doc(&owner_did, None);
        let (owner_key, _) = owner_signing_key();
        let good_zone_doc =
            build_zone_doc_signed_by(&good_zone_did, &owner_did, ts(1000), "good", &owner_key);
        let bad_zone_doc = build_zone_doc_signed_by(
            &bad_zone_did,
            &owner_did,
            ts(1000),
            "bad",
            &other_signing_key(),
        );

        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(owner_did.clone(), "owner", owner_doc)
                    .with_doc(good_zone_did.clone(), "zone", good_zone_doc.clone())
                    .with_doc(bad_zone_did.clone(), "zone", bad_zone_doc),
            ),
            10,
        )
        .await;

        let resolved = q
            .query_did_ex(
                &good_zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, good_zone_doc);

        let err = q
            .query_did_ex(
                &bad_zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[tokio::test]
    async fn signature_by_historical_key_succeeds_with_warning() {
        // T5.1: owner 正常 key rotation 不会自动否决旧 key 历史上合法签发的文档
        // （设计文档第 6 节第 3 条）；用历史 key 验证成功时要带上
        // ResolveWarning::SignedByHistoricalKey。
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "rotated-owner");
        let zone_did = DID::new("bns", "zone-legacy-signed");

        let (new_key, _) = owner_signing_key();
        let owner_doc = build_owner_doc_with_legacy_key(&owner_did, &new_key);
        // zone 文档用被 rotate 掉的旧 key 签名，而不是当前的 #main_key。
        let zone_doc = build_zone_doc_signed_by(
            &zone_did,
            &owner_did,
            ts(1000),
            "legacy-signed",
            &other_signing_key(),
        );

        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(owner_did.clone(), "owner", owner_doc)
                    .with_doc(zone_did.clone(), "zone", zone_doc.clone()),
            ),
            10,
        )
        .await;

        let resolved = q
            .query_did_ex(
                &zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::SignedByHistoricalKey));
    }

    #[tokio::test]
    async fn owner_conflict_between_document_and_authority_is_rejected() {
        // T1.3: 权威发布源记录的 effective_owner 和文档自声明的 owner 不一致时必须拒绝；
        // 一致时正常通过。
        let q = NameQuery::new();
        let owner_x_did = DID::new("bns", "owner-x");
        let owner_y_did = DID::new("bns", "owner-y");
        let zone_did = DID::new("bns", "conflicted-zone");

        // 文档自声明 owner 是 Y，但权威源记录的 effective_owner 是 X。
        let zone_doc_declares_y = build_zone_doc(&zone_did, &owner_y_did, ts(1000), "conflict");
        let conflicting_state = PublishedState {
            did: zone_did.clone(),
            doc_type: "zone".to_string(),
            name_status: NameStatus::Active,
            document_status: DocumentStatus::Active,
            document_ref: Some(DocumentRef::inline(zone_doc_declares_y)),
            document_version: Some(1),
            previous_version: None,
            next_version: None,
            effective_owner: Some(owner_x_did.clone()),
            owner_source: OwnerSource::MethodAuthority,
            authority_root: None,
            authority_seq: Some(1),
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: None,
        };
        q.add_provider(
            Box::new(PublishedStateProvider {
                state: conflicting_state,
            }),
            0,
        )
        .await;

        let err = q
            .query_did_ex(
                &zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::OwnerConflict(_)));

        // 一致的场景：文档自声明 owner 和权威源记录的 effective_owner 都是 X，且能
        // 递归解析到 X 的 owner 文档，应该正常通过。
        let q2 = NameQuery::new();
        let zone_did2 = DID::new("bns", "consistent-zone");
        let zone_doc_declares_x = build_zone_doc(&zone_did2, &owner_x_did, ts(1000), "consistent");
        let owner_x_doc = build_owner_doc(&owner_x_did, None);
        let consistent_state = PublishedState {
            did: zone_did2.clone(),
            doc_type: "zone".to_string(),
            name_status: NameStatus::Active,
            document_status: DocumentStatus::Active,
            document_ref: Some(DocumentRef::inline(zone_doc_declares_x.clone())),
            document_version: Some(1),
            previous_version: None,
            next_version: None,
            effective_owner: Some(owner_x_did.clone()),
            owner_source: OwnerSource::MethodAuthority,
            authority_root: None,
            authority_seq: Some(1),
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: None,
        };
        q2.add_provider(
            Box::new(PublishedStateProvider {
                state: consistent_state,
            }),
            0,
        )
        .await;
        q2.add_provider(
            Box::new(DidDocProvider::new("owner-x").with_doc(
                owner_x_did.clone(),
                "owner",
                owner_x_doc,
            )),
            10,
        )
        .await;

        let resolved = q2
            .query_did_ex(
                &zone_did2,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc_declares_x);
        assert_eq!(
            resolved.document_metadata.buckyos.document_status,
            Some(DocumentStatus::Active)
        );
        assert_eq!(resolved.document_metadata.deactivated, Some(false));
    }

    #[tokio::test]
    async fn owner_revoke_before_iat_rejects_older_documents() {
        // T2.1: owner 声明 revoke_before_iat = 1000，iat <= 1000 的合法签名文档被拒绝，
        // iat > 1000 的正常通过。
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "revoking-owner");
        let old_zone_did = DID::new("bns", "zone-old-iat");
        let new_zone_did = DID::new("bns", "zone-new-iat");

        let owner_doc = build_owner_doc(&owner_did, Some(ts(1000)));
        let old_zone_doc = build_zone_doc(&old_zone_did, &owner_did, ts(900), "old");
        let new_zone_doc = build_zone_doc(&new_zone_did, &owner_did, ts(1100), "new");

        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(owner_did.clone(), "owner", owner_doc)
                    .with_doc(old_zone_did.clone(), "zone", old_zone_doc)
                    .with_doc(new_zone_did.clone(), "zone", new_zone_doc.clone()),
            ),
            10,
        )
        .await;

        let err = q
            .query_did_ex(
                &old_zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revoke_before_iat"));

        let resolved = q
            .query_did_ex(
                &new_zone_did,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, new_zone_doc);
    }

    struct LoopProvider {
        docs: Vec<(DID, String, EncodedDocument)>,
    }

    #[async_trait]
    impl NsProvider for LoopProvider {
        fn get_id(&self) -> String {
            "loop-provider".to_string()
        }

        // 强制模拟一个"owner doc_type 也需要继续递归"的 method（现实中默认不会这样），
        // 专门用来验证 policy.descend() 的环路/深度保护是真的生效，而不是死循环/栈溢出。
        fn is_owner_root(
            &self,
            _did: &DID,
            _doc_type: &DidDocType,
            _published: Option<&PublishedState>,
        ) -> bool {
            false
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
            did: &DID,
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            let wanted = doc_type.unwrap_or_default();
            self.docs
                .iter()
                .find(|(d, t, _)| d == did && t == wanted.as_str())
                .map(|(_, _, doc)| doc.clone())
                .ok_or_else(|| NSError::NotFound("no matching doc".into()))
        }
    }

    #[tokio::test]
    async fn owner_recursion_loop_is_rejected_within_max_depth() {
        // T0.2: A 的 owner 是 B，B 的 owner 是 A，构造出的环路必须在 max_depth 内报错，
        // 而不是死循环/栈溢出。
        let did_a = DID::new("bns", "loop-a");
        let did_b = DID::new("bns", "loop-b");

        let doc_a = build_zone_doc(&did_a, &did_b, ts(100), "a-owned-by-b");
        let doc_b = build_zone_doc(&did_b, &did_a, ts(100), "b-owned-by-a");

        let q = NameQuery::new();
        q.add_provider(
            Box::new(LoopProvider {
                docs: vec![
                    (did_a.clone(), "owner".to_string(), doc_a),
                    (did_b.clone(), "owner".to_string(), doc_b),
                ],
            }),
            10,
        )
        .await;

        let result = q
            .query_did_ex(
                &did_a,
                Some(DidDocType::Owner),
                None,
                ResolvePolicy::default(),
            )
            .await;
        assert!(result.is_err());
    }

    fn migrated_state(did: &DID, doc_type: &str, migration_target: &DID) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            name_status: NameStatus::Active,
            document_status: DocumentStatus::Migrated,
            document_ref: None,
            document_version: Some(1),
            previous_version: None,
            next_version: None,
            effective_owner: None,
            owner_source: OwnerSource::Unknown,
            authority_root: None,
            authority_seq: Some(1),
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: Some(migration_target.clone()),
        }
    }

    #[tokio::test]
    async fn migrated_document_status_follows_target_when_policy_allows() {
        // T0.1: document_status == Migrated 且 policy.follow_migration == true 时，
        // 应该真正递归解析到 migration_target 的文档。
        let did_old = DID::new("bns", "migrated-old");
        let did_new = DID::new("bns", "migrated-new");
        let owner_did = DID::new("bns", "migrated-owner");

        let owner_doc = build_owner_doc(&owner_did, None);
        let new_doc = build_zone_doc(&did_new, &owner_did, ts(0), "migration-target");

        let q = NameQuery::new();
        q.add_provider(
            Box::new(PublishedStateProvider {
                state: migrated_state(&did_old, "zone", &did_new),
            }),
            0,
        )
        .await;
        q.add_provider(
            Box::new(
                DidDocProvider::new("chain")
                    .with_doc(did_new.clone(), "zone", new_doc.clone())
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
            10,
        )
        .await;

        let resolved = q
            .query_did_ex(
                &did_old,
                Some(DidDocType::Zone),
                None,
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.document, new_doc);
    }

    #[tokio::test]
    async fn migrated_document_status_rejected_when_policy_disallows() {
        // T0.1: policy.follow_migration == false 时保留 Disabled 语义，不能静默
        // 递归到 migration_target。
        let did_old = DID::new("bns", "migrated-old-2");
        let did_new = DID::new("bns", "migrated-new-2");

        let q = NameQuery::new();
        q.add_provider(
            Box::new(PublishedStateProvider {
                state: migrated_state(&did_old, "zone", &did_new),
            }),
            0,
        )
        .await;

        let mut policy = ResolvePolicy::default();
        policy.follow_migration = false;
        let err = q
            .query_did_ex(&did_old, Some(DidDocType::Zone), None, policy)
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));
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
        let result = q.query_did(&did, Some(DidDocType::Info), Some(10)).await;
        assert!(result.is_err());

        // 不限制时应当拿到低优先级结果
        let (doc, exp, trust) = q
            .query_did(&did, Some(DidDocType::Info), None)
            .await
            .unwrap();
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
