use jsonwebtoken::DecodingKey;
use log::{error, info, warn};
use name_lib::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    content_hash_matches, is_key_class_method, structural_owner, BodyEvidence, DidDocType,
    DiscoveredDocument, DocumentBody, DocumentStatus, MethodProviders, NameInfo, NsProvider,
    OwnerDocumentPolicy, ProviderAnswer, ProviderResolveResult, PublishedState, RecordType,
    RegisteredSupplement, ResolvePolicy, ResolveWarning, ResolvedDocument,
};

/// 候选文档在验证阶段被拒绝的原因。契约违规会被记录为 warning 并静默丢弃该候选,
/// 其它候选仍可能验证成功;`Failed` 是具体的验证/递归失败原因,当所有候选都失败时
/// 会把最后一个 `Failed` 原因作为整体解析错误返回,而不是笼统的 NotFound。
enum CandidateRejection {
    ContractViolation(ResolveWarning),
    Failed(NSError),
}

/// resolver 主循环的三种产出(简化文档 2.1 节的结果二分法,在 (did, doc_type)
/// 粒度上的展开)。`NameClient` 依据它决定缓存动作:负状态写 negative cache;
/// NoAnswer 时才轮到策略点④的 stale cache 兜底。
#[derive(Debug)]
pub enum ResolveOutcome {
    /// 得到了一份可核实(或按契约免验证)的文档。
    Resolved(ResolvedDocument),
    /// 权威源的负状态回答(策略点①):`Revoked / Tombstoned`,以及策略不允许
    /// 跟随时的 `Migrated`。这是"回答",不是"查不到"。
    Negative {
        status: DocumentStatus,
        message: String,
    },
    /// 查询没有产出可核实的文档:权威源没回答、权威源明确 Missing、候选被作废
    /// 或无资格露面。三种情况的兜底资格各不相同,由调用方(NameClient)裁决。
    NoAnswer {
        /// 权威渠道存在却没回答(断网/超时)。已验证缓存兜底的入场券。
        authority_unknown: bool,
        /// 权威源明确回答"从未发布"。屏蔽 stale cache 兜底——旧的"已发布"缓存
        /// 与权威答复矛盾(简化文档 2.1 节)。
        authority_missing: bool,
        last_error: Option<NSError>,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Channel {
    Authority,
    Supplement,
}

pub struct NameQuery {
    /// 每个 DID method 的解析注册模型:至多一个权威渠道 + 有序补充源(T2.2)。
    /// zone_resolver 不在这里:它是 cache 层组件,由 `NameClient` 在进入
    /// resolver core 之前查询(T5.5),NameQuery 只保留 resolver core。
    methods: Arc<RwLock<HashMap<String, MethodProviders>>>,
    /// 普通名字解析(DNS 语义 `resolve(name)` / `resolve_ip`)使用的有序 provider
    /// 列表,与 DID 解析管线相互独立。
    dns_providers: Arc<RwLock<Vec<Box<dyn NsProvider>>>>,
}

impl NameQuery {
    pub fn new() -> NameQuery {
        NameQuery {
            methods: Arc::new(RwLock::new(HashMap::new())),
            dns_providers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 注册某 method 的权威发布渠道。一个 method 至多一个权威渠道;重复设置视为
    /// 配置错误,保留первый注册者并打警告。
    pub async fn set_method_authority(
        &self,
        method: impl Into<String>,
        provider: Box<dyn NsProvider>,
    ) {
        let method = method.into();
        let mut methods = self.methods.write().await;
        let entry = methods.entry(method.clone()).or_default();
        if entry.authority.is_some() {
            warn!(
                "method {} already has an authority provider, ignoring {}",
                method,
                provider.get_id()
            );
            return;
        }
        entry.authority = Some(provider);
    }

    /// 追加某 method 的补充源。补充源是显式有序列表,first-win。
    pub async fn add_method_supplement(
        &self,
        method: impl Into<String>,
        provider: Box<dyn NsProvider>,
    ) {
        let mut methods = self.methods.write().await;
        methods
            .entry(method.into())
            .or_default()
            .supplements
            .push(RegisteredSupplement::always(provider));
    }

    /// 追加一个只允许 current-zone 自举调用的补充源。调用方必须在
    /// `ResolvePolicy::with_current_zone` 中给出精确 zone DID;其它请求会跳过
    /// 该 provider 并继续后面的补充源。
    pub async fn add_current_zone_bootstrap_supplement(
        &self,
        method: impl Into<String>,
        provider: Box<dyn NsProvider>,
    ) {
        let mut methods = self.methods.write().await;
        methods
            .entry(method.into())
            .or_default()
            .supplements
            .push(RegisteredSupplement::current_zone_bootstrap(provider));
    }

    /// 覆盖某 method 的免验证 doc_type 契约(默认只有 `info`)。
    pub async fn set_no_proof_doc_types(&self, method: &str, doc_types: HashSet<DidDocType>) {
        let mut methods = self.methods.write().await;
        methods
            .entry(method.to_string())
            .or_default()
            .no_proof_doc_types = doc_types;
    }

    /// 该 (method, doc_type) 是否走免验证的 Info 路径(method 契约,不由 provider
    /// 运行时协商)。未注册的 method 按默认契约(只有 info)回答。
    pub async fn is_no_proof_doc_type(&self, method: &str, doc_type: &DidDocType) -> bool {
        let methods = self.methods.read().await;
        match methods.get(method) {
            Some(entry) => entry.no_proof_doc_types.contains(doc_type),
            None => *doc_type == DidDocType::Info,
        }
    }

    /// 注册普通名字解析(DNS 语义)的 provider,与 DID 管线无关。
    pub async fn add_dns_provider(&self, provider: Box<dyn NsProvider>) {
        self.dns_providers.write().await.push(provider);
    }

    /// 兼容旧注册接口:按 provider 自声明的 method 列表注册进 method registry
    /// (首个注册者成为该 method 的权威渠道,后续为有序补充源);不声明 method 的
    /// provider 只注册进普通名字解析列表。新代码请使用显式注册接口。
    pub async fn add_provider(&self, provider: Box<dyn NsProvider>, _trust_level: Option<i32>) {
        let declared = provider.methods();
        if declared.is_empty() {
            info!(
                "provider {} declares no DID methods; registered for plain name queries only",
                provider.get_id()
            );
            self.add_dns_provider(provider).await;
            return;
        }
        if declared.len() > 1 {
            warn!(
                "provider {} declares multiple methods {:?}; registering under {} only — register explicitly per method instead",
                provider.get_id(),
                declared,
                declared[0]
            );
        }
        let method = declared[0].clone();
        let mut methods = self.methods.write().await;
        let entry = methods.entry(method).or_default();
        if entry.authority.is_none() {
            entry.authority = Some(provider);
        } else {
            entry
                .supplements
                .push(RegisteredSupplement::always(provider));
        }
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

    /// 兼容包装:把 `ResolveOutcome` 折叠成 `NSResult<ResolvedDocument>`。
    /// 需要按结果类型区分缓存动作的调用方(NameClient)请用 `query_did_outcome`。
    pub async fn query_did_ex(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        match self.query_did_outcome(did, doc_type, policy).await? {
            ResolveOutcome::Resolved(resolved) => Ok(resolved),
            ResolveOutcome::Negative { message, .. } => Err(NSError::Disabled(message)),
            ResolveOutcome::NoAnswer { last_error, .. } => {
                Err(last_error.unwrap_or_else(|| NSError::NotFound(did.to_host_name())))
            }
        }
    }

    /// resolver 主循环:一条路径 + 四个策略点(简化文档第 3 节)。
    ///
    /// 策略只来自两处:权威源返回的发布状态和 owner document。expected_owner 与
    /// 候选入场门禁不是策略,是约束——它们决定"用谁验、有没有资格",没有裁量空间。
    pub async fn query_did_outcome(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        policy: ResolvePolicy,
    ) -> NSResult<ResolveOutcome> {
        // 硬门禁(T0.1):key 类 DID 不是合法入参,不进入 provider 管线。
        if is_key_class_method(&did.method) {
            return Err(NSError::InvalidDID(format!(
                "key-class DID {} is not a legal resolve_did input; keys only appear inside documents",
                did.to_string()
            )));
        }

        let doc_type = doc_type.unwrap_or_default();
        let methods = self.methods.read().await;
        let Some(method_providers) = methods.get(&did.method) else {
            return Err(NSError::NotFound(format!(
                "DID method not supported: {}",
                did.method
            )));
        };

        // 免验证的 Info 类 doc_type 按 method 契约事先声明,走独立轻量路径。
        // 外层 NameClient 负责进程内与本机持久化 cache。
        if method_providers.no_proof_doc_types.contains(&doc_type) {
            return self
                .resolve_unproof_info(method_providers, did, &doc_type, &policy)
                .await;
        }

        // 本地覆盖(hosts 语义,简化文档第 7 节):短路在权威查询之前,连 REVOKED
        // 都盖得住;owner 递归复用同一个 policy 时同样命中。显式打标。
        if let Some(store) = policy.local_authority_override.as_ref() {
            if let Some(document) = store.get(did, &doc_type) {
                return Ok(ResolveOutcome::Resolved(
                    ResolvedDocument::from_document(
                        document,
                        did,
                        &doc_type,
                        Some("local-authority-override".to_string()),
                        BodyEvidence::Anchored,
                        None,
                    )
                    .with_warning(ResolveWarning::LocalAuthorityOverride),
                ));
            }
        }

        // expected_owner 先取名字结构的默认值(2.4 节);权威源的 owner 绑定可覆盖。
        let mut expected_owner = structural_owner(did);
        let mut doc_hash: Option<String> = None;
        let mut published: Option<PublishedState> = None;
        let mut authority_unknown = false;
        let mut authority_missing = false;
        let mut last_error: Option<NSError> = None;
        let mut warnings: Vec<ResolveWarning> = Vec::new();

        // ---- 权威阶段(介绍文档第 7 节:第一个总是权威源)----
        // 至多一个权威发布渠道;同一渠道的多个委托读取端(镜像、网关)在注册时
        // 用 `AuthorityReaders` 组合,这里只面对一个权威 provider。zone_resolver
        // 不在这里:它是 cache 层组件,在进入 resolver core 之前已由 NameClient
        // 查询(T5.5)。
        let mut authority_body = None;
        if let Some(authority) = method_providers.authority.as_ref() {
            match self
                .authority_answer(authority.as_ref(), did, &doc_type)
                .await
            {
                // 二分法:unknown = 没得到回答。权威源没回答要记下来:候选的
                // "已验证"资格取决于它(2.1 节 → 策略点③)。
                ProviderResolveResult::Unknown(err) => {
                    warn!(
                        "authority for {}#{} did not answer: {}",
                        did.to_string(),
                        doc_type,
                        err
                    );
                    authority_unknown = true;
                    last_error = Some(err);
                }
                ProviderResolveResult::Dr(answer) => {
                    // 权威源的回答可以携带 owner 绑定(不必带文档本体),并覆盖结构
                    // 默认值——owner 变更/委托只有这条路生效,候选文档说了不算(2.4 节)。
                    if let Some(binding) = answer.owner_binding.clone() {
                        expected_owner = Some(binding);
                    }
                    if answer.doc_hash.is_some() {
                        doc_hash = answer.doc_hash.clone();
                    }
                    if answer.published.is_some() {
                        published = answer.published.clone();
                    }

                    match answer.status.clone() {
                        Some(DocumentStatus::Revoked) | Some(DocumentStatus::Tombstoned) => {
                            // 策略点①:负状态终止查询。缓存动作(删 positive、写 negative)
                            // 由 NameClient 依据这个 outcome 执行。
                            let status = answer.status.clone().unwrap();
                            return Ok(ResolveOutcome::Negative {
                                message: format!(
                                    "{}#{} is {:?}",
                                    did.to_string(),
                                    doc_type,
                                    status
                                ),
                                status,
                            });
                        }
                        Some(DocumentStatus::Migrated) => {
                            if policy.follow_migration {
                                if let Some(target) = answer.migration_target.clone() {
                                    let next_policy = policy.descend(&target, &doc_type)?;
                                    return Box::pin(self.query_did_outcome(
                                        &target,
                                        Some(doc_type.clone()),
                                        next_policy,
                                    ))
                                    .await;
                                }
                            }
                            return Ok(ResolveOutcome::Negative {
                                status: DocumentStatus::Migrated,
                                message: format!("{}#{} is migrated", did.to_string(), doc_type),
                            });
                        }
                        Some(DocumentStatus::Missing) | Some(DocumentStatus::Expired) => {
                            // 策略点②:权威源明确回答"从未发布/已过期"。自签名候选是否有
                            // 入场资格由策略决定;入场不豁免 expected_owner 一致性与验签。
                            authority_missing = true;
                            if !policy.allow_self_signed_when_missing {
                                return Ok(ResolveOutcome::NoAnswer {
                                    authority_unknown,
                                    authority_missing: true,
                                    last_error: Some(NSError::NotFound(format!(
                                        "{}#{} missing in method authority",
                                        did.to_string(),
                                        doc_type
                                    ))),
                                });
                            }
                        }
                        Some(DocumentStatus::Active) | None => {
                            // 权威源 Active 可能只带锚点(doc_hash / owner 绑定),
                            // body 缺席时由补充源提供。
                            authority_body = answer.body;
                        }
                    }
                }
            }
        }

        // 权威信道取回的 body(Anchored)。入场判定失败只作废这一份 body,
        // 补充源仍可能给出属于已发布集合的候选。
        if let Some(body) = authority_body {
            match self
                .admit_body(
                    did,
                    &doc_type,
                    &body,
                    expected_owner.as_ref(),
                    doc_hash.as_deref(),
                    authority_unknown,
                    &policy,
                    &mut warnings,
                )
                .await
            {
                Ok(candidate_warnings) => {
                    return Ok(ResolveOutcome::Resolved(Self::resolved_with_warnings(
                        body,
                        did,
                        &doc_type,
                        published.as_ref(),
                        warnings,
                        candidate_warnings,
                    )));
                }
                Err(CandidateRejection::ContractViolation(warning)) => {
                    warnings.push(warning);
                }
                Err(CandidateRejection::Failed(err)) => {
                    last_error = Some(err);
                }
            }
        }

        // ---- 补充源阶段:显式有序,first-win ----
        // 补充源永远只产出候选文档(need_proof),给不出发布状态和 owner 绑定;
        // 它答不上来也不影响任何门禁。
        for supplement in method_providers.supplements.iter() {
            if !supplement.is_enabled(did, &policy) {
                continue;
            }
            let provider = supplement.provider.as_ref();
            let Ok(body) = self
                .query_provider_body(provider, did, &doc_type, BodyEvidence::NeedProof)
                .await
            else {
                continue;
            };

            match self
                .admit_body(
                    did,
                    &doc_type,
                    &body,
                    expected_owner.as_ref(),
                    doc_hash.as_deref(),
                    authority_unknown,
                    &policy,
                    &mut warnings,
                )
                .await
            {
                Ok(candidate_warnings) => {
                    return Ok(ResolveOutcome::Resolved(Self::resolved_with_warnings(
                        body,
                        did,
                        &doc_type,
                        published.as_ref(),
                        warnings,
                        candidate_warnings,
                    )));
                }
                Err(CandidateRejection::ContractViolation(warning)) => {
                    warnings.push(warning);
                    continue;
                }
                Err(CandidateRejection::Failed(err)) => {
                    // 一份坏 body 只作废它自己,不让一份坏结果终止整个解析。
                    last_error = Some(err);
                    continue;
                }
            }
        }

        // ---- 查询没有产出可核实的文档 ----
        // 负状态屏蔽与策略点④(stale cache)在 NameClient 依据这个 outcome 执行。
        Ok(ResolveOutcome::NoAnswer {
            authority_unknown,
            authority_missing,
            last_error,
        })
    }

    /// 候选通过入场判定后的结果组装:累计的 warnings 一并挂上。
    fn resolved_with_warnings(
        body: DocumentBody,
        did: &DID,
        doc_type: &DidDocType,
        published: Option<&PublishedState>,
        warnings: Vec<ResolveWarning>,
        candidate_warnings: Vec<ResolveWarning>,
    ) -> ResolvedDocument {
        let discovered_documents = body.discovered_documents.clone();
        let mut resolved = ResolvedDocument::from_document(
            body.document,
            did,
            doc_type,
            body.resolver_id,
            body.evidence,
            published,
        )
        .with_discovered_documents(discovered_documents);
        for warning in warnings.into_iter().chain(candidate_warnings) {
            resolved = resolved.with_warning(warning);
        }
        resolved
    }

    /// 把权威读取端的原始接口归一成 `ProviderAnswer`。证据等级由**注册位置**
    /// (权威渠道/补充源)决定,不由 provider 自己声明——这是"need_proof 按
    /// 取回信道打标"的落点。
    async fn authority_answer(
        &self,
        provider: &dyn NsProvider,
        did: &DID,
        doc_type: &DidDocType,
    ) -> ProviderResolveResult {
        match provider.resolve_published_state(did, doc_type).await {
            Ok(Some(state)) => {
                let mut body = state
                    .document_ref
                    .as_ref()
                    .and_then(|doc_ref| doc_ref.inline_document.clone())
                    .map(|doc| DocumentBody::anchored(doc, Some(provider.get_id())));
                // 状态是 Active 而回答没有内联 body 时,再问一次权威渠道的文档接口;
                // 失败不算 unknown——状态已经是 DR,body 可以由补充源提供(anchor-only)。
                if body.is_none() && state.document_status == DocumentStatus::Active {
                    if let Ok(doc_body) = self
                        .query_provider_body(provider, did, doc_type, BodyEvidence::Anchored)
                        .await
                    {
                        body = Some(doc_body);
                    }
                }
                ProviderResolveResult::Dr(ProviderAnswer {
                    status: Some(state.document_status.clone()),
                    owner_binding: state.effective_owner.clone(),
                    doc_hash: state
                        .document_ref
                        .as_ref()
                        .and_then(|doc_ref| doc_ref.content_hash.clone()),
                    migration_target: state.migration_target.clone(),
                    body,
                    published: Some(state),
                })
            }
            Ok(None) => {
                // 权威源没有发布状态能力(did:web 类 canonical endpoint):权威回答
                // 退化为"取回文档本体"。NotFound 是权威渠道的明确回答(Missing),
                // Disabled 是负状态,其余错误才是 unknown——网络错误不能伪装成"从未发布"。
                match provider.query_did_documents(did, None).await {
                    Ok(Some(documents)) => {
                        let requested_key = doc_type.as_str();
                        match documents.get(requested_key) {
                            Some(doc) => ProviderResolveResult::Dr(ProviderAnswer {
                                status: Some(DocumentStatus::Active),
                                body: Some(
                                    DocumentBody::anchored(doc.clone(), Some(provider.get_id()))
                                        .with_discovered_documents(Self::discovered_documents(
                                            did, &documents,
                                        )),
                                ),
                                ..Default::default()
                            }),
                            None => ProviderResolveResult::Dr(ProviderAnswer {
                                status: Some(DocumentStatus::Missing),
                                ..Default::default()
                            }),
                        }
                    }
                    Ok(None) => {
                        match provider
                            .query_did(did, Self::legacy_doc_type(doc_type), None)
                            .await
                        {
                            Ok(doc) => ProviderResolveResult::Dr(ProviderAnswer {
                                status: Some(DocumentStatus::Active),
                                body: Some(DocumentBody::anchored(doc, Some(provider.get_id()))),
                                ..Default::default()
                            }),
                            Err(NSError::NotFound(_)) => {
                                ProviderResolveResult::Dr(ProviderAnswer {
                                    status: Some(DocumentStatus::Missing),
                                    ..Default::default()
                                })
                            }
                            Err(NSError::Disabled(_)) => {
                                ProviderResolveResult::Dr(ProviderAnswer {
                                    status: Some(DocumentStatus::Revoked),
                                    ..Default::default()
                                })
                            }
                            Err(err) => ProviderResolveResult::Unknown(err),
                        }
                    }
                    Err(NSError::NotFound(_)) => ProviderResolveResult::Dr(ProviderAnswer {
                        status: Some(DocumentStatus::Missing),
                        ..Default::default()
                    }),
                    Err(NSError::Disabled(_)) => ProviderResolveResult::Dr(ProviderAnswer {
                        status: Some(DocumentStatus::Revoked),
                        ..Default::default()
                    }),
                    Err(err) => ProviderResolveResult::Unknown(err),
                }
            }
            Err(err) => ProviderResolveResult::Unknown(err),
        }
    }

    /// verify 家族(`build_verify_context`)的权威阶段入口:对 (did, doc_type) 运行一次
    /// 权威渠道查询并归一化。`Err(NotFound)` = method 未注册;`Ok(None)` = 该
    /// method 没有注册权威渠道(发布状态不可知,外部候选只能按 NeedProof 验证);
    /// `Ok(Some(..))` = 权威读取端的回答(Dr)或"没有得到回答"(Unknown)。
    pub(crate) async fn authority_answer_for(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Option<ProviderResolveResult>> {
        let methods = self.methods.read().await;
        let Some(method_providers) = methods.get(&did.method) else {
            return Err(NSError::NotFound(format!(
                "DID method not supported: {}",
                did.method
            )));
        };
        let Some(authority) = method_providers.authority.as_ref() else {
            return Ok(None);
        };
        Ok(Some(
            self.authority_answer(authority.as_ref(), did, doc_type)
                .await,
        ))
    }

    async fn query_provider_body(
        &self,
        provider: &dyn NsProvider,
        did: &DID,
        doc_type: &DidDocType,
        evidence: BodyEvidence,
    ) -> NSResult<DocumentBody> {
        match provider.query_did_documents(did, None).await? {
            Some(documents) => {
                let document = documents.get(doc_type.as_str()).cloned().ok_or_else(|| {
                    NSError::NotFound(format!("DID Document not found: {doc_type}"))
                })?;
                Ok(
                    DocumentBody::with_evidence(document, evidence, Some(provider.get_id()))
                        .with_discovered_documents(Self::discovered_documents(did, &documents)),
                )
            }
            None => {
                let document = provider
                    .query_did(did, Self::legacy_doc_type(doc_type), None)
                    .await?;
                Ok(DocumentBody::with_evidence(
                    document,
                    evidence,
                    Some(provider.get_id()),
                ))
            }
        }
    }

    fn discovered_documents(
        zone_did: &DID,
        documents: &HashMap<String, EncodedDocument>,
    ) -> Vec<DiscoveredDocument> {
        documents
            .iter()
            .filter_map(|(doc_type, document)| {
                let (did, doc_type) = match doc_type.as_str() {
                    "zone" => (zone_did.clone(), Some(DidDocType::Zone)),
                    "boot" => (zone_did.clone(), Some(DidDocType::Boot)),
                    "owner" => (zone_did.clone(), Some(DidDocType::Owner)),
                    "info" => (zone_did.clone(), Some(DidDocType::Info)),
                    "user" => (zone_did.clone(), Some(DidDocType::User)),
                    "device" => (zone_did.clone(), Some(DidDocType::Device)),
                    "did-object" => (zone_did.clone(), Some(DidDocType::DidObject)),
                    device_name => {
                        if device_name.is_empty() {
                            return None;
                        }
                        (
                            DID::new(
                                &zone_did.method,
                                &format!("{}.{}", device_name, zone_did.id),
                            ),
                            None,
                        )
                    }
                };
                Some(DiscoveredDocument {
                    did,
                    doc_type,
                    document: document.clone(),
                })
            })
            .collect()
    }

    /// 旧版 provider 约定:默认 doc_type(zone)的文档存放在不带 doc_type 的位置
    /// (`did.json`)。归一层保留这个取回细节,provider 不用感知。
    fn legacy_doc_type(doc_type: &DidDocType) -> Option<DidDocType> {
        if *doc_type == DidDocType::Zone {
            None
        } else {
            Some(doc_type.clone())
        }
    }

    /// body 入场判定。Anchored 只做自述一致性与 hash 锚定;NeedProof 走完整的
    /// expected_owner + owner 递归 + verify(2.3/2.4 节)。
    async fn admit_body(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        body: &DocumentBody,
        expected_owner: Option<&DID>,
        doc_hash: Option<&str>,
        authority_unknown: bool,
        policy: &ResolvePolicy,
        warnings: &mut Vec<ResolveWarning>,
    ) -> Result<Vec<ResolveWarning>, CandidateRejection> {
        match body.evidence {
            BodyEvidence::UnproofInfo => Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: body.evidence.as_str().to_string(),
                    reason: "doc_type requires verification".to_string(),
                },
            )),
            BodyEvidence::Anchored => {
                // 权威信道取回的 body,need_proof = false。仍然做两条硬性 sanity:
                // 文档自述的 id(若声明了)必须与请求一致;权威源锚定了 hash 时
                // body 必须属于已发布集合。
                if let Some(doc_id) = Self::extract_doc_id(&body.document) {
                    if doc_id != *did {
                        return Err(CandidateRejection::ContractViolation(
                            ResolveWarning::EvidenceContractViolation {
                                evidence: body.evidence.as_str().to_string(),
                                reason: format!(
                                    "document id {} does not match requested {}",
                                    doc_id.to_string(),
                                    did.to_string()
                                ),
                            },
                        ));
                    }
                }
                if let Some(hash) = doc_hash {
                    if !content_hash_matches(hash, &body.document) {
                        return Err(CandidateRejection::Failed(NSError::Failed(format!(
                            "{}#{} anchored body does not match authority doc_hash",
                            did.to_string(),
                            doc_type
                        ))));
                    }
                }
                Ok(Vec::new())
            }
            BodyEvidence::NeedProof => {
                self.verify_need_proof_candidate(
                    did,
                    doc_type,
                    body,
                    expected_owner,
                    doc_hash,
                    authority_unknown,
                    policy,
                    warnings,
                )
                .await
            }
        }
    }

    /// verify(2.3 节):doc.id == did ∧ doc.owner == expected_owner ∧ hash 匹配
    /// (权威源锚定了 hash 时) ∧ owner key 验签 ∧ owner 策略(revoke_before_iat)。
    /// 递归解析的是 **expected_owner** 的 owner 文档,绝不是候选自声明的 owner
    /// ——那是第 4 节的 owner 冒充攻击面。
    async fn verify_need_proof_candidate(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        body: &DocumentBody,
        expected_owner: Option<&DID>,
        doc_hash: Option<&str>,
        authority_unknown: bool,
        policy: &ResolvePolicy,
        warnings: &mut Vec<ResolveWarning>,
    ) -> Result<Vec<ResolveWarning>, CandidateRejection> {
        // 策略点③(默认档):权威源没回答时,发布状态验证不了——就算验签通过,
        // 也可能正顶掉一份已发布甚至已吊销的结果。候选没有"已验证"的资格;
        // unproof 露面默认不实现(D1),正路是已验证缓存兜底。
        if authority_unknown {
            return Err(CandidateRejection::Failed(NSError::Failed(format!(
                "{}#{} authority did not answer; self-signed candidate cannot be verified",
                did.to_string(),
                doc_type
            ))));
        }

        // 硬规则(2.4 节):推不出 expected_owner 的候选直接出局,连降级露面的
        // 资格都没有。一级名字的绑定只能来自权威源。
        let Some(expected_owner) = expected_owner else {
            return Err(CandidateRejection::Failed(NSError::OwnerConflict(format!(
                "{}#{} has no expected owner (no authority binding and no structural default); \
                 self-signed candidate rejected",
                did.to_string(),
                doc_type
            ))));
        };

        // need_proof 语义上必须能验证:JsonLd 结构上不可能携带签名,属于证据契约违规。
        if !body.document.is_proof() {
            return Err(CandidateRejection::ContractViolation(
                ResolveWarning::EvidenceContractViolation {
                    evidence: body.evidence.as_str().to_string(),
                    reason: "unsigned JsonLd body".to_string(),
                },
            ));
        }

        // 结构上无法识别的候选是契约违规,静默丢弃而不是中断整体解析。
        let parsed = parse_did_doc(body.document.clone()).map_err(|err| {
            CandidateRejection::ContractViolation(ResolveWarning::EvidenceContractViolation {
                evidence: body.evidence.as_str().to_string(),
                reason: format!("not a recognizable document: {}", err),
            })
        })?;

        // verify 第一行:文档的自述(我是谁)必须与请求一致。
        let doc_id = parsed.get_id();
        if doc_id != *did {
            return Err(CandidateRejection::Failed(NSError::Failed(format!(
                "candidate document id {} does not match requested {}#{}",
                doc_id.to_string(),
                did.to_string(),
                doc_type
            ))));
        }

        // verify 第二行:doc.owner == expected_owner,不一致直接作废——这是
        // 强攻击信号(owner 冒充,或未经权威源发布的 owner 变更),打警告。
        let declared_owner_str = parsed.get_iss().ok_or_else(|| {
            CandidateRejection::ContractViolation(ResolveWarning::EvidenceContractViolation {
                evidence: body.evidence.as_str().to_string(),
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
        if &declared_owner != expected_owner {
            warnings.push(ResolveWarning::OwnerMismatch {
                declared: declared_owner.to_string(),
                expected: expected_owner.to_string(),
            });
            return Err(CandidateRejection::Failed(NSError::OwnerConflict(format!(
                "{}#{} declares owner {} but expected owner is {}",
                did.to_string(),
                doc_type,
                declared_owner.to_string(),
                expected_owner.to_string()
            ))));
        }

        // hash 锚定:Active 时只有属于已发布集合的 body 验得过(第 4 节执行点)。
        if let Some(hash) = doc_hash {
            if !content_hash_matches(hash, &body.document) {
                return Err(CandidateRejection::Failed(NSError::Failed(format!(
                    "{}#{} candidate body does not match authority doc_hash",
                    did.to_string(),
                    doc_type
                ))));
            }
        }

        // 递归解析 expected_owner 的 owner 文档(2.5 节)。owner 约定:只有权威
        // provider 返回 owner 文档且 need_proof = false,递归到此自然终止。
        // 用 for_authority_lookup() 收紧 policy,并用 descend() 做环路/深度检查。
        let next_policy = policy
            .for_authority_lookup()
            .descend(expected_owner, &DidDocType::Owner)
            .map_err(CandidateRejection::Failed)?;
        let owner_outcome =
            Box::pin(self.query_did_outcome(expected_owner, Some(DidDocType::Owner), next_policy))
                .await
                .map_err(|err| {
                    CandidateRejection::Failed(NSError::Failed(format!(
                        "resolve owner {} for {}#{} failed: {}",
                        expected_owner.to_string(),
                        did.to_string(),
                        doc_type,
                        err
                    )))
                })?;

        let owner_resolved = match owner_outcome {
            ResolveOutcome::Resolved(resolved) => resolved,
            // owner 被权威源否定(吊销/不存在):这份文档直接作废。
            ResolveOutcome::Negative { message, .. } => {
                return Err(CandidateRejection::Failed(NSError::Failed(format!(
                    "owner {} of {}#{} is negatively answered by authority: {}",
                    expected_owner.to_string(),
                    did.to_string(),
                    doc_type,
                    message
                ))));
            }
            // 策略点③的另一半:owner document 拿不到,签名验证不了。"验证不了"
            // 不等于"验证失败",但默认没有 unproof 露面资格(D1)。
            ResolveOutcome::NoAnswer { last_error, .. } => {
                return Err(CandidateRejection::Failed(NSError::Failed(format!(
                    "owner document {} for {}#{} is unavailable: {}",
                    expected_owner.to_string(),
                    did.to_string(),
                    doc_type,
                    last_error
                        .map(|err| err.to_string())
                        .unwrap_or_else(|| "no answer".to_string())
                ))));
            }
        };

        let owner_document =
            OwnerDocument::decode(&owner_resolved.document, None).map_err(|err| {
                CandidateRejection::Failed(NSError::Failed(format!(
                    "owner document {} is not a valid OwnerDocument: {}",
                    expected_owner.to_string(),
                    err
                )))
            })?;
        let (decoding_key, _jwk) = owner_document.get_auth_key(None).ok_or_else(|| {
            CandidateRejection::Failed(NSError::Failed(format!(
                "owner document {} has no usable auth key",
                expected_owner.to_string()
            )))
        })?;

        // owner 策略检查:revoke_before_iat replay guard(T1.3 保留资产)。
        let owner_policy = OwnerDocumentPolicy::from_owner_document(&owner_document);
        if let Some(revoke_before_iat) = owner_policy.revoke_before_iat {
            let iat = Self::extract_timestamp(&body.document, "iat");
            if let Some(iat) = iat {
                if iat <= revoke_before_iat {
                    return Err(CandidateRejection::Failed(NSError::Failed(format!(
                        "{}#{} iat {} is not after owner revoke_before_iat {}",
                        did.to_string(),
                        doc_type,
                        iat,
                        revoke_before_iat
                    ))));
                }
            }
        }

        // owner key 验签。默认 key 失败时回退尝试 owner 的历史 key(刚发生过 key
        // rotation 时旧文档仍然用旧 key 签名),成功则记 SignedByHistoricalKey
        // warning 而不是直接否决(T1.3 保留资产)。
        let mut candidate_warnings = Vec::new();
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
                    expected_owner.to_string(),
                ))));
            }
            candidate_warnings.push(ResolveWarning::SignedByHistoricalKey);
        }

        Ok(candidate_warnings)
    }

    /// 免验证 Info 类的轻量路径:仍然按"权威渠道优先,补充源有序"first-win,
    /// 但不做任何验证,证据固定为 UnproofInfo。
    async fn resolve_unproof_info(
        &self,
        method_providers: &MethodProviders,
        did: &DID,
        doc_type: &DidDocType,
        policy: &ResolvePolicy,
    ) -> NSResult<ResolveOutcome> {
        let mut authority_unknown = false;
        let mut last_error: Option<NSError> = None;

        let providers = method_providers
            .authority
            .iter()
            .map(|provider| (Channel::Authority, provider.as_ref()))
            .chain(
                method_providers
                    .supplements
                    .iter()
                    .filter(|supplement| supplement.is_enabled(did, policy))
                    .map(|supplement| (Channel::Supplement, supplement.provider.as_ref())),
            );

        for (channel, provider) in providers {
            match provider.query_did(did, Some(doc_type.clone()), None).await {
                Ok(doc) => {
                    return Ok(ResolveOutcome::Resolved(
                        ResolvedDocument::from_unauthenticated_info(
                            doc,
                            did,
                            doc_type,
                            Some(provider.get_id()),
                        ),
                    ));
                }
                Err(NSError::NotFound(msg)) => {
                    last_error = Some(NSError::NotFound(msg));
                }
                Err(err) => {
                    if channel == Channel::Authority {
                        authority_unknown = true;
                    }
                    last_error = Some(err);
                }
            }
        }

        Ok(ResolveOutcome::NoAnswer {
            authority_unknown,
            authority_missing: false,
            last_error: Some(last_error.unwrap_or_else(|| {
                NSError::NotFound(format!(
                    "unauthenticated info not found: {}#{}",
                    did.to_string(),
                    doc_type
                ))
            })),
        })
    }

    fn extract_doc_id(doc: &EncodedDocument) -> Option<DID> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(|id| id.as_str())
                    .map(|id| id.to_string())
            })
            .and_then(|id| DID::from_str(&id).ok())
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
    use crate::{DocumentRef, PublishedState};
    use async_trait::async_trait;
    use buckyos_kit::buckyos_get_unix_timestamp;
    use jsonwebtoken::{jwk::Jwk, EncodingKey};
    use name_lib::NSError;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 固定的测试用 Ed25519 keypair(owner key)。
    const OWNER_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
    const OWNER_PUBLIC_JWK_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
    // 另一把不同的 Ed25519 keypair,用来构造"mallory 自签"的攻击场景。
    const MALLORY_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----";
    const MALLORY_PUBLIC_JWK_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";

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

    fn mallory_signing_key() -> (EncodingKey, Jwk) {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": MALLORY_PUBLIC_JWK_X
        }))
        .unwrap();
        (
            EncodingKey::from_ed_pem(MALLORY_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
            jwk,
        )
    }

    /// 相对当前真实时间的偏移量,避免 JWT 的 `exp` 校验把测试用的小整数 iat
    /// 当成"很久以前过期"。
    fn ts(offset_secs: i64) -> u64 {
        (buckyos_get_unix_timestamp() as i64 + offset_secs) as u64
    }

    fn build_owner_doc_with_key(
        owner_did: &DID,
        valid_iat: Option<u64>,
        key: &EncodingKey,
        jwk: Jwk,
    ) -> EncodedDocument {
        let mut owner = OwnerDocument::new(
            owner_did.clone(),
            "owner".to_string(),
            "owner@test".to_string(),
            jwk,
        );
        owner.version_seq = Some(0);
        owner.valid_iat = valid_iat;
        owner.encode(Some(key)).unwrap()
    }

    fn build_owner_doc(owner_did: &DID, valid_iat: Option<u64>) -> EncodedDocument {
        let (key, jwk) = owner_signing_key();
        build_owner_doc_with_key(owner_did, valid_iat, &key, jwk)
    }

    /// 构造一个刚发生过 key rotation 的 owner 文档:`#main_key` 是新 key(owner
    /// signing key),另外保留一个 `#legacy_key` 历史条目(mallory key 充当旧 key)。
    fn build_owner_doc_with_legacy_key(owner_did: &DID, new_key: &EncodingKey) -> EncodedDocument {
        let (_, new_jwk) = owner_signing_key();
        let (_, legacy_jwk) = mallory_signing_key();
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

    /// 通用 mock provider:按 (did, doc_type) 精确匹配返回预先注册好的文档,
    /// query_did 的 doc_type=None 视为 zone(与 legacy_doc_type 约定一致)。
    struct DocProvider {
        id: String,
        docs: Vec<(DID, String, EncodedDocument)>,
        states: Vec<PublishedState>,
        calls: AtomicUsize,
    }

    impl DocProvider {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                docs: Vec::new(),
                states: Vec::new(),
                calls: AtomicUsize::new(0),
            }
        }

        fn with_doc(mut self, did: DID, doc_type: &str, doc: EncodedDocument) -> Self {
            self.docs.push((did, doc_type.to_string(), doc));
            self
        }

        fn with_state(mut self, state: PublishedState) -> Self {
            self.states.push(state);
            self
        }
    }

    #[async_trait]
    impl NsProvider for DocProvider {
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
            did: &DID,
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let wanted = doc_type.unwrap_or_default();
            self.docs
                .iter()
                .find(|(d, t, _)| d == did && t == wanted.as_str())
                .map(|(_, _, doc)| doc.clone())
                .ok_or_else(|| NSError::NotFound("no matching doc".into()))
        }

        async fn resolve_published_state(
            &self,
            did: &DID,
            doc_type: &DidDocType,
        ) -> NSResult<Option<PublishedState>> {
            Ok(self
                .states
                .iter()
                .find(|state| state.did == *did && state.doc_type == doc_type.as_str())
                .cloned())
        }
    }

    /// 永远传输失败的 provider(unknown,不是 Missing)。
    struct DownProvider;

    #[async_trait]
    impl NsProvider for DownProvider {
        fn get_id(&self) -> String {
            "down-provider".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::Failed("network down".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Err(NSError::Failed("network down".into()))
        }

        async fn resolve_published_state(
            &self,
            _did: &DID,
            _doc_type: &DidDocType,
        ) -> NSResult<Option<PublishedState>> {
            Err(NSError::Failed("network down".into()))
        }
    }

    struct CountingMissProvider {
        id: String,
        calls: Arc<AtomicUsize>,
    }

    impl CountingMissProvider {
        fn new(id: &str, calls: Arc<AtomicUsize>) -> Self {
            Self {
                id: id.to_string(),
                calls,
            }
        }
    }

    #[async_trait]
    impl NsProvider for CountingMissProvider {
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(NSError::NotFound("no matching doc".into()))
        }
    }

    fn missing_state(did: &DID, doc_type: &str) -> PublishedState {
        PublishedState::missing(did.clone(), doc_type.to_string())
    }

    fn missing_state_with_owner(did: &DID, doc_type: &str, owner: &DID) -> PublishedState {
        let mut state = PublishedState::missing(did.clone(), doc_type.to_string());
        state.effective_owner = Some(owner.clone());
        state
    }

    fn negative_state(did: &DID, doc_type: &str, status: DocumentStatus) -> PublishedState {
        let mut state = PublishedState::missing(did.clone(), doc_type.to_string());
        state.document_status = status;
        state
    }

    async fn resolve(
        q: &NameQuery,
        did: &DID,
        doc_type: DidDocType,
        policy: ResolvePolicy,
    ) -> NSResult<ResolveOutcome> {
        q.query_did_outcome(did, Some(doc_type), policy).await
    }

    fn allow_missing_policy() -> ResolvePolicy {
        let mut policy = ResolvePolicy::default();
        policy.allow_self_signed_when_missing = true;
        policy
    }

    // ---- T0.1: key 类 DID 不是合法入参 ----

    #[tokio::test]
    async fn key_class_did_rejected_without_touching_providers() {
        let q = NameQuery::new();
        let provider = DocProvider::new("bns-authority");
        q.set_method_authority("dev", Box::new(provider)).await;

        for did_str in [
            "did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE",
            "did:key:z6Mk",
        ] {
            let did = DID::from_str(did_str).unwrap();
            let err = q
                .query_did_ex(&did, None, ResolvePolicy::default())
                .await
                .unwrap_err();
            assert!(matches!(err, NSError::InvalidDID(_)), "{}", did_str);
        }
    }

    // ---- 权威渠道 anchored 快路径 ----

    #[tokio::test]
    async fn authority_body_is_anchored_and_wins_first() {
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "zone1.alice");
        let owner_did = DID::new("bns", "alice");
        let zone_doc = build_zone_doc(&zone_did, &owner_did, ts(100), "authority-zone");

        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("authority").with_doc(
                zone_did.clone(),
                "zone",
                zone_doc.clone(),
            )),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                zone_did.clone(),
                "zone",
                build_zone_doc(&zone_did, &owner_did, ts(200), "supplement-zone"),
            )),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, zone_doc);
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::Anchored)
        );
    }

    // ---- T0.2: expected_owner 硬规则 ----

    #[tokio::test]
    async fn first_level_did_without_owner_binding_rejects_self_signed_candidate() {
        // 一级名字无权威 owner 绑定:自签名候选连露面资格都没有。
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "alice");
        // 候选自声明 owner = 自己,签名合法。
        let zone_doc = build_zone_doc(&zone_did, &zone_did, ts(100), "self-owned");
        let owner_doc = build_owner_doc(&zone_did, None);

        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("authority").with_state(missing_state(&zone_did, "zone"))),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(
                DocProvider::new("supplement")
                    .with_doc(zone_did.clone(), "zone", zone_doc)
                    .with_doc(zone_did.clone(), "owner", owner_doc),
            ),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(matches!(last_error, Some(NSError::OwnerConflict(_))));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn mallory_self_declared_owner_is_rejected() {
        // 攻击场景(简化文档第 4 节):候选文档声明 owner = mallory 并由 mallory
        // key 签名。expected_owner(结构默认值 = alice)不是 mallory,必须拒绝——
        // 即使 mallory 的 owner 文档可以被解析、签名本身合法。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let mallory_did = DID::new("bns", "mallory");
        let (mallory_key, mallory_jwk) = mallory_signing_key();

        let forged_doc =
            build_zone_doc_signed_by(&app_did, &mallory_did, ts(100), "forged", &mallory_key);
        let mallory_owner_doc =
            build_owner_doc_with_key(&mallory_did, None, &mallory_key, mallory_jwk);

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&app_did, "zone"))
                    .with_doc(mallory_did.clone(), "owner", mallory_owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(app_did.clone(), "zone", forged_doc)),
        )
        .await;

        let outcome = resolve(&q, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(matches!(last_error, Some(NSError::OwnerConflict(_))));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn structural_owner_candidate_verifies_via_expected_owner_recursion() {
        // 二级名字 + 权威源 Missing + 策略允许:候选仍必须通过 expected_owner
        // 一致性与 owner 验签(策略点②只发放入场券)。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let owner_did = DID::new("bns", "alice");
        let app_doc = build_zone_doc(&app_did, &owner_did, ts(100), "app-doc");
        let owner_doc = build_owner_doc(&owner_did, None);

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&app_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                app_did.clone(),
                "zone",
                app_doc.clone(),
            )),
        )
        .await;

        let outcome = resolve(&q, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, app_doc);
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::NeedProof)
        );
    }

    #[tokio::test]
    async fn authority_owner_binding_overrides_structural_default() {
        // 权威源的 owner 绑定覆盖结构默认值:结构上 app1.alice 归 alice,但权威源
        // 记录 owner 已变更为 bob——此时声明 alice 的候选被拒绝,声明 bob 的通过。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let bob_did = DID::new("bns", "bob");
        let bob_owner_doc = build_owner_doc(&bob_did, None);
        let app_doc_by_bob = build_zone_doc(&app_did, &bob_did, ts(100), "bob-owned");

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state_with_owner(&app_did, "zone", &bob_did))
                    .with_doc(bob_did.clone(), "owner", bob_owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                app_did.clone(),
                "zone",
                app_doc_by_bob.clone(),
            )),
        )
        .await;

        let outcome = resolve(&q, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, app_doc_by_bob);

        // 反向:owner 绑定是 bob 时,声明 alice(结构默认值)的候选也必须拒绝。
        let q2 = NameQuery::new();
        let alice_did = DID::new("bns", "alice");
        let alice_owner_doc = build_owner_doc(&alice_did, None);
        let app_doc_by_alice = build_zone_doc(&app_did, &alice_did, ts(100), "alice-owned");
        q2.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state_with_owner(&app_did, "zone", &bob_did))
                    .with_doc(alice_did.clone(), "owner", alice_owner_doc),
            ),
        )
        .await;
        q2.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                app_did.clone(),
                "zone",
                app_doc_by_alice,
            )),
        )
        .await;

        let outcome = resolve(&q2, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(matches!(last_error, Some(NSError::OwnerConflict(_))));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    // ---- T0.3: verify 硬约束 ----

    #[tokio::test]
    async fn candidate_document_id_mismatch_is_rejected() {
        // 文档自述 id 与请求 DID 不一致:拒绝。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let other_did = DID::new("bns", "app2.alice");
        let owner_did = DID::new("bns", "alice");
        // 文档 id 是 app2.alice,但按 app1.alice 请求。
        let wrong_id_doc = build_zone_doc(&other_did, &owner_did, ts(100), "wrong-id");
        let owner_doc = build_owner_doc(&owner_did, None);

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&app_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                app_did.clone(),
                "zone",
                wrong_id_doc,
            )),
        )
        .await;

        let outcome = resolve(&q, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                let msg = last_error.unwrap().to_string();
                assert!(msg.contains("does not match requested"), "{}", msg);
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn authority_doc_hash_anchors_published_set() {
        // 权威源 Active 只带 doc_hash 锚点:hash 不匹配的候选拒绝,匹配的通过。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let owner_did = DID::new("bns", "alice");
        let published_doc = build_zone_doc(&app_did, &owner_did, ts(100), "published");
        let shadow_doc = build_zone_doc(&app_did, &owner_did, ts(200), "newer-but-unpublished");
        let owner_doc = build_owner_doc(&owner_did, None);

        let anchor_state = |target: &EncodedDocument| {
            let mut state = PublishedState::missing(app_did.clone(), "zone".to_string());
            state.document_status = DocumentStatus::Active;
            state.document_ref = Some(DocumentRef {
                uri: None,
                content_hash: Some(crate::document_content_hash(target)),
                inline_document: None,
            });
            state
        };

        // 场景 1:补充源给出的是未发布的新文档(签名合法)→ 拒绝。
        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(anchor_state(&published_doc))
                    .with_doc(owner_did.clone(), "owner", owner_doc.clone()),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(app_did.clone(), "zone", shadow_doc)),
        )
        .await;
        let outcome = resolve(&q, &app_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(last_error.unwrap().to_string().contains("doc_hash"));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }

        // 场景 2:补充源给出已发布的 body → 通过。
        let q2 = NameQuery::new();
        q2.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(anchor_state(&published_doc))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q2.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                app_did.clone(),
                "zone",
                published_doc.clone(),
            )),
        )
        .await;
        let outcome = resolve(&q2, &app_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, published_doc);
    }

    // ---- T0.4: DR / unknown 二分 ----

    #[tokio::test]
    async fn authority_unknown_rejects_self_signed_candidate() {
        // 权威源没回答(断网)≠ Missing:候选没有"已验证"资格,默认也没有 unproof
        // 露面资格。"谁能断你的网,谁就能给你塞文档"必须堵死。
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let owner_did = DID::new("bns", "alice");
        let app_doc = build_zone_doc(&app_did, &owner_did, ts(100), "valid-but-unverifiable");
        let owner_doc = build_owner_doc(&owner_did, None);

        q.set_method_authority("bns", Box::new(DownProvider)).await;
        q.add_method_supplement(
            "bns",
            Box::new(
                DocProvider::new("supplement")
                    .with_doc(app_did.clone(), "zone", app_doc)
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;

        let outcome = resolve(&q, &app_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer {
                authority_unknown,
                authority_missing,
                ..
            } => {
                assert!(authority_unknown);
                assert!(!authority_missing);
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn authority_missing_without_policy_permission_stops_resolution() {
        let q = NameQuery::new();
        let app_did = DID::new("bns", "app1.alice");
        let owner_did = DID::new("bns", "alice");
        let app_doc = build_zone_doc(&app_did, &owner_did, ts(100), "candidate");

        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("authority").with_state(missing_state(&app_did, "zone"))),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(app_did.clone(), "zone", app_doc)),
        )
        .await;

        // 默认策略不允许 Missing 自签名入场。
        let outcome = resolve(&q, &app_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer {
                authority_missing, ..
            } => assert!(authority_missing),
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    // ---- 策略点①: 负状态 ----

    #[tokio::test]
    async fn revoked_authority_answer_returns_negative_outcome() {
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "revoked.alice");

        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("authority").with_state(negative_state(
                &zone_did,
                "zone",
                DocumentStatus::Revoked,
            ))),
        )
        .await;
        // 即使补充源有"合法"文档,负状态也终止查询。
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                zone_did.clone(),
                "zone",
                build_zone_doc(&zone_did, &DID::new("bns", "alice"), ts(100), "zombie"),
            )),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::Negative { status, .. } => {
                assert_eq!(status, DocumentStatus::Revoked);
            }
            other => panic!("expected Negative, got {:?}", other),
        }
    }

    // ---- Migrated ----

    fn migrated_state(did: &DID, doc_type: &str, target: &DID) -> PublishedState {
        let mut state = PublishedState::missing(did.clone(), doc_type.to_string());
        state.document_status = DocumentStatus::Migrated;
        state.migration_target = Some(target.clone());
        state
    }

    #[tokio::test]
    async fn migrated_follows_target_when_policy_allows() {
        let q = NameQuery::new();
        let old_did = DID::new("bns", "old-zone");
        let new_did = DID::new("bns", "zone1.alice");
        let owner_did = DID::new("bns", "alice");
        let new_doc = build_zone_doc(&new_did, &owner_did, ts(0), "migration-target");

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(migrated_state(&old_did, "zone", &new_did))
                    .with_doc(new_did.clone(), "zone", new_doc.clone()),
            ),
        )
        .await;

        let outcome = resolve(&q, &old_did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, new_doc);
    }

    #[tokio::test]
    async fn migrated_rejected_when_policy_disallows() {
        let q = NameQuery::new();
        let old_did = DID::new("bns", "old-zone-2");
        let new_did = DID::new("bns", "new-zone-2");

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(migrated_state(&old_did, "zone", &new_did)),
            ),
        )
        .await;

        let mut policy = ResolvePolicy::default();
        policy.follow_migration = false;
        let outcome = resolve(&q, &old_did, DidDocType::Zone, policy)
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::Negative { status, .. } => {
                assert_eq!(status, DocumentStatus::Migrated);
            }
            other => panic!("expected Negative, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn migration_loop_is_rejected_by_descend_guard() {
        let q = NameQuery::new();
        let did_a = DID::new("bns", "loop-a");
        let did_b = DID::new("bns", "loop-b");

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(migrated_state(&did_a, "zone", &did_b))
                    .with_state(migrated_state(&did_b, "zone", &did_a)),
            ),
        )
        .await;

        let result = resolve(&q, &did_a, DidDocType::Zone, ResolvePolicy::default()).await;
        assert!(result.is_err());
    }

    // ---- 历史 key / revoke_before_iat(T1.3 保留资产) ----

    #[tokio::test]
    async fn signature_by_historical_key_succeeds_with_warning() {
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "alice");
        let zone_did = DID::new("bns", "legacy.alice");

        let (new_key, _) = owner_signing_key();
        let owner_doc = build_owner_doc_with_legacy_key(&owner_did, &new_key);
        // zone 文档用被 rotate 掉的旧 key(mallory key 充当)签名。
        let (legacy_key, _) = mallory_signing_key();
        let zone_doc = build_zone_doc_signed_by(
            &zone_did,
            &owner_did,
            ts(1000),
            "legacy-signed",
            &legacy_key,
        );

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&zone_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(
                zone_did.clone(),
                "zone",
                zone_doc.clone(),
            )),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, zone_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::SignedByHistoricalKey));
    }

    #[tokio::test]
    async fn wrong_signature_candidate_is_rejected() {
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "alice");
        let zone_did = DID::new("bns", "badsig.alice");

        let owner_doc = build_owner_doc(&owner_did, None);
        let (mallory_key, _) = mallory_signing_key();
        // 声明的 owner 是 alice(与 expected_owner 一致),但签名是 mallory 的。
        let bad_doc =
            build_zone_doc_signed_by(&zone_did, &owner_did, ts(1000), "bad-sig", &mallory_key);

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&zone_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("supplement").with_doc(zone_did.clone(), "zone", bad_doc)),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(last_error
                    .unwrap()
                    .to_string()
                    .contains("signature verification failed"));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn owner_revoke_before_iat_rejects_older_documents() {
        let q = NameQuery::new();
        let owner_did = DID::new("bns", "alice");
        let old_zone_did = DID::new("bns", "old.alice");
        let new_zone_did = DID::new("bns", "new.alice");

        let owner_doc = build_owner_doc(&owner_did, Some(ts(1000)));
        let old_zone_doc = build_zone_doc(&old_zone_did, &owner_did, ts(900), "old");
        let new_zone_doc = build_zone_doc(&new_zone_did, &owner_did, ts(1100), "new");

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&old_zone_did, "zone"))
                    .with_state(missing_state(&new_zone_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(
                DocProvider::new("supplement")
                    .with_doc(old_zone_did.clone(), "zone", old_zone_doc)
                    .with_doc(new_zone_did.clone(), "zone", new_zone_doc.clone()),
            ),
        )
        .await;

        let outcome = resolve(&q, &old_zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        match outcome {
            ResolveOutcome::NoAnswer { last_error, .. } => {
                assert!(last_error
                    .unwrap()
                    .to_string()
                    .contains("revoke_before_iat"));
            }
            other => panic!("expected NoAnswer, got {:?}", other),
        }

        let outcome = resolve(&q, &new_zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, new_zone_doc);
    }

    // ---- 契约违规只作废单个候选 ----

    #[tokio::test]
    async fn contract_violating_candidate_recorded_as_warning_while_valid_one_wins() {
        let q = NameQuery::new();
        let zone_did = DID::new("bns", "zone1.alice");
        let owner_did = DID::new("bns", "alice");

        let owner_doc = build_owner_doc(&owner_did, None);
        let good_doc = build_zone_doc(&zone_did, &owner_did, ts(1000), "good");
        let unsigned_doc = EncodedDocument::JsonLd(json!({
            "id": zone_did.to_string(),
            "iat": ts(2000),
            "exp": ts(3000),
            "marker": "unsigned-candidate"
        }));

        q.set_method_authority(
            "bns",
            Box::new(
                DocProvider::new("authority")
                    .with_state(missing_state(&zone_did, "zone"))
                    .with_doc(owner_did.clone(), "owner", owner_doc),
            ),
        )
        .await;
        // 第一个补充源给出无签名 JsonLd(契约违规),第二个给出可验证候选。
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("bad-supplement").with_doc(
                zone_did.clone(),
                "zone",
                unsigned_doc,
            )),
        )
        .await;
        q.add_method_supplement(
            "bns",
            Box::new(DocProvider::new("good-supplement").with_doc(
                zone_did.clone(),
                "zone",
                good_doc.clone(),
            )),
        )
        .await;

        let outcome = resolve(&q, &zone_did, DidDocType::Zone, allow_missing_policy())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, good_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .iter()
            .any(|warning| matches!(warning, ResolveWarning::EvidenceContractViolation { .. })));
    }

    // ---- Info 免验证路径 ----

    #[tokio::test]
    async fn info_doc_type_uses_unproof_path() {
        let q = NameQuery::new();
        let did = DID::new("web", "device.example");
        let info_doc = EncodedDocument::JsonLd(json!({
            "iat": 100,
            "exp": 200,
            "info": true
        }));

        q.set_method_authority(
            "web",
            Box::new(DocProvider::new("authority").with_doc(did.clone(), "info", info_doc.clone())),
        )
        .await;

        let outcome = resolve(&q, &did, DidDocType::Info, ResolvePolicy::default())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, info_doc);
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::UnproofInfo)
        );
        assert_eq!(resolved.document_metadata.buckyos.doc_type, "info");
        assert_eq!(resolved.document_metadata.buckyos.document_status, None);
    }

    // ---- 本地覆盖 ----

    #[tokio::test]
    async fn local_authority_override_short_circuits_before_authority() {
        let q = NameQuery::new();
        let did = DID::new("bns", "override.alice");
        let override_doc = EncodedDocument::JsonLd(json!({"marker": "override"}));

        // 权威源甚至会回答 Revoked——override 也要盖得住(hosts 语义)。
        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("authority").with_state(negative_state(
                &did,
                "zone",
                DocumentStatus::Revoked,
            ))),
        )
        .await;

        let store = Arc::new(crate::LocalAuthorityOverrideStore::new());
        store.set(
            did.clone(),
            &DidDocType::Zone,
            override_doc.clone(),
            "test-env",
            None,
        );
        let policy = ResolvePolicy::default().with_local_authority_override(store);

        let outcome = resolve(&q, &did, DidDocType::Zone, policy).await.unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, override_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::LocalAuthorityOverride));
    }

    // ---- method registry ----

    #[tokio::test]
    async fn current_zone_bootstrap_scope_gates_verified_document_loop() {
        let q = NameQuery::new();
        let current_zone = DID::new("web", "current.example");
        let other_zone = DID::new("web", "other.example");
        let calls = Arc::new(AtomicUsize::new(0));

        q.add_current_zone_bootstrap_supplement(
            "web",
            Box::new(CountingMissProvider::new(
                "dns-bootstrap",
                calls.clone(),
            )),
        )
        .await;

        let current_policy = ResolvePolicy::default().with_current_zone(current_zone.clone());
        let _ = q
            .query_did_ex(
                &current_zone,
                Some(DidDocType::Boot),
                current_policy.clone(),
            )
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // policy 被带到非 current-zone DID 时必须在 provider I/O 之前跳过。
        let _ = q
            .query_did_ex(&other_zone, Some(DidDocType::Boot), current_policy)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 默认 policy 对 current-zone bootstrap supplement 也没有访问权限。
        let _ = q
            .query_did_ex(
                &current_zone,
                Some(DidDocType::Boot),
                ResolvePolicy::default(),
            )
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn current_zone_bootstrap_supplement_is_scoped_to_exact_policy_did() {
        let q = NameQuery::new();
        let current_zone = DID::new("web", "current.example");
        let other_zone = DID::new("web", "other.example");

        let bootstrap_current =
            EncodedDocument::JsonLd(json!({"marker": "current-zone-bootstrap"}));
        let bootstrap_other =
            EncodedDocument::JsonLd(json!({"marker": "must-not-leak-to-other-zone"}));
        let normal_current = EncodedDocument::JsonLd(json!({"marker": "normal-current"}));
        let normal_other = EncodedDocument::JsonLd(json!({"marker": "normal-other"}));

        q.add_current_zone_bootstrap_supplement(
            "web",
            Box::new(
                DocProvider::new("dns-bootstrap")
                    .with_doc(current_zone.clone(), "info", bootstrap_current.clone())
                    .with_doc(other_zone.clone(), "info", bootstrap_other),
            ),
        )
        .await;
        q.add_method_supplement(
            "web",
            Box::new(
                DocProvider::new("normal-supplement")
                    .with_doc(current_zone.clone(), "info", normal_current.clone())
                    .with_doc(other_zone.clone(), "info", normal_other.clone()),
            ),
        )
        .await;

        let current_policy = ResolvePolicy::default().with_current_zone(current_zone.clone());
        let current = q
            .query_did_ex(
                &current_zone,
                Some(DidDocType::Info),
                current_policy.clone(),
            )
            .await
            .unwrap();
        assert_eq!(current.document, bootstrap_current);
        assert_eq!(
            current.resolution_metadata.resolver_id.as_deref(),
            Some("dns-bootstrap")
        );

        // 同一 policy 传播到其它 DID 时,bootstrap supplement 必须跳过,并继续
        // 后面的正常 supplement。
        let other = q
            .query_did_ex(&other_zone, Some(DidDocType::Info), current_policy)
            .await
            .unwrap();
        assert_eq!(other.document, normal_other);
        assert_eq!(
            other.resolution_metadata.resolver_id.as_deref(),
            Some("normal-supplement")
        );

        // 普通 resolve 的默认 policy 没有 current-zone 上下文,即使请求 DID
        // 恰好相同也不能访问 bootstrap supplement。
        let current_without_bootstrap = q
            .query_did_ex(
                &current_zone,
                Some(DidDocType::Info),
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(current_without_bootstrap.document, normal_current);
        assert_eq!(
            current_without_bootstrap
                .resolution_metadata
                .resolver_id
                .as_deref(),
            Some("normal-supplement")
        );
    }

    #[tokio::test]
    async fn unknown_method_is_not_supported() {
        let q = NameQuery::new();
        let did = DID::new("web", "example.com");
        let err = q
            .query_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn duplicate_authority_registration_keeps_first() {
        let q = NameQuery::new();
        let did = DID::new("bns", "zone1.alice");
        let owner_did = DID::new("bns", "alice");
        let first_doc = build_zone_doc(&did, &owner_did, ts(100), "first");
        let second_doc = build_zone_doc(&did, &owner_did, ts(200), "second");

        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("first").with_doc(did.clone(), "zone", first_doc.clone())),
        )
        .await;
        q.set_method_authority(
            "bns",
            Box::new(DocProvider::new("second").with_doc(did.clone(), "zone", second_doc)),
        )
        .await;

        let outcome = resolve(&q, &did, DidDocType::Zone, ResolvePolicy::default())
            .await
            .unwrap();
        let ResolveOutcome::Resolved(resolved) = outcome else {
            panic!("expected resolved");
        };
        assert_eq!(resolved.document, first_doc);
    }
}
