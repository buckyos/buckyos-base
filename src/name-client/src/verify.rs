//! verify 家族的 I/O 组合层(doc/verify-did-api-boundary-and-freshness-TODO.md)。
//!
//! 纯 verify 在 `verify_context.rs`(同步、无网络、无写入);本模块提供:
//!
//! - [`NameClient::build_verify_context`]:按 [`crate::ResolveSourcePolicy`]
//!   组装只读 trust snapshot(这是 resolve 家族的操作:可能访问 Zone/权威、
//!   可能回填解析缓存,函数名与 policy 显式暴露这一点);
//! - 组合便捷 API [`NameClient::resolve_and_verify_did_document`] /
//!   [`NameClient::resolve_verify_and_cache_did_document`]:名字显式暴露
//!   "resolve + verify (+ cache)"组合了哪些动作;
//! - [`NameClient::verify_and_promote`]:Observed→Trusted 的 lazy verify,
//!   实现为"按 RemoteAuthority 构建 snapshot → 纯 verify → promote 落盘"。
//!
//! 应用层拿到一份外部 DID Document(典型:RTCP 握手里的 `device_doc_jwt`)时,
//! 不允许自己拼 `payload.owner -> resolve_auth_key -> verify`——那只能证明
//! "JWT 能被它自己声明的 owner 验过"。必须走本模块,验签 owner 只能来自权威
//! 绑定或 method 结构规则(expected_owner),绝不来自 payload。

use buckyos_kit::buckyos_get_unix_timestamp;
use log::*;
use name_lib::*;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::doc_cache::{CacheEvidence, CacheWriteOutcome};
use crate::name_client::NameClient;
use crate::verify_context::*;
use crate::zone_resolver::ZoneLookup;
use crate::{
    is_key_class_method, DidDocType, DocumentStatus, ProviderResolveResult, ResolvePolicy,
    ResolveSourcePolicy, ResolveWarning,
};

/// snapshot 构建序号(进程内单调):同一次验证只消费一个 generation,
/// 避免混用并发更新前后的证据;仅用于诊断。
static SNAPSHOT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// 组合 API 的选项:resolve 行为完全由 `policy`(含
/// [`crate::ResolveSourcePolicy`])显式决定,verify 行为由 `purpose` 决定。
/// 是否写 cache 由**函数名**区分(`resolve_and_verify_*` 不写;
/// `resolve_verify_and_cache_*` 写 verified 命名空间),不再有隐藏的
/// `cache_result` 开关。
#[derive(Debug, Clone)]
pub struct ResolveVerifyOptions {
    pub purpose: VerifyPurpose,
    pub policy: ResolvePolicy,
}

impl Default for ResolveVerifyOptions {
    fn default() -> Self {
        Self {
            purpose: VerifyPurpose::AuthSubject,
            policy: ResolvePolicy::default(),
        }
    }
}

impl ResolveVerifyOptions {
    pub fn with_source(mut self, source: ResolveSourcePolicy) -> Self {
        self.policy.source = source;
        self
    }

    pub fn with_purpose(mut self, purpose: VerifyPurpose) -> Self {
        self.purpose = purpose;
        self
    }
}

/// 组合 API 的错误:resolve 阶段(snapshot 构建)与 verify 阶段分开表达,
/// 调用方能准确区分"证据取不到"和"候选验不过"。
#[derive(Debug)]
pub enum ResolveVerifyError {
    Resolve(NSError),
    Verify(VerifyError),
}

impl std::fmt::Display for ResolveVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(err) => write!(f, "resolve stage failed: {}", err),
            Self::Verify(err) => write!(f, "verify stage failed: {}", err),
        }
    }
}

impl std::error::Error for ResolveVerifyError {}

/// lazy verify(verify_and_promote)的产物(doc/update-did-cache.md"API 草案")。
#[derive(Debug)]
pub enum VerifyPromoteOutcome {
    /// 验证通过,文件已从 unverified 移动(promote)到 verified,可以按 Verified
    /// 返回。极小概率的并发窗口里 verified 已出现更优记录时源文件同样被清理,
    /// 刚验证过的这份文档仍按 Verified 返回。
    Promoted(EncodedDocument),
    /// 验证明确失败(owner 冒充、签名不对、被 owner policy 吊销、权威明确否定)。
    /// unverified 条目已被删除,避免同一份坏数据反复触发验证开销。
    Rejected(NSError),
    /// 验证所需条件暂不可用(owner document 拿不到、权威没回答)。
    /// unverified 条目保留,不删除、不 promote;strict 语义下等同 cache miss,
    /// `ResolvePolicy::allow_unverified_cache_when_unavailable` 决定是否可以在
    /// resolve_did_ex 的宽松模式露面。
    Unavailable(NSError),
}

impl NameClient {
    /// 按 `policy.source` 组装纯 verify 用的只读 trust snapshot。
    ///
    /// 这是 **resolve 家族**的操作,不是纯 verify 的一部分:
    /// - `LocalOnly`:只读本机 `verified/` cache 与负状态记忆,零网络;
    /// - `LocalAndZone`:再加一次 Zone Resolver 查询(Zone 回答时主 scope 为
    ///   Zone,与 L1/L2 层级一致);
    /// - `RemoteAuthority`:再加一次 method authority 查询,产出权威 receipt
    ///   (只有它能支撑 `AuthorityFreshness::Current`);owner 材料走正常优先级
    ///   (`for_owner_lookup`,含缓存复用);
    /// - `BestAvailable`:LocalAndZone + 权威查询(等价于旧 verify 入口的
    ///   证据面)。
    ///
    /// 学习性写入(权威 terminal 负状态写 negative cache、Migrated 删除条目)
    /// 发生在这里——它们归 resolve 的缓存回填,不违反纯 verify 无写入边界。
    pub async fn build_verify_context(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        policy: &ResolvePolicy,
    ) -> NSResult<VerifyContextSnapshot> {
        if is_key_class_method(&did.method) {
            return Err(NSError::InvalidDID(format!(
                "key-class DID {} cannot be a verification subject",
                did.to_string()
            )));
        }
        // Info 契约类 doc_type 按 method 契约免验证,没有 owner 信任链可验。
        if self
            .name_query
            .is_no_proof_doc_type(&did.method, doc_type)
            .await
        {
            return Err(NSError::InvalidParam(format!(
                "doc_type {} is an unauthenticated info contract; verify does not apply",
                doc_type
            )));
        }

        let now = buckyos_get_unix_timestamp();
        let mut snapshot = VerifyContextSnapshot {
            scope: LocalTrustScope::Host,
            generation: SNAPSHOT_GENERATION.fetch_add(1, Ordering::Relaxed),
            checked_at: now,
            valid_until: None,
            authority: SnapshotAuthorityState::NotConsulted,
            owner_binding: None,
            owner_material: None,
            baseline: SnapshotBaseline::Unavailable {
                reason: "local cache disabled".to_string(),
            },
            negative_state: None,
            scope_negative: None,
        };

        // ---- Host 事实(零 I/O 之外的本机文件读)----
        if self.config.enable_cache {
            snapshot.baseline = match self.doc_cache.verified_entry(did, Some(doc_type.clone())) {
                Some((doc, _exp, _evidence)) => match DocumentRevision::of(&doc) {
                    Some(revision) => SnapshotBaseline::Known(revision),
                    None => SnapshotBaseline::Unavailable {
                        reason: "cached baseline document has no derivable iat".to_string(),
                    },
                },
                None => SnapshotBaseline::Empty,
            };
            if let Some((status, message)) =
                self.doc_cache.negative_memory(did, Some(doc_type.clone()))
            {
                // 现状负缓存只记录 terminal 状态。
                let status = match status.as_str() {
                    "Tombstoned" => DocumentStatus::Tombstoned,
                    _ => DocumentStatus::Revoked,
                };
                snapshot.negative_state = Some(SnapshotNegativeState {
                    status,
                    scope: LocalTrustScope::Host,
                    origin: format!("negative-cache: {}", message),
                });
            }
        }

        // ---- Zone 事实(显式允许的 I/O;Zone 回答时主 scope 切到 Zone)----
        let zone_allowed = matches!(
            policy.source,
            ResolveSourcePolicy::LocalAndZone | ResolveSourcePolicy::BestAvailable
        ) && policy.use_zone_resolver;
        if zone_allowed {
            if let Some(zone) = self.zone_resolver_snapshot() {
                match zone.lookup(did, doc_type, false).await {
                    ZoneLookup::Answered(answer) => {
                        snapshot.scope = LocalTrustScope::Zone;
                        if let Some(state) = answer.state.as_ref() {
                            if let Some(owner) = state.effective_owner.clone() {
                                snapshot.owner_binding = Some(SnapshotOwnerBinding {
                                    owner,
                                    source: EvidenceSource::ZoneSnapshot,
                                });
                            }
                            snapshot.valid_until = state.valid_until;
                        }
                        match &answer.result {
                            Ok(resolved) => {
                                // Zone 已接受的当前文档 → Zone scope 基线。
                                // wire docHash 存在时以它为准(candidate hash
                                // 绑定与 freshness 比较使用同一契约)。
                                let wire_revision = answer.state.as_ref().and_then(|state| {
                                    let hash = state
                                        .document_ref
                                        .as_ref()
                                        .and_then(|doc_ref| doc_ref.content_hash.clone())?;
                                    let iat = state
                                        .document_version
                                        .or_else(|| crate::document_iat(&resolved.document))?;
                                    Some(DocumentRevision {
                                        iat,
                                        content_hash: normalize_wire_hash(&hash),
                                    })
                                });
                                snapshot.baseline = match wire_revision
                                    .or_else(|| DocumentRevision::of(&resolved.document))
                                {
                                    Some(revision) => SnapshotBaseline::Known(revision),
                                    None => SnapshotBaseline::Unavailable {
                                        reason: "zone answer has no derivable revision iat"
                                            .to_string(),
                                    },
                                };
                            }
                            Err(NSError::Disabled(detail)) => {
                                // Zone 的 terminal 负回答(Revoked/Tombstoned/
                                // Migrated/deactivated/裸 410)。Migrated 是非
                                // terminal 事实;其余按 terminal 硬失败材料记录。
                                let status = answer
                                    .state
                                    .as_ref()
                                    .map(|state| state.document_status.clone())
                                    .unwrap_or(DocumentStatus::Revoked);
                                if status.is_terminal() {
                                    snapshot.negative_state = Some(SnapshotNegativeState {
                                        status,
                                        scope: LocalTrustScope::Zone,
                                        origin: format!("zone-answer: {}", detail),
                                    });
                                } else {
                                    snapshot.scope_negative = Some(status);
                                    snapshot.baseline = SnapshotBaseline::Empty;
                                }
                            }
                            Err(NSError::NotFound(_)) => {
                                // Zone 明确 Missing/Expired:Zone scope 的非
                                // terminal 负状态事实,是否接受由 freshness
                                // policy 决定(bootstrap 场景)。
                                let status = answer
                                    .state
                                    .as_ref()
                                    .map(|state| state.document_status.clone())
                                    .unwrap_or(DocumentStatus::Missing);
                                snapshot.scope_negative = Some(status);
                                snapshot.baseline = SnapshotBaseline::Empty;
                            }
                            Err(_) => {
                                // Zone 声称回答却给出坏文档:不改变 Host 基线,
                                // 主 scope 退回 Host。
                                snapshot.scope = LocalTrustScope::Host;
                            }
                        }
                    }
                    ZoneLookup::Unknown(err) => {
                        debug!(
                            "zone resolver unknown while building verify context for {}#{}: {}",
                            did.to_string(),
                            doc_type,
                            err
                        );
                    }
                }
            }
        }

        // ---- 权威 receipt(只有它能支撑 AuthorityFreshness::Current)----
        let authority_allowed = matches!(
            policy.source,
            ResolveSourcePolicy::RemoteAuthority | ResolveSourcePolicy::BestAvailable
        );
        if authority_allowed {
            let attempted_at = buckyos_get_unix_timestamp();
            match self.name_query.authority_answer_for(did, doc_type).await? {
                None => {
                    snapshot.authority = SnapshotAuthorityState::NoChannel;
                }
                Some(ProviderResolveResult::Unknown(err)) => {
                    snapshot.authority = SnapshotAuthorityState::Unreachable {
                        attempted_at,
                        source: None,
                        detail: err.to_string(),
                    };
                }
                Some(ProviderResolveResult::Dr(answer)) => {
                    let status = answer.status.clone().unwrap_or(DocumentStatus::Active);
                    // 学习性缓存回填(resolve 家族的职责):权威 terminal 负状态
                    // 写 negative cache;Migrated 删除本机正条目。
                    if self.config.enable_cache {
                        match &status {
                            DocumentStatus::Revoked | DocumentStatus::Tombstoned => {
                                let message = format!(
                                    "{}#{} is {:?} in method authority",
                                    did.to_string(),
                                    doc_type,
                                    status
                                );
                                self.doc_cache.replace_with_negative(
                                    did,
                                    Some(doc_type.clone()),
                                    &status,
                                    &message,
                                );
                            }
                            DocumentStatus::Migrated => {
                                self.doc_cache.delete(did.clone(), Some(doc_type.clone()));
                            }
                            _ => {}
                        }
                    }
                    let source = answer
                        .body
                        .as_ref()
                        .and_then(|body| body.resolver_id.clone())
                        .unwrap_or_else(|| format!("method-authority:{}", did.method));
                    let (published_checked_at, published_valid_until, authority_seq, document_iat) =
                        match answer.published.as_ref() {
                            Some(published) => (
                                published.checked_at,
                                published.valid_until,
                                published.authority_seq,
                                published.document_version,
                            ),
                            None => (None, None, None, None),
                        };
                    if let Some(owner) = answer.owner_binding.clone() {
                        // 权威绑定优先于 Zone 绑定。
                        snapshot.owner_binding = Some(SnapshotOwnerBinding {
                            owner,
                            source: EvidenceSource::AuthorityReceipt,
                        });
                    }
                    if let Some(valid_until) = published_valid_until {
                        snapshot.valid_until = Some(
                            snapshot
                                .valid_until
                                .map_or(valid_until, |current| current.min(valid_until)),
                        );
                    }
                    snapshot.authority = SnapshotAuthorityState::Receipt(AuthorityReceipt {
                        status,
                        doc_hash: answer.doc_hash.clone(),
                        current_body: answer.body.map(|body| body.document),
                        effective_owner: answer.owner_binding,
                        authority_seq,
                        document_iat,
                        migration_target: answer.migration_target,
                        checked_at: published_checked_at.unwrap_or(attempted_at),
                        valid_until: published_valid_until,
                        source,
                    });
                }
            }
        }

        // ---- expected_owner 的 OwnerDocument 材料 ----
        let expected_owner = snapshot
            .owner_binding
            .as_ref()
            .map(|binding| binding.owner.clone())
            .or_else(|| crate::structural_owner(did));
        if let Some(owner) = expected_owner {
            if *doc_type != DidDocType::Owner || owner != *did {
                snapshot.owner_material = self
                    .load_owner_material(&owner, did, doc_type, policy)
                    .await;
            }
        }

        Ok(snapshot)
    }

    /// 解析 expected_owner 的 OwnerDocument(snapshot 构建的一部分)。
    /// 来源受 `policy.source` 约束:LocalOnly/LocalAndZone 不出网;
    /// RemoteAuthority/BestAvailable 走 `for_owner_lookup`(正常优先级 + 收紧
    /// 准入,含 `descend` 环路检查)。拿不到时返回 None(纯 verify 报
    /// `MissingDependency`),不在这里失败。
    async fn load_owner_material(
        &self,
        owner: &DID,
        did: &DID,
        doc_type: &DidDocType,
        policy: &ResolvePolicy,
    ) -> Option<SnapshotOwnerMaterial> {
        match policy.source {
            ResolveSourcePolicy::LocalOnly => self.local_owner_material(owner),
            ResolveSourcePolicy::LocalAndZone => {
                if let Some(material) = self.local_owner_material(owner) {
                    return Some(material);
                }
                let zone = self.zone_resolver_snapshot()?;
                if !policy.use_zone_resolver {
                    return None;
                }
                match zone.lookup(owner, &DidDocType::Owner, false).await {
                    ZoneLookup::Answered(answer) => match answer.result {
                        Ok(resolved) => Some(SnapshotOwnerMaterial {
                            owner: owner.clone(),
                            document: resolved.document,
                            source: EvidenceSource::ZoneSnapshot,
                        }),
                        Err(_) => None,
                    },
                    ZoneLookup::Unknown(_) => None,
                }
            }
            ResolveSourcePolicy::RemoteAuthority | ResolveSourcePolicy::BestAvailable => {
                // 递归入口是 expected_owner,绝不是 declared_owner;descend()
                // 的深度/环路检查跨 verify 与 resolve_did_ex 的相互调用生效。
                let owner_policy = policy
                    .for_owner_lookup()
                    .descend(owner, &DidDocType::Owner)
                    .ok()?;
                let resolved = Box::pin(self.resolve_did_ex(
                    owner,
                    Some(DidDocType::Owner),
                    owner_policy,
                ))
                .await;
                match resolved {
                    Ok(resolved) => {
                        let source = if resolved
                            .resolution_metadata
                            .warnings
                            .contains(&ResolveWarning::LocalAuthorityOverride)
                        {
                            EvidenceSource::LocalOverride
                        } else {
                            match resolved.resolution_metadata.cache_status {
                                Some(crate::CacheStatus::ZoneHit) => EvidenceSource::ZoneSnapshot,
                                Some(crate::CacheStatus::Hit) | Some(crate::CacheStatus::Fallback) => {
                                    EvidenceSource::LocalCache
                                }
                                _ => EvidenceSource::AuthorityReceipt,
                            }
                        };
                        Some(SnapshotOwnerMaterial {
                            owner: owner.clone(),
                            document: resolved.document,
                            source,
                        })
                    }
                    Err(err) => {
                        debug!(
                            "resolve owner document {} for {}#{} failed: {}",
                            owner.to_string(),
                            did.to_string(),
                            doc_type,
                            err
                        );
                        None
                    }
                }
            }
        }
    }

    /// 本机 `verified/` 命名空间里的 owner 材料(Observed/Unverified 不合格)。
    fn local_owner_material(&self, owner: &DID) -> Option<SnapshotOwnerMaterial> {
        if !self.config.enable_cache {
            return None;
        }
        let (doc, _exp, _evidence) = self
            .doc_cache
            .verified_entry(owner, Some(DidDocType::Owner))
            .or_else(|| self.doc_cache.verified_entry(owner, None))?;
        // 必须真的是 OwnerDocument 才能作为验签材料。
        OwnerDocument::decode(&doc, None).ok()?;
        Some(SnapshotOwnerMaterial {
            owner: owner.clone(),
            document: doc,
            source: EvidenceSource::LocalCache,
        })
    }

    /// 组合便捷 API:按 `options.policy` 构建 snapshot,然后纯 verify 调用方
    /// 给出的确切文档。**不写任何 cache**;要落盘用
    /// [`Self::resolve_verify_and_cache_did_document`]。
    pub async fn resolve_and_verify_did_document(
        &self,
        did: &DID,
        doc_type: DidDocType,
        candidate: &EncodedDocument,
        options: &ResolveVerifyOptions,
    ) -> Result<VerifiedDidDocument, ResolveVerifyError> {
        let snapshot = self
            .build_verify_context(did, &doc_type, &options.policy)
            .await
            .map_err(ResolveVerifyError::Resolve)?;
        verify_did_document(
            did,
            doc_type,
            candidate,
            &snapshot,
            VerifyOptions {
                purpose: options.purpose,
            },
        )
        .map_err(ResolveVerifyError::Verify)
    }

    /// JWT 字符串便捷入口(RTCP 等上游拿到的就是 compact JWT)。做 JWT 形状
    /// 检查后走 [`Self::resolve_and_verify_did_document`]。
    pub async fn resolve_and_verify_did_document_jwt(
        &self,
        did: &DID,
        doc_type: DidDocType,
        jwt: &str,
        options: &ResolveVerifyOptions,
    ) -> Result<VerifiedDidDocument, ResolveVerifyError> {
        if jwt.split('.').count() != 3 || jwt.split('.').any(|segment| segment.is_empty()) {
            return Err(ResolveVerifyError::Verify(VerifyError::InvalidDocument {
                detail: "input is not a JWT (expect 3 dot-separated segments)".to_string(),
            }));
        }
        let candidate = EncodedDocument::Jwt(jwt.to_string());
        self.resolve_and_verify_did_document(did, doc_type, &candidate, options)
            .await
    }

    /// DeviceDocument typed wrapper(RTCP 迁移入口):source device 用
    /// `subject_did`,source owner 用 `authz_owner`,tunnel token 验证 key 从
    /// 返回的 DeviceDocument 取;freshness 事实由 RTCP 对照自己的 high-water
    /// policy 使用。对端私钥持有证明与 zone 归属检查仍由 RTCP 自己完成。
    pub async fn resolve_and_verify_device_document_jwt(
        &self,
        did: &DID,
        jwt: &str,
        options: &ResolveVerifyOptions,
    ) -> Result<(DeviceDocument, VerifiedDidDocument), ResolveVerifyError> {
        let verified = self
            .resolve_and_verify_did_document_jwt(did, DidDocType::Device, jwt, options)
            .await?;
        let device_document = DeviceDocument::decode(&verified.document, None).map_err(|err| {
            ResolveVerifyError::Verify(VerifyError::InvalidDocument {
                detail: format!(
                    "decode verified DeviceDocument {} failed: {}",
                    did.to_string(),
                    err
                ),
            })
        })?;
        Ok((device_document, verified))
    }

    /// 组合便捷 API:resolve + verify + **显式**写 verified cache。写入命名空间
    /// 与证据等级由验证事实决定:权威 membership 成立(`AuthorityFreshness::
    /// Current`)写 `Published`,否则写 `Verified`;detached-owner 的
    /// ObjectDocument 结果固定不写([`CacheWriteOutcome::SkippedByPolicy`],
    /// 现有 cache 条目无法记录 purpose)。
    pub async fn resolve_verify_and_cache_did_document(
        &self,
        did: &DID,
        doc_type: DidDocType,
        candidate: &EncodedDocument,
        options: &ResolveVerifyOptions,
    ) -> Result<(VerifiedDidDocument, CacheWriteOutcome), ResolveVerifyError> {
        let verified = self
            .resolve_and_verify_did_document(did, doc_type, candidate, options)
            .await?;
        let outcome = self.store_verified_result(&verified);
        Ok((verified, outcome))
    }

    /// 已验证结果的受控落盘(add_cache 动词的组合封装)。
    fn store_verified_result(&self, verified: &VerifiedDidDocument) -> CacheWriteOutcome {
        if !self.config.enable_cache {
            return CacheWriteOutcome::SkippedByPolicy;
        }
        if verified.validity.detached_owner {
            // detached(只有 ObjectDocument 能走到)不写普通 cache:现有条目
            // 无法记录 purpose / usable_as_authz_subject,旧调用方可能把同一
            // 条目误当权限主体使用。
            return CacheWriteOutcome::SkippedByPolicy;
        }
        let evidence = if matches!(
            verified.freshness.authority,
            AuthorityFreshness::Current { .. }
        ) {
            CacheEvidence::Published
        } else {
            CacheEvidence::Verified
        };
        let exp = Self::cache_ttl_exp(&verified.document);
        let outcome = self.doc_cache.update(
            verified.subject_did.clone(),
            Some(verified.doc_type.clone()),
            verified.document.clone(),
            exp,
            evidence,
        );
        if outcome.stored() && verified.doc_type == DidDocType::Zone {
            // 与 resolve 路径的缓存布局一致:zone 文档同时写默认槽位。
            self.doc_cache.update(
                verified.subject_did.clone(),
                None,
                verified.document.clone(),
                exp,
                evidence,
            );
        }
        outcome
    }

    /// verify_and_promote 的 purpose 默认规则表(doc/update-did-cache.md
    /// "未决问题 4"的实施决定):主体类文档(zone/owner/device/user/boot 及
    /// 默认槽位)按 `AuthSubject` 的严格语义验证(detached owner 直接拒绝);
    /// 客体类文档(did-object 与自定义类型)按 `ObjectDocument`。误判方向是
    /// "更严格、不 promote",不会放宽信任。
    fn default_verify_purpose(doc_type: &DidDocType) -> VerifyPurpose {
        match doc_type {
            DidDocType::DidObject | DidDocType::Custom(_) => VerifyPurpose::ObjectDocument,
            _ => VerifyPurpose::AuthSubject,
        }
    }

    /// 对 `unverified/` cache 里 (did, doc_type) 当前的候选文档做一次 lazy verify
    /// (doc/update-did-cache.md):按 RemoteAuthority 构建 snapshot → 纯 verify
    /// → promote 落盘。Observed→Trusted 需要权威状态,因此 snapshot 构建固定用
    /// `RemoteAuthority`(调用方 policy 的 descend 链与 override 保留)。
    ///
    /// 触发时机只有一处:`resolve_did_ex` 在本机 cache 命中且证据等级为
    /// `Unverified` 时,在使用它之前调用。不做后台批量扫描/预热。
    pub(crate) async fn verify_and_promote(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        policy: &ResolvePolicy,
    ) -> NSResult<VerifyPromoteOutcome> {
        let Some((document, _exp, _source)) =
            self.doc_cache.observed_candidate(did, doc_type.clone())
        else {
            return Err(NSError::NotFound(format!(
                "no observed candidate for {}#{}",
                did.to_string(),
                doc_type.unwrap_or_default()
            )));
        };

        // 不管 unverified 条目是被谁、用什么工具、以什么格式写进来的,这里都
        // 重新做归一化解析——文件存在不等于合法输入。槽位声明的类型优先;
        // 默认槽位由文档自述类型决定;张冠李戴是明确失败。
        if is_key_class_method(&did.method) {
            return Ok(self.reject_observed(
                did,
                doc_type,
                VerifyError::InvalidDocument {
                    detail: format!(
                        "key-class DID {} cannot be a verification subject",
                        did.to_string()
                    ),
                },
            ));
        }
        let parsed = match parse_did_doc(document.clone()) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Ok(self.reject_observed(
                    did,
                    doc_type,
                    VerifyError::InvalidDocument {
                        detail: format!(
                            "observed candidate is not a recognizable DID document: {}",
                            err
                        ),
                    },
                ));
            }
        };
        if parsed.get_id() != *did {
            return Ok(self.reject_observed(
                did,
                doc_type,
                VerifyError::DocumentIdMismatch {
                    expected: did.clone(),
                    actual: parsed.get_id(),
                },
            ));
        }
        let effective_doc_type = match doc_type.as_ref() {
            Some(slot) => {
                if parsed.get_doc_type() != *slot {
                    return Ok(self.reject_observed(
                        did,
                        doc_type.clone(),
                        VerifyError::InvalidDocument {
                            detail: format!(
                                "document body is a {} document, cache slot is {}",
                                parsed.get_doc_type(),
                                slot
                            ),
                        },
                    ));
                }
                slot.clone()
            }
            None => parsed.get_doc_type(),
        };
        // Info 契约类 doc_type 免验证、没有 owner 信任链,不存在 promote 语义。
        if self
            .name_query
            .is_no_proof_doc_type(&did.method, &effective_doc_type)
            .await
        {
            return Ok(self.reject_observed(
                did,
                doc_type,
                VerifyError::InvalidDocument {
                    detail: format!(
                        "doc_type {} is an unauthenticated info contract; \
                         it has no owner trust chain to verify",
                        effective_doc_type
                    ),
                },
            ));
        }

        // snapshot 构建:权威状态是 promote 的必要证据。调用方 policy 保留
        // (descend 链跨 verify_and_promote 与 resolve_did_ex 的相互递归生效)。
        let promote_policy = policy
            .clone()
            .with_source(ResolveSourcePolicy::RemoteAuthority);
        let snapshot = match self
            .build_verify_context(did, &effective_doc_type, &promote_policy)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(err) => {
                // method 未注册等注册面问题:信任链暂时评估不了,不是候选的错。
                return Ok(VerifyPromoteOutcome::Unavailable(
                    NSError::VerifyAndPromoteUnavailable(err.to_string()),
                ));
            }
        };

        let purpose = Self::default_verify_purpose(&effective_doc_type);
        match verify_did_document(
            did,
            effective_doc_type.clone(),
            &document,
            &snapshot,
            VerifyOptions { purpose },
        ) {
            Ok(verified) => match &verified.freshness.authority {
                // 权威绑定候选 / 权威 Active 而未锚定 / 没有权威渠道:候选的
                // 有效性验证已完成,promote(与旧行为一致:Active 下的
                // NeedProof 候选凭 owner 验签转正)。
                AuthorityFreshness::Current { .. }
                | AuthorityFreshness::ActiveUnanchored { .. }
                | AuthorityFreshness::NotChecked => {
                    let exp = Self::cache_ttl_exp(&document);
                    self.doc_cache.promote_observed(did, doc_type, exp);
                    Ok(VerifyPromoteOutcome::Promoted(document))
                }
                // 权威明确否定(不同 body、被替换、Missing/Expired/Migrated):
                // 重试同一份候选没有意义,删除。
                AuthorityFreshness::NotCurrent { reason, .. } => {
                    let reason = reason.clone();
                    Ok(self.reject_observed_with_code(
                        did,
                        doc_type,
                        "AuthorityNotCurrent",
                        format!(
                            "method authority negates observed candidate {}#{}: {:?}",
                            did.to_string(),
                            effective_doc_type,
                            reason
                        ),
                    ))
                }
                // 显式要求了权威判断但权威没回答:条件暂不可用,候选保留。
                AuthorityFreshness::Unavailable { detail, .. } => {
                    Ok(VerifyPromoteOutcome::Unavailable(
                        NSError::VerifyAndPromoteUnavailable(format!(
                            "method authority did not answer for {}#{}; \
                             current publication set cannot be verified: {}",
                            did.to_string(),
                            effective_doc_type,
                            detail
                        )),
                    ))
                }
            },
            Err(VerifyError::MissingDependency { dependencies }) => {
                // Owner 递归基在权威已回答却给不出锚点时,永远无法转正:视作
                // 明确失败(owner document 不能自己给自己作保)。其余缺依赖
                // (owner 文档拿不到、权威没回答)是暂不可用,候选保留。
                let owner_membership_confirmed_gap = effective_doc_type == DidDocType::Owner
                    && matches!(snapshot.authority, SnapshotAuthorityState::Receipt(_));
                if owner_membership_confirmed_gap {
                    return Ok(self.reject_observed_with_code(
                        did,
                        doc_type,
                        "AuthorityNotCurrent",
                        format!(
                            "OwnerDocument candidate for {} is not anchored to the current \
                             publication set; an owner document cannot vouch for itself",
                            did.to_string()
                        ),
                    ));
                }
                Ok(VerifyPromoteOutcome::Unavailable(
                    NSError::VerifyAndPromoteUnavailable(format!(
                        "verification dependencies unavailable for {}#{}: {:?}",
                        did.to_string(),
                        effective_doc_type,
                        dependencies
                    )),
                ))
            }
            Err(err) => Ok(self.reject_observed(did, doc_type, err)),
        }
    }

    /// lazy verify 明确失败的落盘动作:删除 unverified 候选(避免同一份坏数据
    /// 反复触发验证开销),错误按 `VerifyAndPromoteRejected { code, detail }`
    /// 结构化返回,code 复用纯 verify 的稳定错误码集合。
    fn reject_observed(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        err: VerifyError,
    ) -> VerifyPromoteOutcome {
        let code = err.code().to_string();
        let detail = err.to_string();
        self.reject_observed_with_code(did, doc_type, &code, detail)
    }

    fn reject_observed_with_code(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        code: &str,
        detail: String,
    ) -> VerifyPromoteOutcome {
        self.doc_cache.delete_unverified(did, doc_type);
        VerifyPromoteOutcome::Rejected(NSError::VerifyAndPromoteRejected {
            code: code.to_string(),
            detail,
        })
    }
}

/// wire docHash 的归一化(允许 `sha256:` 前缀,大小写不敏感),与
/// [`crate::content_hash_matches`] 同一契约。
fn normalize_wire_hash(hash: &str) -> String {
    hash.strip_prefix("sha256:")
        .unwrap_or(hash)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc_cache::CacheBackend;
    use crate::name_client::NameClientConfig;
    use crate::{
        document_content_hash, evaluate_freshness, CacheStatus, DocumentRef, FreshnessPolicyError,
        FreshnessRequirement, NameInfo, NsProvider, PublishedState, RecordType,
    };
    use async_trait::async_trait;
    use jsonwebtoken::{jwk::Jwk, EncodingKey};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    // 固定的测试 Ed25519 keypair:alice(owner)与 bob(另一个 owner / 攻击者)。
    const ALICE_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
    const ALICE_PUBLIC_JWK_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
    const BOB_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----";
    const BOB_PUBLIC_JWK_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";
    const DEVICE_PUBLIC_X: &str = "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE";

    fn signing_key(pem: &str, x: &str) -> (EncodingKey, Jwk) {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
        }))
        .unwrap();
        (EncodingKey::from_ed_pem(pem.as_bytes()).unwrap(), jwk)
    }

    fn alice_key() -> (EncodingKey, Jwk) {
        signing_key(ALICE_PRIVATE_KEY_PEM, ALICE_PUBLIC_JWK_X)
    }

    fn bob_key() -> (EncodingKey, Jwk) {
        signing_key(BOB_PRIVATE_KEY_PEM, BOB_PUBLIC_JWK_X)
    }

    /// 相对当前真实时间的时间戳:JWT 的 exp 校验基于墙钟。
    fn ts(offset_secs: i64) -> u64 {
        (buckyos_get_unix_timestamp() as i64 + offset_secs) as u64
    }

    fn did(s: &str) -> DID {
        DID::from_str(s).unwrap()
    }

    fn build_owner_doc(owner_did: &DID) -> EncodedDocument {
        let (key, jwk) = alice_key();
        let mut owner = OwnerDocument::new(
            owner_did.clone(),
            "owner".to_string(),
            "owner@test".to_string(),
            jwk,
        );
        owner.iat = ts(-3600);
        owner.exp = ts(3600 * 24 * 365);
        owner.encode(Some(&key)).unwrap()
    }

    fn build_device_doc_with(
        device_did: &DID,
        owner_did: &DID,
        iat: u64,
        name: &str,
        key: &EncodingKey,
    ) -> EncodedDocument {
        let mut device = DeviceDocument::new(name, DEVICE_PUBLIC_X.to_string());
        device.id = device_did.clone();
        device.owner = owner_did.clone();
        device.iat = iat;
        device.exp = iat + 3600 * 24 * 365;
        device.encode(Some(key)).unwrap()
    }

    fn build_device_doc(device_did: &DID, owner_did: &DID, iat: u64) -> EncodedDocument {
        build_device_doc_with(device_did, owner_did, iat, "laptop", &alice_key().0)
    }

    /// 测试用权威 provider:按 (did, doc_type) 返回预注册的发布状态与文档;
    /// `fail_state` 置位后所有查询报传输错误(模拟权威源断网)。
    struct AuthorityProvider {
        id: String,
        docs: Vec<(DID, String, EncodedDocument)>,
        states: Vec<PublishedState>,
        fail_state: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl AuthorityProvider {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                docs: Vec::new(),
                states: Vec::new(),
                fail_state: Arc::new(AtomicBool::new(false)),
                calls: Arc::new(AtomicUsize::new(0)),
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

        fn handles(&self) -> (Arc<AtomicBool>, Arc<AtomicUsize>) {
            (self.fail_state.clone(), self.calls.clone())
        }
    }

    #[async_trait]
    impl NsProvider for AuthorityProvider {
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
            if self.fail_state.load(Ordering::SeqCst) {
                return Err(NSError::Failed("authority offline (test)".into()));
            }
            let wanted = doc_type.unwrap_or_default();
            self.docs
                .iter()
                .find(|(candidate, doc_type, _)| candidate == did && doc_type == wanted.as_str())
                .map(|(_, _, doc)| doc.clone())
                .ok_or_else(|| NSError::NotFound("no matching doc".into()))
        }

        async fn resolve_published_state(
            &self,
            did: &DID,
            doc_type: &DidDocType,
        ) -> NSResult<Option<PublishedState>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_state.load(Ordering::SeqCst) {
                return Err(NSError::Failed("authority offline (test)".into()));
            }
            Ok(self
                .states
                .iter()
                .find(|state| state.did == *did && state.doc_type == doc_type.as_str())
                .cloned())
        }
    }

    fn active_state(did: &DID, doc_type: &str) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            document_status: DocumentStatus::Active,
            document_ref: None,
            document_version: None,
            effective_owner: None,
            authority_seq: None,
            migration_target: None,
            checked_at: None,
            valid_until: None,
        }
    }

    fn mem_client() -> NameClient {
        NameClient::new(NameClientConfig {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            enable_zone_resolver: false,
            ..Default::default()
        })
    }

    fn fs_client(dir: &std::path::Path) -> NameClient {
        NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            enable_zone_resolver: false,
            ..Default::default()
        })
    }

    fn seed_owner(client: &NameClient, owner_did: &DID, owner_doc: &EncodedDocument) {
        client.doc_cache.insert(
            owner_did.clone(),
            Some(DidDocType::Owner),
            owner_doc.clone(),
            ts(1000),
            crate::doc_cache::CacheEvidence::Published,
        );
    }

    /// 递归收集 cache 目录 (相对路径, 内容) 的有序快照,用于断言纯 verify 零写入。
    fn walk_dir_snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path.strip_prefix(root).unwrap().to_string_lossy().to_string();
                    let content = std::fs::read(&path).unwrap_or_default();
                    out.push((rel, content));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    // ---- 测试要求 1 + 2 + 16:纯 verify 零查询、零写入;组合 API 按 policy 访问 ----

    #[tokio::test]
    async fn pure_verify_never_queries_and_never_writes() {
        let tmp = tempdir().unwrap();
        let client = fs_client(tmp.path());
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        let owner_doc = build_owner_doc(&owner_did);
        seed_owner(&client, &owner_did, &owner_doc);

        let device_jwt = build_device_doc(&device_did, &owner_did, ts(-100));
        let authority = AuthorityProvider::new("bns-authority").with_state({
            let mut state = active_state(&device_did, "device");
            state.document_ref = Some(DocumentRef {
                uri: None,
                content_hash: Some(document_content_hash(&device_jwt)),
                inline_document: None,
            });
            state.effective_owner = Some(owner_did.clone());
            state
        });
        let (_fail, calls) = authority.handles();
        client.set_method_authority("bns", Box::new(authority)).await;

        // resolve 阶段(snapshot 构建)按 policy 访问权威渠道。
        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        let calls_after_build = calls.load(Ordering::SeqCst);
        assert!(calls_after_build > 0, "snapshot build should hit authority");

        let dir_before = walk_dir_snapshot(tmp.path());

        // 纯 verify:snapshot 命中(成功)。
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &device_jwt,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::Current { .. }
        ));

        // 验证失败(bob 签名冒充)。
        let forged = build_device_doc_with(&device_did, &owner_did, ts(-100), "laptop", &bob_key().0);
        let err = verify_did_document(
            &device_did,
            DidDocType::Device,
            &forged,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap_err();
        // 伪造文档与权威锚点不同,但 validity 失败先于/独立于 freshness:
        // bob 签名过不了 owner 验签。
        assert!(matches!(err, VerifyError::SignatureRejected { .. }));

        // 缺依赖(去掉 owner 材料)。
        let mut stripped = snapshot.clone();
        stripped.owner_material = None;
        let err = verify_did_document(
            &device_did,
            DidDocType::Device,
            &device_jwt,
            &stripped,
            VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::MissingDependency { .. }));

        // 纯 verify 全程:不发起任何 provider 查询、不写不删任何 cache 文件。
        assert_eq!(calls.load(Ordering::SeqCst), calls_after_build);
        assert_eq!(walk_dir_snapshot(tmp.path()), dir_before);

        // 组合 API 的来源门禁:LocalOnly 不访问权威渠道。
        let local_options = ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::LocalOnly);
        let _ = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &device_jwt, &local_options)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), calls_after_build);

        // RemoteAuthority 组合入口访问权威渠道。
        let remote_options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let verified = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &device_jwt, &remote_options)
            .await
            .unwrap();
        assert!(calls.load(Ordering::SeqCst) > calls_after_build);
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::Current { .. }
        ));
    }

    // ---- 测试要求 3 + 8:local snapshot 的 ValidityEvidence 与 NotChecked ----

    #[tokio::test]
    async fn local_snapshot_validity_evidence_and_authority_not_checked() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let device_jwt = build_device_doc(&device_did, &owner_did, ts(-100));
        // 把候选自己也放进 verified cache(Published):测试要求 8——
        // 即使命中 Published local cache,没有 Remote Resolve 就是 NotChecked。
        client.doc_cache.insert(
            device_did.clone(),
            Some(DidDocType::Device),
            device_jwt.clone(),
            ts(1000),
            crate::doc_cache::CacheEvidence::Published,
        );

        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalOnly);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &device_jwt,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();

        assert_eq!(verified.expected_owner, Some(owner_did.clone()));
        assert_eq!(verified.authz_owner, Some(owner_did.clone()));
        assert!(verified.usable_as_authz_subject);
        assert_eq!(
            verified.validity.expected_owner_source,
            Some(EvidenceSource::StructuralRule)
        );
        assert_eq!(
            verified.validity.owner_document_source,
            Some(EvidenceSource::LocalCache)
        );
        assert!(verified.validity.owner_replay_guard_applied);
        assert_eq!(verified.validity.scope, LocalTrustScope::Host);
        // 测试要求 10:同 iat 同 hash → SameAsLatestKnown。
        assert!(matches!(
            verified.freshness.local,
            LocalFreshness::SameAsLatestKnown {
                scope: LocalTrustScope::Host,
                ..
            }
        ));
        // 测试要求 8:没有 Remote Resolve,authority 仍为 NotChecked。
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::NotChecked
        ));
    }

    // ---- 测试要求 9 + 11:latest-known 比较与同 revision 冲突 ----

    #[tokio::test]
    async fn local_freshness_ordering_and_conflict() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let base_iat = ts(-1000);
        let baseline_jwt = build_device_doc(&device_did, &owner_did, base_iat);
        client.doc_cache.insert(
            device_did.clone(),
            Some(DidDocType::Device),
            baseline_jwt.clone(),
            ts(1000),
            crate::doc_cache::CacheEvidence::Verified,
        );
        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalOnly);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();

        // 测试要求 9:候选 iat = N-100 → OlderThanLatestKnown。
        let older = build_device_doc(&device_did, &owner_did, base_iat - 100);
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &older,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        match &verified.freshness.local {
            LocalFreshness::OlderThanLatestKnown {
                candidate, latest, ..
            } => {
                assert_eq!(candidate.iat, base_iat - 100);
                assert_eq!(latest.iat, base_iat);
            }
            other => panic!("expected OlderThanLatestKnown, got {:?}", other),
        }
        // 本地防回滚 policy 拒绝更旧候选;AnyValid 接受。
        assert!(matches!(
            evaluate_freshness(
                &verified,
                &FreshnessRequirement::NotOlderThanLocalLatest {
                    scope: LocalTrustScope::Host
                }
            ),
            Err(FreshnessPolicyError::OlderThanLocalLatest { .. })
        ));
        evaluate_freshness(&verified, &FreshnessRequirement::AnyValid).unwrap();

        // 更新的候选 → NewerThanLatestKnown。
        let newer = build_device_doc(&device_did, &owner_did, base_iat + 100);
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &newer,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            verified.freshness.local,
            LocalFreshness::NewerThanLatestKnown { .. }
        ));

        // 测试要求 11:同 iat 不同 hash → ConflictAtSameRevision(稳定冲突)。
        let conflicting = build_device_doc_with(&device_did, &owner_did, base_iat, "laptop-b", &alice_key().0);
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &conflicting,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            verified.freshness.local,
            LocalFreshness::ConflictAtSameRevision { .. }
        ));
        assert!(matches!(
            evaluate_freshness(
                &verified,
                &FreshnessRequirement::NotOlderThanLocalLatest {
                    scope: LocalTrustScope::Host
                }
            ),
            Err(FreshnessPolicyError::ConflictAtSameRevision { .. })
        ));
    }

    // ---- 测试要求 13:Observed/unverified 不能推进 latest-known baseline ----

    #[tokio::test]
    async fn observed_entries_do_not_advance_baseline() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let observed = build_device_doc(&device_did, &owner_did, ts(-50));
        client
            .add_observed_cache(
                device_did.clone(),
                Some(DidDocType::Device),
                observed,
                Some(crate::UpdateSource::Push),
            )
            .unwrap();

        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalOnly);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        assert!(matches!(snapshot.baseline, SnapshotBaseline::Empty));

        let candidate = build_device_doc(&device_did, &owner_did, ts(-500));
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &candidate,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        // 观察缓存里有 iat 更大的文档,但 baseline 不被它推进:候选是 FirstKnown。
        assert!(matches!(
            verified.freshness.local,
            LocalFreshness::FirstKnown { .. }
        ));
    }

    // ---- 测试要求 6 + 20:权威 Current 与 Superseded ----

    #[tokio::test]
    async fn remote_authority_hash_match_is_current_and_cacheable() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let device_iat = ts(-100);
        let device_jwt = build_device_doc(&device_did, &owner_did, device_iat);
        let authority = AuthorityProvider::new("bns-authority").with_state({
            let mut state = active_state(&device_did, "device");
            state.document_ref = Some(DocumentRef {
                uri: None,
                content_hash: Some(document_content_hash(&device_jwt)),
                inline_document: None,
            });
            state.document_version = Some(device_iat);
            state.authority_seq = Some(7);
            state.effective_owner = Some(owner_did.clone());
            state.checked_at = Some(ts(-1));
            state.valid_until = Some(ts(600));
            state
        });
        client.set_method_authority("bns", Box::new(authority)).await;

        let options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let (verified, outcome) = client
            .resolve_verify_and_cache_did_document(
                &device_did,
                DidDocType::Device,
                &device_jwt,
                &options,
            )
            .await
            .unwrap();

        match &verified.freshness.authority {
            AuthorityFreshness::Current {
                authority_seq,
                document_iat,
                valid_until,
                ..
            } => {
                assert_eq!(*authority_seq, Some(7));
                assert_eq!(*document_iat, Some(device_iat));
                assert_eq!(*valid_until, Some(ts(600)));
            }
            other => panic!("expected Current, got {:?}", other),
        }
        assert_eq!(
            verified.validity.expected_owner_source,
            Some(EvidenceSource::AuthorityReceipt)
        );
        assert!(verified.validity.membership_proven);
        evaluate_freshness(
            &verified,
            &FreshnessRequirement::RequireAuthorityCurrent { max_age_secs: None },
        )
        .unwrap();

        // 显式 cache 组合:membership 成立 → Published 证据。
        assert!(outcome.stored());
        match client
            .doc_cache
            .lookup(&device_did, Some(DidDocType::Device))
            .unwrap()
        {
            crate::doc_cache::CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, crate::doc_cache::CacheEvidence::Published);
            }
            other => panic!("expected positive cache entry, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn candidate_older_than_authority_document_iat_is_superseded() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let device_iat = ts(-100);
        let authority = AuthorityProvider::new("bns-authority").with_state({
            let mut state = active_state(&device_did, "device");
            // 无 hash/body 锚点,但权威记录的当前发布 iat(wire documentVersion)
            // 比候选新。
            state.document_version = Some(device_iat + 50);
            state.effective_owner = Some(owner_did.clone());
            state
        });
        client.set_method_authority("bns", Box::new(authority)).await;

        let candidate = build_device_doc(&device_did, &owner_did, device_iat);
        let options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let verified = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &candidate, &options)
            .await
            .unwrap();
        match &verified.freshness.authority {
            AuthorityFreshness::NotCurrent {
                reason: AuthorityNotCurrentReason::Superseded,
                current_document_iat,
                ..
            } => {
                assert_eq!(*current_document_iat, Some(device_iat + 50));
            }
            other => panic!("expected Superseded, got {:?}", other),
        }
        assert!(matches!(
            evaluate_freshness(
                &verified,
                &FreshnessRequirement::RequireAuthorityCurrent { max_age_secs: None },
            ),
            Err(FreshnessPolicyError::AuthorityNotCurrent { .. })
        ));
    }

    // ---- 测试要求 7:Active 但当前 body 不同 → NotCurrent(DifferentDocument) ----

    #[tokio::test]
    async fn authority_serving_different_body_is_not_current_fact() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let iat = ts(-100);
        let current_body = build_device_doc_with(&device_did, &owner_did, iat, "laptop-current", &alice_key().0);
        let candidate = build_device_doc_with(&device_did, &owner_did, iat, "laptop-old", &alice_key().0);
        let authority = AuthorityProvider::new("bns-authority")
            .with_state({
                let mut state = active_state(&device_did, "device");
                state.document_ref = Some(DocumentRef::inline(current_body.clone()));
                state.effective_owner = Some(owner_did.clone());
                state
            });
        client.set_method_authority("bns", Box::new(authority)).await;

        let options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        // 有效性验证通过(owner 签名合法),权威否定作为 freshness 事实返回。
        let verified = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &candidate, &options)
            .await
            .unwrap();
        assert!(matches!(
            &verified.freshness.authority,
            AuthorityFreshness::NotCurrent {
                reason: AuthorityNotCurrentReason::DifferentDocument,
                ..
            }
        ));
        assert!(!verified.validity.membership_proven);
    }

    // ---- 测试要求 18:权威 Missing/Expired 是事实,由 policy 决定 ----

    #[tokio::test]
    async fn authority_missing_is_a_fact_not_verify_error() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let authority = AuthorityProvider::new("bns-authority").with_state({
            let mut state = active_state(&device_did, "device");
            state.document_status = DocumentStatus::Missing;
            state
        });
        client.set_method_authority("bns", Box::new(authority)).await;

        let candidate = build_device_doc(&device_did, &owner_did, ts(-100));
        let options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let verified = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &candidate, &options)
            .await
            .unwrap();
        // 未发布 DeviceDocument 的 bootstrap 场景:验证成功 + Missing 事实。
        assert!(matches!(
            &verified.freshness.authority,
            AuthorityFreshness::NotCurrent {
                reason: AuthorityNotCurrentReason::NegativeStatus(DocumentStatus::Missing),
                ..
            }
        ));
        assert_eq!(
            verified.validity.authority_status,
            Some(DocumentStatus::Missing)
        );
        // RequireAuthorityCurrent 拒绝;AnyValid / 本地防回滚接受。
        assert!(evaluate_freshness(
            &verified,
            &FreshnessRequirement::RequireAuthorityCurrent { max_age_secs: None },
        )
        .is_err());
        evaluate_freshness(&verified, &FreshnessRequirement::AnyValid).unwrap();
        evaluate_freshness(
            &verified,
            &FreshnessRequirement::NotOlderThanLocalLatest {
                scope: LocalTrustScope::Host,
            },
        )
        .unwrap();
    }

    // ---- 测试要求 17:terminal 负状态硬失败且零副作用 ----

    #[tokio::test]
    async fn terminal_negative_state_hard_fails_without_side_effects() {
        let tmp = tempdir().unwrap();
        let client = fs_client(tmp.path());
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));
        client.doc_cache.replace_with_negative(
            &device_did,
            Some(DidDocType::Device),
            &DocumentStatus::Revoked,
            "revoked by authority (test)",
        );

        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalOnly);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        let dir_before = walk_dir_snapshot(tmp.path());

        let candidate = build_device_doc(&device_did, &owner_did, ts(-100));
        let err = verify_did_document(
            &device_did,
            DidDocType::Device,
            &candidate,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap_err();
        match err {
            VerifyError::RejectedByNegativeState { scope, status } => {
                assert_eq!(scope, LocalTrustScope::Host);
                assert_eq!(status, DocumentStatus::Revoked);
            }
            other => panic!("expected RejectedByNegativeState, got {}", other),
        }
        // 纯 verify 不做任何 cache 写删(负状态条目原样保留)。
        assert_eq!(walk_dir_snapshot(tmp.path()), dir_before);

        // 手工拼装 snapshot(Caller scope)同样硬失败——不依赖 builder。
        let mut caller_snapshot = VerifyContextSnapshot::empty(LocalTrustScope::Caller(
            "rtcp-session".to_string(),
        ));
        caller_snapshot.negative_state = Some(SnapshotNegativeState {
            status: DocumentStatus::Tombstoned,
            scope: LocalTrustScope::Caller("rtcp-session".to_string()),
            origin: "caller memory".to_string(),
        });
        let err = verify_did_document(
            &device_did,
            DidDocType::Device,
            &candidate,
            &caller_snapshot,
            VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::RejectedByNegativeState { .. }));
    }

    // ---- MissingDependency 的结构化依赖项 ----

    #[tokio::test]
    async fn missing_dependencies_are_structured() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");

        // 无 owner 材料(LocalOnly、空 cache)→ OwnerDocument 依赖。
        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalOnly);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        let candidate = build_device_doc(&device_did, &owner_did, ts(-100));
        let err = verify_did_document(
            &device_did,
            DidDocType::Device,
            &candidate,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap_err();
        match err {
            VerifyError::MissingDependency { dependencies } => {
                assert_eq!(
                    dependencies,
                    vec![VerifyDependency::OwnerDocument {
                        owner: owner_did.clone()
                    }]
                );
            }
            other => panic!("expected MissingDependency, got {}", other),
        }

        // 一级名字(无结构 owner)且权威未被咨询 → OwnerBinding 依赖。
        let first_level = did("did:bns:alice");
        let snapshot = client
            .build_verify_context(&first_level, &DidDocType::Zone, &policy)
            .await
            .unwrap();
        let (alice_signing, alice_jwk) = alice_key();
        let mut zone = ZoneDocument::new(first_level.clone(), first_level.clone(), alice_jwk);
        zone.iat = ts(-100);
        zone.exp = ts(3600 * 24);
        let zone_jwt = zone.encode(Some(&alice_signing)).unwrap();
        let err = verify_did_document(
            &first_level,
            DidDocType::Zone,
            &zone_jwt,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap_err();
        match err {
            VerifyError::MissingDependency { dependencies } => {
                assert!(matches!(
                    dependencies.as_slice(),
                    [VerifyDependency::OwnerBinding { .. }]
                ));
            }
            other => panic!("expected MissingDependency(OwnerBinding), got {}", other),
        }
    }

    // ---- 测试要求 19:iat 补充推导与 InvalidDocument ----

    #[tokio::test]
    async fn revision_iat_derivation_and_invalid_document() {
        // 缺 iat 但有 exp 的 JWT:按补充流程得出 iat = exp - DEFAULT_EXPIRE_TIME。
        let card_did = did("did:web:obj.example.com");
        let mut card = DIDObjectCard::new(
            card_did.clone(),
            "https://obj.example.com/o/1",
            None,
            "profile",
            None::<String>,
        );
        card.iat = None;
        card.exp = Some(ts(600) + DEFAULT_EXPIRE_TIME);
        let card_jwt = card.encode(Some(&alice_key().0)).unwrap();
        let expected_iat = card.exp.unwrap() - DEFAULT_EXPIRE_TIME;

        // 权威 receipt 锚定该候选(ObjectDocument 无 owner 链,靠 membership)。
        let mut snapshot = VerifyContextSnapshot::empty(LocalTrustScope::Caller("test".into()));
        snapshot.authority = SnapshotAuthorityState::Receipt(AuthorityReceipt {
            status: DocumentStatus::Active,
            doc_hash: Some(document_content_hash(&card_jwt)),
            current_body: None,
            effective_owner: None,
            authority_seq: None,
            document_iat: None,
            migration_target: None,
            checked_at: ts(0),
            valid_until: None,
            source: "test-authority".to_string(),
        });
        let verified = verify_did_document(
            &card_did,
            DidDocType::DidObject,
            &card_jwt,
            &snapshot,
            VerifyOptions {
                purpose: VerifyPurpose::ObjectDocument,
            },
        )
        .unwrap();
        assert_eq!(verified.revision.iat, expected_iat);
        assert!(!verified.usable_as_authz_subject);

        // iat/exp 皆无:无法得出 revision iat,文档无效。
        let mut invalid_card = DIDObjectCard::new(
            card_did.clone(),
            "https://obj.example.com/o/1",
            None,
            "profile",
            None::<String>,
        );
        invalid_card.iat = None;
        invalid_card.exp = None;
        let err = invalid_card.encode(Some(&alice_key().0)).unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
        // 手工构造绕过 encode 检查的 JsonLd 同样在 verify 侧被拒。
        let mut value = serde_json::to_value(&invalid_card).unwrap();
        value.as_object_mut().unwrap().remove("iat");
        value.as_object_mut().unwrap().remove("exp");
        let err = verify_did_document(
            &card_did,
            DidDocType::DidObject,
            &EncodedDocument::JsonLd(value),
            &snapshot,
            VerifyOptions {
                purpose: VerifyPurpose::ObjectDocument,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::InvalidDocument { .. }));
    }

    // ---- 测试要求 4 + 5:Zone snapshot 的 Zone scope 事实,ZoneHit 不当权威 ----

    async fn spawn_zone_stub(body: String) -> (String, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_in_task = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                hits_in_task.fetch_add(1, Ordering::SeqCst);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{}", addr), hits)
    }

    #[tokio::test]
    async fn zone_snapshot_gives_zone_scope_facts_but_never_authority_current() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let device_iat = ts(-100);
        let device_jwt = build_device_doc(&device_did, &owner_did, device_iat);
        let jwt_str = device_jwt.to_string();
        let checked_at = ts(-5);
        let valid_until = ts(600);
        let body = json!({
            "didDocument": jwt_str,
            "didDocumentMetadata": {
                "buckyos": {
                    "docType": "device",
                    "documentStatus": "active",
                    "documentVersion": device_iat,
                    "authoritySeq": 9,
                    "effectiveOwner": owner_did.to_string(),
                    "docHash": document_content_hash(&device_jwt),
                    "checkedAt": checked_at,
                    "validUntil": valid_until,
                }
            }
        })
        .to_string();
        let (endpoint, hits) = spawn_zone_stub(body).await;
        client.set_zone_resolver_endpoint(&endpoint);

        // build_verify_context 走 LocalAndZone:Zone 回答 → 主 scope 是 Zone。
        let policy = ResolvePolicy::default().with_source(ResolveSourcePolicy::LocalAndZone);
        let snapshot = client
            .build_verify_context(&device_did, &DidDocType::Device, &policy)
            .await
            .unwrap();
        assert_eq!(snapshot.scope, LocalTrustScope::Zone);
        assert!(matches!(
            snapshot.authority,
            SnapshotAuthorityState::NotConsulted
        ));
        assert_eq!(snapshot.valid_until, Some(valid_until));
        let hits_after_build = hits.load(Ordering::SeqCst);
        assert!(hits_after_build > 0);

        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &device_jwt,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        // Zone scope 的本地 freshness 事实。
        assert!(matches!(
            verified.freshness.local,
            LocalFreshness::SameAsLatestKnown {
                scope: LocalTrustScope::Zone,
                ..
            }
        ));
        // 测试要求 5:ZoneHit 只进 Zone local freshness,不返回 AuthorityCurrent。
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::NotChecked
        ));
        assert_eq!(
            verified.validity.expected_owner_source,
            Some(EvidenceSource::ZoneSnapshot)
        );
        assert_eq!(verified.validity.scope, LocalTrustScope::Zone);
        // 纯 verify 不再打 Zone。
        assert_eq!(hits.load(Ordering::SeqCst), hits_after_build);

        // 测试要求 4 的字段保留:resolve 路径的 ZoneHit 结果保留 authority_seq。
        let resolved = client
            .resolve_did_ex(
                &device_did,
                Some(DidDocType::Device),
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(resolved.document_metadata.buckyos.authority_seq, Some(9));
        assert_eq!(
            resolved.document_metadata.buckyos.document_version,
            Some(device_iat)
        );
    }

    // ---- 权威没回答:Unavailable 事实(显式要求了 Remote Resolve)----

    #[tokio::test]
    async fn authority_unreachable_is_unavailable_fact() {
        let client = mem_client();
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        seed_owner(&client, &owner_did, &build_owner_doc(&owner_did));

        let authority = AuthorityProvider::new("bns-authority");
        let (fail, _calls) = authority.handles();
        client.set_method_authority("bns", Box::new(authority)).await;
        fail.store(true, Ordering::SeqCst);

        let candidate = build_device_doc(&device_did, &owner_did, ts(-100));
        let options =
            ResolveVerifyOptions::default().with_source(ResolveSourcePolicy::RemoteAuthority);
        let verified = client
            .resolve_and_verify_did_document(&device_did, DidDocType::Device, &candidate, &options)
            .await
            .unwrap();
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::Unavailable { .. }
        ));
        assert!(matches!(
            evaluate_freshness(
                &verified,
                &FreshnessRequirement::RequireAuthorityCurrent { max_age_secs: None },
            ),
            Err(FreshnessPolicyError::AuthorityUnavailable { .. })
        ));
    }

    // ---- freshness policy 的检查年龄约束 ----

    #[test]
    fn authority_current_max_age_is_enforced() {
        let owner_did = did("did:bns:alice");
        let device_did = did("did:bns:laptop.alice");
        let device_jwt = build_device_doc(&device_did, &owner_did, ts(-100));
        let mut snapshot = VerifyContextSnapshot::empty(LocalTrustScope::Caller("test".into()));
        snapshot.owner_material = Some(SnapshotOwnerMaterial {
            owner: owner_did.clone(),
            document: build_owner_doc(&owner_did),
            source: EvidenceSource::Caller,
        });
        snapshot.authority = SnapshotAuthorityState::Receipt(AuthorityReceipt {
            status: DocumentStatus::Active,
            doc_hash: Some(document_content_hash(&device_jwt)),
            current_body: None,
            effective_owner: None,
            authority_seq: None,
            document_iat: None,
            migration_target: None,
            checked_at: ts(-3600),
            valid_until: None,
            source: "test-authority".to_string(),
        });
        let verified = verify_did_document(
            &device_did,
            DidDocType::Device,
            &device_jwt,
            &snapshot,
            VerifyOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            verified.freshness.authority,
            AuthorityFreshness::Current { .. }
        ));
        // 检查太旧(1 小时前),max_age 60s 拒绝;不限龄接受。
        assert!(matches!(
            evaluate_freshness(
                &verified,
                &FreshnessRequirement::RequireAuthorityCurrent {
                    max_age_secs: Some(60)
                },
            ),
            Err(FreshnessPolicyError::AuthorityCheckTooOld { .. })
        ));
        evaluate_freshness(
            &verified,
            &FreshnessRequirement::RequireAuthorityCurrent { max_age_secs: None },
        )
        .unwrap();
    }
}
