//! `verify_did_document_jwt`:外部 DID Document JWT 的统一信任判断入口
//! (需求文档 doc/verify-did-document-jwt.md)。
//!
//! 应用层拿到一份外部 JWT(典型:RTCP 握手里的 `device_doc_jwt`)时,不允许
//! 自己拼 `payload.owner -> resolve_auth_key -> verify`——那只能证明"JWT 能被
//! 它自己声明的 owner 验过",不能证明"该 Document 的 DID 在名字系统里确实归
//! 这个 owner 管"。本模块把 `resolve_did` 中 NeedProof 候选的验证语义
//! (expected_owner 硬规则、owner 递归、验签、replay guard)封装给"外部已经
//! 拿到 JWT"的场景,并额外做 CurrentActive 的发布集合 membership 判断,输出
//! 可直接进入权限系统的结构化身份上下文。

use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use log::*;
use name_lib::*;
use serde::{Deserialize, Serialize};

use crate::doc_cache::{CacheEvidence, CacheLookup};
use crate::name_client::NameClient;
use crate::{
    content_hash_matches, is_key_class_method, structural_owner, BodyEvidence, DidDocType,
    DocumentStatus, ProviderResolveResult, ResolvePolicy, ResolveWarning,
};

/// 验证目的(需求文档"API 草案")。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyPurpose {
    /// 默认模式:用于 RTCP、跨 zone 请求、RBAC principal、应用内权限主语。
    /// 若 authority_owner 与 structural_owner 同时存在且不同(detached owner),
    /// 必须拒绝。
    AuthSubject,
    /// 客体文档解析:允许权威 owner 与结构 owner 不同。调用方不得把结果直接
    /// 作为权限主语使用(`usable_as_authz_subject` 恒为 false)。
    ObjectDocument,
}

/// 校验语义(需求文档"API 草案")。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyValidity {
    /// 当前必须合法。默认推荐。
    CurrentActive,
    /// 签发时曾经合法即可。必须显式依赖 method 的历史 owner / 历史发布集合
    /// 查询能力(http_did_resolver_api.md 第 7 节);当前没有任何 resolver 实现
    /// owner-at-iat 查询,严格返回 `HistoricalVerificationUnsupported`,
    /// 绝不静默退化成当前 owner 验证。
    ValidAtIssue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyDidDocumentJwtOptions {
    pub purpose: VerifyPurpose,
    pub validity: VerifyValidity,
    /// 验证通过后是否按证据等级受控写入本机 did_cache(需求文档"Cache 行为")。
    /// 上层不要再用 `update_did_cache` 保存已验证文档——那是 `Unverified` 旁路,
    /// 不能提升信任等级。
    pub cache_result: bool,
}

impl Default for VerifyDidDocumentJwtOptions {
    fn default() -> Self {
        Self {
            purpose: VerifyPurpose::AuthSubject,
            validity: VerifyValidity::CurrentActive,
            cache_result: true,
        }
    }
}

/// 需求文档错误表的稳定错误码,承载在 `NSError::VerifyDidJwtFailed { code, .. }`
/// 上。调用方用 [`VerifyDidJwtErrorCode::of`] 提取后按 code 分支,不要解析 detail。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyDidJwtErrorCode {
    /// JWT 不是可识别的 DID Document。
    InvalidJwtDocument,
    /// `payload.id != did`。
    DocumentIdMismatch,
    /// 无法确定 expected_owner(没有权威 owner 绑定,也没有结构 owner)。
    OwnerBindingUnavailable,
    /// `authority_owner != structural_owner` 且 purpose 为 AuthSubject。
    DetachedOwnerRejected,
    /// `declared_owner != expected_owner`。
    DeclaredOwnerMismatch,
    /// 无法解析 expected_owner 的 OwnerDocument。
    OwnerDocumentUnavailable,
    /// owner key(含历史 key)验签失败。
    SignatureVerificationFailed,
    /// 命中 owner 的 `valid_iat` / `mini_version_seq` replay guard。
    RevokedByOwnerPolicy,
    /// CurrentActive 模式下不在当前合法发布集合(权威负状态、hash/body 不匹配、
    /// 权威没回答、文档自过期等)。
    NotCurrentActive,
    /// ValidAtIssue 模式下 method / resolver 不支持历史查询。
    HistoricalVerificationUnsupported,
}

impl VerifyDidJwtErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidJwtDocument => "InvalidJwtDocument",
            Self::DocumentIdMismatch => "DocumentIdMismatch",
            Self::OwnerBindingUnavailable => "OwnerBindingUnavailable",
            Self::DetachedOwnerRejected => "DetachedOwnerRejected",
            Self::DeclaredOwnerMismatch => "DeclaredOwnerMismatch",
            Self::OwnerDocumentUnavailable => "OwnerDocumentUnavailable",
            Self::SignatureVerificationFailed => "SignatureVerificationFailed",
            Self::RevokedByOwnerPolicy => "RevokedByOwnerPolicy",
            Self::NotCurrentActive => "NotCurrentActive",
            Self::HistoricalVerificationUnsupported => "HistoricalVerificationUnsupported",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "InvalidJwtDocument" => Some(Self::InvalidJwtDocument),
            "DocumentIdMismatch" => Some(Self::DocumentIdMismatch),
            "OwnerBindingUnavailable" => Some(Self::OwnerBindingUnavailable),
            "DetachedOwnerRejected" => Some(Self::DetachedOwnerRejected),
            "DeclaredOwnerMismatch" => Some(Self::DeclaredOwnerMismatch),
            "OwnerDocumentUnavailable" => Some(Self::OwnerDocumentUnavailable),
            "SignatureVerificationFailed" => Some(Self::SignatureVerificationFailed),
            "RevokedByOwnerPolicy" => Some(Self::RevokedByOwnerPolicy),
            "NotCurrentActive" => Some(Self::NotCurrentActive),
            "HistoricalVerificationUnsupported" => Some(Self::HistoricalVerificationUnsupported),
            _ => None,
        }
    }

    /// 从 NSError 提取稳定错误码(只识别 verify_did_document_jwt 的结构化失败)。
    pub fn of(err: &NSError) -> Option<Self> {
        match err {
            NSError::VerifyDidJwtFailed { code, .. } => Self::from_code(code),
            _ => None,
        }
    }
}

fn verify_err(code: VerifyDidJwtErrorCode, detail: impl Into<String>) -> NSError {
    NSError::VerifyDidJwtFailed {
        code: code.as_str().to_string(),
        detail: detail.into(),
    }
}

/// 验证警告沿用 resolver 的警告词表(`SignedByHistoricalKey` 等)。
pub type VerifyWarning = ResolveWarning;

/// `verify_did_document_jwt` 的结构化身份上下文(需求文档"返回值")。
/// 权限系统只能使用这里的字段,不得自行从名字截取 owner。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedDidDocument {
    /// JWT 证明的文档主体 DID(即 Document 的 `id`,已与调用方期望一致)。
    pub subject_did: DID,
    pub doc_type: DidDocType,
    pub document: EncodedDocument,

    /// 由 DID method 名字结构确定性推出的默认 owner(旧草案 visible_owner)。
    /// 当前只有 did:bns 定义;一级名字为 None。
    pub structural_owner: Option<DID>,

    /// 权威源返回的 owner 绑定(`PublishedState.effective_owner` /
    /// wire 字段 `didDocumentMetadata.buckyos.effectiveOwner`)。
    pub authority_owner: Option<DID>,

    /// 本次验签和 owner replay guard 实际使用的 owner:
    /// `authority_owner.or(structural_owner)`,绝不来自 payload。
    /// AuthSubject 成功时必是 Some。
    pub expected_owner: Option<DID>,

    /// JWT payload 自声明的 owner(`DIDDocumentTrait::get_iss()`)。
    /// OwnerDocument 这类递归基为 None。
    pub declared_owner: Option<DID>,

    /// 权限系统使用的 owner 维度主体。只有 `usable_as_authz_subject == true`
    /// 时为 Some(等于 expected_owner)。
    pub authz_owner: Option<DID>,

    pub validity: VerifyValidity,
    pub purpose: VerifyPurpose,
    /// false 时该结果不得作为权限主语进入 RBAC 或应用内 ACL。
    pub usable_as_authz_subject: bool,

    /// 权威源对 (did, doc_type) 的发布状态回答;权威没回答/没有权威渠道时为 None。
    pub authority_status: Option<DocumentStatus>,
    pub authority_seq: Option<u64>,
    pub document_version: Option<u64>,
    /// `Anchored` = 权威源证明外部 JWT 属于当前发布集合;`NeedProof` = 只证明为
    /// expected_owner 签名的候选。
    pub body_evidence: BodyEvidence,
    /// 本次受控写入(或快路径命中)的缓存证据等级;未缓存为 None。
    pub cache_evidence: Option<CacheEvidence>,

    pub warnings: Vec<VerifyWarning>,
}

/// 权威信道给出的当前 body 与外部 JWT 是否为同一份文档:编码原文一致,或
/// (权威内联 JsonLd 时)payload 内容一致。内容一致即视为发布集合成员;
/// 普通文档随后仍要走 owner 验签,签名伪造在验签步骤被拒。
fn same_document(authority_body: &EncodedDocument, external: &EncodedDocument) -> bool {
    if authority_body == external {
        return true;
    }
    match (
        authority_body.clone().to_json_value(),
        external.clone().to_json_value(),
    ) {
        (Ok(authority_value), Ok(external_value)) => authority_value == external_value,
        _ => false,
    }
}

impl NameClient {
    /// 验证一份外部传入的 DID Document JWT(需求文档"校验流程")。
    ///
    /// 与 `resolve_did` 的关系:`resolve_did` 是"按 DID 解析当前文档";本入口是
    /// "外部已经有一份 JWT,判断它可不可信、归谁管"。验签使用的 owner 只能来自
    /// 权威 owner 绑定或 method 结构规则(`expected_owner`),绝不来自 payload。
    pub async fn verify_did_document_jwt(
        &self,
        did: &DID,
        doc_type: DidDocType,
        jwt: &str,
        options: VerifyDidDocumentJwtOptions,
    ) -> NSResult<VerifiedDidDocument> {
        // 硬门禁:key 类 DID 不是名字系统入口(与 resolve_did 一致)。
        if is_key_class_method(&did.method) {
            return Err(NSError::InvalidDID(format!(
                "key-class DID {} cannot be a DID Document JWT subject",
                did.to_string()
            )));
        }
        // Info 契约类 doc_type 按 method 契约免验证,没有 owner 信任链可验。
        if self
            .name_query
            .is_no_proof_doc_type(&did.method, &doc_type)
            .await
        {
            return Err(NSError::InvalidParam(format!(
                "doc_type {} is an unauthenticated info contract; verify_did_document_jwt does not apply",
                doc_type
            )));
        }

        // ---- 1. 解析 JWT payload,但不信任(只用于提取字段)----
        if jwt.split('.').count() != 3 || jwt.split('.').any(|segment| segment.is_empty()) {
            return Err(verify_err(
                VerifyDidJwtErrorCode::InvalidJwtDocument,
                "input is not a JWT (expect 3 dot-separated segments)",
            ));
        }
        let document = EncodedDocument::Jwt(jwt.to_string());
        // parse_did_doc 同时落实"JWT 形式的 DID Document 必须有 version_seq"
        // (ensure_version_seq_for_jwt)。
        let parsed = parse_did_doc(document.clone()).map_err(|err| {
            verify_err(
                VerifyDidJwtErrorCode::InvalidJwtDocument,
                format!("not a recognizable DID Document JWT: {}", err),
            )
        })?;
        if parsed.get_id() != *did {
            return Err(verify_err(
                VerifyDidJwtErrorCode::DocumentIdMismatch,
                format!(
                    "payload.id {} does not match requested {}",
                    parsed.get_id().to_string(),
                    did.to_string()
                ),
            ));
        }
        if parsed.get_doc_type() != doc_type {
            return Err(verify_err(
                VerifyDidJwtErrorCode::InvalidJwtDocument,
                format!(
                    "document body is a {} document, requested doc_type is {}",
                    parsed.get_doc_type(),
                    doc_type
                ),
            ));
        }
        let declared_owner = match parsed.get_iss() {
            None => None,
            Some(iss) => Some(DID::from_str(&iss).map_err(|err| {
                verify_err(
                    VerifyDidJwtErrorCode::InvalidJwtDocument,
                    format!("declared owner {} is not a valid DID: {}", iss, err),
                )
            })?),
        };

        // ---- 11. ValidAtIssue:显式依赖历史查询能力,不静默退化 ----
        // 当前实现没有把候选 iat 传给 resolver 的历史 owner 查询
        // (http_did_resolver_api.md 第 7 节尚未有任何 provider 实现),
        // 严格语义下只能回答"不支持"。
        if options.validity == VerifyValidity::ValidAtIssue {
            return Err(verify_err(
                VerifyDidJwtErrorCode::HistoricalVerificationUnsupported,
                format!(
                    "method {} resolver does not support historical owner-at-iat queries; \
                     ValidAtIssue cannot be evaluated strictly",
                    did.method
                ),
            ));
        }

        // CurrentActive:文档自声明已过期的候选不可能是"当前合法"。
        let now = buckyos_get_unix_timestamp();
        if let Some(exp) = parsed.get_exp() {
            if exp <= now {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::NotCurrentActive,
                    format!("document self-expired at {} (now {})", exp, now),
                ));
            }
        }

        // ---- 2. structural_owner:来自 method 名字结构,应用层不得字符串截取 ----
        let structural = structural_owner(did);

        // ---- in-TTL cache 快路径(校验流程 7 第 6 条:性能优化,不是 stale 兜底)----
        // 触发条件刻意收窄:非 Owner doc_type、外部 JWT 与缓存文档逐字节一致、
        // expected_owner 可由名字结构独立确定且 declared 一致、owner replay guard
        // 通过。此路径跳过权威源往返,owner binding 变更的可见性 ≤ 缓存 TTL,
        // 与 resolve_did 的 in-TTL Hit 是同一档位的取舍。
        if doc_type != DidDocType::Owner && self.config.enable_cache {
            match self.doc_cache.lookup(did, Some(doc_type.clone())) {
                Some(CacheLookup::Negative {
                    message,
                    in_ttl: true,
                    ..
                }) => {
                    // 负状态是权威源的"回答",in-TTL 内直接生效。
                    return Err(verify_err(
                        VerifyDidJwtErrorCode::NotCurrentActive,
                        format!("negative state remembered: {}", message),
                    ));
                }
                Some(CacheLookup::Positive {
                    doc,
                    evidence,
                    in_ttl: true,
                    ..
                }) if matches!(
                    evidence,
                    CacheEvidence::Published | CacheEvidence::Verified
                ) && doc.to_string() == jwt =>
                {
                    if let (Some(so), Some(declared)) =
                        (structural.as_ref(), declared_owner.as_ref())
                    {
                        if so == declared {
                            match self.doc_cache.validate_owner_revocation(
                                did,
                                Some(doc_type.clone()),
                                &document,
                            ) {
                                Ok(()) => {
                                    let usable_as_authz_subject =
                                        options.purpose == VerifyPurpose::AuthSubject;
                                    return Ok(VerifiedDidDocument {
                                        subject_did: did.clone(),
                                        doc_type,
                                        document,
                                        structural_owner: structural.clone(),
                                        authority_owner: None,
                                        expected_owner: Some(so.clone()),
                                        declared_owner: declared_owner.clone(),
                                        authz_owner: if usable_as_authz_subject {
                                            Some(so.clone())
                                        } else {
                                            None
                                        },
                                        validity: options.validity,
                                        purpose: options.purpose,
                                        usable_as_authz_subject,
                                        authority_status: None,
                                        authority_seq: None,
                                        document_version: parsed.get_version_seq(),
                                        body_evidence: evidence.to_body_evidence(),
                                        cache_evidence: Some(evidence),
                                        warnings: Vec::new(),
                                    });
                                }
                                Err(err) => {
                                    info!(
                                        "cached {}#{} rejected by owner replay guard during verify: {}",
                                        did.to_string(),
                                        doc_type,
                                        err
                                    );
                                    self.doc_cache.delete(did.clone(), Some(doc_type.clone()));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // ---- 3. 查询权威状态(PublishedState 语义)----
        // 注:zone resolver(cluster L1 cache)暂不参与本入口;它的回答不携带
        // owner 绑定,留待 zone 服务落地后再扩展。
        let mut authority_owner: Option<DID> = None;
        let mut authority_status: Option<DocumentStatus> = None;
        let mut authority_seq: Option<u64> = None;
        let mut published_version: Option<u64> = None;
        let mut doc_hash: Option<String> = None;
        let mut authority_body: Option<EncodedDocument> = None;

        match self.name_query.authority_answer_for(did, &doc_type).await? {
            // method 没有注册权威渠道:发布状态与 owner 绑定不可知,外部 JWT
            // 只能按 NeedProof 候选走完整 owner 验证(expected_owner 只能来自
            // 名字结构)。
            None => {}
            // 权威渠道存在却没回答(断网/超时):当前发布集合验证不了——就算
            // 验签通过,也可能正顶掉一份已发布甚至已吊销的结果(策略点③同款)。
            Some(ProviderResolveResult::Unknown(err)) => {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::NotCurrentActive,
                    format!(
                        "method authority did not answer for {}#{}; \
                         current publication set cannot be verified: {}",
                        did.to_string(),
                        doc_type,
                        err
                    ),
                ));
            }
            Some(ProviderResolveResult::Dr(answer)) => {
                authority_owner = answer.owner_binding.clone();
                if let Some(published) = answer.published.as_ref() {
                    authority_seq = published.authority_seq;
                    published_version = published.document_version;
                }
                authority_status = answer.status.clone();
                match answer.status {
                    Some(DocumentStatus::Revoked) | Some(DocumentStatus::Tombstoned) => {
                        let status = authority_status.clone().unwrap();
                        let message = format!(
                            "{}#{} is {:?} in method authority",
                            did.to_string(),
                            doc_type,
                            status
                        );
                        // 权威负状态更新 negative cache 并屏蔽后续 fallback
                        // (需求文档"Cache 行为"第 6 条)。
                        if self.config.enable_cache {
                            self.doc_cache.replace_with_negative(
                                did,
                                Some(doc_type.clone()),
                                &status,
                                &message,
                            );
                        }
                        return Err(verify_err(
                            VerifyDidJwtErrorCode::NotCurrentActive,
                            message,
                        ));
                    }
                    Some(DocumentStatus::Migrated) => {
                        if self.config.enable_cache {
                            self.doc_cache.delete(did.clone(), Some(doc_type.clone()));
                        }
                        let target = answer
                            .migration_target
                            .map(|target| target.to_string())
                            .unwrap_or_else(|| "unknown target".to_string());
                        return Err(verify_err(
                            VerifyDidJwtErrorCode::NotCurrentActive,
                            format!(
                                "{}#{} is Migrated to {} in method authority",
                                did.to_string(),
                                doc_type,
                                target
                            ),
                        ));
                    }
                    Some(DocumentStatus::Missing) | Some(DocumentStatus::Expired) => {
                        return Err(verify_err(
                            VerifyDidJwtErrorCode::NotCurrentActive,
                            format!(
                                "{}#{} is {:?} in method authority",
                                did.to_string(),
                                doc_type,
                                authority_status.clone().unwrap()
                            ),
                        ));
                    }
                    Some(DocumentStatus::Active) | None => {
                        doc_hash = answer.doc_hash.clone();
                        authority_body = answer.body.map(|body| body.document);
                    }
                }
            }
        }

        // ---- 7. 当前发布集合 membership ----
        // 权威源锚定了 doc_hash 或给出了当前 body 时,外部 JWT 必须属于/等于它,
        // 匹配成功即提升为 Anchored 证据;权威源只回答 Active 而给不出锚点时
        // membership 未知,外部 JWT 保持 NeedProof 候选档。
        let mut membership_proven = false;
        if let Some(hash) = doc_hash.as_deref() {
            if !content_hash_matches(hash, &document) {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::NotCurrentActive,
                    format!(
                        "external JWT does not match authority doc_hash for {}#{}",
                        did.to_string(),
                        doc_type
                    ),
                ));
            }
            membership_proven = true;
        } else if let Some(current_body) = authority_body.as_ref() {
            if !same_document(current_body, &document) {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::NotCurrentActive,
                    format!(
                        "method authority serves a different current document for {}#{}",
                        did.to_string(),
                        doc_type
                    ),
                ));
            }
            membership_proven = true;
        }

        // ---- 4. expected_owner:只能来自权威绑定或名字结构,绝不来自 payload ----
        let expected_owner = authority_owner.clone().or_else(|| structural.clone());

        // ---- 5. 默认主体策略 ----
        let detached = matches!(
            (structural.as_ref(), authority_owner.as_ref()),
            (Some(structural), Some(authority)) if structural != authority
        );
        if options.purpose == VerifyPurpose::AuthSubject {
            if detached {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::DetachedOwnerRejected,
                    format!(
                        "authority owner {} differs from structural owner {} for {}#{}; \
                         detached owner cannot be an auth subject",
                        authority_owner.as_ref().unwrap().to_string(),
                        structural.as_ref().unwrap().to_string(),
                        did.to_string(),
                        doc_type
                    ),
                ));
            }
            if expected_owner.is_none() {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::OwnerBindingUnavailable,
                    format!(
                        "no authority owner binding and no structural owner for {}#{}; \
                         a first-level name needs an authority binding to be a subject",
                        did.to_string(),
                        doc_type
                    ),
                ));
            }
        }

        let mut warnings: Vec<VerifyWarning> = Vec::new();

        if doc_type == DidDocType::Owner {
            // ---- 递归基:OwnerDocument ----
            // owner 不能自己给自己作保(get_iss() == None):外部 Owner JWT 的
            // 可信性只能来自权威源的 anchored/current membership;文档自带 key
            // 的自签校验只做完整性自检,不构成信任来源。
            if !membership_proven {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::NotCurrentActive,
                    format!(
                        "external OwnerDocument JWT for {} is not anchored to the current \
                         publication set; an owner document cannot vouch for itself",
                        did.to_string()
                    ),
                ));
            }
            let Some((self_key, _jwk)) = parsed.get_auth_key(None) else {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::InvalidJwtDocument,
                    "owner document has no usable auth key",
                ));
            };
            if let Err(err) = decode_json_from_jwt_with_pk(jwt, &self_key) {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::SignatureVerificationFailed,
                    format!("owner document self-signature verification failed: {}", err),
                ));
            }
        } else if let Some(expected) = expected_owner.as_ref() {
            // ---- 6. declared_owner 一致性:自声明 owner 必须等于 expected_owner ----
            match declared_owner.as_ref() {
                None => {
                    return Err(verify_err(
                        VerifyDidJwtErrorCode::DeclaredOwnerMismatch,
                        format!(
                            "document declares no owner but expected owner is {}",
                            expected.to_string()
                        ),
                    ));
                }
                Some(declared) if declared != expected => {
                    return Err(verify_err(
                        VerifyDidJwtErrorCode::DeclaredOwnerMismatch,
                        format!(
                            "{}#{} declares owner {} but expected owner is {}",
                            did.to_string(),
                            doc_type,
                            declared.to_string(),
                            expected.to_string()
                        ),
                    ));
                }
                _ => {}
            }

            // ---- 8. 解析 expected_owner 的 OwnerDocument ----
            // 递归入口是 expected_owner,绝不是 declared_owner;
            // for_authority_lookup():不允许 Missing 自签名入场、不允许 stale cache,
            // 权威负状态生效;descend() 做深度/环路检查。
            let owner_policy = ResolvePolicy::default()
                .for_authority_lookup()
                .descend(expected, &DidDocType::Owner)
                .map_err(|err| {
                    verify_err(VerifyDidJwtErrorCode::OwnerDocumentUnavailable, err.to_string())
                })?;
            let owner_resolved = self
                .resolve_did_ex(expected, Some(DidDocType::Owner), owner_policy)
                .await
                .map_err(|err| {
                    verify_err(
                        VerifyDidJwtErrorCode::OwnerDocumentUnavailable,
                        format!(
                            "resolve owner document {} for {}#{} failed: {}",
                            expected.to_string(),
                            did.to_string(),
                            doc_type,
                            err
                        ),
                    )
                })?;
            let owner_document =
                OwnerDocument::decode(&owner_resolved.document, None).map_err(|err| {
                    verify_err(
                        VerifyDidJwtErrorCode::OwnerDocumentUnavailable,
                        format!(
                            "owner document {} is not a valid OwnerDocument: {}",
                            expected.to_string(),
                            err
                        ),
                    )
                })?;

            // ---- 10. revoke / replay guard:valid_iat + mini_version_seq 统一应用 ----
            owner_document
                .validate_jwt_revocation(doc_type.as_str(), &document)
                .map_err(|err| {
                    verify_err(VerifyDidJwtErrorCode::RevokedByOwnerPolicy, err.to_string())
                })?;

            // ---- 9. 用 owner 默认 key 验签,失败后按现有策略尝试历史 key ----
            let Some((decoding_key, _jwk)) = owner_document.get_auth_key(None) else {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::OwnerDocumentUnavailable,
                    format!(
                        "owner document {} has no usable auth key",
                        expected.to_string()
                    ),
                ));
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
                    return Err(verify_err(
                        VerifyDidJwtErrorCode::SignatureVerificationFailed,
                        format!(
                            "{}#{} signature verification failed against owner {}",
                            did.to_string(),
                            doc_type,
                            expected.to_string()
                        ),
                    ));
                }
                warnings.push(ResolveWarning::SignedByHistoricalKey);
            }
        } else {
            // expected_owner 推不出(只有 ObjectDocument 能走到这里):只有当
            // 权威信道已经证明外部 JWT 就是当前 body 时,才能返回"非授权主体"
            // 结果(校验流程 4 第 3 条);否则 NeedProof 候选彻底没有验证依据。
            if !membership_proven {
                return Err(verify_err(
                    VerifyDidJwtErrorCode::OwnerBindingUnavailable,
                    format!(
                        "no owner binding, no structural owner, and no current-publication \
                         membership proof for {}#{}",
                        did.to_string(),
                        doc_type
                    ),
                ));
            }
        }

        // ---- 结果组装与受控缓存写入(需求文档"Cache 行为"第 1-4 条)----
        let body_evidence = if membership_proven {
            BodyEvidence::Anchored
        } else {
            BodyEvidence::NeedProof
        };
        let usable_as_authz_subject =
            options.purpose == VerifyPurpose::AuthSubject && expected_owner.is_some();
        let authz_owner = if usable_as_authz_subject {
            expected_owner.clone()
        } else {
            None
        };

        let mut cache_evidence: Option<CacheEvidence> = None;
        if options.cache_result && self.config.enable_cache && !detached {
            // detached(只有 ObjectDocument 能走到)不写普通 cache:现有 cache
            // 条目无法记录 purpose / usable_as_authz_subject,旧调用方可能把
            // 同一条目误当权限主体使用(Cache 行为第 3 条)。
            let evidence = if membership_proven {
                CacheEvidence::Published
            } else {
                CacheEvidence::Verified
            };
            let exp = Self::cache_ttl_exp(&document);
            if self.doc_cache.update(
                did.clone(),
                Some(doc_type.clone()),
                document.clone(),
                exp,
                evidence,
            ) {
                cache_evidence = Some(evidence);
                if doc_type == DidDocType::Zone {
                    // 与 resolve 路径的缓存布局一致:zone 文档同时写默认槽位。
                    self.doc_cache
                        .update(did.clone(), None, document.clone(), exp, evidence);
                }
            }
        }

        Ok(VerifiedDidDocument {
            subject_did: did.clone(),
            doc_type,
            document,
            structural_owner: structural,
            authority_owner,
            expected_owner,
            declared_owner,
            authz_owner,
            validity: options.validity,
            purpose: options.purpose,
            usable_as_authz_subject,
            authority_status,
            authority_seq,
            document_version: published_version.or_else(|| parsed.get_version_seq()),
            body_evidence,
            cache_evidence,
            warnings,
        })
    }

    /// 便捷 typed wrapper(需求文档"API 草案"):验证 DeviceDocument JWT 并
    /// 返回解码后的 DeviceDocument。RTCP 迁移用法:
    /// source device 用 `subject_did`,source owner 用 `authz_owner`,tunnel token
    /// 验证 key 从返回的 DeviceDocument 取。对端私钥持有证明与 zone 归属检查
    /// 仍由 RTCP 自己完成(非目标第 5 条)。
    pub async fn verify_device_document_jwt(
        &self,
        did: &DID,
        jwt: &str,
        options: VerifyDidDocumentJwtOptions,
    ) -> NSResult<(DeviceDocument, VerifiedDidDocument)> {
        let verified = self
            .verify_did_document_jwt(did, DidDocType::Device, jwt, options)
            .await?;
        let device_document = DeviceDocument::decode(&verified.document, None).map_err(|err| {
            NSError::Failed(format!(
                "decode verified DeviceDocument {} failed: {}",
                did.to_string(),
                err
            ))
        })?;
        Ok((device_document, verified))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc_cache::CacheBackend;
    use crate::name_client::NameClientConfig;
    use crate::{
        document_content_hash, DocumentRef, NameInfo, NsProvider, PublishedState, RecordType,
    };
    use async_trait::async_trait;
    use jsonwebtoken::{jwk::Jwk, EncodingKey};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    // 固定的测试 Ed25519 keypair:alice(owner)与 bob(另一个 owner / 攻击者)。
    const ALICE_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
    const ALICE_PUBLIC_JWK_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
    const BOB_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----";
    const BOB_PUBLIC_JWK_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";
    // 设备自己的 key(只作为文档内容,不参与 owner 验签)。
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

    fn build_owner_doc(
        owner_did: &DID,
        valid_iat: Option<u64>,
        mini_version_seq: Option<u64>,
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
        owner.mini_version_seq = mini_version_seq;
        owner.encode(Some(key)).unwrap()
    }

    /// 刚发生过 key rotation 的 owner 文档:`#main_key` 是新 key(alice),
    /// `#legacy_key` 保留旧 key(bob 的 key 充当)。
    fn build_owner_doc_with_legacy_key(owner_did: &DID) -> EncodedDocument {
        let (alice_signing, alice_jwk) = alice_key();
        let (_, legacy_jwk) = bob_key();
        let now = ts(0);
        let json_doc = json!({
            "id": owner_did.to_string(),
            "verificationMethod": [
                {
                    "type": "Ed25519VerificationKey2020",
                    "id": "#main_key",
                    "controller": owner_did.to_string(),
                    "publicKeyJwk": alice_jwk,
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
        owner.encode(Some(&alice_signing)).unwrap()
    }

    fn build_device_doc(
        device_did: &DID,
        owner_did: &DID,
        iat: u64,
        version_seq: u64,
        key: &EncodingKey,
    ) -> EncodedDocument {
        let mut device = DeviceDocument::new("laptop", DEVICE_PUBLIC_X.to_string());
        device.id = device_did.clone();
        device.owner = owner_did.clone();
        device.iat = iat;
        device.exp = iat + 3600 * 24 * 365;
        device.version_seq = Some(version_seq);
        device.encode(Some(key)).unwrap()
    }

    fn build_zone_doc(
        zone_did: &DID,
        owner_did: &DID,
        iat: u64,
        key: &EncodingKey,
    ) -> EncodedDocument {
        let (_, owner_jwk) = alice_key();
        let mut zone = ZoneDocument::new(zone_did.clone(), owner_did.clone(), owner_jwk);
        zone.iat = iat;
        zone.exp = iat + 3600 * 24 * 365;
        zone.version_seq = Some(1);
        zone.encode(Some(key)).unwrap()
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

    async fn client_with_bns_authority(provider: AuthorityProvider) -> NameClient {
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: None,
            cache_backend: CacheBackend::Memory,
            // 测试必须关闭 zone resolver:开发机上可能真的跑着 127.0.0.1:3180。
            enable_zone_resolver: false,
            ..Default::default()
        });
        client.set_method_authority("bns", Box::new(provider)).await;
        client
    }

    fn active_state(did: &DID, doc_type: &str, owner: Option<DID>) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            document_status: DocumentStatus::Active,
            document_ref: None,
            document_version: None,
            effective_owner: owner,
            authority_seq: Some(1),
            migration_target: None,
        }
    }

    fn state_with_status(did: &DID, doc_type: &str, status: DocumentStatus) -> PublishedState {
        PublishedState {
            did: did.clone(),
            doc_type: doc_type.to_string(),
            document_status: status,
            document_ref: None,
            document_version: None,
            effective_owner: None,
            authority_seq: Some(1),
            migration_target: None,
        }
    }

    fn alice_owner_state_and_doc(provider: AuthorityProvider) -> AuthorityProvider {
        let alice = did("did:bns:alice");
        let (alice_signing, alice_jwk) = alice_key();
        let owner_doc = build_owner_doc(&alice, None, None, &alice_signing, alice_jwk);
        provider.with_state(PublishedState::active(
            alice,
            "owner".to_string(),
            owner_doc,
        ))
    }

    fn code_of<T: std::fmt::Debug>(result: &NSResult<T>) -> Option<VerifyDidJwtErrorCode> {
        result.as_ref().err().and_then(VerifyDidJwtErrorCode::of)
    }

    // 需求文档测试要求 1/3:JWT 声明 owner 为 bob(即使真用 bob key 签名),
    // 而 expected_owner 由名字结构定为 alice —— 必须失败。
    #[tokio::test]
    async fn declared_owner_must_match_expected_owner() {
        let laptop = did("did:bns:laptop.alice");
        let (bob_signing, _) = bob_key();
        let doc = build_device_doc(&laptop, &did("did:bns:bob"), ts(-60), 1, &bob_signing);

        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test")
                .with_state(active_state(&laptop, "device", None)),
        );
        let client = client_with_bns_authority(provider).await;

        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::DeclaredOwnerMismatch)
        );
    }

    // 需求文档测试要求 4:payload.id != did 直接失败。
    #[tokio::test]
    async fn document_id_mismatch_fails() {
        let laptop = did("did:bns:laptop.alice");
        let phone = did("did:bns:phone.alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &did("did:bns:alice"), ts(-60), 1, &alice_signing);

        let client = client_with_bns_authority(AuthorityProvider::new("bns-test")).await;
        let result = client
            .verify_did_document_jwt(
                &phone,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::DocumentIdMismatch)
        );
    }

    // 需求文档测试要求 2/12:authority_owner=bob 与 structural_owner=alice 冲突,
    // AuthSubject 必须拒绝;ObjectDocument 可继续,但不得作为权限主语,且
    // detached 结果不写普通 Verified cache。
    #[tokio::test]
    async fn detached_owner_rejected_for_auth_subject_allowed_for_object() {
        let laptop = did("did:bns:laptop.alice");
        let bob = did("did:bns:bob");
        let (bob_signing, bob_jwk) = bob_key();
        let doc = build_device_doc(&laptop, &bob, ts(-60), 1, &bob_signing);

        let bob_owner_doc = build_owner_doc(&bob, None, None, &bob_signing, bob_jwk);
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&laptop, "device", Some(bob.clone())))
            .with_state(PublishedState::active(
                bob.clone(),
                "owner".to_string(),
                bob_owner_doc,
            ));
        let client = client_with_bns_authority(provider).await;

        let subject_result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&subject_result),
            Some(VerifyDidJwtErrorCode::DetachedOwnerRejected)
        );

        let object_result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions {
                    purpose: VerifyPurpose::ObjectDocument,
                    ..Default::default()
                },
            )
            .await
            .expect("object purpose should tolerate detached owner");
        assert!(!object_result.usable_as_authz_subject);
        assert_eq!(object_result.authz_owner, None);
        assert_eq!(object_result.expected_owner, Some(bob.clone()));
        assert_eq!(object_result.authority_owner, Some(bob));
        assert_eq!(
            object_result.structural_owner,
            Some(did("did:bns:alice"))
        );
        // detached 结果不写普通 cache。
        assert_eq!(object_result.cache_evidence, None);
        assert!(client
            .doc_cache
            .lookup(&laptop, Some(DidDocType::Device))
            .is_none());
    }

    // 需求文档测试要求 5:权威负状态 / Missing 在 CurrentActive 下失败,
    // 吊销写 negative cache。
    #[tokio::test]
    async fn authority_negative_status_fails_current_active() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 1, &alice_signing);

        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test").with_state(state_with_status(
                &laptop,
                "device",
                DocumentStatus::Revoked,
            )),
        );
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
        assert!(matches!(
            client.doc_cache.lookup(&laptop, Some(DidDocType::Device)),
            Some(CacheLookup::Negative { .. })
        ));

        // Missing 同样失败(但不写 negative cache)。
        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test").with_state(state_with_status(
                &laptop,
                "device",
                DocumentStatus::Missing,
            )),
        );
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
    }

    // 需求文档测试要求 6:owner 设置 valid_iat 后,较旧 iat 的 JWT 失败。
    #[tokio::test]
    async fn owner_valid_iat_revokes_older_jwt() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, alice_jwk) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-3600), 1, &alice_signing);

        let owner_doc = build_owner_doc(&alice, Some(ts(-60)), None, &alice_signing, alice_jwk);
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&laptop, "device", None))
            .with_state(PublishedState::active(
                alice.clone(),
                "owner".to_string(),
                owner_doc,
            ));
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::RevokedByOwnerPolicy)
        );
    }

    // 需求文档测试要求 7:owner 设置 mini_version_seq 后,较旧 version_seq 失败。
    #[tokio::test]
    async fn owner_mini_version_seq_revokes_older_version() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, alice_jwk) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 3, &alice_signing);

        let owner_doc = build_owner_doc(&alice, None, Some(5), &alice_signing, alice_jwk);
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&laptop, "device", None))
            .with_state(PublishedState::active(
                alice.clone(),
                "owner".to_string(),
                owner_doc,
            ));
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::RevokedByOwnerPolicy)
        );
    }

    // 需求文档测试要求 8:默认 key 失败但历史 key 成功,验证通过并返回
    // SignedByHistoricalKey warning。
    #[tokio::test]
    async fn historical_key_fallback_verifies_with_warning() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        // 设备文档用旧 key(bob key 充当 legacy key)签名。
        let (legacy_signing, _) = bob_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 1, &legacy_signing);

        let owner_doc = build_owner_doc_with_legacy_key(&alice);
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&laptop, "device", None))
            .with_state(PublishedState::active(
                alice.clone(),
                "owner".to_string(),
                owner_doc,
            ));
        let client = client_with_bns_authority(provider).await;
        let verified = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("historical key should verify");
        assert!(verified
            .warnings
            .contains(&ResolveWarning::SignedByHistoricalKey));
        assert_eq!(verified.authz_owner, Some(alice));
    }

    // 需求文档测试要求 9:ValidAtIssue 在没有历史查询能力时返回
    // HistoricalVerificationUnsupported。
    #[tokio::test]
    async fn valid_at_issue_is_unsupported() {
        let laptop = did("did:bns:laptop.alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &did("did:bns:alice"), ts(-60), 1, &alice_signing);

        let client = client_with_bns_authority(AuthorityProvider::new("bns-test")).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions {
                    validity: VerifyValidity::ValidAtIssue,
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::HistoricalVerificationUnsupported)
        );
    }

    // 需求文档测试要求 10:一级 BNS 名字不能从结构推导 self-owned;只有权威源
    // 返回 authority_owner = 自己时才能作为 AuthSubject。
    #[tokio::test]
    async fn first_level_name_requires_authority_binding() {
        let alice = did("did:bns:alice");
        let (alice_signing, alice_jwk) = alice_key();
        let zone_doc = build_zone_doc(&alice, &alice, ts(-60), &alice_signing);
        let owner_doc = build_owner_doc(&alice, None, None, &alice_signing, alice_jwk);

        // 权威源不给 owner binding:不得把自声明 owner 当验签依据。
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&alice, "zone", None))
            .with_state(PublishedState::active(
                alice.clone(),
                "owner".to_string(),
                owner_doc.clone(),
            ));
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &alice,
                DidDocType::Zone,
                &zone_doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::OwnerBindingUnavailable)
        );

        // 权威源声明 binding = alice:可以作为 self-owned subject。
        let provider = AuthorityProvider::new("bns-test")
            .with_state(active_state(&alice, "zone", Some(alice.clone())))
            .with_state(PublishedState::active(
                alice.clone(),
                "owner".to_string(),
                owner_doc,
            ));
        let client = client_with_bns_authority(provider).await;
        let verified = client
            .verify_did_document_jwt(
                &alice,
                DidDocType::Zone,
                &zone_doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("authority binding makes first-level name a subject");
        assert!(verified.usable_as_authz_subject);
        assert_eq!(verified.authz_owner, Some(alice.clone()));
        assert_eq!(verified.expected_owner, Some(alice.clone()));
        assert_eq!(verified.structural_owner, None);
        assert_eq!(verified.authority_owner, Some(alice));
    }

    // 需求文档测试要求 11(RTCP 迁移形态):verify_device_document_jwt 输出的
    // source owner 来自 authz_owner,不来自 payload、也不来自名字截取。
    #[tokio::test]
    async fn device_wrapper_returns_typed_document_and_authz_owner() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 1, &alice_signing);

        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test")
                .with_state(active_state(&laptop, "device", Some(alice.clone()))),
        );
        let client = client_with_bns_authority(provider).await;
        let (device_document, verified) = client
            .verify_device_document_jwt(
                &laptop,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("device verification should pass");
        assert_eq!(device_document.name, "laptop");
        assert_eq!(verified.subject_did, laptop);
        assert!(verified.usable_as_authz_subject);
        assert_eq!(verified.authz_owner, Some(alice));
        // 只证明为 expected_owner 签名的候选:NeedProof / Verified 档。
        assert_eq!(verified.body_evidence, BodyEvidence::NeedProof);
        assert_eq!(verified.cache_evidence, Some(CacheEvidence::Verified));
    }

    // 权威源锚定 doc_hash 且匹配:提升为 Published/Anchored;不匹配:失败。
    #[tokio::test]
    async fn doc_hash_membership_promotes_to_published() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 1, &alice_signing);

        let mut anchored = active_state(&laptop, "device", Some(alice.clone()));
        anchored.document_ref = Some(DocumentRef {
            uri: None,
            content_hash: Some(document_content_hash(&doc)),
            inline_document: None,
        });
        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test").with_state(anchored),
        );
        let client = client_with_bns_authority(provider).await;
        let verified = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("hash-anchored member should verify");
        assert_eq!(verified.body_evidence, BodyEvidence::Anchored);
        assert_eq!(verified.cache_evidence, Some(CacheEvidence::Published));

        // hash 不匹配:外部 JWT 不属于当前发布集合。
        let mut mismatched = active_state(&laptop, "device", Some(alice.clone()));
        mismatched.document_ref = Some(DocumentRef {
            uri: None,
            content_hash: Some("deadbeef".to_string()),
            inline_document: None,
        });
        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test").with_state(mismatched),
        );
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
    }

    // 校验流程 7 第 6 条:in-TTL cache 快路径。首次验证写入 Verified cache 后,
    // 权威源断网也能在 TTL 内继续验证同一份 JWT(不发起任何 provider 调用),
    // owner replay guard 仍然生效。
    #[tokio::test]
    async fn in_ttl_cache_fast_path_serves_same_jwt_offline() {
        let laptop = did("did:bns:laptop.alice");
        let alice = did("did:bns:alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &alice, ts(-60), 1, &alice_signing);

        let provider = alice_owner_state_and_doc(
            AuthorityProvider::new("bns-test")
                .with_state(active_state(&laptop, "device", Some(alice.clone()))),
        );
        let (fail_state, calls) = provider.handles();
        let client = client_with_bns_authority(provider).await;

        let first = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("online verification should pass");
        assert_eq!(first.authority_owner, Some(alice.clone()));
        assert_eq!(first.cache_evidence, Some(CacheEvidence::Verified));

        // 权威源断网,快路径仍然服务同一份 JWT。
        fail_state.store(true, Ordering::SeqCst);
        let calls_before = calls.load(Ordering::SeqCst);
        let second = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("in-TTL cache fast path should serve the same JWT");
        assert_eq!(calls.load(Ordering::SeqCst), calls_before);
        assert_eq!(second.authority_owner, None);
        assert_eq!(second.expected_owner, Some(alice));
        assert!(second.usable_as_authz_subject);

        // 不同的 JWT(内容不一致)不走快路径:权威断网时必须失败。
        let other_doc = build_device_doc(&laptop, &did("did:bns:alice"), ts(-30), 2, &alice_signing);
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &other_doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
    }

    // 递归基:外部 OwnerDocument JWT 必须由权威源证明 membership,不能
    // 用自声明 owner 递归回自己;有 binding 时可作为 self-owned subject。
    #[tokio::test]
    async fn owner_doc_type_requires_anchored_membership() {
        let alice = did("did:bns:alice");
        let (alice_signing, alice_jwk) = alice_key();
        let owner_doc = build_owner_doc(&alice, None, None, &alice_signing, alice_jwk);

        // 权威源内联同一份 JWT + binding = alice:membership 证明 + self-owned。
        let mut state = PublishedState::active(alice.clone(), "owner".to_string(), owner_doc.clone());
        state.effective_owner = Some(alice.clone());
        let provider = AuthorityProvider::new("bns-test").with_state(state);
        let client = client_with_bns_authority(provider).await;
        let verified = client
            .verify_did_document_jwt(
                &alice,
                DidDocType::Owner,
                &owner_doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await
            .expect("anchored owner document should verify");
        assert_eq!(verified.body_evidence, BodyEvidence::Anchored);
        assert_eq!(verified.declared_owner, None);
        assert!(verified.usable_as_authz_subject);
        assert_eq!(verified.authz_owner, Some(alice.clone()));

        // 权威源只回答 Active(无锚点、无 body):owner 文档不能自证。
        let mut state = active_state(&alice, "owner", Some(alice.clone()));
        state.document_ref = None;
        let provider = AuthorityProvider::new("bns-test").with_state(state);
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &alice,
                DidDocType::Owner,
                &owner_doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
    }

    // 权威渠道存在却没回答:当前发布集合验证不了,必须失败(不允许把
    // "断网"当成"可以只做验签")。
    #[tokio::test]
    async fn authority_unknown_fails_verification() {
        let laptop = did("did:bns:laptop.alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &did("did:bns:alice"), ts(-60), 1, &alice_signing);

        let provider = AuthorityProvider::new("bns-test");
        let (fail_state, _) = provider.handles();
        fail_state.store(true, Ordering::SeqCst);
        let client = client_with_bns_authority(provider).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Device,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::NotCurrentActive)
        );
    }

    // 请求的 doc_type 与 JWT 实际解析出的文档类型不一致:拒绝。
    #[tokio::test]
    async fn mismatched_doc_type_body_is_rejected() {
        let laptop = did("did:bns:laptop.alice");
        let (alice_signing, _) = alice_key();
        let doc = build_device_doc(&laptop, &did("did:bns:alice"), ts(-60), 1, &alice_signing);

        let client = client_with_bns_authority(AuthorityProvider::new("bns-test")).await;
        let result = client
            .verify_did_document_jwt(
                &laptop,
                DidDocType::Zone,
                &doc.to_string(),
                VerifyDidDocumentJwtOptions::default(),
            )
            .await;
        assert_eq!(
            code_of(&result),
            Some(VerifyDidJwtErrorCode::InvalidJwtDocument)
        );
    }
}
