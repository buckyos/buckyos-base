//! 验证确切输入与 Owner 的两次查询(设计稿 §6;伪代码 `verify_document` /
//! `_verify_document_ex` / `get_expected_owner` / `commit_candidate_doc` /
//! `remove_doc_result`)。
//!
//! `verify_document` 按 opts 获取发布与 Owner 材料,保存发布 / 撤销事实,只有 valid
//! 输入才能推进 best;业务仍须单独完成持钥证明和权限检查。

use super::budget::{erase, BoxFut};
use super::doc_result::{apply_known_constraints, publish_evidence_for, DocResult};
use super::opts::ResolveOpts;
use super::publish_info::PublishInfo;
use super::revision::{is_key_class_method, structural_owner, ParsedDocument, Revision};
use super::source::{SourceRef, SourceTier};
use super::verify_result::{DependencyRole, Validity, VerifyResult};
use crate::name_client::NameClient;
use jsonwebtoken::DecodingKey;
use log::debug;
use name_lib::{
    decode_json_from_jwt_with_pk, DIDDocumentTrait, DidDocType, EncodedDocument, NSError, NSResult,
    OwnerDocument, DID,
};

impl NameClient {
    /// 始终验证收到的确切文档;允许按 opts 补材料并更新解析缓存。
    pub fn verify_document<'a>(
        &'a self,
        did: &'a DID,
        doc_type: Option<DidDocType>,
        body: &'a EncodedDocument,
        revision: Revision,
        opts: ResolveOpts,
    ) -> BoxFut<'a, NSResult<VerifyResult>> {
        erase(self.verify_document_inner(did, doc_type, body, revision, opts))
    }

        pub async fn verify_document_inner(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        body: &EncodedDocument,
        revision: Revision,
        opts: ResolveOpts,
    ) -> NSResult<VerifyResult> {
        revision.validate()?;
        let opts = self.normalize_opts(opts);
        let locker_version = self.locker_version();
        if is_key_class_method(&did.method) {
            return Ok(VerifyResult::new(locker_version).invalid(format!(
                "key-class DID {} cannot be a DID Document subject",
                did.to_string()
            )));
        }
        let parsed = match ParsedDocument::parse(body) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Ok(VerifyResult::new(locker_version).invalid(format!("unparsable document: {}", err)));
            }
        };
        let doc_type = match doc_type {
            Some(doc_type) => doc_type,
            None => match parsed.doc_type.clone() {
                Some(doc_type) => doc_type,
                None => self.resolve_doc_type(did, None, &opts).await?.0,
            },
        };
        let mut opts = opts;
        opts.mark_visited(did, &doc_type);
        if let Err(reason) = parsed.matches(did, &doc_type) {
            let mut report = VerifyResult::new(locker_version).invalid(reason);
            report.doc_type = Some(doc_type);
            report.revision = parsed.revision().cloned();
            return Ok(report);
        }
        let doc_revision = parsed.revision().cloned().expect("matches() guarantees iat");

        // 段 1:读缓存与刷新约束,不包 I/O。
        let mut result = {
            let _guard = self.serialize_document(did, &doc_type, &opts).await?;
            let mut result = self.read_doc_result(did, &doc_type, &opts);
            let owner = self.owner_constraint_for(did, &result, &opts);
            result.refresh_known_constraints(locker_version, owner.as_ref());
            result
        };
        // locker 仍优先;比较的是收到的文档,不能用锁定的另一份文档替代它。
        if let Some(locked) = self.get_locked_document(did, &doc_type, &revision, &opts).await? {
            result = locked;
        }

        let cached = result.find_verified(&doc_revision).cloned();
        if let Some(cached) = cached.as_ref() {
            if self.reusable_for(cached, &result, &revision, &opts, did) {
                let mut report = cached.report.clone();
                let owner = self.owner_constraint_for(did, &result, &opts);
                apply_known_constraints(&mut report, &parsed, &result, &revision, owner.as_ref());
                result.set_selection_flags(&mut report, &doc_revision, &revision);
                if report.success(&revision) {
                    return Ok(report);
                }
            }
        }

        // 即便缓存命中失败,也可复用该确切文档原先取得的 authority / trust 来源材料。
        let source = match cached.as_ref() {
            Some(cached) if cached.is_valid() || cached.source.tier != SourceTier::Normal => {
                cached.source.clone()
            }
            _ => SourceRef::normal("verify-input"),
        };
        let info = self
            .get_publish_info(did, &doc_type, &revision, &opts, &result)
            .await?;
        let (report, info) = self
            .verify_document_ex(did, &doc_type, &parsed, &mut result, info, &source, &revision, &opts)
            .await?;
        let mut report = report;
        if !result.locked {
            result.apply_publish_info(info.as_ref());
            report = result.accept_verified(body.clone(), source, report, &revision);
            let (merged, conflict) = self.update_doc_result(did, &doc_type, result, &opts).await?;
            result = merged;
            // 提交后按存储中的最终状态重新裁决:另一方先提交的撤销 / 禁用同样约束本次报告。
            if report.is_valid() {
                let owner = self.owner_constraint_for(did, &result, &opts);
                apply_known_constraints(&mut report, &parsed, &result, &revision, owner.as_ref());
                if !report.is_valid() {
                    let trusted = report.is_signed;
                    report = report.finish(trusted);
                }
            }
            if let Some(conflict) = conflict {
                if conflict == doc_revision || result.find_verified(&doc_revision).is_none() {
                    report = report.invalid(format!(
                        "conflict: stored verified document already occupies iat {}",
                        doc_revision.iat
                    ));
                }
            }
        }
        result.set_selection_flags(&mut report, &doc_revision, &revision);
        Ok(report)
    }

    /// 验证缓存是否可复用:来源范围、owner / locker 依赖、目标查询的发布依据。
    fn reusable_for(
        &self,
        cached: &super::doc_result::Choice,
        result: &DocResult,
        revision: &Revision,
        opts: &ResolveOpts,
        did: &DID,
    ) -> bool {
        if !cached.is_valid() {
            return false;
        }
        if cached.report.locker_version != self.locker_version() && cached.report.publish_evidence.as_ref().map_or(false, |e| e.simulated) {
            return false;
        }
        if opts.force_authority_query {
            // 缺本轮匹配 receipt 的旧验证结果不能让本次权威查询短路。
            let has_receipt = opts
                .authority_receipts(did, &result.doc_type)
                .iter()
                .any(|r| r.answer.publish_info.as_ref().and_then(|i| i.latest_revision()) == Some(cached.revision.clone()));
            if !has_receipt {
                return false;
            }
        }
        if !revision.is_current() && result.slot_for(revision).is_none() {
            return false;
        }
        if let Some(owner) = self.owner_constraint_for(did, result, opts) {
            if let Some(used) = cached
                .report
                .dependencies
                .iter()
                .find(|d| d.role == DependencyRole::CurrentOwner)
            {
                if let Some(current) = owner.revision.as_ref() {
                    if *current != used.revision {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// 伪代码 `_verify_document_ex`。返回报告与合并后的发布信息。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_document_ex<'a>(
        &'a self,
        did: &'a DID,
        doc_type: &'a DidDocType,
        doc: &'a ParsedDocument,
        result: &'a mut DocResult,
        publish_info: Option<PublishInfo>,
        source: &'a SourceRef,
        revision: &'a Revision,
        opts: &'a ResolveOpts,
    ) -> BoxFut<'a, NSResult<(VerifyResult, Option<PublishInfo>)>> {
        erase(self.verify_document_ex_inner(did, doc_type, doc, result, publish_info, source, revision, opts))
    }

    pub(crate) async fn verify_document_ex_inner(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        doc: &ParsedDocument,
        result: &mut DocResult,
        publish_info: Option<PublishInfo>,
        source: &SourceRef,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<(VerifyResult, Option<PublishInfo>)> {
        let locker_version = self.locker_version();
        let mut report = VerifyResult::new(locker_version);
        report.doc_type = Some(doc_type.clone());
        report.requested_doc_type = result.requested_doc_type.clone();
        report.source_tier = Some(source.tier);
        report.source_id = Some(source.id.clone());
        if let Err(reason) = doc.matches(did, doc_type) {
            return Ok((report.invalid(reason), publish_info));
        }
        let doc_revision = doc.revision().cloned().expect("matches() guarantees iat");
        report.revision = Some(doc_revision.clone());

        // 公共状态 / owner 绑定可合并;hash 只能检查同 iat 的已发布记录。
        let mut publish_info = publish_info;
        let mut record = publish_info
            .as_ref()
            .and_then(|info| info.record_for(doc_revision.iat).cloned());
        if record.is_none() && !source.is_locker() {
            let exact = Revision::exact(doc_revision.iat, &doc_revision.hash);
            let version_info = self
                .get_publish_info(did, doc_type, &exact, opts, result)
                .await?;
            publish_info = PublishInfo::merge(publish_info, version_info);
            record = publish_info
                .as_ref()
                .and_then(|info| info.record_for(doc_revision.iat).cloned());
        }
        if let Some(record) = record.as_ref() {
            if record.published {
                if let Some(hash) = record.hash.as_ref() {
                    if !doc_revision.matches_hash(hash) {
                        return Ok((report.invalid("同 iat 的发布记录与文档 hash 不符"), publish_info));
                    }
                }
                report.is_published = true;
                if let Some(info) = publish_info.as_ref() {
                    report.publish_evidence = publish_evidence_for(info, &doc_revision);
                    if info.source.is_some() && !info.simulated {
                        report.authority_receipt = info.source.clone();
                    }
                }
            }
        }
        result.apply_publish_info(publish_info.as_ref());
        report.owner_binding = self.get_expected_owner(did, publish_info.as_ref(), result);
        let owner = self.owner_constraint_for(did, result, opts);
        apply_known_constraints(&mut report, doc, result, revision, owner.as_ref());
        if report.validity == Validity::Invalid {
            return Ok((report.finish(false), publish_info));
        }

        // owner 文档不能靠自己签名建立信任;核对 authority / locker 返回的确切根文档。
        if *doc_type == DidDocType::Owner {
            let (roots, _) = self.get_document(did, &DidDocType::Owner, revision, opts).await?;
            if !roots.contains_published_or_locked(&doc_revision, revision) {
                report.add_missing("缺少该 owner 文档的权威或 locker 依据");
                return Ok((report.finish(true), publish_info));
            }
            if let Some(choice) = roots.find_verified(&doc_revision) {
                report.publish_evidence = choice.report.publish_evidence.clone();
                report.is_published = choice.report.is_published;
                if choice.report.authority_receipt.is_some() {
                    report.authority_receipt = choice.report.authority_receipt.clone();
                }
            }
            return Ok((report.finish(true), publish_info));
        }

        if record.as_ref().map_or(false, |r| r.is_latest) && report.is_published {
            // 当前权威发布记录精确锚定输入,可按权威依据通过。
            return Ok((report.finish(true), publish_info));
        }
        if !source.need_verify() {
            // authority / trust 允许无签名 JSON;免验签仍检查身份、时间及本地已知负状态。
            return Ok((report.finish(true), publish_info));
        }
        if !doc.is_jwt() {
            return Ok((report.invalid("普通来源的文档需要 JWT 签名"), publish_info));
        }
        if doc.id.is_none() {
            return Ok((report.invalid("普通来源的文档缺少 id"), publish_info));
        }

        let Some(expected_owner) = self.get_expected_owner(did, publish_info.as_ref(), result) else {
            report.add_missing("缺少可信 owner 绑定");
            return Ok((report.finish(false), publish_info));
        };
        match doc.owner.as_ref() {
            Some(owner) if *owner == expected_owner => {}
            Some(owner) => {
                return Ok((
                    report.invalid(format!(
                        "owner 不匹配: declared {} expected {}",
                        owner.to_string(),
                        expected_owner.to_string()
                    )),
                    publish_info,
                ));
            }
            None => return Ok((report.invalid("文档未声明 owner"), publish_info)),
        }
        if expected_owner == *did {
            return Ok((report.invalid("普通文档不能以自己为 owner 自建信任"), publish_info));
        }

        let owner_opts = match opts.create_get_owner_opts(&expected_owner) {
            Ok(owner_opts) => owner_opts,
            Err(err) => {
                report.add_missing(format!("owner 递归不可用: {}", err));
                return Ok((report.finish(false), publish_info));
            }
        };
        let current_revision = Revision::current();
        // 签发时 owner = iat 不晚于文档签发时刻的最近已发布 owner;`closest` 是严格早于,
        // 所以边界取 `doc.iat + 1`(同一秒内激活并签发的设备文档也能命中当前 owner)。
        let signing_revision = Revision::closest(doc_revision.iat.saturating_add(1));
        let current = (self.resolve_did_ex(
            &expected_owner,
            Some(DidDocType::Owner),
            current_revision.clone(),
            owner_opts.clone(),
        ))
        .await?;
        let current_owner = current.select(&current_revision).cloned();
        // 第二次查询通常命中推导:current 来自 authority 且 current.iat < doc.iat。
        let historical = (self.resolve_did_ex(
            &expected_owner,
            Some(DidDocType::Owner),
            signing_revision.clone(),
            owner_opts,
        ))
        .await?;
        let signing_owner = historical.select(&signing_revision).cloned();

        match signing_owner.as_ref() {
            Some(signing_owner) => {
                let owner_doc = match OwnerDocument::decode(&signing_owner.doc, None) {
                    Ok(owner_doc) => owner_doc,
                    Err(err) => {
                        return Ok((
                            report.invalid(format!("签发时 owner 文档无法解析: {}", err)),
                            publish_info,
                        ));
                    }
                };
                let EncodedDocument::Jwt(jwt) = &doc.document else {
                    unreachable!("is_jwt() checked above");
                };
                if !verify_jwt_signature(jwt, &owner_doc) {
                    return Ok((report.invalid("签名错误"), publish_info));
                }
                report.is_signed = true;
                report.remember_dependency(
                    &expected_owner,
                    signing_owner.revision.clone(),
                    DependencyRole::SigningOwner,
                    signing_revision.clone(),
                    is_simulated(signing_owner),
                );
            }
            None => {
                report.add_missing(format!(
                    "签发时的 owner 文档:需要 closest 发布依据 ({})",
                    historical.reason()
                ));
            }
        }
        match current_owner.as_ref() {
            Some(current_owner) => {
                if let Ok(owner_doc) = OwnerDocument::decode(&current_owner.doc, None) {
                    if let Some(valid_iat) = owner_doc.valid_iat {
                        if doc_revision.iat <= valid_iat {
                            report.is_revoked = true;
                            report.add_reason(format!(
                                "iat {} is not after current owner valid_iat {}",
                                doc_revision.iat, valid_iat
                            ));
                        }
                    }
                }
                report.remember_dependency(
                    &expected_owner,
                    current_owner.revision.clone(),
                    DependencyRole::CurrentOwner,
                    current_revision,
                    is_simulated(current_owner),
                );
            }
            None if current.is_disabled() => {
                report.is_revoked = true;
                report.add_reason(format!("owner {} is disabled", expected_owner.to_string()));
            }
            None => {
                report.add_missing(format!(
                    "当前 owner 文档:无法判断当前撤销约束 ({})",
                    current.reason()
                ));
            }
        }
        let trusted = report.is_signed;
        Ok((report.finish(trusted), publish_info))
    }

    /// 可信 owner 绑定优先;BNS 无对象子路径的名字缺省取上级名字。其它 method
    /// 不能从候选自报字段选信任根。
    pub(crate) fn get_expected_owner(
        &self,
        did: &DID,
        publish_info: Option<&PublishInfo>,
        result: &DocResult,
    ) -> Option<DID> {
        if let Some(binding) = publish_info.and_then(|info| info.owner_binding.clone()) {
            return Some(binding);
        }
        if let Some(binding) = result.owner_binding.clone() {
            return Some(binding);
        }
        if let Some(binding) = result
            .publish_info
            .as_ref()
            .and_then(|info| info.owner_binding.clone())
        {
            return Some(binding);
        }
        structural_owner(did)
    }

    /// 投递候选(收件箱路径):只投递候选,不等于发布或成功选择。
    /// trust 只能由有权限的预装 / 配置入口指定(`SourceRef::configured_trust`)。
    pub async fn commit_candidate_doc(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        body: &EncodedDocument,
        source: SourceRef,
        opts: ResolveOpts,
    ) -> NSResult<()> {
        let opts = self.normalize_opts(opts);
        let parsed = ParsedDocument::parse(body).map_err(|err| {
            NSError::UnverifiedCacheWriteRejected(format!("document is not parsable: {}", err))
        })?;
        let doc_type = match doc_type {
            Some(doc_type) => doc_type,
            None => parsed
                .doc_type
                .clone()
                .unwrap_or(DidDocType::Zone),
        };
        parsed
            .matches(did, &doc_type)
            .map_err(NSError::UnverifiedCacheWriteRejected)?;
        let revision = parsed
            .revision()
            .cloned()
            .ok_or_else(|| NSError::UnverifiedCacheWriteRejected("document has no iat".to_string()))?;
        let source = match source.tier {
            SourceTier::Authority => {
                // 远端提交不能自称 authority。
                SourceRef::normal(source.id)
            }
            _ => source,
        };
        let mut result = {
            let _guard = self.serialize_document(did, &doc_type, &opts).await?;
            self.read_doc_result(did, &doc_type, &opts)
        };
        if result.find_verified(&revision).is_some() {
            return Ok(());
        }
        result.add_candidate(body.clone(), revision, source.clone());
        self.update_doc_result(did, &doc_type, result, &opts).await?;
        if self.use_disk_for(&opts) && source.tier == SourceTier::Normal {
            if let Err(err) = self.store.write_inbox(did, &doc_type, body, &source.id) {
                debug!("write inbox for {}#{} failed: {}", did.to_string(), doc_type, err);
            }
        }
        Ok(())
    }

    /// 删除普通文档 body;不隐式解锁,不抹掉已知禁用 / 撤销。
    pub async fn remove_doc_result(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        opts: ResolveOpts,
    ) -> NSResult<()> {
        let opts = self.normalize_opts(opts);
        let _guard = self.serialize_document(did, doc_type, &opts).await?;
        self.store
            .remove_document_bodies(&opts.scope, did, doc_type)?;
        self.info_cache.remove(did, doc_type);
        Ok(())
    }

    fn use_disk_for(&self, opts: &ResolveOpts) -> bool {
        opts.allow_local_cache() && self.config.enable_cache && self.store.is_persistent()
    }
}

/// 该选择是否由 locker 模拟发布提供。
fn is_simulated(choice: &super::doc_result::Choice) -> bool {
    choice
        .report
        .publish_evidence
        .as_ref()
        .map_or(false, |evidence| evidence.simulated)
}

/// 用签发时 owner 文档的全部 key(默认 + 历史)核验 JWT 签名。
pub fn verify_jwt_signature(jwt: &str, owner: &OwnerDocument) -> bool {
    if let Some((key, _)) = owner.get_auth_key(None) {
        if decode_json_from_jwt_with_pk(jwt, &key).is_ok() {
            return true;
        }
    }
    owner
        .get_historical_keys()
        .into_iter()
        .any(|(_, jwk)| match DecodingKey::from_jwk(&jwk) {
            Ok(key) => decode_json_from_jwt_with_pk(jwt, &key).is_ok(),
            Err(_) => false,
        })
}
