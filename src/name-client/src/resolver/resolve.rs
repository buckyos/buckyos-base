//! 获取与选择的主路径(设计稿 §3、§5;伪代码 `resolve_did_ex` / `_get_document` /
//! `get_publish_info` / `get_document_by_provider` / `request_source`)。
//!
//! 串行锁 `(scope, did, doc_type)` 只在"读缓存 / 刷新约束"与"验证后原子提交"两段
//! 内持有(TODO §5 R1);provider / locker I/O 与候选验证(含 Owner 递归)不持锁,
//! 跨请求去重由任务合并负责(键含访问策略)。

use super::budget::{erase, BoxFut, BudgetError};
use super::concurrency::Backoff;
use super::doc_result::{Choice, DocResult, OwnerConstraint};
use super::opts::{NetworkSources, ReceiptSet, ResolveOpts};
use super::publish_info::PublishInfo;
use super::revision::{is_key_class_method, DocRevision, ParsedDocument, Revision};
use super::source::{
    normalize_source_answer, DefaultDocType, Operation, RegisteredSource, Source, SourceAnswer,
    SourceRef, SourceTier,
};
use super::store::DocStore;
use super::verify_result::VerifyResult;
use super::zone_locker::ZoneLocker;
use crate::name_client::NameClient;
use super::clock::unix_now;
use log::warn;
use name_lib::{DIDDocumentTrait, DidDocType, EncodedDocument, NSError, NSResult, OwnerDocument, DID};
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

/// 进程内免验证 Info 缓存(设备 Info 等由 Zone 内共享,不走发布 / 验签)。
#[derive(Default)]
pub struct InfoCache {
    entries: std::sync::Mutex<std::collections::HashMap<(DID, String), (EncodedDocument, u64)>>,
}

impl InfoCache {
    pub fn get(&self, did: &DID, doc_type: &DidDocType) -> Option<(EncodedDocument, u64)> {
        let now = unix_now();
        let entries = self.entries.lock().unwrap();
        entries
            .get(&(did.clone(), doc_type.to_string()))
            .filter(|(_, exp)| *exp > now)
            .cloned()
    }

    pub fn insert(&self, did: &DID, doc_type: &DidDocType, doc: EncodedDocument, exp: u64) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() > 4096 {
            let now = unix_now();
            entries.retain(|_, (_, e)| *e > now);
        }
        entries.insert((did.clone(), doc_type.to_string()), (doc, exp));
    }

    pub fn remove(&self, did: &DID, doc_type: &DidDocType) {
        self.entries
            .lock()
            .unwrap()
            .remove(&(did.clone(), doc_type.to_string()));
    }
}

impl NameClient {
    pub fn locker_version(&self) -> u64 {
        self.local_locker.version()
    }

    pub(crate) fn zone_locker_snapshot(&self) -> Option<Arc<ZoneLocker>> {
        self.zone_locker.read().ok().and_then(|z| z.clone())
    }

    /// 便捷入口默认选项:本机 locker + Zone locker + 磁盘缓存 + 联网。
    pub fn default_resolve_opts(&self) -> ResolveOpts {
        let mut opts = ResolveOpts::default();
        if let Some(scope) = self.config.default_scope.clone() {
            opts.scope = scope;
        }
        opts
    }

    /// 最外层建立有限预算与新的 receipt 集合;单步超时与配置上限取小。
    pub(crate) fn normalize_opts(&self, opts: ResolveOpts) -> ResolveOpts {
        let opts = opts
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        let mut opts = opts.normalize(self.config.resolve_timeout);
        if opts.depth() == 0 {
            // 最外层调用(递归经 `descend` 时 depth > 0):本轮回答从新的一轮开始。
            opts.begin_receipt_round();
        }
        if !self.config.enable_cache {
            opts.allow_local_cache = false;
        }
        opts
    }

    fn use_disk(&self, opts: &ResolveOpts) -> bool {
        opts.allow_local_cache() && self.config.enable_cache && self.store.is_persistent()
    }

    fn lock_key(&self, did: &DID, doc_type: &DidDocType, opts: &ResolveOpts) -> String {
        DocStore::result_key(&opts.scope, did, doc_type)
    }

    pub(crate) async fn serialize_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        opts: &ResolveOpts,
    ) -> NSResult<OwnedMutexGuard<()>> {
        self.locks
            .lock(&self.lock_key(did, doc_type, opts), opts.budget())
            .await
    }

    // ---------- 入口 ----------

    /// `resolve_did_ex(did, doc_type, revision, opts) -> DocResult`。
    /// `doc_type = None` 按 method / provider 规则归一(TODO D4),发生在缓存键之前。
    pub fn resolve_did_ex<'a>(
        &'a self,
        did: &'a DID,
        doc_type: Option<DidDocType>,
        revision: Revision,
        opts: ResolveOpts,
    ) -> BoxFut<'a, NSResult<DocResult>> {
        erase(self.resolve_did_ex_inner(did, doc_type, revision, opts))
    }

        pub async fn resolve_did_ex_inner(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        revision: Revision,
        opts: ResolveOpts,
    ) -> NSResult<DocResult> {
        if is_key_class_method(&did.method) {
            return Err(NSError::InvalidDID(format!(
                "key-class DID {} is not a legal resolve_did input; keys only appear inside documents",
                did.to_string()
            )));
        }
        revision.validate()?;
        let opts = self.normalize_opts(opts);
        let requested = doc_type.clone();
        let (doc_type, type_reasons) = self.resolve_doc_type(did, doc_type, &opts).await?;
        let mut opts = opts;
        opts.mark_visited(did, &doc_type);

        if self.registry.is_no_proof_doc_type(&did.method, &doc_type) {
            let mut result = self.resolve_info(did, &doc_type, &revision, &opts).await?;
            result.requested_doc_type = requested;
            return Ok(result);
        }

        let (mut result, publish_info) = self.get_document(did, &doc_type, &revision, &opts).await?;
        result.requested_doc_type = requested;
        for reason in type_reasons {
            result.add_reason(reason);
        }
        if result.locked || result.is_disabled() {
            return Ok(result);
        }
        if doc_type == DidDocType::Owner
            || (!revision.is_current() && result.satisfies_published_target(&revision))
        {
            return Ok(result);
        }

        // 普通候选按 iat 从高到低验证;同 iat 的坏候选不阻止其它 hash 的合法候选。
        let mut publish_info = publish_info;
        let candidates = result.candidates_for(&revision, publish_info.as_ref());
        for candidate in candidates {
            opts.budget().check()?;
            let parsed = match ParsedDocument::parse(&candidate.doc) {
                Ok(parsed) => parsed,
                Err(err) => {
                    result.reject(candidate.revision.clone(), format!("unparsable candidate: {}", err));
                    continue;
                }
            };
            let source = candidate.primary_source();
            let (report, merged_info) = self
                .verify_document_ex(did, &doc_type, &parsed, &mut result, publish_info.clone(), &source, &revision, &opts)
                .await?;
            publish_info = merged_info;
            if !report.is_valid() && report.validity == super::verify_result::Validity::Unknown {
                if let Some(existing) = result
                    .candidates
                    .iter_mut()
                    .find(|c| c.revision == candidate.revision)
                {
                    existing.last_reason = Some(report.reason());
                }
                result.add_reason(format!("candidate {}: {}", candidate.revision, report.reason()));
                continue;
            }
            result.remove_candidate(&candidate.revision);
            if !report.is_valid() {
                result.add_reason(format!("candidate {}: {}", candidate.revision, report.reason()));
                if report.is_revoked || report.is_disabled || report.conflict.is_some() {
                    result.reject(candidate.revision.clone(), report.reason());
                }
                continue;
            }
            let accepted = result.accept_verified(candidate.doc.clone(), source, report, &revision);
            if !accepted.is_valid() {
                result.add_reason(format!("candidate {}: {}", candidate.revision, accepted.reason()));
                continue;
            }
            if revision.is_current() && result.best.is_some() {
                break;
            }
            if !revision.is_current() && result.satisfies_published_target(&revision) {
                break;
            }
        }

        if revision.is_current() && result.best.as_ref().map_or(false, Choice::is_valid) {
            // 以本机低成本使用为目标:选出 best 后可清空候选。
            result.clear_candidates();
        }
        let (merged, conflict) = self.update_doc_result(did, &doc_type, result, &opts).await?;
        let mut merged = merged;
        if let Some(conflict) = conflict {
            merged.add_reason(format!("conflict with stored version at iat {}", conflict.iat));
        }
        Ok(merged)
    }

    /// 便捷入口:current 下 owner 选择 latest,普通文档选择 best。
    pub async fn resolve_did(&self, did: &DID, doc_type: Option<DidDocType>) -> NSResult<EncodedDocument> {
        self.resolve_did_revision(did, doc_type, Revision::current()).await
    }

    /// 指定查询只返回目标,不能退回 best。
    pub async fn resolve_did_revision(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        revision: Revision,
    ) -> NSResult<EncodedDocument> {
        let result = self
            .resolve_did_ex(did, doc_type, revision.clone(), self.default_resolve_opts())
            .await?;
        select_or_error(&result, &revision)
    }

    /// `doc_type = None` 的归一(TODO D4):路径型对象 → `did-object`;其余由该
    /// method 的 authority 决定;无法确定时按旧默认 `zone` 并把 warn 写入 reasons。
    pub async fn resolve_doc_type(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        opts: &ResolveOpts,
    ) -> NSResult<(DidDocType, Vec<String>)> {
        if let Some(doc_type) = doc_type {
            return Ok((doc_type, Vec::new()));
        }
        if did.id.contains(':') {
            return Ok((DidDocType::DidObject, Vec::new()));
        }
        if let Some(authority) = self.registry.authority(&did.method) {
            opts.budget().check()?;
            match authority.source.default_doc_type(did, opts).await {
                Some(DefaultDocType::Known { doc_type, reasons }) => return Ok((doc_type, reasons)),
                Some(DefaultDocType::Ambiguous(reason)) => {
                    return Err(NSError::InvalidParam(format!(
                        "ambiguous default doc_type for {}: {}",
                        did.to_string(),
                        reason
                    )));
                }
                None => {}
            }
        }
        Ok((
            DidDocType::Zone,
            vec![format!(
                "doc_type not specified for {}; defaulted to zone",
                did.to_string()
            )],
        ))
    }

    // ---------- Info(免验证,Zone 内共享) ----------

    async fn resolve_info(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<DocResult> {
        if let Some(locked) = self.get_locked_document(did, doc_type, revision, opts).await? {
            return Ok(locked);
        }
        let mut result = DocResult::empty(opts.scope.clone(), did.clone(), doc_type.clone());
        if let Some((doc, exp)) = self.info_cache.get(did, doc_type) {
            let mut report = VerifyResult::new(self.locker_version());
            report.revision = DocRevision::of(&doc);
            report.doc_type = Some(doc_type.clone());
            report.source_tier = Some(SourceTier::Trust);
            report.source_id = Some("info-cache".to_string());
            let report = report.finish(true);
            let mut source = SourceRef::configured_trust("info-cache");
            source.kind = super::source::SourceKind::Inbox;
            let _ = exp;
            result.accept_verified(doc, source, report, revision);
        } else {
            result.add_reason(format!(
                "info document {}#{} is not available from lockers or the info cache",
                did.to_string(),
                doc_type
            ));
        }
        Ok(result)
    }

    // ---------- 获取 ----------

    /// 伪代码 `_get_document`。
    pub(crate) fn get_document<'a>(
        &'a self,
        did: &'a DID,
        doc_type: &'a DidDocType,
        revision: &'a Revision,
        opts: &'a ResolveOpts,
    ) -> BoxFut<'a, NSResult<(DocResult, Option<PublishInfo>)>> {
        erase(self.get_document_inner(did, doc_type, revision, opts))
    }

    pub(crate) async fn get_document_inner(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<(DocResult, Option<PublishInfo>)> {
        if let Some(locked) = self.get_locked_document(did, doc_type, revision, opts).await? {
            let info = locked_publish_info(&locked);
            return Ok((locked, info));
        }

        // 段 1:只包读缓存与刷新约束,不包任何 I/O。
        let mut result = {
            let _guard = self.serialize_document(did, doc_type, opts).await?;
            let mut result = self.read_doc_result(did, doc_type, opts);
            let owner = self.owner_constraint_for(did, &result, opts);
            result.refresh_known_constraints(self.locker_version(), owner.as_ref());
            result
        };

        let mut publish_info = self.get_publish_info(did, doc_type, revision, opts, &result).await?;
        if publish_info.as_ref().map_or(false, |info| info.simulated) {
            // locker 的模拟发布事实只用于本次选择,不写入普通来源缓存。
            result.locked = true;
        }
        result.apply_publish_info(publish_info.as_ref());
        result.fill_latest_from_known(publish_info.as_ref());
        result.fill_slot_from_known(revision, publish_info.as_ref());
        if result.is_disabled() {
            // 本轮发布信息带来的禁用 / 撤销同样撤掉已有选择资格,否则旧 best 会被 select 返回。
            let owner = self.owner_constraint_for(did, &result, opts);
            result.refresh_known_constraints(self.locker_version(), owner.as_ref());
            let (merged, _) = self.update_doc_result(did, doc_type, result, opts).await?;
            return Ok((merged, publish_info));
        }

        // owner / exact / closest 的发布目标已由本轮(或推导出的)发布依据满足:
        // 不再发任何来源请求(设计稿 §1:closest 由 current 推出时第二次查询不联网)。
        if (*doc_type == DidDocType::Owner || !revision.is_current())
            && result.satisfies_published_target(revision)
        {
            let (merged, _) = self.update_doc_result(did, doc_type, result, opts).await?;
            return Ok((merged, publish_info));
        }
        let providers = self.registry.providers_for(did, doc_type, opts);
        if providers.is_empty() && self.registry.authority(&did.method).is_none() {
            result.add_reason(format!("no source registered for DID method {}", did.method));
        }
        let owner = self.owner_constraint_for(did, &result, opts);
        let mut providers = providers.into_iter();
        while let Some(provider) = providers.next() {
            opts.budget().check()?;
            let answer = self
                .get_document_by_provider(&provider, did, doc_type, revision, opts)
                .await?;
            result.commit(&answer, revision, self.locker_version(), owner.as_ref());
            if provider.is_authority() {
                publish_info = PublishInfo::merge(publish_info, answer.publish_info.clone());
                result.fill_latest_from_known(answer.publish_info.as_ref());
                result.fill_slot_from_known(revision, publish_info.as_ref());
            }
            if result.is_disabled() {
                break;
            }
            if (*doc_type == DidDocType::Owner || !revision.is_current())
                && result.satisfies_published_target(revision)
            {
                break;
            }
            if provider.is_authority() && revision.is_current() && authority_body_is_best(&result, &answer) {
                let rest: Vec<RegisteredSource> = providers.by_ref().collect();
                for answer in self.collect_supplements(&rest, did, doc_type, revision, opts).await? {
                    result.commit(&answer, revision, self.locker_version(), owner.as_ref());
                }
                break;
            }
        }

        let owner = self.owner_constraint_for(did, &result, opts);
        result.refresh_known_constraints(self.locker_version(), owner.as_ref());
        let (merged, _) = self.update_doc_result(did, doc_type, result, opts).await?;
        Ok((merged, publish_info))
    }

    /// 读取结果快照并并入收件箱候选。
    pub(crate) fn read_doc_result(&self, did: &DID, doc_type: &DidDocType, opts: &ResolveOpts) -> DocResult {
        let use_disk = self.use_disk(opts);
        let mut result = self
            .store
            .get_doc_result(&opts.scope, did, doc_type, use_disk)
            .unwrap_or_else(|| DocResult::empty(opts.scope.clone(), did.clone(), doc_type.clone()));
        result.mark_base_generation();
        result.reasons.clear();
        if let Some(did_level) = self
            .store
            .get_doc_result(&opts.scope, did, &did_state_doc_type(), use_disk)
        {
            result.adopt_did_state(&did_level);
        }
        if use_disk {
            for inbox in self.store.collect_inbox(did, doc_type) {
                if let Some(revision) = DocRevision::of(&inbox.document) {
                    if result.find_verified(&revision).is_none() {
                        result.add_candidate(inbox.document, revision, SourceRef::normal(inbox.source));
                    }
                }
            }
        }
        result
    }

    /// 段 2:在串行锁内重读存储中的最新结果,再把本地快照按同键原子合并。
    pub(crate) async fn update_doc_result(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        result: DocResult,
        opts: &ResolveOpts,
    ) -> NSResult<(DocResult, Option<DocRevision>)> {
        if result.locked {
            return Ok((result, None));
        }
        let _guard = self.serialize_document(did, doc_type, opts).await?;
        let use_disk = self.use_disk(opts);
        let store = self.store.clone();
        let scope = opts.scope.clone();
        let did = did.clone();
        let doc_type = doc_type.clone();
        if use_disk {
            opts.budget()
                .wait(tokio::task::spawn_blocking(move || {
                    let merged = store.merge_doc_result(&scope, &did, &doc_type, result, true)?;
                    sync_did_state(&store, &scope, &did, &merged.0, true)?;
                    Ok(merged)
                }))
                .await?
                .map_err(|err| NSError::Failed(format!("merge task failed: {}", err)))?
        } else {
            let merged = store.merge_doc_result(&scope, &did, &doc_type, result, false)?;
            sync_did_state(&store, &scope, &did, &merged.0, false)?;
            Ok(merged)
        }
    }

    /// 当前 owner 的已知约束:只按可信绑定 / 名字结构定位,只读取本机已有材料。
    pub(crate) fn owner_constraint_for(
        &self,
        did: &DID,
        result: &DocResult,
        opts: &ResolveOpts,
    ) -> Option<OwnerConstraint> {
        if result.doc_type == DidDocType::Owner {
            return None;
        }
        let owner = self.get_expected_owner(did, result.publish_info.as_ref(), result)?;
        if owner == *did {
            return None;
        }
        let owner_result = if opts.allow_local_lock() {
            self.local_locker
                .get_document(&owner, &DidDocType::Owner, &Revision::current())
                .and_then(|answer| {
                    DocResult::locked_from(
                        &answer,
                        opts.scope.clone(),
                        &owner,
                        &DidDocType::Owner,
                        &Revision::current(),
                        self.locker_version(),
                    )
                })
        } else {
            None
        }
        .or_else(|| {
            self.store
                .get_doc_result(&opts.scope, &owner, &DidDocType::Owner, self.use_disk(opts))
        })?;
        let mut constraint = OwnerConstraint {
            disabled: owner_result.is_disabled(),
            valid_iat: None,
            revision: None,
        };
        if let Some(latest) = owner_result.select(&Revision::current()) {
            constraint.revision = Some(latest.revision.clone());
            if let Ok(owner_doc) = OwnerDocument::decode(&latest.doc, None) {
                constraint.valid_iat = owner_doc.valid_iat;
            }
        }
        Some(constraint)
    }

    // ---------- locker ----------

    /// 本机 locker > Zone locker。Unknown / 未覆盖归一为 None;明确不存在 / 禁用
    /// 是强制回答。
    pub(crate) fn get_locked_document<'a>(
        &'a self,
        did: &'a DID,
        doc_type: &'a DidDocType,
        revision: &'a Revision,
        opts: &'a ResolveOpts,
    ) -> BoxFut<'a, NSResult<Option<DocResult>>> {
        erase(self.get_locked_document_inner(did, doc_type, revision, opts))
    }

    pub(crate) async fn get_locked_document_inner(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<Option<DocResult>> {
        opts.budget().check()?;
        let locker_version = self.locker_version();
        if opts.allow_local_lock() {
            if let Some(answer) = self.local_locker.get_document(did, doc_type, revision) {
                if let Some(result) = DocResult::locked_from(
                    &answer,
                    opts.scope.clone(),
                    did,
                    doc_type,
                    revision,
                    locker_version,
                ) {
                    return Ok(Some(result));
                }
            }
        }
        if opts.allow_zone_lock() {
            if let Some(zone) = self.zone_locker_snapshot() {
                let sref = zone.source_ref();
                let answer = self
                    .request_source(zone.clone(), &sref, Operation::Document, did, doc_type, revision, opts)
                    .await?;
                if !answer.is_unknown() {
                    if let Some(result) = DocResult::locked_from(
                        &answer,
                        opts.scope.clone(),
                        did,
                        doc_type,
                        revision,
                        locker_version,
                    ) {
                        return Ok(Some(result));
                    }
                }
            }
        }
        Ok(None)
    }

    // ---------- 发布信息 ----------

    /// 只返回本次所问版本的信息;locker 对 body / publish_info 分别回答,缺席的列
    /// 继续查。exact / closest 可由本轮或缓存中的 authority current 回答推导。
    pub(crate) fn get_publish_info<'a>(
        &'a self,
        did: &'a DID,
        doc_type: &'a DidDocType,
        revision: &'a Revision,
        opts: &'a ResolveOpts,
        result: &'a DocResult,
    ) -> BoxFut<'a, NSResult<Option<PublishInfo>>> {
        erase(self.get_publish_info_inner(did, doc_type, revision, opts, result))
    }

    pub(crate) async fn get_publish_info_inner(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
        result: &DocResult,
    ) -> NSResult<Option<PublishInfo>> {
        opts.budget().check()?;
        if opts.allow_local_lock() {
            if let Some(info) = self.local_locker.get_publish_info(did, doc_type, revision) {
                return Ok(Some(info));
            }
        }
        if opts.allow_zone_lock() {
            if let Some(zone) = self.zone_locker_snapshot() {
                let sref = zone.source_ref();
                let answer = self
                    .request_source(zone.clone(), &sref, Operation::PublishInfo, did, doc_type, revision, opts)
                    .await?;
                if answer.publish_info.is_some() {
                    return Ok(answer.publish_info);
                }
            }
        }
        let authority = self.registry.authority(&did.method);

        // 推导:本轮或缓存里的 authority current 回答。
        if !revision.is_current() {
            if let Some(authority) = authority.as_ref() {
                if let Some(current) = opts.reusable_query_answer(
                    &authority.sref,
                    did,
                    doc_type,
                    &Revision::current().cache_key(),
                    Operation::PublishInfo,
                ) {
                    if let Some(derived) = current.publish_info.as_ref().and_then(|c| c.derive_for(revision)) {
                        return Ok(Some(derived));
                    }
                }
            }
            if !opts.force_authority_query {
                if let Some(current) = result.publish_info_fresh(unix_now()) {
                    if !current.simulated || opts.allow_local_lock() || opts.allow_zone_lock() {
                        if let Some(derived) = current.derive_for(revision) {
                            return Ok(Some(derived));
                        }
                    }
                }
            }
        }

        let Some(authority) = authority else {
            return Ok(None);
        };
        if !revision.is_current() && !authority.source.supports_publish_info() {
            return Ok(None);
        }
        let answer = self
            .get_document_by_provider(&authority, did, doc_type, revision, opts)
            .await?;
        Ok(answer.publish_info)
    }

    /// authority 本轮已给出有效 best:其余来源并发查询,只在宽限期内收集,按注册顺序
    /// 返回。宽限期到期或单个来源出错按该来源 Unknown 处理(不退避);总预算耗尽 /
    /// 取消照常向外抛。
    async fn collect_supplements(
        &self,
        providers: &[RegisteredSource],
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<Vec<SourceAnswer>> {
        let grace_opts = opts
            .clone()
            .with_budget(opts.budget().child(self.config.supplement_grace));
        let answers = futures::future::join_all(
            providers
                .iter()
                .map(|provider| self.get_document_by_provider(provider, did, doc_type, revision, &grace_opts)),
        )
        .await;
        opts.budget().check()?;
        Ok(providers
            .iter()
            .zip(answers)
            .map(|(provider, answer)| {
                answer.unwrap_or_else(|err| {
                    let reason = format!(
                        "{}: not answered within the supplement grace after the authority answer: {}",
                        provider.sref.id, err
                    );
                    opts.record_unanswered(&provider.sref, Operation::Document, reason.clone());
                    SourceAnswer::unknown(provider.sref.clone(), reason, false)
                })
            })
            .collect())
    }

    // ---------- provider 查询 ----------

    /// 伪代码 `get_document_by_provider`:本轮回答复用 → 查询缓存 → 任务合并。
    pub(crate) fn get_document_by_provider<'a>(
        &'a self,
        provider: &'a RegisteredSource,
        did: &'a DID,
        doc_type: &'a DidDocType,
        revision: &'a Revision,
        opts: &'a ResolveOpts,
    ) -> BoxFut<'a, NSResult<SourceAnswer>> {
        erase(self.get_document_by_provider_inner(provider, did, doc_type, revision, opts))
    }

    pub(crate) async fn get_document_by_provider_inner(
        &self,
        provider: &RegisteredSource,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<SourceAnswer> {
        opts.budget().check()?;
        let sref = &provider.sref;
        if let Some(current) =
            opts.reusable_query_answer(sref, did, doc_type, &revision.cache_key(), Operation::Document)
        {
            return Ok(current);
        }
        let key = format!(
            "{}|{}|{}|{}|{}",
            opts.scope.key(),
            sref.id,
            did.to_string(),
            doc_type.as_str(),
            revision.cache_key()
        );
        let force_query = sref.is_authority() && opts.force_authority_query;
        if !force_query {
            if let Some(cached) = self.store.get_query_answer(&key) {
                return Ok(cached);
            }
        }
        if !revision.is_current() && !provider.source.supports_publish_info() {
            return Ok(SourceAnswer::unknown(
                sref.clone(),
                "此来源不支持指定版本/closest 查询",
                false,
            ));
        }
        // 门禁在合并之前:策略拒绝不加入任何任务。
        if let Some(refused) = self.gate(sref, Operation::Document, opts) {
            return Ok(refused);
        }
        let backoff_key = Backoff::key(&sref.id, &format!("{}#{}", did.to_string(), doc_type), &opts.access_policy_key());
        if let Some(remaining) = self.backoff.should_skip(&backoff_key) {
            let reason = format!(
                "{} is backing off for {}ms after a recent failure",
                sref.id,
                remaining.as_millis()
            );
            opts.record_unanswered(sref, Operation::Document, reason.clone());
            return Ok(SourceAnswer::unknown(sref.clone(), reason, false));
        }

        let merge_key = format!("{}|{}", key, opts.access_policy_key());
        let source = provider.source.clone();
        let task_sref = sref.clone();
        let task_did = did.clone();
        let task_doc_type = doc_type.clone();
        let task_revision = revision.clone();
        let task_opts = opts.clone();
        let answer = self
            .merger
            .merge_or_run(merge_key, opts, move |budget| {
                erase(async move {
                    let task_opts = task_opts.with_budget(budget);
                    query_source(source, &task_sref, Operation::Document, &task_did, &task_doc_type, &task_revision, &task_opts).await
                })
            })
            .await?;
        opts.budget().check()?;
        opts.record_query_answer(sref, did, doc_type, &revision.cache_key(), &answer);
        if answer.failure {
            self.backoff.record_failure(backoff_key.clone());
            if self.throttle.should_log(&backoff_key) {
                warn!(
                    "source {} failed for {}#{} {}: {}",
                    sref.id,
                    did.to_string(),
                    doc_type,
                    revision,
                    answer.reason_text()
                );
            }
        } else if !answer.is_unknown() {
            self.backoff.record_success(&backoff_key);
        }
        if answer.cacheable {
            self.store
                .set_query_answer(key, answer.clone(), answer.cache_ttl_secs());
        }
        Ok(answer)
    }

    /// 来源与传输门禁(伪代码 `request_source` 的前半段)。
    fn gate(&self, sref: &SourceRef, operation: Operation, opts: &ResolveOpts) -> Option<SourceAnswer> {
        let allowed = if sref.is_zone_locker() {
            opts.allow_zone_lock()
        } else if sref.is_locker() {
            opts.allow_local_lock()
        } else {
            opts.allow_request()
                && (opts.network_sources == NetworkSources::All || sref.is_authority())
        };
        if !allowed || !opts.transport_policy.permits(sref) {
            let reason = if !allowed {
                format!("本次请求的来源策略不允许访问 {}", sref.id)
            } else {
                format!("本次请求的传输策略不允许访问 {}", sref.id)
            };
            opts.record_unanswered(sref, operation, reason.clone());
            return Some(SourceAnswer::unknown(sref.clone(), reason, false));
        }
        None
    }

    /// 伪代码 `request_source`:门禁 + 预算内查询 + 归一。locker 请求传
    /// `without_zone_lock()`(防自选)。
    pub(crate) async fn request_source(
        &self,
        source: Arc<dyn Source>,
        sref: &SourceRef,
        operation: Operation,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> NSResult<SourceAnswer> {
        opts.budget().check()?;
        if let Some(refused) = self.gate(sref, operation, opts) {
            return Ok(refused);
        }
        if let Some(reused) =
            opts.reusable_query_answer(sref, did, doc_type, &revision.cache_key(), operation)
        {
            return Ok(reused);
        }
        let request_opts = if sref.is_zone_locker() {
            opts.clone().without_zone_lock()
        } else {
            opts.clone()
        };
        let answer = query_source(source, sref, operation, did, doc_type, revision, &request_opts).await;
        opts.budget().check()?;
        if !sref.is_locker() {
            opts.record_query_answer(sref, did, doc_type, &revision.cache_key(), &answer);
        }
        Ok(answer)
    }
}

/// 在预算内执行一次来源查询并归一。单个来源超时返回 Unknown(failure);总预算
/// 耗尽由调用方 `budget.check()` 向外抛。
async fn query_source(
    source: Arc<dyn Source>,
    sref: &SourceRef,
    operation: Operation,
    did: &DID,
    doc_type: &DidDocType,
    revision: &Revision,
    opts: &ResolveOpts,
) -> SourceAnswer {
    let budget = opts.budget();
    let cap = budget.step_cap(opts.request_timeout);
    let run = async {
        match operation {
            Operation::Document => source.get_document(did, doc_type, revision, opts).await,
            Operation::PublishInfo => source.get_publish_info(did, doc_type, revision, opts).await,
        }
    };
    match budget.run(cap, run).await {
        Ok(raw) => normalize_source_answer(raw, sref, did, doc_type, revision),
        Err(BudgetError::Timeout(timeout)) => {
            let reason = format!("{}: {}", sref.id, timeout);
            opts.record_unanswered(sref, operation, reason.clone());
            SourceAnswer::failure(sref.clone(), reason)
        }
        Err(BudgetError::Terminated(err)) => {
            opts.record_unanswered(sref, operation, err.to_string());
            SourceAnswer::unknown(sref.clone(), err.to_string(), false)
        }
    }
}

/// 本轮 authority 回答的文档已验证并成为 best。
fn authority_body_is_best(result: &DocResult, answer: &SourceAnswer) -> bool {
    let Some(revision) = answer.body.as_ref().and_then(DocRevision::of) else {
        return false;
    };
    result
        .best
        .as_ref()
        .map_or(false, |best| best.is_valid() && best.revision == revision)
}

/// DID 级状态记录的伪类型:与各 doc_type 结果同 scope 存放。
pub(crate) fn did_state_doc_type() -> DidDocType {
    DidDocType::custom("did-state")
}

/// 把结果里更新的 DID 级状态写入 DID 级记录(按检查时刻裁决,见 `DocResult::merge_into`)。
fn sync_did_state(
    store: &DocStore,
    scope: &super::opts::Scope,
    did: &DID,
    merged: &DocResult,
    use_disk: bool,
) -> NSResult<()> {
    if merged.did_state_checked_at.is_none() || merged.doc_type == did_state_doc_type() {
        return Ok(());
    }
    let known = store
        .get_doc_result(scope, did, &did_state_doc_type(), use_disk)
        .and_then(|record| record.did_state_checked_at);
    if known >= merged.did_state_checked_at {
        return Ok(());
    }
    let mut record = DocResult::empty(scope.clone(), did.clone(), did_state_doc_type());
    record.did_state = merged.did_state.clone();
    record.did_state_checked_at = merged.did_state_checked_at;
    store
        .merge_doc_result(scope, did, &did_state_doc_type(), record, use_disk)
        .map(|_| ())
}

fn locked_publish_info(locked: &DocResult) -> Option<PublishInfo> {
    locked.publish_info.clone()
}

/// 把 `DocResult` 的选择结果折叠成便捷入口的 `NSResult<EncodedDocument>`。
pub fn select_or_error(result: &DocResult, revision: &Revision) -> NSResult<EncodedDocument> {
    if let Some(choice) = result.select(revision) {
        return Ok(choice.doc.clone());
    }
    if let Some(reason) = result.disabled_reason() {
        return Err(NSError::Disabled(reason));
    }
    Err(NSError::NotFound(format!(
        "{}#{} ({}) : {}",
        result.did.to_string(),
        result.doc_type,
        revision,
        result.reason()
    )))
}

/// RTCP `AuthorityCurrent` 门禁:只接受本轮真实 authority receipt 精确绑定的有效
/// 文档。模拟发布、旧 receipt、旧 latest、仅 trust best 或更高缓存 best 都不满足。
pub fn select_authority_current(result: &DocResult, receipts: &ReceiptSet) -> Option<Choice> {
    for receipt in receipts.authority_receipts(&result.did, &result.doc_type) {
        if receipt.revision_key != Revision::current().cache_key() {
            continue;
        }
        let Some(info) = receipt.answer.publish_info.as_ref() else {
            continue;
        };
        if info.simulated {
            continue;
        }
        let Some(latest) = info.latest_revision() else {
            continue;
        };
        if let Some(choice) = result.find_verified(&latest) {
            if choice.is_valid() {
                return Some(choice.clone());
            }
        }
        // receipt 带 body 时,body 本身也可以按精确 hash 使用(需已验证)。
        if let Some(body) = receipt.answer.body.as_ref() {
            if let Some(rev) = DocRevision::of(body) {
                if rev == latest {
                    if let Some(choice) = result.find_verified(&rev) {
                        if choice.is_valid() {
                            return Some(choice.clone());
                        }
                    }
                }
            }
        }
    }
    None
}
