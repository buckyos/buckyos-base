//! 结果模型(设计稿 §2.2、§5、§7):`DocResult` 按 `(scope, did, doc_type)` 保存,
//! latest / best / 历史记录保留来源、原查询和验证结果;候选按 `(iat, hash)` 保存;
//! exact / closest 按完整查询分槽。

use super::opts::Scope;
use super::publish_info::{DidState, PublishInfo, TypeState};
use super::revision::{DocRevision, ParsedDocument, Revision};
use super::source::{Carrier, SourceAnswer, SourceRef, SourceTier};
use super::verify_result::{DependencyRole, PublishEvidence, Validity, VerifyResult};
use super::clock::unix_now;
use name_lib::{DidDocType, EncodedDocument, DID};
use serde::{Deserialize, Serialize};

/// 已验证的选择项。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Choice {
    pub doc: EncodedDocument,
    pub revision: DocRevision,
    pub source: SourceRef,
    pub query: Revision,
    pub report: VerifyResult,
    pub obtained_at: u64,
    #[serde(default)]
    pub exp: Option<u64>,
}

impl Choice {
    pub fn is_valid(&self) -> bool {
        self.report.is_valid()
    }
}

/// 待验候选。多个来源的相同文档合并来源,不覆盖其它 hash。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub doc: EncodedDocument,
    pub revision: DocRevision,
    pub sources: Vec<SourceRef>,
    pub added_at: u64,
    #[serde(default)]
    pub last_reason: Option<String>,
}

impl Candidate {
    /// 候选的最高来源等级(authority > trust > normal)决定验证路径。
    pub fn tier(&self) -> SourceTier {
        let mut best = SourceTier::Normal;
        for source in &self.sources {
            match source.tier {
                SourceTier::Authority => return SourceTier::Authority,
                SourceTier::Trust => best = SourceTier::Trust,
                SourceTier::Normal => {}
            }
        }
        best
    }

    pub fn primary_source(&self) -> SourceRef {
        let tier = self.tier();
        self.sources
            .iter()
            .find(|s| s.tier == tier)
            .cloned()
            .unwrap_or_else(|| SourceRef::normal("unknown"))
    }
}

/// exact / closest 查询槽:必须保留该查询依据;只有 body 或普通 valid 报告不足以填槽。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Slot {
    pub query: Revision,
    /// None:closest 确认查询边界之前没有已发布版本。
    pub revision: Option<DocRevision>,
    pub evidence: PublishEvidence,
    pub valid_until: u64,
}

/// 确定拒绝过的版本(撤销、hash 不符、签名错误),不重复验证。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rejected {
    pub revision: DocRevision,
    pub reason: String,
    pub at: u64,
}

/// 当前 owner 的已知约束(只读取本机已有材料,不隐含网络请求)。
#[derive(Debug, Clone, Default)]
pub struct OwnerConstraint {
    pub disabled: bool,
    pub valid_iat: Option<u64>,
    pub revision: Option<DocRevision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocResult {
    pub scope: Scope,
    pub did: DID,
    pub doc_type: DidDocType,
    #[serde(default)]
    pub requested_doc_type: Option<DidDocType>,
    #[serde(default)]
    pub did_state: Option<DidState>,
    #[serde(default)]
    pub type_state: Option<TypeState>,
    #[serde(default)]
    pub state_source: Option<String>,
    #[serde(default)]
    pub state_valid_until: Option<u64>,
    /// 当前状态(did_state / type_state)所依据回答的检查时刻;跨进程合并时较新的一方胜出,
    /// 基于旧快照的本地结果不能覆盖存储中更新的状态。
    #[serde(default)]
    pub state_checked_at: Option<u64>,
    /// DID 级状态所依据回答的检查时刻:DID 级状态覆盖该 DID 的全部类型,各类型结果与 DID 级
    /// 记录之间按它同步。
    #[serde(default)]
    pub did_state_checked_at: Option<u64>,
    #[serde(default)]
    pub owner_binding: Option<DID>,
    #[serde(default)]
    pub latest: Option<Choice>,
    #[serde(default)]
    pub best: Option<Choice>,
    #[serde(default)]
    pub history: Vec<Choice>,
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub slots: Vec<Slot>,
    #[serde(default)]
    pub rejected: Vec<Rejected>,
    /// 最近合并的 authority 发布信息(current 查询),与 `valid_until` 一起缓存。
    #[serde(default)]
    pub publish_info: Option<PublishInfo>,
    #[serde(default)]
    pub publish_info_valid_until: Option<u64>,
    /// locker 回答:不写入普通来源缓存。
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub locker_version: u64,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub generation: u64,
    /// 本地快照读取时存储中的 generation(不落盘):提交时若存储未变,整体替换;
    /// 否则按同键原子合并。
    #[serde(skip)]
    pub base_generation: u64,
}

impl DocResult {
    pub fn empty(scope: Scope, did: DID, doc_type: DidDocType) -> Self {
        Self {
            scope,
            did,
            doc_type,
            requested_doc_type: None,
            did_state: None,
            type_state: None,
            state_source: None,
            state_valid_until: None,
            state_checked_at: None,
            did_state_checked_at: None,
            owner_binding: None,
            latest: None,
            best: None,
            history: Vec::new(),
            candidates: Vec::new(),
            slots: Vec::new(),
            rejected: Vec::new(),
            publish_info: None,
            publish_info_valid_until: None,
            locked: false,
            locker_version: 0,
            reasons: Vec::new(),
            updated_at: unix_now(),
            generation: 0,
            base_generation: 0,
        }
    }

    /// 采用 DID 级记录中更新的 DID 级状态(DID 级状态覆盖该 DID 的全部类型)。
    pub fn adopt_did_state(&mut self, did_level: &DocResult) {
        if did_level.did_state_checked_at > self.did_state_checked_at {
            self.did_state = did_level.did_state.clone();
            self.did_state_checked_at = did_level.did_state_checked_at;
        }
    }

    /// 标记"本快照基于存储的这一代"。
    pub fn mark_base_generation(&mut self) {
        self.base_generation = self.generation;
    }

    pub fn is_owner(&self) -> bool {
        self.doc_type == DidDocType::Owner
    }

    pub fn is_disabled(&self) -> bool {
        self.did_state.as_ref().map_or(false, DidState::is_disabled)
            || self.type_state.as_ref().map_or(false, TypeState::is_disabled)
    }

    pub fn disabled_reason(&self) -> Option<String> {
        match (&self.did_state, &self.type_state) {
            (Some(DidState::Tombstoned), _) => Some(format!("{} is tombstoned", self.did.to_string())),
            (Some(DidState::Migrated { target }), _) => Some(format!(
                "{} is migrated{}",
                self.did.to_string(),
                target
                    .as_ref()
                    .map(|t| format!(" to {}", t.to_string()))
                    .unwrap_or_default()
            )),
            (_, Some(TypeState::Revoked)) => Some(format!(
                "{}#{} is revoked",
                self.did.to_string(),
                self.doc_type
            )),
            _ => None,
        }
    }

    /// 该类型在 authority 看来不存在(missing / invalid):不是禁用,但没有 latest。
    pub fn is_not_exist(&self) -> bool {
        self.type_state.as_ref().map_or(false, TypeState::is_not_exist)
    }

    pub fn add_reason(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    /// 人可读的整体原因(选择失败时返回给调用方)。
    pub fn reason(&self) -> String {
        if let Some(reason) = self.disabled_reason() {
            return reason;
        }
        if self.reasons.is_empty() {
            format!("{}#{} has no usable document", self.did.to_string(), self.doc_type)
        } else {
            self.reasons.join("; ")
        }
    }

    pub fn migration_target(&self) -> Option<DID> {
        match &self.did_state {
            Some(DidState::Migrated { target }) => target.clone(),
            _ => None,
        }
    }

    // ---------- 发布信息 ----------

    /// None 不抹掉已知状态;负状态覆盖其声明的 DID / 类型 / 版本范围。
    pub fn apply_publish_info(&mut self, info: Option<&PublishInfo>) {
        let Some(info) = info else {
            return;
        };
        let now = unix_now();
        // 依据的检查时刻:缓存读取再次应用同一回答时不变,有效期不因此续期。
        let evidence_at = info.evidence_time(now);
        let previous_did_state = self.did_state.clone();
        let merged = PublishInfo::merge(self.publish_info.take(), Some(info.clone()));
        if let Some(merged) = merged.as_ref() {
            if merged.did_state.is_some() {
                self.did_state = merged.did_state.clone();
            }
            if info.did_state.is_some() || self.did_state != previous_did_state {
                self.did_state_checked_at = Some(self.did_state_checked_at.map_or(evidence_at, |at| at.max(evidence_at)));
            }
            if let Some(type_state) = merged.type_state.as_ref() {
                // Unknown 不能覆盖已知禁用;新的明确回答可以翻篇(authority 新回答)。
                self.type_state = Some(type_state.clone());
            }
            if merged.owner_binding.is_some() {
                self.owner_binding = merged.owner_binding.clone();
            }
            self.state_source = merged.source.clone();
            if info.did_state.is_some() || info.type_state.is_some() {
                if self.state_checked_at.map_or(true, |at| evidence_at >= at) {
                    self.state_checked_at = Some(evidence_at);
                    self.state_valid_until = Some(info.expires_at(now));
                }
            } else if self.state_valid_until.is_none() {
                self.state_valid_until = Some(info.expires_at(now));
            }
            if info.query.is_current() {
                let expires = info.expires_at(now);
                self.publish_info_valid_until = Some(self.publish_info_valid_until.map_or(expires, |v| v.max(expires)));
            }
        }
        self.publish_info = merged;
        // authority 明确 missing / invalid 的 current 回答:没有当前已发布版本。
        if info.query.is_current() && !info.simulated {
            if let Some(state) = info.type_state.as_ref() {
                if state.is_not_exist() {
                    if let Some(latest) = self.latest.take() {
                        if latest.report.is_published {
                            self.history.push(latest);
                        }
                    }
                }
            }
        }
    }

    pub fn publish_info_fresh(&self, now: u64) -> Option<&PublishInfo> {
        let info = self.publish_info.as_ref()?;
        match self.publish_info_valid_until {
            Some(valid_until) if valid_until > now => Some(info),
            _ => None,
        }
    }

    // ---------- 提交来源回答 ----------

    /// `result.commit(answer, revision)`:
    /// 1. Unknown 不改变已知事实;
    /// 2. 只有 authority 的 publish_info 能合并状态和发布依据;
    /// 3. 检查 body 的 DID / doc_type / iat 并校验该 iat 的已知发布 hash;
    /// 4. authority / trust 文档经检查后成为可用 latest / best(owner 不写 best);
    /// 5. normal 按 (iat, hash) 放入 candidates。
    pub fn commit(
        &mut self,
        answer: &SourceAnswer,
        revision: &Revision,
        locker_version: u64,
        owner: Option<&OwnerConstraint>,
    ) {
        if answer.is_unknown() {
            if let Some(reason) = answer.reason.as_ref() {
                self.add_reason(format!("{}: {}", answer.source.id, reason));
            }
            return;
        }
        if answer.source.is_authority() {
            if let Some(info) = answer.publish_info.as_ref() {
                self.apply_publish_info(Some(info));
            }
        }
        let Some(body) = answer.body.as_ref() else {
            return;
        };
        let parsed = match ParsedDocument::parse(body) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.add_reason(format!("{}: unparsable document: {}", answer.source.id, err));
                return;
            }
        };
        if let Err(reason) = parsed.matches(&self.did, &self.doc_type) {
            self.add_reason(format!("{}: {}", answer.source.id, reason));
            return;
        }
        let Some(doc_revision) = parsed.revision().cloned() else {
            return;
        };
        if self.is_rejected(&doc_revision) {
            return;
        }
        // 同 iat 的已发布 hash 与输入不符则确定无效。
        if let Some(record) = self
            .publish_info
            .as_ref()
            .and_then(|info| info.record_for(doc_revision.iat))
        {
            if record.published {
                if let Some(hash) = record.hash.as_ref() {
                    if !doc_revision.matches_hash(hash) {
                        self.reject(
                            doc_revision.clone(),
                            format!("{}: published hash at iat {} differs", answer.source.id, doc_revision.iat),
                        );
                        return;
                    }
                }
            }
        }

        match answer.source.tier {
            SourceTier::Authority | SourceTier::Trust => {
                let mut report = VerifyResult::new(locker_version);
                report.revision = Some(doc_revision.clone());
                report.doc_type = Some(self.doc_type.clone());
                report.source_tier = Some(answer.source.tier);
                report.source_id = Some(answer.source.id.clone());
                if answer.source.is_authority() {
                    report.authority_receipt = Some(answer.source.id.clone());
                }
                report.owner_binding = self
                    .owner_binding
                    .clone()
                    .or_else(|| super::revision::structural_owner(&self.did));
                // 发布依据:来自本回答的 publish_info 或已合并的发布记录。
                let evidence = answer
                    .publish_info
                    .as_ref()
                    .filter(|_| answer.source.is_authority())
                    .and_then(|info| publish_evidence_for(info, &doc_revision));
                if let Some(evidence) = evidence {
                    report.is_published = true;
                    report.publish_evidence = Some(evidence);
                }
                apply_known_constraints(&mut report, &parsed, self, revision, owner);
                let report = report.finish(true);
                let report = self.accept_verified(body.clone(), answer.source.clone(), report, revision);
                if !report.is_valid() {
                    self.add_reason(format!("{}: {}", answer.source.id, report.reason()));
                }
            }
            SourceTier::Normal => {
                self.add_candidate(body.clone(), doc_revision, answer.source.clone());
            }
        }
    }

    pub fn add_candidate(&mut self, doc: EncodedDocument, revision: DocRevision, source: SourceRef) {
        if self.is_rejected(&revision) {
            return;
        }
        if let Some(existing) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.revision == revision)
        {
            if !existing.sources.iter().any(|s| s.id == source.id && s.tier == source.tier) {
                existing.sources.push(source);
            }
            return;
        }
        self.candidates.push(Candidate {
            doc,
            revision,
            sources: vec![source],
            added_at: unix_now(),
            last_reason: None,
        });
    }

    pub fn remove_candidate(&mut self, revision: &DocRevision) {
        self.candidates.retain(|candidate| candidate.revision != *revision);
    }

    pub fn clear_candidates(&mut self) {
        self.candidates.clear();
    }

    pub fn is_rejected(&self, revision: &DocRevision) -> bool {
        self.rejected.iter().any(|r| r.revision == *revision)
    }

    pub fn reject(&mut self, revision: DocRevision, reason: String) {
        self.remove_candidate(&revision);
        self.add_reason(reason.clone());
        if !self.is_rejected(&revision) {
            self.rejected.push(Rejected {
                revision,
                reason,
                at: unix_now(),
            });
        }
        if self.rejected.len() > 64 {
            self.rejected.remove(0);
        }
    }

    /// 按查询筛选候选,按 iat 从高到低。current 检查所有候选;exact / closest
    /// 只检查对应发布查询选中的候选,缺依据时为空。
    pub fn candidates_for(
        &self,
        revision: &Revision,
        publish_info: Option<&PublishInfo>,
    ) -> Vec<Candidate> {
        let mut selected: Vec<Candidate> = match revision {
            Revision::Current => self.candidates.clone(),
            Revision::Exact { iat, hash } => self
                .candidates
                .iter()
                .filter(|c| c.revision.iat == *iat && c.revision.hash == *hash)
                .cloned()
                .collect(),
            Revision::Closest { .. } => {
                let target = publish_info
                    .and_then(|info| info.satisfies(revision))
                    .or_else(|| self.slot_for(revision).and_then(|slot| slot.revision.clone()));
                match target {
                    Some(target) => self
                        .candidates
                        .iter()
                        .filter(|c| c.revision == target)
                        .cloned()
                        .collect(),
                    None => Vec::new(),
                }
            }
        };
        selected.sort_by(|a, b| b.revision.iat.cmp(&a.revision.iat));
        selected
    }

    // ---------- 验证结果接受 ----------

    /// validity=unknown 保留待验材料;invalid 不推进 best;valid 才比较已验证版本。
    /// 同 iat 同 hash 幂等;同 iat 不同 hash 把本次报告改为 invalid(conflict)。
    pub fn accept_verified(
        &mut self,
        doc: EncodedDocument,
        source: SourceRef,
        mut report: VerifyResult,
        revision: &Revision,
    ) -> VerifyResult {
        let Some(doc_revision) = report.revision.clone() else {
            return report;
        };
        if report.validity == Validity::Invalid {
            if report.is_revoked || report.is_disabled {
                let reason = report.reason();
                self.reject(doc_revision, reason);
            }
            return report;
        }
        if report.validity != Validity::Valid {
            report.clear_selection_flags();
            return report;
        }
        if let Some(existing) = self.conflicting_choice(&doc_revision) {
            report.conflict = Some(existing.clone());
            let report = report.invalid(format!(
                "conflict: verified document {} already occupies iat {}",
                existing, doc_revision.iat
            ));
            return report;
        }

        let now = unix_now();
        let choice = Choice {
            exp: ParsedDocument::parse(&doc).ok().and_then(|p| p.exp),
            doc,
            revision: doc_revision.clone(),
            source,
            query: revision.clone(),
            report: report.clone(),
            obtained_at: now,
        };

        if !self.is_owner() {
            let replace = match self.best.as_ref() {
                None => true,
                Some(best) => !best.is_valid() || best.revision.iat < doc_revision.iat,
            };
            if replace {
                if let Some(old) = self.best.take() {
                    if old.report.is_published && old.revision != doc_revision {
                        self.push_history(old);
                    }
                }
                self.best = Some(choice.clone());
            }
        }

        let is_latest_record = report
            .publish_evidence
            .as_ref()
            .map_or(false, |e| e.record.is_latest && e.record.published);
        if is_latest_record {
            let replace = match self.latest.as_ref() {
                None => true,
                Some(latest) => latest.revision.iat <= doc_revision.iat,
            };
            if replace {
                if let Some(old) = self.latest.take() {
                    if old.revision != doc_revision {
                        self.push_history(old);
                    }
                }
                self.latest = Some(choice.clone());
            }
        } else if report.is_published {
            self.push_history(choice.clone());
        }

        if !revision.is_current() {
            if let Some(evidence) = report.publish_evidence.as_ref() {
                if evidence.query == *revision {
                    self.set_slot(Slot {
                        query: revision.clone(),
                        revision: Some(doc_revision.clone()),
                        evidence: evidence.clone(),
                        valid_until: slot_valid_until(evidence, now),
                    });
                    if !self.history.iter().any(|c| c.revision == doc_revision)
                        && self.latest.as_ref().map(|l| &l.revision) != Some(&doc_revision)
                    {
                        self.push_history(choice.clone());
                    }
                }
            }
        }

        self.remove_candidate(&doc_revision);
        self.set_selection_flags(&mut report, &doc_revision, revision);
        self.updated_at = now;
        report
    }

    /// closest 回答确认边界之前没有任何版本:记录空槽,查询目标"已回答"。
    pub fn set_empty_slot(&mut self, revision: &Revision, evidence: PublishEvidence) {
        let valid_until = slot_valid_until(&evidence, unix_now());
        self.set_slot(Slot {
            query: revision.clone(),
            revision: None,
            evidence,
            valid_until,
        });
    }

    fn set_slot(&mut self, slot: Slot) {
        self.slots.retain(|existing| existing.query != slot.query);
        self.slots.push(slot);
    }

    fn push_history(&mut self, choice: Choice) {
        if self.history.iter().any(|c| c.revision == choice.revision) {
            return;
        }
        self.history.push(choice);
        self.history
            .sort_by(|a, b| b.revision.iat.cmp(&a.revision.iat));
        self.history.truncate(16);
    }

    /// 已验证版本中与该 revision 同 iat 不同 hash 者。
    fn conflicting_choice(&self, revision: &DocRevision) -> Option<DocRevision> {
        self.verified_choices()
            .into_iter()
            .map(|c| c.revision.clone())
            .find(|r| r.iat == revision.iat && r.hash != revision.hash)
    }

    pub fn verified_choices(&self) -> Vec<&Choice> {
        let mut choices: Vec<&Choice> = Vec::new();
        if let Some(latest) = self.latest.as_ref() {
            choices.push(latest);
        }
        if let Some(best) = self.best.as_ref() {
            choices.push(best);
        }
        choices.extend(self.history.iter());
        choices
    }

    pub fn find_verified(&self, revision: &DocRevision) -> Option<&Choice> {
        self.verified_choices()
            .into_iter()
            .find(|c| c.revision == *revision)
    }

    pub fn slot_for(&self, revision: &Revision) -> Option<&Slot> {
        let now = unix_now();
        self.slots
            .iter()
            .find(|slot| slot.query == *revision && slot.valid_until > now)
    }

    /// 输入与可用选择的关系;invalid / unknown 时全部为 False。
    pub fn set_selection_flags(
        &self,
        report: &mut VerifyResult,
        revision: &DocRevision,
        query: &Revision,
    ) {
        report.clear_selection_flags();
        if !report.is_valid() {
            return;
        }
        report.is_best = self
            .best
            .as_ref()
            .map_or(false, |best| best.is_valid() && best.revision == *revision);
        report.is_latest = self
            .latest
            .as_ref()
            .map_or(false, |latest| latest.is_valid() && latest.revision == *revision);
        match query {
            Revision::Current => {}
            Revision::Exact { .. } => {
                report.is_exact = self
                    .slot_for(query)
                    .map_or(false, |slot| slot.revision.as_ref() == Some(revision));
            }
            Revision::Closest { .. } => {
                report.is_closest = self
                    .slot_for(query)
                    .map_or(false, |slot| slot.revision.as_ref() == Some(revision));
            }
        }
    }

    /// exact / closest 的发布依据到位后,若目标版本已是本地已验证的文档
    /// (例如 current 查询拿到的 latest),直接填槽,不必重复下载。
    pub fn fill_slot_from_known(&mut self, revision: &Revision, publish_info: Option<&PublishInfo>) {
        if revision.is_current() || self.slot_for(revision).is_some() {
            return;
        }
        let Some(info) = publish_info.filter(|info| info.query == *revision) else {
            return;
        };
        let now = unix_now();
        match info.satisfies(revision) {
            Some(target) => {
                let Some(choice) = self.find_verified(&target).filter(|c| c.is_valid()).cloned() else {
                    return;
                };
                let Some(evidence) = publish_evidence_for(info, &target) else {
                    return;
                };
                let valid_until = slot_valid_until(&evidence, now);
                self.set_slot(Slot {
                    query: revision.clone(),
                    revision: Some(target.clone()),
                    evidence,
                    valid_until,
                });
                if self.latest.as_ref().map(|l| &l.revision) != Some(&target) {
                    self.push_history(choice);
                }
            }
            None => {
                if let Revision::Closest { before_iat } = revision {
                    if info.closest_confirmed_empty(*before_iat) {
                        let evidence = PublishEvidence {
                            source: info.source.clone().unwrap_or_else(|| "authority".to_string()),
                            simulated: info.simulated,
                            derived: info.derived,
                            record: super::publish_info::PublishRecord::not_published(*before_iat),
                            query: revision.clone(),
                            boundary: info.boundary.clone(),
                            checked_at: info.checked_at.unwrap_or(now),
                            valid_until: info.valid_until,
                        };
                        self.set_empty_slot(revision, evidence);
                    }
                }
            }
        }
    }

    /// authority 的 current 发布回答指明的 latest 若已是本地验证过的文档(例如 trust 取得的
    /// body),按这份新的发布依据把它记为 latest,不必重复下载;不伪造 `is_signed`,body
    /// 保留原来源,发布依据保留 authority 来源。
    pub fn fill_latest_from_known(&mut self, publish_info: Option<&PublishInfo>) {
        let Some(info) = publish_info
            .filter(|info| info.query.is_current() && !info.derived && !info.simulated && !info.is_disabled())
        else {
            return;
        };
        let Some(target) = info.latest_revision() else {
            return;
        };
        if self.latest.as_ref().map_or(false, |latest| latest.revision == target && latest.is_valid()) {
            return;
        }
        let Some(mut choice) = self.find_verified(&target).filter(|c| c.is_valid()).cloned() else {
            return;
        };
        let Some(evidence) = publish_evidence_for(info, &target) else {
            return;
        };
        choice.report.is_published = true;
        choice.report.publish_evidence = Some(evidence);
        if let Some(best) = self.best.as_mut().filter(|best| best.revision == target) {
            best.report.is_published = true;
            best.report.publish_evidence = choice.report.publish_evidence.clone();
        }
        if let Some(old) = self.latest.take() {
            if old.revision != target && old.report.is_published {
                self.push_history(old);
            }
        }
        self.latest = Some(choice);
    }

    // ---------- 选择 ----------

    /// current 下 owner 选择 latest,普通文档选择 best;指定查询只返回目标。
    pub fn select(&self, revision: &Revision) -> Option<&Choice> {
        match revision {
            Revision::Current => {
                if self.is_owner() {
                    self.latest.as_ref().filter(|c| c.is_valid())
                } else {
                    self.best.as_ref().filter(|c| c.is_valid())
                }
            }
            Revision::Exact { .. } | Revision::Closest { .. } => {
                let slot = self.slot_for(revision)?;
                let target = slot.revision.as_ref()?;
                self.find_verified(target).filter(|c| c.is_valid())
            }
        }
    }

    pub fn select_document(&self, revision: &Revision) -> Option<EncodedDocument> {
        self.select(revision).map(|c| c.doc.clone())
    }

    /// 指定查询的发布目标是否已有依据(含"确认不存在"的空槽)。
    pub fn satisfies_published_target(&self, revision: &Revision) -> bool {
        match revision {
            // 已合并的发布依据指明了另一份 latest 时,缓存的旧 latest 不满足目标。
            Revision::Current => self.latest.as_ref().map_or(false, |latest| {
                latest.is_valid()
                    && self
                        .publish_info
                        .as_ref()
                        .and_then(PublishInfo::latest_revision)
                        .map_or(true, |published| published == latest.revision)
            }),
            _ => match self.slot_for(revision) {
                Some(slot) => match slot.revision.as_ref() {
                    Some(target) => self.find_verified(target).map_or(false, Choice::is_valid),
                    None => true,
                },
                None => false,
            },
        }
    }

    /// owner 输入必须匹配 authority / locker 给出的确切根文档。
    pub fn contains_published_or_locked(&self, revision: &DocRevision, query: &Revision) -> bool {
        match query {
            Revision::Current => self
                .latest
                .as_ref()
                .map_or(false, |l| l.is_valid() && l.revision == *revision),
            _ => self
                .slot_for(query)
                .map_or(false, |slot| slot.revision.as_ref() == Some(revision)),
        }
    }

    // ---------- 约束刷新 ----------

    /// 每次 resolve / verify 读结果时执行:检查 owner revision、locker 配置版本、
    /// 已知负状态及本机 exp。失效 best 从选择中移除;尚可重验的 body 回到候选。
    pub fn refresh_known_constraints(
        &mut self,
        locker_version: u64,
        owner: Option<&OwnerConstraint>,
    ) {
        let now = unix_now();
        // 过期的发布查询回答:TTL 过期不等于清除已知禁用 / 撤销。
        if let Some(valid_until) = self.state_valid_until {
            if valid_until <= now {
                if let Some(TypeState::Missing) | Some(TypeState::Invalid { .. }) =
                    self.type_state.as_ref()
                {
                    self.type_state = None;
                }
                self.state_valid_until = None;
            }
        }
        self.slots.retain(|slot| slot.valid_until > now);
        self.rejected.retain(|r| r.at + 24 * 3600 > now);

        let locker_changed = self.locker_version != locker_version;
        let mut recheck: Vec<Choice> = Vec::new();
        if let Some(latest) = self.latest.take() {
            match self.recheck_choice(latest, now, locker_changed, owner) {
                Ok(choice) => self.latest = Some(choice),
                Err(choice) => recheck.push(choice),
            }
        }
        if let Some(best) = self.best.take() {
            match self.recheck_choice(best, now, locker_changed, owner) {
                Ok(choice) => self.best = Some(choice),
                Err(choice) => recheck.push(choice),
            }
        }
        let history = std::mem::take(&mut self.history);
        for choice in history {
            match self.recheck_choice(choice, now, locker_changed, owner) {
                Ok(choice) => self.history.push(choice),
                Err(choice) => recheck.push(choice),
            }
        }
        for choice in recheck {
            if choice.report.validity == Validity::Invalid
                && (choice.report.is_revoked || choice.report.is_disabled || choice.report.is_expired)
            {
                // 确定撤销 / 过期 / 禁用的 body 不重复验证,也不能在提交合并时复活。
                let reason = choice.report.reason();
                self.reject(choice.revision, reason);
                continue;
            }
            self.add_candidate(choice.doc, choice.revision, choice.source);
        }
        if locker_changed {
            self.locker_version = locker_version;
        }
    }

    /// 重新应用已知约束。`Ok` 保留(可能已更新 report),`Err` 需要重验或已失效。
    fn recheck_choice(
        &self,
        mut choice: Choice,
        now: u64,
        locker_changed: bool,
        owner: Option<&OwnerConstraint>,
    ) -> Result<Choice, Choice> {
        let check_time = match (&self.doc_type, &choice.query) {
            (DidDocType::Owner, Revision::Exact { iat, .. }) => *iat,
            (DidDocType::Owner, Revision::Closest { before_iat }) => *before_iat,
            _ => now,
        };
        let mut invalidated = false;
        if let Some(exp) = choice.exp {
            if exp <= check_time && !choice.report.is_expired {
                choice.report.is_expired = true;
                invalidated = true;
            }
        }
        if self.is_disabled() && !choice.report.is_disabled {
            choice.report.is_disabled = true;
            invalidated = true;
        }
        if let Some(TypeState::Revoked) = self.type_state.as_ref() {
            choice.report.is_revoked = true;
            invalidated = true;
        }
        if !self.is_owner() {
            if let Some(owner) = owner {
                if owner.disabled {
                    choice.report.is_revoked = true;
                    invalidated = true;
                }
                if let Some(valid_iat) = owner.valid_iat {
                    if choice.revision.iat <= valid_iat {
                        choice.report.is_revoked = true;
                        invalidated = true;
                    }
                }
                // 实际验证依赖(当前 owner revision)变更:签名结论需要重验。
                if let Some(current) = owner.revision.as_ref() {
                    let used = choice
                        .report
                        .dependencies
                        .iter()
                        .find(|d| d.role == DependencyRole::CurrentOwner);
                    if let Some(used) = used {
                        if used.revision != *current {
                            return Err(choice);
                        }
                    }
                }
            }
        }
        if invalidated {
            choice.report = choice.report.finish(true);
            return Err(choice);
        }
        // locker 配置变化:由 locker 模拟发布满足的依据(包括 owner 等验证依赖)都要重验。
        if locker_changed
            && (choice
                .report
                .publish_evidence
                .as_ref()
                .map_or(false, |e| e.simulated)
                || choice.report.dependencies.iter().any(|d| d.simulated))
        {
            return Err(choice);
        }
        Ok(choice)
    }

    // ---------- 跨进程合并 ----------

    /// 段 2:在存储中最新结果上合并本地快照。接受规则:unknown 保留待验材料;
    /// invalid 不推进 best;valid 才与已验证版本比较;同 iat 同 hash 幂等;
    /// 同 iat 不同 hash 保留旧结果并返回冲突。
    pub fn merge_into(stored: Option<DocResult>, local: DocResult) -> (DocResult, Option<DocRevision>) {
        let Some(mut base) = stored else {
            let mut local = local;
            local.generation += 1;
            local.locked = false;
            return (local, None);
        };
        if base.generation == local.base_generation {
            // 存储自读取后未变:本地快照已在同一基线上重新判定过全部约束,整体替换。
            let mut local = local;
            local.generation = base.generation + 1;
            local.locked = false;
            local.updated_at = unix_now();
            return (local, None);
        }
        let mut conflict: Option<DocRevision> = None;
        // 本地已确定拒绝(撤销 / 过期 / 禁用)的版本不能从存储中复活;存储中已拒绝的版本
        // 也不能借本地旧快照复活。
        let locally_rejected: Vec<DocRevision> = local.rejected.iter().map(|r| r.revision.clone()).collect();
        let stored_rejected: Vec<DocRevision> = base.rejected.iter().map(|r| r.revision.clone()).collect();
        let not_rejected = |choice: &Option<Choice>| {
            choice.clone().filter(|c| !stored_rejected.contains(&c.revision))
        };
        if base.best.as_ref().map_or(false, |c| locally_rejected.contains(&c.revision)) {
            base.best = None;
        }
        if base.latest.as_ref().map_or(false, |c| locally_rejected.contains(&c.revision)) {
            base.latest = None;
        }
        base.history.retain(|c| !locally_rejected.contains(&c.revision));
        base.requested_doc_type = local.requested_doc_type.clone();
        // 状态按所依据回答的检查时刻裁决:本地快照只有带来了更新的依据时才覆盖存储。
        if local.state_checked_at > base.state_checked_at {
            base.type_state = local.type_state.clone();
            base.state_source = local.state_source.clone();
            base.state_valid_until = local.state_valid_until;
            base.state_checked_at = local.state_checked_at;
        }
        if local.did_state_checked_at > base.did_state_checked_at {
            base.did_state = local.did_state.clone();
            base.did_state_checked_at = local.did_state_checked_at;
        }
        if local.owner_binding.is_some() {
            base.owner_binding = local.owner_binding.clone();
        }
        if local.publish_info.is_some() {
            base.publish_info = PublishInfo::merge(base.publish_info.take(), local.publish_info.clone());
            base.publish_info_valid_until = local.publish_info_valid_until.max(base.publish_info_valid_until);
        }

        // best / latest:取更高的有效版本;同 iat 不同 hash 记冲突。
        let local_best = not_rejected(&local.best);
        let local_latest = not_rejected(&local.latest);
        base.best = Self::merge_choice(base.best.take(), local_best, &mut conflict, false);
        base.latest = Self::merge_choice(base.latest.take(), local_latest, &mut conflict, true);
        if base.is_owner() {
            base.best = None;
        }
        for choice in local.history {
            if stored_rejected.contains(&choice.revision) {
                continue;
            }
            if base
                .verified_choices()
                .iter()
                .any(|c| c.revision.iat == choice.revision.iat && c.revision.hash != choice.revision.hash)
            {
                conflict.get_or_insert(choice.revision.clone());
                continue;
            }
            base.push_history(choice);
        }
        for candidate in local.candidates {
            if base.is_rejected(&candidate.revision) {
                continue;
            }
            match base
                .candidates
                .iter_mut()
                .find(|c| c.revision == candidate.revision)
            {
                Some(existing) => {
                    for source in candidate.sources {
                        if !existing.sources.iter().any(|s| s.id == source.id && s.tier == source.tier) {
                            existing.sources.push(source);
                        }
                    }
                }
                None => base.candidates.push(candidate),
            }
        }
        // 本地已验证的版本不再是候选。
        let verified: Vec<DocRevision> = base
            .verified_choices()
            .into_iter()
            .map(|c| c.revision.clone())
            .collect();
        base.candidates.retain(|c| !verified.contains(&c.revision));
        if base.candidates.len() > 32 {
            base.candidates.sort_by(|a, b| b.revision.iat.cmp(&a.revision.iat));
            base.candidates.truncate(32);
        }
        for slot in local.slots {
            match base.slots.iter_mut().find(|s| s.query == slot.query) {
                Some(existing) => {
                    if slot.valid_until >= existing.valid_until {
                        *existing = slot;
                    }
                }
                None => base.slots.push(slot),
            }
        }
        for rejected in local.rejected {
            if !base.is_rejected(&rejected.revision) {
                base.rejected.push(rejected);
            }
        }
        base.reasons = local.reasons;
        base.locked = false;
        base.locker_version = local.locker_version;
        // 合并后的状态(可能来自存储中更新的撤销 / 禁用)同样约束本地带来的选择。
        base.refresh_known_constraints(base.locker_version, None);
        base.updated_at = unix_now();
        base.generation += 1;
        (base, conflict)
    }

    fn merge_choice(
        stored: Option<Choice>,
        local: Option<Choice>,
        conflict: &mut Option<DocRevision>,
        is_latest: bool,
    ) -> Option<Choice> {
        match (stored, local) {
            (None, local) => local,
            (stored, None) => stored,
            (Some(stored), Some(local)) => {
                if stored.revision == local.revision {
                    // 幂等:保留较新的报告。
                    return Some(if local.obtained_at >= stored.obtained_at { local } else { stored });
                }
                if stored.revision.iat == local.revision.iat {
                    if stored.is_valid() {
                        *conflict = Some(local.revision.clone());
                        return Some(stored);
                    }
                    return Some(local);
                }
                let take_local = if is_latest {
                    local.revision.iat > stored.revision.iat || !stored.is_valid()
                } else {
                    (local.is_valid() && local.revision.iat > stored.revision.iat) || !stored.is_valid()
                };
                Some(if take_local { local } else { stored })
            }
        }
    }

    // ---------- locker ----------

    /// locker 回答按 revision 匹配目标:锁定当前文档不能冒充 exact / closest 的
    /// 历史目标。不匹配返回 None(继续向后查)。
    pub fn locked_from(
        answer: &SourceAnswer,
        scope: Scope,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        locker_version: u64,
    ) -> Option<DocResult> {
        let mut result = DocResult::empty(scope, did.clone(), doc_type.clone());
        result.locked = true;
        result.locker_version = locker_version;
        if let Some(info) = answer.publish_info.as_ref() {
            result.apply_publish_info(Some(info));
        }
        if result.is_disabled() {
            return Some(result);
        }
        let Some(body) = answer.body.as_ref() else {
            // 只有状态列(如明确 missing / invalid):强制回答。
            return if answer.publish_info.is_some() {
                Some(result)
            } else {
                None
            };
        };
        let parsed = ParsedDocument::parse(body).ok()?;
        parsed.matches(did, doc_type).ok()?;
        let doc_revision = parsed.revision()?.clone();
        let simulated_target = answer
            .publish_info
            .as_ref()
            .and_then(|info| info.satisfies(revision))
            .map_or(false, |target| target == doc_revision);
        let matches_target = match revision {
            Revision::Current => true,
            Revision::Exact { iat, hash } => doc_revision.iat == *iat && doc_revision.hash == *hash,
            // locker 可在 scope 内模拟完整历史(`LockOptions::simulate_history`)。
            Revision::Closest { before_iat } => doc_revision.iat < *before_iat || simulated_target,
        };
        if !matches_target {
            // 锁定文档不是目标,但 locker 对该目标给出了明确回答(如 latest 之后的 exact
            // 未发布、closest 确认为空):这是强制回答,不能当 miss 继续查,也不写入普通缓存。
            let answers_target = answer.publish_info.as_ref().map_or(false, |info| match revision {
                Revision::Exact { iat, .. } => info.record_for(*iat).map_or(false, |r| !r.published),
                Revision::Closest { before_iat } => info.closest_confirmed_empty(*before_iat),
                Revision::Current => false,
            });
            return answers_target.then_some(result);
        }
        let now = unix_now();
        let mut report = VerifyResult::new(locker_version);
        report.revision = Some(doc_revision.clone());
        report.doc_type = Some(doc_type.clone());
        report.source_tier = Some(SourceTier::Authority);
        report.source_id = Some(answer.source.id.clone());
        let evidence = PublishEvidence {
            source: answer.source.id.clone(),
            simulated: true,
            derived: false,
            record: super::publish_info::PublishRecord::published(
                doc_revision.iat,
                &doc_revision.hash,
                true,
            ),
            query: revision.clone(),
            boundary: match revision {
                Revision::Closest { before_iat } => Some(super::publish_info::Boundary {
                    query_iat: *before_iat,
                    selected: Some(doc_revision.clone()),
                    confirmed: true,
                }),
                _ => None,
            },
            checked_at: now,
            valid_until: None,
        };
        report.is_published = true;
        report.publish_evidence = Some(evidence);
        let check_time = match (doc_type, revision) {
            (DidDocType::Owner, Revision::Exact { iat, .. }) => *iat,
            (DidDocType::Owner, Revision::Closest { before_iat }) => *before_iat,
            _ => now,
        };
        if parsed.exp.map_or(false, |exp| exp <= check_time) {
            report.is_expired = true;
        }
        let report = report.finish(true);
        result.accept_verified(body.clone(), answer.source.clone(), report, revision);
        Some(result)
    }
}

/// 从 authority 发布信息中为该 revision 找发布依据。exact / closest 回答只为
/// 它选中的版本作证:查询 hash 不符或边界未确认时没有依据。
pub fn publish_evidence_for(info: &PublishInfo, revision: &DocRevision) -> Option<PublishEvidence> {
    let record = info.record_for(revision.iat)?;
    if !record.published {
        return None;
    }
    if let Some(hash) = record.hash.as_ref() {
        if !revision.matches_hash(hash) {
            return None;
        }
    }
    if !info.query.is_current() && info.satisfies(&info.query).as_ref() != Some(revision) {
        return None;
    }
    Some(PublishEvidence {
        source: info.source.clone().unwrap_or_else(|| "authority".to_string()),
        simulated: info.simulated,
        derived: info.derived,
        record: record.clone(),
        query: info.query.clone(),
        boundary: info.boundary.clone(),
        checked_at: info.checked_at.unwrap_or_else(unix_now),
        valid_until: info.valid_until,
    })
}

/// 查询槽的有效期:依据检查时刻起的历史查询上限,且不超过来源声明的 validUntil。
fn slot_valid_until(evidence: &PublishEvidence, now: u64) -> u64 {
    let cap = evidence.checked_at.min(now) + super::publish_info::HISTORICAL_QUERY_TTL_SECS;
    evidence.valid_until.map_or(cap, |valid_until| valid_until.min(cap))
}

/// 仅读取当前已有的状态和 owner 材料,不隐含网络请求;不把"未发现撤销"说成全网确认。
pub fn apply_known_constraints(
    report: &mut VerifyResult,
    doc: &ParsedDocument,
    result: &DocResult,
    revision: &Revision,
    owner: Option<&OwnerConstraint>,
) {
    let now = unix_now();
    let check_time = match (&result.doc_type, revision) {
        (DidDocType::Owner, Revision::Exact { iat, .. }) => *iat,
        (DidDocType::Owner, Revision::Closest { before_iat }) => *before_iat,
        _ => now,
    };
    if let Some(exp) = doc.exp {
        if exp <= check_time {
            report.is_expired = true;
        }
    }
    if result.is_disabled() {
        report.is_disabled = true;
        if let Some(reason) = result.disabled_reason() {
            report.add_reason(reason);
        }
    }
    if let Some(TypeState::Revoked) = result.type_state.as_ref() {
        report.is_revoked = true;
    }
    if let (Some(iat), Some(owner)) = (doc.iat, owner) {
        if result.doc_type != DidDocType::Owner {
            if owner.disabled {
                report.is_revoked = true;
                report.add_reason("current owner is disabled".to_string());
            }
            if let Some(valid_iat) = owner.valid_iat {
                if iat <= valid_iat {
                    report.is_revoked = true;
                    report.add_reason(format!(
                        "iat {} is not after owner valid_iat {}",
                        iat, valid_iat
                    ));
                }
            }
        }
    }
    if report.is_expired || report.is_disabled || report.is_revoked {
        report.validity = Validity::Invalid;
        report.clear_selection_flags();
    }
}

/// 收件箱 / 进程内投递的候选回答。
pub fn candidate_answer(source: SourceRef, body: EncodedDocument) -> SourceAnswer {
    SourceAnswer::new(source).with_body(body, Carrier::Cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::publish_info::{DocumentStatus, PublishRecord};
    use serde_json::json;

    fn doc(iat: u64, marker: &str) -> EncodedDocument {
        EncodedDocument::JsonLd(json!({
            "id": "did:bns:zone1.alice",
            "iat": iat,
            "exp": iat + 100_000_000,
            "marker": marker
        }))
    }

    fn did() -> DID {
        DID::new("bns", "zone1.alice")
    }

    fn authority_answer(iat: u64, marker: &str) -> SourceAnswer {
        let body = doc(iat, marker);
        let rev = DocRevision::of(&body).unwrap();
        let info = PublishInfo::new(did(), DidDocType::Zone, Revision::current())
            .with_status(&DocumentStatus::Active, None, None)
            .with_record(PublishRecord::published(rev.iat, &rev.hash, true))
            .with_source("authority");
        SourceAnswer::new(SourceRef::provider("authority", SourceTier::Authority))
            .with_body(body, Carrier::Inline)
            .with_publish_info(info)
    }

    #[test]
    fn authority_sets_latest_and_best_trust_only_best() {
        let now = unix_now();
        let mut result = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        result.commit(&authority_answer(now - 100, "v1"), &Revision::current(), 0, None);
        assert!(result.latest.is_some() && result.best.is_some());

        let trust = SourceAnswer::new(SourceRef::provider("trust", SourceTier::Trust))
            .with_body(doc(now - 50, "v2"), Carrier::Body);
        result.commit(&trust, &Revision::current(), 0, None);
        assert_eq!(result.latest.as_ref().unwrap().revision.iat, now - 100);
        assert_eq!(result.best.as_ref().unwrap().revision.iat, now - 50);
        assert!(!result.best.as_ref().unwrap().report.is_published);
        assert!(!result.best.as_ref().unwrap().report.is_signed);
    }

    #[test]
    fn same_iat_different_hash_conflicts_after_verification() {
        let now = unix_now();
        let mut result = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        result.commit(&authority_answer(now - 100, "v1"), &Revision::current(), 0, None);
        let other = doc(now - 100, "v1-evil");
        let rev = DocRevision::of(&other).unwrap();
        let mut report = VerifyResult::new(0);
        report.revision = Some(rev);
        report.doc_type = Some(DidDocType::Zone);
        let report = report.finish(true);
        let report = result.accept_verified(
            other,
            SourceRef::normal("x"),
            report,
            &Revision::current(),
        );
        assert_eq!(report.validity, Validity::Invalid);
        assert!(report.conflict.is_some());
        assert_eq!(result.best.as_ref().unwrap().report.reasons.len(), 0);
    }

    #[test]
    fn merge_keeps_stored_on_conflict_and_unions_candidates() {
        let now = unix_now();
        let mut stored = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        stored.commit(&authority_answer(now - 100, "v1"), &Revision::current(), 0, None);
        // 模拟另一进程在本地快照读取之后提交过(存储代际前进),走合并路径。
        stored.generation = 3;
        let mut local = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        local.commit(&authority_answer(now - 100, "v1-other"), &Revision::current(), 0, None);
        local.add_candidate(
            doc(now - 10, "cand"),
            DocRevision::of(&doc(now - 10, "cand")).unwrap(),
            SourceRef::normal("inbox"),
        );
        let (merged, conflict) = DocResult::merge_into(Some(stored.clone()), local);
        assert!(conflict.is_some());
        assert_eq!(merged.candidates.len(), 1);
        assert_eq!(merged.generation, 4);

        // 存储代际未变:本地快照整体替换(已重新判定过约束)。
        let mut snapshot = stored.clone();
        snapshot.mark_base_generation();
        snapshot.best = None;
        let (replaced, conflict) = DocResult::merge_into(Some(stored), snapshot);
        assert!(conflict.is_none());
        assert!(replaced.best.is_none());
        assert_eq!(replaced.generation, 4);
    }

    #[test]
    fn locked_result_matches_target_revision_only() {
        let now = unix_now();
        let body = doc(now - 100, "locked");
        let rev = DocRevision::of(&body).unwrap();
        let answer = SourceAnswer::new(SourceRef::local_locker()).with_body(body, Carrier::Locker);
        let current = DocResult::locked_from(&answer, Scope::Host, &did(), &DidDocType::Zone, &Revision::current(), 1).unwrap();
        assert!(current.locked && current.select(&Revision::current()).is_some());
        assert!(DocResult::locked_from(&answer, Scope::Host, &did(), &DidDocType::Zone, &Revision::exact(now - 100, "zz"), 1).is_none());
        let closest = DocResult::locked_from(&answer, Scope::Host, &did(), &DidDocType::Zone, &Revision::closest(now), 1).unwrap();
        assert_eq!(closest.select(&Revision::closest(now)).unwrap().revision, rev);
        assert!(DocResult::locked_from(&answer, Scope::Host, &did(), &DidDocType::Zone, &Revision::closest(now - 100), 1).is_none());
    }

    #[test]
    fn refresh_revokes_by_owner_valid_iat() {
        let now = unix_now();
        let mut result = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        result.commit(&authority_answer(now - 100, "v1"), &Revision::current(), 0, None);
        let owner = OwnerConstraint {
            disabled: false,
            valid_iat: Some(now - 50),
            revision: None,
        };
        result.refresh_known_constraints(0, Some(&owner));
        assert!(result.best.is_none() && result.latest.is_none());
        assert!(result.candidates.is_empty(), "revoked bodies are not re-verified");
    }

    fn trust_answer(doc: EncodedDocument) -> SourceAnswer {
        SourceAnswer::new(SourceRef::provider("trust", SourceTier::Trust)).with_body(doc, Carrier::Body)
    }

    /// T07:exp 等号即不可选;刷新约束只读本机时间,确定过期的 body 不回到候选。
    #[test]
    fn refresh_expires_at_the_exact_second() {
        use super::super::clock::test_clock;
        let _clock = test_clock::Frozen::at(10_000);
        let body = EncodedDocument::JsonLd(json!({"id": "did:bns:zone1.alice", "iat": 100, "exp": 10_010}));
        let mut result = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        test_clock::set(10_009);
        result.commit(&trust_answer(body.clone()), &Revision::current(), 0, None);
        result.refresh_known_constraints(0, None);
        assert!(result.select(&Revision::current()).is_some());
        test_clock::set(10_010);
        result.refresh_known_constraints(0, None);
        assert!(result.select(&Revision::current()).is_none());
        assert!(result.candidates.is_empty());
        assert!(result.is_rejected(&DocRevision::of(&body).unwrap()));
    }

    /// T16:提交时存储已前进(另一方写入了撤销并拒绝了旧版本);基于旧快照的本地结果不能把
    /// 状态恢复为 Active,也不能让被拒绝的版本复活。
    #[test]
    fn merge_does_not_resurrect_state_from_a_stale_snapshot() {
        let now = unix_now();
        let mut snapshot = DocResult::empty(Scope::Host, did(), DidDocType::Zone);
        snapshot.commit(&authority_answer(now - 100, "v0"), &Revision::current(), 0, None);
        snapshot.generation = 1;
        snapshot.mark_base_generation();

        let mut stored = snapshot.clone();
        let revoked = PublishInfo::new(did(), DidDocType::Zone, Revision::current())
            .with_status(&DocumentStatus::Revoked, None, None)
            .with_source("authority");
        stored.apply_publish_info(Some(&revoked));
        stored.refresh_known_constraints(0, None);
        stored.generation = 2;
        assert!(stored.is_disabled() && stored.best.is_none());

        let mut local = snapshot;
        local.commit(&trust_answer(doc(now - 50, "newer")), &Revision::current(), 0, None);
        assert!(local.best.as_ref().unwrap().is_valid());
        let (merged, _) = DocResult::merge_into(Some(stored), local);
        assert!(merged.is_disabled(), "stale Active snapshot overwrote the stored revocation");
        assert!(merged.select(&Revision::current()).is_none());
        assert!(merged.latest.is_none(), "rejected v0 came back as latest");
    }
}
