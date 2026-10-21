//! 发布信息(设计稿 §2.2、HTTP binding §3/§4/§7)。
//!
//! `PublishInfo` 包含 DID 级/类型级状态、可信 owner 绑定和带明确 iat 的发布记录。
//! `None / NoAnswer` 只是没有回答,不表示禁用,也不证明从未发布;Unknown 不能
//! 覆盖已知禁用或撤销;负状态只覆盖它明确声明的 DID、类型或版本范围。

use super::revision::{normalize_hash, DocRevision, Revision};
use buckyos_kit::buckyos_get_unix_timestamp;
use name_lib::{DidDocType, DID};
use serde::{Deserialize, Serialize};

/// 发布查询回答的默认 TTL(产品刷新口径:常规缓存窗口约 30 秒)。
pub const PUBLISH_QUERY_TTL_SECS: u64 = 30;
/// `invalid` 是明确回答但可能随关联文档修复而变化,短 TTL。
pub const INVALID_STATE_TTL_SECS: u64 = 30;
/// 类型级 `missing` 的记忆窗口。
pub const MISSING_STATE_TTL_SECS: u64 = 60;
/// 终止性负状态(revoked / tombstoned)的重查间隔。
pub const TERMINAL_STATE_TTL_SECS: u64 = 3600;
/// exact / closest 历史查询回答的复用上限:不能无限复用。
pub const HISTORICAL_QUERY_TTL_SECS: u64 = 3600;

/// wire `documentStatus` 状态机(HTTP binding §4)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned,
    /// 权威源对该 `(did, doc_type)` 做过确定性校验并拒绝(cyfs-gateway#207 C1)。
    Invalid,
}

impl Default for DocumentStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl DocumentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Revoked | Self::Tombstoned)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Migrated => "migrated",
            Self::Tombstoned => "tombstoned",
            Self::Invalid => "invalid",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "missing" => Some(Self::Missing),
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "migrated" => Some(Self::Migrated),
            "tombstoned" => Some(Self::Tombstoned),
            "invalid" => Some(Self::Invalid),
            _ => None,
        }
    }
}

impl std::fmt::Display for DocumentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DID 级状态:覆盖该 DID 的全部类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidState {
    Normal,
    Tombstoned,
    Migrated { target: Option<DID> },
}

impl DidState {
    pub fn is_disabled(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// 类型级状态:只覆盖声明的 `(did, doc_type)`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeState {
    Active,
    Expired,
    /// 该来源没有文档,不自动等于整个 DID 禁用。
    Missing,
    /// 明确回答:确定性校验失败。选择时等同 Missing,不升级为 DID 禁用。
    Invalid { reason: String },
    Revoked,
}

impl TypeState {
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Missing / Invalid:该来源没有可选文档,但不禁用。
    pub fn is_not_exist(&self) -> bool {
        matches!(self, Self::Missing | Self::Invalid { .. })
    }

    pub fn to_document_status(&self) -> DocumentStatus {
        match self {
            Self::Active => DocumentStatus::Active,
            Self::Expired => DocumentStatus::Expired,
            Self::Missing => DocumentStatus::Missing,
            Self::Invalid { .. } => DocumentStatus::Invalid,
            Self::Revoked => DocumentStatus::Revoked,
        }
    }
}

/// 一条带明确 iat 的发布记录。`published=false` 是显式"该版本未发布"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRecord {
    pub iat: u64,
    pub hash: Option<String>,
    pub published: bool,
    pub is_latest: bool,
}

impl PublishRecord {
    pub fn published(iat: u64, hash: impl AsRef<str>, is_latest: bool) -> Self {
        Self {
            iat,
            hash: Some(normalize_hash(hash.as_ref())),
            published: true,
            is_latest,
        }
    }

    pub fn not_published(iat: u64) -> Self {
        Self {
            iat,
            hash: None,
            published: false,
            is_latest: false,
        }
    }

    pub fn revision(&self) -> Option<DocRevision> {
        self.hash
            .as_ref()
            .map(|hash| DocRevision::new(self.iat, hash))
    }
}

/// closest 查询的边界回答:`(selected.iat, query_iat)` 内没有已发布版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub query_iat: u64,
    /// None 表示查询边界之前没有任何已发布版本。
    pub selected: Option<DocRevision>,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishInfo {
    pub did: DID,
    pub doc_type: DidDocType,
    #[serde(default)]
    pub did_state: Option<DidState>,
    #[serde(default)]
    pub type_state: Option<TypeState>,
    #[serde(default)]
    pub owner_binding: Option<DID>,
    #[serde(default)]
    pub records: Vec<PublishRecord>,
    #[serde(default)]
    pub latest_iat: Option<u64>,
    #[serde(default)]
    pub boundary: Option<Boundary>,
    /// 该回答描述的查询(current / exact / closest)。
    #[serde(default)]
    pub query: Revision,
    #[serde(default)]
    pub checked_at: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<u64>,
    /// 产生回答的来源 id;locker 模拟发布时 `simulated = true`。
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub simulated: bool,
    /// 由 current 回答推导而来(设计稿 §1 closest 推导规则)。
    #[serde(default)]
    pub derived: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl PublishInfo {
    pub fn new(did: DID, doc_type: DidDocType, query: Revision) -> Self {
        Self {
            did,
            doc_type,
            did_state: None,
            type_state: None,
            owner_binding: None,
            records: Vec::new(),
            latest_iat: None,
            boundary: None,
            query,
            checked_at: Some(buckyos_get_unix_timestamp()),
            valid_until: None,
            source: None,
            simulated: false,
            derived: false,
            reasons: Vec::new(),
        }
    }

    /// 由 wire `documentStatus` 建立状态(DID 级 / 类型级分流)。
    pub fn with_status(mut self, status: &DocumentStatus, reason: Option<String>, target: Option<DID>) -> Self {
        match status {
            DocumentStatus::Tombstoned => self.did_state = Some(DidState::Tombstoned),
            DocumentStatus::Migrated => self.did_state = Some(DidState::Migrated { target }),
            DocumentStatus::Active => self.type_state = Some(TypeState::Active),
            DocumentStatus::Expired => self.type_state = Some(TypeState::Expired),
            DocumentStatus::Missing => self.type_state = Some(TypeState::Missing),
            DocumentStatus::Revoked => self.type_state = Some(TypeState::Revoked),
            DocumentStatus::Invalid => {
                self.type_state = Some(TypeState::Invalid {
                    reason: reason.unwrap_or_else(|| "authority rejected the document".to_string()),
                })
            }
        }
        self
    }

    pub fn with_record(mut self, record: PublishRecord) -> Self {
        if record.is_latest {
            self.latest_iat = Some(self.latest_iat.map_or(record.iat, |iat| iat.max(record.iat)));
        }
        self.records.push(record);
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn is_disabled(&self) -> bool {
        self.did_state.as_ref().map_or(false, DidState::is_disabled)
            || self.type_state.as_ref().map_or(false, TypeState::is_disabled)
    }

    /// 只返回覆盖该 iat 的发布记录;V1 的 hash 不约束 iat 不同的 V2。
    pub fn record_for(&self, iat: u64) -> Option<&PublishRecord> {
        self.records.iter().find(|record| record.iat == iat)
    }

    pub fn latest_record(&self) -> Option<&PublishRecord> {
        self.records
            .iter()
            .filter(|record| record.published && record.is_latest)
            .max_by_key(|record| record.iat)
    }

    /// 按 `is_latest` 记录或 `latest_iat` 得出的当前已发布版本。
    pub fn latest_revision(&self) -> Option<DocRevision> {
        self.latest_record().and_then(PublishRecord::revision)
    }

    pub fn cache_ttl_secs(&self) -> u64 {
        let base = match (&self.did_state, &self.type_state) {
            (Some(DidState::Tombstoned), _) | (_, Some(TypeState::Revoked)) => {
                TERMINAL_STATE_TTL_SECS
            }
            (_, Some(TypeState::Invalid { .. })) => INVALID_STATE_TTL_SECS,
            (_, Some(TypeState::Missing)) => MISSING_STATE_TTL_SECS,
            _ if !self.query.is_current() => HISTORICAL_QUERY_TTL_SECS,
            _ => PUBLISH_QUERY_TTL_SECS,
        };
        match self.valid_until {
            Some(valid_until) => {
                let now = buckyos_get_unix_timestamp();
                base.min(valid_until.saturating_sub(now).max(1))
            }
            None => base,
        }
    }

    /// 该回答是否满足指定查询的发布目标。exact 核对 iat+hash;closest 核对边界。
    pub fn satisfies(&self, revision: &Revision) -> Option<DocRevision> {
        match revision {
            Revision::Current => self.latest_revision(),
            Revision::Exact { iat, hash } => self.records.iter().find_map(|record| {
                if record.iat == *iat && record.published {
                    let record_hash = record.hash.as_ref()?;
                    (record_hash == hash).then(|| DocRevision::new(*iat, hash))
                } else {
                    None
                }
            }),
            Revision::Closest { before_iat } => {
                let boundary = self.boundary.as_ref()?;
                if boundary.query_iat != *before_iat || !boundary.confirmed {
                    return None;
                }
                boundary.selected.clone()
            }
        }
    }

    /// closest 回答是否"确认边界之前没有任何版本"。
    pub fn closest_confirmed_empty(&self, before_iat: u64) -> bool {
        self.boundary
            .as_ref()
            .map_or(false, |b| b.query_iat == before_iat && b.confirmed && b.selected.is_none())
    }

    /// 由 authority(或 locker 模拟发布)的 current 回答 L 推出 exact/closest 回答
    /// (设计稿 §1):`query_iat > L.iat` 时 `closest(query_iat) = L`;
    /// `exact(iat, hash)` 在 `iat == L.iat && hash == L.hash` 时命中。
    /// `query_iat <= L.iat` 必须发真正的历史查询,返回 None。
    pub fn derive_for(&self, revision: &Revision) -> Option<PublishInfo> {
        if !self.query.is_current() || self.is_disabled() {
            return None;
        }
        let latest = self.latest_record()?;
        let latest_revision = latest.revision()?;
        let mut derived = self.clone();
        derived.query = revision.clone();
        derived.derived = true;
        derived.boundary = None;
        derived.records = vec![PublishRecord {
            iat: latest.iat,
            hash: latest.hash.clone(),
            published: true,
            is_latest: true,
        }];
        match revision {
            Revision::Current => None,
            Revision::Exact { iat, hash } => {
                if *iat == latest_revision.iat && *hash == latest_revision.hash {
                    Some(derived)
                } else if *iat > latest_revision.iat {
                    // latest 之后不存在已发布版本:该 iat 确定未发布。
                    derived.records.push(PublishRecord::not_published(*iat));
                    Some(derived)
                } else {
                    None
                }
            }
            Revision::Closest { before_iat } => {
                if *before_iat > latest_revision.iat {
                    derived.boundary = Some(Boundary {
                        query_iat: *before_iat,
                        selected: Some(latest_revision),
                        confirmed: true,
                    });
                    Some(derived)
                } else {
                    None
                }
            }
        }
    }

    /// 合并两份回答:只有 authority 的 publish_info 可合并;Unknown(None)不抹去
    /// 已知事实;显式负状态优先于 Unknown;记录按 iat 去重(新回答覆盖同 iat)。
    pub fn merge(base: Option<PublishInfo>, other: Option<PublishInfo>) -> Option<PublishInfo> {
        match (base, other) {
            (None, None) => None,
            (Some(base), None) => Some(base),
            (None, Some(other)) => Some(other),
            (Some(mut base), Some(other)) => {
                // 已知禁用 / 撤销只被新的明确 current 回答翻篇(设计稿:None / Unknown
                // 不能覆盖已知禁用);历史版本回答和推导回答不描述当前状态,不能覆盖。
                let can_clear_disabled = other.query.is_current() && !other.derived;
                if other.did_state.is_some() {
                    let keep_base = !can_clear_disabled
                        && base.did_state.as_ref().map_or(false, DidState::is_disabled)
                        && !other
                            .did_state
                            .as_ref()
                            .map_or(false, DidState::is_disabled);
                    if !keep_base {
                        base.did_state = other.did_state.clone();
                    }
                }
                if other.type_state.is_some() {
                    let keep_base = !can_clear_disabled
                        && base
                            .type_state
                            .as_ref()
                            .map_or(false, TypeState::is_disabled)
                        && !other
                            .type_state
                            .as_ref()
                            .map_or(false, TypeState::is_disabled);
                    if !keep_base {
                        base.type_state = other.type_state.clone();
                    }
                }
                if other.owner_binding.is_some() {
                    base.owner_binding = other.owner_binding.clone();
                }
                for record in other.records {
                    base.records.retain(|existing| existing.iat != record.iat);
                    if record.is_latest {
                        for existing in base.records.iter_mut() {
                            if existing.iat < record.iat {
                                existing.is_latest = false;
                            }
                        }
                    }
                    base.records.push(record);
                }
                if let Some(latest) = other.latest_iat {
                    base.latest_iat = Some(base.latest_iat.map_or(latest, |b| b.max(latest)));
                }
                if other.boundary.is_some() && other.query == base.query {
                    base.boundary = other.boundary;
                }
                if other.checked_at.is_some() {
                    base.checked_at = other.checked_at;
                }
                base.valid_until = match (base.valid_until, other.valid_until) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                if other.source.is_some() {
                    base.source = other.source;
                }
                base.simulated = base.simulated || other.simulated;
                base.derived = base.derived && other.derived;
                base.reasons.extend(other.reasons);
                Some(base)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> DID {
        DID::new("bns", "alice")
    }

    fn current_answer(iat: u64, hash: &str) -> PublishInfo {
        PublishInfo::new(did(), DidDocType::Owner, Revision::current())
            .with_status(&DocumentStatus::Active, None, None)
            .with_record(PublishRecord::published(iat, hash, true))
    }

    #[test]
    fn closest_derives_only_after_latest() {
        let current = current_answer(100, "aa");
        let derived = current.derive_for(&Revision::closest(150)).unwrap();
        assert!(derived.derived);
        assert_eq!(
            derived.satisfies(&Revision::closest(150)),
            Some(DocRevision::new(100, "aa"))
        );
        assert!(current.derive_for(&Revision::closest(100)).is_none());
        assert!(current.derive_for(&Revision::closest(50)).is_none());
    }

    #[test]
    fn exact_derives_on_latest_hit_and_future_iat() {
        let current = current_answer(100, "aa");
        assert!(current
            .derive_for(&Revision::exact(100, "AA"))
            .unwrap()
            .satisfies(&Revision::exact(100, "aa"))
            .is_some());
        let future = current.derive_for(&Revision::exact(200, "bb")).unwrap();
        assert_eq!(future.record_for(200).map(|r| r.published), Some(false));
        assert!(current.derive_for(&Revision::exact(50, "cc")).is_none());
        // 同 iat 不同 hash:latest 已占该 iat,不推导(由真正的 exact 查询回答)。
        assert!(current.derive_for(&Revision::exact(100, "zz")).is_none());
    }

    #[test]
    fn merge_keeps_known_negative_state() {
        let revoked = PublishInfo::new(did(), DidDocType::Zone, Revision::current())
            .with_status(&DocumentStatus::Revoked, None, None);
        // 没有回答、历史版本回答都不能覆盖已知撤销。
        let merged = PublishInfo::merge(Some(revoked.clone()), None).unwrap();
        assert!(merged.is_disabled());
        let historical_active = PublishInfo::new(
            did(),
            DidDocType::Zone,
            Revision::exact(10, "aa"),
        )
        .with_status(&DocumentStatus::Active, None, None);
        let merged = PublishInfo::merge(Some(revoked.clone()), Some(historical_active)).unwrap();
        assert!(merged.is_disabled());
        let mut derived_active = PublishInfo::new(did(), DidDocType::Zone, Revision::current())
            .with_status(&DocumentStatus::Active, None, None);
        derived_active.derived = true;
        let merged = PublishInfo::merge(Some(revoked.clone()), Some(derived_active)).unwrap();
        assert!(merged.is_disabled());
        // 新的明确 current 回答(如重新签发后 authority 回答 active)可以翻篇。
        let active = PublishInfo::new(did(), DidDocType::Zone, Revision::current())
            .with_status(&DocumentStatus::Active, None, None);
        let merged = PublishInfo::merge(Some(revoked), Some(active)).unwrap();
        assert!(!merged.is_disabled());
        let invalid = PublishInfo::new(did(), DidDocType::Device, Revision::current())
            .with_status(&DocumentStatus::Invalid, Some("mismatch".into()), None);
        assert!(!invalid.is_disabled());
        assert!(invalid.type_state.as_ref().unwrap().is_not_exist());
        assert_eq!(invalid.cache_ttl_secs(), INVALID_STATE_TTL_SECS);
    }
}
