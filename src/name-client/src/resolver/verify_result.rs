//! 验证报告(设计稿 §2.3):"签名正确""当前有效""命中查询目标""业务允许使用"
//! 是不同结论。

use super::publish_info::{Boundary, PublishRecord};
use super::revision::{DocRevision, Revision};
use super::source::SourceTier;
use super::clock::unix_now;
use name_lib::{DidDocType, DID};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validity {
    Valid,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyRole {
    CurrentOwner,
    SigningOwner,
}

/// 验证依赖(第一期只填 owner;`refresh_known_constraints` 遍历它而不是只看 owner)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub did: DID,
    pub doc_type: DidDocType,
    pub revision: DocRevision,
    pub role: DependencyRole,
    pub query: Revision,
    /// 依赖由 locker 模拟发布满足:locker 配置变化时需要重验。
    #[serde(default)]
    pub simulated: bool,
}

/// 发布依据:来源、是否 locker 模拟、命中的记录与查询边界。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishEvidence {
    pub source: String,
    pub simulated: bool,
    pub derived: bool,
    pub record: PublishRecord,
    pub query: Revision,
    pub boundary: Option<Boundary>,
    pub checked_at: u64,
    /// 来源声明的回答有效期(`validUntil`);查询槽不能比它活得更久。
    #[serde(default)]
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub validity: Validity,
    /// 实际签名核验通过;authority / trust 免签不能设置它。
    pub is_signed: bool,
    /// 输入的确切版本有发布依据;locker 模拟发布保留来源标记。
    pub is_published: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub is_disabled: bool,
    pub is_best: bool,
    pub is_latest: bool,
    pub is_exact: bool,
    pub is_closest: bool,
    pub reasons: Vec<String>,
    pub missing: Vec<String>,
    pub dependencies: Vec<Dependency>,
    pub locker_version: u64,
    #[serde(default)]
    pub publish_evidence: Option<PublishEvidence>,
    #[serde(default)]
    pub revision: Option<DocRevision>,
    #[serde(default)]
    pub doc_type: Option<DidDocType>,
    #[serde(default)]
    pub requested_doc_type: Option<DidDocType>,
    #[serde(default)]
    pub source_tier: Option<SourceTier>,
    #[serde(default)]
    pub source_id: Option<String>,
    /// 同 iat 不同 hash 的冲突对象。
    #[serde(default)]
    pub conflict: Option<DocRevision>,
    pub verified_at: u64,
    /// 本次验证实际发出的权威 receipt 来源(用于 AuthorityCurrent 门禁)。
    #[serde(default)]
    pub authority_receipt: Option<String>,
    /// 本次验证使用的可信 owner 绑定(权威绑定或名字结构);authority / trust 免签
    /// 路径没有 owner 依赖项时调用方据此取 owner。
    #[serde(default)]
    pub owner_binding: Option<DID>,
}

impl VerifyResult {
    pub fn new(locker_version: u64) -> Self {
        Self {
            validity: Validity::Unknown,
            is_signed: false,
            is_published: false,
            is_revoked: false,
            is_expired: false,
            is_disabled: false,
            is_best: false,
            is_latest: false,
            is_exact: false,
            is_closest: false,
            reasons: Vec::new(),
            missing: Vec::new(),
            dependencies: Vec::new(),
            locker_version,
            publish_evidence: None,
            revision: None,
            doc_type: None,
            requested_doc_type: None,
            source_tier: None,
            source_id: None,
            conflict: None,
            verified_at: unix_now(),
            authority_receipt: None,
            owner_binding: None,
        }
    }

    pub fn invalid(mut self, reason: impl Into<String>) -> Self {
        self.validity = Validity::Invalid;
        self.reasons.push(reason.into());
        self.clear_selection_flags();
        self
    }

    pub fn unknown(mut self, reason: impl Into<String>) -> Self {
        self.validity = Validity::Unknown;
        self.missing.push(reason.into());
        self.clear_selection_flags();
        self
    }

    pub fn add_reason(&mut self, reason: impl Into<String>) {
        self.reasons.push(reason.into());
    }

    pub fn add_missing(&mut self, missing: impl Into<String>) {
        self.missing.push(missing.into());
    }

    pub fn remember_dependency(
        &mut self,
        did: &DID,
        revision: DocRevision,
        role: DependencyRole,
        query: Revision,
        simulated: bool,
    ) {
        self.dependencies.push(Dependency {
            did: did.clone(),
            doc_type: DidDocType::Owner,
            revision,
            role,
            query,
            simulated,
        });
    }

    pub fn clear_selection_flags(&mut self) {
        self.is_best = false;
        self.is_latest = false;
        self.is_exact = false;
        self.is_closest = false;
    }

    pub fn is_valid(&self) -> bool {
        self.validity == Validity::Valid
    }

    pub fn is_owner(&self) -> bool {
        self.doc_type == Some(DidDocType::Owner)
    }

    /// 已知错误 / 过期 / 禁用 / 撤销 → invalid;缺必要材料 → unknown;
    /// 否则 trusted → valid。不把未查询到的发布信息当缺少必要材料。
    pub fn finish(mut self, trusted: bool) -> Self {
        if self.validity == Validity::Invalid
            || self.is_expired
            || self.is_disabled
            || self.is_revoked
        {
            self.validity = Validity::Invalid;
            if self.is_expired && !self.reasons.iter().any(|r| r.contains("expired")) {
                self.reasons.push("document expired".to_string());
            }
            if self.is_revoked && !self.reasons.iter().any(|r| r.contains("revoked")) {
                self.reasons.push("document revoked".to_string());
            }
            if self.is_disabled && !self.reasons.iter().any(|r| r.contains("disabled")) {
                self.reasons.push("document disabled".to_string());
            }
            self.clear_selection_flags();
            return self;
        }
        if !self.missing.is_empty() || !trusted {
            self.validity = Validity::Unknown;
            if !trusted && self.missing.is_empty() {
                self.missing.push("document is not trusted".to_string());
            }
            self.clear_selection_flags();
            return self;
        }
        self.validity = Validity::Valid;
        self
    }

    /// validity 为 valid 且命中目标;exact / closest 还必须有对应发布查询依据。
    pub fn success(&self, revision: &Revision) -> bool {
        if !self.is_valid() {
            return false;
        }
        match revision {
            Revision::Current => {
                if self.is_owner() {
                    self.is_latest
                } else {
                    self.is_best
                }
            }
            Revision::Exact { .. } => self.is_exact && self.publish_evidence.is_some(),
            Revision::Closest { .. } => self.is_closest && self.publish_evidence.is_some(),
        }
    }

    pub fn reason(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.reasons.iter().cloned());
        parts.extend(self.missing.iter().map(|m| format!("missing: {}", m)));
        if parts.is_empty() {
            match self.validity {
                Validity::Valid => "valid".to_string(),
                Validity::Invalid => "invalid".to_string(),
                Validity::Unknown => "unknown".to_string(),
            }
        } else {
            parts.join("; ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_prioritizes_known_errors_over_missing() {
        let mut report = VerifyResult::new(0);
        report.is_signed = true;
        report.is_revoked = true;
        report.add_missing("whatever");
        let report = report.finish(true);
        assert_eq!(report.validity, Validity::Invalid);
        assert!(report.is_signed);
        assert!(!report.success(&Revision::current()));

        let report = {
            let mut r = VerifyResult::new(0);
            r.add_missing("owner");
            r.finish(true)
        };
        assert_eq!(report.validity, Validity::Unknown);

        let mut report = VerifyResult::new(0).finish(true);
        assert_eq!(report.validity, Validity::Valid);
        report.is_best = true;
        assert!(report.success(&Revision::current()));
        assert!(!report.success(&Revision::exact(1, "a")));
    }
}
