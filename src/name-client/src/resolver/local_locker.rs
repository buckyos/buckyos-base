//! 本机 locker(设计稿 §2.1):按 `/etc/hosts` 模型优先且强制回答,可以在本机
//! scope 内覆盖根材料或模拟发布,但不能冒充公网权威回答;结果不写入普通来源缓存。
//!
//! 只能由本机管理员、测试框架或显式运维命令写入;配置版本号进入验证报告的
//! `locker_version`,配置变化使相关验证缓存重判。

use super::publish_info::{Boundary, DocumentStatus, PublishInfo, PublishRecord, TypeState};
use super::revision::{DocRevision, ParsedDocument, Revision};
use super::source::{Carrier, SourceAnswer, SourceRef};
use buckyos_kit::buckyos_get_unix_timestamp;
use log::warn;
use name_lib::{DidDocType, EncodedDocument, NSError, NSResult, DID};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockOptions {
    /// 记录写入者声明的作用域(machine / test-env / CI job),仅诊断。
    #[serde(default)]
    pub scope: String,
    /// `None` 表示不过期。
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// 模拟发布:回答 publish_info(当前版本 = 锁定文档)。默认 true。
    #[serde(default = "default_true")]
    pub simulate_publish: bool,
    /// 把锁定文档当作该 scope 内的**完整历史**:对任意 `closest(iat)` 都回答它
    /// (Root Trust 场景:激活时合成的 Owner 文档 iat 为合成时刻,却要为更早签发的
    /// 设备 / Zone 文档充当签发时 owner)。默认 false:锁定的当前文档不冒充历史目标。
    #[serde(default)]
    pub simulate_history: bool,
}

fn default_true() -> bool {
    true
}

impl Default for LockOptions {
    fn default() -> Self {
        Self {
            scope: "machine".to_string(),
            expires_at: None,
            simulate_publish: true,
            simulate_history: false,
        }
    }
}

#[derive(Debug, Clone)]
struct LockedEntry {
    document: Option<EncodedDocument>,
    negative: Option<TypeState>,
    options: LockOptions,
}

/// 配置文件里的一条锁定记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedDocumentConfig {
    pub did: String,
    pub doc_type: String,
    #[serde(default)]
    pub document: Option<serde_json::Value>,
    /// `"missing"` / `"revoked"` / `"invalid"` 等负状态(与 document 二选一)。
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub options: LockOptions,
}

#[derive(Debug, Default)]
pub struct LocalLocker {
    entries: RwLock<HashMap<(DID, String), LockedEntry>>,
    version: AtomicU64,
}

impl LocalLocker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    fn bump(&self) {
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    pub fn lock_document(
        &self,
        did: DID,
        doc_type: &DidDocType,
        document: EncodedDocument,
        options: LockOptions,
    ) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(
            (did, doc_type.to_string()),
            LockedEntry {
                document: Some(document),
                negative: None,
                options,
            },
        );
        drop(entries);
        self.bump();
    }

    /// 强制负回答(明确不存在 / 禁用),不能当 miss 回退。
    pub fn lock_negative(&self, did: DID, doc_type: &DidDocType, state: TypeState, options: LockOptions) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(
            (did, doc_type.to_string()),
            LockedEntry {
                document: None,
                negative: Some(state),
                options,
            },
        );
        drop(entries);
        self.bump();
    }

    pub fn unlock(&self, did: &DID, doc_type: &DidDocType) {
        let removed = self
            .entries
            .write()
            .unwrap()
            .remove(&(did.clone(), doc_type.to_string()))
            .is_some();
        if removed {
            self.bump();
        }
    }

    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
        self.bump();
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 从 JSON 配置文件加载(数组形式的 [`LockedDocumentConfig`])。
    pub fn load_file(&self, path: &Path) -> NSResult<usize> {
        let content = fs_read(path)?;
        let configs: Vec<LockedDocumentConfig> = serde_json::from_str(&content).map_err(|err| {
            NSError::Failed(format!("parse locker config {}: {}", path.display(), err))
        })?;
        let mut loaded = 0;
        for config in configs {
            let did = DID::from_str(&config.did)?;
            let doc_type = DidDocType::from(config.doc_type.as_str());
            if let Some(document) = config.document {
                let document = match document {
                    serde_json::Value::String(jwt) => EncodedDocument::Jwt(jwt),
                    other => EncodedDocument::JsonLd(other),
                };
                self.lock_document(did, &doc_type, document, config.options);
                loaded += 1;
            } else if let Some(status) = config.status {
                let state = match status.as_str() {
                    "missing" => TypeState::Missing,
                    "revoked" => TypeState::Revoked,
                    "invalid" => TypeState::Invalid {
                        reason: config.reason.unwrap_or_else(|| "locked invalid".to_string()),
                    },
                    other => {
                        warn!("locker config {}: unsupported status {}", config.did, other);
                        continue;
                    }
                };
                self.lock_negative(did, &doc_type, state, config.options);
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    fn entry(&self, did: &DID, doc_type: &DidDocType) -> Option<LockedEntry> {
        let entries = self.entries.read().unwrap();
        let entry = entries.get(&(did.clone(), doc_type.to_string()))?;
        if let Some(expires_at) = entry.options.expires_at {
            if expires_at <= buckyos_get_unix_timestamp() {
                return None;
            }
        }
        Some(entry.clone())
    }

    /// 锁定文档的身份:供"锁定的 owner 文档"等诊断。
    pub fn locked_revision(&self, did: &DID, doc_type: &DidDocType) -> Option<DocRevision> {
        self.entry(did, doc_type)?
            .document
            .as_ref()
            .and_then(DocRevision::of)
    }

    fn publish_info_for(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        entry: &LockedEntry,
    ) -> Option<PublishInfo> {
        if let Some(negative) = entry.negative.as_ref() {
            let status = negative.to_document_status();
            let reason = match negative {
                TypeState::Invalid { reason } => Some(reason.clone()),
                _ => None,
            };
            let mut info = PublishInfo::new(did.clone(), doc_type.clone(), revision.clone())
                .with_status(&status, reason, None)
                .with_source("local-locker");
            info.simulated = true;
            return Some(info);
        }
        if !entry.options.simulate_publish {
            return None;
        }
        let document = entry.document.as_ref()?;
        let doc_revision = DocRevision::of(document)?;
        let mut info = PublishInfo::new(did.clone(), doc_type.clone(), revision.clone())
            .with_status(&DocumentStatus::Active, None, None)
            .with_record(PublishRecord::published(doc_revision.iat, &doc_revision.hash, true))
            .with_source("local-locker");
        info.simulated = true;
        match revision {
            Revision::Current => {}
            Revision::Exact { iat, hash } => {
                if *iat != doc_revision.iat || *hash != doc_revision.hash {
                    if *iat > doc_revision.iat || entry.options.simulate_history {
                        info.records.push(PublishRecord::not_published(*iat));
                    } else {
                        // 锁定的当前文档不能冒充历史目标:本 locker 无意见。
                        return None;
                    }
                }
            }
            Revision::Closest { before_iat } => {
                if *before_iat > doc_revision.iat || entry.options.simulate_history {
                    info.boundary = Some(Boundary {
                        query_iat: *before_iat,
                        selected: Some(doc_revision),
                        confirmed: true,
                    });
                } else {
                    return None;
                }
            }
        }
        Some(info)
    }

    /// 文档列。Unknown / 未覆盖归一为 None;明确不存在 / 禁用仍是强制回答。
    pub fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
    ) -> Option<SourceAnswer> {
        let entry = self.entry(did, doc_type)?;
        let sref = SourceRef::local_locker();
        let mut answer = SourceAnswer::new(sref);
        answer.cacheable = false;
        if let Some(document) = entry.document.as_ref() {
            if ParsedDocument::parse(document).is_err() {
                warn!("locked document for {}#{} is unparsable", did.to_string(), doc_type);
                return None;
            }
            answer = answer.with_body(document.clone(), Carrier::Locker);
        }
        if let Some(info) = self.publish_info_for(did, doc_type, revision, &entry) {
            answer = answer.with_publish_info(info);
        }
        if answer.is_unknown() {
            return None;
        }
        Some(answer)
    }

    /// 发布信息列。缺席(未模拟发布)返回 None,继续向后查。
    pub fn get_publish_info(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
    ) -> Option<PublishInfo> {
        let entry = self.entry(did, doc_type)?;
        self.publish_info_for(did, doc_type, revision, &entry)
    }
}

fn fs_read(path: &Path) -> NSResult<String> {
    std::fs::read_to_string(path)
        .map_err(|err| NSError::ReadLocalFileError(format!("{}: {}", path.display(), err)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn locker_answers_current_and_derived_queries_in_scope() {
        let locker = LocalLocker::new();
        let did = DID::new("bns", "alice");
        let doc = EncodedDocument::JsonLd(json!({"id": "did:bns:alice", "iat": 100, "exp": 2_000_000_000}));
        locker.lock_document(did.clone(), &DidDocType::Owner, doc.clone(), LockOptions::default());
        assert_eq!(locker.version(), 1);

        let current = locker.get_document(&did, &DidDocType::Owner, &Revision::current()).unwrap();
        assert!(current.body.is_some() && current.publish_info.as_ref().unwrap().simulated);
        assert!(locker.get_document(&did, &DidDocType::Owner, &Revision::closest(150)).is_some());
        let before = locker.get_document(&did, &DidDocType::Owner, &Revision::closest(50)).unwrap();
        assert!(before.publish_info.is_none(), "closest before the locked doc is not simulated");
        assert!(locker.get_document(&did, &DidDocType::Zone, &Revision::current()).is_none());

        locker.lock_negative(did.clone(), &DidDocType::Zone, TypeState::Missing, LockOptions::default());
        let negative = locker.get_document(&did, &DidDocType::Zone, &Revision::current()).unwrap();
        assert!(negative.body.is_none());
        assert!(negative.publish_info.unwrap().type_state.unwrap().is_not_exist());
        locker.unlock(&did, &DidDocType::Zone);
        assert_eq!(locker.version(), 3);

        // Root Trust:simulate_history 时对更早的 closest 也回答锁定文档。
        locker.lock_document(
            did.clone(),
            &DidDocType::Owner,
            doc,
            LockOptions {
                simulate_history: true,
                ..Default::default()
            },
        );
        let before = locker.get_document(&did, &DidDocType::Owner, &Revision::closest(50)).unwrap();
        assert!(before.publish_info.unwrap().satisfies(&Revision::closest(50)).is_some());
    }
}
