//! 结果存储(TODO D2):`doc_result` 按 `(scope, did, doc_type)` 保存,跨进程原子合并。
//!
//! 后端评估结论:workspace 已有的 `redb` 是**单进程独占打开**(第二个进程打开同一
//! 文件得到 `DatabaseAlreadyOpen`),而同一主机上的 node_daemon、cyfs-gateway、
//! 各服务进程都持有各自的 NameClient 并共享同一缓存目录,所以 redb 不满足"跨进程
//! 原子合并"。这里采用"每键一个 JSON 文件 + 同名 `.lock` 文件上的 OS 文件锁
//! (`std::fs::File::lock`)"做读-改-写:锁内重读存储中的最新结果再合并(段 2),
//! 不持锁等待任何网络 I/O。内存后端提供同样的串行语义。
//!
//! 目录布局(`{cache_dir}`):
//! - `results/{scope}/{did_filename}.{doc_type}.json`:结果文件,只有 name-client
//!   特权进程可写(目录权限由部署保证);
//! - `unverified/`:收件箱。其它本机进程投递候选只能放到这里,文件名
//!   `{did_filename}.doc.json`(旧协议)或 `{did_filename}.{doc_type}.doc.json`;
//!   收件箱里的文档一律按 `Source::normal()` 进入 candidates;
//! - 查询回答缓存与 receipt 只在进程内存中,不落盘。

use super::doc_result::DocResult;
use super::opts::Scope;
use super::source::SourceAnswer;
use super::clock::unix_now;
use buckyos_kit::get_buckyos_service_local_data_dir;
use log::{debug, warn};
use name_lib::{DidDocType, EncodedDocument, NSError, NSResult, DID};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// 本机 DID 文档缓存的存储后端。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheBackend {
    Filesystem,
    Memory,
}

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 进程内查询回答缓存条目(带绝对过期时刻)。
#[derive(Clone, Debug)]
struct CachedAnswer {
    answer: SourceAnswer,
    valid_until: u64,
}

enum Backend {
    Memory(Mutex<HashMap<String, DocResult>>),
    Files { dir: PathBuf },
}

/// 收件箱里的一份候选。
#[derive(Clone, Debug)]
pub struct InboxDocument {
    pub document: EncodedDocument,
    pub source: String,
}

pub struct DocStore {
    backend: Backend,
    /// `allow_local_cache=false` 时使用的内存后端(语义不变)。
    memory_only: Mutex<HashMap<String, DocResult>>,
    query_cache: Mutex<HashMap<String, CachedAnswer>>,
    inbox_dirs: Vec<PathBuf>,
}

impl DocStore {
    pub fn default_cache_dir() -> PathBuf {
        get_buckyos_service_local_data_dir("did_docs")
    }

    pub fn new_memory() -> Arc<Self> {
        Arc::new(Self {
            backend: Backend::Memory(Mutex::new(HashMap::new())),
            memory_only: Mutex::new(HashMap::new()),
            query_cache: Mutex::new(HashMap::new()),
            inbox_dirs: Vec::new(),
        })
    }

    pub fn new_files(dir: Option<PathBuf>) -> Arc<Self> {
        let dir = dir.unwrap_or_else(Self::default_cache_dir);
        for sub in ["results", "unverified", "inbox"] {
            if let Err(err) = fs::create_dir_all(dir.join(sub)) {
                warn!(
                    "prepare did cache directory {} failed: {}",
                    dir.join(sub).display(),
                    err
                );
            }
        }
        debug!("doc store directory: {}", dir.display());
        Arc::new(Self {
            inbox_dirs: vec![dir.join("unverified"), dir.join("inbox")],
            backend: Backend::Files { dir },
            memory_only: Mutex::new(HashMap::new()),
            query_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn new(backend: CacheBackend, dir: Option<PathBuf>) -> Arc<Self> {
        match backend {
            CacheBackend::Memory => Self::new_memory(),
            CacheBackend::Filesystem => Self::new_files(dir),
        }
    }

    pub fn is_persistent(&self) -> bool {
        matches!(self.backend, Backend::Files { .. })
    }

    pub fn cache_dir(&self) -> Option<&Path> {
        match &self.backend {
            Backend::Files { dir } => Some(dir),
            Backend::Memory(_) => None,
        }
    }

    pub fn result_key(scope: &Scope, did: &DID, doc_type: &DidDocType) -> String {
        format!("{}/{}.{}", scope.key(), did.to_filename(), doc_type.as_str())
    }

    fn result_path(dir: &Path, scope: &Scope, did: &DID, doc_type: &DidDocType) -> PathBuf {
        let scope_dir = match scope {
            Scope::Host => "host".to_string(),
            Scope::Zone(zone) => format!("zone.{}", zone.to_filename()),
        };
        dir.join("results")
            .join(scope_dir)
            .join(format!("{}.{}.json", did.to_filename(), doc_type.as_str()))
    }

    // ---------- doc_result ----------

    /// 读取结果快照(不加锁;等待者在段 2 重读)。
    pub fn get_doc_result(
        &self,
        scope: &Scope,
        did: &DID,
        doc_type: &DidDocType,
        use_disk: bool,
    ) -> Option<DocResult> {
        let key = Self::result_key(scope, did, doc_type);
        if !use_disk {
            return self.memory_only.lock().unwrap().get(&key).cloned();
        }
        match &self.backend {
            Backend::Memory(map) => map.lock().unwrap().get(&key).cloned(),
            Backend::Files { dir } => {
                let path = Self::result_path(dir, scope, did, doc_type);
                read_result_file(&path)
            }
        }
    }

    /// 段 2:在同键锁内重读存储中的最新结果并原子合并。返回合并后的结果与冲突。
    pub fn merge_doc_result(
        &self,
        scope: &Scope,
        did: &DID,
        doc_type: &DidDocType,
        local: DocResult,
        use_disk: bool,
    ) -> NSResult<(DocResult, Option<super::revision::DocRevision>)> {
        let key = Self::result_key(scope, did, doc_type);
        if !use_disk {
            let mut map = self.memory_only.lock().unwrap();
            let (merged, conflict) = DocResult::merge_into(map.get(&key).cloned(), local);
            map.insert(key, merged.clone());
            return Ok((merged, conflict));
        }
        match &self.backend {
            Backend::Memory(map) => {
                let mut map = map.lock().unwrap();
                let (merged, conflict) = DocResult::merge_into(map.get(&key).cloned(), local);
                map.insert(key, merged.clone());
                Ok((merged, conflict))
            }
            Backend::Files { dir } => {
                let path = Self::result_path(dir, scope, did, doc_type);
                let _guard = FileLock::acquire(&path)?;
                let stored = read_result_file(&path);
                let (merged, conflict) = DocResult::merge_into(stored, local);
                write_result_file(&path, &merged)?;
                Ok((merged, conflict))
            }
        }
    }

    /// 删除普通文档 body;不隐式解锁,不把已知禁用 / 撤销变成从未见过。
    pub fn remove_document_bodies(
        &self,
        scope: &Scope,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<()> {
        let key = Self::result_key(scope, did, doc_type);
        let strip = |result: &mut DocResult| {
            result.latest = None;
            result.best = None;
            result.history.clear();
            result.candidates.clear();
            result.slots.clear();
            result.publish_info = None;
            result.publish_info_valid_until = None;
            result.generation += 1;
            result.updated_at = unix_now();
        };
        if let Some(result) = self.memory_only.lock().unwrap().get_mut(&key) {
            strip(result);
        }
        match &self.backend {
            Backend::Memory(map) => {
                if let Some(result) = map.lock().unwrap().get_mut(&key) {
                    strip(result);
                }
            }
            Backend::Files { dir } => {
                let path = Self::result_path(dir, scope, did, doc_type);
                let _guard = FileLock::acquire(&path)?;
                if let Some(mut stored) = read_result_file(&path) {
                    strip(&mut stored);
                    write_result_file(&path, &stored)?;
                }
            }
        }
        self.invalidate_query_answers(did, doc_type);
        Ok(())
    }

    // ---------- 查询回答缓存(进程内) ----------

    pub fn get_query_answer(&self, key: &str) -> Option<SourceAnswer> {
        let now = unix_now();
        let cache = self.query_cache.lock().unwrap();
        cache
            .get(key)
            .filter(|entry| entry.valid_until > now)
            .map(|entry| entry.answer.clone())
    }

    pub fn set_query_answer(&self, key: String, answer: SourceAnswer, ttl_secs: u64) {
        let now = unix_now();
        let mut cache = self.query_cache.lock().unwrap();
        if cache.len() > 4096 {
            cache.retain(|_, entry| entry.valid_until > now);
        }
        if cache.len() > 8192 {
            cache.clear();
        }
        cache.insert(
            key,
            CachedAnswer {
                answer,
                valid_until: now + ttl_secs.max(1),
            },
        );
    }

    pub fn invalidate_query_answers(&self, did: &DID, doc_type: &DidDocType) {
        let needle = format!("|{}|{}|", did.to_string(), doc_type.as_str());
        let mut cache = self.query_cache.lock().unwrap();
        cache.retain(|key, _| !key.contains(&needle));
    }

    // ---------- 收件箱 ----------

    /// 读取收件箱中投递给 `(did, doc_type)` 的候选。旧协议文件名不带 doc_type,
    /// 由调用方按 body 内容判断是否匹配(`DocResult::commit` 会检查身份与类型)。
    pub fn collect_inbox(&self, did: &DID, doc_type: &DidDocType) -> Vec<InboxDocument> {
        let mut found = Vec::new();
        let filename = did.to_filename();
        for dir in &self.inbox_dirs {
            for name in [
                format!("{}.{}.doc.json", filename, doc_type.as_str()),
                format!("{}.doc.json", filename),
            ] {
                let path = dir.join(&name);
                let Ok(content) = fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(document) = EncodedDocument::from_str(content.trim().to_string()) else {
                    warn!("inbox file {} is not a DID document", path.display());
                    continue;
                };
                let source = fs::read_to_string(dir.join(name.replace(".doc.json", ".meta.json")))
                    .ok()
                    .and_then(|meta| serde_json::from_str::<serde_json::Value>(&meta).ok())
                    .and_then(|meta| meta.get("source").and_then(|s| s.as_str()).map(String::from))
                    .unwrap_or_else(|| "inbox".to_string());
                found.push(InboxDocument {
                    document,
                    source: format!("inbox:{}", source),
                });
            }
        }
        found
    }

    /// 进程内投递的候选写入收件箱目录(与文件系统协议等价),便于其它进程也能看到。
    pub fn write_inbox(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        document: &EncodedDocument,
        source: &str,
    ) -> NSResult<()> {
        let Some(dir) = self.inbox_dirs.first() else {
            return Ok(());
        };
        let name = format!("{}.{}.doc.json", did.to_filename(), doc_type.as_str());
        write_atomic(&dir.join(&name), &document.to_string())?;
        let meta = serde_json::json!({
            "source": source,
            "observed_at": unix_now(),
        });
        write_atomic(&dir.join(name.replace(".doc.json", ".meta.json")), &meta.to_string())
    }
}

fn read_result_file(path: &Path) -> Option<DocResult> {
    let content = fs::read_to_string(path).ok()?;
    match serde_json::from_str::<DocResult>(&content) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!("doc result file {} is corrupt: {}", path.display(), err);
            None
        }
    }
}

fn write_result_file(path: &Path, result: &DocResult) -> NSResult<()> {
    let content = serde_json::to_string(result)
        .map_err(|err| NSError::Failed(format!("serialize doc result failed: {}", err)))?;
    write_atomic(path, &content)
}

/// 两段式原子写:先写同目录下的临时文件,再 rename 进目标位置。
fn write_atomic(target: &Path, content: &str) -> NSResult<()> {
    let parent = target
        .parent()
        .ok_or_else(|| NSError::Failed("invalid cache path".to_string()))?;
    fs::create_dir_all(parent)
        .map_err(|err| NSError::Failed(format!("create {} failed: {}", parent.display(), err)))?;
    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        target
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "entry".to_string()),
        std::process::id(),
        TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    {
        let mut file = fs::File::create(&tmp_path)
            .map_err(|err| NSError::Failed(format!("create {} failed: {}", tmp_path.display(), err)))?;
        file.write_all(content.as_bytes())
            .map_err(|err| NSError::Failed(format!("write {} failed: {}", tmp_path.display(), err)))?;
        let _ = file.sync_data();
    }
    fs::rename(&tmp_path, target).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        NSError::Failed(format!("rename {} failed: {}", target.display(), err))
    })
}

/// 跨进程文件锁:同键 `.lock` 文件上的独占锁。
struct FileLock {
    file: fs::File,
}

impl FileLock {
    fn acquire(result_path: &Path) -> NSResult<Self> {
        let lock_path = result_path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                NSError::Failed(format!("create {} failed: {}", parent.display(), err))
            })?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|err| NSError::Failed(format!("open {} failed: {}", lock_path.display(), err)))?;
        file.lock()
            .map_err(|err| NSError::Failed(format!("lock {} failed: {}", lock_path.display(), err)))?;
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::super::doc_result::DocResult;
    use super::super::revision::DocRevision;
    use super::super::source::SourceRef;
    use super::*;
    use serde_json::json;

    fn did() -> DID {
        DID::new("bns", "zone1.alice")
    }

    fn candidate(marker: &str) -> (EncodedDocument, DocRevision) {
        let doc = EncodedDocument::JsonLd(json!({
            "id": "did:bns:zone1.alice", "iat": 1000, "exp": 2_000_000_000, "marker": marker
        }));
        let rev = DocRevision::of(&doc).unwrap();
        (doc, rev)
    }

    #[test]
    fn file_store_merges_across_instances_like_processes() {
        let tmp = tempfile::tempdir().unwrap();
        let a = DocStore::new_files(Some(tmp.path().to_path_buf()));
        let b = DocStore::new_files(Some(tmp.path().to_path_buf()));
        let scope = Scope::Host;

        let mut local_a = DocResult::empty(scope.clone(), did(), DidDocType::Zone);
        let (doc_a, rev_a) = candidate("a");
        local_a.add_candidate(doc_a, rev_a.clone(), SourceRef::normal("a"));
        a.merge_doc_result(&scope, &did(), &DidDocType::Zone, local_a, true)
            .unwrap();

        let mut local_b = DocResult::empty(scope.clone(), did(), DidDocType::Zone);
        let (doc_b, rev_b) = candidate("b");
        local_b.add_candidate(doc_b, rev_b.clone(), SourceRef::normal("b"));
        let (merged, _) = b
            .merge_doc_result(&scope, &did(), &DidDocType::Zone, local_b, true)
            .unwrap();
        assert_eq!(merged.candidates.len(), 2, "both processes' candidates survive");
        assert_eq!(merged.generation, 2);

        let reread = a.get_doc_result(&scope, &did(), &DidDocType::Zone, true).unwrap();
        assert_eq!(reread.candidates.len(), 2);

        a.remove_document_bodies(&scope, &did(), &DidDocType::Zone).unwrap();
        let after = b.get_doc_result(&scope, &did(), &DidDocType::Zone, true).unwrap();
        assert!(after.candidates.is_empty());
    }

    #[test]
    fn inbox_files_are_collected_as_normal_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DocStore::new_files(Some(tmp.path().to_path_buf()));
        let (doc, _) = candidate("inbox");
        fs::write(
            tmp.path()
                .join("unverified")
                .join(format!("{}.doc.json", did().to_filename())),
            doc.to_string(),
        )
        .unwrap();
        let found = store.collect_inbox(&did(), &DidDocType::Zone);
        assert_eq!(found.len(), 1);
        assert!(found[0].source.starts_with("inbox"));
        store
            .write_inbox(&did(), &DidDocType::Zone, &doc, "push")
            .unwrap();
        assert_eq!(store.collect_inbox(&did(), &DidDocType::Zone).len(), 2);
    }

    #[test]
    fn query_answers_expire() {
        let store = DocStore::new_memory();
        let answer = SourceAnswer::no_answer(SourceRef::normal("x"), "na");
        store.set_query_answer("k|did:bns:a|zone|current".into(), answer, 1);
        assert!(store.get_query_answer("k|did:bns:a|zone|current").is_some());
        store.invalidate_query_answers(&DID::new("bns", "a"), &DidDocType::Zone);
        assert!(store.get_query_answer("k|did:bns:a|zone|current").is_none());
    }
}
