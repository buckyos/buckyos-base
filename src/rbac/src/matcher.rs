//! Cached versions of the regex-based Casbin matcher functions.
//!
//! Casbin 2.x builds every `Regex` on every call: `keyGet3` compiles three,
//! `keyMatch3` and `regexMatch` one each. A Unicode class such as `[^/]` makes
//! each compile initialise a ~320 KB table, and the BuckyOS matcher calls
//! `keyGet3` up to four times per policy line, so authorization was dominated
//! by allocation and page faults.
//!
//! The functions below keep Casbin's pattern rewriting, capture numbering and
//! matching exactly; only the compiled form of each distinct pattern is reused.
//! Request values are never cached as patterns: every call still matches the
//! current request against the current policy.
//!
//! An invalid pattern makes Casbin panic inside `enforce`; here it fails
//! closed instead (no match, empty capture) and is logged once.

use casbin::function_map::{dynamic_to_str, OperatorFunction};
use casbin::rhai::Dynamic;
use casbin::{CoreApi, Enforcer};
use lazy_static::lazy_static;
use log::warn;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Entries per cache. Patterns come from the policy (a few hundred at most);
/// the bound only matters for a model that matches against request values.
const PATTERN_CACHE_CAPACITY: usize = 1024;

static REGEX_COMPILES: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    /// `{var}` as `keyMatch3` rewrites it (Casbin's `MAT_P`).
    static ref KEY_MATCH3_VAR: Regex = Regex::new(r"\{[^/]*\}").unwrap();
    /// `{var}` as `keyGet3` finds it.
    static ref KEY_GET3_VAR: Regex = Regex::new(r"\{[^/]+?\}").unwrap();
    static ref KEY_MATCH3_CACHE: PatternCache<Regex> = PatternCache::new("keyMatch3");
    static ref KEY_GET3_CACHE: PatternCache<KeyGet3Pattern> = PatternCache::new("keyGet3");
    static ref REGEX_MATCH_CACHE: PatternCache<Regex> = PatternCache::new("regexMatch");
}

/// Compiled patterns of one function, keyed by the raw policy pattern. Each
/// cache has a single fixed rewrite and default regex options, so the raw
/// pattern is the complete key. A failed compile is cached as `None`.
struct PatternCache<T> {
    function: &'static str,
    entries: Mutex<HashMap<String, Option<Arc<T>>>>,
}

impl<T> PatternCache<T> {
    fn new(function: &'static str) -> Self {
        Self {
            function,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_compile(
        &self,
        pattern: &str,
        compile: impl FnOnce(&str) -> Result<T, regex::Error>,
    ) -> Option<Arc<T>> {
        if let Some(entry) = self.lock().get(pattern) {
            return entry.clone();
        }
        // Compile outside the lock; a concurrent first use may compile twice
        // and keeps whichever entry landed first.
        let compiled = match compile(pattern) {
            Ok(compiled) => Some(Arc::new(compiled)),
            Err(error) => {
                warn!(
                    "rbac {} pattern {:?} is invalid and never matches: {}",
                    self.function, pattern, error
                );
                None
            }
        };
        let mut entries = self.lock();
        if entries.len() >= PATTERN_CACHE_CAPACITY && !entries.contains_key(pattern) {
            entries.clear();
        }
        entries
            .entry(pattern.to_string())
            .or_insert(compiled)
            .clone()
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Option<Arc<T>>>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    REGEX_COMPILES.fetch_add(1, Ordering::Relaxed);
    Regex::new(pattern)
}

/// Casbin rewrites `/*` to `/.*` before handling `{var}`.
fn expand_wildcards(key2: &str) -> std::borrow::Cow<'_, str> {
    if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    }
}

/// Same result as `casbin::function_map::regex_match`.
pub fn regex_match(key1: &str, key2: &str) -> bool {
    REGEX_MATCH_CACHE
        .get_or_compile(key2, compile)
        .is_some_and(|regex| regex.is_match(key1))
}

/// Same result as `casbin::function_map::key_match3`.
pub fn key_match3(key1: &str, key2: &str) -> bool {
    KEY_MATCH3_CACHE
        .get_or_compile(key2, |key2| {
            let key2 = expand_wildcards(key2);
            let key2 = KEY_MATCH3_VAR.replace_all(&key2, "[^/]+");
            compile(&format!("^{}$", key2))
        })
        .is_some_and(|regex| regex.is_match(key1))
}

struct KeyGet3Pattern {
    regex: Regex,
    /// Variable names in pattern order; variable `i` is capture group `i + 1`.
    vars: Vec<String>,
}

fn compile_key_get3(key2: &str) -> Result<KeyGet3Pattern, regex::Error> {
    let key2 = expand_wildcards(key2);
    let vars = KEY_GET3_VAR
        .find_iter(&key2)
        .map(|var| {
            let var = var.as_str();
            var[1..var.len() - 1].to_string()
        })
        .collect();
    let key2 = KEY_GET3_VAR.replace_all(&key2, "([^/]+?)");
    // Remaining `{` are literal text, not variables.
    let key2 = key2.replace('{', "\\{");
    Ok(KeyGet3Pattern {
        regex: compile(&format!("^{}$", key2))?,
        vars,
    })
}

/// Same result as `casbin::function_map::key_get3`.
pub fn key_get3(key1: &str, key2: &str, path_var: &str) -> String {
    let Some(pattern) = KEY_GET3_CACHE.get_or_compile(key2, compile_key_get3) else {
        return String::new();
    };
    let Some(caps) = pattern.regex.captures(key1) else {
        return String::new();
    };
    pattern
        .vars
        .iter()
        .position(|var| var == path_var)
        .and_then(|i| caps.get(i + 1))
        .map_or_else(String::new, |value| value.as_str().to_string())
}

struct KeyGet3Call {
    key1: String,
    key2: String,
    path_var: String,
    value: String,
}

thread_local! {
    /// The last `keyGet3` call on this thread. A matcher line evaluates the
    /// same `keyGet3(r.obj, p.obj, p.sub)` up to four times in a row, and the
    /// function is pure, so repeating the last answer is exact.
    static LAST_KEY_GET3: RefCell<Option<KeyGet3Call>> = const { RefCell::new(None) };
}

fn key_get3_repeated(key1: &str, key2: &str, path_var: &str) -> String {
    LAST_KEY_GET3.with(|last| {
        if let Some(call) = last.borrow().as_ref() {
            if call.key1 == key1 && call.key2 == key2 && call.path_var == path_var {
                return call.value.clone();
            }
        }
        let value = key_get3(key1, key2, path_var);
        *last.borrow_mut() = Some(KeyGet3Call {
            key1: key1.to_string(),
            key2: key2.to_string(),
            path_var: path_var.to_string(),
            value: value.clone(),
        });
        value
    })
}

/// Replace Casbin's built-in `keyMatch3`, `keyGet3` and `regexMatch` of
/// `enforcer` with the cached versions.
pub(crate) fn install_cached_matchers(enforcer: &mut Enforcer) {
    enforcer.add_function(
        "keyMatch3",
        OperatorFunction::Arg2(|key1: Dynamic, key2: Dynamic| {
            key_match3(&dynamic_to_str(&key1), &dynamic_to_str(&key2)).into()
        }),
    );
    enforcer.add_function(
        "keyGet3",
        OperatorFunction::Arg3(|key1: Dynamic, key2: Dynamic, path_var: Dynamic| {
            key_get3_repeated(
                &dynamic_to_str(&key1),
                &dynamic_to_str(&key2),
                &dynamic_to_str(&path_var),
            )
            .into()
        }),
    );
    enforcer.add_function(
        "regexMatch",
        OperatorFunction::Arg2(|key1: Dynamic, key2: Dynamic| {
            regex_match(&dynamic_to_str(&key1), &dynamic_to_str(&key2)).into()
        }),
    );
}

/// Regexes compiled by the cached matcher functions since process start.
pub fn matcher_regex_compile_count() -> u64 {
    REGEX_COMPILES.load(Ordering::Relaxed)
}

/// Patterns currently held by the matcher caches.
pub fn matcher_cached_pattern_count() -> usize {
    KEY_MATCH3_CACHE.len() + KEY_GET3_CACHE.len() + REGEX_MATCH_CACHE.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use casbin::function_map as reference;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// Policy-side patterns: the shapes used by BuckyOS policies plus the
    /// corner cases of Casbin's rewriting (literal braces, regex syntax,
    /// several variables in one segment, Unicode, invalid regex).
    const PATTERNS: &[&str] = &[
        "obj://*",
        "obj://config/*",
        "obj://config/boot/*",
        "obj://config/users*",
        "obj://config/users/{user}/*",
        "obj://config/users/{user}/content_defaults",
        "obj://config/users/{user}/apps/{app}/settings",
        "obj://config/users/{admin}/apps/{app}/{key}",
        "obj://config/users/{user}/agents/{agent}/spec",
        "obj://config/services/{service}/info",
        "obj://config/services/{app}@[^/@]+/instances/{node}",
        "obj://config/services/{frame}/*",
        "obj://msg-center/inbox/*",
        "obj://msg-center/group",
        "obj://task/{users}",
        "dfs://homes/:userid",
        "/config/devices/{device}/*",
        "/proj_{project}_admin/",
        "/{a}{b}/x",
        "/{a}-{b}/{c}",
        "/{}/x",
        "/{a/b}/x",
        "/a{2}/x",
        "/a.b+c?/{v}",
        "/用户/{用户名}/资料",
        "/emoji/{e}/😀",
        "",
        "/(group)/{v}",
        "/broken[/{v}",
        "read|write",
        "write|create|delete",
        "list|query",
        "all",
        "^read$",
        "r.*d",
        "(",
        "[^/]+",
    ];

    /// Request-side values.
    const KEYS: &[&str] = &[
        "obj://config/boot/config",
        "obj://config/users",
        "obj://config/users/alice",
        "obj://config/users/alice/content_defaults",
        "obj://config/users/alice/apps/notes/settings",
        "obj://config/users/alice/apps/notes/settings/extra",
        "obj://config/users/alice/agents/xiaobai.test.buckyos.io/spec",
        "obj://config/services/msg-center/info",
        "obj://config/services/notes@alice/instances/ood1",
        "obj://config/services/notes@alice@x/instances/ood1",
        "obj://msg-center/inbox/did:web:alice.test.buckyos.io",
        "obj://msg-center/group",
        "obj://task/alice",
        "dfs://homes/alice",
        "/config/devices/ood1/info",
        "/proj_project1_admin/",
        "/ab/x",
        "/a-b-c/d",
        "/{}/x",
        "/{a/b}/x",
        "/aa/x",
        "/a.b+c?/v",
        "/a.bbc/v",
        "/用户/张三/资料",
        "/emoji/🙂/😀",
        "/(group)/v",
        "/group/v",
        "",
        "read",
        "write",
        "delete",
        "list",
        "all",
        "reed",
    ];

    const PATH_VARS: &[&str] = &[
        "user",
        "app",
        "admin",
        "users",
        "agent",
        "node",
        "service",
        "frame",
        "project",
        "a",
        "b",
        "c",
        "e",
        "v",
        "用户名",
        "missing",
        "",
    ];

    /// Casbin's answer, or `None` where Casbin panics on an invalid pattern.
    fn reference_answer<T>(f: impl FnOnce() -> T) -> Option<T> {
        catch_unwind(AssertUnwindSafe(f)).ok()
    }

    #[test]
    fn cached_functions_match_casbin() {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut compared = 0;
        for pattern in PATTERNS {
            for key in KEYS {
                let expected = reference_answer(|| reference::regex_match(key, pattern));
                assert_eq!(
                    regex_match(key, pattern),
                    expected.unwrap_or(false),
                    "regexMatch({key:?}, {pattern:?})"
                );
                let expected = reference_answer(|| reference::key_match3(key, pattern));
                assert_eq!(
                    key_match3(key, pattern),
                    expected.unwrap_or(false),
                    "keyMatch3({key:?}, {pattern:?})"
                );
                // Variables of this pattern, plus names it does not have.
                let path_vars = PATH_VARS.iter().filter(|var| {
                    matches!(**var, "missing" | "") || pattern.contains(&format!("{{{var}}}"))
                });
                for path_var in path_vars {
                    let expected = reference_answer(|| reference::key_get3(key, pattern, path_var));
                    assert_eq!(
                        key_get3(key, pattern, path_var),
                        expected.clone().unwrap_or_default(),
                        "keyGet3({key:?}, {pattern:?}, {path_var:?})"
                    );
                    assert_eq!(
                        key_get3_repeated(key, pattern, path_var),
                        expected.unwrap_or_default(),
                        "repeated keyGet3({key:?}, {pattern:?}, {path_var:?})"
                    );
                    compared += 1;
                }
            }
        }
        std::panic::set_hook(hook);
        assert!(compared > PATTERNS.len() * KEYS.len() * 2);
    }

    #[test]
    fn captures_follow_casbin_group_numbering() {
        let pattern = "obj://config/services/{app}@[^/@]+/instances/{node}";
        let key = "obj://config/services/notes@alice/instances/ood1";
        assert_eq!(key_get3(key, pattern, "app"), "notes");
        assert_eq!(key_get3(key, pattern, "node"), "ood1");
        assert_eq!(key_get3("/(group)/v", "/(group)/{v}", "v"), "");
        assert_eq!(
            key_get3("/用户/张三/资料", "/用户/{用户名}/资料", "用户名"),
            "张三"
        );
    }

    #[test]
    fn invalid_patterns_fail_closed() {
        assert!(!regex_match("(", "("));
        assert!(!key_match3("/broken[/v", "/broken[/{v}"));
        assert_eq!(key_get3("/broken[/v", "/broken[/{v}", "v"), "");
    }

    #[test]
    fn pattern_cache_is_bounded() {
        let cache: PatternCache<Regex> = PatternCache::new("test");
        for i in 0..PATTERN_CACHE_CAPACITY * 3 {
            let pattern = format!("^/high-cardinality/{i}$");
            assert!(cache.get_or_compile(&pattern, compile).is_some());
            assert!(cache.len() <= PATTERN_CACHE_CAPACITY);
        }
        let first = cache.get_or_compile("^/stable$", compile).unwrap();
        let again = cache.get_or_compile("^/stable$", compile).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
    }
}
