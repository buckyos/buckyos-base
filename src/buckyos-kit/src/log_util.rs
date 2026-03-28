use crate::{get_buckyos_dev_user_home, get_buckyos_log_dir, get_buckyos_root_dir, get_version};
use flexi_logger::{
    Cleanup, Criterion, DeferredNow, Duplicate, FileSpec, Logger, LoggerHandle, Naming,
    WriteMode,
};
use log::{LevelFilter, Record};
use once_cell::sync::OnceCell;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    panic,
    path::{Path, PathBuf},
};

const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;
const DEFAULT_MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
const DEFAULT_MAX_FILES: usize = 10;

static LOGGER_STATE: OnceCell<LoggingState> = OnceCell::new();

struct LoggingState {
    app_name: String,
    _handle: LoggerHandle,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PartialLogSettings {
    level: Option<String>,
    max_file_size: Option<u64>,
    max_files: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedLogSettings {
    level: LevelFilter,
    max_file_size: u64,
    max_files: usize,
}

impl Default for ResolvedLogSettings {
    fn default() -> Self {
        Self {
            level: DEFAULT_LOG_LEVEL,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

impl PartialLogSettings {
    fn merge(&mut self, other: PartialLogSettings) {
        if other.level.is_some() {
            self.level = other.level;
        }
        if other.max_file_size.is_some() {
            self.max_file_size = other.max_file_size;
        }
        if other.max_files.is_some() {
            self.max_files = other.max_files;
        }
    }

    fn resolve(self) -> ResolvedLogSettings {
        let level = self
            .level
            .as_deref()
            .and_then(parse_level_filter)
            .unwrap_or(DEFAULT_LOG_LEVEL);

        ResolvedLogSettings {
            level,
            max_file_size: self.max_file_size.unwrap_or(DEFAULT_MAX_FILE_SIZE),
            max_files: self.max_files.unwrap_or(DEFAULT_MAX_FILES),
        }
    }
}

pub fn init_logging(app_name: &str, is_service: bool) {
    let resolved_app_name = resolve_app_name(app_name);

    if let Some(state) = LOGGER_STATE.get() {
        if state.app_name != resolved_app_name {
            warn!(
                "logging already initialized for app {}, ignore re-init request for {}",
                state.app_name, resolved_app_name
            );
        }
        return;
    }

    let settings = resolve_log_settings(&resolved_app_name);
    let pid = std::process::id();
    let log_dir = get_buckyos_log_dir("", is_service).join(&resolved_app_name);

    if let Err(err) = fs::create_dir_all(&log_dir) {
        eprintln!(
            "Failed to create log directory {}: {}",
            log_dir.display(),
            err
        );
        return;
    }

    let file_spec = FileSpec::default()
        .directory(log_dir.clone())
        .basename(format!("{}.{}", resolved_app_name, pid))
        .suffix("log");

    let logger = match Logger::try_with_str(settings.level.to_string()) {
        Ok(logger) => logger,
        Err(err) => {
            eprintln!(
                "Failed to parse log level {} for {}: {}",
                settings.level, resolved_app_name, err
            );
            return;
        }
    };

    let logger = logger
        .format(log_format)
        .log_to_file(file_spec)
        .append()
        .duplicate_to_stdout(Duplicate::All)
        .rotate(
            Criterion::Size(settings.max_file_size),
            Naming::TimestampsCustomFormat {
                current_infix: Some(""),
                format: "r%Y%m%d_%H%M%S_%6f",
            },
            Cleanup::KeepLogFiles(settings.max_files),
        )
        .write_mode(WriteMode::BufferAndFlush)
        .cleanup_in_background_thread(true);

    let handle = match logger.start() {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("Failed to init logging for {}: {}", resolved_app_name, err);
            return;
        }
    };

    if LOGGER_STATE
        .set(LoggingState {
            app_name: resolved_app_name.clone(),
            _handle: handle,
        })
        .is_err()
    {
        return;
    }

    info!(
        "{} start logging, pid: {}, buckyos version {}",
        resolved_app_name,
        pid,
        get_version()
    );
    info!("log level: {}", settings.level);
    info!(
        "log file rotation: max_file_size={} bytes, max_files={}",
        settings.max_file_size, settings.max_files
    );
    info!("log directory: {}", log_dir.display());
}

pub fn init_log_panic() {
    panic::set_hook(Box::new(|panic_info| {
        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            format!("panic message: {}", s)
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            format!("panic message: {}", s)
        } else {
            "panic occurred".to_string()
        };

        error!("[PANIC] unwrap/panic failed at {} - {}", location, message);
        eprintln!("[PANIC] unwrap/panic failed at {} - {}", location, message);
    }));
}

fn log_format(
    writer: &mut dyn Write,
    now: &mut DeferredNow,
    record: &Record<'_>,
) -> Result<(), std::io::Error> {
    let file = record
        .file()
        .and_then(|path| Path::new(path).file_name())
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    write!(
        writer,
        "{} {:<5} [{}:{}] {}",
        now.format("%m-%d %H:%M:%S%.3f"),
        record.level(),
        file,
        record.line().unwrap_or(0),
        record.args()
    )
}

fn resolve_app_name(app_name: &str) -> String {
    let candidate = if app_name.trim().is_empty() {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.file_stem().map(|stem| stem.to_string_lossy().to_string()))
            .unwrap_or_else(|| "app".to_string())
    } else {
        app_name.trim().to_string()
    };

    let sanitized = candidate
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect::<String>()
        .trim()
        .to_string();

    if sanitized.is_empty() {
        "app".to_string()
    } else {
        sanitized
    }
}

fn resolve_log_settings(app_name: &str) -> ResolvedLogSettings {
    let mut merged = PartialLogSettings::default();

    for path in log_settings_paths() {
        let file_settings = match load_log_settings_file(&path) {
            Ok(file_settings) => file_settings,
            Err(err) => {
                eprintln!("Failed to load log settings: {}", err);
                continue;
            }
        };

        if let Some(defaults) = file_settings.get("default").cloned() {
            merged.merge(defaults);
        }
        if let Some(settings) = file_settings.get(app_name).cloned() {
            merged.merge(settings);
        }
    }

    if let Some(level) = std::env::var("BUCKY_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
    {
        merged.level = Some(level);
    }

    merged.resolve()
}

fn log_settings_paths() -> [PathBuf; 2] {
    [
        get_buckyos_root_dir().join("log").join("log_settings.cfg"),
        get_buckyos_dev_user_home().join("log_settings.cfg"),
    ]
}

fn load_log_settings_file(path: &Path) -> Result<HashMap<String, PartialLogSettings>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;

    let value: toml::Value = toml::from_str(&content)
        .map_err(|err| format!("failed to parse {}: {}", path.display(), err))?;

    let mut result = HashMap::new();
    let Some(table) = value.as_table() else {
        return Err(format!(
            "invalid log settings in {}, top-level table expected",
            path.display()
        ));
    };

    for (key, entry) in table {
        if key == "apps" {
            if let Some(app_table) = entry.as_table() {
                for (app_name, app_entry) in app_table {
                    if let Some(settings) = parse_settings_table(app_entry) {
                        result.insert(app_name.clone(), settings);
                    }
                }
            }
            continue;
        }

        if let Some(settings) = parse_settings_table(entry) {
            result.insert(key.clone(), settings);
        }
    }

    Ok(result)
}

fn parse_settings_table(value: &toml::Value) -> Option<PartialLogSettings> {
    let table = value.as_table()?;
    let mut settings = PartialLogSettings::default();

    for (key, value) in table {
        match key.as_str() {
            "level" | "log_level" => {
                if let Some(level) = value.as_str() {
                    settings.level = Some(level.trim().to_string());
                }
            }
            "size" | "max_size" | "max_file_size" | "file_size" | "rotate_size" => {
                if let Some(size) = parse_size_value(value) {
                    settings.max_file_size = Some(size);
                }
            }
            "max_files" | "file_count" | "rotate_keep" | "keep" | "count" => {
                if let Some(count) = parse_usize_value(value) {
                    settings.max_files = Some(count.max(1));
                }
            }
            _ => {}
        }
    }

    Some(settings)
}

fn parse_level_filter(level: &str) -> Option<LevelFilter> {
    level.trim().parse().ok()
}

fn parse_size_value(value: &toml::Value) -> Option<u64> {
    if let Some(size) = value.as_integer() {
        return u64::try_from(size).ok();
    }

    let raw = value.as_str()?.trim().to_ascii_uppercase().replace('_', "");
    parse_human_size(&raw)
}

fn parse_usize_value(value: &toml::Value) -> Option<usize> {
    if let Some(count) = value.as_integer() {
        return usize::try_from(count).ok();
    }

    value.as_str()?.trim().parse::<usize>().ok()
}

fn parse_human_size(raw: &str) -> Option<u64> {
    let split = raw
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(raw.len());
    let (number, unit) = raw.split_at(split);
    let value = number.parse::<u64>().ok()?;
    let multiplier = match unit.trim() {
        "" | "B" => 1,
        "K" | "KB" => 1024,
        "M" | "MB" => 1024 * 1024,
        "G" | "GB" => 1024 * 1024 * 1024,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_app_name() {
        let inferred = resolve_app_name("");
        assert!(!inferred.is_empty());
        assert!(!inferred.contains('/'));
        assert!(!inferred.contains('\\'));
        assert_eq!(resolve_app_name("my-app"), "my-app");
        assert_eq!(resolve_app_name("bad/name"), "bad_name");
    }

    #[test]
    fn test_parse_human_size() {
        assert_eq!(parse_human_size("200MB"), Some(200 * 1024 * 1024));
        assert_eq!(parse_human_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_human_size("4096"), Some(4096));
        assert_eq!(parse_human_size("12XB"), None);
    }

    #[test]
    fn test_load_log_settings_file_supports_default_and_apps() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("log_settings.cfg");

        fs::write(
            &config_path,
            r#"
[default]
level = "warn"
size = "128MB"
count = 3

[test_app]
level = "debug"
max_file_size = "64MB"

[apps.worker]
keep = 12
"#,
        )
        .unwrap();

        let settings = load_log_settings_file(&config_path).unwrap();
        assert_eq!(
            settings.get("default"),
            Some(&PartialLogSettings {
                level: Some("warn".to_string()),
                max_file_size: Some(128 * 1024 * 1024),
                max_files: Some(3),
            })
        );
        assert_eq!(
            settings.get("test_app"),
            Some(&PartialLogSettings {
                level: Some("debug".to_string()),
                max_file_size: Some(64 * 1024 * 1024),
                max_files: None,
            })
        );
        assert_eq!(
            settings.get("worker"),
            Some(&PartialLogSettings {
                level: None,
                max_file_size: None,
                max_files: Some(12),
            })
        );
    }

    #[test]
    fn test_partial_log_settings_resolve_defaults() {
        let mut settings = PartialLogSettings::default();
        settings.merge(PartialLogSettings {
            level: Some("trace".to_string()),
            max_file_size: Some(1024),
            max_files: Some(2),
        });

        assert_eq!(
            settings.resolve(),
            ResolvedLogSettings {
                level: LevelFilter::Trace,
                max_file_size: 1024,
                max_files: 2,
            }
        );
    }
}
