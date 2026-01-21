use buckyos_kit::get_buckyos_log_dir;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{fmt::MakeWriter, prelude::*, EnvFilter};

/// 日志轮转配置
#[derive(Debug, Clone)]
pub struct RotatingLogConfig {
    /// 应用名称
    pub app_name: String,
    /// 是否为服务模式
    pub is_service: bool,
    /// 单个日志文件最大大小（字节），默认 10MB
    pub max_file_size: u64,
    /// 日志文件总数上限，默认 10 个
    pub max_files: usize,
    /// 当前日志文件名，默认 "current.log"
    pub current_name: String,
}

impl Default for RotatingLogConfig {
    fn default() -> Self {
        Self {
            app_name: "app".to_string(),
            is_service: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 10,
            current_name: "current.log".to_string(),
        }
    }
}

impl RotatingLogConfig {
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
            ..Default::default()
        }
    }

    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn max_files(mut self, count: usize) -> Self {
        self.max_files = count;
        self
    }

    pub fn is_service(mut self, is_service: bool) -> Self {
        self.is_service = is_service;
        self
    }

    pub fn current_name(mut self, name: impl Into<String>) -> Self {
        self.current_name = name.into();
        self
    }
}

/// 自定义的轮转日志写入器
pub struct RotatingFileWriter {
    config: RotatingLogConfig,
    log_dir: PathBuf,
    current_file: Arc<Mutex<Option<File>>>,
    current_size: Arc<Mutex<u64>>,
}

impl RotatingFileWriter {
    pub fn new(config: RotatingLogConfig) -> io::Result<Self> {
        let log_dir = get_buckyos_log_dir(&config.app_name, config.is_service);
        fs::create_dir_all(&log_dir)?;

        let writer = Self {
            config,
            log_dir,
            current_file: Arc::new(Mutex::new(None)),
            current_size: Arc::new(Mutex::new(0)),
        };

        // 初始化当前日志文件
        writer.init_current_file()?;

        Ok(writer)
    }

    /// 初始化或打开当前日志文件
    fn init_current_file(&self) -> io::Result<()> {
        let current_path = self.log_dir.join(&self.config.current_name);
        
        // 如果文件存在，检查大小
        let current_size = if current_path.exists() {
            fs::metadata(&current_path)?.len()
        } else {
            0
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current_path)?;

        *self.current_file.lock().unwrap() = Some(file);
        *self.current_size.lock().unwrap() = current_size;

        Ok(())
    }

    /// 轮转日志文件
    fn rotate(&self) -> io::Result<()> {
        // 关闭当前文件
        *self.current_file.lock().unwrap() = None;

        let pid = std::process::id();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        
        // 生成归档文件名：app_pid_timestamp.log
        let archive_name = format!(
            "{}_{}_{}_{}.log",
            self.config.app_name, pid, timestamp, 
            chrono::Local::now().timestamp()
        );
        
        let current_path = self.log_dir.join(&self.config.current_name);
        let archive_path = self.log_dir.join(&archive_name);

        // 重命名当前文件
        if current_path.exists() {
            fs::rename(&current_path, &archive_path)?;
        }

        // 清理旧文件
        self.cleanup_old_files()?;

        // 创建新的当前文件
        self.init_current_file()?;

        Ok(())
    }

    /// 清理超出数量限制的旧日志文件
    fn cleanup_old_files(&self) -> io::Result<()> {
        let mut log_files: Vec<_> = fs::read_dir(&self.log_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let path = entry.path();
                path.is_file() 
                    && path.extension().and_then(|s| s.to_str()) == Some("log")
                    && path.file_name().and_then(|s| s.to_str()) != Some(&self.config.current_name)
            })
            .collect();

        // 按修改时间排序（最新的在前）
        log_files.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let b_time = b.metadata().and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });

        // 删除超出限制的文件
        for entry in log_files.iter().skip(self.config.max_files.saturating_sub(1)) {
            if let Err(e) = fs::remove_file(entry.path()) {
                eprintln!("Failed to remove old log file {:?}: {}", entry.path(), e);
            }
        }

        Ok(())
    }

    /// 写入数据
    fn write_data(&self, buf: &[u8]) -> io::Result<()> {
        let mut size = self.current_size.lock().unwrap();
        
        // 检查是否需要轮转
        if *size + buf.len() as u64 > self.config.max_file_size {
            drop(size); // 释放锁
            self.rotate()?;
            size = self.current_size.lock().unwrap();
        }

        // 写入数据
        if let Some(ref mut file) = *self.current_file.lock().unwrap() {
            file.write_all(buf)?;
            file.flush()?;
            *size += buf.len() as u64;
        }

        Ok(())
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_data(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut file) = *self.current_file.lock().unwrap() {
            file.flush()?;
        }
        Ok(())
    }
}

/// 为 tracing 提供的 MakeWriter 实现
#[derive(Clone)]
pub struct RotatingLogMakeWriter {
    writer: Arc<Mutex<RotatingFileWriter>>,
}

impl RotatingLogMakeWriter {
    pub fn new(config: RotatingLogConfig) -> io::Result<Self> {
        let writer = RotatingFileWriter::new(config)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
        })
    }
}

impl<'a> MakeWriter<'a> for RotatingLogMakeWriter {
    type Writer = RotatingLogWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingLogWriterGuard {
            writer: self.writer.clone(),
        }
    }
}

pub struct RotatingLogWriterGuard {
    writer: Arc<Mutex<RotatingFileWriter>>,
}

impl Write for RotatingLogWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.lock().unwrap().flush()
    }
}

/// 初始化带轮转的 tracing 日志
pub fn init_rotating_tracing(config: RotatingLogConfig) -> Result<(), Box<dyn std::error::Error>> {
    let rotating_writer = RotatingLogMakeWriter::new(config)?;

    // 环境变量过滤器
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // 终端层
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_ansi(true);

    // 文件层（使用轮转写入器）
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_ansi(false)
        .with_writer(rotating_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    tracing::info!("Rotating tracing logger initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotating_log() {
        let config = RotatingLogConfig::new("test_app")
            .max_file_size(1024) // 1KB for testing
            .max_files(3);

        let mut writer = RotatingFileWriter::new(config).unwrap();

        // 写入一些数据
        for i in 0..10 {
            let msg = format!("Test message {}\n", i).repeat(100);
            writer.write_all(msg.as_bytes()).unwrap();
        }

        writer.flush().unwrap();
    }
}

