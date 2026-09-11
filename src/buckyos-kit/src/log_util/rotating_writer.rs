use flexi_logger::{writers::LogWriter, DeferredNow};
use log::Record;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Synchronous file output with fallible rotation. The current descriptor stays
/// open until its replacement is installed, including when opening a file fails.
pub(super) struct RotatingWriter {
    state: Mutex<State>,
}

struct State {
    file: File,
    path: PathBuf,
    dir: PathBuf,
    basename: String,
    size: u64,
    max_size: u64,
    max_files: usize,
    retry_at: Option<Instant>,
}

impl RotatingWriter {
    pub(super) fn new(
        dir: PathBuf,
        basename: String,
        max_size: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        let path = dir.join(format!("{basename}.log"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            state: Mutex::new(State {
                file,
                path,
                dir,
                basename,
                size,
                max_size,
                max_files: max_files.max(1),
                retry_at: None,
            }),
        })
    }

    fn write_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut diagnostic = None;
        if state.size > state.max_size && state.retry_at.is_none_or(|at| now >= at) {
            // Bound expensive filesystem retries and diagnostics during EMFILE.
            match state.rotate() {
                Ok(cleanup_error) => {
                    state.retry_at = None;
                    diagnostic = cleanup_error.map(|err| ("Log cleanup failed", err));
                }
                Err(err) => {
                    state.retry_at = Some(now + RETRY_DELAY);
                    diagnostic = Some(("Log rotation failed; keeping current file", err));
                }
            }
        }
        let result = state.file.write_all(bytes);
        if result.is_ok() {
            state.size = state.size.saturating_add(bytes.len() as u64);
        }
        drop(state);
        // Do not take the stderr lock while holding the file lock.
        if let Some((message, err)) = diagnostic {
            let _ = writeln!(io::stderr(), "{message}: {err}");
        }
        result
    }
}

impl LogWriter for RotatingWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record) -> io::Result<()> {
        // User Display implementations may panic or log recursively. Format
        // before taking the file lock so neither can poison or deadlock it.
        let mut bytes = Vec::with_capacity(256);
        super::log_format(&mut bytes, now, record)?;
        bytes.push(b'\n');
        self.write_bytes(&bytes)
    }

    fn flush(&self) -> io::Result<()> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .file
            .flush()
    }
}

impl State {
    fn rotate(&mut self) -> io::Result<Option<io::Error>> {
        let timestamp = chrono::Local::now()
            .format("r%Y%m%d_%H%M%S_%6f")
            .to_string();
        let mut collision = 0u64;
        // create_new protects against leftover staging files and clock collisions.
        let (staging, archive, replacement) = loop {
            let name = if collision == 0 {
                format!("{}.{}.log", self.basename, timestamp)
            } else {
                format!("{}.{}.restart-{collision:04}.log", self.basename, timestamp)
            };
            collision = collision.saturating_add(1);
            let archive = self.dir.join(name);
            if archive.try_exists()? {
                continue;
            }
            let staging = archive.with_extension("tmp");
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
            {
                Ok(file) => break (staging, archive, file),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        };

        if let Err(err) = fs::rename(&self.path, &archive) {
            drop(replacement);
            let _ = fs::remove_file(&staging);
            return Err(err);
        }
        let current = self.dir.join(format!("{}.log", self.basename));
        if let Err(err) = fs::rename(&staging, &current) {
            // Track the real location even if rollback also fails. The open file
            // remains writable, and a later attempt can rotate from that path.
            if fs::rename(&archive, &self.path).is_err() {
                self.path = archive;
            }
            drop(replacement);
            let _ = fs::remove_file(&staging);
            return Err(err);
        }
        self.file = replacement;
        self.path = current;
        self.size = 0;
        // Cleanup is best effort. An error must not stop writing the new file.
        Ok(self.cleanup().err())
    }

    fn cleanup(&self) -> io::Result<()> {
        let prefix = format!("{}.r", self.basename);
        let mut archives = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".log") && entry.file_type()?.is_file() {
                archives.push((entry.metadata()?.modified()?, entry.path()));
            }
        }
        archives.sort_unstable();
        // Preserve KeepLogFiles semantics for timestamp rotation: keep this many
        // archives in addition to the current file, scoped to this process.
        let remove_count = archives.len().saturating_sub(self.max_files);
        for (_, path) in archives.into_iter().take(remove_count) {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_rotation_keeps_writing_and_recovers() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("logs");
        fs::create_dir(&dir).unwrap();
        let writer = RotatingWriter::new(dir.clone(), "app.1".into(), 4, 3).unwrap();
        writer.write_bytes(b"before\n").unwrap();
        let moved = root.path().join("moved");
        fs::rename(&dir, &moved).unwrap();
        writer.write_bytes(b"during\n").unwrap();
        assert_eq!(
            fs::read(moved.join("app.1.log")).unwrap(),
            b"before\nduring\n"
        );
        fs::rename(&moved, &dir).unwrap();
        writer.state.lock().unwrap().retry_at = None;
        writer.write_bytes(b"after\n").unwrap();
        assert_eq!(fs::read(dir.join("app.1.log")).unwrap(), b"after\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[test]
    fn failed_install_rolls_back_and_keeps_original_file() {
        let dir = tempfile::tempdir().unwrap();
        let writer = RotatingWriter::new(dir.path().into(), "app.1".into(), 4, 3).unwrap();
        writer.write_bytes(b"before\n").unwrap();
        let current = dir.path().join("app.1.log");
        let old = dir.path().join("old.log");
        fs::rename(&current, &old).unwrap();
        writer.state.lock().unwrap().path = old.clone();
        // A directory at the destination makes installation fail after archiving.
        fs::create_dir(&current).unwrap();
        writer.write_bytes(b"during\n").unwrap();
        assert_eq!(fs::read(&old).unwrap(), b"before\nduring\n");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            2,
            "staging/archive leaked"
        );
        fs::remove_dir(&current).unwrap();
        writer.state.lock().unwrap().retry_at = None;
        writer.write_bytes(b"after\n").unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"after\n");
        assert!(!old.exists());
    }

    #[test]
    fn retention_leaves_other_processes_and_unrelated_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.2.r123.log"), "other process").unwrap();
        fs::write(dir.path().join("settings.cfg"), "settings").unwrap();
        let writer = RotatingWriter::new(dir.path().into(), "app.1".into(), 1, 3).unwrap();
        for _ in 0..12 {
            writer.write_bytes(b"record\n").unwrap();
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 6);
        assert_eq!(
            fs::read_to_string(dir.path().join("app.2.r123.log")).unwrap(),
            "other process"
        );
        assert!(dir.path().join("settings.cfg").exists());
    }

    #[test]
    fn concurrent_rotation_preserves_complete_records() {
        let dir = tempfile::tempdir().unwrap();
        let writer = std::sync::Arc::new(
            RotatingWriter::new(dir.path().into(), "app.1".into(), 128, 1000).unwrap(),
        );
        std::thread::scope(|scope| {
            for thread in 0..4 {
                let writer = writer.clone();
                scope.spawn(move || {
                    for line in 0..100 {
                        writer
                            .write_bytes(format!("{thread}:{line}\n").as_bytes())
                            .unwrap();
                    }
                });
            }
        });
        let mut actual = Vec::new();
        for entry in fs::read_dir(dir.path()).unwrap() {
            actual.extend(
                fs::read_to_string(entry.unwrap().path())
                    .unwrap()
                    .lines()
                    .map(str::to_owned),
            );
        }
        let mut expected = (0..4)
            .flat_map(|thread| (0..100).map(move |line| format!("{thread}:{line}")))
            .collect::<Vec<_>>();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }
}
