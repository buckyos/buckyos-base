//! Process isolation is required for global logger/panic hooks and fd limits.
use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

fn run_child(test: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("logs")).unwrap();
    fs::write(
        dir.path().join("logs/log_settings.cfg"),
        "[default]\nmax_file_size = 1024\nmax_files = 10\n",
    )
    .unwrap();
    let stderr_path = dir.path().join("stderr");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("BUCKYOS_LOG_RESILIENCE_CHILD", "1")
        .env("BUCKYOS_ROOT", dir.path())
        .env("BUCKY_LOG", "info")
        .stdout(fs::File::create(dir.path().join("stdout")).unwrap())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = fs::read_to_string(stderr_path).unwrap();
            assert!(status.success(), "child failed: {status}\n{stderr}");
            return (dir, stderr);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("logger child timed out (possible deadlock)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn panic_hook_does_not_reenter_logger() {
    if std::env::var_os("BUCKYOS_LOG_RESILIENCE_CHILD").is_some() {
        struct PanickingLogger;
        impl log::Log for PanickingLogger {
            fn enabled(&self, _: &log::Metadata) -> bool {
                true
            }
            fn log(&self, _: &log::Record) {
                panic!("panic inside logger");
            }
            fn flush(&self) {}
        }
        log::set_logger(&PanickingLogger).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        buckyos_kit::init_log_panic();
        assert!(std::panic::catch_unwind(|| log::error!("trigger")).is_err());
        return;
    }
    let (_, stderr) = run_child("panic_hook_does_not_reenter_logger");
    assert!(stderr.contains("[PANIC]"));
    assert!(stderr.contains("panic inside logger"));
}

#[cfg(unix)]
#[test]
fn fd_exhaustion_keeps_logging_and_rotation_recovers() {
    if std::env::var_os("BUCKYOS_LOG_RESILIENCE_CHILD").is_some() {
        buckyos_kit::init_logging("fd-test", true);
        buckyos_kit::init_log_panic();
        log::info!("before-exhaustion {}", "x".repeat(2048));
        // Only lower the limit in this child. The test runner remains unaffected.
        unsafe {
            let mut limits = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits), 0);
            limits.rlim_cur = limits.rlim_cur.min(128);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limits), 0);
        }
        let mut files = Vec::new();
        loop {
            match fs::File::open("/dev/null") {
                Ok(file) => files.push(file),
                Err(err) => {
                    assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        for i in 0..100 {
            log::error!("during-exhaustion-{i}");
        }
        drop(files);
        std::thread::sleep(Duration::from_millis(1100));
        log::info!("after-recovery");
        // No logger handle drop/flush should be required to persist these records.
        std::process::exit(0);
    }
    let (dir, stderr) = run_child("fd_exhaustion_keeps_logging_and_rotation_recovers");
    assert!(!stderr.contains("[PANIC]"), "{stderr}");
    assert!(
        stderr.contains("Log rotation failed"),
        "EMFILE did not exercise rotation: {stderr}"
    );
    assert_eq!(stderr.matches("Log rotation failed").count(), 1);
    let entries = fs::read_dir(dir.path().join("logs/fd-test"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 2, "rotation did not recover");
    let mut all = String::new();
    for entry in entries {
        let content = fs::read_to_string(entry.path()).unwrap();
        if !entry.file_name().to_string_lossy().contains(".r") {
            assert!(content.contains("after-recovery"));
        }
        all.push_str(&content);
    }
    assert!(all.contains("before-exhaustion"));
    assert!(all.contains("after-recovery"));
    for i in 0..100 {
        assert!(
            all.contains(&format!("during-exhaustion-{i}\n")),
            "missing record {i}"
        );
    }
}
