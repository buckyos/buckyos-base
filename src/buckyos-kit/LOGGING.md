# 日志故障处理

`init_logging` 使用 flexi_logger 进行级别过滤及 stdout 输出，由本地
`log_util/rotating_writer.rs` 实现同步文件写入与大小轮转。配置文件位置、
日志行格式和 `app.PID.log` 当前文件名保持不变；归档使用
`app.PID.rYYYYMMDD_HHMMSS_microseconds.log`，重名时附加 `.restart-NNNN`。

- 轮转先打开临时替换文件，再归档旧文件并安装新文件。所有文件系统错误均按
  `io::Result` 处理，不通过 panic 传播到业务调用。
- 轮转失败时保留旧文件描述符并继续写入，最多每秒重试一次；资源恢复后，
  下一次满足重试时间的日志写入会重新尝试轮转。失败期间文件可以超过大小上限。
- 安装新文件失败时尝试回滚；回滚也失败时记录旧文件的实际路径，继续使用
  原描述符。清理失败不阻断新文件写入。错误诊断直接写 stderr。
- `max_files` 保持原时间戳轮转语义：当前 PID 的归档保留数量，另外保留当前文件。
  不清理其他 PID 的日志，也不把该配置当成整个应用目录的总量限制。
- 文件直接写入，不依赖定时 flush 或静态 logger handle 的析构，因此正常写入
  完成后立即退出进程不会丢失用户态缓冲中的末尾日志。这不等价于断电持久化。
- `init_log_panic` 只向 stderr 写入 panic 信息，并忽略写入错误。它不调用 logger，
  以避免日志内部 panic 时重入锁；服务可通过 systemd journal 查看此输出。

回归验证：

```sh
cargo test --manifest-path src/Cargo.toml -p buckyos-kit --lib log_util::
cargo test --manifest-path src/Cargo.toml -p buckyos-kit --test log_resilience
```

fd 耗尽测试仅在 Unix 运行，在带超时的子进程中降低 `RLIMIT_NOFILE`、占满 fd，
检查期间日志保留及释放 fd 后轮转恢复。其他测试覆盖 panic hook、轮转回滚、
保留数量、并发记录完整性和立即退出。
