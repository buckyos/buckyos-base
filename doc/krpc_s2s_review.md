
### Findings

1. **[P1] `Tls` 模式允许 HTTPS → HTTP 重定向降级。**  
   只校验初始 URL，随后使用 reqwest 默认重定向策略且未启用 `https_only(true)`。307/308 可把包含 session token 的 POST Body 重发到明文 HTTP。应为 TLS 模式单独构造 HTTPS-only client，并拒绝降级重定向。  
   [src/kRPC/src/lib.rs:141](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/lib.rs:141) [src/kRPC/src/lib.rs:104](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/lib.rs:104)

2. **[P1] S2S 客户端在认证前无界缓冲 chunked response。**  
   缺少 `Content-Length` 时直接调用 `response.bytes()`，Body 上限在完整分配后才检查。HTTP 链路上的攻击者无需伪造 AEAD，即可返回合法 Header 加超大 chunked Body 制造内存耗尽。需要流式累计并在超过上限时立即终止。  
   [src/kRPC/src/lib.rs:401](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/lib.rs:401)

3. **[P1] 过期 grace 私钥不会被删除或 zeroize。**  
   grace 清理只发生在“再次轮换且 fingerprint 改变”时；相同 key 的 reload 会提前返回，正常 candidate/DH 访问也只是忽略过期项，`Arc<LoadedS2sKey>` 仍永久持有私钥。这会把旧 epoch 的泄露窗口延长到进程退出或下一次不同轮换。  
   [src/name-client/src/identity_s2s.rs:106](/Users/liuzhicong/project/buckyos-base/src/name-client/src/identity_s2s.rs:106) [src/name-client/src/identity_s2s.rs:127](/Users/liuzhicong/project/buckyos-base/src/name-client/src/identity_s2s.rs:127)

4. **[P1] “单请求单 policy snapshot”实际上没有实现。**  
   入口、plaintext/encrypted 分支、`open_request` 和 `seal_response` 分别重新读取 policy。并发 reload 时可能用旧的 `HandlerManaged` 做 token 判断、同时用新的 peer policy 解密，形成短暂策略绕过。应在入口取得一次 `Arc<S2sServerSecurityPolicy>`，一路显式传递。  
   [src/buckyos-http-server/src/s2s_rpc_server.rs:56](/Users/liuzhicong/project/buckyos-base/src/buckyos-http-server/src/s2s_rpc_server.rs:56) [src/kRPC/src/s2s/server_ctx.rs:171](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/s2s/server_ctx.rs:171)

5. **[P2] 首次 key lookup 返回空时不会执行设计要求的 refresh retry。**  
   `seal_request(...)?` 直接退出循环；第二次 `refresh_verified_keys` 仅在收到 HTTP 非 2xx 或 response 解密失败后发生。冷 cache/未知 key 本可刷新恢复，却被直接归类为 permanent failure。  
   [src/kRPC/src/lib.rs:343](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/lib.rs:343)

6. **[P2] `max_header_value_len` 是无效配置。**  
   policy 暴露该限制，但 Header parser 始终使用编译期默认值，服务端没有把 snapshot 中的限制传入；配置更严格的上限不会生效。设计要求的 HTTP Header 总数/总大小限制也尚未实现。  
   [src/kRPC/src/s2s/policy.rs:210](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/s2s/policy.rs:210) [src/kRPC/src/s2s/headers.rs:142](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/s2s/headers.rs:142)

7. **[P2] pinned 模式静默跳过本地 key/service DID binding。**  
   `with_pinned_key` 只固定远端 key，但构造时把本地 binding 标记为 `CallerAsserted`，因此错误的本地显式私钥不会在构造阶段失败，只会在线上调用时被远端拒绝，不符合设计的 fail-fast binding 要求。  
   [src/kRPC/src/s2s/client.rs:164](/Users/liuzhicong/project/buckyos-base/src/kRPC/src/s2s/client.rs:164)

验证方面，`cargo test -p kRPC -p buckyos-http-server -p name-client` 共 318 个测试全部通过，工作区未修改。设计中已注明的独立完整 AEAD 向量验证、跨语言互操作、共享 replay backend 等仍是公网验收阻塞项。