# resolve_did default DocType TODO

> 状态：讨论中，暂不执行。
>
> 本 TODO 只记录 `doc_type = None` 的可能语义和待确认设计点。是否执行、如何执行，
> 需要在 resolver-provider 契约和 BNS 合约能力确认后再决定。

## 核心设计意图

`resolve_did(did, None)` 表示调用方对返回的 DocType 没有预期，愿意接受这个 DID
在对应 resolver-provider 下定义的默认 DocType。它不是 `zone` 的别名，也不是全局
固定类型。

如果调用方有明确类型预期，必须传入 `Some(DidDocType)`。这种情况下，resolver 返回的
实际 DocType 必须与预期一致，否则应返回类型不匹配错误。

换句话说：

- `Some(t)`：调用方要求拿 `t`，结果必须是 `t`。
- `None`：调用方接受 provider 针对这个 DID 选择的默认 DocType，结果必须携带实际
  DocType。

## BNS 当前约束

参考 `/Users/liuzhicong/project/cyfs-gateway/doc/BNS/BNS 智能合约接口设计.md`：

- `doc_type` 是 canonical lower-case ASCII string。
- `resolveDocument(name, docType)` / `resolveDid(did, docType)` 都接收必填
  `string calldata docType`。
- 当前合约接口没有 `set default_doc_type` 或 `resolveDocument(name, None)` 语义。

因此，`None` 不能直接透传到 BNS 合约。BNS resolver 如果要支持 `None`，必须在
resolver-provider 内部先做默认 DocType 选择，再用明确 DocType 查询合约。

## BNS 默认选择规则草案

对某个 BNS name，按当前有效发布状态统计 active DocType：

1. 如果合约未来支持显式 `default_doc_type`，优先使用合约声明的默认值。
2. 如果没有显式默认值，且该名字下有且仅有一个 active DocType，`None` 解析为这个
   DocType。
3. 如果没有显式默认值，且存在多个 active DocType：
   - 默认应返回 ambiguity error，因为 resolver 无法判断调用方想要哪一种。
   - 兼容语义可选：如果多个类型中包含 `zone`，可以返回 `zone`，因为历史实现曾把
     default 近似为 `zone`。
4. 如果没有任何 active DocType，返回 NotFound/Missing。

这里的 `zone` 只应是 BNS provider 的兼容策略，不应上升为 `None == zone` 的全局规则。

## 推广到所有 Provider

默认 DocType 是 resolver-provider 的内部契约。不同 DID method 可以用不同策略：

- did:web / canonical host：`None` 可以读取标准 `did.json`，实际 DocType 由文档内容
  或 provider 规则确定。
- BNS：`None` 需要先根据 Registry/indexer 可见的 active DocType 集合选择默认值，再
  查询明确 DocType。
- 其它 method：provider 可以定义自己的默认 DocType 策略，但必须在结果中暴露实际
  DocType。

通用 resolver 不应该在入口处把 `None` 归一成 `DidDocType::Zone`。它应该把
`Option<DidDocType>` 保留到 provider 边界，并让 provider 对 `None` 作出方法内决策。

## 待确认问题

- BNS 合约或 indexer 是否提供“列出某 name 下所有 active DocType”的能力？如果没有，
  “有且仅有一个 Type”无法由 resolver 可靠判断。
- BNS 是否应该增加 name-level `default_doc_type` 字段或单独的设置接口？
- 多 active DocType 且包含 `zone` 时，兼容返回 `zone` 是否会掩盖配置错误？是否需要
  warning 标记？
- `ResolvedDocument.document_metadata.buckyos.doc_type` 应只写 actual DocType，还是同时
  增加 `requestedDocType` / `defaulted` / `defaultReason` 之类的 metadata？
- cache key 应如何处理 `None`：按 actual DocType 写正缓存，是否还需要一条
  `(did, None) -> actual DocType` 的短期映射？

## 可能实现任务

- 在 resolver 内部区分 `requested_doc_type: Option<DidDocType>` 和
  `actual_doc_type: DidDocType`。
- 对 `Some(expected)` 做 actual type 校验；对 `None` 接受 provider 选择的默认类型。
- 为 provider 增加默认 DocType 选择契约，或让 `query_did(did, None)` 明确表示
  provider-defined default。
- BNS provider 实现 ambiguity error，并可选实现 `zone` 兼容 fallback。
- 同步修订 `DEFAULT_DID_DOC_TYPE`、`legacy_doc_type` 和 HTTP resolver 文档里
  “缺省 type = zone”的表述。
- 增加测试：
  - BNS name 只有一个 active DocType 时，`None` 返回该类型；
  - BNS name 有多个 active DocType 且无默认值时，`None` 报 ambiguity；
  - BNS name 有多个 active DocType 且启用 `zone` 兼容时，`None` 返回 `zone` 并带 warning；
  - `Some(expected)` 收到其它 actual DocType 时失败。
