# 伪代码：只描述逻辑，不展开异步、数据库和 wire 格式。
# 根据 review 的回答整理。helper 名称已回写为 name-client/src/resolver/ 中的实际 Rust 名(2026-10-20 M1–M6)。
# 2026-10-20 按 resolve-did重构-TODO.md 回写：closest 由 current 推导、Invalid 负状态、
# doc_type=None 归一、串行锁只包读缓存段与提交段（I/O 不持锁，任务合并去重）。
# wire（versionId/versionTime、BuckyOS-DID-Document 响应头、Zone locker 预算头）见 http_did_resolver_api.md。

# ---------- 数据与约定 ----------
# doc_result 按 (scope, did, doc_type) 保存，进程内/跨进程共享。
# state: 正常 / 禁用 / 未知，保留原因和来源；None/Unknown 不能覆盖已知禁用。
# latest: 已发布的最高版本；best: 看到且验证通过的最高版本，可以尚未发布。
# owner 是信任根，只从 authority/locker 获得当前或指定的已发布版本，不设置 best。
# exact: 本次指定的已发布 (iat, hash)；closest: 已发布版本中最大的 iat < 查询时间。
# candidates: (iat, content_hash) -> (doc, source)，允许同 iat 的多个待验候选。
# latest/best/历史条目保留来源、原查询和验证结果；exact/closest 按完整查询分槽，不能串用。
# 同 iat 同 hash 幂等；通过验证后，同 iat 不同 hash 才按版本冲突拒绝，不让坏候选占槽。
# hash 沿用现有编码契约：JWT 对原文取 hash，JSON 对规范化序列化结果取 hash。
# JSON 语义比较可用于内容合并，不能替代 JWT 的确切输入验签/发布 hash 校验。

# 来源只有三档：authority / trust / normal。
# authority 能确认发布；trust 免 owner 验签、可产生 best，但不因此声称发布或 is_signed。
# normal 只贡献候选。来源等级由本机配置/owner 绑定确定，不能由收到的文档自报。
# locker 按 /etc/hosts 模型优先且强制返回，可以在其 scope 内模拟发布；结果不写进普通来源缓存。
# trust 站点解绑只影响下一次 resolve 的来源列表，不撤销此前已取得的可信文档。
# 旧文档仍受 exp、明确撤销和版本替换约束；解绑本身不降低其已记录的来源等级。

# opts 中和版本有关的需求提取到 revision 参数中；opts 保留请求来源、预算、缓存、locker 等控制。
# revision=None 等价于 Revision.current()：同时获取 latest + best，owner 只获取 latest。
# Revision.exact(iat, hash)：指定已发布版本；Revision.closest(iat)：最接近且严格早于 iat 的已发布版本。
# exact/closest 需要 resolver 的 publish_info 协议回答相应查询；locker 可在本 scope 模拟。
# 不支持/无回答时保留原因，不能退回当前版本，也不能把本机见过的最大历史版本当 closest。
# closest 可由 authority 的 current 回答 L 推出：L 是 latest 证明 (L.iat, +∞) 无已发布版本，
# 故 query_iat > L.iat 时 closest(query_iat) = L；exact(iat, hash) 在 iat == L.iat 且 hash 相同时命中。
# 推出的回答按完整查询分槽缓存，证据指向该 current receipt；trust/normal 的 body 不能用于推导。
# query_iat <= L.iat 时必须发真正的历史查询（wire: versionTime）。
# doc.revision() 是文档身份 (iat, hash)，revision 是查询条件，二者不要混用。
# normalize/with/create_get_owner_opts 都返回副本；递归 owner 查询显式传自己的 revision。
# 副本继承同一 deadline、取消信号和来源/传输限制，只能收紧，不能通过递归或 fallback 恢复默认值。
# no_request 禁止所有普通 provider（包括 authority）的网络查询，仍可读取允许的本机材料。
# local locker 是本地访问；Zone locker 由 allow_zone_lock 单独控制，不受 no_request 开关控制，
# 但必须服从同一传输限制和预算。严格不联网的调用同时设置 no_request + without_zone_lock。
# Zone locker 自己向外 resolve 时关闭 allow_zone_lock；这只防再次选择自己，不能证明传输无环。
# allow_local_cache 只决定普通缓存是否使用磁盘；内存缓存一直存在，不改变验证规则。
# 不要求多个来源在同一时刻回答；已经知道的禁用/撤销和本地 exp 检查不能因缓存命中跳过。

# publish_info=None 表示 NoAnswer，不是禁用，也不证明从未发布。
# publish_info 包含 DID/类型级状态、可信 owner 绑定和有明确 iat 的发布记录。
# 按 revision 查询当前发布版本、指定版本或 closest；公共状态、版本记录和查询回答分别缓存。
# exact 查询必须返回该 iat 的实际发布 hash，以便核对；closest 回答还须确认该查询边界内没有更高发布版本。
# record_for(iat) 只返回覆盖该 iat 的记录；当前 V1 的 hash 不约束 iat 不同的 V2。
# 已发布记录含 hash；显式“该版本未发布”和 NoAnswer 均不妨碍继续验签。
# Invalid(reason) 是 authority 对 (did, doc_type) 确定性校验失败的明确回答（如 BNS device/zone 身份不一致）：
# 不是 Unknown、不退避、可短 TTL 缓存；选择时等同 NotExist；不升级 DID 禁用；不阻止 trust/normal 候选经 owner 链验签。
# authority 不得把这类失败报成 5xx（cyfs-gateway#207 根因 3）。

# verify_result 的事实字段：is_signed / is_published / is_revoked / is_expired / is_disabled。
# is_signed 只表示签名核验通过，trust 免签不设置它；未检查的事实保留 unknown/reason。
# validity = valid / invalid / unknown；缺材料是 unknown，身份/hash/签名确定错误是 invalid。
# is_best / is_latest / is_exact / is_closest 是输入与可用选择的关系，无效时都为 False。
# success(revision) = validity == valid 且命中目标；current 普通文档取 best，owner 取 latest。
# exact/closest 还须有对应查询的发布依据；签名有效但目标发布无法确认时，success=False 并保留原因。
# 签名正确但已撤销的文档可以返回 is_signed=True、is_revoked=True，其它选择标志为 False。

# ---------- 目录/路径入口与 HTTP 文档载体 ----------
# 本节补充本轮讨论的获取约定；具体 HTTP header 名称/编码不在此伪代码中冻结。
# 无对象子路径的 did:bns:xxxx 是目录型；did:bns:xxxx:aaa:bbb 是路径型 DID Object。
# HTTP Object URL 按 URL.path 的尾 "/" 区分目录/路径，query 不参与判断；
# 不能先 trim 尾 "/" 或把两者作为同一发现入口缓存，丢掉查询语义。
# DID 表示与 Object URL 分开：冒号路径由 method 映射到 URL 路径，
# did:web:example.com:user:alice 对应 https://example.com/user/alice。
# 未带 "/" 的根名字 DID 仍按 method 识别为目录，不能套用裸 HTTP URL 的尾斜杠判断。
#
# 目录入口按 method/发布模式的既有规则取得默认 did.json：
# - 根域名静态发布沿用 /.well-known/did.json；BNS Web 映射使用配置的 bridge host。
# - 显式 HTTP 目录 https://example.com/user/alice/ -> 同目录 did.json，保留原 query。
# 路径对象默认直接 GET 映射后的原 URL，不追加 /did.json、/owner.json 或其它类型文件；
# 只有显式选择非默认文档类型时，才在该 URL 上设置 type 查询参数。
# 默认路径文档是 DID Object Card（逻辑 doc_type 为 did-object），通常不构造 type 参数。
# 内部 doc_type 用于匹配/缓存，不等于必须发出的 query selector；
# 调用入口按已知对象/发布契约确定默认类型，不把全局 zone 默认值套给路径对象，
# 也不能依据未验证响应把调用方要求的类型悄悄改掉。缓存键仍使用真实 doc_type。
# 设置 type 使用 URL query API，保留无关参数；已有选择器与调用方要求冲突时拒绝，
# 不覆盖业务参数或重复拼多个 type；query selector 不改变 Object DID。
# 入口未指定 doc_type 时可先从输入 URL 的显式 type 归一实际类型，再进入缓存/串行流程；
# 已指定类型则必须一致。默认查询/目录分支同样校验已有 type，不能因不新增参数而漏检。
# doc_type=None 的归一在缓存键之前完成，表示接受 method/provider 的默认类型，不是 zone 的别名：
# - 路径型对象 -> did-object；
# - 无子路径的 did:bns:<name> -> BNS provider 按 active 类型集合选择：唯一则取之，多个无默认报 ambiguity，
#   多个且含 zone 取 zone 并在 reasons 记 warn；
# - did:web 根域名 -> /.well-known/did.json，实际类型由文档内容确定；其它 method 自定规则并返回实际类型。
# 结果携带 requested_doc_type / actual_doc_type。旧 Zone 分支的 Device→Agent→Owner 探测删除；
# BNS 对 ood1.<name> 的设备槽位联合校验只挂显式 device 查询。
#
# 兼容边界：以上是 DID Object 直接入口的规则，不替换所有 provider 的 wire URL。
# BNS authority 等现有 /1.0/identifiers/{did}?type=... 仍按原 API 查询；
# 目录原有的显式类型文件（如 /.well-known/owner.json）继续使用。
# 旧路径型 did:web /{path}/did.json、/{path}/{doc_type}.json 发布模式保留为兼容路由，
# 由已知 method/provider 配置选择，不对新路径对象无条件追加这些后缀或无限盲试。
# HTTP 旧业务 body 不必改成 Card；提供者可在响应 header 内联完整 DID Document。
# 新客户端统一从 body/header 提取，旧客户端仍可使用原 body 和 Content-Type。
# 这需要 provider 实现增加能力；不声称所有旧端点已支持新入口、header 或历史查询。
#
# body 支持已有裸 JSON/JWT、DID Resolution Result 信封；
# header 只识别协议明确声明的文档字段，解码出原始 JSON/JWT，不把任意 header 当 Card。
# header binding 已定（http_did_resolver_api.md §8）：BuckyOS-DID-Document: "jwt <compact>" | "json <base64url>"，
# 单值 ≤ 16 KiB，重复出现或超限视为损坏而非缺席。
# Link 指向 Card 可作为后续可选扩展，不能替代本轮对 header 内联文档的支持。
# 提取后的 SourceAnswer.body 表示确切 DID Document，不一定是原 HTTP entity body。
# 原业务 body 没有声明为 DID Document 时，不参与 Card 冲突比较。
# body/header 同时声明文档时须身份、类型、iat/hash 一致；否则拒绝本次来源回答，
# 不按位置优先级挑一份，也不因此声明整个 DID 禁用。JWT 原文不能重序列化后比较。
# HTTP 错误、明确禁用/撤销和 publish_info 仍按原契约处理，header 不能覆盖这些事实。
# header 只是载体，不提升 authority/trust 等级，不自动产生发布依据或 is_signed；
# Card 的 URL/DID 绑定、controller/Owner、时间与签名仍走同一验证规则。
# Card 有效也不自动证明旧业务 body 的内容完整性；Card 更新须使旧响应头可过期/重验，
# 缓存 TTL 不能覆盖 Card 自身 exp，旧业务 body 的 ETag 不能冒充 Card 的 iat/hash。


def build_document_request_url(location, doc_type):
    # location 来自已知 method/provider 路由和调用输入，保留目录标记、原 URL 和对象身份。
    location.check_input_type_selector(doc_type)
    if location.is_resolver_api() or location.is_legacy_static_route():
        return location.existing_document_url(doc_type)  # 保持原 API/静态发布路由。
    # 默认逻辑类型归一为无 selector；显式非默认类型才需要选择器。
    selector = location.non_default_type_selector(doc_type)
    if location.is_directory():
        # 默认按根目录 well-known 或显式 URL 目录规则补 did.json；
        # 已有目录显式类型的映射继续沿用该发布契约，不影响路径对象的 query 规则。
        return location.directory_document_url(selector)
    url = location.object_url.copy()
    if selector is not None:
        url = url.with_document_type_query(selector)  # 安全合并 query；冲突则拒绝，不静默覆盖。
    return url


def document_answer_from_http(response, expected_did, doc_type, opts):
    opts.budget.check()
    # response 保留原 Object URL 与实际请求/重定向上下文；对象 URL 绑定不能误用 Card 存放地址。
    # helper 先处理 HTTP 状态和已有发布状态信封，再识别文档 body；
    # 支持旧业务 body + header，业务 body 不必是 JSON，且不强制下载无关的大文件。
    # 格式错误的显式 DID 文档/信封仍报错，不能借 allow_legacy_body 吞掉。
    answer = decode_http_source_answer(response, allow_legacy_body=True, opts=opts)
    header_doc = decode_declared_document_header(response.headers, opts=opts)
    # header 缺席返回 None；显式文档字段存在但损坏/超限则报来源回答错误，不伪装成缺席。
    if header_doc is not None:
        if answer.body is not None:
            require_same_exact_document(answer.body, header_doc, opts=opts)
        else:
            answer.body = header_doc  # 保留其原文、响应来源、时间和 header 载体信息。
        answer.remember_document_carrier("header")
    # 只检查请求身份/类型/URL 绑定，尚未完成信任验证；保留此前解析的状态与发布事实。
    # 无文档且无状态回答时保留“不提供 DID 文档”的原因，不把普通业务响应当解析成功。
    answer.check_requested_document_binding(expected_did, doc_type, opts=opts)
    return answer


# ---------- 请求来源与统一预算 ----------
# 来源信任等级和网络访问许可是两个维度：trust/authority 不自动意味着传输不依赖待建隧道。
# opts.network_sources 默认 all；authority_only 只允许普通 provider 中的 authority 发出请求。
# 此限制在查询缓存之后、实际 I/O 之前执行，不删除已有 trust/normal 材料，也不改变 best 的定义。
# 普通 resolve 仍收集 authority/trust/normal；authority Unknown 不构成全局停止补充源的规则。
# opts.transport_policy 默认使用普通传输；RTCP 身份引导使用 independent_control_plane：
# 仅允许本机可信配置声明、实际传输可保证不依赖目标隧道/Relay 转发入口的控制通道，未知则拒绝。
# 此策略约束身份/地址材料获取；最后绑定已验证身份的目标 RTCP 拨号另受连接准入控制，
# 其内部发现/补材料仍受该策略约束，不能借“最终拨号”例外恢复默认解析。
# provider 名称、等级和远端自报字段不能证明通道独立；authority 的地址解析/代理也必须满足该约束。
# 连接每一跳（DNS、代理、重定向、well-known/upper fallback、内部子查询）都执行同一限制；
# 不支持传递限制的 provider/locker 在受限路径不可用，不能偷偷改用默认 HTTP 客户端。
# 限制只约束此次获取，不把被禁止访问的站点标为不可信，也不凭缓存命中声明公网当前身份。
# opts.force_authority_query 默认 False；显式要求本次权威回答时跳过权威查询缓存，但可复用已有 body。
# 同一调用取得的精确回答可在 body/publish_info 间复用；记录本轮 receipt，跨调用缓存不能伪装成本轮查询。
# reusable_query_answer 只查本轮材料：可按新 receipt 的精确 hash 复用已有合法 body，保留 body 原来源；
# 不隐含联网、不刷新旧证据时间、不把 body 单独当作发布回答。缺少所问内容时返回 None。
# 本轮 receipt 属于请求上下文，随递归继承且按 DID/doc_type/revision/来源区分，不把缓存查询时间刷新为当前。
# 最外层新调用建立新的 receipt 集合；复用配置 Opts 不得继承上次调用的“本轮回答”。
#
# ResolveOpts::normalize 在最外层按 monotonic_now() + config.resolve_timeout 建立有限的绝对 deadline，
# 有调用方截止时间时取更早者；已有 budget 时只继承/收紧，owner current/closest 和重试不续期。
# 跨主机 locker 传剩余时长，由服务端按自己的单调时钟和本地上限收紧；不传可比较的绝对单调时钟值。
# 客户端仍执行自己的 deadline/取消，服务端也须终止无用工作，不能靠转发获得新的一整份预算。
# resolution_budget 包住整个操作，覆盖锁/并发许可等待、缓存 I/O、locker、provider、验证和提交。
# 同步解析/验签限制输入大小、深度和 key 数量，计算分片检查预算；不能依赖异步超时抢占同步计算。
# 每次请求的 connect/total timeout 取配置上限与剩余预算的较小值；provider 的内部重试共享剩余预算。
# 单个来源超时可返回 Unknown 并在剩余预算内尝试下个允许来源；总预算耗尽抛 ResolutionDeadlineExceeded，
# 取消抛 ResolutionCancelled，两者终止整次调用，不能 catch 后继续 fallback 或返回旧缓存冒充成功。
# 两种终止均不声明 DID 不存在/禁用/撤销；已经完成的合法原子提交保留，未完成工作取消。
# budget.run/上下文退出必须取消未共享的子任务、关闭未完成的连接并释放锁/许可，不能留下后台请求。
# serialize_document 的锁获取也可取消并受该 deadline 限制；调用链 visited 不能识别新入站请求的网络环。
# 同键串行锁不得跨 provider/locker I/O 持有：否则回流入站的受限解析会在同一把锁上等外层的补充源请求，
# 外层又在等入站的 TLS 握手，每次烧满整份预算才失败（cyfs-gateway#207）。
# 锁只包两段：读缓存/刷新约束/决定查询；验证后原子提交。I/O 阶段由任务合并（键含访问策略）去重。
# 跨进程原子合并也不是网络防环。
#
# 并发合并覆盖身份解析阶段；共享任务须有有限自身预算，各等待者保留自己的 deadline/取消信号。
# 合并键包含 scope/DID/doc_type/revision 及来源/传输/证据要求，受限请求不能加入会访问目标站点的任务。
# 单个等待者退出不取消其它有效等待者的任务，最后一个离开时取消无用任务；不能延长共享任务的期限。
# 并发数/等待队列有上限，真实来源/传输失败按目标、来源及访问策略短期退避，错误日志限流。
# 策略拒绝、调用者取消/预算不足不触发影响其它策略的共享退避；退避不能替代首次请求的门禁和超时。


def request_source(source, operation, did, doc_type, revision, opts):
    opts.budget.check()  # 总 deadline/取消向外传播，不转为可继续回退的 Unknown。
    if source.is_zone_locker():
        allowed = opts.allow_zone_lock()
        request_opts = opts.without_zone_lock()
    else:
        allowed = opts.allow_request() and (
            opts.network_sources == "all" or source.is_authority()
        )
        request_opts = opts
    if not allowed or not opts.transport_policy.permits(source):
        reason = "本次请求的来源或传输策略不允许访问"
        opts.record_unanswered(source, operation, reason, cacheable=False)
        # 策略拒绝只记录本次诊断；不写共享负缓存，否则会影响允许访问此源的其它调用。
        return Unknown(reason, cacheable=False)
    query = source.get_document if operation == "document" else source.get_publish_info
    # source 的实现接收并执行 request_opts，包含内部解析、每一跳的检查和剩余预算。
    # HTTP provider 内部用 build_document_request_url 选择文档入口，
    # 用 document_answer_from_http 统一提取 body/header；所有读取/解码仍在本预算内。
    # publish_info 的查询仍走其已有协议，不能从“header 中有 Card”推导发布状态。
    try:
        raw = opts.budget.run(
            lambda: query(did, doc_type, revision, opts=request_opts),
            connect_timeout=min(opts.connect_timeout, opts.budget.remaining()),
            request_timeout=min(opts.request_timeout, opts.budget.remaining()),
        )
        # 统一回答带 body/publish_info/reason/cacheable；发布查询的 None 归一为真实来源的 NoAnswer。
        return normalize_source_answer(raw, operation)
    except SourceTimeout as err:
        # 只捕获单个来源的超时；若总预算也已到期，check 必须向外抛终止错误。
        opts.budget.check()
        opts.record_unanswered(source, operation, str(err), cacheable=False)
        return Unknown(str(err), cacheable=False)


# ---------- 获取与选择 ----------
def resolve_did_ex(did, doc_type, revision=None, opts=None):
    revision = normalize_revision(revision)  # None -> current；exact 必须同时有 iat/hash。
    opts = ResolveOpts::normalize(opts, doc_type)
    # 串行键为 (scope, did, doc_type)，不同 revision 也会更新同一 best，不能分别加锁。
    # 锁只在 get_document 的读缓存段和 update_doc_result 的提交段内持有；
    # provider/locker I/O 和候选验证（含 owner 递归）不持锁，跨请求去重由任务合并负责。
    # 等待者重新读缓存并判断自己的输入/revision/opts，不能复用另一份文档的验证成功。
    # 不持数据库事务等待任何 I/O；跨进程由提交时的原子合并裁决最终结果。
    with resolution_budget(opts):
        result, publish_info = get_document(did, doc_type, revision, opts)
        if result.locked:
            return result
        if result.state.is_disabled():
            return result
        if doc_type == "owner" or (not revision.is_current() and result.satisfies_published_target(revision)):
            return result

        # authority/trust 取得的可用文档已经进入 best；普通候选按 iat 从高到低验证。
        # 同 iat 的候选逐个验证；无效候选不阻止同 iat 的合法文档。
        # current 检查所有候选；exact/closest 只检查对应发布查询选中的候选，缺依据则目标未满足。
        for doc, source in result.candidates.candidates_for(revision, publish_info).descending_iat():
            opts.budget.check()
            report = verify_document_ex(did, doc_type, doc, result, publish_info, source, revision, opts)
            if report.validity == "unknown":
                continue
            result.candidates.remove(doc.revision())
            if report.validity == "invalid":
                continue
            # 只推进到更高的已验证版本；同版本幂等，同 iat 不同 hash 拒绝并保留冲突原因。
            result.accept_verified(doc, source, report, revision)
            if revision.is_current() and result.best:
                break
            if not revision.is_current() and result.satisfies_published_target(revision):
                break

        if revision.is_current() and result.best:
            # 以本机低成本使用为目标，选出 best 后可清空候选，包括本轮暂时缺材料的候选。
            # best 后续失效时重新 resolve，不承诺本机保存完整历史或成为其它节点的文档源。
            result.candidates.clear()
        result = update_doc_result(did, doc_type, result, opts)
        return result


def resolve_did(did, doc_type, revision=None):
    revision = normalize_revision(revision)
    opts = ResolveOpts::default().allow_local_lock().allow_zone_lock().allow_local_cache()
    result = resolve_did_ex(did, doc_type, revision=revision, opts=opts)
    # current 下 owner 选择 latest，普通文档选择 best；指定查询只返回目标，不能退回 best。
    return result.select(revision)


def get_document(did, doc_type, revision, opts):
    locked = get_locked_document(did, doc_type, revision, opts)
    if locked is not None:
        return locked, None

    with serialize_document(did, doc_type, opts):  # 段 1：只包读缓存与刷新约束，不包任何 I/O。
        result = get_doc_result(did, doc_type, opts)
        refresh_known_constraints(result, opts)
    publish_info = get_publish_info(did, doc_type, revision, opts)
    result.apply_publish_info(publish_info)  # None 不抹掉已知状态，负状态覆盖其声明的 DID/类型/版本范围。
    if result.state.is_disabled():
        result = update_doc_result(did, doc_type, result, opts)
        return result, publish_info

    # 顺序：authority > trust > normal；owner 只查询 authority。
    # helper 可用已允许的本地材料构造源；内部递归查询仍继承 opts。
    for provider in SourceRegistry::providers_for(did, doc_type, opts):
        opts.budget.check()
        # 不持串行锁；get_document_by_provider 内部经 TaskMerger::merge_or_run 按 (scope, provider, did, doc_type,
        # revision, 访问策略) 合并并发的相同查询，受限请求不会加入会访问目标站点的任务。
        answer = get_document_by_provider(provider, did, doc_type, revision, opts)
        # 一次回答可同时带 body 和 publish_info；拆开缓存，避免重复网络请求。
        result.commit(answer, provider, revision, opts)
        if provider.is_authority():
            publish_info = merge_publish_info(publish_info, answer.publish_info)
        if result.state.is_disabled():
            break
        if (doc_type == "owner" or not revision.is_current()) and result.satisfies_published_target(revision):
            break
        # 默认 latest + best 收集本轮允许的来源，已有 latest 也继续寻找可能更高的 best。
        # authority 本轮回答的文档已验证并成为 best 时，其余来源并发查询，只等宽限期
        # （config.supplement_grace，默认 1 秒）：到期未回答记为该来源 Unknown，不退避、
        # 不终止调用；总预算耗尽/取消照常外抛。authority 未给出有效 best 时仍逐个等待（buckyos#684）。
        if provider.is_authority() and revision.is_current() and result.best_is(answer.body):
            rest = remaining_providers()
            grace_opts = opts.with_budget(opts.budget.child(config.supplement_grace))
            answers = gather(get_document_by_provider(p, did, doc_type, revision, grace_opts) for p in rest)
            opts.budget.check()
            for p, answer in zip(rest, answers):
                result.commit(answer_or_unknown(answer, p), p, revision, opts)
            break

    refresh_known_constraints(result, opts)
    result = update_doc_result(did, doc_type, result, opts)
    return result, publish_info


def get_locked_document(did, doc_type, revision, opts):
    opts.budget.check()
    # helper 将 Unknown/未覆盖归一为 None；明确的不存在/禁用仍是强制回答，不能当 miss 回退。
    if opts.allow_local_lock():
        answer = LocalLocker.get_document(did, doc_type, revision, opts)
        if answer is not None:
            return answer.DocResult::locked_from(revision, opts)
    if opts.allow_zone_lock():
        # Unknown/未覆盖归一为 None；策略拒绝不伪造“不存在”的强制回答。
        answer = locker_answer_or_none(
            request_source(ZoneLocker, "document", did, doc_type, revision, opts)
        )
        if answer is not None:
            return answer.DocResult::locked_from(revision, opts)
    return None


def get_document_by_provider(provider, did, doc_type, revision, opts):
    opts.budget.check()
    current = opts.reusable_query_answer(provider, did, doc_type, revision, "document")
    if current is not None:
        return current
    key = (opts.scope, provider.id, did, doc_type, revision.cache_key())
    cached = local_cache(opts).get_resolve_result(key)
    force_query = provider.is_authority() and opts.force_authority_query
    if cached is not None and cached.valid_until > now() and not force_query:
        return cached.answer  # 不刷新原查询时间。
    if not revision.is_current() and not provider.supports_publish_info():
        return Unknown("此来源不支持指定版本/closest 查询", cacheable=False)
    # 共享任务有自己的有限预算；每个等待者保留自己的 deadline/取消，最后一个离开才取消任务。
    answer = TaskMerger::merge_or_run(
        key=(opts.scope, provider.id, did, doc_type, revision.cache_key(), opts.access_policy_key()),
        run=lambda: request_source(provider, "document", did, doc_type, revision, opts),
        opts=opts,
    )
    opts.record_query_answer(provider, did, doc_type, revision, answer)
    # OK / NotExist / 来源回答的 Unknown 分开保存；Unknown 只短期退避，不能变成 NotExist/禁用。
    # 策略拒绝、调用预算/取消不得污染共享查询缓存；不能仅因构造了 Unknown 就缓存。
    if answer.cacheable:
        local_cache(opts).set_resolve_result(key, answer, answer.cache_ttl())
    return answer


def get_publish_info(did, doc_type, revision, opts):
    opts.budget.check()
    # 只返回本次所问版本的信息；locker 对 body/publish_info 分别回答，缺席的列继续查。
    if opts.allow_local_lock():
        answer = LocalLocker.get_publish_info(did, doc_type, revision, opts)
        if answer is not None:
            return answer
    if opts.allow_zone_lock():
        answer = request_source(ZoneLocker, "publish_info", did, doc_type, revision, opts)
        if answer.publish_info is not None:
            return answer.publish_info
    provider = get_method_authority(did)
    if provider is not None:
        current = opts.reusable_query_answer(provider, did, doc_type, revision, "publish_info")
        if current is not None:
            return current.publish_info
    key = (opts.scope, did, doc_type, revision.cache_key())
    cached = local_cache(opts).get_publish_info(key)
    if cached is not None and cached.valid_until > now() and not opts.force_authority_query:
        return cached.info
    if provider is None or not provider.supports_publish_info():
        return None
    answer = request_source(provider, "publish_info", did, doc_type, revision, opts)
    info = answer.publish_info
    # 公共状态与 (iat, hash) 记录分别合并；未回答不撤销已知负状态，None 只作短期退避。
    # None 的原因保留在本次诊断；只有真实来源的 NoAnswer 可缓存，策略拒绝/本地超时不能写入。
    opts.record_query_answer(provider, did, doc_type, revision, answer)
    if answer.cacheable:
        local_cache(opts).update_publish_info(key, info)
    return info


# ---------- 验证调用方给出的确切文档 ----------
def verify_document(did, doc_type, doc_body, revision=None, opts=None):
    revision = normalize_revision(revision)
    opts = ResolveOpts::normalize(opts, doc_type)
    with resolution_budget(opts):
        doc = parse_document(doc_body, opts=opts)  # 标准 JSON/JWT；受输入上限和预算约束，提取不等于信任。
        if not doc.matches(did, doc_type) or doc.iat is None:
            return Invalid("文档身份、类型或 iat 不合法")

        with serialize_document(did, doc_type, opts):  # 段 1：读缓存与刷新约束，不包 I/O。
            result = get_doc_result(did, doc_type, opts)
            refresh_known_constraints(result, opts)
        # locker 仍优先；这里比较的是收到的文档，不能用锁定的另一份文档替代它。
        locked = get_locked_document(did, doc_type, revision, opts)
        if locked is not None:
            result = locked
        cached = result.find_verified(doc.revision())
        # reusable_for 检查来源范围、owner/locker 依赖，以及目标查询的发布依据是否仍可复用。
        # 默认 best 的签名结论可复用，不为每次缓存命中强制刷新公网发布状态。
        # force_authority_query 时，缺本轮匹配 receipt 的旧验证结果不能让本次权威查询短路。
        if cached is not None and cached.reusable_for(revision, opts):
            report = cached.report.copy_for(doc)
            apply_known_constraints(report, doc, result, revision, opts)
            report.set_selection_flags(doc, result, revision)
            if report.success(revision):
                return report

        # 即便缓存命中失败，也可复用该确切文档原先取得的 authority/trust 来源材料。
        # 验签所用 owner/locker 依据失效时不能改作免签来源；单纯解绑不抹掉已有 trust 来源。
        source = reusable_source(cached, opts) if cached is not None else Source.normal()
        info = get_publish_info(did, doc_type, revision, opts)  # I/O 与 owner 递归都不持锁。
        report = verify_document_ex(did, doc_type, doc, result, info, source, revision, opts)
        if not result.locked:
            # 保存发布/撤销事实；只有 valid 的输入才可推进 best；不依赖业务准入结果。
            # update_doc_result 在段 2 的锁内重读存储并原子合并；合并后发现同 iat 不同 hash 则改报 invalid(conflict)。
            result.accept_verified(doc, source, report, revision)
            result = update_doc_result(did, doc_type, result, opts)
        report.set_selection_flags(doc, result, revision)
        return report


def verify_document_ex(did, doc_type, doc, result, publish_info, source, revision, opts):
    report = VerifyResult(locker_version=opts.locker_version())  # 默认 unknown，所有选择标志 False。
    if not doc.matches(did, doc_type) or doc.iat is None:
        return report.invalid("文档身份、类型或 iat 不合法")

    # 公共状态/owner 绑定可合并；hash 只能检查同 iat 的已发布记录。
    record = publish_info.record_for(doc.iat) if publish_info is not None else None
    if record is None:
        version_info = get_publish_info(did, doc_type, Revision.exact(doc.iat, doc.content_hash()), opts)
        publish_info = merge_publish_info(publish_info, version_info)
        record = publish_info.record_for(doc.iat) if publish_info is not None else None
    if record is not None and record.is_published:
        if record.hash != doc.content_hash():
            return report.invalid("同 iat 的发布记录与文档 hash 不符")
        report.is_published = True
    report.apply_publish_info(publish_info, doc.iat)
    apply_known_constraints(report, doc, result, revision, opts)

    # owner 文档不能靠自己签名建立信任；核对 authority/locker 返回的确切根文档。
    if doc_type == "owner":
        roots, _ = get_document(did, "owner", revision, opts)
        if not roots.contains_published_or_locked(doc.revision(), revision):
            return report.unknown("缺少该 owner 文档的权威或 locker 依据")
        report.use_root_evidence(roots, doc.revision())  # 保留发布/模拟发布依据，供外层更新 latest/历史记录。
        return report.finish(trusted=True)

    if record is not None and record.is_latest and report.is_published:
        # 当前权威发布记录精确锚定输入，可按权威依据通过；历史发布本身不跳过当前有效性判断。
        return report.finish(trusted=True)
    if not source.need_verify():
        # authority/trust 允许无签名 JSON。普通 trust 不产生 is_published/is_signed。
        # 免验签仍检查身份、时间及本地已知负状态，远端未知事实不冒充已检查。
        return report.finish(trusted=True)
    if not doc.is_jwt():
        return report.invalid("普通来源的文档需要 JWT 签名")

    expected_owner = get_expected_owner(did, publish_info, result)
    if expected_owner is None:
        return report.unknown("缺少可信 owner 绑定")
    if doc.owner != expected_owner:
        return report.invalid("owner 不匹配")

    owner_opts = opts.create_get_owner_opts()  # 继承来源/传输/locker 限制、同一预算/取消信号及环路检查。
    current_revision = Revision.current()
    signing_revision = Revision.closest(doc.iat)  # 与调用方要查询哪个子文档版本无关。
    current = resolve_did_ex(expected_owner, "owner", revision=current_revision, opts=owner_opts)
    current_owner = current.select(current_revision)
    # 第二次查询通常命中推导：current 来自 authority 且 current_owner.iat < doc.iat 时，
    # closest(doc.iat) 的槽位已由 current receipt 填好，不再发网络请求；否则走真实历史查询。
    historical = resolve_did_ex(expected_owner, "owner", revision=signing_revision, opts=owner_opts)
    signing_owner = historical.select(signing_revision)

    # 历史 owner 决定验签 key，当前 owner 决定当前撤销线，两份查询都可命中缓存。
    # 历史查询只确认当时的材料，旧 owner 的 exp 不按“今天”判断；不能用当前 owner 冒充缺失的历史版本。
    if signing_owner is not None:
        # 这里只核验签名，exp/撤销单独判断，才能报告“历史签名正确、当前已撤销”。
        if not verify_jwt_signature(doc, signing_owner.get_public_keys(), opts=opts):
            return report.invalid("签名错误")
        report.is_signed = True
    else:
        report.add_missing("签发时的 owner 文档：需要 closest 发布依据")
    if current_owner is not None:
        if current_owner.valid_iat is not None and doc.iat <= current_owner.valid_iat:
            report.is_revoked = True
        report.remember_owner(expected_owner, current_owner.revision(), role="current")
    elif current.state.is_disabled():
        report.is_revoked = True
    else:
        report.add_missing("当前 owner 文档：无法判断当前撤销约束")
    if signing_owner is not None:
        report.remember_owner(expected_owner, signing_owner.revision(), role="signing", revision=signing_revision)
    # 已撤销时保留 is_signed，但 finish 判 invalid，不允许进入任何成功选择。
    return report.finish(trusted=report.is_signed)


# ---------- 合并、失效与持久化的必要规则 ----------
def apply_known_constraints(report, doc, result, revision, opts):
    # 仅读取当前已有的状态和 owner 材料，不隐含网络请求；不把“未发现撤销”说成全网确认。
    check_time = now()
    if doc.doc_type == "owner" and not revision.is_current():
        check_time = revision.iat  # exact 在指定时刻、closest 在查询时刻检查根材料；不作为当前根。
    report.is_expired = doc.exp is not None and doc.exp <= check_time
    report.is_disabled |= result.state.is_disabled()
    report.apply_known_negative_states(did=doc.did, doc_type=doc.doc_type, iat=doc.iat)
    # 仅按可信绑定/名字结构定位当前 owner，不能使用候选自报的 owner；历史根不套用子文档撤销线。
    if doc.doc_type != "owner":
        owner_state, owner = get_cached_current_owner_for(doc.did, result, opts)
        if owner_state is not None and owner_state.is_disabled():
            report.is_revoked = True
        if owner is not None and owner.valid_iat is not None and doc.iat <= owner.valid_iat:
            report.is_revoked = True
    if report.is_expired or report.is_disabled or report.is_revoked:
        report.validity = "invalid"
        report.clear_selection_flags()


def refresh_known_constraints(result, opts):
    # 每次 resolve/verify 读结果时执行；验证缓存记录使用过的 owner revision 和 locker 配置版本。
    # owner 的 key/撤销约束、locker 等实际验证依据改变则旧验证结果 dirty，需要时重验。
    # owner 仅修改站点绑定不使旧 trust 文档失效；后续查询按新绑定构造来源。
    # 本机时间经过 exp、已知禁用/撤销也会撤掉选择资格，不必等待下一次网络 resolve。
    result.invalidate_changed_owner_or_locker_dependencies(opts)
    result.apply_cached_negative_states(opts)
    for choice in result.choices():
        apply_known_constraints(choice.report, choice.doc, result, choice.revision, opts)
        result.update_choice_validity(choice)
    result.expire_query_answers(now())  # 发布查询 TTL 与文档 exp 分开，历史回答不能无限复用。
    # best/latest 按当前时间判断；exact/closest 的 owner 历史材料按所查询的历史时间判断。
    # 失效 best 从选择中移除；尚可重验的 body 回到 candidates，确定撤销的 body 不重复验证。
    # latest 的发布记录可继续保留用于说明历史事实，但无效条目不满足 select/success。


# result.commit(answer, provider, revision, opts) 的逻辑：
# 1. Unknown 不改变已知事实；NotExist 是该源无文档，不自动等于 DID 禁用。
# 2. 只有 authority 的 publish_info 能合并状态和发布依据；trust/normal 不能声明发布或修改 owner 绑定。
# 3. 检查 body 的 DID/doc_type/iat，并校验该 iat 的已知发布 hash；应用已知时间/撤销约束。
# 4. authority 更新 latest/历史记录；历史回答不直接覆盖 latest。owner 至此结束，不设置 best。
# 5. 非 owner 的 authority/trust 文档经上述检查成为可用 best；trust 目前不声明正式发布。
# 6. normal 按 (iat, hash) 放入 candidates；多个来源的相同文档可合并来源，不覆盖其它 hash。
# best/同版本冲突的裁决与 accept_verified 相同；任何候选都不能凭自己的高 iat 推进已验证基线。
# exact/closest 槽还须匹配本次发布查询的回答；裸 body/仅有该版本已发布的记录不能证明 closest。
# 已缓存的合法 body 可按新的发布回答填入目标槽，不必重复下载；查询缺依据时只保留材料。
# satisfies_published_target/candidates_for/select 共用此规则；exact 核对 iat+hash，closest 核对查询边界。
# locker 的 DocResult::locked_from 同样按 revision 匹配目标，不用锁定的当前文档冒充指定历史版本。

# result.accept_verified/accept_verified 的逻辑：
# validity=unknown 保留待验材料；invalid 不推进 best；valid 才比较已经验证过的版本。
# 同 iat 同 hash 幂等，同 iat 不同 hash 将本次报告改为 invalid(conflict)，不替换旧版。
# 更旧但有效的文档仍可报告 is_signed/is_published，不会成为 best。
# 发布依据明确本输入为当前发布版本时更新 latest；历史发布只存历史，不能仅凭 is_published 更新 latest。
# accept_verified 同时保留报告里的发布查询依据；exact/closest 缺依据时即使输入 valid 也不能填目标槽。
# owner 的根证据同样按此处理，始终不写 best；模拟发布保持 locker 来源标记。
# set_selection_flags 每次针对本次 doc 和更新后的结果计算；invalid/unknown 一律清空选择标志。
# 跨进程提交后若最终状态已有同 iat 不同 hash，重新标记本次 invalid(conflict)，不能仍报验证成功。
# report.finish: 已知错误/过期/禁用/撤销优先 invalid；缺必要材料为 unknown；否则 trusted 才为 valid。
# finish 不把未查询到的发布信息当缺少必要材料，不把 trust 免签当 is_signed。


def get_expected_owner(did, publish_info, result):
    binding = trusted_owner_binding(publish_info, result)
    if binding is not None:
        return binding
    # 路径对象的 controller/Zone/Owner 链须先形成可信绑定；不能自报 controller 建根，
    # 也不能把“取得签发者的 owner 文档”实现为向对象 URL 追加 /owner.json。
    if did.method == "bns" and not did.has_object_path():
        return did.get_upper() or did  # 子名字的上级；一级用户的 profile 由自己的 owner 根验证。
    return None  # 其它 method 使用其可信绑定规则，不能取候选自报的 owner。


def SourceRegistry::providers_for(did, doc_type, opts):
    authority = get_method_authority(did)
    if doc_type == "owner":
        return available(authority)  # 不为查 owner 再通过同一 owner 构造 trust 源。
    # BNS owner 的绑定站点作为 trust，其它配置源为 normal；owner 材料获取继承 opts。
    # 构造来源优先用本地材料；需要补 owner 时走带同一 opts 的 resolve，不能绕过 request_source。
    # network_sources 不过滤已有来源缓存：authority_only 仍可复用本地材料，但不访问 trust/normal。
    return available(authority) + bound_trust_providers(did, opts) + normal_providers(did, opts)


def local_cache(opts):
    return DocStore(files+flock) if opts.allow_local_cache() else DocStore(memory)


def get_doc_result(did, doc_type, opts):
    return local_cache(opts).get_doc_result(opts.scope, did, doc_type) or empty_doc_result(did, doc_type)


def update_doc_result(did, doc_type, result, opts):
    # 段 2：在 serialize_document 内重读存储中的最新结果，再把本地快照按同键原子合并，
    # 保留未被更高版本替换的 best、公共负状态和分时间的历史记录。
    # 嵌入式存储负责跨进程裁决，内存后端提供同样的串行语义；不要求多个不同 DID 的全局快照。
    with serialize_document(did, doc_type, opts):
        return local_cache(opts).merge_doc_result(opts.scope, did, doc_type, result)


def commit_candidate_doc(did, doc_type, doc_body, source, opts=None):
    opts = ResolveOpts::normalize(opts, doc_type)
    # trust 只能由有权限的预装/配置入口指定，不能直接采用远端提交的 source 字符串。
    with resolution_budget(opts), serialize_document(did, doc_type, opts):
        result = get_doc_result(did, doc_type, opts)
        result.candidates.add(parse_document(doc_body, opts=opts), source)
        update_doc_result(did, doc_type, result, opts)


def remove_doc_result(did, doc_type, opts):
    # 删除普通文档缓存；不隐式解锁，不把已知禁用/撤销变成从未见过。
    opts = ResolveOpts::normalize(opts, doc_type)
    with resolution_budget(opts):
        local_cache(opts).remove_document_bodies(opts.scope, did, doc_type)


# ---------- 使用场景 ----------
def open_rtcp_tunnel(remote_did, requirement, caller_opts=None):
    # #207 的入口是 Relay 发起 RTCP 前解析目标，必须在这一阶段就限制来源：
    # https://github.com/buckyos/cyfs-gateway/issues/207
    opts = ResolveOpts::normalize(caller_opts, "device")
    opts = (
        opts.with_network_sources("authority_only")
        .with_transport_policy(independent_control_plane)
    )
    if requirement == "AuthorityCurrent":
        opts = opts.with_force_authority_query()
    # 本机 / Zone locker 按 hosts 模型优先且强制返回，两种要求下都先于 method authority。
    # Zone locker 是 Zone 级 hosts，让整个集群对同一 DID 得到一致结果，地位与本机 locker 相同，
    # 不按出站来源对待（buckyos#710：SN 中继的目标身份由 SN 自己的 zone resolver 回答，
    # 不再请求经本 SN 中继才能到达的该域名 HTTPS）。Zone locker 仍须传递剩余预算/取消和
    # without_zone_lock。访问 Zone locker 本身要经过的节点/中继（例如普通节点的 3180 经
    # RTCP 转发到 OOD）列入客户端的 Zone locker 例外（set_zone_locker_bypass），解析它们时
    # 跳过 Zone locker，否则访问 Zone locker 要先解析它们，形成回环。locker 的回答（含 missing/invalid/revoked）不再交给 authority；
    # locker Unknown / 未覆盖时，AuthorityCurrent 只接受本轮真实 authority 回答。
    # 把 snapshot 准入升级为 MethodAuthorityCurrent、或从权威否定中恢复的后台确认，
    # 要的是 method authority 本身的回答：那里关闭两种 locker。
    with resolution_budget(opts):
        result = resolve_did_ex(remote_did, "device", opts=opts)
        if result.locked:
            identity = result.select(Revision.current())  # trust：host / zone snapshot
        else:
            identity = select_authority_current(result, requirement, opts)
        if identity is None:
            return error("目标身份材料不足或不满足 RTCP 身份要求", result.reason)
        # 没有 locker 回答时，select_authority_current 是 RTCP 的证据门禁，不直接把普通
        # select(current) 的 best 当公网当前：AuthorityCurrent 从本轮真实 authority receipt
        # 选择有效文档，检查精确 DID/type/iat/hash 绑定。
        # 即使缓存 best 更新，也不能用它替换 receipt 指定的 body；旧 latest/Unknown 不满足本次确认。
        # TrustedSnapshot 按自身准入策略检查允许的本地依据，不能因来源限制而放宽验证。
        # 复用/建连携带这一确切身份快照；地址材料获取也继承来源/传输限制和剩余预算，
        # 不在下层重新调用默认 resolve。实际 RTCP 建连仍完成持钥证明、身份绑定和业务准入。
        return connect_rtcp_with_identity(remote_did, identity, opts=opts)


def on_rtcp_hello(hello, caller_opts=None):
    if hello.to != self.did:
        return error("我不是你的目标")
    # 与 outbound 的握手共用剩余预算；新入站从握手入口建立有限预算，不信任对端指定更长的期限。
    opts = ResolveOpts::normalize(caller_opts, "device").not_allow_request().without_zone_lock()
    report = verify_document(hello.from_did, "device", hello.device_doc, opts=opts)
    if not report.success(Revision.current()):
        return error("device doc 验证失败", report.reason)
    # 缺 owner 等材料先结束本次握手；应用可在独立、限并发且有退避的控制通道任务中补齐再重试。
    # 独立任务可建立自己的有限预算，但继续使用独立通道限制，不在原请求链内放开来源调用默认 resolve。
    # 不自动无限重试；RTCP 仍独立完成持钥证明和业务准入，同键锁等待也受握手剩余预算限制。


# 设计验收（隔离环境；不向生产 Relay 制造回流）：
# - 普通 current：authority 成功或 Unknown 后仍查询允许的 trust/normal，并能选出更高的有效 best。
# - RTCP outbound：模拟 BNS 502/503、断连、不响应、坏身份；目标 HTTPS 指向同一 Relay，
#   断言 trust/normal 网络调用为 0，且等待、连接、FD 在总预算内释放；另一合法 Zone 仍可用。
# - no_request + without_zone_lock：冷缓存及 owner current/closest 均不联网，缺材料明确失败。
# - 显式启用独立 Zone locker：body/publish_info 均执行传输门禁；禁止经目标隧道回流及重定向绕过。
# - authority 自身的 DNS/代理/内部 fallback 需要目标 RTCP 时，受限请求直接拒绝，不因 authority 等级放行。
# - 串行锁等待、owner 递归、多 provider 重试共用 deadline；超时/取消不残留请求或锁，
#   不写禁用状态、不污染普通调用缓存；并发合并不跨访问策略复用网络任务。
# - AuthorityCurrent：本机 / Zone locker 的强制回答优先（trust 记为 host/zone snapshot，含负状态）；
#   没有 locker 回答时不接受模拟发布/旧 receipt/仅 trust best；有效身份、吊销与隧道复用仍按原准入要求检查。
# - 目录/路径：无 path 的 BNS 根按 method 目录规则取 did.json；:aaa:bbb 直取对象 URL，
#   默认 did-object 不附 type，非默认类型才安全合并 query；显式 URL 尾 "/" 不被提前抹掉。
# - 旧 resolver API、根目录显式类型文件、已配置的旧路径静态发布路由仍可使用；
#   新路径入口不无条件追加 /did.json 或 /owner.json，路径对象缺可信绑定时不自建 Owner 根。
# - 旧 HTML/JSON/媒体 body + 合法文档 header 可提取 Card；body/header 两种载体同等验证，
#   相同文档幂等、不同文档拒绝该响应；损坏/超限 header 不覆盖负状态或绕过验证。
# - authority 只支持 current 且文档 iat 晚于当前 owner 发布时间：closest 由推导得到，不发历史查询；
#   文档 iat 早于当前 owner 时 501 保留缺材料原因，不用当前 owner 冒充。
# - authority 回答 Invalid：不退避、类型级负状态；normal JWT 仍可经 owner 链成为 best；AuthorityCurrent 拒绝。
# - 回流：外层默认策略解析在补充源 I/O 中，入站受限策略解析同一 (scope, did, doc_type) 不被串行锁阻塞，
#   各自在预算内结束；BNS 对健康 Zone 返回 503/不响应时 Relay 对自身连接数不增长。


def get_device_info(device_name):
    # Info 不走普通 DID Document 验签/发布，由 Zone locker 提供 zone 内共享。
    return resolve_did(self.zone_did.child(device_name), "device_info")


def get_user_profile(user_did):
    owner = resolve_did(user_did, "owner")
    profile = resolve_did(user_did, "profile")
    return merge_fields_by_iat(owner, profile)  # 应用层按 iat 合并，高版本字段覆盖低版本。


def get_app_doc(app_did):
    return resolve_did(app_did, "app")


def preinstall():
    for doc in build_preinstall_app_docs():
        # 预装是无签名 JSON，iat=编译时间，作为本机配置的 trust 候选；只影响 best，不改变 latest。
        # 后续更大 iat 的正式/可信版本仍可替代；不为预装增加第四种信任等级。
        commit_candidate_doc(doc.did, "app", doc, Source.configured_trust("preinstall"))


# 产品刷新口径：常规缓存窗口约 30s；无缓存首次查询可立即看到新版本，离线时不承诺 30s。
# 安装器按结果提示五种情况：无法确认有效性、latest、best、已发布历史版本、未确认发布的历史版本。
# 过期/撤销和未完成的检查单独显示，不能用颜色掩盖；安装策略可允许用户强制安装。
# 升级按 iat 判断；测试环境可通过 locker 改 owner/root 或模拟发布，配置变化使相关验证缓存重判。

# ---------- 后续迁移 ----------
# TODO(AppDoc)：修正 buckyos 中 JSON AppDoc + 独立 AppDocSignatureEnvelope 的另行设计，
# 统一使用 DID Document 的 JSON/JWT 两种形式和 iat 版本约定；同步 AppDoc/PIKG 生成、发布、读取和验签。
# 普通来源用 JWT，可信来源可以用无签名 JSON；不在 resolver 内增加 AppDoc 独立签名适配层。
