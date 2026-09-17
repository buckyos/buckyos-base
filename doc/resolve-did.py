# 伪代码：只描述逻辑，不展开异步、数据库和 wire 格式。
# 根据 review 的回答整理。helper 的约定写在相邻注释中，不代表已有同名实现。

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

# opts 中和版本有关的需求提取到 revesion 参数中；opts 只保留请求、缓存、locker 等控制。
# revesion=None 等价于 Revision.current()：同时获取 latest + best，owner 只获取 latest。
# Revision.exact(iat, hash)：指定已发布版本；Revision.closest(iat)：最接近且严格早于 iat 的已发布版本。
# exact/closest 需要 resolver 的 publish_info 协议回答相应查询；locker 可在本 scope 模拟。
# 不支持/无回答时保留原因，不能退回当前版本，也不能把本机见过的最大历史版本当 closest。
# doc.revision() 是文档身份 (iat, hash)，revesion 是查询条件，二者不要混用。
# normalize/with/create_get_owner_opts 都返回副本；递归 owner 查询显式传自己的 revesion。
# no_request 禁止普通 provider 网络查询，递归 owner 查询继承；local/Zone locker 访问是例外。
# Zone locker 自己向外 resolve 时关闭 allow_zone_lock，避免请求自己；owner 递归同样保留该设置。
# allow_local_cache 只决定普通缓存是否使用磁盘；内存缓存一直存在，不改变验证规则。
# 不要求多个来源在同一时刻回答；已经知道的禁用/撤销和本地 exp 检查不能因缓存命中跳过。

# publish_info=None 表示 NoAnswer，不是禁用，也不证明从未发布。
# publish_info 包含 DID/类型级状态、可信 owner 绑定和有明确 iat 的发布记录。
# 按 revesion 查询当前发布版本、指定版本或 closest；公共状态、版本记录和查询回答分别缓存。
# exact 查询必须返回该 iat 的实际发布 hash，以便核对；closest 回答还须确认该查询边界内没有更高发布版本。
# record_for(iat) 只返回覆盖该 iat 的记录；当前 V1 的 hash 不约束 iat 不同的 V2。
# 已发布记录含 hash；显式“该版本未发布”和 NoAnswer 均不妨碍继续验签。

# verify_result 的事实字段：is_signed / is_published / is_revoked / is_expired / is_disabled。
# is_signed 只表示签名核验通过，trust 免签不设置它；未检查的事实保留 unknown/reason。
# validity = valid / invalid / unknown；缺材料是 unknown，身份/hash/签名确定错误是 invalid。
# is_best / is_latest / is_exact / is_closest 是输入与可用选择的关系，无效时都为 False。
# success(revesion) = validity == valid 且命中目标；current 普通文档取 best，owner 取 latest。
# exact/closest 还须有对应查询的发布依据；签名有效但目标发布无法确认时，success=False 并保留原因。
# 签名正确但已撤销的文档可以返回 is_signed=True、is_revoked=True，其它选择标志为 False。

# ---------- 获取与选择 ----------
def resolve_did_ex(did, doc_type, revesion=None, opts=None):
    revesion = normalize_revesion(revesion)  # None -> current；exact 必须同时有 iat/hash。
    opts = normalize_opts(opts, doc_type)
    # 串行键仍为 (scope, did, doc_type)，不同 revesion 也会更新同一 best，不能分别加锁。
    # 等待者重新读缓存并判断自己的输入/revesion/opts，不能复用另一份文档的验证成功。
    # 不持数据库事务等待 locker/provider；跨进程由提交时的原子合并裁决最终结果。
    # 递归 owner 使用另一文档键；保留调用链的环路检查，不在持有本键时再次进入本键。
    with serialize_document(did, doc_type, opts):
        result, publish_info = _get_document(did, doc_type, revesion, opts)
        if result.locked:
            return result
        if result.state.is_disabled():
            return result
        if doc_type == "owner" or (not revesion.is_current() and result.satisfies_published_target(revesion)):
            return result

        # authority/trust 取得的可用文档已经进入 best；普通候选按 iat 从高到低验证。
        # 同 iat 的候选逐个验证；无效候选不阻止同 iat 的合法文档。
        # current 检查所有候选；exact/closest 只检查对应发布查询选中的候选，缺依据则目标未满足。
        for doc, source in result.candidates.for_revesion(revesion, publish_info).descending_iat():
            report = _verify_document_ex(did, doc_type, doc, result, publish_info, source, revesion, opts)
            if report.validity == "unknown":
                continue
            result.candidates.remove(doc.revision())
            if report.validity == "invalid":
                continue
            # 只推进到更高的已验证版本；同版本幂等，同 iat 不同 hash 拒绝并保留冲突原因。
            result.accept_verified(doc, source, report, revesion)
            if revesion.is_current() and result.best:
                break
            if not revesion.is_current() and result.satisfies_published_target(revesion):
                break

        if revesion.is_current() and result.best:
            # 以本机低成本使用为目标，选出 best 后可清空候选，包括本轮暂时缺材料的候选。
            # best 后续失效时重新 resolve，不承诺本机保存完整历史或成为其它节点的文档源。
            result.candidates.clear()
        result = update_doc_result(did, doc_type, result, opts)
        return result


def resolve_did(did, doc_type, revesion=None):
    revesion = normalize_revesion(revesion)
    opts = Opts.default().allow_local_lock().allow_zone_lock().allow_local_cache()
    result = resolve_did_ex(did, doc_type, revesion=revesion, opts=opts)
    # current 下 owner 选择 latest，普通文档选择 best；指定查询只返回目标，不能退回 best。
    return result.select(revesion)


def _get_document(did, doc_type, revesion, opts):
    locked = get_locked_document(did, doc_type, revesion, opts)
    if locked is not None:
        return locked, None

    result = get_doc_result(did, doc_type, opts)
    refresh_known_constraints(result, opts)
    publish_info = get_publish_info(did, doc_type, revesion, opts)
    result.apply_publish_info(publish_info)  # None 不抹掉已知状态，负状态覆盖其声明的 DID/类型/版本范围。
    if result.state.is_disabled():
        result = update_doc_result(did, doc_type, result, opts)
        return result, publish_info

    # 顺序：authority > trust > normal；owner 只查询 authority。
    # helper 可用已允许的本地材料构造源；内部递归查询仍继承 opts。
    for provider in _get_did_providers(did, doc_type, opts):
        answer = get_document_by_provider(provider, did, doc_type, revesion, opts)
        # 一次回答可同时带 body 和 publish_info；拆开缓存，避免重复网络请求。
        result.commit(answer, provider, revesion, opts)
        if provider.is_authority():
            publish_info = merge_publish_info(publish_info, answer.publish_info)
        if result.state.is_disabled():
            break
        if (doc_type == "owner" or not revesion.is_current()) and result.satisfies_published_target(revesion):
            break
        # 默认 latest + best 收集本轮允许的来源，已有 latest 也继续寻找可能更高的 best。

    refresh_known_constraints(result, opts)
    result = update_doc_result(did, doc_type, result, opts)
    return result, publish_info


def get_locked_document(did, doc_type, revesion, opts):
    # helper 将 Unknown/未覆盖归一为 None；明确的不存在/禁用仍是强制回答，不能当 miss 回退。
    if opts.allow_local_lock():
        answer = local_locked.get_document(did, doc_type, revesion, opts)
        if answer is not None:
            return answer.as_locked_result(revesion, opts)
    if opts.allow_zone_lock():
        # locker 可以网络访问；服务端内部转发时必须关闭自己的 Zone locker。
        answer = zone_locked.get_document(did, doc_type, revesion, opts.without_zone_lock())
        if answer is not None:
            return answer.as_locked_result(revesion, opts)
    return None


def get_document_by_provider(provider, did, doc_type, revesion, opts):
    key = (opts.scope, provider.id, did, doc_type, revesion.cache_key())
    cached = local_cache(opts).get_resolve_result(key)
    if cached is not None and cached.valid_until > now():
        return cached.answer  # 不刷新原查询时间。
    if not opts.allow_request():
        return Unknown("provider 查询未获允许或缓存已过期")
    if not revesion.is_current() and not provider.supports_publish_info():
        return Unknown("此来源不支持指定版本/closest 查询")
    answer = provider.get_document(did, doc_type, revesion)
    # OK / NotExist / Unknown 分开保存；Unknown 只短期退避，不能变成 NotExist/禁用。
    local_cache(opts).set_resolve_result(key, answer, answer.cache_ttl())
    return answer


def get_publish_info(did, doc_type, revesion, opts):
    # 只返回本次所问版本的信息；locker 对 body/publish_info 分别回答，缺席的列继续查。
    if opts.allow_local_lock():
        answer = local_locked.get_publish_info(did, doc_type, revesion)
        if answer is not None:
            return answer
    if opts.allow_zone_lock():
        answer = zone_locked.get_publish_info(did, doc_type, revesion, opts.without_zone_lock())
        if answer is not None:
            return answer
    key = (opts.scope, did, doc_type, revesion.cache_key())
    cached = local_cache(opts).get_publish_info(key)
    if cached is not None and cached.valid_until > now():
        return cached.info
    if not opts.allow_request():
        return None
    provider = get_method_authority(did)
    if provider is None or not provider.supports_publish_info():
        return None
    info = provider.get_publish_info(did, doc_type, revesion)
    # 公共状态与 (iat, hash) 记录分别合并；未回答不撤销已知负状态，None 只作短期退避。
    local_cache(opts).update_publish_info(key, info)
    return info


# ---------- 验证调用方给出的确切文档 ----------
def verify_document(did, doc_type, doc_body, revesion=None, opts=None):
    revesion = normalize_revesion(revesion)
    opts = normalize_opts(opts, doc_type)
    doc = parse_document(doc_body)  # 标准 DID Document JSON 或 JWT；提取字段不等于信任。
    if not doc.matches(did, doc_type) or doc.iat is None:
        return Invalid("文档身份、类型或 iat 不合法")

    with serialize_document(did, doc_type, opts):
        result = get_doc_result(did, doc_type, opts)
        refresh_known_constraints(result, opts)
        # locker 仍优先；这里比较的是收到的文档，不能用锁定的另一份文档替代它。
        locked = get_locked_document(did, doc_type, revesion, opts)
        if locked is not None:
            result = locked
        cached = result.find_verified(doc.revision())
        # reusable_for 检查来源范围、owner/locker 依赖，以及目标查询的发布依据是否仍可复用。
        # 默认 best 的签名结论可复用，不为每次缓存命中强制刷新公网发布状态。
        if cached is not None and cached.reusable_for(revesion, opts):
            report = cached.report.copy_for(doc)
            apply_known_constraints(report, doc, result, revesion, opts)
            report.set_selection_flags(doc, result, revesion)
            if report.success(revesion):
                return report

        # 即便缓存命中失败，也可复用该确切文档原先取得的 authority/trust 来源材料。
        # 验签所用 owner/locker 依据失效时不能改作免签来源；单纯解绑不抹掉已有 trust 来源。
        source = reusable_source(cached, opts) if cached is not None else Source.normal()
        info = get_publish_info(did, doc_type, revesion, opts)
        report = _verify_document_ex(did, doc_type, doc, result, info, source, revesion, opts)
        if not result.locked:
            # 保存发布/撤销事实；只有 valid 的输入才可推进 best；不依赖业务准入结果。
            result.apply_verification(doc, source, report, revesion)
            result = update_doc_result(did, doc_type, result, opts)
        report.set_selection_flags(doc, result, revesion)
        return report


def _verify_document_ex(did, doc_type, doc, result, publish_info, source, revesion, opts):
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
    apply_known_constraints(report, doc, result, revesion, opts)

    # owner 文档不能靠自己签名建立信任；核对 authority/locker 返回的确切根文档。
    if doc_type == "owner":
        roots, _ = _get_document(did, "owner", revesion, opts)
        if not roots.contains_published_or_locked(doc.revision(), revesion):
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

    owner_opts = opts.create_get_owner_opts()  # 继承请求/缓存/locker 限制及环路检查。
    current_revesion = Revision.current()
    signing_revesion = Revision.closest(doc.iat)  # 与调用方要查询哪个子文档版本无关。
    current = resolve_did_ex(expected_owner, "owner", revesion=current_revesion, opts=owner_opts)
    current_owner = current.select(current_revesion)
    historical = resolve_did_ex(expected_owner, "owner", revesion=signing_revesion, opts=owner_opts)
    signing_owner = historical.select(signing_revesion)

    # 历史 owner 决定验签 key，当前 owner 决定当前撤销线，两份查询都可命中缓存。
    # 历史查询只确认当时的材料，旧 owner 的 exp 不按“今天”判断；不能用当前 owner 冒充缺失的历史版本。
    if signing_owner is not None:
        # 这里只核验签名，exp/撤销单独判断，才能报告“历史签名正确、当前已撤销”。
        if not verify_jwt_signature(doc, signing_owner.get_public_keys()):
            return report.invalid("签名错误")
        report.is_signed = True
    else:
        report.add_missing("签发时的 owner 文档：需要 closest 发布依据")
    if current_owner is not None:
        if current_owner.mini_iat is not None and doc.iat <= current_owner.mini_iat:
            report.is_revoked = True
        report.remember_owner(expected_owner, current_owner.revision(), role="current")
    elif current.state.is_disabled():
        report.is_revoked = True
    else:
        report.add_missing("当前 owner 文档：无法判断当前撤销约束")
    if signing_owner is not None:
        report.remember_owner(expected_owner, signing_owner.revision(), role="signing", revesion=signing_revesion)
    # 已撤销时保留 is_signed，但 finish 判 invalid，不允许进入任何成功选择。
    return report.finish(trusted=report.is_signed)


# ---------- 合并、失效与持久化的必要规则 ----------
def apply_known_constraints(report, doc, result, revesion, opts):
    # 仅读取当前已有的状态和 owner 材料，不隐含网络请求；不把“未发现撤销”说成全网确认。
    check_time = now()
    if doc.doc_type == "owner" and not revesion.is_current():
        check_time = revesion.iat  # exact 在指定时刻、closest 在查询时刻检查根材料；不作为当前根。
    report.is_expired = doc.exp is not None and doc.exp <= check_time
    report.is_disabled |= result.state.is_disabled()
    report.apply_known_negative_states(did=doc.did, doc_type=doc.doc_type, iat=doc.iat)
    # 仅按可信绑定/名字结构定位当前 owner，不能使用候选自报的 owner；历史根不套用子文档撤销线。
    if doc.doc_type != "owner":
        owner_state, owner = get_cached_current_owner_for(doc.did, result, opts)
        if owner_state is not None and owner_state.is_disabled():
            report.is_revoked = True
        if owner is not None and owner.mini_iat is not None and doc.iat <= owner.mini_iat:
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
        apply_known_constraints(choice.report, choice.doc, result, choice.revesion, opts)
        result.update_choice_validity(choice)
    result.expire_query_answers(now())  # 发布查询 TTL 与文档 exp 分开，历史回答不能无限复用。
    # best/latest 按当前时间判断；exact/closest 的 owner 历史材料按所查询的历史时间判断。
    # 失效 best 从选择中移除；尚可重验的 body 回到 candidates，确定撤销的 body 不重复验证。
    # latest 的发布记录可继续保留用于说明历史事实，但无效条目不满足 select/success。


# result.commit(answer, provider, revesion, opts) 的逻辑：
# 1. Unknown 不改变已知事实；NotExist 是该源无文档，不自动等于 DID 禁用。
# 2. 只有 authority 的 publish_info 能合并状态和发布依据；trust/normal 不能声明发布或修改 owner 绑定。
# 3. 检查 body 的 DID/doc_type/iat，并校验该 iat 的已知发布 hash；应用已知时间/撤销约束。
# 4. authority 更新 latest/历史记录；历史回答不直接覆盖 latest。owner 至此结束，不设置 best。
# 5. 非 owner 的 authority/trust 文档经上述检查成为可用 best；trust 目前不声明正式发布。
# 6. normal 按 (iat, hash) 放入 candidates；多个来源的相同文档可合并来源，不覆盖其它 hash。
# best/同版本冲突的裁决与 accept_verified 相同；任何候选都不能凭自己的高 iat 推进已验证基线。
# exact/closest 槽还须匹配本次发布查询的回答；裸 body/仅有该版本已发布的记录不能证明 closest。
# 已缓存的合法 body 可按新的发布回答填入目标槽，不必重复下载；查询缺依据时只保留材料。
# satisfies_published_target/for_revesion/select 共用此规则；exact 核对 iat+hash，closest 核对查询边界。
# locker 的 as_locked_result 同样按 revesion 匹配目标，不用锁定的当前文档冒充指定历史版本。

# result.accept_verified/apply_verification 的逻辑：
# validity=unknown 保留待验材料；invalid 不推进 best；valid 才比较已经验证过的版本。
# 同 iat 同 hash 幂等，同 iat 不同 hash 将本次报告改为 invalid(conflict)，不替换旧版。
# 更旧但有效的文档仍可报告 is_signed/is_published，不会成为 best。
# 发布依据明确本输入为当前发布版本时更新 latest；历史发布只存历史，不能仅凭 is_published 更新 latest。
# apply_verification 同时保留报告里的发布查询依据；exact/closest 缺依据时即使输入 valid 也不能填目标槽。
# owner 的根证据同样按此处理，始终不写 best；模拟发布保持 locker 来源标记。
# set_selection_flags 每次针对本次 doc 和更新后的结果计算；invalid/unknown 一律清空选择标志。
# 跨进程提交后若最终状态已有同 iat 不同 hash，重新标记本次 invalid(conflict)，不能仍报验证成功。
# report.finish: 已知错误/过期/禁用/撤销优先 invalid；缺必要材料为 unknown；否则 trusted 才为 valid。
# finish 不把未查询到的发布信息当缺少必要材料，不把 trust 免签当 is_signed。


def get_expected_owner(did, publish_info, result):
    binding = trusted_owner_binding(publish_info, result)
    if binding is not None:
        return binding
    if did.method == "bns":
        return did.get_upper() or did  # 子名字的上级；一级用户的 profile 由自己的 owner 根验证。
    return None  # 其它 method 使用其可信绑定规则，不能取候选自报的 owner。


def _get_did_providers(did, doc_type, opts):
    authority = get_method_authority(did)
    if doc_type == "owner":
        return available(authority)  # 不为查 owner 再通过同一 owner 构造 trust 源。
    # BNS owner 的绑定站点作为 trust，其它配置源为 normal；owner 材料获取继承 opts。
    return available(authority) + bound_trust_providers(did, opts) + normal_providers(did, opts)


def local_cache(opts):
    return sqlite_cache if opts.allow_local_cache() else memory_cache


def get_doc_result(did, doc_type, opts):
    return local_cache(opts).get_doc_result(opts.scope, did, doc_type) or empty_doc_result(did, doc_type)


def update_doc_result(did, doc_type, result, opts):
    # 按同键原子合并，保留未被更高版本替换的 best、公共负状态和分时间的历史记录。
    # sqlite 负责跨进程，内存后端提供同样的串行语义；不要求多个不同 DID 的全局快照。
    return local_cache(opts).merge_doc_result(opts.scope, did, doc_type, result)


def commit_candidate_doc(did, doc_type, doc_body, source, opts=None):
    opts = normalize_opts(opts, doc_type)
    # trust 只能由有权限的预装/配置入口指定，不能直接采用远端提交的 source 字符串。
    with serialize_document(did, doc_type, opts):
        result = get_doc_result(did, doc_type, opts)
        result.candidates.add(parse_document(doc_body), source)
        update_doc_result(did, doc_type, result, opts)


def remove_doc_result(did, doc_type, opts):
    # 删除普通文档缓存；不隐式解锁，不把已知禁用/撤销变成从未见过。
    local_cache(opts).remove_document_bodies(opts.scope, did, doc_type)


# ---------- 使用场景 ----------
def on_rtcp_hello(hello):
    if hello.to != self.did:
        return error("我不是你的目标")
    opts = Opts.default().not_allow_request()
    report = verify_document(hello.from_did, "device", hello.device_doc, opts=opts)
    if not report.success(Revision.current()):
        return error("device doc 验证失败", report.reason)
    # 缺 owner 等材料由应用补齐再重试；RTCP 仍独立完成持钥证明和业务准入。


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
