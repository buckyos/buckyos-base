# 伪代码 不考虑异步，全是逻辑
# REVIEW 说明：以下 Qxx 结合当前 Rust 实现记录讨论；标注“已确认”的是讨论结论，其余仍待讨论。
# P1 表示会影响验证/版本选择正确性，P2 表示接口、缓存或调用方迁移需明确；不检查伪代码语法。

# doc_result的设计
## state：当前did+doc_type的状态，正常 / 被禁用 / 未知，并保留原因和来源。
## latest: 已经发布的最高版本，通过权威源确认。本机预装和模拟发布不冒充正式发布(locker可以）
## best: 看到的、验证通过的最高版本，不要求已经发布，可以等于latest
## closest: 根据Opts中给定的iat时间,选择刚好小于该iat的已经发布版本（一般只有owner doc支持）
## condidates: 未验证的候选doc,类型是 iat->(doc,source)
## doc_result 是跨进程/线程 共享的，要注意处理好同步边界
# REVIEW Q01 [已确认：best/latest 定义；P1：验证依据待明确]
# best 是已看到且验证通过的最高版本，latest 是已发布的最高版本；允许 best=未发布 V2、latest=已发布 V1。
# 剩余问题：无签名预装/可信源免签是否也算“验证通过”？如算，应保留信任依据，不等同于 is_signed。
# latest 仍需要发布依据；可信来源本身不等于已发布。locker 模拟发布的范围和来源也需保留。

# did-doc 版本与证据：
## revision = (iat, content_hash)，同 iat 的content_hash必然不同,iat不同哦那个content_hash必然不同。系统会拒绝同iat的第二个版本
# REVIEW Q02 [P1，同版本冲突] 同 iat 同 hash 的重复获取应幂等，同 iat 不同 hash 才是冲突，对吗？
# condidates 若只以 iat 为键，先到的伪造候选可能占住合法版本；是否按 (iat, hash) 暂存，验证后再裁决？
# 现有 doc_cache.rs::merge_verdict 区分 AlreadyPresent/RejectedConflict；新的拒绝规则也应明确跨来源时如何处理。
# 回答：能通过签名验证的 相同iat不会是相同内容的（签名的时候会控制），这里主要是把这种异常情况快速失败了

# souce的设计
## 权威源(authority)
## 其它源(normal)
## 可信源(trust)

# opts 的设计：保留现有开关，不引入业务模式。
## 默认选 best；need_latest / closest_iat 只是获取和选择目标，不改变事实含义。
## no_request 禁止全部网络，包括 Zone 和递归 Owner 查询；仍可读允许的本地材料。
## allow_local_cache 是指允许读取磁盘上的cache,实现cache的跨进程，内存内的cache总是存在的
## 在无local_cache的系统里，只是会发生更多的网络请求（且进程间不共享），但一段时间后也会稳定下来
# REVIEW Q03 [P1，访问边界] no_request 与 allow_zone_lock 同时设置时，两个 get_* 都会先调用 Zone；
# 是否要求 Zone helper 自己检查 no_request，且 owner 派生 opts、动态 provider 发现也原样继承访问限制？
# 现有 provider.rs::ResolvePolicy 保留 LocalAndZone、without_zone_resolver、descend 环路保护及 current-zone 限制；
# 这些约束在新 opts 中如何表达，尤其 Zone 服务内部调用和 owner 递归不能重新查询自己？
# 回答:访问locker不算是发起request, 之前的设计太复杂了，现在参考修改/etc/hosts和自建dns server的心智模型进行了简化


def resolve_did_ex(did,doc_type,opts):
    # 获得doc_result，该流程可能会通过权威源更新doc_result.latest
    doc_result,publish_info = _get_document(did,doc_type,opts)

    # REVIEW Q04 [P2，返回闭环] 权威文档（特别是 owner）若按来源视为验证通过，谁负责同时更新 best？
    # commit 的说明只更新 latest/closest，而这里 owner 直接返回，resolve_did 却只读 best，可能取不到 owner。
    # need_latest 未满足时允许返回仅有 best 的结果吗？建议明确“返回事实”与“目标已满足”的判断契约。
    # 回答：owner_doc作为信任根正常情况下要么通过locker设置，要么从权威源获取（因此没有best 只会是latest）
    if opts.need_latest():
        if doc_result.latest:
            return doc_result
    
    #比如 owner_doc 不需要验证，也不会有condidates
    if !need_proof(doc_result,opts):
        return doc_result

    # 对整个doc_result进行一次验证,更新condidates和best
    # 因为latest,closest 必定来自权威源，这里假设权威源返回的结果一定应用了publish_info和owner_document里的负面约束
    # 不假设权威源
    # REVIEW Q05 [P1，候选选择] 是否按 iat 降序验证，且不能低于已有 best？例如 V3 缺 owner、V2 验证通过，
    # “删除所有剩余候选”会丢掉刚保留的 V3，是否只清理已确定无效/不再需要的候选？
    # 每轮须把当前 doc 传给 _verify_document_ex；验证后的 best/候选删除也要提交，_get_document 中的保存早于验证。
    # 回答：总要有一个地方删除condidates, 大部分情况下,best一旦选中，其它的都不会被使用了。如果best被revoke,也就是再走有一次resolve流程
    for iat,(doc,source) in doc_result.condidates
        if source.need_verify()
            verify_result = _verify_document_ex(did,doc_type,doc_result,publish_info,opts)
            # 验证结果是unknown （比如断网/没有owner document） => 保留候选，并尝试验证下一个
            # 验证成功（有签名）：设置best,删除所有剩余候选并返回
            # 验证失败：删除当前候选并验证下一个 
        else:
            # 设置best,删除所有剩余候选并返回

    return doc_result

def resolve_did(did,doc_type):
    opts = Opts::default().allow_local_lock().allow_zone_lock().need_best().allow_local_cache()
    doc_result = resolve_did_ex(did,doc_type,opts)
    if doc_result.best:
        return doc_result.best
    else:
        return None

# 返回 doc_result
def _get_document(did,doc_type,opts):
    doc_result = default_doc_result()
    # 根据opts中的scope locker 获得doc，一般在开发环境使用
    # REVIEW Q06 [P1，锁的约束] lock 是“获取时优先返回”，还是也约束 verify 收到的确切文档？
    # 例如锁 V1 后直接 verify(V2)，当前 verify 没读 body lock，仍可能接纳 V2。只锁 body 是否还读取发布负状态？
    # 请明确锁的覆盖列及解锁效果；模拟 owner 验出的子文档不能在解锁后无条件沿用为生产信任（见 Q09/Q17）。
    # 回答: 锁的效果相当于传统的/etc/hosts配置，能确保必定返回
    if opts.allow_local_lock():
        doc_reuslt = local_locked.get_document(did,doc_type)
        if doc_result:
            return doc_result,null

    # zone_lock可以解决分布式一致性问题,buckyos对unkown did 通常使用这个模式短接，其内部可以触发一般性的get_document
    if opts.allow_zone_lock():
        doc_result = zone_locked.get_document(did,doc_type)
        if doc_result:
            return doc_result,null

    # 和权威源通信一次，获得publish_info(有cache), 可以知道该did是否禁用
    # 该过程可能会写入local_cache，让下面权威源的get_document_by_provider直接返回
    # publish_info是
    publish_info = get_publish_info(did,doc_type,opts)
    # REVIEW Q07 [P1，未知与否定] publish_info 可能因断网、no_request、method 不支持而缺失，不能直接等同禁用。
    # 能否区分 Unknown / 明确无发布记录 / Active / 禁用或撤销，并说明 DID 级禁用是否覆盖所有 doc_type？
    # 现有 name_query.rs 区分 NoAnswer 与 Negative；新设计放开“权威未知仍可验签”可以成立，但要保留这一区别。
    # 回答：publish_info无法获取（这里是等于None）是NoAnswer，属于常态,Negative作为publish_info的内部状态了
    
    if !publish_info.is_enable():
        doc_result.state = disable
        update_doc_result(doc_result,opts)
        return doc_result,publish_info

        
    old_doc_reuslt = get_doc_result(did,doc_type,opts)
    
    # 发起网络操作,一般的顺序 权威源 > 加速源（如有) > 普通源 ，对owner_doc, 只可用权威源
    # 比如 did:bns:app1.alice
    # 权威源 bns.buckyos.ai)
    # 其它源 opts 中的配置 
    # 可信源 https://alice.web3.buckyos.ai/  或  https://example.com/ (alice的owner_document里配置了binded zone=example.com), 
    if opts.allow_request():
        providers = _get_did_providers(did,doc_type,opts)
        for provider in providers:
            # 对权威源，一次通信应该也可以把publish info拉回来
            # provider 里有cache, ttl之内网络请求只会发送一次
            resolve_result = get_document_by_provider(provider,did,doc_type,opts)
            doc_result.commit(resolve_result,provider.source_type,opts)
            # 如果当前opts只是想知道latest,可以提前结束。整的的best总是会尝试多搞几下的
            # REVIEW Q05 续：已确认 best 只针对“看到且验证通过”的集合，不要求证明全网没有更高版本。
            # 这里尚未验证候选，is_ok(need_best) 的停止条件仍需明确；获取多少来源由查询策略决定。
            if doc_result.is_ok(opts):
                break

        # 把old_doc_result合并进来        
        doc_result.merge(old_doc_result)           
        update_doc_result(doc_result,opts)
        return doc_result,publish_info
    else
        return old_doc_reuslt,publish_info

def get_document_by_provider(provider,did,doc_type,opts):
    # 读本地cache
    closet_iat =  opts.get_closest_iat()
    if closet_iat:
        cache_key = provider.get_id()+did+doc_type+closet_iat
    else:
        cache_key = provider.get_id()+did+doc_type

    resolve_result,ttl = local_cache.get_resolve_result(cache_key)
    # REVIEW Q08 [P2，缓存期限] cache miss、Unknown 的短期退避和明确 NotExist 的缓存是否分别处理？
    # get_publish_info 返回的过期材料、doc_result 中的 latest/best 也需保留原 checked_at/valid_until；
    # 否则 provider TTL 过期后，旧 latest 仍可能经 merge 和快速路径无限续用。文档 exp 应作为独立的硬期限。
    # 回答：这种多来源的best select操作没必要追求强一致性，在当前的各种要素作用下best就好了。（类似DNS不会要求一个页面上同时解析多个域名的结果完全一致）
    if now() > ttl :
        local_cache.remove_resolve_result(cache_key)
        # 通过provider发起请求
        resolve_result = provider.get_document(did,doc_type,closet_iat)
        # 缓存结果（任何结果）
        local_cache.set_resolve_result(cache_key,resolve_result)

    return resolve_result


# 对一个文档的字节流 进行验证 （可以是 no_request模式）
## 从本地cache中加载，判断是否是已经验证过的内容
## 开始真正验证：
##    先看一下did的publish_info（可能直接拿到latest版本） => 是一个已发布的版本 / 是latest
##    拿到owner-document (注意根据iat拿) -> 是一个有正确签名的版本 -> 是best? (默认策略) 
def verify_document(did,doc_type,doc_body,opts):
    # REVIEW Q09 [P1，快速路径门禁] 所有成功出口之前，是否统一检查请求 DID/doc_type、文档 exp、已知禁用/撤销，
    # 以及本次 scope 下的锁/owner 约束？缓存相等只证明曾被接纳；owner 提高撤销线或解除测试锁后应失效。
    # 现有 verify_context.rs::verify_did_document 检查身份/类型/exp/负状态，name_client.rs 缓存命中也跑 owner replay guard。
    # 回答：TODO 这里之前的考虑是只有触发过resolve_did,才会真正的改变verify_document的结果... 
    #     这里要深度思考一下这个设计是否正确
    doc_result = get_doc_result(did,doc_type,opts)
    # == 是做json 语义比较，JSON和jwt也可以比较
    # REVIEW Q10 [P1，确切输入] 如果保留 payload 但替换 JWT 签名，JSON 语义相等会让坏签名命中 best/latest。
    # 是否改为按确切 artifact 的 hash 复用验证证据？现有 provider.rs::document_content_hash 对 JWT 原文取 hash，
    # 对 JSON 规范化序列化后取 hash；JSON/JWT 可比较业务内容，但不能因此继承彼此的签名或发布证明。
    # 回答：现在系统优先解决自己能用最低的成本完成可信解析的问题，不强调能成为别人的源（因此会比较愿意删除condidate），
    #       内核完成后，未来估计是通过zone-resolve来强化自己成为普通源的能力（让网络里有更多的普通源）

    
    if doc_result.latest == doc_body:
        verify_result.is_latest = true
    if doc_result.best == doc_body:
        verify_result.is_best = true 
    if verify_result.success():
        # 快速验证路径成功
        return verify_result

    # 从权威源获得关于该iat版本的publish info
    opts.set_iat(doc_body.iat)
    publish_info = get_publish_info(did,doc_type,opts)
    verify_result = _verify_document_ex(did,doc_type,doc_body,doc_result,publish_info,opts)
    # REVIEW Q18 已澄清：best 记录看到且验证通过的版本，verify 可更新它，不以调用方业务准入通过为前提。
    is_changed = merge_doc_result_by_verify_result(doc_result,doc_body,verify_result)
    if is_changed:
        update_doc_result(doc_result,opts)
    return verify_result
    


def _verify_document_ex(did,doc_type,doc_body,doc_result,publish_info,opts):
    verify_result.is_best = false # 是能看到的最新版本
    verify_result.is_signed = false # 创建时有有效的owner签名
    verify_result.is_latest = false # 是当前发布的最新版本
    verify_result.is_published = false # 曾经发布过
    verify_result.is_revoked = false # 已经被吊销
    # REVIEW Q11 [P1，成功含义] success() 的真值规则是什么？is_published 与 is_revoked 可以同时成立，
    # is_latest 也未必满足 need_best；是否先产出 Valid / Invalid(reason) / Unknown(dependency)，再判断选择目标？
    # 历史发布不应让已撤销文档提前成功，缺 owner 也不应与坏签名一样删除候选。所有入口应使用同一规则。
    # 回答：这个success一般是根据opts得到了best/latest/closet即可算成功 
    
    
    if doc_result.latest == doc_body:
        verify_result.is_latest = true
    if doc_result.best == doc_body:
        verify_result.is_best = true 
    if verify_result.success():
        # 快速验证路径成功
        return verify_result

    if doc_body.is_json():
        return error("验证失败:doc需要有效的签名")

    expected_owner = get_expected_owner(did)  

    # 正常情况下无法得到publish_info是正常的，一旦存在主要是做负面判断
    if publish_info:
        expected_owner = publish_info.owner
        if !publish_info.is_enable():
            return error("验证失败: did被禁用")
        if publish_info.is_revoke():
            verify_result.is_revoked = True
        # REVIEW Q12 [已确认语义，P1：流程待调整] 已发布 V1、未发布 V2 验证通过时，应允许 best=V2、latest=V1。
        # 下面的 else 不能仅因 V2 未发布就报 hash 错误，应继续验证；须区分未发布、查询未知和同版本 hash 冲突。
        # 这是相对现有 name_query.rs 解析路径要求命中已知锚点的行为变化；已知禁用/撤销仍需检查。
        # 回答 这里的语义是：通过iat查询回来了is_published（latest是最新已发布）,但是发布记录里的hash和当前doc_body不同，那就必然是错了（还挺严重)
        if publish_info.is_published(hash(doc_body)):
            verify_result.is_published = True
            if publish_info.is_latest:
                verify_result.is_latest = True
        else:
            return error("验证失败:hash错误")
        
    if verify_result.success():
        # 快速验证路径成功
        return verify_result

    if expected_owner != doc_body.owner:
        return error("验证失败: owner不匹配")


    # 获得验证需要的owner_document(最好是签发时的owner_document)
    # REVIEW Q13 [P1，历史验签与当前撤销] closest 的边界是 < iat 还是 <= iat？同秒更新 owner/签发子文档会受影响。
    # 历史 owner 可提供当时的公钥，但其旧撤销线不能覆盖当前已知撤销：旧私钥还能签出回填旧 iat 的新 JWT。
    # 是否保留当前 owner/绑定的负面约束，再单独选择历史验签材料？历史验签成功不等于当前可用于认证。
    # 现有 NsProvider 没有历史查询参数；OwnerDocument 有历史 key，新增 closest 还需约定历史不可得时的 Unknown 行为。
    # 回答 verify_result 把是否曾经发布，创建时的签名是否正确，当前是否有效（有没有被撤销）分开了，比如一个通过mini_iat撤销的doc(通常都未发布)是:
    #  is_best = false,is_latest = false,is_signed = true,is_published = false,is_revoked = true
    get_owner_doc_opts = opts.create_get_owner_opts()
    if opts.allow_veirfy_iat():
        get_owner_doc_opts.set_closest_iat(doc_body.iat)

    # 如果opts里有no_request,这里不会触发读放大    
    owner_doc_result = get_document(expected_owner,"owner",get_owner_doc_opts)
    if owner_doc_result.is_ok():
        if get_owner_doc_opts.allow_veirfy_iat():
           owner_doc =  owner_doc_result.closest
        else:
           owner_doc = owner_doc_result.latest
        
        if !verify_jwt(doc_body,owner_doc.get_public_key):
            return error("验证失败: 签名错误")

        # 执行验证
        # REVIEW Q13 续：现有 user.rs::validate_jwt_revocation 用 valid_iat，拒绝 iat <= valid_iat；
        # 此处 mini_iat 使用 <。这是字段重命名且边界改变，还是伪代码简写？应明确等于撤销线时的结果。
        # 回答 已修复
        if doc_body.iat <= owner_doc.mini_iat:
            verify_result.is_revoked = true

        verify_result.is_signed = True
        if doc_result.is_best(doc_body.iat):
            verify_result.is_best = True
    

    return verify_result

def get_publish_info(did,doc_type,opts):
    if opts.allow_local_lock():
        doc_reuslt = local_locked.get_publish_info(did,doc_type)
        if doc_result:
            return doc_result

    if opts.allow_zone_lock():
        doc_result = zone_locked.get_publish_info(did,doc_type)
        if doc_result:
            return doc_result
        

    publish_info,ttl = local_cache.get_publish_info(did,doc_type,opts)
    if ttl > now():
        return publish_info 

    # publish info只能从权威源获得(目前只有did:bns有支持publish_info的权威源)
    if opts.allow_request:
        provider = _get_did_providers(did)
        if provider.supports_publish_info():
            publish_info = provider.get_publish_info(did,doc_type,opts)
            # 这里有个细节，正对整个did+doctype的publish info 和 针对特定iat的publish info 应该分别缓存，但有共用的部分
            local_cache.update_publish_info(did,doc_type,publish_info)
            return publish_info
    
    return publish_info

def doc_result.merge(self,old_doc_result):
    # REVIEW Q14 [P1，合并规则] 这里没保留 old.best/state；本轮网络 Unknown 时，已有 best/禁用记忆是否会丢失？
    # closest 依赖目标 iat，不能把 closest(100) 直接合并给 closest(200)；是按目标分槽，还是存历史后每次选择？
    # latest 的有效期/来源、同 iat 冲突和旧负状态也需要明确合并规则，不能仅在字段为 None 时补旧值（见 Q08）。
    # 回答：这是一个减少伪代码长度的辅助函数，通常有closest的时候，old_doc_result和self都在一个context
    
    if self.latest == None:
        self.latest = old_doc_result.latest
    
    if self.closest == None:
        self.closest = old_doc_result.closest

    self.condidates.merge(old_doc_result.condidates)

def doc_result.commit(self,resolve_result,source_type,opts):
    # 得到resolve_result,注意解析结果有 OK | Unknonw | NotExist ，不要搞错了
    # source_type 如果是 权威源，则会更新 latest 和 closet
    # source_type 如果是 可信源，则会更新 latest(协议暂未支持) 和 best
    # REVIEW Q01 续：这里的 trust 是有正式发布授权的代理，还是只获准提供可接受文档的源？后者不应凭来源更新 latest。
    # 否则，只是增加condidate 
    # 回答：我更新了说明       
    pass

def get_expected_owner(did):
    # REVIEW Q15 [P1，owner 推导] 这个 helper 尚未接入验证；无 publish_info 时 expected_owner 没有来源。
    # 现有 provider.rs::structural_owner 只对 did:bns 子名字取 upper_did，did:web 和 BNS 一级名不按此规则推导。
    # 是否保留 method 规则 + 可信绑定？当前分支对有上级名字返回自身，且不能用候选自报 owner 填补可信绑定缺口。
    # 回答：伪代码写漏了，我补充了
    result_did = did.get_upper()
    if result_did == None:
        return upper_did

    return did

def need_proof(did,doc_type,doc_result)
    if doc_type.is_owner():
        return False

    # 去除了旧的info不需要proof的逻辑，info类的数据不应该通过did-doc体系发布
    #if doc_type.is_info():
    #    return false
    return True

def _get_did_providers(did,doc_type,opts):
    # 当did.type = "bns"时，有根据owner_document的配置构造可信源的逻辑
    # REVIEW Q16 [P1，绑定与授权] binded_zone 是定位地址，还是同时授权站点免 owner 签名发布 app/profile？
    # 现有 lib.rs 把 did:bns 的 WebProvider 注册为 NeedProof 补充源；升级为 trust 会扩大站点的权限。
    # 若确实委托免签，需明确 DID/doc_type 范围，并让缓存记录所依赖的 owner 绑定版本，unbind 后撤销该信任。
    # owner 本身仍须从权威/显式本地信任取得，否则为了找可信站点又解析同一个 owner，会形成循环。
    # 回答：实际情况是,bns因为成本问题只有user/owner doc,其它的doc其实都是通过trust provider分发的。（算best不算iat,这也是为什么现在使用best成为默认策略）
    #       设计上，trust源查询的结果不需要用签名验证，但也不算是正式发布（我在考虑如果trust上支持正式的publish info 才算发布）


def local_cache.get_publish_info(did,doc_type,opts):
     if opts.allow_local_cache:
        return publish_info_db.get_doc_result(did,doc_type)
    else:
        return publish_info_map.get_doc_result(did,doc_type)   


# doc_result 持久化控制4函数，注意opts只决定用内存cache还是磁盘cache
# REVIEW Q17 [P1，共享与提交] key 是否还要区分 scope/信任配置？测试锁下接纳的版本不能覆盖同 DID 的生产 best。
# update 是整份覆盖还是在存储内原子合并？V2/V3 并发验证、V3 先提交时，V2 必须得到“已落后”的结果而非覆盖 V3。
# 还需明确内存/磁盘是同一状态的两层还是两个独立空间，以及版本基线是否随 body 淘汰；这不只是多发网络请求的差别。
# 现有 doc_cache.rs 的 merge_verdict 可参考；单个文件 rename 原子并不保证跨进程的读-比较-写原子。
# 回答：在这里说的是语义，本地磁盘实现用sqlite会比较简单。内存里的原子性靠数据库设计保证。
#       这里有一个重要的基础语义，name_client对实质性的resolve/verify操作应该幂等的只有一个，后续操作block住再执行可以直接复用上一次行动的结果cache


def get_doc_result(did,doc_type,opts):
    if opts.allow_local_cache:
        return doc_result_db.get_doc_result(did,doc_type)
    else:
        return doc_result_map.get_doc_result(did,doc_type)

def update_doc_result(did,doc_type,opts):
    if opts.allow_local_cache:
        return doc_result_db.update_doc_result(did,doc_type)
    else:
        return doc_result_map.update_doc_result(did,doc_type)

def commit_condidate_doc(did,doc_type,doc_body,source,opts):
    if opts.allow_local_cache:
        return doc_result_db.commit_condidate_doc(did,doc_type)
    else:
        return doc_result_map.commit_condidate_doc(did,doc_type)

def remove_doc_result(did,doc_type,doc_body,opts):
    if opts.allow_local_cache:
        return doc_result_db.remove_doc_result(did,doc_type)
    else:
        return doc_result_map.remove_doc_result(did,doc_type)  


## --------- demos --------- 
# rtcp握手的时候对hello里的doc进行验证
def on_rtcp_hello(hello):
    # REVIEW Q18 [已澄清：best 不依赖业务准入；P2：RTCP 迁移]
    # best 记录看到且验证通过的版本，握手随后被拒绝不否定该事实；此前建议必须延后更新 best 的理由不成立。
    # 现有 rtcp.rs 在业务准入后提交缓存，迁移时需区分 best 的更新与连接准入；持钥证明及授权仍独立执行。
    # 当前入站验证使用 LocalAndZone，这里改为全禁网络会要求提前具备 owner 材料；缺材料应如何反馈/补齐？
    # 回答：简化rtcp协议内核的实现是设计目的之一，缺材料通过应用逻辑补齐。
    if hello.to != self.did:
        error("我不是你的目标")
    opts = Opts::default().not_allow_request()
    verify_result = verify_document(hello.from,"device",hello.device_doc,opts)
    if !verify_result.is_best:
        error("from devcie doc 验证失败 {}",verify_result.reason)

# 获取device_info
def get_device_info(deviceName):
    # REVIEW Q19 [P2，Info 迁移] need_proof 已说明 Info 退出 DID Document 体系，但这里仍通过 resolve_did 获取。
    # 现有 name_client.rs 有独立的 resolve_unproof_info_with_cache 路径；本例改用什么入口，还是保留兼容路由？
    # 回答：这里的意思是，通过Zone-resolve(zone locker)可以实现zone内的device info共享
    device_did = self.zone_did.child(deviceName)
    device_info = resolve_did(device_did,"device_info")

# 获取用户（did:bns:alice）的profile，应用层有合并
## 用户没有自己的ood,通过binded zone => did:web:example.com 获得信息
def get_user_profile(user_did):
    ## 获得 owner_doc
    owner_doc = resolve_did_ex(user_did,"owner")
    user_profile = resolve_did_ex(user_did,"profile")

    # 合并owner_doc和user_info,高版本覆盖低版本
    # REVIEW Q20 [P2，资料合并] 两种 doc_type 的 iat 能直接决定字段优先级吗？较新 profile 会覆盖 owner 的 name 等字段。
    # 现有 profile_resolver.rs::merge_profile_with_owner_document 始终让 owner 身份字段覆盖 profile；这是有意改变吗？
    # 同时“30s TTL”通常表示已缓存观察的刷新窗口，并不意味着任何新发布都至少等待 30s 才能被首次查询看到。
    # 回答：iat就能决定新旧版本了，这是一个有意的改变，30s说的是产品口径的最坏情况

## 用户调整profile:任何did_doc的调整，都需要至少30s 才能生效，可以通过一些lock接口来在一些scop强制生效

# 用户unbind zone

# 获取应用 (did:bns:app1.alice) 的app_doc
## 用户没有自己的ood,通过binded zone => did:web:example.com 获得信息
def get_app_doc(app_did):
    app_doc = resolve_did_ex(app_did,"app")

    
# 预装的app doc,并且能够支持升级
## 在系统中，通过配置文件添加了“相当于从可信源获得的 iat=编译时间 的app_doc_json",从而避免了build的时候需要对内置的xxx_doc进行签名 
## 这种配置，会让默认的 resolve_did_ex().best生效，但不会改变 resolve_did_ex().latest(正式发布的最新版本)
def preinstall():
    # REVIEW Q01/Q02 续：iat=本机编译时间 会不会比正式新版本的签发 iat 更大，从而让只按 iat 升级永远选预装版本？
    # 是否保留上游版本时间，或明确正式版本替换预装版本的规则？无签名 JSON 的信任依据应继续标为本机预装。
    # 都是无签名的json格式app doc
    # 回答：这正是目的，通过编译构造的app原理上肯定是比已经发布的版本更大的，但用户用源码构建后，也能得到后续自动更新的推送
    #       无签名 JSON 的信任依据继续标为本机预装 ： 现在不区分复杂的信任依据，就是3档 
    app_docs = build_preinstall_app_docs()
    for app_doc_json in app_docs:
        commit_condidate_doc(app_doc_json.did,"app",app_doc_json,"trust")
    

# 影响pikg的安装流程
## 正常情况下，resolve_did可以提示用户pikg的下面集中情况 （红 橙 黄 浅绿 绿）4个安全等级
## A.红 无法验证（没有owner的签名) B.绿 是latest版本 C.黄 是best版本 D.浅绿 提示是一个发布过的历史版本 E.橙 提示是一个未发布过的历史版本
## 通过安装器策略，都可以强行安装的（无视app-doc的验证），升级判断只看iat
## 如果要修改 resolve_did的验证结果，则需要使用lock() / commit 操作 （测试环境?)

# 强制改变特定owner_doc，能在测试环境模拟一些"真实发布行为"
## 比如特定app的自动升级流程，可以用lock()操作，修改指定did的owner_doc,进而可以在系统内签发假的新版本app_doc，进而触发验证
## 这个比较适合app开发者，在无正式的发布密钥的情况下，在一个生产环境的buckyos里进行app的网络升级测试

