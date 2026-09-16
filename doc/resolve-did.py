# 伪代码 不考虑异步，全是逻辑

# doc_result的设计
## state：当前did+doc_type的状态，正常 / 被禁用 / 未知，并保留原因和来源。
## latest: 通过权威源获得的已发布的最新版本。本机预装和模拟发布不冒充正式发布(locker可以）
## best: 有可验证签名的 最高版本,可以等于latest
## closest: 根据Opts中给定的iat时间,选择刚好小于该iat的已经发布版本（一般只有owner doc支持）
## condidates: 未验证的候选doc,类型是 iat->(doc,source)
## doc_result 是跨进程/线程 共享的，要注意处理好同步边界

# did-doc 版本与证据：
## revision = (iat, content_hash)，同 iat 的content_hash必然不同,iat不同哦那个content_hash必然不同。系统会拒绝同iat的第二个版本


# souce的设计
## 权威源(authority)
## 其它源(normal)
## 可信源(trust)

# opts 的设计：保留现有开关，不引入业务模式。
## 默认选 best；need_latest / closest_iat 只是获取和选择目标，不改变事实含义。
## no_request 禁止全部网络，包括 Zone 和递归 Owner 查询；仍可读允许的本地材料。
## allow_local_cache 是指允许读取磁盘上的cache,实现cache的跨进程，内存内的cache总是存在的
## 在无local_cache的系统里，只是会发生更多的网络请求（且进程间不共享），但一段时间后也会稳定下来


def resolve_did_ex(did,doc_type,opts):
    # 获得doc_result，该流程可能会通过权威源更新doc_result.latest
    doc_result,publish_info = _get_document(did,doc_type,opts)

    if opts.need_latest():
        if doc_result.latest:
            return doc_result
    
    #比如 owner_doc 不需要验证，也不会有condidates
    if !need_proof(doc_result,opts):
        return doc_result

    # 对整个doc_result进行一次验证,更新condidates和best
    # 因为latest,closest 必定来自权威源，这里假设权威源返回的结果一定应用了publish_info和owner_document里的负面约束
    # 不假设权威源
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
    doc_result = get_doc_result(did,doc_type,opts)
    # == 是做json 语义比较，JSON和jwt也可以比较
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
    is_changed = merge_doc_result_by_verify_result(doc_result,doc_body,verify_result)
    if is_changed:
        update_doc_result(doc_result,opts)
    return verify_result
    


def _verify_document_ex(did,doc_type,doc_body,doc_result,publish_info,opts):
    verify_result.is_best = false # 是能看到的最新版本
    verify_result.is_signed = false # 有有效的owner签名
    verify_result.is_latest = false # 是当前发布的最新版本
    verify_result.is_published = false # 曾经发布过
    verify_result.is_revoked = false # 已经被吊销
    
    if doc_result.latest == doc_body:
        verify_result.is_latest = true
    if doc_result.best == doc_body:
        verify_result.is_best = true 
    if verify_result.success():
        # 快速验证路径成功
        return verify_result

    if doc_body.is_json():
        return error("验证失败:doc需要有效的签名")

    # 正常情况下无法得到publish_info是正常的，一旦存在主要是做负面判断
    if publish_info:
        expected_owner = publish_info.owner
        if !publish_info.is_enable():
            return error("验证失败: did被禁用")
        if publish_info.is_revoke():
            verify_result.is_revoked = True
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

        # 执行验证
        if doc_body.iat < owner_doc.mini_iat:
            return error("验证失败: did_doc已经被吊销,签发时间早于owner要求的最小iat")
        
        if !verify_jwt(doc_body,owner_doc.get_public_key):
            return error("验证失败: 签名错误")

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
    if self.latest == None:
        self.latest = old_doc_result.latest
    
    if self.closest == None:
        self.closest = old_doc_result.closest

    self.condidates.merge(old_doc_result.condidates)

def doc_result.commit(self,resolve_result,source_type,opts):
    # 得到resolve_result,注意解析结果有 OK | Unknonw | NotExist ，不要搞错了
    # source_type 如果是 权威源，则会更新 latest 和 closet
    # source_type 如果是 可信源，则会更新 latest
    # 否则，只是增加condidate        
    pass

def get_expected_owner(did):
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


def local_cache.get_publish_info(did,doc_type,opts):
     if opts.allow_local_cache:
        return publish_info_db.get_doc_result(did,doc_type)
    else:
        return publish_info_map.get_doc_result(did,doc_type)   


# doc_result 持久化控制4函数，注意opts只决定用内存cache还是磁盘cache
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
    if hello.to != self.did:
        error("我不是你的目标")
    opts = Opts::default().not_allow_request()
    verify_result = verify_document(hello.from,"device",hello.device_doc,opts)
    if !verify_result.is_best:
        error("from devcie doc 验证失败 {}",verify_result.reason)

# 获取device_info
def get_device_info(deviceName):
    device_did = self.zone_did.child(deviceName)
    device_info = resolve_did(device_did,"device_info")

# 获取用户（did:bns:alice）的profile，应用层有合并
## 用户没有自己的ood,通过binded zone => did:web:example.com 获得信息
def get_user_profile(user_did):
    ## 获得 owner_doc
    owner_doc = resolve_did_ex(user_did,"owner")
    user_profile = resolve_did_ex(user_did,"profile")

    # 合并owner_doc和user_info,高版本覆盖低版本

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
    # 都是无签名的json格式app doc
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

