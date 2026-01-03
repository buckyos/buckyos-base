# Resovle did-doc的流程

注意该流程不是objid->named obj的流程！

## 几个个核心问题：能得到，能验证，定义协议

1. 按provicer的信任等级从高到低尝试resolve （因此高优先级的provider要尽快在本地失败，只处理自己能处理的did查询）
2. 同级别的proovider会同时请求，并尝试合并使用最新的那个解析结果
3. 本地缓存的保存策略与did与current-zone的关系有关，关系越近，越倾向于永久存储
4. 如果基于did-resove机制，优化URL并确定一些跨zone的url格式


## 几个关键的provider与协议

解析器0. 基于智能合约(BNS)的协议，本质上，是一个运行在current zone的http 解析器
解析器1. 基于dns协议的did-doc解析器
解析器2. 基于http的did-doc解析器，与0的协议相同，适合查询did:bns:$objname.$zonename 这种二级对象
解析器3. 基于udp广播的did-doc解析器，通过udp在局域网（或地址范围）广播查询请求，期待任意设备响应并返回

给定一个did,解析器2如何解析出did-doc? 
如果did是一个名字，did->local_host，得到解析器2的url,并发起http请求，获取did-doc
发起http请求前的解析工作，不能依赖解析器2，而是需要依赖解析器0和解析器1（让解析器2能工作的前提条件)
    0. 解析并验证zone-document,验证流程需要解析器0
    1. 如果zone-document中不包含地址，那么需要进一步解析nameinfo(得到动态的地址信息)
    2. 如果需要通过rtcp协议建立可信链接，还需要通过解析器0或1，得到gateway device的did-doc(exchange-key)

如果did是一个named-obj-id, 那么可以基于必要的信息，找到合适的zone,并用cyfs://协议发起请求，希望得到对应的named obj
    有哪些是必要的信息？did:dev:$pubkey.$zonename, 传播者，收录者都是context
    这种did其实走的是named obj GET流程，不再是did-doc resolve流程了

## 综上,buckyos对did-doc resolve扩展的基础设施有

- 基于https协议的did-doc解析器（这个在协议设计上与w3c相兼容）
- 基于dns协议扩展实现的zone-doc解析器(DNS TXT的 BOOT ,PKX, DEV 扩展)
    在此之上，实现了对所有的did:web:xxx 的解析
- 实现了bns合约，并针对bns合约实现了通用的https did-doc解析器（只支持bns方法）
- 实现了基于cyfs://协议的did-doc解析器（使用rtcp+http协议），避免了大量解析器对ca证书的依赖

## 在上述基础设施的基础上，buckyos提供了去中心互联网的基础设施

did:bns:xxx 的解析，取代DNS，并提供根信任(CA)
rtcp + http协议，取代https
向下兼容，可以在现有浏览器里支持下面几种访问
    https://www.alice.web3.buckyos.ai/index.html 通过web3网桥，让旧客户端也可以访问
    https://www.alice.bns.did/index.html  不依赖dns根解析
    cyfs://www.alice.bns.did/index.html  不依赖ca证书（如果https协议的新版本支持rtcp的证书逻辑，则可以继续保持https)

基于zone的虚拟局域网
    ping $devicename.alice.bns.did 可以得到动态的地址信息（是否需要兼容DNS的解析）
    rtcp://$devicename.alice.bns.did/:port  可以与设备发起可信的链接（直连，这个过程是走resolve-did的流程的，获得ip地址的过程会与zone-gateway-node连接）
    rtcp://ood1.alice.bns.did/rtcp://$devicename.alice.bns.did/:port  可以通过zone-gateway中转，与设备发起可信的链接

如何在互联网上通过URL公开zone的一个服务？ (buckyos需要定义一种通用的service-doc的格式)
    stream://smb.alice.bns.did/ 可以访问zone级别的smb服务(buckyos-selector外露的问题?)
        根据zone内的名字对象规范，stream://smb.alice.bns.did/ 可以访问zone级别的smb服务 ，该服务的详细定义，可以通过resolve-did("did:bns:smb.alice","service")得到
        某种意义，等价于先通过 https://alice.bns.did/services/smb  得到smb服务的doc,然后再基于doc里的信息，构造smb-client
        stream的实现:
            1. doc = resolve-did("smb.alice.bns.did","service") //得到service-doc
            2. select_stream_url_from_service_doc(doc) //根据service-doc的解析，然后根据解析结果构造正确的 stream url, 该流程里包含了一部分本地selector逻辑
            3. stream = open_stream(stream_url) //打开stream
   
    zone内名字对象类型上是：用户、设备、服务（应用服务），  服务和应用服务的区别在于 “是zone提供的服务，还是 zone内特定应用提供的服务”
    通过cyfs-gateway, 创建一个本地端口映射后，就能进行兼容性的使用， 445->stream://smb.alice.bns.did/ 

区分did-resolve与named obj get的流程
    named-obj-id可以很容易转换成did,因此只要ObjID->DID成立，且did-resolve框架种有正确的provider,那么named-obj-get就能工作
    named-obj-get是一个明确的，给定了target后的协议流程,可以实现成一个Provider
    named-obj-get不包含复杂的provider管理（所以是GET不是reslove)
    并不是所有的did-doc都是named obj, 主要使用did的对象，使用did-resolve流程
    系统谨慎的扩展did-doc的类型，而named-obj被设计成易于扩展
    比如did:dev:$pubkey.zonename, 这个did就不是一个典型的named objid
    有机会解析出地址(成为rtcp://中target的did)的对象，优先使用did-resolve流程 
    对必须保存在system-config中的对象，优先使用did-resolve流程
    比如did:bns:$appname.$zonename, 虽然appname可以指向一个 pkg-meta,pkg-meta是一个namedobj,但此时使用did-resolve机制，更多的是指向一个"app instace doc",该app instance的信息并不是一个pkg-meta.
    


## 如何在bns合约中支持did:web:xxx 的解析？
    标准的智能合约是不行的，有权属不清的问题
    核心问题是,bns合约中如何确认有权添加记录？ bns合约的时代代码中，不能读取DNS Record!

## 系统里的did-doc类型:用户,zone,设备，服务
    无ip,owner-config(did:bns:zonename#owner,无签名), user-config（did:bns:$username.$zonename，有所在zone的owner签名)
    有ip,zone-boot-config(did:bns:zonename，有owner签名), zone-config (did:bns:zonename#full 有ood签名)
    有ip,device-mini-config(did:bns:$devname.$zonename，有zone的owner签名), device-config(did:bns:$devname.$zonename#full 有owner的签名),device-info(did:bns:$pubkey.$zonename,device自己签名)
    有ip,service-info(did:bns:$servicename.$zonename，有owner签名),需要给service一个自签名来表达自己的身份么？
        service-info没有ip,而是说明提供服务的具体device-name,再通过reslove(device)得到ip?

## did-doc缓存的问题：
    有缓存的目的通常是减少查询，但会带来更新不及时的问题
    不同级别的provicer的缓存策略不同,允许不同的provicer返回不同的缓存有效时间
    根据缓存里的信息构造context,获得更多的reslove机会？ （比如根据pkg owner的信息，获得更新pkg-doc的新地址)


## 现有体系的扩展方法：
    通过一个新的did method + 特定的provider,实现扩展（扩展寻址和可信验证方法）
    扩展后，可以让一个 rtcp:// url 从不可达变成可达