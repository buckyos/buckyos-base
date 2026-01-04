# Resolve did-doc的流程

注意该流程不是objid->named obj的流程！

## 几个核心问题：能得到，能验证，定义协议

1. 按provicer的信任等级从高到低尝试resolve （因此高优先级的provider要尽快在本地失败，只处理自己能处理的did查询）
2. 同级别的proovider会同时请求，并尝试合并使用最新的那个解析结果
3. 本地缓存的保存策略与did与current-zone的关系有关，关系越近，越倾向于永久存储
4. 基于did-resolve 机制，优化URL并确定一些跨zone的url格式


## 几个关键的provider与协议

解析器0. 基于智能合约(BNS)的协议，协议上。是一个运行在current zone的http 解析器
解析器1. 基于dns协议的did-doc解析器（目前主力)
解析器2. 基于http的did-doc解析器，与0的协议基本相同，但更适合查询did:bns:$objname.$zonename 这种zone内的二级对象
- "https://{provider}/1.0/identifiers/{did?type=doc_type}", 
这种URL适合在有明确的provider的情况下查询任意did
- "https://{hostname}/.well-known/did.json","https://{hostname}/.well-known/doc-type.json","https://{hostname}/{did_inner_path}/did.json"
这种URL适合在没有provider的情况下，根据来自did的hostname,查询Zone内的did
解析器3. 基于udp广播的did-doc解析器，通过udp在局域网（或地址范围）广播查询请求，期待任意设备响应并返回

给定一个did,解析器2如何在provider为NULL时解析出did-doc? 
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

## 基于上述设计，buckyos规划了去中心互联网的新基础设施
- did:bns:xxx 的解析，取代DNS，并提供根信任(CA)。这个是可扩展的
- rtcp + x协议，取代tls+x协议
- bdt（未来），支持p2p的rtcp
- cyfs:// and datagram:// 拓扑无关的访问协议

### 与现在的基础设施兼容

向下兼容，可以在现有浏览器里支持下面几种访问
    https://www.alice.web3.buckyos.ai/index.html 通过web3网桥，让旧客户端也可以访问
    https://www.alice.bns.did/index.html  不依赖dns根解析

       ping $devicename.alice.bns.did 可以得到动态的地址信息（是否需要兼容DNS的解析） 
### 新的URL
    cyfs://www.alice.bns.did/index.html  不依赖ca证书（如果https协议的新版本支持rtcp的证书逻辑，则可以继续保持https)
基于zone的虚拟局域网
    rtcp://$devicename.alice.bns.did/:port  可以与设备发起可信的链接（直连，这个过程是走resolve-did的流程的，获得ip地址的过程会与zone-gateway-node连接）
    rtcp://ood1.alice.bns.did/rtcp://$devicename.alice.bns.did/:port  可以通过zone-gateway中转，与设备发起可信的链接
如何在互联网上通过URL公开zone的一个服务？ (buckyos需要定义一种通用的service-doc的格式)
    cyfs://smb.alice.bns.did/ 可以访问zone级别的smb服务(buckyos-selector外露的问题?)
        根据zone内的名字对象规范，stream://smb.alice.bns.did/ 可以访问zone级别的smb服务 ，该服务的详细定义，可以通过resolve-did("did:bns:smb.alice","service")得到
        某种意义，等价于先通过 https://alice.bns.did/services/smb  得到smb服务的doc,然后再基于doc里的信息，构造smb-client
        stream的实现:
            1. doc = resolve-did("smb.alice.bns.did","service") //得到service-doc
            2. select_stream_url_from_service_doc(doc) //根据service-doc的解析，然后根据解析结果构造正确的 stream url, 该流程里包含了一部分本地selector逻辑
            3. stream = open_stream(stream_url) //打开stream
   
    zone内名字对象类型上是：用户、设备、服务（应用服务），  服务和应用服务的区别在于 “是zone提供的服务，还是 zone内特定应用提供的服务”
    通过cyfs-gateway, 创建一个本地端口映射后，就能进行兼容性的使用， 445->stream://smb.alice.bns.did/ 

## 区分did-resolve与named obj get的流程
- named-obj-id可以很容易转换成did,因此只要ObjID->DID成立，且did-resolve框架种有正确的provider,那么named-obj-get就能工作
- named-obj-get是一个明确的，给定了target后的协议流程,可以实现成一个Provider
- named-obj-get不包含复杂的provider管理（所以是GET不是reslove)
- 并不是所有的did-doc都是named obj, 主要使用did的对象，使用did-resolve流程
- 系统谨慎的扩展did-doc的类型，而named-obj被设计成易于扩展
- 比如did:dev:$pubkey.zonename, 这个did就不是一个典型的named objid
- 有机会解析出地址(成为rtcp://中target的did)的对象，优先使用did-resolve流程 
- 对必须保存在system-config中的对象，优先使用did-resolve流程
  比如did:bns:$appname.$zonename, 虽然appname可以指向一个 pkg-meta,pkg-meta是一个namedobj,但此时使用did-resolve机制，更多的是指向一个"app instace doc",该app instance的信息并不是一个pkg-meta.
    

## 如何在bns合约中支持did:web:xxx 的解析？不能支持解析，但可以支持对owner的深度解析
- did:web:test.buckyos.io的owner如何指定？
  - 在DNS Record中，添加OWNER的意义：可以通过BNS合约得到完整的OwnerConfig,有更丰富的信息，并且在OwnerConfig与PKX冲突的情况下，提示攻击风险
- 标准的智能合约是能拥有did:web:xxx的，必须是其拥有者修改DNS Record来建立到BNS OwnerConfig的关系

## did-doc缓存设计：

- did-doc会缓存查询结果的优先级。低优先级的缓存结果，不会阻止高优先级的provider查询
- 有缓存的目的通常是减少查询，但会带来更新不及时的问题，不同级别的provicer的缓存策略不同,允许不同的provicer返回不同的缓存有效时间(而不只是doc里的exp time)
- 有的provider可以根据缓存里的信息构造context,获得更多的reslove机会？ （比如根据pkg owner的信息，获得更新pkg-doc的新地址)


## 现有体系的扩展方法：

- 通过一个新的did method + 特定的provider,实现扩展（扩展寻址和可信验证方法）
可以思考如何在buckyos中合理的增加对ens的支持
扩展后，可以让一个 rtcp://xxx.ens.did/ 的url 从不可达变成可达


## 参考：系统里的did-doc类型:用户,zone,设备，服务

因为历史原因，BuckyOS内置关键类型的DIDDocument，一般称作XXXConfig
并不是所有的did都可以与host之间完美互转。只有“顶层对象”才可以实现，非顶层对象did可以转换成一个url(buckyos目前只在内部使用该url,不鼓励发布该URL)

### OwnerConfig 
- 无ip (不能与一个Owner建立连接)
- did:bns:$name, did:bns:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc.$name, did:web:$hostname(不推荐)
  - doc_type = "owner"，由于`did:bns:$name` 默认doc_type是zone,所以这里几乎是一直要填写的
- did:bns:$name:users:root，did:web:$hostname:users:root 也能拿到Zone的OwnerConfig，此时不需要doc-type
- OwnerConfig(由公钥构造时可以无签名)

```json

```

### ZoneBootConfig
- 无ip
- did:bns:$name,did:web:$hostname
  - doc_type = "boot"
- ZoneBootConfig，有Owner的签名
因为要保存到TXT Record中，所以json设计非常紧凑。
正常逻辑不使用ZoneBootConfig,而是基于ZoneBootConfig构造ZoneConfig后使用
```json
```


### ZoneConfig
- 有ip,有exchange_key
- did:bns:$name,did:web:$hostname
  - doc_type = "zone" (也是默认doc-type,一般无需填写)
- ZoneConfig（由ZoneBootConfig构造时可以无签名)

```json
```

### DeviceMiniConfig
- did 无 （在常规逻辑中无法看到MiniConfig，也不应该去查询）
  - doc_type = 无，
- 有Owner的签名
因为要保存到TXT Record种，所以json设计非常紧凑
正常逻辑不使用DeviceMiniConfig,而是基于DeviceMiniConfig构造的DeviceConfig后使用
```json
```

### DeviceConfig
- 有ip,有exchange_key
- did:bns:$name,did:web:$hostname
  - doc_type = $devcie_friendly_name，(比如ood1,ood2)
- did:bns:$device_friendlyname.$name, did:web:$device_friendlyname.$hostname,did:dev:$pubkey
  - doc_type = 无，使用二级did的时候，名字是精确的所以也可以不指定
  - 没必要支持did:dev:$pubkey:$hostname?
- 注意device-did的确定，可能会深刻的影响rtcp stack中的session管理
- 由MiniConfig构造时无签名，但大多数时候，都是使用有签名的DeviceConfig.

注意当DeviceConfig中包含address的时候，说明该Device的netid是WAN，其resolve-ip的结果与resolve-did相关
```json
```

问题：
当有两个名字指向同一个DevcieConfig时，Cache系统如何识别？
当与Zone外设备连接时，DeviceConfig中不需要有太多的隐私信息？

### DeviceInfo
DeviceInfo是由Device自己签名构造的，包含Device实时信息的DeviceInfo，通常不参与resolve-did,但会参与resolve-ip


### ServiceInfo
- 有ip,有exchange_key
- did:bns:$service_name.$name,did:web:$service_name.$hostname
    - doc_type = $service_type ,比如http,smb.. 系统允许在一个名字上提供多个类型的服务，默认是http
    - 需要给service一个自签名来表达自己的身份么并允许更新一些信息么？
- ServiceInfo (有owner签名(或zone-verify-hub签名？),
service-info没有直接包含ip,而是说明提供服务的具体device did,再通过reslove(device_did)得到ip,exchange-key
```json
```

#### UserConfig
- 无ip (不能与一个User建立连接)
- did:bns:$name:users:$username
- UserConfig（应有所在zone的owner签名)
UserConfig通过Zone的技术设施，创建的只属于某个Zone的用户（传统的互联网账号都属于这一类）
当这个用户在BNS上有注册时，应该通过AlsoKnownAs说明其Global的身份，并使用从BNS查询得到的OwnerConfig来代替UserConfig

```json
```
- UserConfig + OwnerConfig的联合登录流程实例
