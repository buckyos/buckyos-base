# BNS 介绍
BNS是与DNS的对应，是buckyos未来的默认名字系统
BNS使用智能合约作为底层，完整的支持了 name(did:bns:$name) -> did-document的查询,以及name->name_info的查询

## 解决的关键问题

### 去中心化的实现 name->did-document 的可信查询
基于智能合约的特性
- 通过name可以得到可信的owner（OwnerConfig,包含公钥）
- 智能合约保障了只有Owner才能更新did-document，并通过Owner公钥对DID-Document的JWT进行传播验证

比现在的DNS协议可靠（防篡改）

### 支持交易
可以安全的实现name交易（更换owner),这里name可以遵循NFT协议
交易后由于owner的公钥变化，要及时更新所有DIDDocument的JWT

## 子名字
BNS通过合约机制，允许任何人“注册”新名字，并将名字绑定到任意DID-Document。但从成本和合约容量的角度来考虑，一般只需要把Zone-Document放上去就好了
后续可以使用子名字 did:bns:subname.zonename 
- 解析器会首先尝试向BNS查询subname.zonename，成功则返回
- 解析器查询zonename成功
- 解析基于zone-document的数据，向zone-resolver发起subname.zonename查询，返回did-document
- 基于zone-document的数据，对返回的did-document进行验证

## 实际使用

- 创建用户 （通常zonename和用户名相同）
创建did:bns:$zonename 默认段 -> zone-document , 附加段(owner) -> owner-config


### pkg的did

- 发布应用app
在自己的zone上发布 app-doc, app的did是 did:bns:$appname.$zonename, app的作者did是did:bns:$username, app的拥有者did是did:bns:$username
也可以选择给app一个唯一的名字 did:bns:$appname (此时appname不能被别人使用过)
did:bns:$appname 默认段 -> app-config

在系统内，可以加载的app都是需要PkgId的（在zone内repo上保持唯一即可）
一般是构成 nightly-linux-amd64.$zonename-$appname 这样的PkgName,PkgSimpleName是$zonename-$appname

- 提交应用
提交应用需要 “源” 提交`PkgSimpleName`,并依次提交 平台名.PkgSimpleName#版本号 => AppDoc的映射
一般的源，会根据did:bns:$appname.$zonename 对收到的appdoc进行验证，但源也有随意收入的权利


- 安装应用
用户通常可以基于 PkgId + 源 来
