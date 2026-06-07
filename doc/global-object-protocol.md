# 设计理念

## 什么时候用Global Object
成本上： DID-Object(一个域名1个) > GlobalObject > CYFS NamedObject（代表的是数据）

## 核心流程

1. 用URI表达的标准Global Object Document
2. 指定Object Profile的方法
3. 基于Object Profile，可以使用标准协议
- 访问属性
- 调用方法
- 链接事件


## 协议设计

### 通过URI得到 Global Object Document

> DID-Document兼容
> 基于域名的did和基于uri-path的DID的核心区别是 ？


### Global Object Profile的定义

> 兼容 W3C Wot Thing Description 2.0 (是其子集)

### 调用方法（xcall）

基于(拼接出来)的endpoint ，发送krpc请求。参数里有时也会带上objid

### 订阅事件

基于(拼接出来)的endpoint ，建立事件通知的通道（只支持ws://和wss://）
通常一个对象只有一个事件endpoint,不同的事件有不同的event frame

### 访问属性

标准的GET 

不太变化，非结构化的内容，放到属性里
不太变化，结构化的内容，放到Object Document里
经常变化，的内容，放到调用方法里
