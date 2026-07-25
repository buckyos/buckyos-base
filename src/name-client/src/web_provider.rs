/*
web_resolver(doc/已有did-resolver介绍.md 第 2 节):did:web 的权威 resolver,
同时是 did:bns 的直连补充源。did:web 把身份锚定在域名的控制权上:文档发布在
该域名 HTTPS 站点的固定路径下,本 provider 是这个 canonical endpoint 的读取端。

获取顺序(同一发布渠道内的两个 HTTP 信道,均由本 provider 完成):
  1. 先查 W3C well-known 静态 URL(构造规则见下)。这个顺序的意义:持有域名和
     CA 证书的网站运营者只需静态部署一份符合规范的文件就完成了 DID 发布,
     不需要运行任何动态服务;
  2. well-known 拿不到文档时,回退到上级名字(uppername)的 resolver 接口:
       GET {scheme}://{uppername}/1.0/identifiers/{did}?type={doc_type}
     uppername 由通用的 `DID::upper_did()` 给出(去掉名字最左一个 label,
     did:web:ood1.example.com => did:web:example.com):上级域名可以为其全部
     子域集中提供动态解析,BuckyOS 里 zone gateway 为 zone 内设备 DID 提供
     解析就是这个形态。`upper_did()` 为 None 时不回退——域名默认至少有一个点,
     根域名(example.com)的上级只剩顶级域(com),不可能向它查询;IP host 同理;
  3. 两个信道都失败时 unknown 优先于 NotFound(与权威渠道多读取端的
     合并语义一致):只有两个信道一致回答"没有",才允许主循环归一成 Missing;
     410/deactivated 是权威负回答,出现即终止,不再尝试下一个信道。

did:bns:同样的取回逻辑作用在名字的规范 host 映射上(介绍文档第 2 节):
  did:bns:{name} ↔ {name}.{bns_root},bns_root 使用独立的 web3_bridge.bns
  配置(bns_provider.rs 的 bns_web3_bridge_host),不与 BNS 权威 resolver 的
  bns_host 混用。
  did:bns:alice        => https://alice.{bns_root}/.well-known/did.json
  did:bns:ood1.alice   => https://ood1.alice.{bns_root}/.well-known/did.json
    回退 uppername     => https://alice.{bns_root}/1.0/identifiers/did:bns:ood1.alice
  一级名字(alice)没有 uppername;它的权威解析由指向 bns_host 的
  bns_resolver 负责,这里不重复查询。
  注意:这条信道不是 BNS 的权威渠道(权威是 BNS 合约/网关),所以 WebProvider
  在 did:bns 下只能注册为补充源,产出 need_proof 候选,注册见 lib.rs。

well-known URL 构造遵循 W3C did:web 规范 §3.2 Read
(https://w3c-ccg.github.io/did-method-web/):
  1. 把 method-specific id 里的 ":" 全部替换成 "/",得到域名 + 可选路径;
  2. 对域名段做百分号解码,还原被编码成 %3A 的端口冒号(路径段不解码,原样拼接);
  3. 前面拼上 https:// 得到基础 URL;
  4. 如果没有路径,追加 /.well-known;
  5. 追加 /did.json 得到最终 URL。

did:web => url 映射:
  did:web:example.com                    => https://example.com/.well-known/did.json
  did:web:example.com:user:alice         => https://example.com/user/alice/did.json
  did:web:example.com%3A3000             => https://example.com:3000/.well-known/did.json
  did:web:example.com%3A3000:user:alice  => https://example.com:3000/user/alice/did.json
  回退信道(well-known 未命中后):
  did:web:ood1.example.com               => https://example.com/1.0/identifiers/did:web:ood1.example.com

BuckyOS 扩展:同一 DID 的多种文档发布在同一目录下,带 doc_type 的查询把文件名
did.json 换成 {doc_type}.json。默认 doc_type(zone)由归一层转成"不带 doc_type"
的查询(见 name_query.rs 的 legacy_doc_type),落在标准的 did.json 上:
  (did:web:example.com, None)             => https://example.com/.well-known/did.json
  (did:web:example.com, owner)            => https://example.com/.well-known/owner.json
  (did:web:example.com:user:alice, info)  => https://example.com/user/alice/info.json
  (did:web:ood1.example.com, owner) 回退  => https://example.com/1.0/identifiers/did:web:ood1.example.com?type=owner

输入校验(非法输入直接拒绝,而不是照拼,防止构造出跳出发布目录的 URL):
  - host 解码后只允许 [A-Za-z0-9.-] + 可选的一个纯数字端口;IDN 域名需用 punycode;
  - 路径段限制在 DID idchar 内([A-Za-z0-9._-] 及 pct-encoded 的 '%'),
    拒绝空段、"." 与 "..";
  - doc_type 只允许 [A-Za-z0-9_-]。

发布状态:did:web 的静态发布面没有独立的"发布状态"信道,`resolve_published_state`
恒为 Ok(None);由主循环把 `query_did` 的结果归一成权威回答(200 => Active,
404 => Missing,410/deactivated => 负状态,其余错误 => unknown),见 name_query.rs
的 authority_answer。上级 resolver 若返回带 buckyos 扩展的信封,query_did 里的
parse_response 已能拆包并识别 deactivated;待服务端信封实现后,这里可以经同一
uppername 端点补上真正的发布状态查询。did:web 的权威渠道 = DNS TXT + 本 provider
两个委托读取端的 first-win 合并,注册见 lib.rs。
*/

use crate::bns_provider::bns_web3_bridge_host;
use crate::{BaseHttpProvider, DidDocType, NameInfo, NsProvider, PublishedState, RecordType};
use async_trait::async_trait;
use log::{debug, info};
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use percent_encoding::percent_decode_str;
use reqwest::Client;
use std::net::IpAddr;

/// canonical endpoint 读取端:did:web 的域名发布面,以及 did:bns 名字的
/// 规范 host 映射(`{name}.{bns_root}`)。
pub struct WebProvider {
    client: Client,
    scheme: String,
}

impl WebProvider {
    /// 规范要求线上必须 https。
    pub fn new() -> Self {
        Self::new_with_scheme("https")
    }

    /// 仅供本地/测试环境用 http 连接自建站点。
    pub fn new_with_scheme(scheme: &str) -> Self {
        Self {
            client: Client::new(),
            scheme: scheme.to_string(),
        }
    }

    /// 规范第 1、2 步:id 的第一段是 host,百分号解码还原端口冒号,
    /// 并校验解码结果仍然是 hostname[:port] 的形状。
    fn decode_host(did: &DID, raw_host: &str) -> NSResult<String> {
        let host = percent_decode_str(raw_host).decode_utf8().map_err(|e| {
            NSError::InvalidDID(format!(
                "invalid did:web host in {}: {}",
                did.to_string(),
                e
            ))
        })?;

        let (name, port) = match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host.as_ref(), None),
        };

        let name_is_valid = !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
        let port_is_valid = match port {
            Some(port) => !port.is_empty() && port.parse::<u16>().is_ok(),
            None => true,
        };
        if !name_is_valid || !port_is_valid {
            return Err(NSError::InvalidDID(format!(
                "invalid did:web host: {}",
                did.to_string()
            )));
        }

        Ok(host.into_owned())
    }

    /// did:bns 的规范 host 映射(介绍文档第 2 节):did:bns:{name} ↔
    /// {name}.{bns_root}。名字部分不做百分号解码(bns 名字没有端口语义),
    /// 只放行 hostname 合法字符,防止拼出跳出发布目录的 host。
    fn bns_canonical_host(did: &DID, raw_name: &str) -> NSResult<String> {
        let name_is_valid = !raw_name.is_empty()
            && raw_name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
        if !name_is_valid {
            return Err(NSError::InvalidDID(format!(
                "invalid did:bns name: {}",
                did.to_string()
            )));
        }
        let bridge = bns_web3_bridge_host()?;
        Ok(format!("{}.{}", raw_name, bridge))
    }

    /// 名字(id 第一段)到取回 host 的映射:did:web 直接用解码后的域名,
    /// did:bns 落在名字的规范 host 映射上。
    fn canonical_host(did: &DID, raw_name: &str) -> NSResult<String> {
        match did.method.as_str() {
            "web" => Self::decode_host(did, raw_name),
            "bns" => Self::bns_canonical_host(did, raw_name),
            other => Err(NSError::NotFound(format!(
                "unsupported did method: {}",
                other
            ))),
        }
    }

    /// 路径段原样拼进 URL(pct-encoded 不解码),因此只放行 DID idchar,
    /// 并拒绝空段与 "." / ".."。
    fn validate_path_segment(did: &DID, segment: &str) -> NSResult<()> {
        let chars_ok = segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '%'));
        if segment.is_empty() || segment == "." || segment == ".." || !chars_ok {
            return Err(NSError::InvalidDID(format!(
                "invalid did:web path segment \"{}\" in {}",
                segment,
                did.to_string()
            )));
        }
        Ok(())
    }

    /// 文件名 stem:不带 doc_type 用规范的 "did",带 doc_type 用 doc_type 本身。
    fn doc_file_stem(doc_type: Option<&DidDocType>) -> NSResult<&str> {
        let doc_type = doc_type.map(DidDocType::as_str).unwrap_or("did");
        if doc_type.is_empty()
            || !doc_type
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(NSError::InvalidParam(format!(
                "invalid DID document type: {}",
                doc_type
            )));
        }
        Ok(doc_type)
    }

    /// 信道 1:W3C well-known 静态 URL(did:bns 用规范 host 映射代入同一构造)。
    fn build_url(&self, did: &DID, doc_type: Option<&DidDocType>) -> NSResult<String> {
        let doc_file = Self::doc_file_stem(doc_type)?;

        // 规范第 1 步:":" => "/"。第一段是名字(host),其余段构成路径。
        let mut segments = did.id.split(':');
        let raw_host = segments.next().unwrap_or_default();
        let host = Self::canonical_host(did, raw_host)?;

        let path_segments: Vec<&str> = segments.collect();
        for segment in &path_segments {
            Self::validate_path_segment(did, segment)?;
        }

        // 第 3~5 步:无路径 => /.well-known/{stem}.json,有路径 => /{path}/{stem}.json。
        if path_segments.is_empty() {
            Ok(format!(
                "{}://{}/.well-known/{}.json",
                self.scheme, host, doc_file
            ))
        } else {
            Ok(format!(
                "{}://{}/{}/{}.json",
                self.scheme,
                host,
                path_segments.join("/"),
                doc_file
            ))
        }
    }

    /// 信道 2:上级名字的 resolver 接口(与 BaseHttpProvider 的
    /// `/1.0/identifiers/{did}?type={doc_type}` 同一格式)。
    fn build_upper_resolver_url(
        &self,
        upper_host: &str,
        did: &DID,
        doc_type: Option<&DidDocType>,
    ) -> NSResult<String> {
        let stem = Self::doc_file_stem(doc_type)?;
        let base = format!(
            "{}://{}/1.0/identifiers/{}",
            self.scheme,
            upper_host,
            did.to_string()
        );
        if doc_type.is_some() {
            Ok(format!("{}?type={}", base, stem))
        } else {
            Ok(base)
        }
    }

    async fn fetch_document(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
        url: &str,
    ) -> NSResult<EncodedDocument> {
        debug!("web provider querying {}", url);
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        // 响应解析(404/410/deactivated 与 JsonLd/Jwt 归一,含 resolver 信封拆包)
        // 是 method-agnostic 的,统一复用 BaseHttpProvider。
        BaseHttpProvider::parse_response(did, doc_type, "web-provider", resp).await
    }

    /// 两个取回信道都失败时的错误合并:unknown(传输失败等)优先于 NotFound。
    /// 只有两个信道一致回答"没有",才能把 NotFound 交给主循环归一成 Missing
    /// ——与 AuthorityReaders 的读取端合并语义一致(宁可少回答,
    /// 不把断网伪装成从未发布)。
    fn merge_fetch_errors(well_known_err: NSError, upper_err: NSError) -> NSError {
        match (&well_known_err, &upper_err) {
            (NSError::NotFound(_), NSError::NotFound(_)) => well_known_err,
            (NSError::NotFound(_), _) => upper_err,
            _ => well_known_err,
        }
    }
}

#[async_trait]
impl NsProvider for WebProvider {
    fn get_id(&self) -> String {
        "web-provider".to_string()
    }

    fn methods(&self) -> Vec<String> {
        // 仅供 add_provider 兼容注册(首个注册者成为该 method 的权威渠道)。
        // did:bns 下本 provider 只能是补充源,不能经这条兼容路径注册,
        // 所以这里只自声明 web;did:bns 请用 add_method_supplement 显式接入。
        vec!["web".to_string()]
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "web provider does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        if did.method != "web" && did.method != "bns" {
            return Err(NSError::NotFound(format!(
                "unsupported did method: {}",
                did.to_string()
            )));
        }

        // 信道 1:well-known 静态 URL(静态部署优先,域名运营者不需要动态服务)。
        let well_known_url = self.build_url(did, doc_type.as_ref())?;
        let well_known_err = match self
            .fetch_document(did, doc_type.as_ref(), &well_known_url)
            .await
        {
            Ok(doc) => return Ok(doc),
            // 410/deactivated 是权威负回答,直接终止,不再回退。
            Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
            Err(err) => err,
        };

        // 信道 2:回退到 uppername(DID::upper_did)的 resolver 接口。
        // uppername 也走各 method 的规范 host 映射(did:bns:alice => alice.{bns_root})。
        let Some(upper_did) = did.upper_did() else {
            return Err(well_known_err);
        };
        let upper_host = Self::canonical_host(&upper_did, &upper_did.id)?;
        let resolver_url = self.build_upper_resolver_url(&upper_host, did, doc_type.as_ref())?;
        info!(
            "did:web well-known miss for {} ({}), falling back to upper resolver {}",
            did.to_string(),
            well_known_err,
            resolver_url
        );
        match self
            .fetch_document(did, doc_type.as_ref(), &resolver_url)
            .await
        {
            Ok(doc) => Ok(doc),
            Err(NSError::Disabled(msg)) => Err(NSError::Disabled(msg)),
            Err(upper_err) => Err(Self::merge_fetch_errors(well_known_err, upper_err)),
        }
    }

    async fn resolve_published_state(
        &self,
        _did: &DID,
        _doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        // did:web 的静态发布面没有独立的发布状态信道:恒为 Ok(None),
        // 让主循环把 query_did 的 200/404/410 归一成 Active/Missing/负状态
        // (name_query.rs authority_answer 的 Ok(None) 分支)。上级 resolver
        // 的 buckyos 信封在服务端实现后,可在此经同一 uppername 端点查询。
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;

    // ------------------------ did:web => url(W3C §3.2)------------------------

    #[test]
    fn builds_well_known_url_for_root_did() {
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        assert_eq!(
            provider.build_url(&did, None).unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn builds_path_url_for_did_with_segments() {
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:w3c-ccg.github.io:user:alice").unwrap();

        assert_eq!(
            provider.build_url(&did, None).unwrap(),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
    }

    #[test]
    fn decodes_percent_encoded_port() {
        let provider = WebProvider::new();

        let root = DID::from_str("did:web:example.com%3A3000").unwrap();
        assert_eq!(
            provider.build_url(&root, None).unwrap(),
            "https://example.com:3000/.well-known/did.json"
        );

        let with_path = DID::from_str("did:web:example.com%3A3000:user:alice").unwrap();
        assert_eq!(
            provider.build_url(&with_path, None).unwrap(),
            "https://example.com:3000/user/alice/did.json"
        );
    }

    #[test]
    fn http_scheme_is_available_for_local_test() {
        let provider = WebProvider::new_with_scheme("http");
        let did = DID::from_str("did:web:127.0.0.1%3A3200:devices:cam01").unwrap();

        assert_eq!(
            provider.build_url(&did, None).unwrap(),
            "http://127.0.0.1:3200/devices/cam01/did.json"
        );
    }

    // ------------------------ buckyos doc_type 扩展 ------------------------

    #[test]
    fn doc_type_replaces_file_stem() {
        let provider = WebProvider::new();
        let root = DID::from_str("did:web:example.com").unwrap();
        let path_did = DID::from_str("did:web:example.com:users:alice").unwrap();

        assert_eq!(
            provider.build_url(&root, Some(&DidDocType::Owner)).unwrap(),
            "https://example.com/.well-known/owner.json"
        );
        assert_eq!(
            provider
                .build_url(&path_did, Some(&DidDocType::custom("profile")))
                .unwrap(),
            "https://example.com/users/alice/profile.json"
        );
    }

    // ------------------------ did:bns 的规范 host 映射 ------------------------

    /// 测试进程内保证 web3 bridge 配置就位,并读回实际生效的 bns 根域
    /// (全局 OnceCell 可能已被其它测试或 machine.json 抢先初始化)。
    fn ensure_bns_bridge() -> String {
        let mut cfg = std::collections::HashMap::new();
        cfg.insert("bns".to_string(), "web3.buckyos.ai".to_string());
        let _ = name_lib::KNOWN_WEB3_BRIDGE_CONFIG.set(cfg);
        bns_web3_bridge_host().unwrap()
    }

    #[test]
    fn builds_bns_well_known_url_via_bridge_mapping() {
        let bridge = ensure_bns_bridge();
        let provider = WebProvider::new();

        let first_level = DID::from_str("did:bns:alice").unwrap();
        assert_eq!(
            provider.build_url(&first_level, None).unwrap(),
            format!("https://alice.{}/.well-known/did.json", bridge)
        );
        assert_eq!(
            provider
                .build_url(&first_level, Some(&DidDocType::Owner))
                .unwrap(),
            format!("https://alice.{}/.well-known/owner.json", bridge)
        );

        let sub_name = DID::from_str("did:bns:ood1.alice").unwrap();
        assert_eq!(
            provider.build_url(&sub_name, None).unwrap(),
            format!("https://ood1.alice.{}/.well-known/did.json", bridge)
        );
    }

    #[test]
    fn builds_bns_upper_resolver_url_via_bridge_mapping() {
        let bridge = ensure_bns_bridge();
        let provider = WebProvider::new();
        let did = DID::from_str("did:bns:ood1.alice").unwrap();

        let upper = did.upper_did().unwrap();
        assert_eq!(upper, DID::new("bns", "alice"));
        let upper_host = WebProvider::canonical_host(&upper, &upper.id).unwrap();
        assert_eq!(upper_host, format!("alice.{}", bridge));
        assert_eq!(
            provider
                .build_upper_resolver_url(&upper_host, &did, Some(&DidDocType::Owner))
                .unwrap(),
            format!(
                "https://alice.{}/1.0/identifiers/did:bns:ood1.alice?type=owner",
                bridge
            )
        );

        // 一级名字没有 uppername:它的 resolver 接口就是 BNS 网关本身,
        // 归 bns_resolver(权威渠道)负责,这里不产生回退请求。
        assert_eq!(DID::from_str("did:bns:alice").unwrap().upper_did(), None);
    }

    #[test]
    fn rejects_malformed_bns_names() {
        ensure_bns_bridge();
        for bad in [
            "did:bns:",               // 空名字
            "did:bns:alice%2Fevil",   // 名字里藏了 "/"
            "did:bns:alice%3A3000",   // bns 名字没有端口语义
            "did:bns:alice..evil%00", // 非法字符
        ] {
            let did = DID::from_str(bad).unwrap();
            assert!(
                matches!(
                    WebProvider::canonical_host(&did, did.id.split(':').next().unwrap()),
                    Err(NSError::InvalidDID(_))
                ),
                "should reject {}",
                bad
            );
        }
    }

    // ------------------------ uppername 回退信道 ------------------------

    #[test]
    fn builds_upper_resolver_url_from_upper_did() {
        // uppername 语义(根域名/IP 返回 None、端口路径不继承等)的完整覆盖
        // 见 name-lib did.rs 的 test_upper_did;这里验证回退 URL 的拼装。
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:ood1.example.com").unwrap();
        let upper = did.upper_did().unwrap();
        assert_eq!(upper, DID::new("web", "example.com"));

        assert_eq!(
            provider
                .build_upper_resolver_url(&upper.id, &did, None)
                .unwrap(),
            "https://example.com/1.0/identifiers/did:web:ood1.example.com"
        );
        assert_eq!(
            provider
                .build_upper_resolver_url(&upper.id, &did, Some(&DidDocType::Owner))
                .unwrap(),
            "https://example.com/1.0/identifiers/did:web:ood1.example.com?type=owner"
        );

        // 根域名没有 uppername,query_did 不会产生回退请求
        assert_eq!(
            DID::from_str("did:web:example.com").unwrap().upper_did(),
            None
        );
    }

    #[test]
    fn merge_prefers_unknown_over_not_found() {
        let not_found = || NSError::NotFound("not found".to_string());
        let unknown = || NSError::Failed("connection refused".to_string());

        // 两个信道一致说"没有"才是 NotFound(=> Missing)
        assert!(matches!(
            WebProvider::merge_fetch_errors(not_found(), not_found()),
            NSError::NotFound(_)
        ));
        // 任一信道传输失败,整体是 unknown,不能伪装成 Missing
        assert!(matches!(
            WebProvider::merge_fetch_errors(not_found(), unknown()),
            NSError::Failed(_)
        ));
        assert!(matches!(
            WebProvider::merge_fetch_errors(unknown(), not_found()),
            NSError::Failed(_)
        ));
    }

    // ------------------------ 非法输入必须拒绝 ------------------------

    #[test]
    fn rejects_malformed_hosts() {
        let provider = WebProvider::new();
        for bad in [
            "did:web:",                    // 空 host
            "did:web:example.com%2Fevil",  // host 里藏了 "/"
            "did:web:user%40example.com",  // host 里藏了 "@"
            "did:web:example.com%3Aabc",   // 端口不是数字
            "did:web:example.com%3A99999", // 端口超出 u16
        ] {
            let did = DID::from_str(bad).unwrap();
            assert!(
                matches!(provider.build_url(&did, None), Err(NSError::InvalidDID(_))),
                "should reject {}",
                bad
            );
        }
    }

    #[test]
    fn rejects_malformed_path_segments() {
        let provider = WebProvider::new();
        for bad in [
            "did:web:example.com:",           // 结尾空段
            "did:web:example.com::alice",     // 中间空段
            "did:web:example.com:..:secrets", // 路径穿越
        ] {
            let did = DID::from_str(bad).unwrap();
            assert!(
                matches!(provider.build_url(&did, None), Err(NSError::InvalidDID(_))),
                "should reject {}",
                bad
            );
        }
    }

    #[test]
    fn rejects_unsafe_doc_type() {
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:example.com").unwrap();

        assert!(matches!(
            provider.build_url(&did, Some(&DidDocType::custom("../owner"))),
            Err(NSError::InvalidParam(_))
        ));
    }

    // ------------------------ provider 语义 ------------------------

    #[tokio::test]
    async fn query_did_rejects_unsupported_method_without_network() {
        // did:web / did:bns 之外的 method 一概不受理(key 类 DID 更是在主循环
        // 入口就被拒绝,这里只是 provider 层的兜底)。
        let provider = WebProvider::new();
        let did =
            DID::from_str("did:key:z6Mksw4bDmn77uB5iVbQJBALV4CfqUGNoTCJQwdse1dQcvbK").unwrap();
        let err = provider.query_did(&did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn published_state_is_always_not_applicable() {
        // canonical endpoint 没有发布状态能力,永远 Ok(None) 且不发任何网络请求,
        // 状态归一交给主循环的 authority_answer。
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:example.com").unwrap();
        let state = provider
            .resolve_published_state(&did, &DidDocType::Zone)
            .await
            .unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn resolve_did_web_identity_foundation() {
        let provider = WebProvider::new();
        // identity.foundation 长期发布着自己的 .well-known/did.json,作为稳定样例
        let did = DID::from_str("did:web:identity.foundation").unwrap();

        match provider.query_did(&did, None, None).await {
            Ok(doc) => {
                let json = doc.to_json_value().unwrap();
                println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
                assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
            }
            // 公网站点偶发 404 / 无网环境,视为环境性问题,不阻断单测
            Err(NSError::NotFound(_)) | Err(NSError::Failed(_)) => {
                println!(
                    "skip: document missing or network unavailable for {}",
                    did.to_string()
                );
            }
            Err(e) => panic!("unexpected err: {:?}", e),
        }
    }
}
