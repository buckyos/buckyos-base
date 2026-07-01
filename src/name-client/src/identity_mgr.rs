use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::DidDocType;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use buckyos_kit::get_buckyos_root_dir;
use chrono::{DateTime, Utc};
use name_lib::{NSError, NSResult, DID};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const IDENTITY_KEYREF_SCHEMA: &str = "buckyos.identity.keyref.v1";
pub const X509_METADATA_SCHEMA: &str = "buckyos.identity.x509.metadata.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRoots {
    pub public_root: PathBuf,
    pub security_root: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityUsage {
    Server,
    Client,
    Authentication,
    Assertion,
    KeyAgreement,
    Capability,
}

impl IdentityUsage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
            Self::Authentication => "authentication",
            Self::Assertion => "assertion",
            Self::KeyAgreement => "key-agreement",
            Self::Capability => "capability",
        }
    }

    fn is_x509(self) -> bool {
        matches!(self, Self::Server | Self::Client)
    }

    fn public_key_ext(self) -> &'static str {
        match self {
            Self::Server | Self::Client => "pem",
            Self::Authentication | Self::Assertion | Self::KeyAgreement | Self::Capability => "jwk",
        }
    }
}

impl fmt::Display for IdentityUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IdentityUsage {
    type Err = NSError;

    fn from_str(value: &str) -> NSResult<Self> {
        match value {
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            "authentication" => Ok(Self::Authentication),
            "assertion" => Ok(Self::Assertion),
            "key-agreement" => Ok(Self::KeyAgreement),
            "capability" => Ok(Self::Capability),
            _ => Err(NSError::InvalidParam(format!("UnsupportedUsage: {value}"))),
        }
    }
}

//这种URL适合在有明确的provider的情况下查询任意did
//- "https://{hostname}/.well-known/did.json","https://{hostname}/.well-known/doc-type.json"
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IdentityMaterial {
    DidDocJson(Option<DidDocType>),
    DidDocJwt(Option<DidDocType>),
    Cert,
    Chain,
    Fullchain,
    Ca,
    PublicKey,
    Csr,
    Meta,
    PrivateKey,
    KeyRef,
    VerificationMethod,
}

impl IdentityMaterial {
    fn public_file_name(&self, usage: IdentityUsage) -> NSResult<String> {
        let stem = usage.as_str();
        match self {
            Self::DidDocJwt(doc_type) => did_document_file_name(doc_type, "jwt", "did_doc.jwt"),
            Self::DidDocJson(doc_type) => did_document_file_name(doc_type, "json", "did.json"),
            Self::Cert => Ok(format!("{stem}.cert.pem")),
            Self::Chain => Ok(format!("{stem}.chain.pem")),
            Self::Fullchain => Ok(format!("{stem}.fullchain.pem")),
            Self::Ca => Ok(format!("{stem}.ca.pem")),
            Self::PublicKey => Ok(format!("{stem}.public.{}", usage.public_key_ext())),
            Self::Csr => Ok(format!("{stem}.csr.pem")),
            Self::Meta => Ok(format!("{stem}.meta.json")),
            Self::VerificationMethod => Ok(format!("{stem}.verification-method.json")),
            Self::PrivateKey | Self::KeyRef => Err(NSError::InvalidParam(format!(
                "security material {} cannot be placed under public identity root",
                self.as_str()
            ))),
        }
    }

    fn security_file_name(&self, usage: IdentityUsage) -> NSResult<String> {
        let stem = usage.as_str();
        match self {
            Self::PrivateKey => Ok(format!("{stem}.private.pem")),
            Self::KeyRef => Ok(format!("{stem}.keyref.json")),
            _ => Err(NSError::InvalidParam(format!(
                "public material {} cannot be placed under security root",
                self.as_str()
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DidDocJson(_) => "did-doc-json",
            Self::DidDocJwt(_) => "did-doc-jwt",
            Self::Cert => "cert",
            Self::Chain => "chain",
            Self::Fullchain => "fullchain",
            Self::Ca => "ca",
            Self::PublicKey => "public-key",
            Self::Csr => "csr",
            Self::Meta => "meta",
            Self::PrivateKey => "private-key",
            Self::KeyRef => "keyref",
            Self::VerificationMethod => "verification-method",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X509Paths {
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub fullchain: PathBuf,
    pub ca: Option<PathBuf>,
    pub metadata: PathBuf,
    pub keyref: PathBuf,
    pub private_key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityMatchType {
    Exact,
    Wildcard,
}

impl IdentityMatchType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Wildcard => "wildcard",
        }
    }
}

impl fmt::Display for IdentityMatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityDirMatch {
    pub match_type: IdentityMatchType,
    pub raw_host_uri: String,
    pub dir_name: String,
    pub public_dir: PathBuf,
    pub security_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFileMatch {
    pub match_type: IdentityMatchType,
    pub raw_host_uri: String,
    pub dir_name: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyAccess {
    File { path: PathBuf, format: String },
    Signer { endpoint: String, protocol: String },
    RemoteMeta { url: String, method: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRef {
    pub did: String,
    pub usage: IdentityUsage,
    pub algorithm: String,
    pub public_key_fingerprint: String,
    pub access: KeyAccess,
    pub exportable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Metadata {
    pub schema: Option<String>,
    pub did: String,
    pub raw_host_uri: String,
    pub dir_name: String,
    pub usage: IdentityUsage,
    #[serde(rename = "match")]
    pub match_info: Option<X509MatchMetadata>,
    pub certificate: Option<X509CertificateMetadata>,
    pub san: Option<X509SanMetadata>,
    pub paths: Option<X509PathMetadata>,
    pub did_binding: Option<Value>,
    pub renewal: Option<Value>,
    pub updated_at: Option<String>,
    pub generation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum X509MatchMetadata {
    Exact { host: String },
    Wildcard { host_pattern: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct X509CertificateMetadata {
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<String>,
    pub not_after: String,
    pub fingerprint_sha256: Option<String>,
    pub public_key_fingerprint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct X509SanMetadata {
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub uri: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct X509PathMetadata {
    pub cert: Option<String>,
    pub chain: Option<String>,
    pub fullchain: Option<String>,
    pub ca: Option<String>,
    pub key_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStatus {
    pub installed: bool,
    pub locally_usable: bool,
    pub match_type: Option<String>,
    pub expired: bool,
    pub not_before_valid: bool,
    pub will_expire_within: Option<Duration>,
    pub revoked: Option<bool>,
    pub key_matches_certificate: Option<bool>,
    pub did_binding_valid: Option<bool>,
}

impl IdentityRoots {
    pub fn new(public_root: PathBuf, security_root: PathBuf) -> Self {
        Self {
            public_root,
            security_root,
        }
    }

    pub fn from_env_or_buckyos_root() -> NSResult<Self> {
        let buckyos_root = get_buckyos_root_dir();
        let public_root = env::var("BUCKYOS_IDENTITY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| buckyos_root.join("local").join("identity"));
        let security_root = env::var("BUCKYOS_SECURITY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| buckyos_root.join("security"));
        Ok(Self::new(public_root, security_root))
    }

    pub fn raw_host_uri(&self, did_or_hostname: &str) -> NSResult<String> {
        did_input_to_raw_host_uri(did_or_hostname)
    }

    pub fn dir_name(&self, did_or_hostname: &str) -> NSResult<String> {
        encode_filename_checked(&self.raw_host_uri(did_or_hostname)?)
    }

    pub fn public_dir(&self, did_or_hostname: &str) -> NSResult<PathBuf> {
        Ok(self.public_root.join(self.dir_name(did_or_hostname)?))
    }

    pub fn security_dir(&self, did_or_hostname: &str) -> NSResult<PathBuf> {
        Ok(self.security_root.join(self.dir_name(did_or_hostname)?))
    }

    pub fn public_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> NSResult<PathBuf> {
        Ok(self
            .public_dir(did_or_hostname)?
            .join(material.public_file_name(usage)?))
    }

    pub fn security_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> NSResult<PathBuf> {
        Ok(self
            .security_dir(did_or_hostname)?
            .join(material.security_file_name(usage)?))
    }

    pub fn x509_paths(&self, did_or_hostname: &str, usage: IdentityUsage) -> NSResult<X509Paths> {
        ensure_x509_usage(usage)?;
        Ok(X509Paths {
            cert: self.public_file(did_or_hostname, usage, IdentityMaterial::Cert)?,
            chain: self.public_file(did_or_hostname, usage, IdentityMaterial::Chain)?,
            fullchain: self.public_file(did_or_hostname, usage, IdentityMaterial::Fullchain)?,
            ca: Some(self.public_file(did_or_hostname, usage, IdentityMaterial::Ca)?),
            metadata: self.public_file(did_or_hostname, usage, IdentityMaterial::Meta)?,
            keyref: self.security_file(did_or_hostname, usage, IdentityMaterial::KeyRef)?,
            private_key: Some(self.security_file(
                did_or_hostname,
                usage,
                IdentityMaterial::PrivateKey,
            )?),
        })
    }

    pub fn find_identity_dir(&self, did_or_hostname: &str) -> NSResult<IdentityDirMatch> {
        let exact_raw_host_uri = self.raw_host_uri(did_or_hostname)?;
        let exact = self.dir_match(IdentityMatchType::Exact, exact_raw_host_uri.clone())?;
        if exact.public_dir.exists() || exact.security_dir.exists() {
            return Ok(exact);
        }

        if let Some(wildcard_raw_host_uri) = wildcard_raw_host_uri(&exact_raw_host_uri) {
            let wildcard = self.dir_match(IdentityMatchType::Wildcard, wildcard_raw_host_uri)?;
            if wildcard.public_dir.exists() || wildcard.security_dir.exists() {
                return Ok(wildcard);
            }
        }

        Err(NSError::NotFound(format!(
            "IdentityNotInstalled: {did_or_hostname}"
        )))
    }

    pub fn find_public_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> NSResult<IdentityFileMatch> {
        let file_name = material.public_file_name(usage)?;
        self.find_file(
            did_or_hostname,
            file_name,
            true,
            format!("{} {}", usage, material.as_str()),
        )
    }

    pub fn find_security_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> NSResult<IdentityFileMatch> {
        let file_name = material.security_file_name(usage)?;
        self.find_file(
            did_or_hostname,
            file_name,
            false,
            format!("{} {}", usage, material.as_str()),
        )
    }

    pub fn load_keyref(&self, keyref_path: &Path) -> NSResult<KeyRef> {
        let content = fs::read_to_string(keyref_path).map_err(|err| {
            NSError::ReadLocalFileError(format!(
                "Failed to read keyref {}: {err}",
                keyref_path.display()
            ))
        })?;
        let raw: RawKeyRef = serde_json::from_str(&content)
            .map_err(|err| NSError::InvalidParam(format!("invalid keyref json: {err}")))?;
        raw.into_keyref(self, keyref_path.parent())
    }

    pub fn private_key_file_for_legacy_tool(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
    ) -> NSResult<PathBuf> {
        let keyref_match =
            self.find_security_file(did_or_hostname, usage, IdentityMaterial::KeyRef)?;
        let keyref = self.load_keyref(&keyref_match.path)?;
        if keyref.usage != usage {
            return Err(NSError::InvalidState(format!(
                "keyref usage mismatch: expected {usage}, got {}",
                keyref.usage
            )));
        }
        if !keyref.exportable {
            return Err(private_key_not_exportable());
        }
        match keyref.access {
            KeyAccess::File { path, .. } => Ok(path),
            KeyAccess::Signer { .. } | KeyAccess::RemoteMeta { .. } => {
                Err(private_key_not_exportable())
            }
        }
    }

    pub fn parse_x509_metadata(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
    ) -> NSResult<X509Metadata> {
        ensure_x509_usage(usage)?;
        let meta_match = self.find_public_file(did_or_hostname, usage, IdentityMaterial::Meta)?;
        let content = fs::read_to_string(&meta_match.path).map_err(|err| {
            NSError::ReadLocalFileError(format!(
                "Failed to read metadata {}: {err}",
                meta_match.path.display()
            ))
        })?;
        let metadata: X509Metadata = serde_json::from_str(&content)
            .map_err(|err| NSError::InvalidParam(format!("invalid x509 metadata json: {err}")))?;
        Ok(metadata)
    }

    pub fn check_x509_local_status(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
    ) -> NSResult<IdentityStatus> {
        ensure_x509_usage(usage)?;

        let fullchain = self.find_public_file(did_or_hostname, usage, IdentityMaterial::Fullchain);
        let cert = self.find_public_file(did_or_hostname, usage, IdentityMaterial::Cert);
        let metadata = self.parse_x509_metadata(did_or_hostname, usage);
        let keyref = self.find_security_file(did_or_hostname, usage, IdentityMaterial::KeyRef);

        let installed = fullchain.is_ok() || cert.is_ok() || metadata.is_ok();
        let match_type = fullchain
            .as_ref()
            .ok()
            .map(|m| m.match_type.to_string())
            .or_else(|| cert.as_ref().ok().map(|m| m.match_type.to_string()))
            .or_else(|| {
                metadata.as_ref().ok().and_then(|m| {
                    m.match_info.as_ref().map(|match_info| match match_info {
                        X509MatchMetadata::Exact { .. } => IdentityMatchType::Exact.to_string(),
                        X509MatchMetadata::Wildcard { .. } => {
                            IdentityMatchType::Wildcard.to_string()
                        }
                    })
                })
            });

        let pem_ok = fullchain
            .as_ref()
            .ok()
            .or_else(|| cert.as_ref().ok())
            .map(|file_match| certificate_pem_looks_parseable(&file_match.path).unwrap_or(false))
            .unwrap_or(false);

        let mut expired = false;
        let mut not_before_valid = true;
        let mut will_expire_within = None;
        let mut metadata_consistent = metadata.is_ok();
        let mut san_matches = true;
        let mut key_matches_certificate = None;
        let mut did_binding_valid = None;

        if let Ok(metadata) = metadata.as_ref() {
            metadata_consistent =
                metadata_consistent && self.metadata_matches_input(did_or_hostname, metadata);
            metadata_consistent = metadata_consistent && metadata.usage == usage;
            san_matches = self.metadata_san_matches_input(did_or_hostname, metadata);

            if let Some(certificate) = metadata.certificate.as_ref() {
                let now = Utc::now();
                let not_after = parse_rfc3339_utc(&certificate.not_after)?;
                expired = now > not_after;
                will_expire_within = if now <= not_after {
                    (not_after - now).to_std().ok()
                } else {
                    None
                };
                if let Some(not_before) = certificate.not_before.as_ref() {
                    let not_before = parse_rfc3339_utc(not_before)?;
                    not_before_valid = now >= not_before;
                }
            }

            if let (Some(certificate), Ok(keyref_match)) = (metadata.certificate.as_ref(), &keyref)
            {
                if let Some(cert_key_fingerprint) = certificate.public_key_fingerprint.as_ref() {
                    key_matches_certificate = Some(
                        self.load_keyref(&keyref_match.path)
                            .map(|keyref| {
                                keyref
                                    .public_key_fingerprint
                                    .eq_ignore_ascii_case(cert_key_fingerprint)
                            })
                            .unwrap_or(false),
                    );
                }
            }

            if let Some(san) = metadata.san.as_ref() {
                if !san.uri.is_empty() {
                    did_binding_valid = Some(san.uri.iter().any(|uri| uri == &metadata.did));
                }
            }
        }

        let locally_usable = installed
            && pem_ok
            && keyref.is_ok()
            && metadata.is_ok()
            && metadata_consistent
            && san_matches
            && key_matches_certificate.unwrap_or(true)
            && did_binding_valid.unwrap_or(true)
            && !expired
            && not_before_valid;

        Ok(IdentityStatus {
            installed,
            locally_usable,
            match_type,
            expired,
            not_before_valid,
            will_expire_within,
            revoked: None,
            key_matches_certificate,
            did_binding_valid,
        })
    }

    pub async fn check_x509_remote_status(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
    ) -> NSResult<IdentityStatus> {
        self.check_x509_local_status(did_or_hostname, usage)
    }

    pub fn did_web_document_url(&self, did_or_hostname: &str) -> NSResult<String> {
        did_web_document_url(did_or_hostname)
    }

    pub fn did_web_dns_san(&self, did_or_hostname: &str) -> NSResult<String> {
        did_web_dns_san(did_or_hostname)
    }

    fn find_file(
        &self,
        did_or_hostname: &str,
        file_name: String,
        public_root: bool,
        description: String,
    ) -> NSResult<IdentityFileMatch> {
        let exact_raw_host_uri = self.raw_host_uri(did_or_hostname)?;
        let exact_dir_name = encode_filename_checked(&exact_raw_host_uri)?;
        let root = if public_root {
            &self.public_root
        } else {
            &self.security_root
        };
        let exact_path = root.join(&exact_dir_name).join(&file_name);
        if exact_path.exists() {
            return Ok(IdentityFileMatch {
                match_type: IdentityMatchType::Exact,
                raw_host_uri: exact_raw_host_uri,
                dir_name: exact_dir_name,
                path: exact_path,
            });
        }

        if let Some(wildcard_raw_host_uri) = wildcard_raw_host_uri(&exact_raw_host_uri) {
            let wildcard_dir_name = encode_filename_checked(&wildcard_raw_host_uri)?;
            let wildcard_path = root.join(&wildcard_dir_name).join(file_name);
            if wildcard_path.exists() {
                return Ok(IdentityFileMatch {
                    match_type: IdentityMatchType::Wildcard,
                    raw_host_uri: wildcard_raw_host_uri,
                    dir_name: wildcard_dir_name,
                    path: wildcard_path,
                });
            }
        }

        Err(NSError::NotFound(format!(
            "UsageNotInstalled: {did_or_hostname} {description}"
        )))
    }

    fn dir_match(
        &self,
        match_type: IdentityMatchType,
        raw_host_uri: String,
    ) -> NSResult<IdentityDirMatch> {
        let dir_name = encode_filename_checked(&raw_host_uri)?;
        Ok(IdentityDirMatch {
            match_type,
            public_dir: self.public_root.join(&dir_name),
            security_dir: self.security_root.join(&dir_name),
            raw_host_uri,
            dir_name,
        })
    }

    fn metadata_matches_input(&self, did_or_hostname: &str, metadata: &X509Metadata) -> bool {
        let raw_host_uri = match self.raw_host_uri(did_or_hostname) {
            Ok(raw_host_uri) => raw_host_uri,
            Err(_) => return false,
        };
        if metadata.raw_host_uri != raw_host_uri {
            if let Some(wildcard_raw_host_uri) = wildcard_raw_host_uri(&raw_host_uri) {
                if metadata.raw_host_uri != wildcard_raw_host_uri {
                    return false;
                }
            } else {
                return false;
            }
        }
        encode_filename(&metadata.raw_host_uri) == metadata.dir_name
    }

    fn metadata_san_matches_input(&self, did_or_hostname: &str, metadata: &X509Metadata) -> bool {
        let Some(san) = metadata.san.as_ref() else {
            return true;
        };
        let Ok(dns_name) = self.did_web_dns_san(did_or_hostname) else {
            return true;
        };
        san.dns
            .iter()
            .any(|entry| dns_san_matches(entry, &dns_name))
    }
}

pub fn encode_filename(raw_host_uri: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut filename = String::with_capacity(raw_host_uri.len());
    for byte in raw_host_uri.bytes() {
        if is_filename_keep_byte(byte) {
            filename.push(byte as char);
        } else {
            filename.push('%');
            filename.push(HEX[(byte >> 4) as usize] as char);
            filename.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    filename
}

pub fn decode_filename(dir_name: &str) -> NSResult<String> {
    validate_dir_name(dir_name)?;

    let bytes = dir_name.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err(NSError::InvalidParam(format!(
                    "invalid encoded filename: {dir_name}"
                )));
            }
            let high = hex_value(bytes[index + 1]).ok_or_else(|| {
                NSError::InvalidParam(format!("invalid encoded filename: {dir_name}"))
            })?;
            let low = hex_value(bytes[index + 2]).ok_or_else(|| {
                NSError::InvalidParam(format!("invalid encoded filename: {dir_name}"))
            })?;
            decoded.push((high << 4) | low);
            index += 3;
        } else if is_filename_keep_byte(byte) {
            decoded.push(byte);
            index += 1;
        } else {
            return Err(NSError::InvalidParam(format!(
                "invalid encoded filename: {dir_name}"
            )));
        }
    }

    String::from_utf8(decoded)
        .map_err(|err| NSError::InvalidParam(format!("invalid encoded filename utf8: {err}")))
}

pub fn did_web_document_url(did_or_hostname: &str) -> NSResult<String> {
    let did = DID::from_str(did_or_hostname.trim())?;
    if did.method != "web" {
        return Err(NSError::InvalidParam(format!(
            "did:web required, got {}",
            did.to_string()
        )));
    }
    let mut parts = did.id.split(':');
    let host = parts
        .next()
        .ok_or_else(|| NSError::InvalidDID(did.to_string()))?;
    let host = percent_decode(host)?;
    let path_segments: Vec<String> = parts.map(percent_decode).collect::<NSResult<_>>()?;
    if path_segments.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!(
            "https://{host}/{}/did.json",
            path_segments.join("/")
        ))
    }
}

pub fn did_web_dns_san(did_or_hostname: &str) -> NSResult<String> {
    let did = DID::from_str(did_or_hostname.trim())?;
    if did.method != "web" {
        return Err(NSError::InvalidParam(format!(
            "did:web required, got {}",
            did.to_string()
        )));
    }
    let raw_host_uri = normalize_wildcard_raw_host_uri(&did.to_raw_host_uri());
    let host = raw_host_uri
        .split_once('/')
        .map(|(host, _)| host)
        .unwrap_or(raw_host_uri.as_str());
    let host = if let Some(rest) = host.strip_prefix("_.") {
        format!("*.{rest}")
    } else {
        host.to_string()
    };
    percent_decode(&host)
}

fn ensure_x509_usage(usage: IdentityUsage) -> NSResult<()> {
    if usage.is_x509() {
        Ok(())
    } else {
        Err(NSError::InvalidParam(format!(
            "UnsupportedUsage: {usage} is not an X.509 usage"
        )))
    }
}

fn did_document_file_name(
    doc_type: &Option<DidDocType>,
    extension: &str,
    default_file_name: &str,
) -> NSResult<String> {
    let Some(doc_type) = doc_type else {
        return Ok(default_file_name.to_string());
    };
    let doc_type = doc_type.as_str();
    validate_doc_type_file_stem(doc_type)?;
    Ok(format!("{doc_type}.{extension}"))
}

fn validate_doc_type_file_stem(doc_type: &str) -> NSResult<()> {
    if doc_type.is_empty()
        || !doc_type
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(NSError::InvalidParam(format!(
            "invalid DID document type: {doc_type}"
        )));
    }
    Ok(())
}

fn is_filename_keep_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'
    )
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn did_input_to_raw_host_uri(did_or_hostname: &str) -> NSResult<String> {
    let input = did_or_hostname.trim();
    if input.is_empty() {
        return Err(NSError::InvalidDID("empty did or hostname".to_string()));
    }

    if DID::is_did(input) {
        let did = DID::from_str(input)?;
        let raw_host_uri = did.to_raw_host_uri();
        Ok(normalize_wildcard_raw_host_uri(&raw_host_uri))
    } else {
        Ok(normalize_wildcard_raw_host_uri(input))
    }
}

fn normalize_wildcard_raw_host_uri(raw_host_uri: &str) -> String {
    let Some((host, path)) = raw_host_uri.split_once('/') else {
        return normalize_wildcard_host(raw_host_uri);
    };
    format!("{}/{}", normalize_wildcard_host(host), path)
}

fn normalize_wildcard_host(host: &str) -> String {
    host.strip_prefix("*.")
        .map(|suffix| format!("_.{suffix}"))
        .unwrap_or_else(|| host.to_string())
}

fn wildcard_raw_host_uri(raw_host_uri: &str) -> Option<String> {
    if raw_host_uri.contains('/') {
        return None;
    }
    let labels: Vec<&str> = raw_host_uri.split('.').collect();
    if labels.len() < 3 || labels.first() == Some(&"_") || labels.first() == Some(&"*") {
        return None;
    }
    Some(format!("_.{}", labels[1..].join(".")))
}

fn encode_filename_checked(raw_host_uri: &str) -> NSResult<String> {
    let dir_name = encode_filename(raw_host_uri);
    validate_dir_name(&dir_name)?;
    Ok(dir_name)
}

fn validate_dir_name(dir_name: &str) -> NSResult<()> {
    if dir_name.is_empty()
        || dir_name == "."
        || dir_name == ".."
        || dir_name.contains('/')
        || dir_name.contains('\\')
        || dir_name.contains('\0')
    {
        return Err(NSError::InvalidParam(format!(
            "invalid identity directory name: {dir_name}"
        )));
    }
    Ok(())
}

fn private_key_not_exportable() -> NSError {
    NSError::Failed("PrivateKeyNotExportable".to_string())
}

fn unsupported_keyref(message: impl Into<String>) -> NSError {
    NSError::InvalidParam(format!("UnsupportedKeyRef: {}", message.into()))
}

fn percent_decode(value: &str) -> NSResult<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.to_string())
        .map_err(|err| NSError::InvalidParam(format!("invalid percent encoding: {err}")))
}

fn expand_path_vars(roots: &IdentityRoots, value: &str) -> String {
    value
        .replace(
            "${BUCKYOS_IDENTITY_ROOT}",
            &roots.public_root.to_string_lossy(),
        )
        .replace(
            "${BUCKYOS_SECURITY_ROOT}",
            &roots.security_root.to_string_lossy(),
        )
        .replace("${BUCKYOS_ROOT}", &get_buckyos_root_dir().to_string_lossy())
}

fn resolve_ref_path(roots: &IdentityRoots, base_dir: Option<&Path>, raw_path: &str) -> PathBuf {
    let expanded = PathBuf::from(expand_path_vars(roots, raw_path));
    if expanded.is_absolute() {
        expanded
    } else if let Some(base_dir) = base_dir {
        base_dir.join(expanded)
    } else {
        expanded
    }
}

#[derive(Debug, Deserialize)]
struct RawKeyRef {
    schema: Option<String>,
    kind: Option<String>,
    did: String,
    usage: IdentityUsage,
    algorithm: String,
    public_key_fingerprint: String,
    mode: String,
    #[serde(default)]
    exportable: bool,
    #[serde(rename = "ref")]
    reference: Value,
}

impl RawKeyRef {
    fn into_keyref(self, roots: &IdentityRoots, base_dir: Option<&Path>) -> NSResult<KeyRef> {
        if let Some(schema) = self.schema.as_ref() {
            if schema != IDENTITY_KEYREF_SCHEMA {
                return Err(NSError::InvalidParam(format!(
                    "unsupported keyref schema: {schema}"
                )));
            }
        }
        if let Some(kind) = self.kind.as_ref() {
            if kind != "key" {
                return Err(NSError::InvalidParam(format!(
                    "unsupported keyref kind: {kind}"
                )));
            }
        }

        let access = match self.mode.as_str() {
            "file" => {
                let ref_type = json_string(&self.reference, "type")?;
                if ref_type != "file" {
                    return Err(unsupported_keyref(format!(
                        "mode=file requires ref.type=file, got {ref_type}"
                    )));
                }
                let path = json_string(&self.reference, "path")?;
                let format =
                    json_string_optional(&self.reference, "format")?.unwrap_or("pkcs8-pem");
                KeyAccess::File {
                    path: resolve_ref_path(roots, base_dir, path),
                    format: format.to_string(),
                }
            }
            "signer" => {
                let ref_type = json_string(&self.reference, "type")?;
                if ref_type != "unix-socket" {
                    return Err(unsupported_keyref(format!(
                        "unsupported signer ref.type={ref_type}"
                    )));
                }
                KeyAccess::Signer {
                    endpoint: expand_path_vars(roots, json_string(&self.reference, "endpoint")?),
                    protocol: json_string(&self.reference, "protocol")?.to_string(),
                }
            }
            "remote-meta" => {
                let ref_type = json_string(&self.reference, "type")?;
                if ref_type != "meta" {
                    return Err(unsupported_keyref(format!(
                        "mode=remote-meta requires ref.type=meta, got {ref_type}"
                    )));
                }
                KeyAccess::RemoteMeta {
                    url: json_string(&self.reference, "url")?.to_string(),
                    method: json_string(&self.reference, "method")?.to_string(),
                }
            }
            other => return Err(unsupported_keyref(format!("unsupported mode={other}"))),
        };

        Ok(KeyRef {
            did: self.did,
            usage: self.usage,
            algorithm: self.algorithm,
            public_key_fingerprint: self.public_key_fingerprint,
            access,
            exportable: self.exportable,
        })
    }
}

fn json_string<'a>(value: &'a Value, key: &str) -> NSResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| NSError::InvalidParam(format!("keyref ref.{key} must be a string")))
}

fn json_string_optional<'a>(value: &'a Value, key: &str) -> NSResult<Option<&'a str>> {
    value
        .get(key)
        .map(|v| {
            v.as_str()
                .ok_or_else(|| NSError::InvalidParam(format!("keyref ref.{key} must be a string")))
        })
        .transpose()
}

fn parse_rfc3339_utc(value: &str) -> NSResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| NSError::InvalidParam(format!("invalid RFC3339 timestamp {value}: {err}")))
}

fn certificate_pem_looks_parseable(path: &Path) -> NSResult<bool> {
    let content = fs::read_to_string(path).map_err(|err| {
        NSError::ReadLocalFileError(format!(
            "Failed to read certificate {}: {err}",
            path.display()
        ))
    })?;
    Ok(extract_pem_blocks(&content, "CERTIFICATE")
        .iter()
        .any(|block| STANDARD.decode(block.as_bytes()).is_ok()))
}

fn extract_pem_blocks(content: &str, label: &str) -> Vec<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut rest = content;

    while let Some(begin_pos) = rest.find(&begin) {
        let after_begin = &rest[begin_pos + begin.len()..];
        let Some(end_pos) = after_begin.find(&end) else {
            break;
        };
        let block = after_begin[..end_pos]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        blocks.push(block);
        rest = &after_begin[end_pos + end.len()..];
    }

    blocks
}

fn dns_san_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some(label) = host.strip_suffix(&format!(".{suffix}")) else {
            return false;
        };
        return !label.is_empty() && !label.contains('.');
    }
    pattern.eq_ignore_ascii_case(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roots(tmp: &tempfile::TempDir) -> IdentityRoots {
        IdentityRoots::new(
            tmp.path().join("local").join("identity"),
            tmp.path().join("security"),
        )
    }

    #[test]
    fn path_helper_maps_did_and_hostname_to_stable_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);

        assert_eq!(
            roots.raw_host_uri("did:web:node1.example.com").unwrap(),
            "node1.example.com"
        );
        assert_eq!(
            roots.dir_name("did:web:node1.example.com").unwrap(),
            "node1.example.com"
        );
        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::Fullchain,
                )
                .unwrap(),
            tmp.path()
                .join("local/identity/node1.example.com/server.fullchain.pem")
        );
        assert_eq!(
            roots
                .security_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::PrivateKey,
                )
                .unwrap(),
            tmp.path()
                .join("security/node1.example.com/server.private.pem")
        );
    }

    #[test]
    fn did_document_material_uses_well_known_style_doc_type_files() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);

        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::DidDocJson(None),
                )
                .unwrap(),
            tmp.path().join("local/identity/node1.example.com/did.json")
        );
        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::DidDocJwt(None),
                )
                .unwrap(),
            tmp.path()
                .join("local/identity/node1.example.com/did_doc.jwt")
        );
        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::DidDocJson(Some(DidDocType::Zone)),
                )
                .unwrap(),
            tmp.path()
                .join("local/identity/node1.example.com/zone.json")
        );
        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::DidDocJson(Some(DidDocType::Owner)),
                )
                .unwrap(),
            tmp.path()
                .join("local/identity/node1.example.com/owner.json")
        );
        assert_eq!(
            roots
                .public_file(
                    "node1.example.com",
                    IdentityUsage::Server,
                    IdentityMaterial::DidDocJwt(Some(DidDocType::custom("profile"))),
                )
                .unwrap(),
            tmp.path()
                .join("local/identity/node1.example.com/profile.jwt")
        );
    }

    #[test]
    fn did_document_material_rejects_unsafe_doc_type_file_stems() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);

        assert!(matches!(
            roots.public_file(
                "node1.example.com",
                IdentityUsage::Server,
                IdentityMaterial::DidDocJson(Some(DidDocType::custom("../owner"))),
            ),
            Err(NSError::InvalidParam(_))
        ));
        assert!(matches!(
            roots.public_file(
                "node1.example.com",
                IdentityUsage::Server,
                IdentityMaterial::DidDocJwt(Some(DidDocType::custom("profile/v1"))),
            ),
            Err(NSError::InvalidParam(_))
        ));
    }

    #[test]
    fn path_did_uses_encoded_raw_host_uri() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);

        assert_eq!(
            roots
                .raw_host_uri("did:web:example.com:user:alice")
                .unwrap(),
            "example.com/user/alice"
        );
        assert_eq!(
            roots.dir_name("did:web:example.com:user:alice").unwrap(),
            "example.com%2Fuser%2Falice"
        );
        assert_eq!(
            roots.public_dir("did:web:example.com:user:alice").unwrap(),
            tmp.path().join("local/identity/example.com%2Fuser%2Falice")
        );
        assert_eq!(
            decode_filename("example.com%2Fuser%2Falice").unwrap(),
            "example.com/user/alice"
        );
        assert_eq!(
            encode_filename("example.com%2Fuser"),
            "example.com%252Fuser"
        );
    }

    #[test]
    fn hostname_input_uses_raw_hostname_without_did_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);

        assert_eq!(
            roots.raw_host_uri("example.com:3000").unwrap(),
            "example.com:3000"
        );
        assert_eq!(
            roots.dir_name("example.com:3000").unwrap(),
            "example.com%3A3000"
        );

        let public_dir = roots.public_dir("example.com:3000").unwrap();
        fs::create_dir_all(&public_dir).unwrap();
        let matched = roots.find_identity_dir("example.com:3000").unwrap();
        assert_eq!(matched.match_type, IdentityMatchType::Exact);
        assert_eq!(matched.raw_host_uri, "example.com:3000");
        assert_eq!(matched.dir_name, "example.com%3A3000");
        assert_eq!(matched.public_dir, public_dir);
    }

    #[test]
    fn wildcard_lookup_checks_exact_first_then_single_label_wildcard() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);
        let wildcard_dir = roots.public_dir("*.example.com").unwrap();
        fs::create_dir_all(&wildcard_dir).unwrap();
        fs::write(wildcard_dir.join("server.fullchain.pem"), "not a cert").unwrap();

        let matched = roots
            .find_public_file(
                "api.example.com",
                IdentityUsage::Server,
                IdentityMaterial::Fullchain,
            )
            .unwrap();
        assert_eq!(matched.match_type, IdentityMatchType::Wildcard);
        assert_eq!(matched.raw_host_uri, "_.example.com");

        assert!(roots
            .find_public_file(
                "example.com",
                IdentityUsage::Server,
                IdentityMaterial::Fullchain,
            )
            .is_err());
        assert!(roots
            .find_public_file(
                "a.b.example.com",
                IdentityUsage::Server,
                IdentityMaterial::Fullchain,
            )
            .is_err());

        let exact_dir = roots.public_dir("api.example.com").unwrap();
        fs::create_dir_all(&exact_dir).unwrap();
        fs::write(exact_dir.join("server.fullchain.pem"), "exact").unwrap();
        let matched = roots
            .find_public_file(
                "api.example.com",
                IdentityUsage::Server,
                IdentityMaterial::Fullchain,
            )
            .unwrap();
        assert_eq!(matched.match_type, IdentityMatchType::Exact);
    }

    #[test]
    fn did_web_helpers_follow_method_mapping() {
        assert_eq!(
            did_web_document_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_document_url("did:web:example.com:user:alice").unwrap(),
            "https://example.com/user/alice/did.json"
        );
        assert_eq!(
            did_web_dns_san("did:web:example.com:user:alice").unwrap(),
            "example.com"
        );
        assert_eq!(did_web_dns_san("*.example.com").unwrap(), "*.example.com");
        assert!(did_web_dns_san("did:bns:waterflier").is_err());
    }

    #[test]
    fn load_keyref_supports_file_signer_and_remote_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);
        let keyref_dir = roots.security_dir("node1.example.com").unwrap();
        fs::create_dir_all(&keyref_dir).unwrap();
        let keyref_path = keyref_dir.join("server.keyref.json");

        fs::write(
            &keyref_path,
            json!({
                "schema": IDENTITY_KEYREF_SCHEMA,
                "kind": "key",
                "did": "did:web:node1.example.com",
                "usage": "server",
                "algorithm": "P-256",
                "public_key_fingerprint": "sha256:test",
                "mode": "file",
                "exportable": true,
                "ref": {
                    "type": "file",
                    "path": "${BUCKYOS_SECURITY_ROOT}/node1.example.com/server.private.pem",
                    "format": "pkcs8-pem"
                }
            })
            .to_string(),
        )
        .unwrap();
        let keyref = roots.load_keyref(&keyref_path).unwrap();
        assert_eq!(keyref.usage, IdentityUsage::Server);
        assert!(matches!(keyref.access, KeyAccess::File { .. }));
        assert_eq!(
            roots
                .private_key_file_for_legacy_tool("node1.example.com", IdentityUsage::Server)
                .unwrap(),
            keyref_dir.join("server.private.pem")
        );

        fs::write(
            &keyref_path,
            json!({
                "schema": IDENTITY_KEYREF_SCHEMA,
                "kind": "key",
                "did": "did:web:node1.example.com",
                "usage": "server",
                "algorithm": "P-256",
                "public_key_fingerprint": "sha256:test",
                "mode": "signer",
                "exportable": false,
                "ref": {
                    "type": "unix-socket",
                    "endpoint": "${BUCKYOS_ROOT}/run/identity/server.sock",
                    "protocol": "buckyos-sign-v1"
                }
            })
            .to_string(),
        )
        .unwrap();
        let keyref = roots.load_keyref(&keyref_path).unwrap();
        assert!(matches!(keyref.access, KeyAccess::Signer { .. }));
        assert!(matches!(
            roots.private_key_file_for_legacy_tool("node1.example.com", IdentityUsage::Server),
            Err(NSError::Failed(message)) if message == "PrivateKeyNotExportable"
        ));

        fs::write(
            &keyref_path,
            json!({
                "schema": IDENTITY_KEYREF_SCHEMA,
                "kind": "key",
                "did": "did:web:node1.example.com",
                "usage": "server",
                "algorithm": "P-256",
                "public_key_fingerprint": "sha256:test",
                "mode": "remote-meta",
                "exportable": false,
                "ref": {
                    "type": "meta",
                    "url": "https://keys.example.com/node1/server.meta.json",
                    "method": "buckyos-remote-sign-v1"
                }
            })
            .to_string(),
        )
        .unwrap();
        let keyref = roots.load_keyref(&keyref_path).unwrap();
        assert!(matches!(keyref.access, KeyAccess::RemoteMeta { .. }));
    }

    #[test]
    fn parse_metadata_and_local_status_uses_flat_files() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = roots(&tmp);
        let public_dir = roots.public_dir("node1.example.com").unwrap();
        let security_dir = roots.security_dir("node1.example.com").unwrap();
        fs::create_dir_all(&public_dir).unwrap();
        fs::create_dir_all(&security_dir).unwrap();

        fs::write(
            public_dir.join("server.fullchain.pem"),
            "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            security_dir.join("server.keyref.json"),
            json!({
                "schema": IDENTITY_KEYREF_SCHEMA,
                "kind": "key",
                "did": "did:web:node1.example.com",
                "usage": "server",
                "algorithm": "P-256",
                "public_key_fingerprint": "sha256:test",
                "mode": "file",
                "exportable": true,
                "ref": {
                    "type": "file",
                    "path": "server.private.pem",
                    "format": "pkcs8-pem"
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            public_dir.join("server.meta.json"),
            json!({
                "schema": X509_METADATA_SCHEMA,
                "did": "did:web:node1.example.com",
                "raw_host_uri": "node1.example.com",
                "dir_name": "node1.example.com",
                "usage": "server",
                "match": { "type": "exact", "host": "node1.example.com" },
                "certificate": {
                    "not_before": "1970-01-01T00:00:00Z",
                    "not_after": "2999-01-01T00:00:00Z",
                    "public_key_fingerprint": "sha256:test"
                },
                "san": { "dns": ["node1.example.com"], "uri": ["did:web:node1.example.com"] }
            })
            .to_string(),
        )
        .unwrap();

        let metadata = roots
            .parse_x509_metadata("node1.example.com", IdentityUsage::Server)
            .unwrap();
        assert_eq!(metadata.dir_name, "node1.example.com");

        let status = roots
            .check_x509_local_status("node1.example.com", IdentityUsage::Server)
            .unwrap();
        assert!(status.installed);
        assert!(status.locally_usable);
        assert_eq!(status.match_type.as_deref(), Some("exact"));
        assert!(!status.expired);
        assert_eq!(status.key_matches_certificate, Some(true));
        assert_eq!(status.did_binding_valid, Some(true));
    }
}
