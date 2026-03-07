//! Name validation utilities for BuckyOS (user, device, agent, app names).

use once_cell::sync::Lazy;
use std::collections::HashSet;

/// Blacklisted names that are never valid regardless of other rules.
static NAME_BLACKLIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // ---- generic reserved (<=6 chars kept for sub-label matching) ----
        "admin",
        "api",
        "config",
        "cyfs",
        "daohub",
        "ftp",
        "imap",
        "mail",
        "null",
        "pop",
        "root",
        "smtp",
        "system",
        "www",
        // ---- system / infrastructure (>6 chars) ----
        "account",
        "accounts",
        "administrator",
        "backend",
        "cluster",
        "console",
        "control",
        "controller",
        "dashboard",
        "database",
        "default",
        "develop",
        "frontend",
        "gateway",
        "internal",
        "localhost",
        "logging",
        "manager",
        "monitor",
        "network",
        "primary",
        "private",
        "production",
        "reserved",
        "service",
        "services",
        "staging",
        "storage",
        "undefined",
        // ---- admin / operator roles (>6 chars) ----
        "hostmaster",
        "moderator",
        "operator",
        "postmaster",
        "superuser",
        "supervisor",
        "sysadmin",
        "webmaster",
        // ---- phishing / social-engineering prone (>6 chars) ----
        "activate",
        "anonymous",
        "banking",
        "billing",
        "confirm",
        "contact",
        "customer",
        "everyone",
        "helpdesk",
        "noreply",
        "notification",
        "official",
        "password",
        "payment",
        "payments",
        "recovery",
        "register",
        "security",
        "support",
        "suspend",
        "trusted",
        "unknown",
        "upgrade",
        "verified",
        "webmail",
        // ---- project-specific reserved ----
        "buckyos",
        "buckycloud",
        "freeinternet",
        "liuzhicong",
        "sourcedao",
        "waterflier",
        "zhicongliu",
    ]
    .into_iter()
    .collect()
});

/// Name type for validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameType {
    App,
    User,
    Device,
    Agent,
}

/// Check if a string is a valid DNS label/name (lowercase, RFC 1035 style).
/// - Each label: 1-63 chars, starts with letter, ends with letter/digit
/// - Allowed: a-z, 0-9, hyphen (not at start/end of label), dot as separator
fn is_valid_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let mut chars = label.chars();
        if !chars.next().map_or(false, |c| c.is_ascii_lowercase()) {
            return false;
        }
        for c in chars {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return false;
            }
        }
        if label.ends_with('-') {
            return false;
        }
    }
    true
}

/// Validate a name by type. Rules:
/// 1) Must be a valid DNS name (input expected to be lowercase)
/// 2) For App: must be "username-appname" format, both parts valid names
/// 3) Name length must be > 6
/// 4) Must not be in the blacklist
pub fn is_valid_name(name: &str, name_type: NameType) -> bool {
    const MIN_LEN: usize = 7; // length > 6

    if name.len() < MIN_LEN {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
        return false;
    }

    // Check that no label in the name is blacklisted (for DNS names like "sub.domain")
    let not_blacklisted = |s: &str| s.split('.').all(|label| !NAME_BLACKLIST.contains(label));

    match name_type {
        NameType::App => {
            let parts: Vec<&str> = name.splitn(2, '-').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return false;
            }
            let (username, appname) = (parts[0], parts[1]);
            username.len() >= MIN_LEN
                && appname.len() >= MIN_LEN
                && is_valid_dns_name(username)
                && is_valid_dns_name(appname)
                && not_blacklisted(username)
                && not_blacklisted(appname)
        }
        NameType::User | NameType::Device | NameType::Agent => {
            is_valid_dns_name(name) && not_blacklisted(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_name() {
        // length must be > 6
        assert!(!is_valid_name("short", NameType::User));
        assert!(!is_valid_name("abc123", NameType::Device)); // len 6, need > 6
        assert!(is_valid_name("mydevice", NameType::Device));
        assert!(!is_valid_name("waterflier", NameType::User)); // blacklisted
        assert!(is_valid_name("myagent1", NameType::Agent));

        // valid DNS: lowercase, letter start, no hyphen at end
        assert!(!is_valid_name("MyDevice", NameType::Device)); // uppercase
        assert!(!is_valid_name("1device", NameType::Device)); // start with digit
        assert!(!is_valid_name("device-", NameType::Device)); // hyphen at end
        assert!(is_valid_name("my-device", NameType::Device));
        assert!(is_valid_name("sub.domain", NameType::User));

        // App: username-appname, both parts valid and length > 6
        assert!(!is_valid_name("waterflier-myapp12", NameType::App)); // username "waterflier" blacklisted
        assert!(!is_valid_name("waterflier-myapp", NameType::App)); // username blacklisted + app len 5
        assert!(is_valid_name("johndoe1-myapp12", NameType::App)); // valid app name
        assert!(!is_valid_name("user-app", NameType::App)); // user len 4, app len 3
        assert!(!is_valid_name("user123-app", NameType::App)); // app len 3
        assert!(!is_valid_name("user123-app456", NameType::App)); // app456 len 6
        assert!(is_valid_name("user1234-app4567", NameType::App));
        assert!(is_valid_name("user1234-app4567.app", NameType::App));
        assert!(!is_valid_name("no-hyphen-here", NameType::App)); // splitn(2,'-') gives ["no","hyphen-here"], user "no" len 2

        // blacklist (exact match on each label)
        assert!(!is_valid_name("administrator", NameType::User));
        assert!(!is_valid_name("localhost", NameType::Device));
        assert!(!is_valid_name("sub.admin.domain", NameType::User)); // sub-label "admin" blacklisted
        assert!(!is_valid_name("administrator-myapp123", NameType::App)); // username blacklisted
        assert!(!is_valid_name("user12345-administrator", NameType::App)); // appname blacklisted

        // phishing / social-engineering names
        assert!(!is_valid_name("official", NameType::User));
        assert!(!is_valid_name("security", NameType::User));
        assert!(!is_valid_name("support", NameType::User));
        assert!(!is_valid_name("verified", NameType::User));
        assert!(!is_valid_name("customer", NameType::User));
        assert!(!is_valid_name("recovery", NameType::User));
        assert!(!is_valid_name("password", NameType::User));
        assert!(!is_valid_name("helpdesk", NameType::Device));
        assert!(!is_valid_name("billing", NameType::User));
        assert!(!is_valid_name("payment", NameType::User));
        assert!(!is_valid_name("notification", NameType::User));

        // system / infrastructure names
        assert!(!is_valid_name("account", NameType::User));
        assert!(!is_valid_name("backend", NameType::Device));
        assert!(!is_valid_name("console", NameType::Device));
        assert!(!is_valid_name("service", NameType::User));
        assert!(!is_valid_name("dashboard", NameType::User));
        assert!(!is_valid_name("controller", NameType::Device));
        assert!(!is_valid_name("production", NameType::Device));

        // admin roles
        assert!(!is_valid_name("sysadmin", NameType::User));
        assert!(!is_valid_name("postmaster", NameType::User));
        assert!(!is_valid_name("webmaster", NameType::User));
        assert!(!is_valid_name("superuser", NameType::User));
    }
}
