use std::env;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BuckyOSChannel {
    Nightly,
    Beta,
    Stable,
}

impl FromStr for BuckyOSChannel {
    type Err = String;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let ret = match str {
            "nightly" => BuckyOSChannel::Nightly,
            "beta" => BuckyOSChannel::Beta,
            "stable" => BuckyOSChannel::Stable,
            _ => {
                log::warn!("unknown channel name {}, use default nightly channel", str);
                BuckyOSChannel::Nightly
            }
        };

        Ok(ret)
    }
}

impl Display for BuckyOSChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BuckyOSChannel::Nightly => write!(f, "nightly"),
            BuckyOSChannel::Beta => write!(f, "beta"),
            BuckyOSChannel::Stable => write!(f, "stable"),
        }
    }
}

impl BuckyOSChannel {
    #[allow(dead_code)]
    fn get_ver(&self) -> u8 {
        match self {
            BuckyOSChannel::Nightly => 0,
            BuckyOSChannel::Beta => 1,
            BuckyOSChannel::Stable => 2,
        }
    }
}

pub fn get_version() -> &'static str {
    &VERSION
}

pub fn get_channel() -> &'static BuckyOSChannel {
    &CHANNEL
}

pub fn get_target() -> &'static str {
    &TARGET
}

fn get_version_impl() -> String {
    format!(
        "{}+build{}{} ({})",
        env!("VERSION"),
        env!("BUILDDATE"),
        env!("VERSION_EXTEND"),
        get_channel()
    )
}

fn get_channel_impl() -> BuckyOSChannel {
    let channel_str = match std::env::var("CYFS_CHANNEL") {
        Ok(channel) => {
            info!(
                "got channel config from CYFS_CHANNEL env: channel={}",
                channel
            );
            channel
        }
        Err(_) => {
            let channel = env!("CHANNEL").to_owned();
            info!("use default channel config: channel={}", channel);
            channel
        }
    };

    BuckyOSChannel::from_str(channel_str.as_str()).unwrap()
}

lazy_static::lazy_static! {
    static ref CHANNEL: BuckyOSChannel = get_channel_impl();
    static ref VERSION: String = get_version_impl();
    static ref TARGET: &'static str = env!("TARGET");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_from_str_table() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expected: BuckyOSChannel,
        }

        let cases = vec![
            Case {
                name: "nightly",
                input: "nightly",
                expected: BuckyOSChannel::Nightly,
            },
            Case {
                name: "beta",
                input: "beta",
                expected: BuckyOSChannel::Beta,
            },
            Case {
                name: "stable",
                input: "stable",
                expected: BuckyOSChannel::Stable,
            },
            Case {
                name: "unknown_defaults",
                input: "unknown",
                expected: BuckyOSChannel::Nightly,
            },
        ];

        for case in cases {
            let parsed = BuckyOSChannel::from_str(case.input).unwrap();
            assert_eq!(parsed, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_channel_display_and_version_output() {
        let cases = vec![
            ("nightly", BuckyOSChannel::Nightly, 0_u8),
            ("beta", BuckyOSChannel::Beta, 1_u8),
            ("stable", BuckyOSChannel::Stable, 2_u8),
        ];

        for (expected, channel, ver) in cases {
            assert_eq!(channel.to_string(), expected);
            assert_eq!(channel.get_ver(), ver);
        }

        let version = get_version();
        assert!(version.contains(env!("VERSION")));
        let target = get_target();
        assert!(!target.is_empty());
    }
}
