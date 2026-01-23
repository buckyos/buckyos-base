mod channel;
mod config;
mod event;
mod json;
mod log_util;
mod machine_config;
mod path;
mod process;
mod provider;
mod serde_helper;
mod stream;

mod time;

#[macro_use]
extern crate log;

pub use channel::*;
pub use config::*;
pub use event::*;
pub use json::*;
pub use log_util::*;
pub use machine_config::*;
pub use path::*;
pub use process::*;
pub use provider::*;
pub use serde_helper::*;
pub use stream::*;

pub use time::*;
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_unix_timestamp() {
        let now = buckyos_get_unix_timestamp();
        assert!(now > 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_execute() {
        unimplemented!()
    }
}
