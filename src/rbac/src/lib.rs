#![allow(dead_code)]
#![allow(unused)]

use casbin::RbacApi;
use casbin::{
    rhai::ImmutableString, CoreApi, DefaultModel, Enforcer, Filter, MemoryAdapter, MgmtApi,
};
use lazy_static::lazy_static;
use log::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const DEFAULT_MODEL: &str = r#"
[request_definition]
r = sub,obj,act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _ # sub, role

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = (g(r.sub, p.sub) || r.sub == p.sub) && ((r.sub == keyGet3(r.obj, p.obj, p.sub) || keyGet3(r.obj, p.obj, p.sub) =="") && keyMatch3(r.obj,p.obj)) && regexMatch(r.act, p.act)
"#;

pub const DEFAULT_POLICY: &str = r#"
p, kernel, /config/*, read|write,allow
p, root, /config/*, read|write,allow

p, ood,/config/*,read,allow
p, ood,/config/agents/*/doc,read,allow
p, ood,/config/users/*/apps/*,read|write,allow
p, ood,/config/nodes/{device}/*,read|write,allow
p, ood,/config/services/*,read|write,allow
p, ood,/config/system/rbac/policy,read|write,allow

p, client,/config/boot/*, read,allow
p, client,/config/agents/*/doc,read,allow
p, client,/config/devices/{device}/*,read,allow
p, client,/config/devices/{device}/info,read|write,allow

p, service, /config/boot/*, read,allow
p, service, /config/agents/*/doc,read,allow
p, service,/config/services/{service}/*,read|write,allow
p, service,/config/services/*/info,read,allow
p, service,/config/users*,read,allow
p, service,/config/users/*/*,read,allow
p, service,/config/system/*,read,allow


p, app, /config/boot/*, read,allow
p, app, /config/agents/*/doc,read,allow
p, app, /config/users/*/apps/{app}/settings,read|write,allow
p, app, /config/users/*/apps/{app}/spec,read,allow
p, app, /config/users/*/apps/{app}/info,read,allow
p, app, /config/services/*/info,read,allow

p, admin, /config/boot/*, read,allow
p, admin,/config/agents/*/doc,read|write,allow
p, admin,/config/users/{user}/*,read|write,allow
p, admin,/config/services/*,read|write,allow

p, user,/config/boot/*, read,allow
p, user,/config/agents/*/doc,read,allow
p, user,/config/users/{user}/*,read,allow
p, user,/config/users/{user}/apps/*/*,read|write,allow
p, user,/config/services/*/info,read,allow


g, node-daemon, kernel
g, scheduler, kernel
g, system-config, kernel
g, verify-hub, kernel
g, task-manager, kernel
g, kmsg, kernel
g, aicc, kernel
g, msg-center, kernel
g, control-panel, kernel
g, buckycli, kernel
g, cyfs-gateway, kernel
"#;

lazy_static! {
    static ref SYS_ENFORCE: Arc<Mutex<Option<Enforcer>>> = { Arc::new(Mutex::new(None)) };
}
pub async fn create_enforcer(
    model_str: Option<&str>,
    policy_str: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let model_str = model_str.unwrap_or(DEFAULT_MODEL);
    let policy_str = policy_str.unwrap_or(DEFAULT_POLICY);

    let m = DefaultModel::from_str(model_str).await?;
    let mut e = Enforcer::new(m, MemoryAdapter::default()).await?;
    for line in policy_str.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            let rule: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
            if rule[0] == "p" {
                e.add_policy(rule[1..].to_vec()).await?;
            } else if rule[0] == "g" {
                e.add_grouping_policy(rule[1..].to_vec()).await?;
            }
        }
    }

    let mut enforcer = SYS_ENFORCE.lock().await;
    *enforcer = Some(e);
    Ok(())
}

pub async fn update_enforcer(policy_str: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let policy_str = policy_str.unwrap_or(DEFAULT_POLICY);
    let model_str = DEFAULT_MODEL;
    return create_enforcer(Some(model_str), Some(policy_str)).await;
}
//use default RBAC config to enforce the access control
//default acl config is stored in the memory,so it is not async function
pub async fn enforce(userid: &str, appid: Option<&str>, res_path: &str, op_name: &str) -> bool {
    let enforcer = SYS_ENFORCE.lock().await;
    if enforcer.is_none() {
        error!("enforcer is not initialized");
        return false;
    }
    let enforcer = enforcer.as_ref().unwrap();

    //let roles = enforcer.get_roles_for_user(userid,None);
    //println!("roles for user {}: {:?}", userid, roles);
    //info!("roles for user {}: {:?}", userid, roles);

    let appid = appid.unwrap_or("kernel");
    let res2 = enforcer.enforce((appid, res_path, op_name));
    if res2.is_err() {
        warn!("enforce error: {}", res2.err().unwrap());
        return false;
    }
    let res2 = res2.unwrap();

    //println!("enforce {},{},{}, result:{}",appid, res_path, op_name,res2);
    debug!(
        "enforce {},{},{}, result:{}",
        appid, res_path, op_name, res2
    );
    if appid == "kernel" {
        return res2;
    }

    let res = enforcer.enforce((userid, res_path, op_name));
    if res.is_err() {
        warn!("enforce error: {}", res.err().unwrap());
        return false;
    }
    let res = res.unwrap();
    //println!("enforce {},{},{} result:{}",userid, res_path, op_name,res);
    debug!("enforce {},{},{} result:{}", userid, res_path, op_name, res);
    return res2 && res;
}

//test
#[cfg(test)]
mod tests {
    use super::*;
    use casbin::{
        rhai::ImmutableString, CoreApi, DefaultModel, Enforcer, Filter, MemoryAdapter, MgmtApi,
    };
    use std::collections::HashMap;
    use tokio::test;

    #[test]
    async fn test_simple_enforce() -> Result<(), Box<dyn std::error::Error>> {
        // 定义模型配置
        let model_str = r#"
[request_definition]
r = sub,act, obj 

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
        "#;

        // 定义策略配置
        let policy_str = r#"
        p, owner, /config/*, read|write,allow
        p, owner, dfs://*, read|write,allow
        p, owner, fs://$device_id:/, read,allow
    
        p, kernel_service, /config/*, read,allow
        p, kernel_service, dfs://*, read,allow
        p, kernel_service, fs://$device_id:/, read,allow
    
        p, frame_service, /config/*, read,allow
        p, frame_service, dfs://*, read,allow
        p, frame_service, fs://$device_id:/, read,allow
    
        p, sudo_user, /config/*, read|write,allow
        p, sudo_user, dfs://*, read|write,allow
    
    
        p, user, dfs://homes/:userid, read|write,allow
        p, user, dfs://public,read|write,allow
        
    
        p, limit_user, dfs://homes/:userid, read,allow
    
        p, guest, dfs://public, read,allow
        p, bob,dfs://public,write,deny
    
        g, alice, owner
        g, bob, user
        g, charlie, user
        g, app1, app_service 
        "#;

        // 使用字符串创建 Casbin 模型和策略适配器
        let m = DefaultModel::from_str(model_str).await?;
        // 创建一个空的内存适配器
        let mut e = Enforcer::new(m, MemoryAdapter::default()).await?;

        // 手动加载策略
        for line in policy_str.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                let rule: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
                if rule[0] == "p" {
                    println!("add policy {:?}", &rule);
                    e.add_policy(rule[1..].to_vec()).await?;
                } else if rule[0] == "g" {
                    println!("add group policy {:?}", &rule);
                    e.add_grouping_policy(rule[1..].to_vec()).await?;
                }
            }
        }

        // 测试权限
        let alice_read_kv = e.enforce(("alice", "write", "/config/config")).unwrap();
        println!("Alice can write /config/config: {}", alice_read_kv); // true
        assert_eq!(alice_read_kv, true);

        Ok(())
    }

    #[test]
    async fn test_enforce() {
        std::env::set_var("BUCKY_LOG", "debug");
        buckyos_kit::init_logging("test_rbac", false);
        let mut policy_str = DEFAULT_POLICY.to_string();
        policy_str = policy_str
            + r#"
g, sys-test, app
g, buckyos-filebrowser, app
g, ood1, ood
g, app1, app
g, lzc-laptop,client
g, alice,admin
g, smb-service,service
g, repo-service,service
g, bob,user
g, jarvis,app
p, su_bob,/config/users/bob/*,read|write,allow
        "#;
        create_enforcer(None, Some(&policy_str)).await.unwrap();
        let res = enforce("ood", Some("node-daemon"), "/config/boot/config", "read").await;
        assert_eq!(res, true);
        assert_eq!(
            enforce("ood1", Some("node-daemon"), "/config/boot/config", "write").await,
            false
        );
        assert_eq!(
            enforce("jarvis", Some("bob"), "/config/agents/jarvis/doc", "read").await,
            true
        );
        assert_eq!(
            enforce("jarvis", Some("bob"), "/config/services/task-manager/info", "read").await,
            true
        );
        assert_eq!(
            enforce(
                "ood1",
                Some("verify-hub"),
                "/config/system/verify-hub/key",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce("root", Some("node-daemon"), "/config/boot/config", "write").await,
            true
        );
        assert_eq!(
            enforce(
                "ood1",
                Some("repo-service"),
                "/config/services/repo-service/instance/ood1",
                "write"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "ood1",
                Some("smb-service"),
                "/config/services/smb-service/latest_smb_items",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce("ood1", Some("smb-service"), "/config/boot/config", "read").await,
            true
        );
        assert_eq!(
            enforce(
                "ood1",
                Some("scheduler"),
                "/config/users/alice/apps/app2/config",
                "write"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "bob",
                Some("node-daemon"),
                "/config/users/alice/apps/app2",
                "read"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "bob",
                Some("app1"),
                "/config/users/bob/apps/app1/settings",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "bob",
                Some("control-panel"),
                "/config/users/bob/settings",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "bob",
                Some("control-panel"),
                "/config/users/bob/settings",
                "write"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "su_bob",
                Some("control-panel"),
                "/config/users/bob/settings",
                "write"
            )
            .await,
            true
        );
     
        assert_eq!(
            enforce(
                "ood1",
                Some("repo-service"),
                "/config/services/verify-hub/info",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce("ood1", Some("cyfs-gateway"), "/config/boot/config", "read").await,
            true
        );
        //app1 can read and write config and info
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app1/spec",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app1/spec",
                "write"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app1/info",
                "read"
            )
            .await,
            true
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app1/info",
                "write"
            )
            .await,
            false
        );
      
        assert_eq!(
            enforce(
                "root",
                Some("app1"),
                "/config/users/alice/apps/app1/settings",
                "write"
            )
            .await,
            true
        );


        //can not read and write app2
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app2/settings",
                "write"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "/config/users/alice/apps/app2/info",
                "read"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "dfs://users/alice/appdata/app2/readme.txt",
                "write"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "dfs://users/alice/appdata/app2/readme.txt",
                "read"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "dfs://users/alice/cache/app2/readme_cache.txt",
                "write"
            )
            .await,
            false
        );
        assert_eq!(
            enforce(
                "alice",
                Some("app1"),
                "dfs://users/alice/cache/app2/readme_cache.txt",
                "read"
            )
            .await,
            false
        );
        assert_eq!(true, true);
        assert_eq!(false, false);
        //su_alice has more permission than alice
        //assert_eq!(enforce("su_alice", Some("control_panel"), "/config/users/alice/apps/app2/config", "write").await, true);
    }
}
