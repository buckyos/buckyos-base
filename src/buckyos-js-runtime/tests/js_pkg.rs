use boa_engine::{JsString, JsValue, NativeFunction};
use buckyos_js_runtime::{JsEngine, JsPkgManager, JsRuntimeErrorCode};
use serde_json::json;
use std::path::Path;

fn write_pkg(root: &Path, dir: &str, files: &[(&str, &str)]) {
    let pkg_dir = root.join(dir);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    for (name, content) in files {
        std::fs::write(pkg_dir.join(name), content).unwrap();
    }
}

const ECHO_MAIN: &str = r#"
export function main(args) {
    if (args.length > 0 && args[0] === "--help") {
        console.log("usage: echo <words>");
        return "";
    }
    return "echo:" + args.join(",");
}
"#;

#[tokio::test]
async fn load_directory_package_with_default_main() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(temp.path(), "echo", &[("main.js", ECHO_MAIN)]);

    let manager = JsPkgManager::new(temp.path().to_path_buf());
    let pkg = manager.get_pkg("echo").await.unwrap();
    assert_eq!(pkg.name(), "echo");
    assert!(pkg.main().ends_with("main.js"));
    assert_eq!(pkg.description(), "");

    let output = pkg
        .run(vec!["a".to_string(), "b c".to_string()])
        .await
        .unwrap();
    assert_eq!(output, "echo:a,b c");
}

#[tokio::test]
async fn pkg_yaml_selects_main_and_metadata() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(
        temp.path(),
        "tpl",
        &[
            (
                "pkg.yaml",
                "name: template\nmain: index.js\ndescription: a template\nhelp: fixed help\n",
            ),
            ("index.js", ECHO_MAIN),
        ],
    );

    let manager = JsPkgManager::new(temp.path().to_path_buf());
    let pkgs = manager.list_pkgs().await.unwrap();
    assert_eq!(pkgs.len(), 1);
    let pkg = &pkgs[0];
    assert_eq!(pkg.name(), "template");
    assert_eq!(pkg.description(), "a template");
    assert!(pkg.main().ends_with("index.js"));
    assert_eq!(pkg.help().await.unwrap(), "fixed help");
    assert_eq!(pkg.run(vec!["x".to_string()]).await.unwrap(), "echo:x");
}

#[tokio::test]
async fn help_without_pkg_yaml_calls_main_with_help_flag() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(temp.path(), "echo", &[("main.js", ECHO_MAIN)]);

    let pkg = JsPkgManager::new(temp.path().to_path_buf())
        .get_pkg("echo")
        .await
        .unwrap();
    assert_eq!(pkg.help().await.unwrap(), "usage: echo <words>");
}

#[tokio::test]
async fn json_args_and_result_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(
        temp.path(),
        "dns",
        &[(
            "main.js",
            r#"
export function main(args) {
    const [op, params, domain] = args;
    return { op: op, token: params.token, ttl: params.ttl + 1, domain: domain, ok: true };
}
"#,
        )],
    );

    let pkg = JsPkgManager::new(temp.path().to_path_buf())
        .get_pkg("dns")
        .await
        .unwrap();
    let result = pkg
        .run_with_json(vec![
            json!("add"),
            json!({"token": "t-1", "ttl": 59}),
            json!("example.com"),
        ])
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({"op": "add", "token": "t-1", "ttl": 60, "domain": "example.com", "ok": true})
    );
}

#[tokio::test]
async fn init_callback_registers_native_function() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(
        temp.path(),
        "native",
        &[(
            "main.js",
            r#"export function main(args) { return "dir=" + currentDir(); }"#,
        )],
    );

    let mut pkg = JsPkgManager::new(temp.path().to_path_buf())
        .get_pkg("native")
        .await
        .unwrap();
    pkg.enable_fetch(false).init_callback(|engine| {
        engine.register_global_builtin_callable(
            "currentDir".to_string(),
            0,
            NativeFunction::from_copy_closure(|_, _, _| {
                Ok(JsValue::from(JsString::from("/fixed/dir")))
            }),
        )?;
        Ok(())
    });
    assert_eq!(pkg.run(vec![]).await.unwrap(), "dir=/fixed/dir");
}

#[tokio::test]
async fn missing_package_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let err = match JsPkgManager::new(temp.path().to_path_buf())
        .get_pkg("nope")
        .await
    {
        Ok(_) => panic!("package should not load"),
        Err(err) => err,
    };
    assert_eq!(err.code(), JsRuntimeErrorCode::Failed);
    assert!(err.msg().contains("main.js"));
}

#[tokio::test]
async fn main_must_return_string_for_run() {
    let temp = tempfile::tempdir().unwrap();
    write_pkg(
        temp.path(),
        "num",
        &[("main.js", "export function main(args) { return 42; }")],
    );
    let pkg = JsPkgManager::new(temp.path().to_path_buf())
        .get_pkg("num")
        .await
        .unwrap();
    let err = pkg.run(vec![]).await.unwrap_err();
    assert_eq!(err.code(), JsRuntimeErrorCode::Failed);
}

#[test]
fn engine_evaluates_string_and_calls_export() {
    let mut engine = JsEngine::builder().enable_fetch(false).build().unwrap();
    engine
        .eval_string("export function add(a, b) { console.log('adding'); return a + b; }")
        .unwrap();
    let result = engine
        .call("add", vec![JsValue::from(2), JsValue::from(3)])
        .unwrap();
    assert_eq!(result.as_number(), Some(5.0));
    assert_eq!(engine.get_output(), "adding");

    let err = engine.call("missing", vec![]).unwrap_err();
    assert_eq!(err.code(), JsRuntimeErrorCode::JsFailed);
}

#[test]
fn eval_file_with_bad_path_is_invalid_path() {
    let mut engine = JsEngine::builder().enable_fetch(false).build().unwrap();
    let err = engine
        .eval_file(Path::new("/definitely/not/here.js"))
        .unwrap_err();
    assert_eq!(err.code(), JsRuntimeErrorCode::InvalidPath);
}
