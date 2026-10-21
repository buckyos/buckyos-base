use std::path::{Path, PathBuf};
use std::sync::Arc;
use boa_engine::{JsString, JsValue};
use boa_engine::object::builtins::JsArray;
use serde::{Deserialize};
use serde_json::Value;
use crate::{into_js_runtime_err, js_runtime_err, JsEngine, JsEngineInitCallback, JsRuntimeResult};

#[derive(Deserialize)]
pub struct JsPkgConfig {
    name: String,
    main: Option<String>,
    description: Option<String>,
    help: Option<String>,
}

#[derive(Clone)]
pub struct JsPkg {
    name: String,
    main: String,
    description: String,
    help: String,
    enable_fetch: bool,
    enable_console: bool,
    enable_commonjs: bool,
    init_callback: Option<JsEngineInitCallback>,
}

impl JsPkg {
    pub fn new(name: impl Into<String>,
               main: impl Into<String>,
               description: impl Into<String>,
               help: impl Into<String>) -> Self {
        JsPkg {
            name: name.into(),
            main: main.into(),
            description: description.into(),
            help: help.into(),
            enable_fetch: true,
            enable_console: true,
            enable_commonjs: true,
            init_callback: None,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn main(&self) -> &str {
        self.main.as_str()
    }

    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    pub fn enable_fetch(&mut self, enable: bool) -> &mut Self {
        self.enable_fetch = enable;
        self
    }

    pub fn enable_console(&mut self, enable: bool) -> &mut Self {
        self.enable_console = enable;
        self
    }

    pub fn enable_commonjs(&mut self, enable: bool) -> &mut Self {
        self.enable_commonjs = enable;
        self
    }

    pub fn init_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(&mut JsEngine) -> JsRuntimeResult<()> + Send + Sync + 'static,
    {
        self.init_callback = Some(Arc::new(callback));
        self
    }

    pub async fn run(&self, args: Vec<String>) -> JsRuntimeResult<String> {
        let enable_fetch = self.enable_fetch;
        let enable_console = self.enable_console;
        let enable_commonjs = self.enable_commonjs;
        let init_callback = self.init_callback.clone();
        let main = self.main.clone();
        let ret = tokio::task::spawn_blocking(move || {
            let mut builder = JsEngine::builder()
                .enable_fetch(enable_fetch)
                .enable_console(enable_console)
                .enable_commonjs(enable_commonjs);
            if let Some(init_callback) = init_callback {
                builder = builder.init_callback(move |engine| (init_callback)(engine));
            }
            let mut js_engine = builder
                .build()
                .map_err(into_js_runtime_err!("build js engine error"))?;

            js_engine.eval_file(Path::new(main.as_str()))
                .map_err(into_js_runtime_err!("eval file {}", main.as_str()))?;

            let args = args.iter()
                .map(|v| JsValue::from(JsString::from(v.as_str())))
                .collect::<Vec<_>>();
            let args = JsArray::from_iter(args.into_iter(), js_engine.context());
            let result = js_engine.call("main", vec![JsValue::from(args)])
                .map_err(into_js_runtime_err!("call main"))?;
            if result.is_string() {
                Ok(result.as_string().unwrap().as_str().to_std_string_lossy())
            } else {
                Err(js_runtime_err!("main must return a string"))
            }
        }).await.map_err(into_js_runtime_err!("run {}", self.name))?;
        ret
    }

    pub async fn run_with_json(&self, args: Vec<Value>) -> JsRuntimeResult<Value> {
        let enable_fetch = self.enable_fetch;
        let enable_console = self.enable_console;
        let enable_commonjs = self.enable_commonjs;
        let init_callback = self.init_callback.clone();
        let main = self.main.clone();
        let ret = tokio::task::spawn_blocking(move || {
            let mut builder = JsEngine::builder()
                .enable_fetch(enable_fetch)
                .enable_console(enable_console)
                .enable_commonjs(enable_commonjs);
            if let Some(init_callback) = init_callback {
                builder = builder.init_callback(move |engine| (init_callback)(engine));
            }
            let mut js_engine = builder
                .build()
                .map_err(into_js_runtime_err!("build js engine error"))?;

            js_engine.eval_file(Path::new(main.as_str()))
                .map_err(into_js_runtime_err!("eval file {}", main.as_str()))?;

            let args = {
                let context = js_engine.context();
                let mut json_args = Vec::new();
                for arg in args.iter() {
                    json_args.push(JsValue::from_json(arg, context).map_err(|e| js_runtime_err!("convert arg err {:?}", e))?);
                }
                JsArray::from_iter(json_args.into_iter(), context)
            };
            let result = js_engine.call("main", vec![JsValue::from(args)])
                .map_err(into_js_runtime_err!("call main"))?;
            let result = result.to_json(js_engine.context())
                .map_err(|e| js_runtime_err!("convert result err {:?}", e))?;
            result.ok_or_else(|| js_runtime_err!("main must return a json value"))
        }).await.map_err(into_js_runtime_err!("run {}", self.name))?;
        ret
    }

    pub async fn help(&self) -> JsRuntimeResult<String> {
        if self.help.is_empty() {
            let enable_fetch = self.enable_fetch;
            let enable_console = self.enable_console;
            let enable_commonjs = self.enable_commonjs;
            let init_callback = self.init_callback.clone();
            let main = self.main.clone();
            let ret = tokio::task::spawn_blocking(move || {
                let mut builder = JsEngine::builder()
                    .enable_fetch(enable_fetch)
                    .enable_console(enable_console)
                    .enable_commonjs(enable_commonjs);
                if let Some(init_callback) = init_callback {
                    builder = builder.init_callback(move |engine| (init_callback)(engine));
                }
                let mut js_engine = builder
                    .build()
                    .map_err(into_js_runtime_err!("build js engine error"))?;

                js_engine.eval_file(Path::new(main.as_str()))
                    .map_err(into_js_runtime_err!("eval file {}", main.as_str()))?;

                let args = vec![JsValue::from(JsString::from("--help"))];
                let args = JsArray::from_iter(args.into_iter(), js_engine.context());
                let _ = js_engine.call("main", vec![JsValue::from(args)])
                    .map_err(into_js_runtime_err!("call main"))?;
                
                Ok(js_engine.get_output())
            }).await.map_err(into_js_runtime_err!("run {}", self.name))?;
            ret
        } else {
            Ok(self.help.clone())
        }
    }
}

pub struct JsPkgManager {
    js_cmd_path: PathBuf,
}
pub type JsPkgManagerRef = Arc<JsPkgManager>;

impl JsPkgManager {
    pub fn new(js_cmd_path: PathBuf) -> Arc<Self> {
        Arc::new(JsPkgManager {
            js_cmd_path,
        })
    }

    pub async fn list_pkgs(&self) -> JsRuntimeResult<Vec<JsPkg>> {
        let dirs = self.js_cmd_path.read_dir()
            .map_err(into_js_runtime_err!("read {:?}", self.js_cmd_path))?;
        let mut pkgs = vec![];
        for entry in dirs {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    let cmd = self.load_pkg(&path).await?;
                    pkgs.push(cmd);
                }
            }
        }
        Ok(pkgs)
    }

    async fn load_pkg(&self, path: &Path) -> JsRuntimeResult<JsPkg> {
        let cfg_path = path.join("pkg.yaml");
        if cfg_path.exists() {
            let content = tokio::fs::read_to_string(cfg_path.as_path()).await
                .map_err(into_js_runtime_err!("read file {}", cfg_path.to_string_lossy().to_string()))?;
            let config = serde_yaml_ng::from_str::<JsPkgConfig>(content.as_str())
                .map_err(into_js_runtime_err!("parse {}", content))?;
            let main = config.main
                .map(|v| path.join(v).to_string_lossy().to_string())
                .unwrap_or(path.join("main.js").to_string_lossy().to_string());
            Ok(JsPkg::new(
                config.name,
                main,
                config.description.unwrap_or("".to_string()),
                config.help.unwrap_or("".to_string()),
            ))
        } else {
            let main_js = path.join("main.js");
            if !main_js.exists() {
                return Err(js_runtime_err!("{} not exists", main_js.to_string_lossy().to_string()));
            }
            if let Some(file_name) = path.file_name() {
                Ok(JsPkg::new(
                    file_name.to_string_lossy().to_string(),
                    main_js.to_string_lossy().to_string(),
                    "",
                    "",
                ))
            } else {
                Err(js_runtime_err!("{} not exists", main_js.to_string_lossy().to_string()))
            }
        }
    }

    pub async fn get_pkg(&self, name: impl Into<String>) -> JsRuntimeResult<JsPkg> {
        self.load_pkg(self.js_cmd_path.join(name.into()).as_path()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_list_pkgs() {
        // 创建临时目录
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path();

        // 创建测试包目录 pkg1
        let pkg1_path = test_path.join("pkg1");
        fs::create_dir_all(&pkg1_path).await.unwrap();
        let main_js_content = r#"
            export function main(args) {
                console.log("Hello from pkg1");
                return "pkg1 executed";
            }
        "#;
        fs::write(pkg1_path.join("main.js"), main_js_content).await.unwrap();

        // 创建测试包目录 pkg2
        let pkg2_path = test_path.join("pkg2");
        fs::create_dir_all(&pkg2_path).await.unwrap();
        let pkg2_yaml_content = r#"
            name: "pkg2"
            main: "index.js"
            description: "A test package"
            params: "test_params"
        "#;
        fs::write(pkg2_path.join("pkg.yaml"), pkg2_yaml_content).await.unwrap();
        let index_js_content = r#"
            export function main(args) {
                console.log("Hello from pkg2");
                console.log(args);
                return "pkg2 executed";
            }
        "#;
        fs::write(pkg2_path.join("index.js"), index_js_content).await.unwrap();

        let manager = JsPkgManager::new(test_path.to_path_buf());
        let pkgs = manager.list_pkgs().await.unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name(), "pkg1");
        assert_eq!(pkgs[1].name(), "pkg2");

        let pkg2 = pkgs[1].clone();
        pkg2.run(vec!["arg1".to_string(), "arg2".to_string()]).await.unwrap();
        
        pkg2.run_with_json(vec![Value::String("arg1".to_string()), Value::String("arg2".to_string())]).await.unwrap();
    }
}
