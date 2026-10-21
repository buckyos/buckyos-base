use std::cell::RefCell;
use std::fs::read_to_string;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use boa_ast::scope::Scope;
use boa_engine::{js_string, Context, JsArgs, JsError, JsNativeError, JsObject, JsResult, JsString, JsValue, Module, NativeFunction, Source};
use boa_engine::class::Class;
use boa_engine::module::{resolve_module_specifier, ModuleLoader, Referrer};
use boa_engine::object::builtins::JsArray;
use boa_engine::property::{Attribute, PropertyKey};
use boa_interner::{Interner};
use boa_parser::Parser;
use rustc_hash::FxHashMap;
use boa_engine::gc::GcRefCell;
use crate::console_logger::{ConsoleLogger, LogCache};
use crate::{into_js_runtime_err, js_runtime_err, JsRuntimeErrorCode, JsRuntimeResult};

fn detect_js_module_type(src: &str, filename: &str) -> &'static str {
    if filename.ends_with(".mjs") {
        return "esm";
    }
    if filename.ends_with(".cjs") {
        return "commonjs";
    }
    let mut interner = Interner::default();
    let source = Source::from_bytes(src.as_bytes());
    let mut parser = Parser::new(source);

    let scope = Scope::default();
    let ast = parser.parse_module(&scope, &mut interner).ok();

    let ast = match ast {
        Some(program) => program,
        None => return "esm",
    };

    if ast.items().exported_names().len() > 0 {
        "esm"
    } else {
        "commonjs"
    }
}

fn module_wrapper(content: impl Into<String>, file_name: &Path) -> String {
    let wrapper_code = format!(r#"const __filename = {:?}; const __dirname = {:?}; function require(module_name) {{return __require(module_name, __filename, __dirname);}} {}"#,
                               file_name, file_name.parent().unwrap_or(Path::new("./")), content.into());
    wrapper_code
}

fn commonjs_wrapper(content: impl Into<String>, file_name: &Path) -> String {
    let wrapper_code = format!(
        r#"const __filename = {:?};const __dirname = {:?};const module = {{exports: {{}}}};var exports = module.exports;function require(module_name) {{return __require(module_name, __filename, __dirname);}} {}
        const default_exports = module.exports;
        export default default_exports;
        "#,
        file_name, file_name.parent().unwrap_or(Path::new("./")), content.into()
    );
    wrapper_code
}

struct JsModuleLoader {
    roots: Mutex<Vec<PathBuf>>,
    module_map: GcRefCell<FxHashMap<PathBuf, Module>>,
}

impl JsModuleLoader {
    pub fn new(roots: Vec<PathBuf>) -> JsRuntimeResult<Self> {
        if !roots.is_empty() {
            if cfg!(target_family = "wasm") {
                return Err(js_runtime_err!(JsRuntimeErrorCode::JsFailed, "cannot resolve a relative path in WASM targets"));
            }
        }
        Ok(Self {
            roots: Mutex::new(roots),
            module_map: GcRefCell::new(FxHashMap::default()),
        })
    }

    #[inline]
    pub fn insert(&self, path: PathBuf, module: Module) {
        self.module_map.borrow_mut().insert(path, module);
    }

    #[inline]
    pub fn get(&self, path: &Path) -> Option<Module> {
        self.module_map.borrow().get(path).cloned()
    }

    pub fn add_module_path(&self, module_path: &Path) -> JsRuntimeResult<()> {
        self.roots.lock().unwrap().push(module_path.canonicalize()
            .map_err(into_js_runtime_err!(JsRuntimeErrorCode::InvalidPath, "Invalid path {:?}", module_path))?);
        Ok(())
    }

    pub fn commonjs_resolve_module(&self, module_name: &str, referrer: &Path) -> JsResult<PathBuf> {
        let roots = {
            self.roots.lock().unwrap().clone()
        };
        let is_relative = module_name.starts_with(".") || module_name.starts_with("..");
        for root in roots.iter() {
            let mut path = if is_relative {
                let path = referrer.join(module_name);
                let path = path
                    .components()
                    .filter(|c| c != &Component::CurDir || c == &Component::Normal("".as_ref()))
                    .try_fold(PathBuf::new(), |mut acc, c| {
                        if c == Component::ParentDir {
                            if acc.as_os_str().is_empty() {
                                return Err(JsError::from_opaque(
                                    js_string!("path is outside the module root").into(),
                                ));
                            }
                            acc.pop();
                        } else {
                            acc.push(c);
                        }
                        Ok(acc)
                    })?;
                if !path.starts_with(root) {
                    return Err(JsError::from_opaque(
                        js_string!("path is outside the module root").into(),
                    ));
                }
                path
            } else {
                root.join(module_name)
            };
            if path.exists() && path.is_dir() {
                let index = path.join("index.js");
                if index.exists() && index.is_file() {
                    return Ok(index);
                }
            }
            if path.exists() && path.is_file() {
                return Ok(path);
            }
            let mut js_path = path.to_path_buf();
            js_path.add_extension("js");
            if js_path.exists() && js_path.is_file() {
                return Ok(js_path);
            }
            path.add_extension("mjs");
            if path.exists() && path.is_file() {
                return Ok(path);
            }
        }
        Err(JsError::from_native(JsNativeError::typ().with_message(format!("module {} not found", module_name))))
    }
}

impl ModuleLoader for JsModuleLoader {
    async fn load_imported_module(self: Rc<Self>, referrer: Referrer, specifier: JsString, context: &RefCell<&mut Context>) -> JsResult<Module> {
        let roots = {
            self.roots.lock().unwrap().clone()
        };
        for root in roots.iter() {
            let short_path = specifier.to_std_string_escaped();
            let path = resolve_module_specifier(
                Some(root),
                &specifier,
                referrer.path(),
                &mut context.borrow_mut(),
            )?;
            if let Some(module) = self.get(&path) {
                return Ok(module);
            }

            let mut path = path.to_path_buf();
            if !path.exists() && !path.ends_with(".js") {
                path.add_extension("js");
            }

            let module_content = tokio::fs::read_to_string(path.as_path()).await.map_err(|e| {
                JsError::from_native(JsNativeError::typ().with_message(format!("could not read module `{short_path}`.err {:?}", e)))
            })?;
            let module_type = detect_js_module_type(module_content.as_str(), path.as_path().to_string_lossy().to_string().as_str());
            let wrapper_code = if module_type == "esm" {
                module_wrapper(module_content, path.as_path())
            } else {
                commonjs_wrapper(module_content, path.as_path())
            };

            let source = Source::from_reader(wrapper_code.as_bytes(), Some(path.as_path()));
            let module = Module::parse(source, None, &mut context.borrow_mut()).map_err(|err| {
                JsNativeError::syntax()
                    .with_message(format!("could not parse module `{short_path}`"))
                    .with_cause(err)
            })?;
            self.insert(path.clone(), module.clone());
            return Ok(module);
        }

        Err(
            JsError::from_native(JsNativeError::typ()
                .with_message(format!("could not find module `{:?}`", specifier))))
    }
}

pub type JsEngineInitCallback = Arc<dyn Fn(&mut JsEngine) -> JsRuntimeResult<()> + Send + Sync>;

pub struct JsEngineBuilder {
    enable_fetch: bool,
    enable_console: bool,
    enable_commonjs: bool,
    init_callback: Option<JsEngineInitCallback>,
}

impl Default for JsEngineBuilder {
    fn default() -> Self {
        Self {
            enable_fetch: true,
            enable_console: true,
            enable_commonjs: true,
            init_callback: None,
        }
    }
}

impl JsEngineBuilder {
    pub fn enable_fetch(mut self, enable: bool) -> Self {
        self.enable_fetch = enable;
        self
    }

    pub fn enable_console(mut self, enable: bool) -> Self {
        self.enable_console = enable;
        self
    }

    pub fn enable_commonjs(mut self, enable: bool) -> Self {
        self.enable_commonjs = enable;
        self
    }

    pub fn init_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&mut JsEngine) -> JsRuntimeResult<()> + Send + Sync + 'static,
    {
        self.init_callback = Some(Arc::new(callback));
        self
    }

    pub fn build(self) -> JsRuntimeResult<JsEngine> {
        JsEngine::create(self)
    }
}

pub struct JsEngine {
    loader: Rc<JsModuleLoader>,
    context: Context,
    module: Option<Module>,
    log_cache: LogCache,
}

unsafe impl Send for JsEngine {}
unsafe impl Sync for JsEngine {}

impl JsEngine {
    pub fn new() -> JsRuntimeResult<Self> {
        Self::create(JsEngineBuilder::default())
    }

    pub fn builder() -> JsEngineBuilder {
        JsEngineBuilder::default()
    }

    fn create(builder: JsEngineBuilder) -> JsRuntimeResult<Self> {
        let JsEngineBuilder {
            enable_fetch,
            enable_console,
            enable_commonjs,
            init_callback,
        } = builder;
        let loader = Rc::new(JsModuleLoader::new(vec![])?);
        let mut context = Context::builder()
            .module_loader(loader.clone())
            .can_block(true)
            .build()
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;

        let log_cache = LogCache::new();
        if enable_fetch && enable_console {
            boa_runtime::register((
                                       boa_runtime::extensions::ConsoleExtension(ConsoleLogger::new(log_cache.clone())),
                                       boa_runtime::extensions::FetchExtension(
                                           boa_runtime::fetch::BlockingReqwestFetcher::default()
                                       ),
                                   ),
                                   None,
                                   &mut context,
            ).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        } else if enable_console {
            boa_runtime::register(
                boa_runtime::extensions::ConsoleExtension(ConsoleLogger::new(log_cache.clone())),
                None,
                &mut context,
            ).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        } else if enable_fetch {
            boa_runtime::register(
                boa_runtime::extensions::FetchExtension(
                    boa_runtime::fetch::BlockingReqwestFetcher::default()
                ),
                None,
                &mut context,
            ).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        }

        if enable_commonjs {
            context.register_global_callable("__require".into(), 0, NativeFunction::from_fn_ptr(require))
                .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        }

        let mut engine = JsEngine {
            loader,
            context,
            module: None,
            log_cache,
        };

        if let Some(init) = init_callback {
            init(&mut engine)?;
        }

        Ok(engine)
    }

    pub fn context(&mut self) -> &mut Context {
        &mut self.context
    }

    pub fn add_module_path(&mut self, module_path: &Path) -> JsRuntimeResult<()> {
        self.loader.add_module_path(module_path)
    }

    pub fn register_global_property<K, V>(
        &mut self,
        key: K,
        value: V,
        attribute: Attribute,
    ) -> JsRuntimeResult<()>
    where
        K: Into<PropertyKey>,
        V: Into<JsValue>, {
        self.context.register_global_property(key, value, attribute)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_callable(
        &mut self,
        name: String,
        length: usize,
        body: NativeFunction,
    ) -> JsRuntimeResult<()> {
        self.context.register_global_callable(JsString::from(name), length, body)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_builtin_callable(
        &mut self,
        name: String,
        length: usize,
        body: NativeFunction,
    ) -> JsRuntimeResult<()> {
        self.context.register_global_builtin_callable(JsString::from(name), length, body)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn register_global_class<C: Class>(&mut self) -> JsRuntimeResult<()> {
        self.context.register_global_class::<C>()
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        Ok(())
    }

    pub fn eval_file(&mut self, path: &Path) -> JsRuntimeResult<()> {
        let path = path.canonicalize()
            .map_err(into_js_runtime_err!(JsRuntimeErrorCode::InvalidPath, "Invalid path {:?}", path))?;
        if let Some(parent) = path.parent() {
            self.add_module_path(parent)?;
        } else {
            self.add_module_path(std::env::current_dir()
                .map_err(into_js_runtime_err!(JsRuntimeErrorCode::InvalidPath))?.as_path())?;
        }
        let source = std::fs::read_to_string(path.as_path())
            .map_err(into_js_runtime_err!(JsRuntimeErrorCode::InvalidPath, "Invalid path {:?}", path.as_path()))?;
        self.eval(source, Some(path.as_path()))
    }

    pub fn eval_file_with_args(&mut self, path: &Path, args: &str) -> JsRuntimeResult<()> {
        if let Some(params) = shlex::split(args) {
            let process_obj = JsObject::default(self.context.intrinsics());
            let params: Vec<_> = params.iter().map(|param| {
                JsValue::from(JsString::from(param.as_str()))
            }).collect();
            let params = JsArray::from_iter(params.into_iter(), &mut self.context);
            process_obj.set(js_string!("argv"), params, false, &mut self.context)
                .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
            self.context.register_global_property(
                js_string!("process"),
                JsValue::from(process_obj),
                Attribute::default(),
            ).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        }
        self.eval_file(path)
    }

    pub fn eval_string(&mut self, code: &str) -> JsRuntimeResult<()> {
        self.eval(code, None)
    }

    pub fn eval_string_with_args(&mut self, code: &str, args: &str) -> JsRuntimeResult<()> {
        if let Some(params) = shlex::split(args) {
            let process_obj = JsObject::default(self.context.intrinsics());
            let params: Vec<_> = params.iter().map(|param| {
                JsValue::from(JsString::from(param.as_str()))
            }).collect();
            let params = JsArray::from_iter(params.into_iter(), &mut self.context);
            process_obj.set(js_string!("argv"), params, false, &mut self.context)
                .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
            self.context.register_global_property(
                js_string!("process"),
                JsValue::from(process_obj),
                Attribute::default(),
            ).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;
        }
        self.eval_string(code)
    }

    fn eval(&mut self, context: impl Into<String>, file_name: Option<&Path>) -> JsRuntimeResult<()> {
        if self.module.is_some() {
            return Err(js_runtime_err!(JsRuntimeErrorCode::JsFailed, "Already loaded a module"));
        }

        let default_name = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf()).join("main.js");
        let file_name = file_name.unwrap_or(default_name.as_path());
        let wrapper_code = module_wrapper(context, file_name);
        let source = Source::from_reader(std::io::Cursor::new(wrapper_code.as_bytes()), Some(file_name));
        let module = Module::parse(source, None, &mut self.context)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;

        let promise_result = module.load_link_evaluate(&mut self.context);

        let _ = promise_result.await_blocking(&mut self.context)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "{e}"))?;

        self.module = Some(module);
        Ok(())
    }

    pub fn call(&mut self, name: &str, args: Vec<JsValue>) -> JsRuntimeResult<JsValue> {
        if self.module.is_none() {
            return Err(js_runtime_err!(JsRuntimeErrorCode::JsFailed, "module didn't execute!"));
        }

        let fun = self.module.as_mut().unwrap().get_value(JsString::from(name), &mut self.context)
            .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "can't find {name} failed: {}", e))?;

        if let Some(fun) = fun.as_callable() {
            let result = fun.call(&JsValue::null(), args.as_slice(), &mut self.context)
                .map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "call {name} failed: {}", e))?;
            if result.is_promise() {
                let result = result.as_promise().unwrap();
                let result = result.await_blocking(&mut self.context).map_err(|e| js_runtime_err!(JsRuntimeErrorCode::JsFailed, "call {name} failed: {}", e))?;
                return Ok(result);
            }
            Ok(result)
        } else {
            Err(js_runtime_err!(JsRuntimeErrorCode::JsFailed, "can't call {name} at {}",
                self.module.as_ref().unwrap().path().unwrap_or(Path::new("")).to_string_lossy().to_string()))
        }
    }

    pub fn get_output(&self) -> String {
        self.log_cache.get_logs().join("\n")
    }
}

fn require(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let arg = args.get_or_undefined(0);
    let dir_name = args.get_or_undefined(2);

    let dir_name = dir_name.to_string(ctx)?.to_std_string_escaped();

    // BUG: Dev branch seems to be passing string arguments along with quotes
    let libfile = arg.to_string(ctx)?.to_std_string_escaped();
    let module_loader = ctx.downcast_module_loader::<JsModuleLoader>().unwrap();
    let libfile = module_loader.commonjs_resolve_module(libfile.as_str(), Path::new(dir_name.as_str()))?;

    if let Some( module) = module_loader.get(libfile.as_path()) {
        let exports = module.get_value(js_string!("default"), ctx)?;
        return Ok(exports)
    }

    let buffer = read_to_string(libfile.clone())
        .map_err(|e| JsNativeError::typ().with_message(e.to_string()))?;


    let wrapper_code = commonjs_wrapper(buffer, libfile.as_path());

    let source = Source::from_reader(wrapper_code.as_bytes(), Some(libfile.as_path()));
    let module = Module::parse(source, None, ctx)?;
    let promise_result = module.load_link_evaluate(ctx);
    module_loader.insert(libfile, module.clone());
    promise_result.await_blocking(ctx)?;

    let exports = module.get_value(js_string!("default"), ctx)?;
    Ok(exports)
}
