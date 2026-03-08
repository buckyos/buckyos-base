use std::{
    env,
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

lazy_static::lazy_static! {
    static ref BUCKYOS_ROOT_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
}

pub fn normalize_path(path_str: &str) -> String {
    let path_str = path_str.replace("\\", "/");
    let mut components = Path::new(&path_str).components().peekable();
    let mut normalized = PathBuf::new();

    while let Some(comp) = components.next() {
        match comp {
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::CurDir => {
                // 忽略当前目录
            }
            Component::Normal(c) => {
                //println!("normal {:?}", c);
                normalized.push(c);
            }
            Component::RootDir => {
                normalized.push(comp);
            }
            Component::Prefix(p) => {
                normalized.push(p.as_os_str()); // Windows 前缀（例如 C:\）
            }
        }
    }

    normalized.to_string_lossy().to_string().replace("\\", "/")
}

pub fn get_buckyos_root_dir() -> PathBuf {
    // 检查缓存
    {
        let cache = BUCKYOS_ROOT_DIR.lock().unwrap();
        if let Some(cached_path) = cache.as_ref() {
            let result = cached_path.clone();
            drop(cache); // 显式释放锁
            return result;
        }
    }

    // 第一次调用，计算路径
    let root_dir = if env::var("BUCKYOS_ROOT").is_ok() {
        Path::new(&env::var("BUCKYOS_ROOT").unwrap()).to_path_buf()
    } else {
        //获得当前可执行文件所在的目录，并向上级目录寻找，直到找到包含applist.json的bin目录
        let mut current_dir = env::current_exe().unwrap().parent().unwrap().to_path_buf();
        while !current_dir.join("applist.json").exists() {
            if let Some(parent) = current_dir.parent() {
                current_dir = parent.to_path_buf();
            } else {
                // 如果到达根目录还没找到，使用默认路径
                break;
            }
        }

        if current_dir.join("applist.json").exists() {
            current_dir.parent().unwrap().to_path_buf()
        } else if cfg!(target_os = "windows") {
            let user_data_dir = env::var("APPDATA")
                .unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()));
            Path::new(&user_data_dir).join("buckyos")
        } else {
            Path::new("/opt/buckyos").to_path_buf()
        }
    };

    // 缓存结果
    {
        let mut cache = BUCKYOS_ROOT_DIR.lock().unwrap();
        *cache = Some(root_dir.clone());
    }

    root_dir
}

pub fn get_buckyos_dev_user_home() -> PathBuf {
    if env::var("BUCKYOS_DEV_HOME").is_ok() {
        return Path::new(&env::var("BUCKYOS_DEV_HOME").unwrap()).to_path_buf();
    }
    let home_dir = env::home_dir().unwrap();
    Path::new(&home_dir).join(".buckycli")
}

pub fn get_buckyos_system_bin_dir() -> PathBuf {
    get_buckyos_root_dir().join("bin")
}

pub fn get_buckyos_system_etc_dir() -> PathBuf {
    get_buckyos_root_dir().join("etc")
}

pub fn get_buckyos_log_dir(service: &str, is_service: bool) -> PathBuf {
    if is_service {
        get_buckyos_root_dir().join("logs").join(service)
    } else {
        // 获取用户临时目录
        if cfg!(target_os = "windows") {
            let temp_dir = env::var("TEMP")
                .or_else(|_| env::var("TMP"))
                .unwrap_or_else(|_| {
                    // 如果环境变量不存在，使用用户目录下的临时文件夹
                    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
                    format!("{}\\AppData\\Local\\Temp", user_profile)
                });
            Path::new(&temp_dir).join("buckyos").join("logs")
        } else {
            Path::new("/tmp").join("buckyos").join("logs")
        }
    }
}

// $buckyos_service_data => cyfs://$zone_id/var/$service_name/ => $buckyos_root/data/var/$service_name
pub fn get_buckyos_service_data_dir(service_name: &str) -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("var")
        .join(service_name)
}

// $buckyos_service_cache => cyfs://$zone_id/cache/$service_name/ => $buckyos_root/data/cache/$service_name
pub fn get_buckyos_service_cache_dir(service_name: &str) -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("cache")
        .join(service_name)
}

// $buckyos_service_home => cyfs://$zone_id/srv/$service_name/ => $buckyos_root/data/srv/$service_name
pub fn get_buckyos_service_home_dir(service_name: &str) -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("srv")
        .join(service_name)
}

// $buckyos_service_local_data => /opt/buckyos/local/$service_name (discouraged)
pub fn get_buckyos_service_local_data_dir(service_name: &str) -> PathBuf {
    get_buckyos_root_dir().join("local").join(service_name)
}

// $buckyos_service_local_cache => /tmp/buckyos/$service_name (discouraged)
pub fn get_buckyos_service_local_cache_dir(service_name: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        let temp_dir = env::var("TEMP")
            .or_else(|_| env::var("TMP"))
            .unwrap_or_else(|_| {
                let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
                format!("{}\\AppData\\Local\\Temp", user_profile)
            });
        Path::new(&temp_dir).join("buckyos").join(service_name)
    } else {
        Path::new("/tmp").join("buckyos").join(service_name)
    }
}

// cyfs://$zone_id/home/$username => $buckyos_root/data/home/$username
pub fn get_buckyos_user_home_dir(user_id: &str) -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("home")
        .join(user_id)
}

// cyfs://$zone_id/home/$username/shared/ => $buckyos_root/data/home/$username/shared
pub fn get_buckyos_user_shared_dir(user_id: &str) -> PathBuf {
    get_buckyos_user_home_dir(user_id).join("shared")
}

// /home/$username/.local/share/$appid => $buckyos_root/data/home/$owner/.local/share/$appid
pub fn get_buckyos_app_data_dir(app_name: &str, owner_id: &str) -> PathBuf {
    get_buckyos_user_home_dir(owner_id)
        .join(".local")
        .join("share")
        .join(app_name)
}

// /tmp/buckyos/$appid
pub fn get_buckyos_app_tmp_dir(app_id: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        let temp_dir = env::var("TEMP")
            .or_else(|_| env::var("TMP"))
            .unwrap_or_else(|_| {
                let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
                format!("{}\\AppData\\Local\\Temp", user_profile)
            });
        Path::new(&temp_dir).join("buckyos").join(app_id)
    } else {
        Path::new("/tmp").join("buckyos").join(app_id)
    }
}

// $buckyos_root/storage - kernel infrastructure persistent storage
pub fn get_buckyos_storage_dir() -> PathBuf {
    get_buckyos_root_dir().join("storage")
}

// cyfs://$zone_id/srv/publish/ => $buckyos_root/data/srv/publish
pub fn get_buckyos_publish_dir() -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("srv")
        .join("publish")
}

pub enum LibraryCategory {
    Public,
    Shared,
    Photo,
    Picture,
    Music,
    Video,
    ROMS,
    ISO,
    Book,
    Softwares,
}

impl LibraryCategory {
    pub fn as_str(&self) -> &str {
        match self {
            LibraryCategory::Public => "public",
            LibraryCategory::Shared => "shared",
            LibraryCategory::Photo => "photo",
            LibraryCategory::Picture => "picture",
            LibraryCategory::Music => "music",
            LibraryCategory::Video => "video",
            LibraryCategory::ROMS => "roms",
            LibraryCategory::ISO => "iso",
            LibraryCategory::Book => "book",
            LibraryCategory::Softwares => "softwares",
        }
    }
}

// cyfs://$zone_id/srv/library/ => $buckyos_root/data/srv/library
pub fn get_buckyos_library_dir(category: LibraryCategory) -> PathBuf {
    get_buckyos_root_dir()
        .join("data")
        .join("srv")
        .join("library")
        .join(category.as_str())
}

pub fn adjust_path(old_path: &str) -> std::io::Result<PathBuf> {
    let new_path = old_path.replace("{BUCKYOS_ROOT}", &get_buckyos_root_dir().to_string_lossy());
    let normalized_path = normalize_path(&new_path);
    Ok(std::path::Path::new(&normalized_path).to_path_buf())
}

pub fn get_buckyos_named_data_dir(mgr_id: &str) -> PathBuf {
    if mgr_id == "default" {
        get_buckyos_root_dir().join("data").join("ndn")
    } else {
        get_buckyos_root_dir().join("data").join("ndn").join(mgr_id)
    }
}

pub fn get_relative_path(base_path: &str, full_path: &str) -> String {
    if full_path.starts_with(base_path) {
        if base_path.ends_with('/') {
            full_path[base_path.len() - 1..].to_string()
        } else {
            full_path[base_path.len()..].to_string()
        }
    } else {
        full_path.to_string()
    }
}

pub fn path_join(base: &str, sub_path: &str) -> PathBuf {
    PathBuf::from(base).join(sub_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_relative_path() {
        let base_path = "/opt/buckyos/data/chunk";
        let full_path = "/opt/buckyos/data/chunk/1234567890";
        let relative_path = get_relative_path(base_path, full_path);
        assert_eq!(relative_path, "/1234567890");

        let base_path = "/opt/buckyos/data/chunk/";
        let full_path = "/opt/buckyos/data/chunk/1234567890/asdf?a=1&b=2";
        let relative_path = get_relative_path(base_path, full_path);
        assert_eq!(relative_path, "/1234567890/asdf?a=1&b=2");

        let home_dir = get_buckyos_dev_user_home();
        println!("home dir: {}", home_dir.display());
    }
    #[test]
    fn test_normalize_path() {
        let path = "C:\\Users\\buckyos\\AppData\\Local\\Temp\\buckyos\\logs\\buckyos.log";
        let normalized = normalize_path(path);
        assert_eq!(
            normalized.as_str(),
            "C:/Users/buckyos/AppData/Local/Temp/buckyos/logs/buckyos.log"
        );

        let path = "C:\\Users\\buckyos\\AppData\\Local\\Temp\\buckyos\\.\\logs\\buckyos.log";
        let normalized = normalize_path(path);
        assert_eq!(
            normalized.as_str(),
            "C:/Users/buckyos/AppData/Local/Temp/buckyos/logs/buckyos.log"
        );

        let path = "C:\\Users\\buckyos\\AppData\\Local\\Temp\\buckyos\\..\\logs\\buckyos.log";
        let normalized = normalize_path(path);
        assert_eq!(
            normalized.as_str(),
            "C:/Users/buckyos/AppData/Local/Temp/logs/buckyos.log"
        );

        let path = "C:\\Users\\buckyos\\AppData\\Local\\Temp\\buckyos\\..\\logs\\buckyos.log";
        let normalized = normalize_path(path);
        assert_eq!(
            normalized.as_str(),
            "C:/Users/buckyos/AppData/Local/Temp/logs/buckyos.log"
        );

        let path = "/opt/buckyos/data/chunk/../1234567890";
        let normalized = normalize_path(path);
        assert_eq!(normalized.as_str(), "/opt/buckyos/data/1234567890");
    }

    #[test]
    fn test_normalize_path_table_cases() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expected: &'static str,
        }

        let cases = vec![
            Case {
                name: "current_dir",
                input: "./a/./b",
                expected: "a/b",
            },
            Case {
                name: "parent_overflow",
                input: "../../a",
                expected: "a",
            },
            Case {
                name: "double_slash",
                input: "//tmp//buckyos//logs",
                expected: "/tmp/buckyos/logs",
            },
            Case {
                name: "mixed_separators",
                input: "a\\b/c",
                expected: "a/b/c",
            },
            Case {
                name: "trailing_parent",
                input: "/opt/buckyos/data/../",
                expected: "/opt/buckyos",
            },
        ];

        for case in cases {
            let result = normalize_path(case.input);
            assert_eq!(result, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_get_relative_path_table_cases() {
        struct Case {
            name: &'static str,
            base: &'static str,
            full: &'static str,
            expected: &'static str,
        }

        let cases = vec![
            Case {
                name: "matching_without_trailing",
                base: "/opt/buckyos/data",
                full: "/opt/buckyos/data/file.txt",
                expected: "/file.txt",
            },
            Case {
                name: "matching_with_trailing",
                base: "/opt/buckyos/data/",
                full: "/opt/buckyos/data/file.txt",
                expected: "/file.txt",
            },
            Case {
                name: "non_matching",
                base: "/opt/buckyos/data",
                full: "/var/tmp/file.txt",
                expected: "/var/tmp/file.txt",
            },
            Case {
                name: "base_equals_full",
                base: "/opt/buckyos/data",
                full: "/opt/buckyos/data",
                expected: "",
            },
        ];

        for case in cases {
            let result = get_relative_path(case.base, case.full);
            assert_eq!(result, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_path_join_table_cases() {
        let cases = vec![
            ("basic", "/opt/buckyos", "logs", "/opt/buckyos/logs"),
            ("absolute_sub", "/opt/buckyos", "/tmp/data", "/tmp/data"),
            ("empty_sub", "/opt/buckyos", "", "/opt/buckyos/"),
        ];

        for (name, base, sub, expected) in cases {
            let joined = path_join(base, sub);
            assert_eq!(joined.to_string_lossy(), expected, "case: {}", name);
        }
    }

    #[test]
    fn test_library_category_as_str_table() {
        let cases = vec![
            (LibraryCategory::Public, "public"),
            (LibraryCategory::Shared, "shared"),
            (LibraryCategory::Photo, "photo"),
            (LibraryCategory::Picture, "picture"),
            (LibraryCategory::Music, "music"),
            (LibraryCategory::Video, "video"),
            (LibraryCategory::ROMS, "roms"),
            (LibraryCategory::ISO, "iso"),
            (LibraryCategory::Book, "book"),
            (LibraryCategory::Softwares, "softwares"),
        ];

        for (category, expected) in cases {
            assert_eq!(category.as_str(), expected);
        }
    }
}
