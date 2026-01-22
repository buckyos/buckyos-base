use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KVAction {
    Create(String),                                //创建一个节点并设置值
    Update(String),                                //完整更新
    Append(String),                                //追加
    SetByJsonPath(HashMap<String, Option<Value>>), //当成json设置其中的一个值,针对一个对象,set可以是一个数组
    Remove,                                        //删除
                                                   //Create(String),
}

pub fn apply_params_to_json(
    input_json: &Value,
    ext_params: Option<&HashMap<String, String>>,
) -> Result<Value, String> {
    let mut real_params = HashMap::new();

    // 先添加内部参数
    let inneer_params = input_json.get("params");
    if inneer_params.is_some() {
        let result = serde_json::from_value(inneer_params.unwrap().clone());
        if result.is_err() {
            return Err(format!(
                "Failed to parse inner params: {}",
                result.err().unwrap()
            ));
        }
        let inner_params: HashMap<String, String> = result.unwrap();
        real_params.extend(inner_params.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    // 再添加外部参数，外部参数会覆盖内部参数
    if ext_params.is_some() {
        real_params.extend(
            ext_params
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }

    if real_params.is_empty() {
        return Ok(input_json.clone());
    }

    //展开json成string
    let json_str = serde_json::to_string(input_json)
        .map_err(|e| format!("Failed to serialize JSON: {}", e))?;

    //对string中的{{param}} 进行替换
    let mut result_str = json_str;
    for (key, value) in real_params.iter() {
        let pattern = format!("{{{{{}}}}}", key);
        result_str = result_str.replace(&pattern, value);
    }

    //判断是否有未替换的{{}}
    if result_str.contains("{{") && result_str.contains("}}") {
        // 找出所有未替换的参数
        let mut unreplaced = Vec::new();
        let mut start = 0;
        while let Some(open_pos) = result_str[start..].find("{{") {
            let abs_open_pos = start + open_pos;
            if let Some(close_pos) = result_str[abs_open_pos..].find("}}") {
                let param = &result_str[abs_open_pos + 2..abs_open_pos + close_pos];
                unreplaced.push(param.to_string());
                start = abs_open_pos + close_pos + 2;
            } else {
                break;
            }
        }
        if !unreplaced.is_empty() {
            return Err(format!(
                "Found unreplaced template parameters: {:?}",
                unreplaced
            ));
        }
    }

    //再次转换成json
    let result_json = serde_json::from_str(&result_str)
        .map_err(|e| format!("Failed to parse JSON after parameter replacement: {}", e))?;

    Ok(result_json)
}

pub fn split_json_path(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in path.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => in_quotes = !in_quotes,
            '/' if !in_quotes && !escaped => {
                if !current.is_empty() {
                    parts.push(current.trim().to_string());
                    current = String::new();
                }
            }
            _ => {
                if escaped && c != '"' && c != '\\' {
                    current.push('\\');
                }
                current.push(c);
                escaped = false;
            }
        }
    }

    if !current.is_empty() {
        parts.push(current.trim().to_string());
    }

    parts.into_iter().filter(|s| !s.is_empty()).collect()
}

// pub fn set_json_by_path(data: &mut Value, path: &str, value: Option<&Value>) {
//     if value.is_some() {
//         let _ = data.merge_in(path, &value.unwrap());
//     } else {
//         let _ = data.merge_in(path, &json!(null));
//     }
// }

pub fn set_json_by_path(data: &mut Value, path: &str, value: Option<&Value>) {
    // 使用新的路径解析方法
    let parts = split_json_path(path);

    // 如果路径为空，直接替换或删除整个 Value
    if parts.is_empty() {
        match value {
            Some(v) => *data = v.clone(),
            None => *data = json!(null),
        }
        return;
    }

    // 从根开始遍历和构建路径
    let mut current = data;
    for (i, part) in parts.iter().enumerate() {
        // 最后一个部分：设置或删除值
        if i == parts.len() - 1 {
            if let Value::Object(map) = current {
                match value {
                    Some(v) => {
                        map.insert(part.to_string(), v.clone());
                    }
                    None => {
                        map.remove(part);
                    }
                }
            }
            break;
        }

        // 确保中间路径存在
        current = current
            .as_object_mut()
            .unwrap_or_else(|| panic!("Cannot create path"))
            .entry(part)
            .or_insert_with(|| json!({}));
    }
}

pub fn get_by_json_path(data: &Value, path: &str) -> Option<Value> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let mut current = data;
    for part in parts {
        current = if let Ok(index) = part.parse::<usize>() {
            // 如果 part 可以解析为数字，则作为数组索引处理
            current.get(index).unwrap_or(&json!(null))
        } else {
            // 否则作为对象键处理
            current.get(part).unwrap_or(&json!(null))
        };
    }

    if current.is_null() {
        None
    } else {
        Some(current.clone())
    }
}

pub fn extend_kv_action_map(
    dest_map: &mut HashMap<String, KVAction>,
    from_map: &HashMap<String, KVAction>,
) {
    for (key, value) in from_map.iter() {
        let old_value = dest_map.get_mut(key);
        match old_value {
            Some(old_value) => match value {
                KVAction::Create(new_value) => {
                    *old_value = KVAction::Create(new_value.clone());
                }
                KVAction::Update(new_value) => {
                    *old_value = KVAction::Update(new_value.clone());
                }
                KVAction::Append(new_value) => {
                    *old_value = KVAction::Append(new_value.clone());
                }
                KVAction::SetByJsonPath(new_value) => match old_value {
                    KVAction::SetByJsonPath(old_value) => {
                        old_value.extend(new_value.clone());
                    }
                    _ => {
                        *old_value = KVAction::SetByJsonPath(new_value.clone());
                    }
                },
                KVAction::Remove => {
                    *old_value = KVAction::Remove;
                }
            },
            None => {
                dest_map.insert(key.clone(), value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_params_to_json_error_cases_table() {
        struct Case {
            name: &'static str,
            input: Value,
            ext_params: Option<HashMap<String, String>>,
            expected_unreplaced: Option<&'static str>,
        }

        let cases = vec![
            Case {
                name: "inner_params_wrong_type",
                input: json!({
                    "params": "not-a-map",
                    "value": "{{x}}"
                }),
                ext_params: None,
                expected_unreplaced: None,
            },
            Case {
                name: "unreplaced_single",
                input: json!({
                    "name": "{{user}}",
                    "age": "{{age}}"
                }),
                ext_params: Some(HashMap::from([("user".to_string(), "alice".to_string())])),
                expected_unreplaced: Some("age"),
            },
            Case {
                name: "unreplaced_with_unicode_keys",
                input: json!({
                    "greet": "{{name}}-{{city}}"
                }),
                ext_params: Some(HashMap::from([("name".to_string(), "张三".to_string())])),
                expected_unreplaced: Some("city"),
            },
            Case {
                name: "unmatched_braces",
                input: json!({
                    "value": "{{name"
                }),
                ext_params: Some(HashMap::from([("name".to_string(), "alice".to_string())])),
                expected_unreplaced: None,
            },
            Case {
                name: "ext_params_only_no_placeholders",
                input: json!({
                    "value": "plain"
                }),
                ext_params: Some(HashMap::from([("name".to_string(), "alice".to_string())])),
                expected_unreplaced: None,
            },
        ];

        for case in cases {
            let result = apply_params_to_json(&case.input, case.ext_params.as_ref());
            match case.name {
                "inner_params_wrong_type" => {
                    assert!(result.is_err(), "case: {}", case.name);
                }
                _ => {
                    if let Some(expected) = case.expected_unreplaced {
                        let err = result.unwrap_err();
                        assert!(err.contains(expected), "case: {}", case.name);
                    } else {
                        assert!(result.is_ok(), "case: {}", case.name);
                    }
                }
            }
        }
    }

    #[test]
    fn test_split_json_path_table() {
        struct Case {
            name: &'static str,
            input: &'static str,
            expected: Vec<&'static str>,
        }

        let cases = vec![
            Case {
                name: "empty",
                input: "",
                expected: vec![],
            },
            Case {
                name: "root_only",
                input: "/",
                expected: vec![],
            },
            Case {
                name: "simple",
                input: "/a/b/c",
                expected: vec!["a", "b", "c"],
            },
            Case {
                name: "quoted_with_slash",
                input: r#"/state/"space add"/value"#,
                expected: vec!["state", "space add", "value"],
            },
            Case {
                name: "escaped_space",
                input: r#"/path/with\ space/value"#,
                expected: vec!["path", r#"with\ space"#, "value"],
            },
            Case {
                name: "unicode_and_emoji",
                input: "/用户/😀/数据",
                expected: vec!["用户", "😀", "数据"],
            },
            Case {
                name: "multiple_separators",
                input: "//a///b/",
                expected: vec!["a", "b"],
            },
        ];

        for case in cases {
            let result = split_json_path(case.input);
            let expected: Vec<String> = case.expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(result, expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_set_json_by_path_table() {
        struct Case {
            name: &'static str,
            initial: Value,
            path: &'static str,
            value: Option<Value>,
            expected: Value,
        }

        let cases = vec![
            Case {
                name: "set_root",
                initial: json!({"a": 1}),
                path: "",
                value: Some(json!({"b": 2})),
                expected: json!({"b": 2}),
            },
            Case {
                name: "delete_root",
                initial: json!({"a": 1}),
                path: "",
                value: None,
                expected: json!(null),
            },
            Case {
                name: "set_nested_create",
                initial: json!({}),
                path: "/user/name",
                value: Some(json!("Alice")),
                expected: json!({"user": {"name": "Alice"}}),
            },
            Case {
                name: "delete_nested",
                initial: json!({"user": {"name": "Alice", "age": 30}}),
                path: "/user/age",
                value: None,
                expected: json!({"user": {"name": "Alice"}}),
            },
            Case {
                name: "quoted_key_with_space",
                initial: json!({}),
                path: r#"/state/"space add"/value"#,
                value: Some(json!("test")),
                expected: json!({"state": {"space add": {"value": "test"}}}),
            },
        ];

        for case in cases {
            let mut data = case.initial.clone();
            let value_ref = case.value.as_ref();
            set_json_by_path(&mut data, case.path, value_ref);
            assert_eq!(data, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_set_json_by_path_panics_on_non_object_parent() {
        let mut data = json!("not-object");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set_json_by_path(&mut data, "/a/b", Some(&json!(1)));
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_by_json_path_table() {
        struct Case {
            name: &'static str,
            path: &'static str,
            expected: Option<Value>,
        }

        let data = json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "friends": [
                    {"name": "Bob", "age": 25},
                    {"name": "Charlie", "age": 28}
                ]
            }
        });

        let cases = vec![
            Case {
                name: "object_key",
                path: "/user/name",
                expected: Some(json!("Alice")),
            },
            Case {
                name: "array_index",
                path: "/user/friends/1/name",
                expected: Some(json!("Charlie")),
            },
            Case {
                name: "missing_key",
                path: "/user/address",
                expected: None,
            },
            Case {
                name: "out_of_range_index",
                path: "/user/friends/5",
                expected: None,
            },
            Case {
                name: "path_without_leading_slash",
                path: "user/age",
                expected: Some(json!(30)),
            },
            Case {
                name: "empty_path_returns_input",
                path: "",
                expected: None,
            },
        ];

        for case in cases {
            let result = get_by_json_path(&data, case.path);
            assert_eq!(result, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn test_extend_kv_action_map_table() {
        let mut dest: HashMap<String, KVAction> = HashMap::new();
        dest.insert("a".to_string(), KVAction::Create("v1".to_string()));
        dest.insert(
            "set".to_string(),
            KVAction::SetByJsonPath(HashMap::from([(String::from("k1"), Some(json!(1)))])),
        );

        let mut from: HashMap<String, KVAction> = HashMap::new();
        from.insert("a".to_string(), KVAction::Update("v2".to_string()));
        from.insert("b".to_string(), KVAction::Append("v3".to_string()));
        from.insert(
            "set".to_string(),
            KVAction::SetByJsonPath(HashMap::from([(String::from("k2"), Some(json!("v")))])),
        );
        from.insert("remove".to_string(), KVAction::Remove);

        extend_kv_action_map(&mut dest, &from);

        match dest.get("a").unwrap() {
            KVAction::Update(v) => assert_eq!(v, "v2"),
            _ => panic!("expected update"),
        }
        match dest.get("b").unwrap() {
            KVAction::Append(v) => assert_eq!(v, "v3"),
            _ => panic!("expected append"),
        }
        match dest.get("set").unwrap() {
            KVAction::SetByJsonPath(map) => {
                assert_eq!(map.get("k1").unwrap().as_ref().unwrap(), &json!(1));
                assert_eq!(map.get("k2").unwrap().as_ref().unwrap(), &json!("v"));
            }
            _ => panic!("expected set"),
        }
        assert!(matches!(dest.get("remove").unwrap(), KVAction::Remove));
    }
    #[test]
    fn test_hash_map_option_value() {
        let mut test_map: HashMap<String, Option<Value>> = HashMap::new();

        test_map.insert("state".to_string(), None);
        test_map.insert("abc".to_string(), Some(json!("123")));
        let test_value = serde_json::to_value(test_map).unwrap();
        let test_str = serde_json::to_string(&test_value).unwrap();
        let test_value2: HashMap<String, Option<Value>> = serde_json::from_str(&test_str).unwrap();
        for (key, value) in test_value2.iter() {
            println!("key:{},value:{:?}", key, value);
        }
    }

    #[test]
    fn test_set_json_by_path() {
        let mut data = json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "address": {
                    "city": "New York"
                }
            }
        });

        let data2 = json!({
            "user": {
                "age": 30,
                "name": "Alice",
                "address": {
                    "city": "New York"
                }
            }
        });

        assert_eq!(data, data2);
        let json_path = format!(
            "servers/main_http_server/hosts/*/routes/\"/kapi/{}\"",
            "ood1"
        );
        set_json_by_path(
            &mut data,
            json_path.as_str(),
            Some(&json!({
                "upstream":format!("http://127.0.0.1:{}",3200),
            })),
        );

        // 设置值
        set_json_by_path(&mut data, "state", Some(&json!("Normal")));
        println!("{}", data);
        // 设置值
        set_json_by_path(&mut data, "/user/name", Some(&json!("Bob")));
        println!("{}", data);
        // 删除字段
        set_json_by_path(&mut data, "/user/age", None);
        println!("{}", data);
        // 删除嵌套字段
        set_json_by_path(&mut data, "/user/address/city", None);
        println!("{}", data);
        // 完全删除 address 对象
        set_json_by_path(&mut data, "/user/address", None);
        println!("{}", data);
        set_json_by_path(&mut data, "/user/address", None);
        println!("{}", data);
    }

    #[test]
    fn test_get_by_json_path() {
        let data = json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "address": {
                    "city": "New York"
                },
                "friends": [
                    {
                        "name": "Bob",
                        "age": 25
                    },
                    {
                        "name": "Charlie",
                        "age": 28
                    }
                ]
            }
        });

        let name = get_by_json_path(&data, "/user/friends/0/name").unwrap();
        assert_eq!(name.as_str().unwrap(), "Bob");
    }

    #[test]
    fn test_split_json_path() {
        assert_eq!(
            split_json_path(r#"/state/"space add"/value"#),
            vec!["state", "space add", "value"]
        );
        assert_eq!(
            split_json_path(r#"/path/with\ space/value"#),
            vec!["path", r#"with\ space"#, "value"]
        );
    }

    #[test]
    fn test_set_json_by_path_with_spaces() {
        let mut data = json!({});
        set_json_by_path(
            &mut data,
            r#"/state/"space add"/value"#,
            Some(&json!("test")),
        );
        assert_eq!(
            data,
            json!({
                "state": {
                    "space add": {
                        "value": "test"
                    }
                }
            })
        );
    }

    #[test]
    fn test_apply_params_to_json() {
        // Test 1: 使用外部参数替换
        let input = json!({
            "name": "{{user_name}}",
            "age": "{{user_age}}",
            "city": "{{city}}"
        });
        let mut ext_params = HashMap::new();
        ext_params.insert("user_name".to_string(), "Alice".to_string());
        ext_params.insert("user_age".to_string(), "30".to_string());
        ext_params.insert("city".to_string(), "New York".to_string());

        let result = apply_params_to_json(&input, Some(&ext_params)).unwrap();
        assert_eq!(result.get("name").unwrap().as_str().unwrap(), "Alice");
        assert_eq!(result.get("age").unwrap().as_str().unwrap(), "30");
        assert_eq!(result.get("city").unwrap().as_str().unwrap(), "New York");

        // Test 2: 使用内部参数替换
        let input_with_inner = json!({
            "params": {
                "service_name": "api-server",
                "port": "8080"
            },
            "config": {
                "name": "{{service_name}}",
                "endpoint": "http://localhost:{{port}}"
            }
        });

        let result = apply_params_to_json(&input_with_inner, None).unwrap();
        assert_eq!(
            result
                .get("config")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str()
                .unwrap(),
            "api-server"
        );
        assert_eq!(
            result
                .get("config")
                .unwrap()
                .get("endpoint")
                .unwrap()
                .as_str()
                .unwrap(),
            "http://localhost:8080"
        );

        // Test 3: 外部参数覆盖内部参数
        let input = json!({
            "params": {
                "env": "dev"
            },
            "environment": "{{env}}"
        });
        let mut ext_params = HashMap::new();
        ext_params.insert("env".to_string(), "production".to_string());

        let result = apply_params_to_json(&input, Some(&ext_params)).unwrap();
        assert_eq!(
            result.get("environment").unwrap().as_str().unwrap(),
            "production"
        );

        // Test 4: 没有参数的情况，直接返回原JSON
        let input = json!({
            "name": "Bob",
            "age": 25
        });

        let result = apply_params_to_json(&input, None).unwrap();
        assert_eq!(result, input);

        // Test 5: 存在未替换的参数应该返回错误
        let input = json!({
            "name": "{{user_name}}",
            "age": "{{user_age}}"
        });
        let mut ext_params = HashMap::new();
        ext_params.insert("user_name".to_string(), "Charlie".to_string());

        let result = apply_params_to_json(&input, Some(&ext_params));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("user_age"));

        // Test 6: 嵌套对象中的参数替换
        let input = json!({
            "params": {
                "db_host": "localhost",
                "db_port": "5432",
                "db_name": "mydb"
            },
            "database": {
                "connection": {
                    "host": "{{db_host}}",
                    "port": "{{db_port}}",
                    "database": "{{db_name}}"
                }
            }
        });

        let result = apply_params_to_json(&input, None).unwrap();
        let connection = result.get("database").unwrap().get("connection").unwrap();
        assert_eq!(
            connection.get("host").unwrap().as_str().unwrap(),
            "localhost"
        );
        assert_eq!(connection.get("port").unwrap().as_str().unwrap(), "5432");
        assert_eq!(
            connection.get("database").unwrap().as_str().unwrap(),
            "mydb"
        );
    }
}
