use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use name_client::{CacheBackend, DIDObjectClient, NameClient, NameClientConfig, SmartProvider};
use name_lib::{DIDObjectCard, DID};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{
    DIDObjectActionRequest, DIDObjectActionSuccess, DIDObjectError, DIDObjectHttpServer,
    DIDObjectRequestContext, DIDObjectServer, DIDObjectServerResult, HttpServer, Runner,
    ServerError, StreamInfo,
};

struct CameraObjectServer {
    card: DIDObjectCard,
    profile: Value,
}

impl CameraObjectServer {
    fn new() -> Self {
        Self::new_with_object(
            DID::new("web", "myhome.com:devices:cam01"),
            "https://myhome.com/devices/cam01",
        )
    }

    fn new_with_object(did: DID, object_url: impl Into<String>) -> Self {
        let object_url = object_url.into();
        let card = DIDObjectCard::new(
            did,
            object_url.clone(),
            Some(DID::new("web", "myhome.com")),
            format!("{object_url}/profile.json"),
            Some("web.camera"),
        );

        let profile = json!({
            "@context": [
                "https://www.w3.org/2022/wot/td/v1.1",
                "https://buckyos.org/ns/did-object/v1"
            ],
            "id": "https://myhome.com/devices/cam01/profile.json",
            "title": "Example Camera",
            "version": {
                "instance": "1.0.0"
            },
            "x-buckyos:traits": [
                "https://buckyos.org/traits/media-source@1"
            ],
            "properties": {
                "brand": {
                    "type": "string",
                    "readOnly": true,
                    "forms": [
                        {
                            "href": "props/brand",
                            "op": "readproperty",
                            "contentType": "application/json"
                        }
                    ]
                },
                "battery": {
                    "type": "integer",
                    "unit": "percent",
                    "readOnly": true,
                    "observable": true,
                    "forms": [
                        {
                            "href": "props/battery",
                            "op": "readproperty",
                            "contentType": "application/json"
                        }
                    ]
                }
            },
            "actions": {
                "query_clip": {
                    "input": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["clip", "live"]
                            }
                        },
                        "required": ["mode"]
                    },
                    "output": {
                        "$ref": "https://buckyos.org/schemas/media-resource-descriptor@1"
                    },
                    "forms": [
                        {
                            "href": "methods/query_clip",
                            "op": "invokeaction",
                            "contentType": "application/json"
                        }
                    ],
                    "x-buckyos:action": {
                        "effect": "read",
                        "idempotency": "recommended"
                    }
                }
            },
            "events": {
                "low_battery": {
                    "data": {
                        "type": "object",
                        "properties": {
                            "battery": {
                                "type": "integer"
                            }
                        }
                    },
                    "forms": [
                        {
                            "href": "events",
                            "op": "subscribeevent",
                            "contentType": "application/json"
                        }
                    ]
                }
            }
        });

        Self { card, profile }
    }
}

#[async_trait]
impl DIDObjectServer for CameraObjectServer {
    fn object_card(&self) -> &DIDObjectCard {
        &self.card
    }

    fn object_profile(&self) -> &Value {
        &self.profile
    }

    async fn read_property(
        &self,
        name: &str,
        _ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value> {
        match name {
            "brand" => Ok(json!("AcmeCam")),
            "battery" => Ok(json!({
                "value": 87,
                "unit": "percent",
                "version": "battery-v42"
            })),
            _ => Err(DIDObjectError::not_found(format!(
                "unknown property '{name}'"
            ))),
        }
    }

    async fn invoke_action(
        &self,
        request: DIDObjectActionRequest,
        _ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<DIDObjectActionSuccess> {
        match request.method.as_str() {
            "query_clip" => {
                let mode = request
                    .params
                    .get("mode")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DIDObjectError::bad_request("missing query_clip mode"))?;

                Ok(DIDObjectActionSuccess::with_meta(
                    json!({
                        "media_type": "video",
                        "transport": "http-media",
                        "href": format!("https://myhome.com/devices/cam01/clips/{mode}.mp4"),
                        "content_type": "video/mp4",
                        "realtime": mode == "live",
                        "seekable": mode != "live"
                    }),
                    json!({
                        "status": "ok",
                        "affected_objects": [
                            "https://myhome.com/devices/cam01"
                        ],
                        "refresh_hints": [
                            "https://myhome.com/devices/cam01"
                        ]
                    }),
                ))
            }
            _ => Err(DIDObjectError::not_found(format!(
                "unknown action '{}'",
                request.method
            ))),
        }
    }
}

struct CameraFleetObjectServer {
    fallback: CameraObjectServer,
}

impl CameraFleetObjectServer {
    fn new() -> Self {
        Self {
            fallback: CameraObjectServer::new(),
        }
    }

    fn camera_id(ctx: &DIDObjectRequestContext) -> DIDObjectServerResult<&str> {
        ctx.object_params
            .get("camera_id")
            .map(String::as_str)
            .ok_or_else(|| DIDObjectError::bad_request("missing camera_id in ObjURL"))
    }
}

#[async_trait]
impl DIDObjectServer for CameraFleetObjectServer {
    fn object_card(&self) -> &DIDObjectCard {
        self.fallback.object_card()
    }

    fn object_profile(&self) -> &Value {
        self.fallback.object_profile()
    }

    async fn object_card_for(
        &self,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<DIDObjectCard> {
        let camera_id = Self::camera_id(&ctx)?;
        Ok(DIDObjectCard::new(
            DID::new("web", &format!("myhome.com:devices:{camera_id}")),
            ctx.object_url.clone(),
            Some(DID::new("web", "myhome.com")),
            format!("{}/profile.json", ctx.object_url.trim_end_matches('/')),
            Some("web.camera"),
        ))
    }

    async fn object_profile_for(
        &self,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value> {
        let camera_id = Self::camera_id(&ctx)?;
        let mut profile = self.fallback.object_profile().clone();
        profile["id"] = json!(format!("{}/profile.json", ctx.object_url));
        profile["title"] = json!(format!("Example Camera {camera_id}"));
        Ok(profile)
    }

    async fn read_property(
        &self,
        name: &str,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value> {
        let camera_id = Self::camera_id(&ctx)?;
        match name {
            "brand" => Ok(json!(format!("AcmeCam/{camera_id}"))),
            "battery" => Ok(json!({
                "camera": camera_id,
                "value": 87,
                "unit": "percent",
                "object_url": ctx.object_url
            })),
            _ => Err(DIDObjectError::not_found(format!(
                "unknown property '{name}'"
            ))),
        }
    }

    async fn invoke_action(
        &self,
        request: DIDObjectActionRequest,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<DIDObjectActionSuccess> {
        let camera_id = Self::camera_id(&ctx)?;
        match request.method.as_str() {
            "query_clip" => Ok(DIDObjectActionSuccess::new(json!({
                "camera": camera_id,
                "object_url": ctx.object_url,
                "mode": request.params.get("mode").and_then(Value::as_str)
            }))),
            _ => Err(DIDObjectError::not_found(format!(
                "unknown action '{}'",
                request.method
            ))),
        }
    }
}

fn full_body(body: impl Into<Bytes>) -> http_body_util::combinators::BoxBody<Bytes, ServerError> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

fn example_http_server() -> Arc<DIDObjectHttpServer<CameraObjectServer>> {
    example_http_server_with_object(
        DID::new("web", "myhome.com:devices:cam01"),
        "https://myhome.com/devices/cam01",
    )
}

fn example_http_server_with_object(
    did: DID,
    object_url: impl Into<String>,
) -> Arc<DIDObjectHttpServer<CameraObjectServer>> {
    Arc::new(DIDObjectHttpServer::new(
        "camera-object",
        Arc::new(CameraObjectServer::new_with_object(did, object_url)),
    ))
}

async fn example_name_client() -> NameClient {
    let client = NameClient::new(NameClientConfig {
        enable_cache: false,
        cache_backend: CacheBackend::Memory,
        ..Default::default()
    });
    client
        .add_provider(Box::new(SmartProvider::new_with_scheme("http")), Some(0))
        .await;
    client
}

async fn read_json_response<T: serde::de::DeserializeOwned>(
    response: http::Response<http_body_util::combinators::BoxBody<Bytes, ServerError>>,
) -> T {
    serde_json::from_slice(&response.collect().await.unwrap().to_bytes()).unwrap()
}

fn random_loopback() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_for_tcp(addr: SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start listening on {addr}");
}

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        addr.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

fn http_json_body<T: serde::de::DeserializeOwned>(response: &str) -> T {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn serves_did_object_card_and_profile() {
    let addr = random_loopback();
    let did = DID::new("web", &format!("127.0.0.1%3A{}:devices:cam01", addr.port()));
    let object_url = format!("http://127.0.0.1:{}/devices/cam01", addr.port());
    let server = example_http_server_with_object(did.clone(), object_url.clone());
    let runner = Runner::with_addr(addr);
    runner
        .add_http_server("/".to_string(), server.clone())
        .unwrap();
    let runner_task = tokio::spawn(async move { runner.run().await });
    wait_for_tcp(addr).await;

    let name_client = example_name_client().await;

    let resolved = name_client.resolve_did(&did, None).await.unwrap();
    let card = DIDObjectCard::from_value(resolved.to_json_value().unwrap()).unwrap();
    assert_eq!(card.id, did);
    assert_eq!(card.service_endpoint().unwrap(), object_url);

    let profile_response = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/devices/cam01/profile.json")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(profile_response.status(), StatusCode::OK);
    let profile: Value = read_json_response(profile_response).await;
    assert_eq!(profile["title"], "Example Camera");
    assert_eq!(
        profile["properties"]["battery"]["forms"][0]["op"],
        "readproperty"
    );

    let did_object_client = DIDObjectClient::new();
    let resolved_object = did_object_client.resolve(&object_url).await.unwrap();
    assert!(DIDObjectClient::card_declares_object_url(
        &resolved_object.object_card,
        &object_url
    ));
    assert!(DIDObjectClient::has_trait(
        &resolved_object.object_profile,
        "https://buckyos.org/traits/media-source@1"
    ));
    assert!(DIDObjectClient::has_property(
        &resolved_object.object_profile,
        "battery"
    ));
    assert!(DIDObjectClient::has_action(
        &resolved_object.object_profile,
        "query_clip"
    ));

    let battery = did_object_client
        .read_property_from_resolved(&resolved_object, "battery")
        .await
        .unwrap();
    assert_eq!(battery["value"], 87);
    assert_eq!(battery["version"], "battery-v42");

    let clip = did_object_client
        .invoke_action_result(&object_url, "query_clip", json!({"mode": "clip"}))
        .await
        .unwrap();
    assert_eq!(clip["media_type"], "video");
    assert_eq!(clip["seekable"], true);

    runner_task.abort();
}

#[tokio::test]
async fn serves_declared_property() {
    let server = example_http_server();

    let response = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/devices/cam01/props/battery")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let battery: Value = read_json_response(response).await;
    assert_eq!(battery["value"], 87);
    assert_eq!(battery["version"], "battery-v42");
}

#[tokio::test]
async fn invokes_action_with_krpc_style_envelope() {
    let server = example_http_server();
    let action_request = json!({
        "method": "query_clip",
        "params": {
            "mode": "clip"
        },
        "obj": "https://myhome.com/devices/cam01",
        "obj_did": "did:web:myhome.com:devices:cam01",
        "trace_id": "trace-test"
    });

    let response = server
        .serve_request(
            http::Request::builder()
                .method("POST")
                .uri("http://localhost/devices/cam01/methods/query_clip")
                .header("content-type", "application/json")
                .body(full_body(serde_json::to_vec(&action_request).unwrap()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let action_response: Value = read_json_response(response).await;
    assert_eq!(action_response["result"]["media_type"], "video");
    assert_eq!(action_response["result"]["seekable"], true);
    assert_eq!(action_response["meta"]["status"], "ok");
}

#[tokio::test]
async fn default_obj_url_pattern_keeps_per_object_server_scoped() {
    let server = example_http_server();

    let response = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/devices/cam02/props/battery")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn obj_url_pattern_routes_object_group_to_one_server() {
    let server = Arc::new(
        DIDObjectHttpServer::new("camera-fleet", Arc::new(CameraFleetObjectServer::new()))
            .with_obj_url_pattern("/devices/{camera_id}"),
    );

    let response = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/devices/cam02/props/battery")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let battery: Value = read_json_response(response).await;
    assert_eq!(battery["camera"], "cam02");
    assert_eq!(battery["object_url"], "http://localhost/devices/cam02");

    let profile_response = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/devices/cam03/profile.json")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(profile_response.status(), StatusCode::OK);
    let profile: Value = read_json_response(profile_response).await;
    assert_eq!(profile["title"], "Example Camera cam03");

    let miss = server
        .serve_request(
            http::Request::builder()
                .method("GET")
                .uri("http://localhost/rooms/lab/props/battery")
                .body(full_body(Bytes::new()))
                .unwrap(),
            StreamInfo::default(),
        )
        .await
        .unwrap();

    assert_eq!(miss.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn runner_routes_multiple_did_object_servers() {
    let addr = random_loopback();
    let runner = Runner::with_addr(addr);
    let cam01_url = format!("http://127.0.0.1:{}/devices/cam01", addr.port());
    let cam02_url = format!("http://127.0.0.1:{}/devices/cam02", addr.port());

    runner
        .add_http_server(
            "/devices/cam01".to_string(),
            example_http_server_with_object(
                DID::new("web", &format!("127.0.0.1%3A{}:devices:cam01", addr.port())),
                cam01_url.clone(),
            ),
        )
        .unwrap();
    runner
        .add_http_server(
            "/devices/cam02".to_string(),
            example_http_server_with_object(
                DID::new("web", &format!("127.0.0.1%3A{}:devices:cam02", addr.port())),
                cam02_url.clone(),
            ),
        )
        .unwrap();

    let runner_task = tokio::spawn(async move { runner.run().await });
    wait_for_tcp(addr).await;

    let cam01_response = http_get(addr, "/devices/cam01/did.json").await;
    assert!(cam01_response.contains("200 OK"), "{cam01_response}");
    let cam01_card: DIDObjectCard = http_json_body(&cam01_response);
    assert_eq!(cam01_card.service_endpoint().unwrap(), cam01_url);

    let cam02_response = http_get(addr, "/devices/cam02/did.json").await;
    assert!(cam02_response.contains("200 OK"), "{cam02_response}");
    let cam02_card: DIDObjectCard = http_json_body(&cam02_response);
    assert_eq!(cam02_card.service_endpoint().unwrap(), cam02_url);

    let miss = http_get(addr, "/devices/cam03/did.json").await;
    assert!(miss.contains("404 Not Found"), "{miss}");

    runner_task.abort();
}

#[tokio::test]
async fn runner_routes_object_group_to_one_did_object_server() {
    let addr = random_loopback();
    let runner = Runner::with_addr(addr);
    let fleet_server = Arc::new(
        DIDObjectHttpServer::new("camera-fleet", Arc::new(CameraFleetObjectServer::new()))
            .with_obj_url_pattern("/devices/{camera_id}"),
    );

    runner
        .add_http_server("/devices".to_string(), fleet_server)
        .unwrap();

    let runner_task = tokio::spawn(async move { runner.run().await });
    wait_for_tcp(addr).await;

    let battery_response = http_get(addr, "/devices/cam10/props/battery").await;
    assert!(battery_response.contains("200 OK"), "{battery_response}");
    let battery: Value = http_json_body(&battery_response);
    assert_eq!(battery["camera"], "cam10");
    assert_eq!(
        battery["object_url"],
        format!("http://127.0.0.1:{}/devices/cam10", addr.port())
    );

    let profile_response = http_get(addr, "/devices/cam11/profile.json").await;
    assert!(profile_response.contains("200 OK"), "{profile_response}");
    let profile: Value = http_json_body(&profile_response);
    assert_eq!(profile["title"], "Example Camera cam11");

    let miss = http_get(addr, "/rooms/lab/props/battery").await;
    assert!(miss.contains("404 Not Found"), "{miss}");

    runner_task.abort();
}
