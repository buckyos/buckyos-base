use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use name_client::{CacheBackend, NameClient, NameClientConfig, SmartProvider};
use name_lib::{DIDObjectCard, DID};
use serde_json::{json, Value};
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
