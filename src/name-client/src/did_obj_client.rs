use crate::resolver::decode_declared_document_header;
use name_lib::{
    resolve_href, ActionError, ActionInvocation, ActionObserved, ActionResponse,
    DIDDocumentTrait, DIDObjectCard, EncodedDocument, NSError, NSResult, ObjectProfile,
};
use reqwest::{Client, StatusCode};
use serde_json::Value;

#[derive(Clone)]
pub struct DIDObjectClient {
    http_client: Client,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedDIDObject {
    pub object_url: String,
    pub object_card: DIDObjectCard,
    pub object_profile: ObjectProfile,
}

impl Default for DIDObjectClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DIDObjectClient {
    pub fn new() -> Self {
        Self::with_http_client(Client::new())
    }

    pub fn with_http_client(http_client: Client) -> Self {
        Self { http_client }
    }

    pub async fn resolve_card(&self, did_object_url: &str) -> NSResult<DIDObjectCard> {
        let card_url = DIDObjectCard::default_card_url(did_object_url);
        let response = self
            .http_client
            .get(&card_url)
            .send()
            .await
            .map_err(|err| NSError::Failed(format!("request {card_url} failed: {err}")))?;
        let status = response.status();
        let header_doc = decode_declared_document_header(response.headers())?;
        let body = response
            .text()
            .await
            .map_err(|err| NSError::Failed(format!("read {card_url} response failed: {err}")))?;
        if !status.is_success() {
            return Err(http_status_error(status, "DID Object Card", body));
        }
        let body_doc = parse_card_body(&body);
        let doc = match (header_doc, body_doc) {
            (Some(header), Some(body)) => {
                if header.clone().to_json_value()? != body.clone().to_json_value()? {
                    return Err(NSError::InvalidData);
                }
                header
            }
            (Some(header), None) => header,
            (None, Some(body)) => body,
            (None, None) => {
                return Err(NSError::NotFound(format!(
                    "DID Object Card not provided by {card_url}"
                )))
            }
        };
        let card = DIDObjectCard::decode(&doc, None)?;
        card.validate()?;
        Ok(card)
    }

    pub async fn resolve_profile_from_card(&self, card: &DIDObjectCard) -> NSResult<ObjectProfile> {
        let service_endpoint = card.service_endpoint()?;
        let profile_url = resolve_href(service_endpoint, card.profile()?);
        let value = self.get_json(&profile_url, "DID Object Profile").await?;
        let profile = ObjectProfile::from_value(value)?;
        profile.validate()?;
        Ok(profile)
    }

    pub async fn resolve_profile(&self, did_object_url: &str) -> NSResult<ObjectProfile> {
        let card = self.resolve_card(did_object_url).await?;
        self.resolve_profile_from_card(&card).await
    }

    pub async fn resolve(&self, did_object_url: &str) -> NSResult<ResolvedDIDObject> {
        let object_url = did_object_url.trim().to_string();
        let object_card = self.resolve_card(did_object_url).await?;
        let object_profile = self.resolve_profile_from_card(&object_card).await?;
        Ok(ResolvedDIDObject {
            object_url,
            object_card,
            object_profile,
        })
    }

    pub fn card_declares_object_url(card: &DIDObjectCard, did_object_url: &str) -> bool {
        card_declares_object_url(card, did_object_url)
    }

    pub fn has_trait(profile: &ObjectProfile, trait_uri: &str) -> bool {
        object_profile_has_trait(profile, trait_uri)
    }

    pub fn has_property(profile: &ObjectProfile, property_name: &str) -> bool {
        object_profile_has_property(profile, property_name)
    }

    pub fn has_action(profile: &ObjectProfile, action_name: &str) -> bool {
        object_profile_has_action(profile, action_name)
    }

    pub fn has_event(profile: &ObjectProfile, event_name: &str) -> bool {
        object_profile_has_event(profile, event_name)
    }

    pub fn property_endpoint(
        card: &DIDObjectCard,
        profile: &ObjectProfile,
        property_name: &str,
    ) -> NSResult<String> {
        profile.property_endpoint(card.service_endpoint()?, property_name)
    }

    pub fn action_endpoint(
        card: &DIDObjectCard,
        profile: &ObjectProfile,
        action_name: &str,
    ) -> NSResult<String> {
        profile.action_endpoint(card.service_endpoint()?, action_name)
    }

    pub fn event_endpoint(
        card: &DIDObjectCard,
        profile: &ObjectProfile,
        event_name: &str,
    ) -> NSResult<String> {
        profile.event_endpoint(card.service_endpoint()?, event_name)
    }

    pub async fn read_property(
        &self,
        did_object_url: &str,
        property_name: &str,
    ) -> NSResult<Value> {
        let resolved = self.resolve(did_object_url).await?;
        self.read_property_from_resolved(&resolved, property_name)
            .await
    }

    pub async fn read_property_from_resolved(
        &self,
        resolved: &ResolvedDIDObject,
        property_name: &str,
    ) -> NSResult<Value> {
        let endpoint = Self::property_endpoint(
            &resolved.object_card,
            &resolved.object_profile,
            property_name,
        )?;
        self.get_json(&endpoint, property_name).await
    }

    pub async fn invoke_action(
        &self,
        did_object_url: &str,
        action_name: &str,
        params: Value,
    ) -> NSResult<ActionResponse> {
        let resolved = self.resolve(did_object_url).await?;
        self.invoke_action_from_resolved(&resolved, action_name, params)
            .await
    }

    pub async fn invoke_action_from_resolved(
        &self,
        resolved: &ResolvedDIDObject,
        action_name: &str,
        params: Value,
    ) -> NSResult<ActionResponse> {
        let endpoint =
            Self::action_endpoint(&resolved.object_card, &resolved.object_profile, action_name)?;
        let profile_url = resolved.object_card.profile().ok().map(ToOwned::to_owned);
        let request = ActionInvocation {
            method: action_name.to_string(),
            params,
            obj: resolved.object_card.object_url().map(ToOwned::to_owned),
            obj_did: Some(resolved.object_card.id.clone()),
            observed: Some(ActionObserved {
                profile: profile_url,
                ..Default::default()
            }),
            idempotency_key: None,
            confirm_token: None,
            trace_id: None,
        };

        let response = self.post_json(&endpoint, &request, action_name).await?;
        let action_response: ActionResponse = serde_json::from_value(response).map_err(|err| {
            NSError::InvalidParam(format!("invalid DID Object action response: {err}"))
        })?;
        action_response.validate()?;
        Ok(action_response)
    }

    pub async fn invoke_action_result(
        &self,
        did_object_url: &str,
        action_name: &str,
        params: Value,
    ) -> NSResult<Value> {
        let response = self
            .invoke_action(did_object_url, action_name, params)
            .await?;
        action_result_or_error(action_name, response)
    }

    async fn get_json(&self, url: &str, target: &str) -> NSResult<Value> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|err| NSError::Failed(format!("request {url} failed: {err}")))?;
        parse_json_response(response, url, target).await
    }

    async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        url: &str,
        payload: &T,
        target: &str,
    ) -> NSResult<Value> {
        let response = self
            .http_client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|err| NSError::Failed(format!("request {url} failed: {err}")))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| NSError::Failed(format!("read {url} response failed: {err}")))?;
        let value: Value = serde_json::from_str(&body).map_err(|err| {
            NSError::Failed(format!("parse {target} response from {url} failed: {err}"))
        })?;

        if status.is_success() || value.get("error").is_some() {
            return Ok(value);
        }

        Err(http_status_error(status, target, body))
    }
}

pub fn object_profile_has_trait(profile: &ObjectProfile, trait_uri: &str) -> bool {
    profile.implements_trait(trait_uri)
}

pub fn object_profile_has_property(profile: &ObjectProfile, property_name: &str) -> bool {
    profile.properties.contains_key(property_name)
}

pub fn object_profile_has_action(profile: &ObjectProfile, action_name: &str) -> bool {
    profile.actions.contains_key(action_name)
}

pub fn object_profile_has_event(profile: &ObjectProfile, event_name: &str) -> bool {
    profile.events.contains_key(event_name)
}

pub fn card_declares_object_url(card: &DIDObjectCard, did_object_url: &str) -> bool {
    let object_url = normalize_object_url(did_object_url);
    card.also_known_as
        .iter()
        .any(|url| normalize_object_url(url) == object_url)
        || card
            .service_endpoint()
            .map(|url| normalize_object_url(url) == object_url)
            .unwrap_or(false)
}

pub fn action_result_or_error(action_name: &str, response: ActionResponse) -> NSResult<Value> {
    if let Some(result) = response.result {
        return Ok(result);
    }

    let error = response.error.unwrap_or_else(|| ActionError {
        code: "invalid_action_response".to_string(),
        message: "missing result and error".to_string(),
        ..Default::default()
    });

    Err(NSError::Failed(format!(
        "DID Object action {action_name} failed: {}: {}",
        error.code, error.message
    )))
}

fn normalize_object_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn parse_card_body(body: &str) -> Option<EncodedDocument> {
    let body = body.trim();
    if body.starts_with('{') {
        let value: Value = serde_json::from_str(body).ok()?;
        let is_did_document = value.get("id").and_then(Value::as_str).is_some_and(|id| id.starts_with("did:"))
            && value.get("service").is_some();
        return is_did_document.then_some(EncodedDocument::JsonLd(value));
    }
    let parts: Vec<&str> = body.split('.').collect();
    if parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
    {
        return Some(EncodedDocument::Jwt(body.to_string()));
    }
    None
}

async fn parse_json_response(
    response: reqwest::Response,
    url: &str,
    target: &str,
) -> NSResult<Value> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| NSError::Failed(format!("read {url} response failed: {err}")))?;

    if !status.is_success() {
        return Err(http_status_error(status, target, body));
    }

    serde_json::from_str(&body)
        .map_err(|err| NSError::Failed(format!("parse {target} response from {url} failed: {err}")))
}

fn http_status_error(status: StatusCode, target: &str, body: String) -> NSError {
    match status {
        StatusCode::NOT_FOUND => NSError::NotFound(target.to_string()),
        StatusCode::FORBIDDEN => NSError::Forbid,
        StatusCode::GONE => NSError::Disabled(format!("{target} disabled")),
        _ => NSError::Failed(format!("{target} request returned HTTP {status}: {body}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_card(object_url: &str) -> DIDObjectCard {
        DIDObjectCard::new(
            DID::from_str("did:web:127.0.0.1:devices:cam01").unwrap(),
            object_url,
            None,
            format!("{object_url}/profile.json"),
            Some("web.camera"),
        )
    }

    fn test_profile() -> Value {
        json!({
            "@context": [
                "https://www.w3.org/2022/wot/td/v1.1",
                "https://buckyos.org/ns/did-object/v1"
            ],
            "id": "https://example.com/profiles/web-camera@1",
            "title": "Web Camera",
            "x-buckyos:traits": [
                "https://buckyos.org/traits/media-source@1"
            ],
            "properties": {
                "battery": {
                    "type": "integer",
                    "readOnly": true,
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
                    "input": { "type": "object" },
                    "output": { "type": "object" },
                    "forms": [
                        {
                            "href": "methods/query_clip",
                            "op": "invokeaction",
                            "contentType": "application/json"
                        }
                    ]
                }
            },
            "events": {
                "low_battery": {
                    "forms": [
                        {
                            "href": "events",
                            "op": "subscribeevent",
                            "contentType": "application/json"
                        }
                    ]
                }
            }
        })
    }

    #[test]
    fn profile_capability_helpers_check_declared_members() {
        let profile = ObjectProfile::from_value(test_profile()).unwrap();
        profile.validate().unwrap();

        assert!(object_profile_has_trait(
            &profile,
            "https://buckyos.org/traits/media-source@1"
        ));
        assert!(object_profile_has_property(&profile, "battery"));
        assert!(object_profile_has_action(&profile, "query_clip"));
        assert!(object_profile_has_event(&profile, "low_battery"));
        assert!(!object_profile_has_property(&profile, "brand"));
    }

    #[test]
    fn endpoint_helpers_use_profile_forms_and_service_endpoint() {
        let card = test_card("https://myhome.com/devices/cam01");
        let profile = ObjectProfile::from_value(test_profile()).unwrap();

        assert_eq!(
            DIDObjectClient::property_endpoint(&card, &profile, "battery").unwrap(),
            "https://myhome.com/devices/cam01/props/battery"
        );
        assert_eq!(
            DIDObjectClient::action_endpoint(&card, &profile, "query_clip").unwrap(),
            "https://myhome.com/devices/cam01/methods/query_clip"
        );
        assert_eq!(
            DIDObjectClient::event_endpoint(&card, &profile, "low_battery").unwrap(),
            "wss://myhome.com/devices/cam01/events"
        );
    }

    #[test]
    fn card_url_helper_accepts_also_known_as_or_service_endpoint() {
        let card = test_card("https://myhome.com/devices/cam01");

        assert!(card_declares_object_url(
            &card,
            "https://myhome.com/devices/cam01/"
        ));
        assert!(!card_declares_object_url(
            &card,
            "https://myhome.com/devices/cam02"
        ));
    }

    #[tokio::test]
    async fn resolves_card_profile_property_and_action() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let object_url = format!("http://{addr}/devices/cam01");
        let card = test_card(&object_url);
        let profile = test_profile();

        let server = tokio::spawn(async move {
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or_default();

                let (status, body) = if first_line.starts_with("GET /devices/cam01 ") {
                    ("200 OK", serde_json::to_string(&card).unwrap())
                } else if first_line.starts_with("GET /devices/cam01/profile.json ") {
                    ("200 OK", serde_json::to_string(&profile).unwrap())
                } else if first_line.starts_with("GET /devices/cam01/props/battery ") {
                    ("200 OK", json!(88).to_string())
                } else if first_line.starts_with("POST /devices/cam01/methods/query_clip ")
                    && request.contains("\"method\":\"query_clip\"")
                {
                    (
                        "200 OK",
                        json!({
                            "result": {
                                "mode": "clip",
                                "url": "https://media.example/clip.mp4"
                            }
                        })
                        .to_string(),
                    )
                } else {
                    ("404 Not Found", json!({"error": "not found"}).to_string())
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client = DIDObjectClient::new();
        let resolved = client.resolve(&object_url).await.unwrap();
        assert!(card_declares_object_url(&resolved.object_card, &object_url));
        assert!(DIDObjectClient::has_property(
            &resolved.object_profile,
            "battery"
        ));

        let battery = client
            .read_property_from_resolved(&resolved, "battery")
            .await
            .unwrap();
        assert_eq!(battery, json!(88));

        let result = client
            .invoke_action_from_resolved(&resolved, "query_clip", json!({"mode": "clip"}))
            .await
            .unwrap();
        assert_eq!(
            result.result.unwrap()["url"],
            json!("https://media.example/clip.mp4")
        );

        server.abort();
    }

    async fn serve_once(listener: TcpListener, responses: Vec<(&'static str, String, Option<String>)>) {
        for (expected_line, body, header) in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or_default().to_string();
            let (status, body) = if first_line.starts_with(expected_line) {
                ("200 OK", body)
            } else {
                ("404 Not Found", json!({"error": first_line}).to_string())
            };
            let header = header
                .map(|value| format!("BuckyOS-DID-Document: {value}\r\n"))
                .unwrap_or_default();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/html\r\n{header}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn path_object_card_comes_from_header_and_directory_appends_did_json() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let object_url = format!("http://{addr}/devices/cam01");
        let dir_url = format!("http://{addr}/devices/");
        let card = test_card(&object_url);
        let header = crate::resolver::encode_declared_document_header(&EncodedDocument::JsonLd(
            serde_json::to_value(&card).unwrap(),
        ));
        let server = tokio::spawn(serve_once(
            listener,
            vec![
                ("GET /devices/cam01 ", "<html>camera</html>".to_string(), Some(header)),
                ("GET /devices/did.json ", serde_json::to_string(&card).unwrap(), None),
                ("GET /devices/cam02 ", "<html>no card</html>".to_string(), None),
            ],
        ));

        let client = DIDObjectClient::new();
        let from_header = client.resolve_card(&object_url).await.unwrap();
        assert_eq!(from_header.id, card.id);
        let from_dir = client.resolve_card(&dir_url).await.unwrap();
        assert_eq!(from_dir.id, card.id);
        let missing = client
            .resolve_card(&format!("http://{addr}/devices/cam02"))
            .await
            .unwrap_err();
        assert!(matches!(missing, NSError::NotFound(_)));
        server.await.unwrap();
    }
}
