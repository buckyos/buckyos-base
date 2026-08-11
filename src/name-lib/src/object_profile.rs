use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EncodedDocument, NSError, NSResult, DID};

pub const WOT_TD_CONTEXT: &str = "https://www.w3.org/2022/wot/td/v1.1";
pub const DID_OBJECT_CONTEXT: &str = "https://buckyos.org/ns/did-object/v1";
pub const INDEX_TRAIT_URI: &str = "https://buckyos.org/traits/index@1";

pub const OP_READ_PROPERTY: &str = "readproperty";
pub const OP_INVOKE_ACTION: &str = "invokeaction";
pub const OP_SUBSCRIBE_EVENT: &str = "subscribeevent";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProfileContext {
    String(String),
    Array(Vec<String>),
}

impl Default for ProfileContext {
    fn default() -> Self {
        ProfileContext::Array(vec![
            WOT_TD_CONTEXT.to_string(),
            DID_OBJECT_CONTEXT.to_string(),
        ])
    }
}

impl ProfileContext {
    pub fn contains(&self, context: &str) -> bool {
        match self {
            ProfileContext::String(value) => value == context,
            ProfileContext::Array(values) => values.iter().any(|value| value == context),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ObjectProfile {
    #[serde(rename = "@context", default)]
    pub context: ProfileContext,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub version: Option<ProfileVersion>,
    #[serde(rename = "x-buckyos:traits")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub traits: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub properties: HashMap<String, PropertyAffordance>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub actions: HashMap<String, ActionAffordance>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub events: HashMap<String, EventAffordance>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub forms: Vec<Form>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl ObjectProfile {
    pub fn from_json_str(profile: &str) -> NSResult<Self> {
        let profile = serde_json::from_str(profile)
            .map_err(|err| NSError::InvalidParam(format!("invalid object profile json: {err}")))?;
        Ok(profile)
    }

    pub fn from_value(value: Value) -> NSResult<Self> {
        let profile = serde_json::from_value(value)
            .map_err(|err| NSError::InvalidParam(format!("invalid object profile json: {err}")))?;
        Ok(profile)
    }

    pub fn decode(doc: EncodedDocument) -> NSResult<Self> {
        Self::from_value(doc.to_json_value()?)
    }

    pub fn validate(&self) -> NSResult<()> {
        if self.id.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "DID Object Profile id cannot be empty".to_string(),
            ));
        }

        if !self.context.contains(WOT_TD_CONTEXT) {
            return Err(NSError::InvalidParam(format!(
                "DID Object Profile @context must contain {WOT_TD_CONTEXT}"
            )));
        }

        for (name, property) in &self.properties {
            validate_name("property", name)?;
            property.validate(name)?;
        }

        for (name, action) in &self.actions {
            validate_name("action", name)?;
            action.validate(name)?;
        }

        for (name, event) in &self.events {
            validate_name("event", name)?;
            event.validate(name)?;
        }

        if self.implements_trait(INDEX_TRAIT_URI) {
            self.validate_index_trait()?;
        }

        Ok(())
    }

    pub fn implements_trait(&self, trait_uri: &str) -> bool {
        self.traits.iter().any(|item| item == trait_uri)
    }

    pub fn property_endpoint(
        &self,
        service_endpoint: &str,
        property_name: &str,
    ) -> NSResult<String> {
        if let Some(property) = self.properties.get(property_name) {
            if let Some(form) = property.form_by_op(OP_READ_PROPERTY) {
                return Ok(resolve_href(service_endpoint, &form.href));
            }
            if !property.forms.is_empty() {
                return Err(NSError::InvalidParam(format!(
                    "property {property_name} has forms but no {OP_READ_PROPERTY} form"
                )));
            }
        } else {
            return Err(NSError::NotFound(format!(
                "property {property_name} in object profile"
            )));
        }

        Ok(resolve_href(
            service_endpoint,
            &format!("props/{property_name}"),
        ))
    }

    pub fn action_endpoint(&self, service_endpoint: &str, action_name: &str) -> NSResult<String> {
        if let Some(action) = self.actions.get(action_name) {
            if let Some(form) = action.form_by_op(OP_INVOKE_ACTION) {
                return Ok(resolve_href(service_endpoint, &form.href));
            }
            if !action.forms.is_empty() {
                return Err(NSError::InvalidParam(format!(
                    "action {action_name} has forms but no {OP_INVOKE_ACTION} form"
                )));
            }
        } else {
            return Err(NSError::NotFound(format!(
                "action {action_name} in object profile"
            )));
        }

        Ok(resolve_href(
            service_endpoint,
            &format!("methods/{action_name}"),
        ))
    }

    pub fn event_endpoint(&self, service_endpoint: &str, event_name: &str) -> NSResult<String> {
        if let Some(event) = self.events.get(event_name) {
            if let Some(form) = event.form_by_op(OP_SUBSCRIBE_EVENT) {
                return Ok(http_to_ws_url(&resolve_href(service_endpoint, &form.href)));
            }
            if !event.forms.is_empty() {
                return Err(NSError::InvalidParam(format!(
                    "event {event_name} has forms but no {OP_SUBSCRIBE_EVENT} form"
                )));
            }
        } else {
            return Err(NSError::NotFound(format!(
                "event {event_name} in object profile"
            )));
        }

        Ok(http_to_ws_url(&resolve_href(service_endpoint, "events")))
    }

    pub fn validate_index_trait(&self) -> NSResult<()> {
        if !self.properties.contains_key("index_schema") {
            return Err(NSError::InvalidParam(
                "IndexTrait profile must declare index_schema property".to_string(),
            ));
        }
        if !self.actions.contains_key("query") {
            return Err(NSError::InvalidParam(
                "IndexTrait profile must declare query action".to_string(),
            ));
        }
        if !self.actions.contains_key("page") {
            return Err(NSError::InvalidParam(
                "IndexTrait profile must declare page action".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ProfileVersion {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct PropertyAffordance {
    #[serde(flatten)]
    pub schema: DataSchema,
    #[serde(rename = "readOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub observable: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub forms: Vec<Form>,
}

impl PropertyAffordance {
    pub fn form_by_op(&self, op: &str) -> Option<&Form> {
        self.forms.iter().find(|form| form.has_op(op))
    }

    pub fn validate(&self, name: &str) -> NSResult<()> {
        validate_forms("property", name, &self.forms, OP_READ_PROPERTY)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionAffordance {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub input: Option<DataSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub output: Option<DataSchema>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub forms: Vec<Form>,
    #[serde(rename = "x-buckyos:action")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub buckyos_action: Option<ActionPolicy>,
    #[serde(rename = "x-buckyos:agentResult")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub agent_result: Option<Value>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl ActionAffordance {
    pub fn form_by_op(&self, op: &str) -> Option<&Form> {
        self.forms.iter().find(|form| form.has_op(op))
    }

    pub fn validate(&self, name: &str) -> NSResult<()> {
        validate_forms("action", name, &self.forms, OP_INVOKE_ACTION)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventAffordance {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data: Option<DataSchema>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub forms: Vec<Form>,
    #[serde(rename = "x-buckyos:event")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub buckyos_event: Option<EventPolicy>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl EventAffordance {
    pub fn form_by_op(&self, op: &str) -> Option<&Form> {
        self.forms.iter().find(|form| form.has_op(op))
    }

    pub fn validate(&self, name: &str) -> NSResult<()> {
        validate_forms("event", name, &self.forms, OP_SUBSCRIBE_EVENT)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Form {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub op: Option<FormOperation>,
    #[serde(rename = "contentType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl Form {
    pub fn has_op(&self, op: &str) -> bool {
        self.op
            .as_ref()
            .map(|item| item.contains(op))
            .unwrap_or(false)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum FormOperation {
    Single(String),
    Multiple(Vec<String>),
}

impl FormOperation {
    pub fn contains(&self, op: &str) -> bool {
        match self {
            FormOperation::Single(value) => value == op,
            FormOperation::Multiple(values) => values.iter().any(|value| value == op),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct DataSchema {
    #[serde(rename = "$ref")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub schema_ref: Option<String>,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub schema_type: Option<JsonSchemaType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub format: Option<String>,
    #[serde(rename = "enum")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub enum_values: Vec<Value>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub properties: HashMap<String, DataSchema>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub items: Option<Box<DataSchema>>,
    #[serde(rename = "additionalProperties")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub additional_properties: Option<AdditionalProperties>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum JsonSchemaType {
    Single(String),
    Multiple(Vec<String>),
}

impl JsonSchemaType {
    pub fn contains(&self, schema_type: &str) -> bool {
        match self {
            JsonSchemaType::Single(value) => value == schema_type,
            JsonSchemaType::Multiple(values) => values.iter().any(|value| value == schema_type),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum AdditionalProperties {
    Bool(bool),
    Schema(Box<DataSchema>),
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub idempotency: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub delivery: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionInvocation {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub obj: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub obj_did: Option<DID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub observed: Option<ActionObserved>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confirm_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub trace_id: Option<String>,
}

impl ActionInvocation {
    pub fn validate_for_profile(&self, profile: &ObjectProfile) -> NSResult<()> {
        if self.method.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "action invocation method cannot be empty".to_string(),
            ));
        }
        if !profile.actions.contains_key(&self.method) {
            return Err(NSError::NotFound(format!(
                "action {} in object profile",
                self.method
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionObserved {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub card_etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub profile_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub object_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub meta: Option<ActionMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub error: Option<ActionError>,
}

impl ActionResponse {
    pub fn success(result: Value) -> Self {
        Self {
            result: Some(result),
            meta: None,
            error: None,
        }
    }

    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            result: None,
            meta: None,
            error: Some(ActionError {
                code: code.into(),
                message: message.into(),
                ..Default::default()
            }),
        }
    }

    pub fn validate(&self) -> NSResult<()> {
        match (&self.result, &self.error) {
            (Some(_), None) => Ok(()),
            (None, Some(_)) => Ok(()),
            _ => Err(NSError::InvalidParam(
                "action response must contain exactly one of result or error".to_string(),
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub created_objects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub affected_objects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub invalidated_objects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub refresh_hints: Vec<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ActionError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub refresh_hints: Vec<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventSubscribeRequest {
    pub op: String,
    pub object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub object_did: Option<DID>,
    pub event: String,
    #[serde(default)]
    pub filter: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub trace_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventSubscription {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub subscription_id: String,
    pub object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub object_did: Option<DID>,
    pub event: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub delivery: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub refresh_hints: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventStatus {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub subscription_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct EventFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub event_id: Option<String>,
    pub subscription_id: String,
    pub object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub object_did: Option<DID>,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cursor: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub summary: Option<String>,
    pub data: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub affected_objects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub invalidated_objects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub refresh_hints: Vec<String>,
}

pub fn resolve_href(service_endpoint: &str, href: &str) -> String {
    let href = href.trim();
    if href.is_empty() {
        return service_endpoint.to_string();
    }

    if is_absolute_url(href) {
        return href.to_string();
    }

    if href.starts_with('/') {
        if let Some(origin) = url_origin(service_endpoint) {
            return format!("{origin}{href}");
        }
    }

    if href.starts_with('?') || href.starts_with('#') {
        return format!("{service_endpoint}{href}");
    }

    format!(
        "{}/{}",
        service_endpoint.trim_end_matches('/'),
        href.trim_start_matches("./")
    )
}

pub fn http_to_ws_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url.to_string()
    }
}

fn is_absolute_url(value: &str) -> bool {
    value.contains("://")
}

fn url_origin(url: &str) -> Option<String> {
    let scheme_pos = url.find("://")?;
    let host_start = scheme_pos + 3;
    let host_end = url[host_start..]
        .find('/')
        .map(|pos| host_start + pos)
        .unwrap_or(url.len());
    Some(url[..host_end].to_string())
}

fn validate_name(kind: &str, name: &str) -> NSResult<()> {
    if name.trim().is_empty() {
        return Err(NSError::InvalidParam(format!(
            "{kind} name cannot be empty"
        )));
    }
    Ok(())
}

fn validate_forms(kind: &str, name: &str, forms: &[Form], required_op: &str) -> NSResult<()> {
    if forms.is_empty() {
        return Ok(());
    }

    for form in forms {
        if form.href.trim().is_empty() {
            return Err(NSError::InvalidParam(format!(
                "{kind} {name} form href cannot be empty"
            )));
        }
    }

    if !forms.iter().any(|form| form.has_op(required_op)) {
        return Err(NSError::InvalidParam(format!(
            "{kind} {name} must include a {required_op} form"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_and_validate_profile_example() {
        let profile = ObjectProfile::from_value(json!({
            "@context": [
                "https://www.w3.org/2022/wot/td/v1.1",
                "https://buckyos.org/ns/did-object/v1"
            ],
            "id": "https://buckyos.org/profiles/web-camera@1",
            "title": "Web Camera",
            "version": {
                "instance": "1.0.0"
            },
            "x-buckyos:traits": [
                "https://buckyos.org/traits/media-source@1"
            ],
            "properties": {
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
                            "battery": { "type": "integer" }
                        }
                    },
                    "forms": [
                        {
                            "href": "events",
                            "op": "subscribeevent",
                            "contentType": "application/json"
                        }
                    ],
                    "x-buckyos:event": {
                        "delivery": "best_effort"
                    }
                }
            }
        }))
        .unwrap();

        profile.validate().unwrap();
        assert_eq!(
            profile
                .property_endpoint("https://myhome.com/devices/cam01", "battery")
                .unwrap(),
            "https://myhome.com/devices/cam01/props/battery"
        );
        assert_eq!(
            profile
                .action_endpoint("https://myhome.com/devices/cam01", "query_clip")
                .unwrap(),
            "https://myhome.com/devices/cam01/methods/query_clip"
        );
        assert_eq!(
            profile
                .event_endpoint("https://myhome.com/devices/cam01", "low_battery")
                .unwrap(),
            "wss://myhome.com/devices/cam01/events"
        );
    }

    #[test]
    fn applies_default_endpoint_rules_when_forms_are_missing() {
        let profile = ObjectProfile::from_value(json!({
            "@context": "https://www.w3.org/2022/wot/td/v1.1",
            "id": "https://example.com/profiles/minimal@1",
            "properties": {
                "summary": { "type": "object" }
            },
            "actions": {
                "refresh": {}
            },
            "events": {
                "changed": {}
            }
        }))
        .unwrap();

        profile.validate().unwrap();
        assert_eq!(
            profile
                .property_endpoint("https://example.com/objects/1/", "summary")
                .unwrap(),
            "https://example.com/objects/1/props/summary"
        );
        assert_eq!(
            profile
                .action_endpoint("https://example.com/objects/1", "refresh")
                .unwrap(),
            "https://example.com/objects/1/methods/refresh"
        );
        assert_eq!(
            profile
                .event_endpoint("http://example.com/objects/1", "changed")
                .unwrap(),
            "ws://example.com/objects/1/events"
        );
    }

    #[test]
    fn preserves_standard_root_path_resolution() {
        assert_eq!(
            resolve_href("https://example.com/objects/1", "/events"),
            "https://example.com/events"
        );
        assert_eq!(
            resolve_href("https://example.com/objects/1", "events"),
            "https://example.com/objects/1/events"
        );
    }

    #[test]
    fn validates_index_trait_required_members() {
        let profile = ObjectProfile::from_value(json!({
            "@context": "https://www.w3.org/2022/wot/td/v1.1",
            "id": "https://example.com/profiles/index@1",
            "x-buckyos:traits": ["https://buckyos.org/traits/index@1"],
            "properties": {
                "index_schema": {}
            },
            "actions": {
                "query": {}
            }
        }))
        .unwrap();

        let err = profile.validate().unwrap_err();
        assert!(matches!(err, NSError::InvalidParam(_)));
    }

    #[test]
    fn validates_action_response_shape() {
        ActionResponse::success(json!({"ok": true}))
            .validate()
            .unwrap();
        ActionResponse::failure("permission_denied", "no")
            .validate()
            .unwrap();

        let invalid = ActionResponse {
            result: Some(json!({})),
            error: Some(ActionError::default()),
            meta: None,
        };
        assert!(invalid.validate().is_err());
    }
}
