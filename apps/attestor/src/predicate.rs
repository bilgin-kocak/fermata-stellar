//! The v1 delivery predicate: status set, max body bytes, content type, tiny JSON-schema subset.
//! Every check is decidable on the revealed transcript alone. A JSON parse failure is a
//! predicate failure (verdict FAILED), never an error.
//!
//! Copied unchanged from Fermata `apps/attestor/src/predicate.rs` @ d7cc642
//! (github.com/bilgin-kocak/fermata, Apache-2.0).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub version: u32,
    pub status: Vec<u16>,
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub json_schema: Option<Schema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Returns the list of failed checks (empty = DELIVERED).
pub fn evaluate(
    p: &Predicate,
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<String> {
    let mut failures = Vec::new();
    if !p.status.contains(&status) {
        failures.push(format!("status {status} not in {:?}", p.status));
    }
    if let Some(max) = p.max_body_bytes
        && body.len() > max
    {
        failures.push(format!("body {} bytes > maxBodyBytes {max}", body.len()));
    }
    if let Some(ct) = &p.content_type {
        match content_type {
            Some(actual)
                if actual
                    .to_ascii_lowercase()
                    .starts_with(&ct.to_ascii_lowercase()) => {}
            other => failures.push(format!("content-type {other:?} does not start with {ct:?}")),
        }
    }
    if let Some(schema) = &p.json_schema {
        match serde_json::from_slice::<Value>(body) {
            Err(e) => failures.push(format!("body is not valid JSON: {e}")),
            Ok(v) => {
                if let Some(ty) = &schema.ty
                    && json_type(&v) != ty
                {
                    failures.push(format!("json type {} != {ty}", json_type(&v)));
                }
                for key in &schema.required {
                    if v.get(key).is_none() {
                        failures.push(format!("required key {key:?} missing"));
                    }
                }
                for (key, prop) in &schema.properties {
                    if let (Some(ty), Some(val)) = (&prop.ty, v.get(key))
                        && json_type(val) != ty
                    {
                        failures.push(format!("key {key:?} has type {} != {ty}", json_type(val)));
                    }
                }
            }
        }
    }
    failures
}
