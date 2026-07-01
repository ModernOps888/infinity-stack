use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NewRecord {
    #[serde(default)]
    pub key: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogRecord {
    pub topic: String,
    pub partition: u32,
    pub offset: u64,
    #[serde(default)]
    pub key: Option<String>,
    pub value: Value,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub score: f64,
    pub fields: BTreeMap<String, Value>,
}
