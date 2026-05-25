use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const INVALIDATION_PATH: &str = "/_cextauthz/cache/invalidate";
pub const INVALIDATION_SECRET_HEADER: &str = "x-cextauthz-invalidation-secret";
pub const CONTROL_QUEUE_NAME: &str = "cextauthz.invalidate.control";
pub const WORKER_QUEUE_PREFIX: &str = "cextauthz.invalidate.";
pub const MESSAGE_VERSION: u32 = 1;
pub const MAX_INVALIDATION_SKEW_MS: u64 = 300_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationOp {
    PurgeKey,
    PurgeAll,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationRequest {
    pub version: u32,
    pub op: InvalidationOp,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub reason: Option<String>,
    pub issued_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QueueMessage {
    RegisterWorker { queue_name: String },
    Invalidate(InvalidationRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidationParseError {
    Json,
    UnsupportedVersion,
    MissingKey,
    BadKey,
    IssuedAtInFuture,
    IssuedAtTooOld,
}

pub fn parse_invalidation(
    body: &[u8],
    now_ms: u64,
) -> Result<InvalidationRequest, InvalidationParseError> {
    let request: InvalidationRequest =
        serde_json::from_slice(body).map_err(|_| InvalidationParseError::Json)?;
    validate_invalidation(request, now_ms)
}

pub fn validate_invalidation(
    request: InvalidationRequest,
    now_ms: u64,
) -> Result<InvalidationRequest, InvalidationParseError> {
    if request.version != MESSAGE_VERSION {
        return Err(InvalidationParseError::UnsupportedVersion);
    }
    if request.issued_at_ms > now_ms.saturating_add(MAX_INVALIDATION_SKEW_MS) {
        return Err(InvalidationParseError::IssuedAtInFuture);
    }
    if now_ms
        > request
            .issued_at_ms
            .saturating_add(MAX_INVALIDATION_SKEW_MS)
    {
        return Err(InvalidationParseError::IssuedAtTooOld);
    }
    match request.op {
        InvalidationOp::PurgeKey => {
            let Some(key) = request.key.as_deref() else {
                return Err(InvalidationParseError::MissingKey);
            };
            if !is_valid_cache_key(key) {
                return Err(InvalidationParseError::BadKey);
            }
        }
        InvalidationOp::PurgeAll => {}
    }
    Ok(request)
}

pub fn is_valid_cache_key(key: &str) -> bool {
    key.len() == 22 && key.starts_with("cache:") && key[6..].bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Default)]
pub struct WorkerRegistry {
    queue_names: HashSet<String>,
}

impl WorkerRegistry {
    pub fn insert(&mut self, queue_name: String) -> bool {
        if queue_name.starts_with(WORKER_QUEUE_PREFIX) && queue_name != CONTROL_QUEUE_NAME {
            self.queue_names.insert(queue_name)
        } else {
            false
        }
    }

    pub fn remove(&mut self, queue_name: &str) {
        self.queue_names.remove(queue_name);
    }

    pub fn queue_names(&self) -> impl Iterator<Item = &str> {
        self.queue_names.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.queue_names.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_779_720_000_000;

    #[test]
    fn parses_purge_key() {
        let body = br#"{"version":1,"op":"purge_key","key":"cache:0123456789abcdef","epoch":42,"reason":"policy update","issued_at_ms":1779720000000}"#;

        let parsed = parse_invalidation(body, NOW).unwrap();

        assert_eq!(parsed.op, InvalidationOp::PurgeKey);
        assert_eq!(parsed.key.as_deref(), Some("cache:0123456789abcdef"));
        assert_eq!(parsed.epoch, 42);
    }

    #[test]
    fn parses_purge_all_without_key() {
        let body = br#"{"version":1,"op":"purge_all","issued_at_ms":1779720000000}"#;

        let parsed = parse_invalidation(body, NOW).unwrap();

        assert_eq!(parsed.op, InvalidationOp::PurgeAll);
        assert_eq!(parsed.key, None);
    }

    #[test]
    fn rejects_missing_key_for_purge_key() {
        let body = br#"{"version":1,"op":"purge_key","issued_at_ms":1779720000000}"#;

        assert_eq!(
            parse_invalidation(body, NOW),
            Err(InvalidationParseError::MissingKey)
        );
    }

    #[test]
    fn rejects_bad_key_for_purge_key() {
        let body = br#"{"version":1,"op":"purge_key","key":"not-a-cache-key","issued_at_ms":1779720000000}"#;

        assert_eq!(
            parse_invalidation(body, NOW),
            Err(InvalidationParseError::BadKey)
        );
    }

    #[test]
    fn rejects_stale_issued_at() {
        let body = br#"{"version":1,"op":"purge_all","issued_at_ms":1779719699999}"#;

        assert_eq!(
            parse_invalidation(body, NOW),
            Err(InvalidationParseError::IssuedAtTooOld)
        );
    }

    #[test]
    fn queue_message_json_roundtrip() {
        let msg = QueueMessage::RegisterWorker {
            queue_name: "cextauthz.invalidate.worker-1".to_string(),
        };

        let bytes = serde_json::to_vec(&msg).unwrap();
        let decoded: QueueMessage = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn registry_accepts_only_worker_queue_names() {
        let mut registry = WorkerRegistry::default();

        assert!(registry.insert("cextauthz.invalidate.worker-1".to_string()));
        assert!(!registry.insert("cextauthz.invalidate.control".to_string()));
        assert!(!registry.insert("other.queue".to_string()));
        assert_eq!(registry.len(), 1);
    }
}
