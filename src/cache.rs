use prost::Message;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

pub const NUM_SHARDS: usize = 16;

#[derive(Clone, Debug, PartialEq)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: Duration,
    pub max_entries: usize,
    pub header_policy: CacheHeaderPolicy,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CacheHeaderPolicy {
    AllExceptRequestId,
    Allowlist(Vec<String>),
    Denylist(Vec<String>),
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: Duration::from_secs(60),
            max_entries: 1000,
            header_policy: CacheHeaderPolicy::AllExceptRequestId,
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CacheEntry {
    #[prost(uint64, tag = "1")]
    pub expires_at_ms: u64,
    #[prost(bool, tag = "2")]
    pub allowed: bool,
    #[prost(uint32, tag = "3")]
    pub denied_status: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct CacheShard {
    #[prost(map = "string, message", tag = "1")]
    pub entries: HashMap<String, CacheEntry>,
}

#[derive(Hash)]
struct CacheKeyInput<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    scheme: &'a str,
    query: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body_fingerprint: u64,
}

pub fn compute_cache_key(req: &crate::pb::CheckRequest) -> String {
    let http = req
        .attributes
        .as_ref()
        .and_then(|a| a.request.as_ref())
        .and_then(|r| r.http.as_ref());

    let (method, path, host, scheme, query, headers, body_fingerprint) = match http {
        Some(h) => {
            let mut headers: Vec<(&str, &str)> = h
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    if name.eq_ignore_ascii_case("x-request-id") {
                        None
                    } else {
                        Some((name.as_str(), value.as_str()))
                    }
                })
                .collect();
            headers.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));

            let mut body_hasher = DefaultHasher::new();
            h.raw_body.hash(&mut body_hasher);

            (
                h.method.as_str(),
                h.path.as_str(),
                h.host.as_str(),
                h.scheme.as_str(),
                h.query.as_str(),
                headers,
                body_hasher.finish(),
            )
        }
        None => ("", "", "", "", "", Vec::new(), 0),
    };

    let input = CacheKeyInput {
        method,
        path,
        host,
        scheme,
        query,
        headers,
        body_fingerprint,
    };

    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("cache:{:016x}", hasher.finish())
}

pub fn shard_id_from_key(key: &str) -> usize {
    key.strip_prefix("cache:")
        .and_then(|hash| u64::from_str_radix(hash, 16).ok())
        .map(|hash| hash as usize % NUM_SHARDS)
        .unwrap_or(0)
}

pub fn shard_shared_key(shard_id: usize) -> String {
    format!("cextauthz.cache.shard.{shard_id}")
}

pub fn shard_quota(max_entries: usize) -> usize {
    max_entries.div_ceil(NUM_SHARDS).max(1)
}

pub fn decode_shard(bytes: Option<&[u8]>) -> CacheShard {
    bytes
        .and_then(|data| CacheShard::decode(data).ok())
        .unwrap_or_default()
}

pub fn evict_expired(shard: &mut CacheShard, now_ms: u64) {
    shard
        .entries
        .retain(|_key, entry| entry.expires_at_ms > now_ms);
}

pub fn enforce_quota(shard: &mut CacheShard, quota: usize) {
    while shard.entries.len() > quota {
        let Some(key) = shard.entries.keys().next().cloned() else {
            break;
        };
        shard.entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn shard_quota_is_nonzero_for_small_caches() {
        assert_eq!(shard_quota(0), 1);
        assert_eq!(shard_quota(1), 1);
        assert_eq!(shard_quota(16), 1);
        assert_eq!(shard_quota(17), 2);
    }

    #[test]
    fn expired_entries_are_removed() {
        let mut shard = CacheShard::default();
        shard.entries.insert(
            "cache:0000000000000001".to_string(),
            CacheEntry {
                expires_at_ms: 100,
                allowed: true,
                denied_status: 0,
            },
        );
        shard.entries.insert(
            "cache:0000000000000002".to_string(),
            CacheEntry {
                expires_at_ms: 200,
                allowed: false,
                denied_status: 403,
            },
        );

        evict_expired(&mut shard, 150);

        assert!(!shard.entries.contains_key("cache:0000000000000001"));
        assert!(shard.entries.contains_key("cache:0000000000000002"));
    }

    #[test]
    fn key_ignores_request_id() {
        let mut headers_a = HashMap::new();
        headers_a.insert("x-request-id".to_string(), "a".to_string());
        headers_a.insert("x-ext-authz".to_string(), "allow".to_string());

        let mut headers_b = headers_a.clone();
        headers_b.insert("x-request-id".to_string(), "b".to_string());

        let request = |headers| crate::pb::CheckRequest {
            attributes: Some(crate::pb::AttributeContext {
                source: None,
                destination: None,
                request: Some(crate::pb::Request {
                    http: Some(crate::pb::HttpRequest {
                        id: String::new(),
                        method: "GET".to_string(),
                        headers,
                        path: "/".to_string(),
                        host: "example.com".to_string(),
                        scheme: "http".to_string(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: Vec::new(),
                    }),
                }),
                context_extensions: HashMap::new(),
            }),
        };

        assert_eq!(
            compute_cache_key(&request(headers_a)),
            compute_cache_key(&request(headers_b))
        );
    }
}
