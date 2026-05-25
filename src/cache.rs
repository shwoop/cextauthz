use prost::Message;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: std::time::Duration,
    pub max_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: std::time::Duration::from_secs(60),
            max_size: 1000,
        }
    }
}

/// What we actually store per cached request.
#[derive(Clone, PartialEq, Message)]
pub struct CacheEntry {
    /// Unix timestamp in milliseconds when this entry expires.
    #[prost(uint64, tag = "1")]
    pub expires_at_ms: u64,

    /// true = allowed, false = denied.
    #[prost(bool, tag = "2")]
    pub allowed: bool,

    /// HTTP status code to return when allowed == false.
    /// Only meaningful when denied.
    #[prost(uint32, tag = "3")]
    pub denied_status: u32,
}

/// A single shard of the cache.
#[derive(Clone, Message)]
pub struct CacheShard {
    #[prost(map = "string, message", tag = "1")]
    pub entries: HashMap<String, CacheEntry>,
}

impl CacheShard {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

pub const NUM_SHARDS: usize = 16;

/// Compute a stable cache key from a CheckRequest.
/// The key excludes the request_id (unique per request) so identical
/// authz requests share the same cached result.
pub fn compute_cache_key(req: &crate::pb::CheckRequest) -> String {
    let http = req
        .attributes
        .as_ref()
        .and_then(|a| a.request.as_ref())
        .and_then(|r| r.http.as_ref());

    let (method, path, host, scheme, query, headers, body_fp) = match http {
        Some(h) => {
            let mut hdrs: Vec<(&str, &str)> = h
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            hdrs.sort_by(|a, b| a.0.cmp(b.0));
            let mut hasher = DefaultHasher::new();
            h.raw_body.hash(&mut hasher);
            (
                h.method.as_str(),
                h.path.as_str(),
                h.host.as_str(),
                h.scheme.as_str(),
                h.query.as_str(),
                hdrs,
                hasher.finish(),
            )
        }
        None => ("", "", "", "", "", Vec::new(), 0),
    };

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

    let input = CacheKeyInput {
        method,
        path,
        host,
        scheme,
        query,
        headers,
        body_fingerprint: body_fp,
    };

    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("cache:{:016x}", hasher.finish())
}

pub fn shard_id_from_key(key: &str) -> usize {
    let hash_part = &key[6..]; // skip "cache:"
    u64::from_str_radix(hash_part, 16).unwrap_or(0) as usize % NUM_SHARDS
}

pub fn shard_shared_key(shard_id: usize) -> String {
    format!("cache_shard:{}", shard_id)
}

pub fn shard_quota(max_size: usize) -> usize {
    max_size.div_ceil(NUM_SHARDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb;
    use std::collections::HashMap;

    fn make_request(
        method: &str,
        path: &str,
        host: &str,
        headers: HashMap<String, String>,
    ) -> pb::CheckRequest {
        pb::CheckRequest {
            attributes: Some(pb::AttributeContext {
                source: None,
                destination: None,
                request: Some(pb::Request {
                    http: Some(pb::HttpRequest {
                        id: "req-1".to_string(),
                        method: method.to_string(),
                        headers,
                        path: path.to_string(),
                        host: host.to_string(),
                        scheme: "https".to_string(),
                        query: "a=1".to_string(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: Vec::new(),
                    }),
                }),
                context_extensions: HashMap::new(),
            }),
        }
    }

    #[test]
    fn cache_key_stable_for_identical_requests() {
        let h = {
            let mut m = HashMap::new();
            m.insert("x-auth".to_string(), "token".to_string());
            m
        };
        let req1 = make_request("GET", "/foo", "example.com", h.clone());
        let req2 = make_request("GET", "/foo", "example.com", h);
        assert_eq!(compute_cache_key(&req1), compute_cache_key(&req2));
    }

    #[test]
    fn cache_key_different_for_different_requests() {
        let req1 = make_request("GET", "/foo", "example.com", HashMap::new());
        let req2 = make_request("POST", "/foo", "example.com", HashMap::new());
        assert_ne!(compute_cache_key(&req1), compute_cache_key(&req2));
    }

    #[test]
    fn cache_key_excludes_request_id() {
        let mut req1 = make_request("GET", "/foo", "example.com", HashMap::new());
        let mut req2 = make_request("GET", "/foo", "example.com", HashMap::new());
        req1.attributes
            .as_mut()
            .unwrap()
            .request
            .as_mut()
            .unwrap()
            .http
            .as_mut()
            .unwrap()
            .id = "id-a".to_string();
        req2.attributes
            .as_mut()
            .unwrap()
            .request
            .as_mut()
            .unwrap()
            .http
            .as_mut()
            .unwrap()
            .id = "id-b".to_string();
        assert_eq!(compute_cache_key(&req1), compute_cache_key(&req2));
    }

    #[test]
    fn cache_shard_roundtrip() {
        let mut shard = CacheShard::new();
        shard.entries.insert(
            "k1".to_string(),
            CacheEntry {
                expires_at_ms: 1234,
                allowed: true,
                denied_status: 0,
            },
        );
        shard.entries.insert(
            "k2".to_string(),
            CacheEntry {
                expires_at_ms: 5678,
                allowed: false,
                denied_status: 403,
            },
        );

        let mut buf = Vec::new();
        shard.encode(&mut buf).unwrap();
        let decoded = CacheShard::decode(&buf[..]).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        assert!(decoded.entries["k1"].allowed);
        assert!(!decoded.entries["k2"].allowed);
        assert_eq!(decoded.entries["k2"].denied_status, 403);
    }

    #[test]
    fn shard_id_distribution() {
        let mut counts = vec![0usize; NUM_SHARDS];
        for i in 0..1000 {
            let key = format!("cache:{:016x}", i);
            counts[shard_id_from_key(&key)] += 1;
        }
        // All shards should have received at least one key.
        for (i, &c) in counts.iter().enumerate() {
            assert!(c > 0, "shard {} got zero keys", i);
        }
    }

    #[test]
    fn shard_quota_rounding() {
        assert_eq!(shard_quota(1000), 63); // 1000 / 16 = 62.5 -> 63
        assert_eq!(shard_quota(16), 1);
        assert_eq!(shard_quota(15), 1);
        assert_eq!(shard_quota(1), 1);
    }
}
