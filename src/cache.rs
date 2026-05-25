use prost::Message;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub const CACHE_ENTRY_OVERHEAD_BYTES: usize = 96;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: std::time::Duration,
    pub size_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: std::time::Duration::from_secs(60),
            size_bytes: 1024 * 1024,
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
    #[prost(uint64, tag = "4")]
    pub epoch: u64,
    #[prost(uint64, tag = "5")]
    pub inserted_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub estimated_bytes: u64,
}

#[derive(Debug, Default)]
pub struct VmCache {
    entries: HashMap<String, CacheEntry>,
    estimated_bytes: usize,
}

impl VmCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    pub fn get_fresh(&mut self, key: &str, now_ms: u64) -> Option<CacheEntry> {
        let expired = self
            .entries
            .get(key)
            .map(|entry| entry.expires_at_ms <= now_ms)
            .unwrap_or(false);
        if expired {
            self.remove_key(key);
            return None;
        }
        self.entries.get(key).cloned()
    }

    pub fn insert(
        &mut self,
        key: String,
        allowed: bool,
        denied_status: u32,
        now_ms: u64,
        ttl_ms: u64,
        epoch: u64,
        budget_bytes: usize,
    ) {
        self.evict_expired(now_ms);
        self.remove_key(&key);

        let estimated_bytes = estimate_entry_bytes(&key);
        let entry = CacheEntry {
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            allowed,
            denied_status,
            epoch,
            inserted_at_ms: now_ms,
            estimated_bytes: estimated_bytes as u64,
        };
        self.estimated_bytes = self.estimated_bytes.saturating_add(estimated_bytes);
        self.entries.insert(key, entry);
        self.enforce_budget(budget_bytes);
    }

    pub fn purge_key(&mut self, key: &str) -> bool {
        self.remove_key(key).is_some()
    }

    pub fn purge_all(&mut self) {
        self.entries.clear();
        self.estimated_bytes = 0;
    }

    pub fn evict_expired(&mut self, now_ms: u64) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if entry.expires_at_ms <= now_ms {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.remove_key(&key);
        }
    }

    fn enforce_budget(&mut self, budget_bytes: usize) {
        while self.estimated_bytes > budget_bytes && !self.entries.is_empty() {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_key, entry)| entry.inserted_at_ms)
                .map(|(key, _entry)| key.clone());
            if let Some(key) = oldest_key {
                self.remove_key(&key);
            } else {
                break;
            }
        }
    }

    fn remove_key(&mut self, key: &str) -> Option<CacheEntry> {
        let removed = self.entries.remove(key);
        if let Some(entry) = &removed {
            self.estimated_bytes = self
                .estimated_bytes
                .saturating_sub(entry.estimated_bytes as usize);
        }
        removed
    }
}

pub fn estimate_entry_bytes(key: &str) -> usize {
    key.len()
        .saturating_add(std::mem::size_of::<CacheEntry>())
        .saturating_add(CACHE_ENTRY_OVERHEAD_BYTES)
}

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
    fn vm_cache_returns_fresh_entry() {
        let mut cache = VmCache::new();
        cache.insert(
            "cache:0000000000000001".to_string(),
            true,
            0,
            1000,
            5000,
            0,
            4096,
        );

        let entry = cache.get_fresh("cache:0000000000000001", 2000).unwrap();
        assert!(entry.allowed);
    }

    #[test]
    fn vm_cache_expires_entry_on_read() {
        let mut cache = VmCache::new();
        cache.insert(
            "cache:0000000000000001".to_string(),
            true,
            0,
            1000,
            100,
            0,
            4096,
        );

        assert!(cache.get_fresh("cache:0000000000000001", 1200).is_none());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.estimated_bytes(), 0);
    }

    #[test]
    fn purge_key_removes_only_matching_entry() {
        let mut cache = VmCache::new();
        cache.insert(
            "cache:0000000000000001".to_string(),
            true,
            0,
            1000,
            5000,
            0,
            4096,
        );
        cache.insert(
            "cache:0000000000000002".to_string(),
            false,
            403,
            1001,
            5000,
            0,
            4096,
        );

        assert!(cache.purge_key("cache:0000000000000001"));
        assert!(cache.get_fresh("cache:0000000000000001", 2000).is_none());
        assert!(cache.get_fresh("cache:0000000000000002", 2000).is_some());
    }

    #[test]
    fn purge_all_clears_entries_and_byte_count() {
        let mut cache = VmCache::new();
        cache.insert(
            "cache:0000000000000001".to_string(),
            true,
            0,
            1000,
            5000,
            0,
            4096,
        );
        cache.insert(
            "cache:0000000000000002".to_string(),
            false,
            403,
            1001,
            5000,
            0,
            4096,
        );

        cache.purge_all();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.estimated_bytes(), 0);
    }

    #[test]
    fn vm_cache_evicts_oldest_until_under_budget() {
        let mut cache = VmCache::new();
        let one_entry_budget = estimate_entry_bytes("cache:0000000000000001");
        cache.insert(
            "cache:0000000000000001".to_string(),
            true,
            0,
            1000,
            5000,
            0,
            one_entry_budget,
        );
        cache.insert(
            "cache:0000000000000002".to_string(),
            true,
            0,
            1001,
            5000,
            0,
            one_entry_budget,
        );

        assert_eq!(cache.len(), 1);
        assert!(cache.get_fresh("cache:0000000000000001", 2000).is_none());
        assert!(cache.get_fresh("cache:0000000000000002", 2000).is_some());
    }
}
