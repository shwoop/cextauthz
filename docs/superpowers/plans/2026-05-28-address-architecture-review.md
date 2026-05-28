# Address Architecture Review Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address every finding in `docs/architecture-review.md` while preserving current behavior by default where that behavior is already documented.

**Architecture:** Add explicit configuration for request body limits, cache-key headers, and the authorization cluster. Expand the minimal ext_authz response model enough to honor denied response details and allowed request-header mutations, and persist those response effects in cache entries so cache hits behave like fresh authorization checks. Keep each change small, testable in native Rust where possible, and reserve Docker integration coverage for behavior that only Envoy can verify.

**Tech Stack:** Rust 2024, `proxy-wasm`, `prost`, `serde_json`, Docker Compose, Envoy, nginx, Istio sample ext_authz service.

---

## Branch Setup

This plan is written on branch `plan/address-architecture-review`. Implementation should happen on a new implementation branch from `main`, without using a worktree:

```bash
git switch main
git switch -c feat/address-architecture-review
```

## Files

- Modify: `src/config.rs`
  - Add plugin config fields for `grpc.cluster`, `request_body.max_bytes`, and `cache.headers`.
  - Replace raw `serde_json::Error` return with a small config error type that can represent parse and validation failures.
  - Validate timeout, body limit, cache TTL, cache capacity, and cache header policy.
- Modify: `src/lib.rs`
  - Store the configured cluster name and request body limit in root and HTTP contexts.
  - Enforce body limit for normal requests and invalidation requests.
  - Dispatch gRPC calls to the configured cluster.
  - Apply allowed request-header mutations and denied response status/body/headers.
  - Store and replay cached response effects.
- Modify: `src/pb.rs`
  - Add the ext_authz response fields this crate will honor: allowed response headers to add, denied response headers to add, and denied body.
- Modify: `src/decision.rs`
  - Replace status-only decisions with a struct that carries status, body, response headers, and allowed request headers.
- Modify: `src/cache.rs`
  - Add explicit cache header policy.
  - Persist cached response effects.
  - Make quota eviction deterministic.
- Modify: `src/request.rs`
  - No structural change expected beyond tests if body limit enforcement stays in `src/lib.rs`.
- Modify: `src/invalidation.rs`
  - No parser change expected; invalidation body size is enforced before parsing.
- Modify: `README.md`
  - Document new config fields, limits, cache header policy, cluster configuration, and response behavior.
- Modify: `integration/envoy.yaml`
  - Update plugin config with explicit defaults used by integration tests.
  - Add an alternate authz cluster if needed by the cluster-name integration test.
- Modify: `integration/docker-compose.yaml`
  - Replace floating fixture images with pinned version tags or digests.
- Modify: `tests/integration_test.rs`
  - Add end-to-end tests for body limits and configured fixture behavior.

---

### Task 1: Validate Configuration and Add New Config Shape

**Files:**
- Modify: `src/config.rs`
- Test: `src/config.rs`

- [ ] **Step 1: Write failing config tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `src/config.rs`:

```rust
#[test]
fn parses_new_operational_settings() {
    let settings = PluginSettings::from_json(
        r#"{
            "timeout_ms": 250,
            "grpc": {"cluster": "custom_ext_authz"},
            "request_body": {"max_bytes": 4096},
            "cache": {
                "enabled": true,
                "ttl_ms": 5000,
                "max_entries": 32,
                "headers": {"mode": "allowlist", "names": ["authorization", "x-ext-authz"]}
            },
            "invalidation": {"secret": "secret"}
        }"#,
    )
    .unwrap();

    assert_eq!(settings.timeout_ms, 250);
    assert_eq!(settings.grpc_cluster, "custom_ext_authz");
    assert_eq!(settings.max_request_body_bytes, 4096);
    assert!(settings.cache.enabled);
    assert_eq!(settings.cache.ttl, Duration::from_millis(5000));
    assert_eq!(settings.cache.max_entries, 32);
    assert_eq!(
        settings.cache.header_policy,
        crate::cache::CacheHeaderPolicy::Allowlist(vec![
            "authorization".to_string(),
            "x-ext-authz".to_string(),
        ])
    );
    assert_eq!(settings.invalidation_secret, "secret");
}

#[test]
fn defaults_preserve_current_behavior_with_safe_body_limit() {
    let settings = PluginSettings::from_json("{}").unwrap();

    assert_eq!(settings.timeout_ms, 1000);
    assert_eq!(settings.grpc_cluster, "ext_authz");
    assert_eq!(settings.max_request_body_bytes, 1_048_576);
    assert_eq!(settings.cache.header_policy, crate::cache::CacheHeaderPolicy::AllExceptRequestId);
}

#[test]
fn rejects_zero_timeout() {
    let err = PluginSettings::from_json(r#"{"timeout_ms":0}"#).unwrap_err();
    assert_eq!(err.to_string(), "timeout_ms must be between 1 and 60000");
}

#[test]
fn rejects_empty_grpc_cluster() {
    let err = PluginSettings::from_json(r#"{"grpc":{"cluster":""}}"#).unwrap_err();
    assert_eq!(err.to_string(), "grpc.cluster must not be empty");
}

#[test]
fn rejects_zero_body_limit() {
    let err = PluginSettings::from_json(r#"{"request_body":{"max_bytes":0}}"#).unwrap_err();
    assert_eq!(
        err.to_string(),
        "request_body.max_bytes must be between 1 and 16777216"
    );
}

#[test]
fn rejects_enabled_cache_with_zero_ttl() {
    let err = PluginSettings::from_json(
        r#"{"cache":{"enabled":true,"ttl_ms":0,"max_entries":10}}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "cache.ttl_ms must be between 1 and 86400000 when cache is enabled");
}

#[test]
fn rejects_enabled_cache_with_zero_entries() {
    let err = PluginSettings::from_json(
        r#"{"cache":{"enabled":true,"ttl_ms":1000,"max_entries":0}}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "cache.max_entries must be greater than 0 when cache is enabled");
}

#[test]
fn rejects_empty_cache_header_name() {
    let err = PluginSettings::from_json(
        r#"{"cache":{"headers":{"mode":"denylist","names":[""]}}}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "cache.headers.names must contain non-empty header names");
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test config --lib
```

Expected: compile failure because `grpc_cluster`, `max_request_body_bytes`, `CacheHeaderPolicy`, and `ConfigError` do not exist yet.

- [ ] **Step 3: Implement config parsing and validation**

Update `src/config.rs` with these shapes and constants:

```rust
use std::fmt;
use std::time::Duration;

const DEFAULT_GRPC_CLUSTER: &str = "ext_authz";
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CACHE_TTL_MS: u64 = 86_400_000;

#[derive(Clone, Debug, PartialEq)]
pub struct PluginSettings {
    pub timeout_ms: u64,
    pub grpc_cluster: String,
    pub max_request_body_bytes: usize,
    pub cache: crate::cache::CacheConfig,
    pub invalidation_secret: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Json(serde_json::Error),
    Validation(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "{err}"),
            Self::Validation(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<serde_json::Error> for ConfigError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(serde::Deserialize)]
struct PluginConfigJson {
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    grpc: GrpcConfigJson,
    #[serde(default)]
    request_body: RequestBodyConfigJson,
    #[serde(default)]
    cache: CacheConfigJson,
    #[serde(default)]
    invalidation: InvalidationConfigJson,
}

#[derive(serde::Deserialize)]
struct GrpcConfigJson {
    #[serde(default = "default_grpc_cluster")]
    cluster: String,
}

impl Default for GrpcConfigJson {
    fn default() -> Self {
        Self {
            cluster: default_grpc_cluster(),
        }
    }
}

#[derive(serde::Deserialize)]
struct RequestBodyConfigJson {
    #[serde(default = "default_max_request_body_bytes")]
    max_bytes: usize,
}

impl Default for RequestBodyConfigJson {
    fn default() -> Self {
        Self {
            max_bytes: default_max_request_body_bytes(),
        }
    }
}
```

Also extend `CacheConfigJson` with:

```rust
#[serde(default)]
headers: CacheHeadersConfigJson,
```

and add:

```rust
#[derive(serde::Deserialize)]
struct CacheHeadersConfigJson {
    #[serde(default = "default_cache_header_mode")]
    mode: String,
    #[serde(default)]
    names: Vec<String>,
}

impl Default for CacheHeadersConfigJson {
    fn default() -> Self {
        Self {
            mode: default_cache_header_mode(),
            names: Vec::new(),
        }
    }
}

fn default_grpc_cluster() -> String {
    DEFAULT_GRPC_CLUSTER.to_string()
}

fn default_max_request_body_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BODY_BYTES
}

fn default_cache_header_mode() -> String {
    "all_except_request_id".to_string()
}
```

Change `PluginSettings::from_json` to return `Result<Self, ConfigError>`, normalize header names to lowercase, and validate:

```rust
impl PluginSettings {
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let config = serde_json::from_str::<PluginConfigJson>(text)?;

        if config.timeout_ms == 0 || config.timeout_ms > MAX_TIMEOUT_MS {
            return Err(ConfigError::Validation("timeout_ms must be between 1 and 60000"));
        }
        if config.grpc.cluster.trim().is_empty() {
            return Err(ConfigError::Validation("grpc.cluster must not be empty"));
        }
        if config.request_body.max_bytes == 0
            || config.request_body.max_bytes > MAX_REQUEST_BODY_BYTES
        {
            return Err(ConfigError::Validation(
                "request_body.max_bytes must be between 1 and 16777216",
            ));
        }
        if config.cache.enabled {
            if config.cache.ttl_ms == 0 || config.cache.ttl_ms > MAX_CACHE_TTL_MS {
                return Err(ConfigError::Validation(
                    "cache.ttl_ms must be between 1 and 86400000 when cache is enabled",
                ));
            }
            if config.cache.max_entries == 0 {
                return Err(ConfigError::Validation(
                    "cache.max_entries must be greater than 0 when cache is enabled",
                ));
            }
        }

        let header_names = normalize_header_names(config.cache.headers.names)?;
        let header_policy = match config.cache.headers.mode.as_str() {
            "all_except_request_id" => crate::cache::CacheHeaderPolicy::AllExceptRequestId,
            "allowlist" => crate::cache::CacheHeaderPolicy::Allowlist(header_names),
            "denylist" => crate::cache::CacheHeaderPolicy::Denylist(header_names),
            _ => {
                return Err(ConfigError::Validation(
                    "cache.headers.mode must be all_except_request_id, allowlist, or denylist",
                ));
            }
        };

        Ok(Self {
            timeout_ms: config.timeout_ms,
            grpc_cluster: config.grpc.cluster,
            max_request_body_bytes: config.request_body.max_bytes,
            cache: crate::cache::CacheConfig {
                enabled: config.cache.enabled,
                ttl: Duration::from_millis(config.cache.ttl_ms),
                max_entries: config.cache.max_entries,
                header_policy,
            },
            invalidation_secret: config.invalidation.secret,
        })
    }
}

fn normalize_header_names(names: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let mut normalized = Vec::with_capacity(names.len());
    for name in names {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(ConfigError::Validation(
                "cache.headers.names must contain non-empty header names",
            ));
        }
        normalized.push(name);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}
```

Update `Default for PluginSettings` to include `grpc_cluster` and `max_request_body_bytes`.

In `src/cache.rs`, add the config-facing policy type and default field now so `src/config.rs` compiles:

```rust
#[derive(Clone, Debug, PartialEq)]
pub enum CacheHeaderPolicy {
    AllExceptRequestId,
    Allowlist(Vec<String>),
    Denylist(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: Duration,
    pub max_entries: usize,
    pub header_policy: CacheHeaderPolicy,
}
```

Update `CacheConfig::default()`:

```rust
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
```

- [ ] **Step 4: Run config tests**

Run:

```bash
cargo test config --lib
```

Expected: all config tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/cache.rs
git commit -m "feat: validate plugin configuration"
```

---

### Task 2: Add Cache Header Policy and Deterministic Eviction

**Files:**
- Modify: `src/cache.rs`
- Test: `src/cache.rs`

- [ ] **Step 1: Write failing cache policy and eviction tests**

Add to `src/cache.rs` tests:

```rust
#[test]
fn key_uses_allowlisted_headers_only() {
    let mut headers_a = HashMap::new();
    headers_a.insert("authorization".to_string(), "Bearer a".to_string());
    headers_a.insert("user-agent".to_string(), "agent-a".to_string());

    let mut headers_b = headers_a.clone();
    headers_b.insert("user-agent".to_string(), "agent-b".to_string());

    let policy = CacheHeaderPolicy::Allowlist(vec!["authorization".to_string()]);

    assert_eq!(
        compute_cache_key(&request_with_headers(headers_a), &policy),
        compute_cache_key(&request_with_headers(headers_b), &policy)
    );
}

#[test]
fn key_uses_denylist_to_ignore_volatile_headers() {
    let mut headers_a = HashMap::new();
    headers_a.insert("authorization".to_string(), "Bearer a".to_string());
    headers_a.insert("traceparent".to_string(), "trace-a".to_string());

    let mut headers_b = headers_a.clone();
    headers_b.insert("traceparent".to_string(), "trace-b".to_string());

    let policy = CacheHeaderPolicy::Denylist(vec!["traceparent".to_string()]);

    assert_eq!(
        compute_cache_key(&request_with_headers(headers_a), &policy),
        compute_cache_key(&request_with_headers(headers_b), &policy)
    );
}

#[test]
fn quota_evicts_nearest_expiry_then_key_order() {
    let mut shard = CacheShard::default();
    shard.entries.insert(
        "cache:b".to_string(),
        CacheEntry {
            expires_at_ms: 200,
            allowed: true,
            denied_status: 0,
            denied_body: String::new(),
            response_headers: Vec::new(),
            request_headers: Vec::new(),
        },
    );
    shard.entries.insert(
        "cache:a".to_string(),
        CacheEntry {
            expires_at_ms: 100,
            allowed: true,
            denied_status: 0,
            denied_body: String::new(),
            response_headers: Vec::new(),
            request_headers: Vec::new(),
        },
    );
    shard.entries.insert(
        "cache:c".to_string(),
        CacheEntry {
            expires_at_ms: 200,
            allowed: true,
            denied_status: 0,
            denied_body: String::new(),
            response_headers: Vec::new(),
            request_headers: Vec::new(),
        },
    );

    enforce_quota(&mut shard, 1);

    assert_eq!(shard.entries.keys().cloned().collect::<Vec<_>>(), vec!["cache:c"]);
}
```

Add this helper inside the test module:

```rust
fn request_with_headers(headers: HashMap<String, String>) -> crate::pb::CheckRequest {
    crate::pb::CheckRequest {
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
    }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test cache --lib
```

Expected: compile failure because new `CacheEntry` fields and the new `compute_cache_key` signature do not exist.

- [ ] **Step 3: Implement cache header policy and deterministic eviction**

The `CacheHeaderPolicy` enum and `CacheConfig.header_policy` field were introduced in Task 1. Keep that type and add cache-key behavior here.

Add reusable response-effect protobuf messages:

```rust
#[derive(Clone, PartialEq, Message)]
pub struct CachedHeader {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}
```

Extend `CacheEntry`:

```rust
#[prost(string, tag = "4")]
pub denied_body: String,
#[prost(message, repeated, tag = "5")]
pub response_headers: Vec<CachedHeader>,
#[prost(message, repeated, tag = "6")]
pub request_headers: Vec<CachedHeader>,
```

Change the cache key signature:

```rust
pub fn compute_cache_key(
    req: &crate::pb::CheckRequest,
    header_policy: &CacheHeaderPolicy,
) -> String
```

Use this filter inside `compute_cache_key`:

```rust
fn include_header(name: &str, policy: &CacheHeaderPolicy) -> bool {
    match policy {
        CacheHeaderPolicy::AllExceptRequestId => !name.eq_ignore_ascii_case("x-request-id"),
        CacheHeaderPolicy::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        CacheHeaderPolicy::Denylist(names) => {
            !name.eq_ignore_ascii_case("x-request-id")
                && !names.iter().any(|denied| denied == name)
        }
    }
}
```

Apply it with normalized names:

```rust
.filter_map(|(name, value)| {
    let normalized = name.to_ascii_lowercase();
    if include_header(&normalized, header_policy) {
        Some((normalized, value.as_str()))
    } else {
        None
    }
})
```

Change `CacheKeyInput.headers` to own normalized header names:

```rust
headers: Vec<(String, &'a str)>,
```

Replace `enforce_quota` with deterministic eviction:

```rust
pub fn enforce_quota(shard: &mut CacheShard, quota: usize) {
    while shard.entries.len() > quota {
        let Some(key) = shard
            .entries
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.expires_at_ms
                    .cmp(&right.expires_at_ms)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _entry)| key.clone())
        else {
            break;
        };
        shard.entries.remove(&key);
    }
}
```

Update existing tests to pass `&CacheHeaderPolicy::AllExceptRequestId` and populate new `CacheEntry` fields.

- [ ] **Step 4: Run cache tests**

Run:

```bash
cargo test cache --lib
```

Expected: all cache tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cache.rs
git commit -m "feat: make cache policy explicit"
```

---

### Task 3: Enforce Request Body Limits

**Files:**
- Modify: `src/lib.rs`
- Test: `src/lib.rs` through WASM check and integration test
- Modify: `tests/integration_test.rs`
- Modify: `integration/envoy.yaml`

- [ ] **Step 1: Add integration test for fail-closed body limit**

In `tests/integration_test.rs`, add:

```rust
#[test]
fn oversized_request_body_is_rejected_before_authz_call() {
    let _env = setup_compose();
    let client = envoy_client();

    let body = "x".repeat(2048);
    let response = client
        .post(format!("{ENVOY_URL}/"))
        .header("x-ext-authz", "allow")
        .body(body)
        .send()
        .expect("Failed to send oversized request to Envoy");

    assert_eq!(response.status(), 413);
    assert_eq!(response.text().unwrap(), "Payload Too Large");
}
```

In `integration/envoy.yaml`, set plugin config for this test environment:

```yaml
request_body:
  max_bytes: 1024
```

- [ ] **Step 2: Run integration test and verify failure**

Run:

```bash
./build.sh
cargo test --test integration_test oversized_request_body_is_rejected_before_authz_call
```

Expected: test fails because oversized bodies are currently buffered and sent to authz.

- [ ] **Step 3: Implement fail-closed body limit**

In `src/lib.rs`, add `grpc_cluster` and `max_request_body_bytes` to `AuthzRoot` and `AuthzHttp`:

```rust
grpc_cluster: String,
max_request_body_bytes: usize,
```

Initialize both from `PluginSettings::default()` and parsed settings.

Add this method on `AuthzHttp`:

```rust
fn reject_payload_too_large(&mut self) -> Action {
    self.dispatched = true;
    self.send_http_response(
        413,
        vec![("content-type", "text/plain")],
        Some(b"Payload Too Large"),
    );
    Action::Pause
}
```

In `on_http_request_body`, before reading new bytes:

```rust
if body_size > self.max_request_body_bytes {
    return self.reject_payload_too_large();
}
```

This limit intentionally covers both regular authorization requests and cache invalidation requests.

- [ ] **Step 4: Run verification**

Run:

```bash
cargo check
cargo check --target wasm32-unknown-unknown
./build.sh
cargo test --test integration_test oversized_request_body_is_rejected_before_authz_call
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs integration/envoy.yaml tests/integration_test.rs
git commit -m "feat: limit buffered request bodies"
```

---

### Task 4: Honor ext_authz Response Details

**Files:**
- Modify: `src/pb.rs`
- Modify: `src/decision.rs`
- Modify: `src/lib.rs`
- Test: `src/decision.rs`
- Test: `src/decision.rs`

- [ ] **Step 1: Write failing decision tests**

In `src/decision.rs`, replace the status-only assertions with tests like:

```rust
#[test]
fn denied_response_carries_status_body_and_headers() {
    let response = crate::pb::CheckResponse {
        status: None,
        http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
            crate::pb::DeniedHttpResponse {
                status: Some(crate::pb::HttpStatus { code: 401 }),
                headers: vec![crate::pb::HeaderValueOption {
                    header: Some(crate::pb::HeaderValue {
                        key: "www-authenticate".to_string(),
                        value: "Bearer".to_string(),
                    }),
                }],
                body: "missing token".to_string(),
            },
        )),
    };

    assert_eq!(
        AuthorizationDecision::from_check_response(&response),
        AuthorizationDecision::Deny {
            status: 401,
            body: "missing token".to_string(),
            headers: vec![("www-authenticate".to_string(), "Bearer".to_string())],
        }
    );
}

#[test]
fn ok_response_carries_request_header_mutations() {
    let response = crate::pb::CheckResponse {
        status: None,
        http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
            crate::pb::OkHttpResponse {
                headers: vec![crate::pb::HeaderValueOption {
                    header: Some(crate::pb::HeaderValue {
                        key: "x-authz-user".to_string(),
                        value: "alice".to_string(),
                    }),
                }],
            },
        )),
    };

    assert_eq!(
        AuthorizationDecision::from_check_response(&response),
        AuthorizationDecision::Allow {
            request_headers: vec![("x-authz-user".to_string(), "alice".to_string())],
        }
    );
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test decision --lib
```

Expected: compile failure because `HeaderValueOption`, `HeaderValue`, and enriched `AuthorizationDecision` variants do not exist.

- [ ] **Step 3: Expand protobuf model**

In `src/pb.rs`, add:

```rust
#[derive(Clone, PartialEq, Message)]
pub struct HeaderValueOption {
    #[prost(message, optional, tag = "1")]
    pub header: Option<HeaderValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HeaderValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}
```

Update responses:

```rust
#[derive(Clone, PartialEq, Message)]
pub struct DeniedHttpResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<HttpStatus>,
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
    #[prost(string, tag = "3")]
    pub body: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct OkHttpResponse {
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
}
```

- [ ] **Step 4: Enrich authorization decisions**

In `src/decision.rs`, change the enum:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow {
        request_headers: Vec<(String, String)>,
    },
    Deny {
        status: u32,
        body: String,
        headers: Vec<(String, String)>,
    },
}
```

Add helper:

```rust
fn header_pairs(headers: &[crate::pb::HeaderValueOption]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|option| option.header.as_ref())
        .filter(|header| !header.key.is_empty())
        .map(|header| (header.key.to_ascii_lowercase(), header.value.clone()))
        .collect()
}
```

Use body fallback:

```rust
let body = if denied.body.is_empty() {
    "Forbidden".to_string()
} else {
    denied.body.clone()
};
```

- [ ] **Step 5: Apply response effects in the filter**

In `src/lib.rs`, replace status-only handling with:

```rust
match decision {
    crate::decision::AuthorizationDecision::Allow { request_headers } => {
        if self.cache_config.enabled {
            self.store_cache_entry(true, 0, "", &[], &request_headers);
        }
        self.apply_request_headers(&request_headers);
        self.resume_http_request();
    }
    crate::decision::AuthorizationDecision::Deny {
        status,
        body,
        headers,
    } => {
        if self.cache_config.enabled {
            self.store_cache_entry(false, status, &body, &headers, &[]);
        }
        self.send_http_response(
            status,
            response_headers_for_local_reply(&headers),
            Some(body.as_bytes()),
        );
    }
}
```

Add helpers:

```rust
fn apply_request_headers(&self, headers: &[(String, String)]) {
    for (name, value) in headers {
        self.set_http_request_header(name, Some(value));
    }
}

fn response_headers_for_local_reply(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    } else {
        let mut local_headers = Vec::with_capacity(headers.len() + 1);
        local_headers.push(("content-type", "text/plain"));
        local_headers.extend(headers.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        local_headers
    }
}
```

If the helper lifetime does not compile as a free function, keep the vector construction inline in the deny branch so borrowed `String` values live through `send_http_response`.

- [ ] **Step 6: Run unit tests**

Run:

```bash
cargo test decision --lib
cargo check --target wasm32-unknown-unknown
```

Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add src/pb.rs src/decision.rs src/lib.rs tests/integration_test.rs
git commit -m "feat: honor authz response details"
```

---

### Task 5: Replay Cached Response Effects

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/cache.rs`
- Test: `src/cache.rs`
- Test: `tests/integration_test.rs`

- [ ] **Step 1: Write cache entry conversion tests**

In `src/cache.rs`, add:

```rust
#[test]
fn cache_entry_can_store_response_effects() {
    let entry = CacheEntry {
        expires_at_ms: 1000,
        allowed: false,
        denied_status: 401,
        denied_body: "missing token".to_string(),
        response_headers: vec![CachedHeader {
            name: "www-authenticate".to_string(),
            value: "Bearer".to_string(),
        }],
        request_headers: Vec::new(),
    };

    assert_eq!(entry.denied_body, "missing token");
    assert_eq!(entry.response_headers[0].name, "www-authenticate");
    assert_eq!(entry.response_headers[0].value, "Bearer");
}
```

- [ ] **Step 2: Run tests and verify failure if Task 2 did not already add fields**

Run:

```bash
cargo test cache_entry_can_store_response_effects --lib
```

Expected: pass if Task 2 already added the fields, otherwise compile failure.

- [ ] **Step 3: Update cache write and hit paths**

Change `store_cache_entry` in `src/lib.rs` to accept response effects:

```rust
fn store_cache_entry(
    &self,
    allowed: bool,
    denied_status: u32,
    denied_body: &str,
    response_headers: &[(String, String)],
    request_headers: &[(String, String)],
)
```

When inserting:

```rust
crate::cache::CacheEntry {
    expires_at_ms,
    allowed,
    denied_status,
    denied_body: denied_body.to_string(),
    response_headers: response_headers
        .iter()
        .map(|(name, value)| crate::cache::CachedHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect(),
    request_headers: request_headers
        .iter()
        .map(|(name, value)| crate::cache::CachedHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect(),
}
```

On a cache hit:

```rust
if entry.allowed {
    let request_headers = cached_headers_to_pairs(&entry.request_headers);
    self.apply_request_headers(&request_headers);
    return Action::Continue;
}
let response_headers = cached_headers_to_pairs(&entry.response_headers);
let body = if entry.denied_body.is_empty() {
    "Forbidden"
} else {
    entry.denied_body.as_str()
};
self.send_http_response(
    entry.denied_status,
    response_headers_for_local_reply(&response_headers),
    Some(body.as_bytes()),
);
return Action::Pause;
```

Add:

```rust
fn cached_headers_to_pairs(headers: &[crate::cache::CachedHeader]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect()
}
```

- [ ] **Step 4: Use configured cache header policy**

In `dispatch_check_request`, change:

```rust
let cache_key = crate::cache::compute_cache_key(&check_req);
```

to:

```rust
let cache_key =
    crate::cache::compute_cache_key(&check_req, &self.cache_config.header_policy);
```

- [ ] **Step 5: Run verification**

Run:

```bash
cargo test cache --lib
cargo test decision --lib
cargo check --target wasm32-unknown-unknown
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/cache.rs
git commit -m "feat: replay cached authz response effects"
```

---

### Task 6: Make Authorization Cluster Configurable

**Files:**
- Modify: `src/lib.rs`
- Modify: `integration/envoy.yaml`
- Test: `tests/integration_test.rs`

- [ ] **Step 1: Write integration fixture config**

In `integration/envoy.yaml`, configure the plugin with:

```yaml
grpc:
  cluster: ext_authz
```

This keeps the existing fixture behavior explicit.

- [ ] **Step 2: Replace hardcoded cluster dispatch**

In `src/lib.rs`, remove:

```rust
const GRPC_CLUSTER: &str = "ext_authz";
```

Change the dispatch call:

```rust
self.dispatch_grpc_call(
    self.grpc_cluster.as_str(),
    GRPC_SERVICE,
    GRPC_METHOD,
    vec![],
    Some(&buf),
    self.timeout,
)
```

Root initialization and `create_http_context` should clone the configured cluster into each `AuthzHttp`.

- [ ] **Step 3: Run verification**

Run:

```bash
cargo check
cargo check --target wasm32-unknown-unknown
./build.sh
cargo test --test integration_test cache_hit_survives_authz_outage_until_purge_all
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs integration/envoy.yaml tests/integration_test.rs
git commit -m "feat: configure authz grpc cluster"
```

---

### Task 7: Pin Integration Fixture Images

**Files:**
- Modify: `integration/docker-compose.yaml`
- Test: Docker Compose pull/up through integration test

- [ ] **Step 1: Update images to non-floating references**

Replace:

```yaml
image: nginx:alpine
image: registry.istio.io/testing/ext-authz:latest
image: envoyproxy/envoy:v1.30-latest
```

with:

```yaml
image: nginx:1.27.5-alpine
image: istio/ext-authz:1.30.0-debug
image: envoyproxy/envoy:v1.30.11
```

Do not fall back to `latest`. If a pinned tag is unavailable in the implementation environment, replace it with a pullable pinned digest for the same image family and document the exact digest in the commit message.

- [ ] **Step 2: Pull fixture images**

Run:

```bash
docker compose -f integration/docker-compose.yaml pull
```

Expected: all three images pull successfully.

- [ ] **Step 3: Run one Docker-backed integration test**

Run:

```bash
./build.sh
cargo test --test integration_test invalidation_rejects_wrong_secret
```

Expected: test passes with the pinned images.

- [ ] **Step 4: Commit**

```bash
git add integration/docker-compose.yaml
git commit -m "test: pin integration fixture images"
```

---

### Task 8: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture-review.md`

- [ ] **Step 1: Update README configuration example**

Change the JSON example in `README.md` to:

```json
{
  "timeout_ms": 1000,
  "grpc": {
    "cluster": "ext_authz"
  },
  "request_body": {
    "max_bytes": 1048576
  },
  "cache": {
    "enabled": true,
    "ttl_ms": 60000,
    "max_entries": 1000,
    "headers": {
      "mode": "all_except_request_id",
      "names": []
    }
  },
  "invalidation": {
    "secret": "integration-secret"
  }
}
```

Update the defaults table:

```markdown
| `grpc.cluster` | `"ext_authz"` | Envoy cluster used for the ext_authz gRPC call |
| `request_body.max_bytes` | `1048576` | maximum buffered request body bytes before returning `413` |
| `cache.headers.mode` | `"all_except_request_id"` | header policy for cache-key construction: `all_except_request_id`, `allowlist`, or `denylist` |
| `cache.headers.names` | `[]` | header names used by `allowlist` or `denylist`; names are normalized to lowercase |
```

Document validation rules:

```markdown
Configuration validation rejects:

- `timeout_ms = 0` or values above `60000`
- empty `grpc.cluster`
- `request_body.max_bytes = 0` or values above `16777216`
- enabled cache with `ttl_ms = 0`, `ttl_ms > 86400000`, or `max_entries = 0`
- empty cache header names
```

Update behavior docs:

```markdown
Request bodies larger than `request_body.max_bytes` fail closed with `413 Payload Too Large`.
Denied ext_authz responses propagate the returned HTTP status, body, and response headers. Allowed ext_authz responses apply returned request-header additions before forwarding upstream.
```

- [ ] **Step 2: Update architecture review status**

Append a short status section to `docs/architecture-review.md`:

```markdown
## Resolution Plan

The findings in this review are addressed by
`docs/superpowers/plans/2026-05-28-address-architecture-review.md`.
The implementation intentionally supports a focused ext_authz response subset:
denied status/body/headers and allowed request-header additions. It does not
attempt to implement dynamic metadata, query parameter mutation, or every
field in Envoy's native ext_authz filter.
```

- [ ] **Step 3: Run docs-adjacent verification**

Run:

```bash
cargo fmt --check
cargo check
cargo check --target wasm32-unknown-unknown
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture-review.md
git commit -m "docs: document architecture review fixes"
```

---

### Task 9: Final Full Verification

**Files:**
- No new files expected.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --check
```

Expected: pass.

- [ ] **Step 2: Native check**

Run:

```bash
cargo check
```

Expected: pass.

- [ ] **Step 3: WASM check**

Run:

```bash
cargo check --target wasm32-unknown-unknown
```

Expected: pass.

- [ ] **Step 4: Build release WASM**

Run:

```bash
./build.sh
```

Expected: prints `target/wasm32-unknown-unknown/release/cextauthz.wasm`.

- [ ] **Step 5: Run Docker-backed integration tests**

Run:

```bash
cargo test --test integration_test
```

Expected: all integration tests pass. If this fails because ports `10000`, `9000`, or `8080` are occupied, stop the conflicting local service and rerun; do not mark the branch complete until the integration suite passes.

- [ ] **Step 6: Review final diff**

Run:

```bash
git diff main...HEAD
```

Expected: changes are limited to the files listed in this plan and all architecture review findings have a corresponding implementation.

- [ ] **Step 7: Commit any verification-only fixes**

If verification required small fixes:

```bash
git add <changed-files>
git commit -m "fix: complete architecture review remediation"
```

If no fixes were needed, do not create an empty commit.

---

## Self-Review

- Spec coverage: every finding in `docs/architecture-review.md` maps to a task:
  - Unbounded body buffering: Task 3.
  - Incomplete response handling: Tasks 4 and 5.
  - Broad cache key policy: Tasks 1, 2, and 5.
  - Nondeterministic eviction: Task 2.
  - Configuration validation: Task 1.
  - Hardcoded cluster: Task 6.
  - Floating fixture images: Task 7.
- Placeholder scan: no planned implementation step depends on an unspecified function name or future design choice. The only conditional path is the ext_authz image reference fallback, which is constrained to a versioned non-`latest` tag.
- Type consistency: `CacheHeaderPolicy`, `CachedHeader`, enriched `CacheEntry`, and enriched `AuthorizationDecision` are introduced before later tasks consume them.
- Scope: the plan deliberately avoids full native ext_authz parity. It implements the response fields this crate intends to honor and documents the unsupported subset.
