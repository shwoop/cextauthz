# Architecture Review Findings

This note captures implementation and architecture concerns found during a
static review of the current Proxy-Wasm ext_authz filter.

## Findings

### Unbounded Request Body Buffering

Severity: High

The filter buffers full request bodies before dispatching authorization checks
or handling cache invalidation. Large or slow request bodies can grow memory
usage inside the WASM VM and Envoy process. The buffered body is also copied
into both `body` and `raw_body` fields in the generated `CheckRequest`.

Relevant code:

- `src/lib.rs`: request body collection in `on_http_request_body`
- `src/request.rs`: `RequestParts::into_check_request`

Recommended direction: add a configurable maximum body size and define fail
closed behavior, such as returning `413 Payload Too Large` or authorizing on
headers only once the limit is reached.

### Incomplete ext_authz Response Handling

Severity: High

The filter classifies `OkHttpResponse` as allow and denied/error responses as
deny, but it discards most response details. Denied responses always return a
local `Forbidden` body instead of the authorization service response body, and
allowed responses cannot apply header mutations because the local protobuf
definition models `OkHttpResponse` as an empty message.

Relevant code:

- `src/lib.rs`: allow/deny response handling in `on_grpc_call_response`
- `src/pb.rs`: minimal `OkHttpResponse` and `DeniedHttpResponse` definitions

Recommended direction: expand the protobuf model and response application path
to support the ext_authz fields this project intends to honor, especially
denied response body and allowed response header mutations.

### Cache Key Policy Is Too Broad

Severity: Medium

Cache keys include all forwarded headers except `x-request-id`. This is safe
only if every included header can affect authorization decisions. In practice,
volatile headers such as tracing headers, `user-agent`, `accept`, and cookies
can significantly reduce cache hit rates. Future header filtering changes could
also accidentally widen decision reuse.

Relevant code:

- `src/cache.rs`: `compute_cache_key`

Recommended direction: make cache header policy explicit and configurable,
using an allowlist or denylist that matches the authorization service contract.

### Nondeterministic Cache Eviction

Severity: Medium

Shard quota enforcement removes the first key returned by `HashMap::keys()`.
That eviction order is arbitrary, so fresh or useful entries may be removed
before older entries. This makes cache behavior difficult to reason about under
load.

Relevant code:

- `src/cache.rs`: `enforce_quota`

Recommended direction: track insertion time, expiry time, or access time and
evict deterministically, for example oldest entry or nearest expiry.

### Configuration Values Need Validation

Severity: Medium

Configuration parsing accepts values that are probably operational mistakes,
including `timeout_ms = 0`, very large TTL values, and `cache.max_entries = 0`.
The current shard quota calculation also turns `max_entries = 0` into one entry
per shard, so zero does not mean no cache entries.

Relevant code:

- `src/config.rs`: `PluginSettings::from_json`
- `src/cache.rs`: `shard_quota`

Recommended direction: validate or clamp configuration during plugin
configuration, and reject values that do not have clear semantics.

### Hardcoded Authorization Cluster

Severity: Low

The gRPC authorization cluster is hardcoded to `ext_authz`. This works for the
local Envoy fixture but limits reuse in Envoy Gateway or other deployments
unless the exact cluster is created externally.

Relevant code:

- `src/lib.rs`: `GRPC_CLUSTER`

Recommended direction: make the cluster name configurable, with `ext_authz` as
the default.

### Floating Integration Fixture Images

Severity: Low

The integration fixture uses floating image tags for Envoy and the test
authorization service. This can cause integration behavior to drift over time.

Relevant code:

- `integration/docker-compose.yaml`

Recommended direction: pin image tags or digests for repeatable integration
test behavior.

## Overall Assessment

The module boundaries are clean and the pure Rust pieces are reasonably
testable. The main architectural risk is that the filter currently behaves as a
simplified ext_authz bridge rather than a close replacement for Envoy's native
ext_authz filter. The highest priority areas are request body limits, response
fidelity, and explicit cache policy.

## Resolution Plan

The findings in this review are addressed by
`docs/superpowers/plans/2026-05-28-address-architecture-review.md`. The
implementation intentionally supports a focused ext_authz response subset:
denied status, denied body, denied response headers, and allowed request-header
additions. It does not attempt to implement dynamic metadata, query parameter
mutation, or every field in Envoy's native ext_authz filter.
