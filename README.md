# cextauthz

`cextauthz` is a Rust 2024 Envoy Proxy-Wasm HTTP filter that delegates request
authorization to an Envoy `ext_authz` gRPC service.

The filter runs inside Envoy, converts incoming HTTP requests into
`envoy.service.auth.v3.CheckRequest` messages, calls the configured
authorization service, and either resumes the request or returns a local error
response. It also supports optional authorization decision caching in
Proxy-Wasm shared data, with an authenticated cache invalidation endpoint.

## Behavior

For each non-invalidation request, the filter:

1. Collects HTTP method, path, query, host, scheme, request ID, headers, and
   body.
2. Builds an Envoy ext_authz `CheckRequest`.
3. Optionally checks the local shared-data cache.
4. Dispatches a gRPC call to:
   - cluster: `ext_authz`
   - service: `envoy.service.auth.v3.Authorization`
   - method: `Check`
5. Allows the request when the authz service returns an `OkHttpResponse`.
6. Denies the request when the service returns a denied or error response.

Denied responses default to HTTP `403` when the authz response does not include
a status. Authz service dispatch failures and gRPC failures return HTTP `503`.
Malformed or empty authz responses return HTTP `500`.

## Configuration

The filter reads JSON from the Envoy Wasm plugin configuration. `grpc.cluster`
is required; the other fields are optional.

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

Defaults:

| Field | Default | Description |
| --- | --- | --- |
| `timeout_ms` | `1000` | gRPC authorization call timeout in milliseconds |
| `grpc.cluster` | required | Envoy cluster used for the ext_authz gRPC call |
| `request_body.max_bytes` | `1048576` | maximum buffered request body bytes before returning `413` |
| `cache.enabled` | `false` | enables shared-data decision caching |
| `cache.ttl_ms` | `60000` | cache entry TTL in milliseconds |
| `cache.max_entries` | `1000` | approximate maximum cache entries across shards |
| `cache.headers.mode` | `"all_except_request_id"` | header policy for cache-key construction: `all_except_request_id`, `allowlist`, or `denylist` |
| `cache.headers.names` | `[]` | header names used by `allowlist` or `denylist`; names are normalized to lowercase |
| `invalidation.secret` | `""` | required secret for cache invalidation requests |

Cache keys include method, path, host, scheme, query, headers, and request body.
The `x-request-id` header is ignored so otherwise identical requests can share a
decision when `cache.headers.mode` is `all_except_request_id`. Use `allowlist`
or `denylist` when only specific headers can affect authorization decisions, or
when volatile headers would reduce cache hit rates.

Configuration validation rejects:

- `timeout_ms = 0` or values above `60000`
- empty `grpc.cluster`
- `request_body.max_bytes = 0` or values above `16777216`
- enabled cache with `ttl_ms = 0`, `ttl_ms > 86400000`, or `max_entries = 0`
- empty cache header names

Request bodies larger than `request_body.max_bytes` fail closed with `413
Payload Too Large`. Denied ext_authz responses propagate the returned HTTP
status, body, and response headers. Allowed ext_authz responses apply returned
request-header additions before forwarding upstream.

## Cache Invalidation

When `invalidation.secret` is configured, clients can purge cached decisions via:

```text
POST /_cextauthz/cache/invalidate
```

The request must include:

```text
x-cextauthz-invalidation-secret: <configured-secret>
```

Purge all cache entries:

```json
{"version":1,"op":"purge_all"}
```

Purge one cache key:

```json
{"version":1,"op":"purge_key","key":"cache:0000000000000001"}
```

Unauthorized invalidation requests return `401`. Malformed invalidation JSON
returns `400`. Successful invalidation returns `204`.

## Project Layout

```text
src/
  lib.rs            Proxy-Wasm filter entry point and request flow
  config.rs         plugin configuration parsing and defaults
  request.rs        HTTP request to CheckRequest conversion
  decision.rs       CheckResponse allow/deny classification
  cache.rs          shared-data cache keys, shards, entries, and eviction
  invalidation.rs   cache invalidation request parsing and validation
  pb.rs             minimal Prost definitions for ext_authz messages
integration/
  docker-compose.yaml
  envoy.yaml
tests/
  integration_test.rs
```

## Prerequisites

- Rust toolchain with the 2024 edition
- `wasm32-unknown-unknown` Rust target
- Docker and Docker Compose for integration tests
- Free local port `10000` for the integration Envoy listener

The build script installs the WASM target automatically if it is missing.

## Build

Check the native crate:

```sh
cargo check
```

Check the WASM target:

```sh
cargo check --target wasm32-unknown-unknown
```

Build the release WASM module:

```sh
./build.sh
```

The Envoy-loadable artifact is written to:

```text
target/wasm32-unknown-unknown/release/cextauthz.wasm
```

## Run Locally

Build the WASM module first:

```sh
./build.sh
```

Start the integration stack:

```sh
docker compose -f integration/docker-compose.yaml up
```

The stack runs:

- Envoy on `http://localhost:10000`
- nginx as the upstream service
- `istio/ext-authz:1.30.0-debug` as the authz service

Example denied request:

```sh
curl -i http://localhost:10000/
```

Example allowed request:

```sh
curl -i -H 'x-ext-authz: allow' http://localhost:10000/
```

Example cache invalidation:

```sh
curl -i \
  -X POST http://localhost:10000/_cextauthz/cache/invalidate \
  -H 'x-cextauthz-invalidation-secret: integration-secret' \
  -d '{"version":1,"op":"purge_all"}'
```

Stop the stack:

```sh
docker compose -f integration/docker-compose.yaml down -v
```

## Deploy with Envoy Gateway

When Envoy Gateway is running in Kubernetes, attach this filter with an
`EnvoyExtensionPolicy`. The policy can target either a `Gateway` or an
`HTTPRoute`. The WASM module can be fetched from an HTTP URL, including a
GitHub release asset URL, as long as the Envoy proxy pods can reach it.

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: cextauthz
  namespace: default
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-route
  wasm:
    - name: cextauthz
      rootID: cextauthz_root
      failOpen: false
      config:
        timeout_ms: 1000
        grpc:
          cluster: ext_authz
        request_body:
          max_bytes: 1048576
        cache:
          enabled: true
          ttl_ms: 60000
          max_entries: 1000
          headers:
            mode: all_except_request_id
            names: []
        invalidation:
          secret: change-me
      code:
        type: HTTP
        http:
          url: https://github.com/YOUR_ORG/cextauthz/releases/download/v0.1.0/cextauthz.wasm
          sha256: "<64-char-sha256-of-the-wasm>"
```

Pin the release version and set `sha256` for production deployments. Without
`sha256`, Envoy Gateway can still fetch the module, but it will not verify the
downloaded WASM bytes.

This filter dispatches authorization checks to the Envoy cluster configured by
`grpc.cluster`. The local Docker fixture creates that cluster in
`integration/envoy.yaml`, but Envoy Gateway will not create it automatically
from the `EnvoyExtensionPolicy`. For Envoy Gateway deployments, add an
`EnvoyPatchPolicy` or other Envoy configuration that creates the cluster named
by `grpc.cluster` for your authorization service.

Envoy Gateway also supports packaging the WASM module as an OCI image and using
`code.type: Image` instead of an HTTP URL.

## Test

Run formatting checks:

```sh
cargo fmt --check
```

Run native checks:

```sh
cargo check
```

Run WASM checks:

```sh
cargo check --target wasm32-unknown-unknown
```

Run Docker-backed integration tests:

```sh
./build.sh
cargo test --test integration_test
```

The integration test starts and cleans up Docker Compose automatically. Port
`10000` must be free before the test starts.

## Development Notes

The crate is configured as both `cdylib` and `rlib`. The `cdylib` output is the
WASM module Envoy loads, while the `rlib` target keeps non-host-dependent logic
testable.

Proxy-Wasm host functions are only available inside the WASM host, so native
tests focus on pure Rust modules such as configuration parsing, request
construction, decision handling, cache helpers, and invalidation validation. Use
the integration test for end-to-end Envoy behavior.
