pub mod cache;
pub mod invalidation;
pub mod pb;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use prost::Message;
    use proxy_wasm::traits::*;
    use proxy_wasm::types::*;
    use std::collections::HashMap;
    use std::time::Duration;

    const GRPC_CLUSTER: &str = "ext_authz";
    const GRPC_SERVICE: &str = "envoy.service.auth.v3.Authorization";
    const GRPC_METHOD: &str = "Check";

    #[derive(serde::Deserialize)]
    struct PluginConfig {
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        cache: CacheConfigJson,
    }

    #[derive(serde::Deserialize, Default)]
    struct CacheConfigJson {
        #[serde(default)]
        enabled: bool,
        #[serde(default = "default_cache_ttl_ms")]
        ttl_ms: u64,
        #[serde(default = "default_cache_max_size")]
        max_size: usize,
    }

    fn default_timeout_ms() -> u64 {
        1000
    }
    fn default_cache_ttl_ms() -> u64 {
        60000
    }
    fn default_cache_max_size() -> usize {
        1000
    }

    pub struct AuthzRoot {
        timeout_ms: u64,
        cache_config: crate::cache::CacheConfig,
    }

    pub struct AuthzHttp {
        pub grpc_token: Option<u32>,
        pub timeout: std::time::Duration,
        dispatched: bool,
        method: String,
        path: String,
        query: String,
        host: String,
        scheme: String,
        request_id: String,
        headers: HashMap<String, String>,
        body_buf: Vec<u8>,
        cache_config: crate::cache::CacheConfig,
        cache_key: Option<String>,
    }

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(AuthzRoot {
                timeout_ms: 1000,
                cache_config: crate::cache::CacheConfig::default(),
            })
        });
    }}

    impl Context for AuthzRoot {}

    impl RootContext for AuthzRoot {
        fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
            if plugin_configuration_size == 0 {
                return true;
            }
            if let Some(config) = self.get_plugin_configuration()
                && let Ok(text) = std::str::from_utf8(&config)
            {
                let trimmed = text.trim();
                if let Ok(json_cfg) = serde_json::from_str::<PluginConfig>(trimmed) {
                    self.timeout_ms = json_cfg.timeout_ms;
                    self.cache_config = crate::cache::CacheConfig {
                        enabled: json_cfg.cache.enabled,
                        ttl: Duration::from_millis(json_cfg.cache.ttl_ms),
                        max_size: json_cfg.cache.max_size,
                    };
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!(
                            "ext_authz: timeout={} ms, cache_enabled={}, cache_ttl={} ms, cache_max_size={}",
                            self.timeout_ms,
                            self.cache_config.enabled,
                            json_cfg.cache.ttl_ms,
                            self.cache_config.max_size
                        ),
                    );
                } else if let Ok(ms) = trimmed.parse::<u64>() {
                    // Backward compatibility: raw u64 milliseconds
                    self.timeout_ms = ms;
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!("ext_authz: timeout configured to {} ms", self.timeout_ms),
                    );
                } else {
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        "ext_authz: plugin config is not valid JSON or u64; using defaults",
                    );
                }
            }
            true
        }

        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::HttpContext)
        }

        fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
            Some(Box::new(AuthzHttp {
                grpc_token: None,
                timeout: Duration::from_millis(self.timeout_ms),
                dispatched: false,
                method: String::new(),
                path: String::new(),
                query: String::new(),
                host: String::new(),
                scheme: String::new(),
                request_id: String::new(),
                headers: HashMap::new(),
                body_buf: Vec::new(),
                cache_config: self.cache_config.clone(),
                cache_key: None,
            }))
        }
    }

    impl Context for AuthzHttp {
        fn on_grpc_call_response(&mut self, token_id: u32, status_code: u32, response_size: usize) {
            if self.grpc_token != Some(token_id) {
                return;
            }
            self.grpc_token = None;

            if status_code != 0 {
                let msg = if status_code == 4 {
                    format!(
                        "ext_authz: gRPC call deadline exceeded (status {})",
                        status_code
                    )
                } else {
                    format!("ext_authz: gRPC call failed with status {}", status_code)
                };
                let _ = proxy_wasm::hostcalls::log(LogLevel::Error, &msg);
                self.send_http_response(
                    503,
                    vec![("content-type", "text/plain")],
                    Some(b"Authz service unavailable"),
                );
                return;
            }

            if let Some(body) = self.get_grpc_call_response_body(0, response_size) {
                match crate::pb::CheckResponse::decode(&body[..]) {
                    Ok(resp) => {
                        let allowed = matches!(
                            resp.http_response,
                            Some(crate::pb::check_response::HttpResponse::OkResponse(_))
                        );

                        if allowed {
                            let _ = proxy_wasm::hostcalls::log(
                                proxy_wasm::types::LogLevel::Info,
                                "ext_authz: request allowed",
                            );
                            self.cache_response_if_needed(&resp, allowed);
                            self.resume_http_request();
                        } else {
                            let _ = proxy_wasm::hostcalls::log(
                                proxy_wasm::types::LogLevel::Info,
                                "ext_authz: request denied",
                            );
                            let status = resp
                                .http_response
                                .as_ref()
                                .and_then(|r| {
                                    if let crate::pb::check_response::HttpResponse::DeniedResponse(
                                        d,
                                    ) = r
                                    {
                                        d.status.as_ref().map(|s| s.code as u32)
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(403);
                            self.cache_response_if_needed(&resp, allowed);
                            self.send_http_response(
                                status,
                                vec![("content-type", "text/plain")],
                                Some(b"Forbidden"),
                            );
                        }
                    }
                    Err(e) => {
                        let _ = proxy_wasm::hostcalls::log(
                            proxy_wasm::types::LogLevel::Error,
                            &format!("ext_authz: failed to decode CheckResponse: {}", e),
                        );
                        self.send_http_response(
                            500,
                            vec![("content-type", "text/plain")],
                            Some(b"Invalid authz response"),
                        );
                    }
                }
            } else {
                let _ = proxy_wasm::hostcalls::log(
                    proxy_wasm::types::LogLevel::Error,
                    "ext_authz: empty gRPC response body",
                );
                self.send_http_response(
                    500,
                    vec![("content-type", "text/plain")],
                    Some(b"Empty authz response"),
                );
            }
        }
    }

    impl HttpContext for AuthzHttp {
        fn on_http_request_headers(&mut self, num_headers: usize, end_of_stream: bool) -> Action {
            if self.dispatched {
                return Action::Pause;
            }

            self.headers = HashMap::with_capacity(num_headers.saturating_sub(4));

            for (name, value) in self.get_http_request_headers() {
                match name.as_str() {
                    ":method" => self.method = value,
                    ":path" => {
                        if let Some(pos) = value.find('?') {
                            self.path = value[..pos].to_string();
                            self.query = value[pos + 1..].to_string();
                        } else {
                            self.path = value;
                        }
                    }
                    ":authority" => self.host = value,
                    ":scheme" => self.scheme = value,
                    _ => {
                        if name.eq_ignore_ascii_case("x-request-id") {
                            self.request_id = value;
                        } else if !name.starts_with(':') {
                            self.headers.insert(name.to_lowercase(), value);
                        }
                    }
                }
            }

            if end_of_stream {
                self.dispatch_check_request()
            } else {
                Action::Pause
            }
        }

        fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
            if self.dispatched {
                return Action::Pause;
            }

            if body_size > 0 {
                if let Some(chunk) = self.get_http_request_body(0, body_size) {
                    self.body_buf.extend_from_slice(&chunk);
                }
            }

            if end_of_stream {
                self.dispatch_check_request()
            } else {
                Action::Pause
            }
        }

        fn on_log(&mut self) {
            let _ = proxy_wasm::hostcalls::log(LogLevel::Info, "ext_authz: request completed");
        }
    }

    impl AuthzHttp {
        fn dispatch_check_request(&mut self) -> Action {
            self.dispatched = true;

            // Build a temporary CheckRequest from clones to compute the cache key
            // BEFORE we consume self fields with std::mem::take.
            let cache_key = if self.cache_config.enabled {
                let temp_req = crate::pb::CheckRequest {
                    attributes: Some(crate::pb::AttributeContext {
                        source: None,
                        destination: None,
                        request: Some(crate::pb::Request {
                            http: Some(crate::pb::HttpRequest {
                                id: String::new(), // excluded from cache key
                                method: self.method.clone(),
                                headers: self.headers.clone(),
                                path: self.path.clone(),
                                host: self.host.clone(),
                                scheme: self.scheme.clone(),
                                query: self.query.clone(),
                                fragment: String::new(),
                                size: self.body_buf.len() as i64,
                                protocol: String::new(),
                                body: String::new(),
                                raw_body: self.body_buf.clone(),
                            }),
                        }),
                        context_extensions: HashMap::new(),
                    }),
                };
                let key = crate::cache::compute_cache_key(&temp_req);
                self.cache_key = Some(key.clone());
                Some(key)
            } else {
                None
            };

            // Check cache before dispatching gRPC call.
            if let Some(ref key) = cache_key {
                let shard_id = crate::cache::shard_id_from_key(key);
                let shard_key = crate::cache::shard_shared_key(shard_id);
                let (data, _cas) = self.get_shared_data(&shard_key);
                if let Some(bytes) = data {
                    if let Ok(shard) = crate::cache::CacheShard::decode(&bytes[..]) {
                        if let Some(entry) = shard.entries.get(key) {
                            let now_ms = self
                                .get_current_time()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            if entry.expires_at_ms > now_ms {
                                if entry.allowed {
                                    let _ = proxy_wasm::hostcalls::log(
                                        LogLevel::Info,
                                        "ext_authz: cache hit (allowed)",
                                    );
                                    return Action::Continue;
                                } else {
                                    let _ = proxy_wasm::hostcalls::log(
                                        LogLevel::Info,
                                        "ext_authz: cache hit (denied)",
                                    );
                                    self.send_http_response(
                                        entry.denied_status,
                                        vec![("content-type", "text/plain")],
                                        Some(b"Forbidden"),
                                    );
                                    return Action::Pause;
                                }
                            }
                        }
                    }
                }
            }

            let check_req = crate::pb::CheckRequest {
                attributes: Some(crate::pb::AttributeContext {
                    source: None,
                    destination: None,
                    request: Some(crate::pb::Request {
                        http: Some(crate::pb::HttpRequest {
                            id: std::mem::take(&mut self.request_id),
                            method: std::mem::take(&mut self.method),
                            headers: std::mem::take(&mut self.headers),
                            path: std::mem::take(&mut self.path),
                            host: std::mem::take(&mut self.host),
                            scheme: std::mem::take(&mut self.scheme),
                            query: std::mem::take(&mut self.query),
                            fragment: String::new(),
                            size: self.body_buf.len() as i64,
                            protocol: String::new(),
                            body: String::from_utf8_lossy(&self.body_buf).to_string(),
                            raw_body: std::mem::take(&mut self.body_buf),
                        }),
                    }),
                    context_extensions: HashMap::new(),
                }),
            };

            let mut buf = Vec::new();
            if check_req.encode(&mut buf).is_err() {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    "ext_authz: failed to encode CheckRequest",
                );
                self.send_http_response(
                    500,
                    vec![("content-type", "text/plain")],
                    Some(b"Failed to encode authz request"),
                );
                return Action::Pause;
            }

            match self.dispatch_grpc_call(
                GRPC_CLUSTER,
                GRPC_SERVICE,
                GRPC_METHOD,
                vec![],
                Some(&buf),
                self.timeout,
            ) {
                Ok(token) => {
                    self.grpc_token = Some(token);
                    Action::Pause
                }
                Err(e) => {
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        &format!("ext_authz: dispatch_grpc_call failed: {:?}", e),
                    );
                    self.send_http_response(
                        503,
                        vec![("content-type", "text/plain")],
                        Some(b"Authz service unavailable"),
                    );
                    Action::Pause
                }
            }
        }

        fn cache_response_if_needed(&mut self, resp: &crate::pb::CheckResponse, allowed: bool) {
            if !self.cache_config.enabled {
                return;
            }
            let Some(ref key) = self.cache_key else {
                return;
            };

            let denied_status = if allowed {
                0
            } else {
                resp.http_response
                    .as_ref()
                    .and_then(|r| {
                        if let crate::pb::check_response::HttpResponse::DeniedResponse(d) = r {
                            d.status.as_ref().map(|s| s.code as u32)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(403)
            };

            let shard_id = crate::cache::shard_id_from_key(key);
            let shard_key = crate::cache::shard_shared_key(shard_id);
            let quota = crate::cache::shard_quota(self.cache_config.max_size);

            for attempt in 0..3 {
                let (data, cas) = self.get_shared_data(&shard_key);
                let mut shard = data
                    .and_then(|b| crate::cache::CacheShard::decode(&b[..]).ok())
                    .unwrap_or_else(crate::cache::CacheShard::new);

                let now_ms = self
                    .get_current_time()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                // Evict expired entries.
                shard.entries.retain(|_k, v| v.expires_at_ms > now_ms);

                let expires_at_ms = now_ms.saturating_add(self.cache_config.ttl.as_millis() as u64);
                shard.entries.insert(
                    key.clone(),
                    crate::cache::CacheEntry {
                        expires_at_ms,
                        allowed,
                        denied_status,
                    },
                );

                // Enforce per-shard quota by dropping arbitrary entries.
                while shard.entries.len() > quota {
                    if let Some(k) = shard.entries.keys().next().cloned() {
                        shard.entries.remove(&k);
                    } else {
                        break;
                    }
                }

                let mut buf = Vec::new();
                if shard.encode(&mut buf).is_err() {
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        "ext_authz: failed to encode cache shard",
                    );
                    return;
                }

                match self.set_shared_data(&shard_key, Some(&buf), cas) {
                    Ok(()) => {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("ext_authz: cached response (attempt {})", attempt + 1),
                        );
                        return;
                    }
                    Err(Status::CasMismatch) => {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Debug,
                            &format!(
                                "ext_authz: cache CAS mismatch, retrying ({}/3)",
                                attempt + 1
                            ),
                        );
                        continue;
                    }
                    Err(e) => {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Error,
                            &format!("ext_authz: failed to write cache shard: {:?}", e),
                        );
                        return;
                    }
                }
            }

            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                "ext_authz: cache write failed after 3 CAS retries",
            );
        }
    }
}
