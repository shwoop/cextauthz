pub mod cache;
pub mod config;
pub mod decision;
pub mod invalidation;
pub mod pb;
pub mod request;

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

    pub struct AuthzRoot {
        timeout_ms: u64,
        grpc_cluster: String,
        max_request_body_bytes: usize,
        cache_config: crate::cache::CacheConfig,
        invalidation_secret: String,
    }

    pub struct AuthzHttp {
        pub grpc_token: Option<u32>,
        pub timeout: std::time::Duration,
        grpc_cluster: String,
        max_request_body_bytes: usize,
        cache_config: crate::cache::CacheConfig,
        cache_key: Option<String>,
        invalidation_secret: String,
        is_invalidation_request: bool,
        dispatched: bool,
        method: String,
        path: String,
        query: String,
        host: String,
        scheme: String,
        request_id: String,
        headers: HashMap<String, String>,
        body_buf: Vec<u8>,
        body_seen: usize,
    }

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            let settings = crate::config::PluginSettings::default();
            Box::new(AuthzRoot {
                timeout_ms: settings.timeout_ms,
                grpc_cluster: settings.grpc_cluster,
                max_request_body_bytes: settings.max_request_body_bytes,
                cache_config: settings.cache,
                invalidation_secret: settings.invalidation_secret,
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
                if let Ok(settings) = crate::config::PluginSettings::from_json(text) {
                    self.timeout_ms = settings.timeout_ms;
                    self.grpc_cluster = settings.grpc_cluster;
                    self.max_request_body_bytes = settings.max_request_body_bytes;
                    self.cache_config = settings.cache;
                    self.invalidation_secret = settings.invalidation_secret;
                    let _ = proxy_wasm::hostcalls::log(
                        proxy_wasm::types::LogLevel::Info,
                        &format!(
                            "ext_authz: configured timeout={}ms cache_enabled={} max_request_body_bytes={}",
                            self.timeout_ms, self.cache_config.enabled, self.max_request_body_bytes
                        ),
                    );
                } else {
                    let _ = proxy_wasm::hostcalls::log(
                        proxy_wasm::types::LogLevel::Warn,
                        "ext_authz: plugin config is not valid JSON; using defaults",
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
                grpc_cluster: self.grpc_cluster.clone(),
                max_request_body_bytes: self.max_request_body_bytes,
                cache_config: self.cache_config.clone(),
                cache_key: None,
                invalidation_secret: self.invalidation_secret.clone(),
                is_invalidation_request: false,
                dispatched: false,
                method: String::new(),
                path: String::new(),
                query: String::new(),
                host: String::new(),
                scheme: String::new(),
                request_id: String::new(),
                headers: HashMap::new(),
                body_buf: Vec::new(),
                body_seen: 0,
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
                        let decision =
                            crate::decision::AuthorizationDecision::from_check_response(&resp);
                        match decision {
                            crate::decision::AuthorizationDecision::Allow { request_headers } => {
                                if self.cache_config.enabled {
                                    self.store_cache_entry(true, 0, "", &[], &request_headers);
                                }
                                let _ = proxy_wasm::hostcalls::log(
                                    proxy_wasm::types::LogLevel::Info,
                                    "ext_authz: request allowed",
                                );
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
                                let _ = proxy_wasm::hostcalls::log(
                                    proxy_wasm::types::LogLevel::Info,
                                    "ext_authz: request denied",
                                );

                                self.send_http_response(
                                    status,
                                    local_reply_headers(&headers),
                                    Some(body.as_bytes()),
                                );
                            }
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
            let mut content_length = None;

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
                            if name.eq_ignore_ascii_case("content-length")
                                && let Ok(length) = value.parse::<usize>()
                            {
                                content_length = Some(length);
                            }
                            self.headers.insert(name.to_lowercase(), value);
                        }
                    }
                }
            }

            if content_length
                .map(|length| length > self.max_request_body_bytes)
                .unwrap_or(false)
            {
                return self.reject_payload_too_large();
            }

            self.is_invalidation_request =
                self.method == "POST" && self.path == crate::invalidation::INVALIDATION_PATH;

            if self.is_invalidation_request {
                if end_of_stream {
                    return self.handle_invalidation_request();
                }
                return Action::Continue;
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

            if body_size > self.max_request_body_bytes {
                return self.reject_payload_too_large();
            }

            if body_size > self.body_seen {
                let new_bytes = body_size - self.body_seen;
                if let Some(chunk) = self.get_http_request_body(self.body_seen, new_bytes) {
                    self.body_buf.extend_from_slice(&chunk);
                }
                self.body_seen = body_size;
            }

            if self.is_invalidation_request {
                if end_of_stream {
                    return self.handle_invalidation_request();
                }
                return Action::Pause;
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
        fn reject_payload_too_large(&mut self) -> Action {
            self.dispatched = true;
            self.send_http_response(
                413,
                vec![("content-type", "text/plain")],
                Some(b"Payload Too Large"),
            );
            Action::Pause
        }

        fn dispatch_check_request(&mut self) -> Action {
            self.dispatched = true;

            let check_req = crate::request::RequestParts {
                method: std::mem::take(&mut self.method),
                path: std::mem::take(&mut self.path),
                query: std::mem::take(&mut self.query),
                host: std::mem::take(&mut self.host),
                scheme: std::mem::take(&mut self.scheme),
                request_id: std::mem::take(&mut self.request_id),
                headers: std::mem::take(&mut self.headers),
                body: std::mem::take(&mut self.body_buf),
            }
            .into_check_request();

            if self.cache_config.enabled {
                let cache_key =
                    crate::cache::compute_cache_key(&check_req, &self.cache_config.header_policy);
                self.cache_key = Some(cache_key.clone());

                if let Some(entry) = self.get_cache_entry(&cache_key) {
                    let _ = proxy_wasm::hostcalls::log(LogLevel::Info, "ext_authz: cache hit");
                    if entry.allowed {
                        let request_headers = cached_headers_to_pairs(&entry.request_headers);
                        self.apply_request_headers(&request_headers);
                        return Action::Continue;
                    }
                    let response_headers = cached_headers_to_pairs(&entry.response_headers);
                    let body = if entry.denied_body.is_empty() {
                        "Forbidden".to_string()
                    } else {
                        entry.denied_body
                    };
                    self.send_http_response(
                        entry.denied_status,
                        local_reply_headers(&response_headers),
                        Some(body.as_bytes()),
                    );
                    return Action::Pause;
                }
            }

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

            let _configured_cluster = &self.grpc_cluster;
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

        fn now_ms(&self) -> u64 {
            self.get_current_time()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }

        fn get_cache_entry(&self, cache_key: &str) -> Option<crate::cache::CacheEntry> {
            let shard_id = crate::cache::shard_id_from_key(cache_key);
            let shared_key = crate::cache::shard_shared_key(shard_id);
            let now_ms = self.now_ms();

            let (bytes, _cas) = self.get_shared_data(&shared_key);
            let shard = crate::cache::decode_shard(bytes.as_deref());
            let entry = shard.entries.get(cache_key)?;
            if entry.expires_at_ms <= now_ms {
                return None;
            }
            Some(entry.clone())
        }

        fn store_cache_entry(
            &self,
            allowed: bool,
            denied_status: u32,
            denied_body: &str,
            response_headers: &[(String, String)],
            request_headers: &[(String, String)],
        ) {
            let Some(cache_key) = self.cache_key.as_deref() else {
                return;
            };
            let shard_id = crate::cache::shard_id_from_key(cache_key);
            let shared_key = crate::cache::shard_shared_key(shard_id);
            let expires_at_ms = self
                .now_ms()
                .saturating_add(self.cache_config.ttl.as_millis() as u64);
            let quota = crate::cache::shard_quota(self.cache_config.max_entries);

            for _ in 0..3 {
                let (bytes, cas) = self.get_shared_data(&shared_key);
                let mut shard = crate::cache::decode_shard(bytes.as_deref());
                crate::cache::evict_expired(&mut shard, self.now_ms());
                shard.entries.insert(
                    cache_key.to_string(),
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
                    },
                );
                crate::cache::enforce_quota(&mut shard, quota);

                let mut encoded = Vec::new();
                if shard.encode(&mut encoded).is_err() {
                    return;
                }
                if self
                    .set_shared_data(&shared_key, Some(&encoded), cas)
                    .is_ok()
                {
                    return;
                }
            }
        }

        fn apply_request_headers(&self, headers: &[(String, String)]) {
            for (name, value) in headers {
                self.set_http_request_header(name, Some(value));
            }
        }

        fn invalidation_authorized(&self) -> bool {
            if self.invalidation_secret.is_empty() {
                return false;
            }
            self.headers
                .get(crate::invalidation::INVALIDATION_SECRET_HEADER)
                .map(|value| value == &self.invalidation_secret)
                .unwrap_or(false)
        }

        fn handle_invalidation_request(&mut self) -> Action {
            self.dispatched = true;

            if !self.invalidation_authorized() {
                self.send_http_response(
                    401,
                    vec![("content-type", "text/plain")],
                    Some(b"Unauthorized"),
                );
                return Action::Pause;
            }

            let request = match crate::invalidation::InvalidationRequest::parse(&self.body_buf) {
                Ok(request) => request,
                Err(err) => {
                    self.send_http_response(
                        400,
                        vec![("content-type", "text/plain")],
                        Some(err.as_bytes()),
                    );
                    return Action::Pause;
                }
            };

            match request.op {
                crate::invalidation::InvalidationOp::PurgeKey => {
                    let key = request.key.unwrap();
                    self.purge_cache_key(&key);
                }
                crate::invalidation::InvalidationOp::PurgeAll => {
                    self.purge_all_cache_shards();
                }
            }

            self.send_http_response(204, vec![], None);
            Action::Pause
        }

        fn purge_cache_key(&self, cache_key: &str) {
            let shard_id = crate::cache::shard_id_from_key(cache_key);
            let shared_key = crate::cache::shard_shared_key(shard_id);

            for _ in 0..3 {
                let (bytes, cas) = self.get_shared_data(&shared_key);
                let mut shard = crate::cache::decode_shard(bytes.as_deref());
                shard.entries.remove(cache_key);

                let mut encoded = Vec::new();
                if shard.encode(&mut encoded).is_err() {
                    return;
                }
                if self
                    .set_shared_data(&shared_key, Some(&encoded), cas)
                    .is_ok()
                {
                    return;
                }
            }
        }

        fn purge_all_cache_shards(&self) {
            let empty = crate::cache::CacheShard::default();
            let mut encoded = Vec::new();
            if empty.encode(&mut encoded).is_err() {
                return;
            }

            for shard_id in 0..crate::cache::NUM_SHARDS {
                let shared_key = crate::cache::shard_shared_key(shard_id);
                for _ in 0..3 {
                    let (_bytes, cas) = self.get_shared_data(&shared_key);
                    if self
                        .set_shared_data(&shared_key, Some(&encoded), cas)
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }
    }

    fn cached_headers_to_pairs(headers: &[crate::cache::CachedHeader]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|header| (header.name.clone(), header.value.clone()))
            .collect()
    }

    fn local_reply_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
        let mut response_headers = Vec::new();
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            response_headers.push(("content-type", "text/plain"));
        }
        response_headers.extend(
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        response_headers
    }
}
