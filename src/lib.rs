pub mod cache;
pub mod invalidation;
pub mod pb;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use prost::Message;
    use proxy_wasm::traits::*;
    use proxy_wasm::types::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::time::Duration;

    const GRPC_CLUSTER: &str = "ext_authz";
    const GRPC_SERVICE: &str = "envoy.service.auth.v3.Authorization";
    const GRPC_METHOD: &str = "Check";
    const VM_ID: &str = "cextauthz_vm";

    #[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum PluginRole {
        HttpFilter,
        Singleton,
    }

    impl Default for PluginRole {
        fn default() -> Self {
            Self::HttpFilter
        }
    }

    #[derive(serde::Deserialize)]
    struct PluginConfig {
        #[serde(default)]
        role: PluginRole,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        cache: CacheConfigJson,
        #[serde(default)]
        invalidation: InvalidationConfigJson,
    }

    #[derive(serde::Deserialize, Default)]
    struct CacheConfigJson {
        #[serde(default)]
        enabled: bool,
        #[serde(default = "default_cache_ttl_ms")]
        ttl_ms: u64,
        #[serde(default = "default_cache_size_kb")]
        size_kb: usize,
    }

    #[derive(Clone, Debug, serde::Deserialize, Default)]
    struct InvalidationConfigJson {
        #[serde(default)]
        secret: Option<String>,
    }

    fn default_timeout_ms() -> u64 {
        1000
    }
    fn default_cache_ttl_ms() -> u64 {
        60000
    }
    fn default_cache_size_kb() -> usize {
        1024
    }

    pub struct AuthzRoot {
        role: PluginRole,
        timeout_ms: u64,
        cache_config: crate::cache::CacheConfig,
        cache: Rc<RefCell<crate::cache::VmCache>>,
        invalidation_secret: Option<String>,
        worker_queue_name: Option<String>,
        worker_queue_id: Option<u32>,
        control_queue_id: Option<u32>,
        registered_worker_queue_names: crate::invalidation::WorkerRegistry,
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
        cache: Rc<RefCell<crate::cache::VmCache>>,
        invalidation_secret: Option<String>,
        control_queue_id: Option<u32>,
        is_invalidation_request: bool,
    }

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(AuthzRoot {
                role: PluginRole::HttpFilter,
                timeout_ms: 1000,
                cache_config: crate::cache::CacheConfig::default(),
                cache: Rc::new(RefCell::new(crate::cache::VmCache::new())),
                invalidation_secret: None,
                worker_queue_name: None,
                worker_queue_id: None,
                control_queue_id: None,
                registered_worker_queue_names: crate::invalidation::WorkerRegistry::default(),
            })
        });
    }}

    impl Context for AuthzRoot {}

    impl RootContext for AuthzRoot {
        fn on_queue_ready(&mut self, queue_id: u32) {
            if Some(queue_id) == self.control_queue_id && self.role == PluginRole::Singleton {
                self.drain_control_queue(queue_id);
            } else if Some(queue_id) == self.worker_queue_id && self.role == PluginRole::HttpFilter
            {
                self.drain_worker_queue(queue_id);
            }
        }
        fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
            if plugin_configuration_size == 0 {
                return true;
            }
            if let Some(config) = self.get_plugin_configuration()
                && let Ok(text) = std::str::from_utf8(&config)
            {
                let trimmed = text.trim();
                if let Ok(json_cfg) = serde_json::from_str::<PluginConfig>(trimmed) {
                    self.role = json_cfg.role;
                    self.timeout_ms = json_cfg.timeout_ms;
                    self.cache_config = crate::cache::CacheConfig {
                        enabled: json_cfg.cache.enabled,
                        ttl: Duration::from_millis(json_cfg.cache.ttl_ms),
                        size_bytes: json_cfg.cache.size_kb.saturating_mul(1024),
                    };
                    self.invalidation_secret = json_cfg.invalidation.secret.clone();
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Info,
                        &format!(
                            "ext_authz: role={:?}, timeout={} ms, cache_enabled={}, cache_ttl={} ms, cache_size_kb={}",
                            self.role,
                            self.timeout_ms,
                            self.cache_config.enabled,
                            json_cfg.cache.ttl_ms,
                            json_cfg.cache.size_kb
                        ),
                    );
                } else if let Ok(ms) = trimmed.parse::<u64>() {
                    // Backward compatibility: raw u64 milliseconds
                    if self.role == PluginRole::Singleton {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Warn,
                            "ext_authz: raw u64 timeout config not supported for singleton; ignoring",
                        );
                    } else {
                        self.timeout_ms = ms;
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("ext_authz: timeout configured to {} ms", self.timeout_ms),
                        );
                    }
                } else {
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        "ext_authz: plugin config is not valid JSON or u64; using defaults",
                    );
                }
            }
            match self.role {
                PluginRole::HttpFilter => self.configure_worker_queue(),
                PluginRole::Singleton => self.configure_singleton_queue(),
            }
            true
        }

        fn get_type(&self) -> Option<ContextType> {
            match self.role {
                PluginRole::HttpFilter => Some(ContextType::HttpContext),
                PluginRole::Singleton => None,
            }
        }

        fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
            if self.role != PluginRole::HttpFilter {
                return None;
            }
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
                cache: self.cache.clone(),
                invalidation_secret: self.invalidation_secret.clone(),
                control_queue_id: self.control_queue_id,
                is_invalidation_request: false,
            }))
        }
    }

    impl AuthzRoot {
        fn configure_singleton_queue(&mut self) {
            if self.control_queue_id.is_some() {
                return;
            }
            let queue_id = self.register_shared_queue(crate::invalidation::CONTROL_QUEUE_NAME);
            self.control_queue_id = Some(queue_id);
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!(
                    "ext_authz: singleton registered control queue id {}",
                    queue_id
                ),
            );
        }

        fn configure_worker_queue(&mut self) {
            if self.worker_queue_id.is_none() {
                let queue_name = format!(
                    "{}{}-{}",
                    crate::invalidation::WORKER_QUEUE_PREFIX,
                    self.get_current_time()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos(),
                    self.cache.borrow().len()
                );
                let queue_id = self.register_shared_queue(&queue_name);
                self.worker_queue_name = Some(queue_name);
                self.worker_queue_id = Some(queue_id);
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    &format!(
                        "ext_authz: worker registered invalidation queue id {}",
                        queue_id
                    ),
                );
            }

            if self.control_queue_id.is_none() {
                self.control_queue_id =
                    self.resolve_shared_queue(VM_ID, crate::invalidation::CONTROL_QUEUE_NAME);
            }

            if let (Some(control_queue_id), Some(worker_queue_name)) =
                (self.control_queue_id, self.worker_queue_name.as_ref())
            {
                let msg = crate::invalidation::QueueMessage::RegisterWorker {
                    queue_name: worker_queue_name.clone(),
                };
                if let Ok(bytes) = serde_json::to_vec(&msg) {
                    if let Err(status) = self.enqueue_shared_queue(control_queue_id, Some(&bytes)) {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Warn,
                            &format!("ext_authz: failed to register worker queue: {:?}", status),
                        );
                    }
                }
            } else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    "ext_authz: singleton control queue not resolvable during worker configure",
                );
            }
        }

        fn drain_control_queue(&mut self, queue_id: u32) {
            loop {
                match self.dequeue_shared_queue(queue_id) {
                    Ok(Some(bytes)) => self.handle_control_queue_message(&bytes),
                    Ok(None) => break,
                    Err(status) => {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Warn,
                            &format!("ext_authz: failed to dequeue control queue: {:?}", status),
                        );
                        break;
                    }
                }
            }
        }

        fn handle_control_queue_message(&mut self, bytes: &[u8]) {
            let Ok(message) = serde_json::from_slice::<crate::invalidation::QueueMessage>(bytes)
            else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    "ext_authz: malformed control queue message",
                );
                return;
            };
            match message {
                crate::invalidation::QueueMessage::RegisterWorker { queue_name } => {
                    if self
                        .registered_worker_queue_names
                        .insert(queue_name.clone())
                    {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("ext_authz: registered worker queue {}", queue_name),
                        );
                    }
                }
                crate::invalidation::QueueMessage::Invalidate(request) => {
                    self.broadcast_invalidation(&request);
                }
            }
        }

        fn broadcast_invalidation(&mut self, request: &crate::invalidation::InvalidationRequest) {
            let Ok(bytes) = serde_json::to_vec(&crate::invalidation::QueueMessage::Invalidate(
                request.clone(),
            )) else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    "ext_authz: failed to encode invalidation broadcast",
                );
                return;
            };

            let queue_names: Vec<String> = self
                .registered_worker_queue_names
                .queue_names()
                .map(str::to_string)
                .collect();

            for queue_name in queue_names {
                let Some(queue_id) = self.resolve_shared_queue(VM_ID, &queue_name) else {
                    self.registered_worker_queue_names.remove(&queue_name);
                    continue;
                };
                if let Err(status) = self.enqueue_shared_queue(queue_id, Some(&bytes)) {
                    self.registered_worker_queue_names.remove(&queue_name);
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        &format!(
                            "ext_authz: failed to fan out to {}: {:?}",
                            queue_name, status
                        ),
                    );
                }
            }
        }

        fn drain_worker_queue(&mut self, queue_id: u32) {
            loop {
                match self.dequeue_shared_queue(queue_id) {
                    Ok(Some(bytes)) => self.handle_worker_queue_message(&bytes),
                    Ok(None) => break,
                    Err(status) => {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Warn,
                            &format!("ext_authz: failed to dequeue worker queue: {:?}", status),
                        );
                        break;
                    }
                }
            }
        }

        fn handle_worker_queue_message(&mut self, bytes: &[u8]) {
            let Ok(crate::invalidation::QueueMessage::Invalidate(request)) =
                serde_json::from_slice::<crate::invalidation::QueueMessage>(bytes)
            else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    "ext_authz: malformed worker queue message",
                );
                return;
            };
            self.apply_invalidation(&request);
        }

        fn apply_invalidation(&mut self, request: &crate::invalidation::InvalidationRequest) {
            match request.op {
                crate::invalidation::InvalidationOp::PurgeKey => {
                    if let Some(key) = request.key.as_deref() {
                        self.cache.borrow_mut().purge_key(key);
                    }
                }
                crate::invalidation::InvalidationOp::PurgeAll => {
                    self.cache.borrow_mut().purge_all();
                }
            }
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
                Action::Continue
            }
        }

        fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
            if self.dispatched {
                return Action::Pause;
            }

            if self.is_invalidation_request {
                if body_size > 0 {
                    if let Some(chunk) = self.get_http_request_body(0, body_size) {
                        self.body_buf.clear();
                        self.body_buf.extend_from_slice(&chunk);
                    }
                }
                if end_of_stream {
                    return self.handle_invalidation_request();
                }
                return Action::Continue;
            }

            if body_size > 0 {
                if let Some(chunk) = self.get_http_request_body(0, body_size) {
                    self.body_buf.extend_from_slice(&chunk);
                }
            }

            if end_of_stream {
                self.dispatch_check_request()
            } else {
                Action::Continue
            }
        }

        fn on_log(&mut self) {
            let _ = proxy_wasm::hostcalls::log(LogLevel::Info, "ext_authz: request completed");
        }
    }

    impl AuthzHttp {
        fn invalidation_authorized(&self) -> bool {
            let Some(expected) = self.invalidation_secret.as_deref() else {
                return false;
            };
            self.headers
                .get(crate::invalidation::INVALIDATION_SECRET_HEADER)
                .map(|actual| actual == expected)
                .unwrap_or(false)
        }

        fn handle_invalidation_request(&mut self) -> Action {
            if !self.invalidation_authorized() {
                self.send_http_response(
                    401,
                    vec![("content-type", "text/plain")],
                    Some(b"Unauthorized"),
                );
                return Action::Pause;
            }

            let now_ms = self.now_ms();
            let request = match crate::invalidation::parse_invalidation(&self.body_buf, now_ms) {
                Ok(request) => request,
                Err(error) => {
                    let _ = proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        &format!("ext_authz: invalid invalidation request: {:?}", error),
                    );
                    self.send_http_response(
                        400,
                        vec![("content-type", "text/plain")],
                        Some(b"Bad invalidation request"),
                    );
                    return Action::Pause;
                }
            };

            self.apply_invalidation_locally(&request);
            self.enqueue_invalidation_for_fanout(&request);

            self.send_http_response(202, vec![("content-type", "text/plain")], Some(b"Accepted"));
            Action::Pause
        }

        fn apply_invalidation_locally(
            &mut self,
            request: &crate::invalidation::InvalidationRequest,
        ) {
            match request.op {
                crate::invalidation::InvalidationOp::PurgeKey => {
                    if let Some(key) = request.key.as_deref() {
                        self.cache.borrow_mut().purge_key(key);
                    }
                }
                crate::invalidation::InvalidationOp::PurgeAll => {
                    self.cache.borrow_mut().purge_all();
                }
            }
        }

        fn enqueue_invalidation_for_fanout(
            &self,
            request: &crate::invalidation::InvalidationRequest,
        ) {
            let Some(control_queue_id) = self.control_queue_id else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    "ext_authz: accepted invalidation but control queue is unavailable",
                );
                return;
            };

            let msg = crate::invalidation::QueueMessage::Invalidate(request.clone());
            let Ok(bytes) = serde_json::to_vec(&msg) else {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    "ext_authz: failed to encode invalidation fan-out message",
                );
                return;
            };

            if let Err(status) = self.enqueue_shared_queue(control_queue_id, Some(&bytes)) {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    &format!(
                        "ext_authz: failed to enqueue invalidation fan-out: {:?}",
                        status
                    ),
                );
            }
        }
    }

    impl AuthzHttp {
        fn now_ms(&self) -> u64 {
            self.get_current_time()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }

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
                let now_ms = self.now_ms();
                if let Some(entry) = self.cache.borrow_mut().get_fresh(key, now_ms) {
                    if entry.allowed {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            "ext_authz: cache hit (allowed)",
                        );
                        return Action::Continue;
                    }
                    let _ =
                        proxy_wasm::hostcalls::log(LogLevel::Info, "ext_authz: cache hit (denied)");
                    self.send_http_response(
                        entry.denied_status,
                        vec![("content-type", "text/plain")],
                        Some(b"Forbidden"),
                    );
                    return Action::Pause;
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

            let now_ms = self.now_ms();
            let ttl_ms = self.cache_config.ttl.as_millis() as u64;
            self.cache.borrow_mut().insert(
                key.clone(),
                allowed,
                denied_status,
                now_ms,
                ttl_ms,
                0,
                self.cache_config.size_bytes,
            );
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!(
                    "ext_authz: cached response locally, entries={}, estimated_bytes={}",
                    self.cache.borrow().len(),
                    self.cache.borrow().estimated_bytes()
                ),
            );
        }
    }
}
