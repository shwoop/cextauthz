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

    pub struct AuthzRoot {
        timeout_ms: u64,
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
    }

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(AuthzRoot { timeout_ms: 1000 })
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
                if let Ok(ms) = text.trim().parse::<u64>() {
                    self.timeout_ms = ms;
                    let _ = proxy_wasm::hostcalls::log(
                        proxy_wasm::types::LogLevel::Info,
                        &format!("ext_authz: timeout configured to {} ms", self.timeout_ms),
                    );
                } else {
                    let _ = proxy_wasm::hostcalls::log(
                        proxy_wasm::types::LogLevel::Warn,
                        "ext_authz: plugin config is not a valid u64 (milliseconds); using default 1000 ms",
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
                    format!("ext_authz: gRPC call deadline exceeded (status {})", status_code)
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
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                "ext_authz: request completed",
            );
        }
    }

    impl AuthzHttp {
        fn dispatch_check_request(&mut self) -> Action {
            self.dispatched = true;

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
    }
}
