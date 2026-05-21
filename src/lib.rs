use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(NoopRoot) });
}}

struct NoopRoot;

impl Context for NoopRoot {}

impl RootContext for NoopRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(NoopHttp))
    }
}

struct NoopHttp;

impl Context for NoopHttp {}
impl HttpContext for NoopHttp {}
