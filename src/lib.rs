#[cfg(target_arch = "wasm32")]
mod wasm {
    use proxy_wasm::traits::*;
    use proxy_wasm::types::*;

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(super::NoopRoot) });
    }}

    impl Context for super::NoopRoot {}

    impl RootContext for super::NoopRoot {
        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::HttpContext)
        }

        fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
            Some(Box::new(super::NoopHttp))
        }
    }

    impl Context for super::NoopHttp {}
    impl HttpContext for super::NoopHttp {}
}

pub struct NoopRoot;
pub struct NoopHttp;
