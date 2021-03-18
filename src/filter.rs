
mod lib;

use log::debug;
use proxy_wasm::hostcalls::log;
use proxy_wasm::types::LogLevel::Info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;
use std::any::Any;

#[no_mangle]
pub fn _start() {
    //proxy_wasm::set_log_level(wasm::types::LogLevel::Trace);

    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(HttpAuth) });
}

struct HttpAuth;

impl HttpAuth {
    fn fail(&mut self) {
      debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
    }
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for HttpAuth {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, num_headers: usize) -> Action {
        // get all the request headers
        let headers = self.get_http_request_headers();
        log(Info, "Got {} HTTP headers in #{}.");

        self.send_http_response(302, vec![("Location", "https://www.vg.no")], Some(b"redirect"));
        Action::Pause
    }

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        // Add a header on the response.
        self.set_http_response_header("Hello", Some("world"));
        Action::Continue
    }
}

impl Context for HttpAuth {

}
