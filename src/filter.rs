
mod lib;

use log::debug;
use log::error;
use proxy_wasm::hostcalls::log;
use proxy_wasm::types::LogLevel;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;
use std::any::Any;
use serde::{Serialize, Deserialize};
use proxy_wasm::types::LogLevel::Info;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Debug);

    proxy_wasm::set_root_context(
        |_| -> Box<dyn RootContext> {
            Box::new(OAuthRootContext {
                config: None
            })
        });
}

struct OAuthRootContext {
    config: Option<FilterConfig>
}

struct OAuthFilter {
    config: FilterConfig
}


#[derive(Deserialize, Clone, Debug)]
struct FilterConfig {
    #[serde(default = "default_redirect_uri")]
    redirect_uri: String,
    #[serde(default = "default_target_header_name")]
    target_header_name: String,
    #[serde(default = "default_oidc_cookie_name")]
    cookie_name: String,
    auth_cluster: String,
    auth_host: String,
    login_uri: String,
    token_uri: String,
    client_id: String,
    client_secret: String
}

impl OAuthFilter {
    fn fail(&mut self) {
      debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
    }
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, num_headers: usize) -> Action {
        // get all the request headers
        let headers = self.get_http_request_headers();
        log(LogLevel::Info, "Got some {} HTTP headers in {}.");
        log(LogLevel::Info, format!("OAuth filter is configured with: {:?}", self.config).as_str());

        self.send_http_response(302, vec![("Location", "https://www.vg.no")], Some(b"redirect"));
        Action::Pause
    }

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        // Add a header on the response.
        self.set_http_response_header("Hello", Some("world"));
        Action::Continue
    }
}

impl Context for OAuthFilter {}

impl Context for OAuthRootContext {}
impl RootContext for OAuthRootContext {

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_buffer) = self.get_configuration() {
            let oauth_filter_config: FilterConfig = serde_json::from_slice(config_buffer.as_slice()).unwrap();
            log(LogLevel::Info, format!("OAuth filter configured with: {:?}", oauth_filter_config).as_str());
            self.config = Some(oauth_filter_config);
            true
        } else {
            log(LogLevel::Error, "No configuration supplied for OAuth filter");
            false
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        match self.config.as_ref() {
            None => None,
            Some(filter_config) => {
                Some(Box::new(OAuthFilter{
                    config: filter_config.clone()
                }))
            }
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}


fn default_redirect_uri() -> String {
    "{proto}://{authority}{path}".to_owned()
}

fn default_oidc_cookie_name() -> String {
    "oidcToken".to_owned()
}

fn default_target_header_name() -> String {
    "authorization".to_owned()
}