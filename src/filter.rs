
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
use std::collections::HashMap;
use std::iter::{FromIterator, Map};
use url;
use oauth2::basic::BasicClient;
use oauth2::{ClientId, ClientSecret, AuthUrl, TokenUrl, RedirectUrl};
use oauth2::url::ParseError;

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
    config: FilterConfig,
    client: BasicClient,
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
    issuer: String,
    auth_uri: String,
    token_uri: String,
    client_id: String,
    client_secret: String
}

impl OAuthFilter {

    fn new(config: FilterConfig) -> Result<OAuthFilter, ParseError> {
        let client =
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(config.client_secret.clone())),
                AuthUrl::new(config.auth_uri.clone())?,
                Some(TokenUrl::new(config.token_uri.clone())?)
            )
                .set_redirect_url(RedirectUrl::new(config.redirect_uri.clone())?);
        Ok(OAuthFilter {
            config,
            client,
        })
    }

    fn fail(&mut self) {
      debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
    }

    fn token_header(&self) -> Option<String> {
        self.get_http_request_header(self.config.target_header_name.as_str())
    }

    fn session_cookie(&self) -> Option<String> {
        // wont work for real cookies
        self.get_http_request_header(self.config.cookie_name.as_str())
    }

    fn code_param(&self) -> Option<String> {
        match self.get_http_request_header(":path") {
            None => None,
            Some(path) => {
                let params = url::form_urlencoded::parse(path.as_bytes());
                for (k, v) in params {
                    if k == "code" {
                        return Some(v.to_string())
                    }
                }
                return None
            }
        }
    }

    fn send_authorization_redirect(&self, extra_headers: Vec<(&str, &str)>) {
        //self.send_http_response(302, headers, None);
    }
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, num_headers: usize) -> Action {

        if let None = self.session_cookie() {
            self.send_authorization_redirect(vec![(self.config.cookie_name.as_str(), "RandomCookieValue")]);
            return Action::Pause
        }
        if let Some(code) = self.code_param() {
            log(LogLevel::Info, format!("Received path with code: {}", code.as_str()).as_str());
            return Action::Continue
        }

        log(LogLevel::Error, "Not implemented reached");
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
            None => {
                log(LogLevel::Error,
                    "No configuration supplied, cannot create HttpContext");
                None
            },
            Some(filter_config) => {
                Some(Box::new(OAuthFilter::new(filter_config.clone()).unwrap()))
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
    "oidcSession".to_owned()
}

fn default_target_header_name() -> String {
    "Authorization".to_owned()
}