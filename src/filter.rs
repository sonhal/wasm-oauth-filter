extern crate serde;

mod util;
pub mod oauther;
mod cache;



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
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{ClientId, ClientSecret, AuthUrl, TokenUrl, RedirectUrl, PkceCodeChallenge, CsrfToken, Scope, PkceCodeVerifier, AuthorizationCode, HttpRequest, AuthType, http, StandardTokenResponse, AccessToken, EmptyExtraTokenFields};
use oauth2::url::ParseError;
use base64;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use getrandom::getrandom;
use url::Url;
use crate::oauther::OAuther;
use crate::cache::{LocalCache, SharedCache};
use oauth2::http::HeaderMap;
use std::cell::RefCell;
use std::rc::Rc;


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
    oauther: OAuther,
    cache: Rc<RefCell<SharedCache>>,
}


#[derive(Deserialize, Clone, Debug)]
pub struct FilterConfig {
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

    fn new(config: FilterConfig, cache: SharedCache) -> Result<OAuthFilter, ParseError> {
        proxy_wasm::hostcalls::log(Info, "Creating new HttpContext");

        let cache = Rc::new(RefCell::new(cache));
        let oauther = OAuther::new(config.clone(), Box::new(cache.clone()))?;
        Ok(OAuthFilter {
            config,
            oauther,
            cache
        })
    }

    fn send_error(&self, code: u32, response: ErrorResponse) {
        let body = serde_json::to_string_pretty(&response).unwrap();
        log::error!("{}", body);
        self.send_http_response(
            code,
            vec![("Content-Type", "application/json")],
            Some(body.as_bytes())
        );
    }

    fn fail(&mut self) {
      log::debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
    }

    fn token_header(&self) -> Option<String> {
        self.get_http_request_header(self.config.target_header_name.as_str())
    }

    fn respond_with_redirect(&self, url: Url, headers: HeaderMap) {
        let mut headers: Vec<(&str, &str)> =
            headers.iter().map( |(name, value)| { (name.as_str(), value.to_str().unwrap()) }).collect();
        headers.append(&mut vec![("location", url.as_str())]);

        self.send_http_response(
            302,
            headers,
            None
        );
    }
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let headers = self.get_http_request_headers();
        let headers: Vec<(&str, &str)>
            = headers.iter().map( |(name, value)|{ (name.as_str(), value.as_str()) }).collect();

        match self.oauther.handle_request_header(headers) {
            oauther::Action::Redirect( url, headers) => {
                self.respond_with_redirect(url, headers);
                return Action::Pause;
            },
            oauther::Action::HttpCall( request) => {
                let mut request_headers: Vec<(&str, &str)> =
                    request.headers.iter()
                        .map(
                            |( name, value)|
                                { (name.as_str(), value.to_str().unwrap()) }
                        ).collect();

                let authority = Url::parse(self.config.auth_uri.as_str()).unwrap();
                let authority = authority.origin().unicode_serialization();
                request_headers.append(&mut vec![
                (":method", "POST"),
                (":path", "/customiss/token"),
                (":authority", authority.as_str())]);

                self.dispatch_http_call(
                    &self.config.auth_cluster,
                    request_headers,
                    Some(request.body.as_slice()),
                    vec![],
                    Duration::from_secs(5));
                return Action::Pause;
            },
            oauther::Action::Allow(headers) => {
                let request_headers = self.get_http_request_headers();
                let mut request_headers: Vec<(&str, &str)> = request_headers.iter()
                        .map(
                            |( name, value)|
                                { (name.as_str(), value.as_str()) }
                        ).collect();
                let mut headers: Vec<(&str, &str)> = headers.iter()
                    .map(
                        |( name, value)|
                            { (name.as_str(), value.to_str().unwrap()) }
                    ).collect();

                request_headers.append(&mut headers);
                self.set_http_request_headers(request_headers);
                Action::Continue
            }
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    id_token: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    expires_in: i64
}

#[derive(Serialize)]
struct ErrorResponse {
    status: String,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>
}


impl Context for OAuthFilter {

    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        proxy_wasm::hostcalls::log(LogLevel::Debug, "Token response from auth server received");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match serde_json::from_slice::<TokenResponse>(body.as_slice()) {
                Ok(data) => {
                    if data.error != "" {
                        self.send_error(
                            500,
                            create_error_with_description(
                                data.error.to_owned(),
                                data.error_description.to_owned()
                            )
                        );
                        return
                    }

                    if data.access_token != "" {
                        log::debug!("access token found");
                        let test_token = "testingonly".to_string();
                        let request = StandardTokenResponse::new(
                            AccessToken::new(data.access_token),
                            BasicTokenType::Bearer,
                            EmptyExtraTokenFields {}
                        );

                        let action: oauther::Action = self.oauther.handle_token_call_response(&test_token, &request);
                        match action {
                            oauther::Action::Redirect(_, _) => unreachable!(),
                            oauther::Action::HttpCall(_) => unreachable!(),
                            oauther::Action::Allow(headers) => {
                                let mut headers: Vec<(&str, &str)>
                                    = headers.iter().map( |(name, value)|{ (name.as_str(), value.to_str().unwrap()) }).collect();
                                let old_headers: Vec<(String, String)> = self.get_http_request_headers();
                                let mut old_headers: Vec<(&str, &str)> = old_headers.iter().map(| (name, value) |{ (name.as_str(), value.as_str())}).collect();
                                headers.append(&mut old_headers);

                                self.set_http_request_headers(headers.clone());
                                proxy_wasm::hostcalls::log(LogLevel::Info, format!("Resuming call with headers={:?}", headers).as_str());
                                let mut cache = self.cache.borrow_mut();
                                cache.store(self);
                                return
                            }
                        }
                    }
                },
                Err(e) => {
                    self.send_error(
                        500,
                        create_error(format!("Invalid token response:  {:?}", e))
                    );
                }
            };
        } else {
            self.send_error(
                500,
                create_error(format!("Received invalid payload from authorization server"))
            );
        }
    }
}

fn create_error_with_description(error: String, error_description: String) -> ErrorResponse {
    ErrorResponse{
        status: "error".to_owned(),
        error: error,
        error_description: Some(error_description)
    }
}

fn create_error(error: String) -> ErrorResponse {
    ErrorResponse{
        status: "error".to_owned(),
        error: error,
        error_description: None
    }
}

impl Context for OAuthRootContext {}
impl RootContext for OAuthRootContext {

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_buffer) = self.get_configuration() {
            let oauth_filter_config: FilterConfig = serde_json::from_slice(config_buffer.as_slice()).unwrap();
            proxy_wasm::hostcalls::log(LogLevel::Info, format!("OAuth filter configured with: {:?}", oauth_filter_config).as_str());
            self.config = Some(oauth_filter_config);
            true
        } else {
            proxy_wasm::hostcalls::log(LogLevel::Error, "No configuration supplied for OAuth filter");
            false
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        match self.config.as_ref() {
            None => {
                proxy_wasm::hostcalls::log(LogLevel::Error,
                    "No configuration supplied, cannot create HttpContext");
                None
            },
            Some(filter_config) => {
                match SharedCache::from_host(self) {
                    Ok(cache) => {
                        proxy_wasm::hostcalls::log(LogLevel::Info, "Stored cache returned from host");
                        Some(Box::new(OAuthFilter::new(filter_config.clone(), cache).unwrap()))
                    }
                    Err(_) => {
                        // attempt to create shared
                        proxy_wasm::hostcalls::log(LogLevel::Info, "Error trying to get shared cache from host, attempt to create new");
                        let mut cache = SharedCache::new();
                        cache.store(self);
                        Some(Box::new(OAuthFilter::new(filter_config.clone(), cache).unwrap()))
                    }
                }
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

fn log_debug(message: String) {
    cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "wasi"))] {
                proxy_wasm::hostcalls::log(LogLevel::Debug, &message);
            } else {
                log::debug!(message);
            }
        }
}