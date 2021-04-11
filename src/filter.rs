mod util;
pub mod oauth_client;
pub mod mock_overrides;
mod cache;
mod session;
mod messages;


use proxy_wasm::types::LogLevel;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;
use serde::{Deserialize};
use url;
use oauth2::basic::{BasicTokenType};
use oauth2::{StandardTokenResponse, AccessToken, EmptyExtraTokenFields};
use oauth2::url::ParseError;
use url::Url;
use crate::oauth_client::{OAuthClient};
use crate::cache::{SharedCache};
use oauth2::http::HeaderMap;
use std::cell::RefCell;
use crate::session::{SessionCache};
use std::ops::Deref;
use crate::messages::{ErrorBody};


#[cfg(not(test))]
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
    oauth_client: OAuthClient,
    cache: RefCell<SharedCache>,
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
    client_secret: String,
    #[serde(default = "default_extra_params")]
    extra_params: Vec<(String, String)>
}


impl OAuthFilter {

    fn new(config: FilterConfig, cache: SharedCache) -> Result<OAuthFilter, ParseError> {
        log_debug("Creating new HttpContext");
        log_info(format!("Cache state={:?}", cache).as_str());
        let cache = RefCell::new(cache);

        let oauther = OAuthClient::new(config.clone())?;
        Ok(OAuthFilter {
            config,
            oauth_client: oauther,
            cache
        })
    }

    fn send_error(&self, code: u32, response: crate::messages::ErrorBody) {
        let body = serde_json::to_string_pretty(&response).unwrap();
        log_err(body.as_str());
        self.send_http_response(
            code,
            vec![("Content-Type", "application/json")],
            Some(body.as_bytes())
        );
    }

    fn send_bad_request(&self, message: String) {
        log_err(message.as_str());
        self.send_error(400,
                        crate::messages::ErrorBody::new(
                            "400".to_string(),
                            message,
                            None)
        );
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

    fn oauth_action_handler(&self, action: oauth_client::Action) -> Result<Action, Status> {
        let mut cache = self.cache.borrow_mut();
        match action {
            oauth_client::Action::Redirect(url, headers, update) => {
                cache.set(update);
                cache.store(self).unwrap();
                self.respond_with_redirect(url, headers);
                Ok(Action::Pause)
            }
            oauth_client::Action::TokenRequest(request) => {
                let mut request_headers: Vec<(&str, &str)> = serialize_headers(&request.headers);

                let token_url: Url = self.config.token_uri.parse().unwrap();
                let authority = token_url.domain().unwrap().to_ascii_lowercase(); // TODO fix so it works in test and prod
                let path = token_url.path();
                request_headers.append(&mut vec![
                    (":method", "POST"),
                    (":path", path),
                    (":authority", authority.as_str())]);

                self.dispatch_http_call(
                    &self.config.auth_cluster,
                    request_headers,
                    Some(request.body.as_slice()),
                    vec![],
                    Duration::from_secs(15))?;
                Ok(Action::Pause)
            },
            oauth_client::Action::Allow(additional_headers) => {

                // TODO simplify and clean this this up
                let old_headers: Vec<(String, String)> = self.get_http_request_headers();
                let additional_headers: Vec<(&str, &str)> = serialize_headers(&additional_headers);
                let new_headers: Vec<(String, String)> = merge_old_and_new(old_headers, additional_headers);
                let headers = serialize_string_headers(&new_headers);

                log_info(format!("Resuming call with headers={:?}", headers).as_str());
                self.set_http_request_headers(headers);
                Ok(Action::Continue)
            }
        }
    }

    fn session(&self, headers: &Vec<(&str, &str)>) -> Option<crate::session::Session> {
        crate::session::Session::from_headers(
            self.config.cookie_name.clone(),
            headers.clone(),
            self.cache.borrow().deref()
        )
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
        let user_session = self.session(&headers);

        match self.oauth_client.handle_request(user_session, headers) {
            Ok(oauther_action) => {
                match self.oauth_action_handler(oauther_action) {
                    Ok(filter_action) => filter_action,
                    Err(status) => {
                        self.send_bad_request(format!("Error occurred when handling action, status={:?}", status));
                        Action::Pause
                    }
                }
            }
            Err(status) => {
                self.send_bad_request(format!("Error occurred handling request headers, status = {:?}", status));
                Action::Pause
            }
        }
    }
}

impl Context for OAuthFilter {

    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        log_debug("Token response from auth server received");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match serde_json::from_slice::<crate::messages::TokenResponse>(body.as_slice()) {
                Ok(response) => {
                    match response {
                        crate::messages::TokenResponse::Error(response) =>
                            self.send_error(500, response.to_error_body()),
                        crate::messages::TokenResponse::Success(response) => {
                            log::debug!("access token found");

                            // TODO clean this up
                            let headers = self.get_http_request_headers();
                            let headers: Vec<(&str, &str)>
                                = headers.iter().map( |(name, value)|{ (name.as_str(), value.as_str()) }).collect();


                            let user_session = self.session(&headers);
                            let action = self.oauth_client.handle_token_call_response(user_session, &response);
                            match action {
                                Ok(action) => {
                                    // TODO maybe bad to just ignore return here?
                                    match self.oauth_action_handler(action) {
                                        Ok(_) => {} // TODO maybe seperate handling for token responses?
                                        Err( status) => self.send_error(
                                            500,
                                            ErrorBody::new("500".to_string(), format!("ERROR when handling action, status{:?}", status), None))
                                    }
                                },
                                Err(error) => self.send_error(
                                    500,
                                    ErrorBody::new("500".to_string(), format!("Invalid token response:  {:?}", error), None)
                                )
                            }
                        }
                    }
                },
                Err(e) => {
                    log::debug!("Error response from token endpoint={:?}", String::from_utf8(body));
                    self.send_error(
                        500,
                        ErrorBody::new("500".to_string(), format!("Invalid token response:  {:?}", e), None)
                    );
                }
            };
        } else {
            self.send_error(
                500,
                ErrorBody::new("500".to_string(),format!("Received invalid payload from authorization server"), None)
            );
        }
    }
}

impl Context for OAuthRootContext {}
impl RootContext for OAuthRootContext {

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_buffer) = self.get_configuration() {
            let oauth_filter_config: FilterConfig = serde_json::from_slice(config_buffer.as_slice()).unwrap();
            log_info(format!("OAuth filter configured with: {:?}", oauth_filter_config).as_str());
            self.config = Some(oauth_filter_config);
            true
        } else {
            log_err("No configuration supplied for OAuth filter");
            false
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        match self.config.as_ref() {
            None => {
                log_err("No configuration supplied, cannot create HttpContext");
                None
            },
            Some(filter_config) => {
                match SharedCache::from_host(self) {
                    Ok(cache) => {
                        log_info("Stored cache returned from host");
                        Some(Box::new(OAuthFilter::new(filter_config.clone(), cache).unwrap()))
                    }
                    Err(_) => {
                        // attempt to create shared
                        log_info("Could not get shared cache from host, attempt to create new");
                        let mut cache = SharedCache::new();
                        match cache.store(self) {
                            Ok(_) => {}
                            Err(error) => {
                                panic!(error)
                            }
                        }
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

fn default_extra_params() -> Vec<(String, String)> {
    Vec::new()
}

fn serialize_headers(headers: &HeaderMap) -> Vec<(&str, &str)> {
    headers.iter()
        .map(
            |( name, value)|
                { (name.as_str(), value.to_str().unwrap()) }
        ).collect()
}

fn serialize_string_headers(headers: &Vec<(String, String)>) -> Vec<(&str, &str)> {
    headers.iter()
        .map(
            |( name, value)|
                { (name.as_str(), value.as_str()) }
        ).collect()
}

fn merge_old_and_new(old: Vec<(String, String)>, new: Vec<(&str, &str)>) -> Vec<(String, String)> {
    let new: Vec<(String, String)> = new.iter().map(| (name, value) | { (name.to_string(), value.to_string())}).collect();
    let merged: Vec<(String, String)> =
        old.iter().chain(new.iter()).map( | (name, value) | { (name.to_string(),  value.to_string())}).collect();
    merged
}

fn log_debug(message: &str) {
    host_log(LogLevel::Debug, message);
}

fn log_info(message: &str) {
    host_log(LogLevel::Info, message)
}

fn log_warn(message: &str) {
    host_log(LogLevel::Warn, message)
}

fn log_err(message: &str) {
    host_log(LogLevel::Error, message)
}

fn host_log(level: LogLevel, message: &str) {
    cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "wasi"))] {
                    match proxy_wasm::hostcalls::log(level, message) {
                        Ok(_) => {}
                        Err(status) => panic!(format!("ERROR when attempting to log using `proxy_wasm::hostcalls::log` status returned from host: {:?} ", status))
                    }
            } else {
                println!("{:?} {}", level, message);
            }
        }
}