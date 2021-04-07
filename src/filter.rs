mod util;
pub mod oauth_service;
pub mod mock_overrides;
mod cache;
mod session;


use proxy_wasm::types::LogLevel;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use url;
use oauth2::basic::{BasicTokenType};
use oauth2::{StandardTokenResponse, AccessToken, EmptyExtraTokenFields};
use oauth2::url::ParseError;
use url::Url;
use crate::oauth_service::{OAuthService, Cache};
use crate::cache::{SharedCache};
use oauth2::http::HeaderMap;
use std::cell::RefCell;
use std::rc::Rc;
use cookie::Expiration::Session;
use crate::session::SessionCache;


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
    oauther: OAuthService,
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
        log_debug("Creating new HttpContext");
        log_info(format!("Cache state={:?}", cache).as_str());


        let cache = Rc::new(RefCell::new(cache));
        let oauther = OAuthService::new(config.clone(), Box::new(cache.clone()))?;
        Ok(OAuthFilter {
            config,
            oauther,
            cache
        })
    }

    fn send_error(&self, code: u32, response: ErrorResponse) {
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
        self.send_error(400, ErrorResponse {
            status: "400".to_string(),
            error: message,
            error_description: None
        });
    }

    fn fail(&mut self) {
      log::debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
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

    fn oauth_action_handler(&self, action: oauth_service::Action) -> Result<Action, Status> {
        let mut cache = self.cache.borrow_mut();

        match action {
            oauth_service::Action::Redirect(url, headers, update) => {
                // TODO store session update
                cache.set(update);
                cache.store(self).unwrap(); // TODO, check if it is best called here
                self.respond_with_redirect(url, headers);
                Ok(Action::Pause)
            }
            oauth_service::Action::HttpCall(request) => {
                let mut request_headers: Vec<(&str, &str)> = serialize_headers(&request.headers);

                let token_url: Url = self.config.token_uri.parse().unwrap();
                let authority = token_url.origin().unicode_serialization();
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
                    Duration::from_secs(5))?;
                Ok(Action::Pause)
            },
            oauth_service::Action::Allow(additional_headers) => {

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
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let headers = self.get_http_request_headers();
        let headers: Vec<(&str, &str)>
            = headers.iter().map( |(name, value)|{ (name.as_str(), value.as_str()) }).collect();

        match self.oauther.handle_request(None, headers) {
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
        log_debug("Token response from auth server received");
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
                        let request = StandardTokenResponse::new(
                            AccessToken::new(data.access_token),
                            BasicTokenType::Bearer,
                            EmptyExtraTokenFields {}
                        );

                        let action = self.oauther.handle_token_call_response(&"dummy".to_string(), &request);
                        match action {
                            Ok(action) => {
                                // TODO maybe bad to just ignore return here?
                                match self.oauth_action_handler(action) {
                                    Ok(_) => {} // TODO maybe seperate handling for token responses?
                                    Err( status) => self.send_error(
                                        500,
                                        create_error(format!("ERROR when handling action, status{:?}", status)))
                                }
                            },
                            Err(error) => self.send_error(
                                500,
                                create_error(format!("Invalid token response:  {:?}", error))
                            )
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
        error,
        error_description: Some(error_description)
    }
}

fn create_error(error: String) -> ErrorResponse {
    ErrorResponse{
        status: "error".to_owned(),
        error,
        error_description: None
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