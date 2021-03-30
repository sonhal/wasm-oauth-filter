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
use std::ops::Deref;


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
        proxy_wasm::hostcalls::log(Info, format!("Cache state={:?}", cache).as_str());


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

    fn send_bad_request(&self, message: String) {
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

    fn oauth_action_handler(&self, action: oauther::Action) -> Action {
        let mut cache = self.cache.borrow_mut();
        cache.store(self).unwrap(); // TODO, check if it is best called here
        match action {
            oauther::Action::Redirect( url, headers) => {
                self.respond_with_redirect(url, headers);
                Action::Pause
            }
            oauther::Action::HttpCall( request) => {
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
                    Duration::from_secs(5));
                Action::Pause
            },
            oauther::Action::Allow(additional_headers) => {

                // TODO simplify and clean this this up
                let old_headers: Vec<(String, String)> = self.get_http_request_headers();
                let mut additional_headers: Vec<(&str, &str)> = serialize_headers(&additional_headers);
                let new_headers: Vec<(String, String)> = merge_old_and_new(old_headers, additional_headers);
                let headers = serialize_string_headers(&new_headers);

                proxy_wasm::hostcalls::log(LogLevel::Info, format!("Resuming call with headers={:?}", headers).as_str());
                self.set_http_request_headers(headers);
                Action::Continue
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

        match self.oauther.handle_request_header(headers) {
            Ok(action) => self.oauth_action_handler(action),
            Err(error) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, error.as_str());
                self.send_bad_request(error);
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
                        let request = StandardTokenResponse::new(
                            AccessToken::new(data.access_token),
                            BasicTokenType::Bearer,
                            EmptyExtraTokenFields {}
                        );

                        let action = self.oauther.handle_token_call_response(&"dummy".to_string(), &request);
                        match action {
                            Ok(action) => {
                                // TODO maybe bad to just ignore return here?
                                self.oauth_action_handler(action);
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

fn log_debug(message: String) {
    cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "wasm32", target_os = "wasi"))] {
                proxy_wasm::hostcalls::log(LogLevel::Debug, &message);
            } else {
                println!("{}", message);
            }
        }
}

#[cfg(test)]

pub mod overrides {
    use proxy_wasm::types::{Status, MapType, BufferType};

    #[no_mangle]
    pub extern "C" fn proxy_done() -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_http_call(
        upstream_data: *const u8,
        upstream_size: usize,
        headers_data: *const u8,
        headers_size: usize,
        body_data: *const u8,
        body_size: usize,
        trailers_data: *const u8,
        trailers_size: usize,
        timeout: u32,
        return_token: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_enqueue_shared_queue(
        queue_id: u32,
        value_data: *const u8,
        value_size: usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_dequeue_shared_queue(
        queue_id: u32,
        return_value_data: *mut *mut u8,
        return_value_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_register_shared_queue(
        name_data: *const u8,
        name_size: usize,
        return_id: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_set_property(
        path_data: *const u8,
        path_size: usize,
        value_data: *const u8,
        value_size: usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_resolve_shared_queue(
        vm_id_data: *const u8,
        vm_id_size: usize,
        name_data: *const u8,
        name_size: usize,
        return_id: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_property(
        path_data: *const u8,
        path_size: usize,
        return_value_data: *mut *mut u8,
        return_value_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_header_map_pairs(
        map_type: MapType,
        return_map_data: *mut *mut u8,
        return_map_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_buffer_bytes(
        buffer_type: BufferType,
        start: usize,
        max_size: usize,
        return_buffer_data: *mut *mut u8,
        return_buffer_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_current_time_nanoseconds(return_time: *mut u64) -> Status {
        Status::Ok
    }

}