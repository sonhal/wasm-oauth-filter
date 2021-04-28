mod util;
pub mod mock_overrides;
mod cache;
mod session;
mod messages;
mod oauth_client;
mod oauth_client_types;
mod discovery;
mod config;


use proxy_wasm::types::LogLevel;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;
use serde::{Deserialize};
use url;
use oauth2::basic::{BasicTokenType};
use oauth2::{StandardTokenResponse, AccessToken, EmptyExtraTokenFields};
use url::{Url, ParseError};
use crate::cache::{SharedCache};
use oauth2::http::HeaderMap;
use std::cell::RefCell;
use crate::session::{SessionCache, SessionUpdate};
use std::ops::Deref;
use crate::messages::{ErrorBody, DownStreamResponse, TokenResponse, HttpRequest};
use crate::oauth_client::{CALLBACK_PATH, START_PATH, SIGN_OUT_PATH, ClientConfig};
use crate::oauth_client_types::{TokenRequest, ClientError, Redirect, Access, Request};
use url::form_urlencoded::parse;
use crate::discovery::{ConfigError, JsonWebKeySet, ProviderMetadata};
use std::collections::HashMap;
use jwt_simple::prelude::RSAPublicKeyLike;
use jwt_simple::claims::{NoCustomClaims, JWTClaims};
use jwt_simple::Error;


#[cfg(not(test))]
#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Debug);
    proxy_wasm::set_root_context(
        |_| -> Box<dyn RootContext> {
            Box::new(OAuthRootContext {
                config: None,
                provider_metadata: None,
                jwks: None,
                request_active: false,
            })
        });
}

struct OAuthRootContext {
    config: Option<RawFilterConfig>,
    provider_metadata: Option<ProviderMetadata>,
    jwks: Option<JsonWebKeySet>,
    request_active: bool,
}

struct OAuthFilter {
    config: RawFilterConfig,
    oauth_client: crate::oauth_client::OAuthClient,
    cache: RefCell<SharedCache>,
}


#[derive(Deserialize, Clone, Debug)]
pub struct RawFilterConfig {
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
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_cookie_expire")]
    cookie_expire: u64, // in seconds
    #[serde(default = "default_extra_params")]
    extra_params: Vec<(String, String)>,
    oidc_issuer_url: Option<String>
}


impl OAuthFilter {

    fn new(config: RawFilterConfig, cache: SharedCache) -> Result<OAuthFilter, ParseError> {
        log::debug!("Creating new HttpContext");
        log::debug!("Cache for HttpContext = {:?}", cache);
        log::debug!("Config for HttpContext = {:?}", config);
        let cache = RefCell::new(cache);

        let oauth_client = crate::oauth_client::OAuthClient::new(config.client_config())?;
        Ok(OAuthFilter {
            config,
            oauth_client,
            cache
        })
    }

    fn send_error(&self, code: u32, response: crate::messages::ErrorBody) {
        let body = serde_json::to_string_pretty(&response).unwrap();
        log::error!("{}", body);
        self.send_http_response(
            code,
            vec![("Content-Type", "application/json")],
            Some(body.as_bytes())
        );
    }


    fn send_error_response(&self, response: DownStreamResponse) {
        let body = serde_json::to_string_pretty(&response).unwrap();
        let mut headers = response.headers();
        headers.push(("Content-Type", "application/json"));
        log::error!("{}", body);

        self.send_http_response(
            response.code(),
            headers,
            Some(body.as_bytes())
        );
    }

    // Send redirect response to end-user
    fn respond_with_redirect(&self, url: Url, headers: Vec<(String, String)>) {
        let mut headers: Vec<(&str, &str)> =
            headers.iter().map( |(name, value)| { (name.as_str(), value.as_str()) }).collect();
        headers.append(&mut vec![("location", url.as_str())]);

        self.send_http_response(
            302,
            headers,
            None
        );
    }

    // Parse session cookie from request headers
    fn session(&self, headers: &Vec<(String, String)>) -> Option<crate::session::Session> {
        crate::session::Session::_from_headers(
            self.config.cookie_name.clone(),
            headers,
            self.cache.borrow().deref()
        )
    }

    // Call the client by right method depending on the request path
    fn endpoint(&self, request: crate::oauth_client_types::Request, session: Option<crate::session::Session>) -> Result<FilterAction, ClientError> {
        let mut cache = self.cache.borrow_mut();
        if request.url().path().starts_with(CALLBACK_PATH) {
            let token_request = self.oauth_client.callback(request, session)?;
            Ok(FilterAction::TokenRequest(token_request))
        }
        else if request.url().path().starts_with(START_PATH) {
            let (redirect, update) = self.oauth_client.start(request)?;
            cache.set(update);
            cache.store(self).unwrap(); // TODO handle errors
            Ok(FilterAction::Redirect(redirect))
        } else if request.url().path().starts_with(SIGN_OUT_PATH) {
            let (response, update) = self.oauth_client.sign_out(session)?;
            cache.set(update);
            cache.store(self).unwrap(); // TODO handle errors
            Ok(FilterAction::Response(response))
        } else {
            match self.oauth_client.proxy(session)? {
                Access::Denied(response) => Ok(FilterAction::Response(response)),
                Access::Allowed(headers) => Ok(FilterAction::Allow(headers)),
                Access::UnAuthenticated => {
                    // Clean up
                    let (redirect, update) = self.oauth_client.start(request)?;
                    cache.set(update);
                    cache.store(self).unwrap(); // TODO handle errors
                    Ok(FilterAction::Redirect(redirect))
                }
            }
        }
    }
}

// Represent actions the filter carries out during OAuth
enum FilterAction {
    TokenRequest(TokenRequest),
    Redirect(Redirect),
    Response(DownStreamResponse),
    Allow(Vec<(String, String)>)
}


// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let headers = self.get_http_request_headers();
        let user_session = self.session(&headers);

        let request = Request::new(headers);
        let request = if let Err(error) = request {
            self.send_error_response(error.response());
            return Action::Pause;
        } else { request.unwrap() };

        match self.endpoint(request, user_session) {
            Ok(filter_action) => {
                match filter_action {
                    FilterAction::TokenRequest(request) => {
                        self.dispatch_http_call(
                            &self.config.auth_cluster,
                            request.headers(),
                            Some(request.body()),
                            vec![],
                            Duration::from_secs(20));
                        Action::Pause
                    }
                    FilterAction::Redirect(redirect) => {
                        self.respond_with_redirect(redirect.url().clone(), redirect.headers().clone());
                        Action::Pause
                    }
                    FilterAction::Response(response) => {
                        self.send_error_response(response);
                        Action::Pause
                    }
                    FilterAction::Allow(token_headers) => {
                        for header in token_headers {
                            self.add_http_request_header(header.0.as_str(), header.1.as_str());
                        }
                        Action::Continue
                    }
                }
            }
            Err(error) => {
                self.send_error_response(error.response());
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
        log::debug!("Token response from auth server received");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match serde_json::from_slice::<crate::messages::TokenResponse>(body.as_slice()) {
                Ok(response) => {
                    match response {
                        crate::messages::TokenResponse::Error(response) =>
                            self.send_error(500, response.to_error_body()),
                        crate::messages::TokenResponse::Success(response) => {
                            log::debug!("access token found");

                            let headers = self.get_http_request_headers();
                            let user_session = self.session(&headers);

                            match self.oauth_client.token_response(TokenResponse::Success(response), user_session) {
                                Ok((redirect, update)) => {
                                    let mut cache = self.cache.borrow_mut();
                                    cache.set(update);
                                    cache.store(self).unwrap(); // TODO handle errors
                                    self.respond_with_redirect(redirect.url().clone(), redirect.headers().clone())
                                }
                                Err(error) => self.send_error_response(error.response())
                            }
                        }
                    }
                },
                Err(_) => {
                    let error_message = String::from_utf8(body);
                    log::debug!("Error response from token endpoint={:?}", error_message);
                    self.send_error(
                        500,
                        ErrorBody::new("500".to_string(), format!("Invalid token response:  {:?}", error_message), None)
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

impl Context for OAuthRootContext {

    // Handle http discovery responses during configuration
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        log::debug!("OAuthRootContext received HTTP response");
        let bytes = match self.get_http_call_response_body(0, body_size) {
            None => {
                log::error!("No body in HTTP response");
                return;
            }
            Some(bytes) => bytes,
        };

        if self.provider_metadata.is_none() {
            ProviderMetadata::from_bytes(bytes)
                .map_err(|err| {
                    log::error!("ERROR parsing ProviderMetadata = {}", err);
                    panic!("Invalid ProviderMetadata response") // Crash hard here as we cannot serve requests
                })
                .map(|provider_metadata| {
                    self.provider_metadata = Some(provider_metadata);
                    let request = discovery::jwks_request(self.provider_metadata.clone().unwrap().jwks_url());
                    match self.dispatch(request) {
                        Ok(_) => { log::debug!("successfully JWKS request")}
                        Err(err) => { log::error!("Failed to JWKS request, Envoy status = {:?}", err)}
                    }
                    log::debug!("Provider Metadata configured: {:?}", self.provider_metadata)
                });
        } else {
            JsonWebKeySet::from_bytes(bytes)
                .map_err( |err| {
                    log::error!("ERROR parsing JsonWebKeySet = {}", err);
                    panic!("Invalid JWKS response body");
            })
                .map(|jwks| {
                    self.jwks = Some(jwks);
                    log::debug!("JWKS configured: {:?}", self.jwks);
                    self.stop_discovery();
                });
        }
    }
}

impl RootContext for OAuthRootContext {

    // handles receiving of configuration when filter is instantiated
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_buffer) = self.get_configuration() {
            let oauth_filter_config: RawFilterConfig = serde_json::from_slice(config_buffer.as_slice()).unwrap();
            log::info!("OAuth filter configured with:\n{:?}", oauth_filter_config);
            self.config = Some(oauth_filter_config);

            if self.config.as_ref().unwrap().is_oidc_configured() {
                self.start_discovery();
                true
            } else { true }
        } else {
            log::error!("Error when configuring RootContext, no configuration supplied for OAuth filter");
            false
        }
    }

    // Handles on tick events from host
    fn on_tick(&mut self) {
        log::debug!("RootContext tick, request active={}", self.request_active);
        if !self.request_active {
            match self.dispatch_discovery() {
                Ok(_) => { log::debug!("successfully dispatched discovery request")}
                Err(_) => { log::error!("Failed to dispatch discovery request")}
            }
        }
        self.request_active = true;
    }

    // Creates a new HttpContext for a HTTP request from end-user
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        match self.config.as_ref() {
            None => {
                log::error!("No configuration supplied, cannot create HttpContext");
                None
            },
            Some(filter_config) => {
                match SharedCache::from_host(self) {
                    Ok(cache) => {
                        log::debug!("Stored cache returned from host");
                        Some(Box::new(OAuthFilter::new(self.filter_config().unwrap(), cache).unwrap()))
                    }
                    Err(_) => {
                        // attempt to create shared
                        log::info!("Could not get shared cache from host, attempt to create new");
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

impl OAuthRootContext {

    fn filter_config(&self) -> Result<RawFilterConfig, ConfigError> {
        let filter_config = if let Some(config) =  &self.config {
            config
        } else { return Err(ConfigError::BadState("RootContext config not set".to_string())) };
        if filter_config.is_oidc_configured() {
            match &self.provider_metadata {
                None => return Err(ConfigError::BadState("provider_metadata not set".to_string())),
                Some(provider_metadata) => Ok(
                    RawFilterConfig {
                        token_uri: provider_metadata.token_endpoint().clone().unwrap().to_string(),
                        auth_uri: provider_metadata.authorization_endpoint().to_string(),
                        ..filter_config.clone()
                    }
                ),
            }
        } else {
            Ok(filter_config.clone())
        }

    }

    // Activate RootContext tick handler which will dispatch discovery request
    fn start_discovery(&self) {
        // Cannot dispatch HTTP calls in config handler, so we need to dispatch in tick handler
        self.set_tick_period(Duration::from_secs(2))
    }

    // Deactivate RootContext tick handler
    fn stop_discovery(&self) {
        // Stop the tick events
        self.set_tick_period(Duration::from_secs(0))
    }

    // Dispatch a OIDC discovery request to the authorization server
    fn dispatch_discovery(&self) -> Result<(), discovery::ConfigError> {

        let config = if let Some(config) = &self.config {
            config
        } else { return Err(discovery::ConfigError::Parse("Filter config is None".to_string())); };

        if config.oidc_issuer_url.is_none() {
            return Err(discovery::ConfigError::Parse("OIDC issuer is not set".to_string()));
        }
        let oidc_url = config.oidc_issuer_url.clone().unwrap()
            .parse::<Url>()
            .map_err(|err| { discovery::ConfigError::Parse(err.to_string())})?;
        let request = discovery::discovery_request(oidc_url)
            .map_err(|err| { ConfigError::Parse(err.to_string())})?;

        let result = self.dispatch(request);
        if result.is_err() {
            log::error!("ERROR when attempting http request to discovery endpoint, error={:?}", result);
            return Err(ConfigError::Response(500, "Error".to_string())); // TODO FIX
        }
        Ok(())
    }

    // Dispatch HTTP request to the authorization server
    fn dispatch(&self, request: HttpRequest) -> Result<u32, Status> {
        log::debug!("HTTP request to cluster={}  request={:?}",&self.config.as_ref().unwrap().auth_cluster, request);
        self.dispatch_http_call(
            &self.config.as_ref().unwrap().auth_cluster,
            request.headers(),
            None,
            vec![],
            Duration::from_secs(5)
        )
    }
}


impl RawFilterConfig {
    fn is_oidc_configured(&self) -> bool {
        self.scopes.contains(&"openid".to_string())
    }

    fn client_config(&self) -> ClientConfig {
        ClientConfig::new(
            &self.cookie_name,
            self.redirect_uri.as_str(),
            self.auth_uri.as_str(),
            self.token_uri.as_str(),
            &self.client_id,
            &self.client_secret,
            self.extra_params.clone(),
            self.scopes.clone(),
            self.cookie_expire as u32
        )
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

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

fn default_extra_params() -> Vec<(String, String)> {
    Vec::new()
}

fn default_cookie_expire() -> u64 { 3600 }