
mod util;
pub mod oauther;


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
use oauth2::{ClientId, ClientSecret, AuthUrl, TokenUrl, RedirectUrl, PkceCodeChallenge, CsrfToken, Scope, PkceCodeVerifier, AuthorizationCode, HttpRequest, AuthType, http};
use oauth2::url::ParseError;
use base64;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use getrandom::getrandom;
use url::Url;


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
    auth_server: Url,
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

    fn new(config: FilterConfig) -> Result<OAuthFilter, ParseError> {
        let client =
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(config.client_secret.clone())),
                AuthUrl::new(config.auth_uri.clone())?,
                Some(TokenUrl::new(config.token_uri.clone())?)
            )
                .set_redirect_url(RedirectUrl::new(config.redirect_uri.clone())?);

        let auth_server = Url::parse(config.issuer.as_str()).unwrap();
        Ok(OAuthFilter {
            config,
            client,
            auth_server
        })
    }

    fn send_error(&self, code: u32, response: ErrorResponse) {
        let body = serde_json::to_string_pretty(&response).unwrap();
        error!("{}", body);
        self.send_http_response(
            code,
            vec![("Content-Type", "application/json")],
            Some(body.as_bytes())
        );
    }

    fn fail(&mut self) {
      debug!("auth: allowed");
      self.send_http_response(403, vec![], Some(b"not authorized"));
    }

    fn token_header(&self) -> Option<String> {
        self.get_http_request_header(self.config.target_header_name.as_str())
    }

    fn session_cookie(&self) -> Option<String> {
        if let Some(cookie_header) = self.get_http_request_header("cookie") {
            let cookies: Vec<_> = cookie_header.split(";").collect();
            for cookie_string in cookies {
                let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                let cookie_name = &cookie_string[0..cookie_name_end];
                if cookie_name.trim() == self.config.cookie_name {
                    return Some(cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_owned());
                }
            }
        }
        None
    }

    fn code_param(&self) -> Option<String> {
        let authority = self.get_http_request_header(":authority");
        let path = self.get_http_request_header(":path");
        let url =  (authority, path);
        if let (Some(authority), Some(path)) = url {
            log(LogLevel::Info, format!("path value found: {}", path).as_str());
            let params = url::Url::parse(format!("http://{}{}", authority, path).as_str()).unwrap();
            for (k, v) in params.query_pairs() {
                log(LogLevel::Info, format!("query {}={}", k, v).as_str());
                if k.to_string() == "code" {
                    return Some(v.to_string())
                }
            }
            return None
        }
        None
    }

    pub fn new_random_verifier(num_bytes: u32) -> PkceCodeVerifier {
        let random_bytes: Vec<u8> = (0..num_bytes).map(|_| {
            let mut buf = [0u8; 1];
            getrandom(&mut buf).unwrap();
            buf[0]
        }).collect();
        PkceCodeVerifier::new(base64::encode_config(
            &random_bytes,
            base64::URL_SAFE_NO_PAD,
        ))
    }

    fn send_authorization_redirect(&self) {
        // TODO cache verifier for use in the token call
        let pkce_challenge= PkceCodeChallenge::from_code_verifier_sha256(&OAuthFilter::new_random_verifier(32));

        let (auth_url, csrf_token) = self.client
            .authorize_url(|| CsrfToken::new("state123".to_string()))
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            //.set_pkce_challenge(pkce_challenge)
            .url();

        self.send_http_response(
            302,
            vec![
                ("Location", auth_url.as_str()),
                //("Set-Cookie", format!("{}={};Max-Age=300", self.config.cookie_name, "RandomCookieValue").as_str())
            ],
            None
        );
    }
}

// Implement http functions related to this request.
// This is the core of the filter code.
impl HttpContext for OAuthFilter {

    // This callback will be invoked when request headers arrive
    fn on_http_request_headers(&mut self, num_headers: usize) -> Action {

        if let Some(code) = self.code_param() {

            let request = util::token_request(&AuthType::RequestBody,
                                &ClientId::new(self.config.client_id.clone()),
                                Some(&ClientSecret::new(self.config.client_id.clone())),
                                &[],
                                Some(&RedirectUrl::new(self.config.redirect_uri.clone()).unwrap()),
                                None,
                                &TokenUrl::new(self.config.token_uri.clone()).unwrap(),
                                vec![("grant_type", "authorization_code"), ("code", code.as_str())]);

            let mut request_headers: Vec<(&str, &str)> = request.headers.iter().map( |(k, v)| { (k.as_str(), v.to_str().unwrap() )}).collect();
            let authority = self.auth_server.origin().unicode_serialization();
            request_headers.append(&mut vec![
                (":method", "POST"),
                (":path", "/customiss/token"),
                (":authority", authority.as_str()),
            ]);
            self.dispatch_http_call("cluster_mock_auth", request_headers, Some(request.body.as_slice()), vec![],  Duration::from_secs(5));

            // self.set_http_request_header(":path", Some("/"));
            log(LogLevel::Info, format!("Received path with code: {}", code.as_str()).as_str());
            return Action::Pause
        }
        if let None = self.session_cookie() {
            self.send_authorization_redirect();
            return Action::Pause
        }

        log(LogLevel::Error, "Session cookie found, Access granted");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        // Add a header on the response.
        self.set_http_response_header("Hello", Some("world"));
        Action::Continue
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
        log(LogLevel::Debug, "Token response from auth server received");
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

                    if data.id_token != "" {
                        debug!("id_token found. Setting cookie and redirecting...");
                        self.send_http_response(
                            302,
                            vec![
                                ("Set-Cookie", format!("{}={};Max-Age=300", self.config.cookie_name, "RandomCookieValue").as_str()),
                                ("Location", "http://localhost:8090/"),
                            ],
                            Some(b""),
                        );
                        return
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

