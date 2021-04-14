use oauth2::basic::BasicClient;
use crate::{FilterConfig, util};
use std::string::ParseError;
use oauth2::{AuthUrl, TokenUrl, RedirectUrl, ClientId, ClientSecret, HttpRequest, PkceCodeChallenge, CsrfToken, Scope, PkceCodeVerifier, AuthType};
use time::Duration;
use crate::session::{Session, SessionUpdate, SessionType};
use crate::messages::{DownStreamResponse, TokenResponse};
use url::Url;
use oauth2::http::HeaderMap;
use std::any::Any;

type Headers = Vec<(String, String)>;

#[derive(Debug)]
struct Request {
    headers: Headers,
    url: Url,
}

impl Request {
    fn new(headers: Headers) -> Result<Self, ClientError> {
        let url = Self::request_url(headers.clone())?;
        Ok(Request { headers, url })
    }

    fn authorization_code(&self) -> Option<String> {
        self.find_query("code")
    }


    fn state(&self) -> Option<String>  {
        self.find_query("state")
    }

    fn find_query(&self, name: &str) -> Option<String>  {
        for (key, value ) in self.url.query_pairs() {
            if key == name {
                return Some(value.to_string())
            }
        }
        None
    }


    fn request_url(headers: Headers) -> Result<Url, ClientError> {
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1.clone() });
        let mut host_url = Self::host_url(headers)?;
        host_url.join(path.as_ref().unwrap_or(&"".to_string()).as_str())
            .map_err(|err| {
                ClientError::new(500, format!("Could not create URL from base={}, and path={}", host_url, path.unwrap_or_default()),None )
            })
    }

    fn host_url(headers: Headers) -> Result<Url, ClientError> {
        let scheme =
            headers.iter().find(|(name, _)| { *name == "x-forwarded-proto" }).map(|entry| { entry.1.clone() });
        let authority =
            headers.iter().find(|(name, _)| { *name == ":authority" }).map(|entry| { entry.1.clone() });
        match (scheme, authority) {
            (None, _) => Err(ClientError::new(400,"No scheme in request header".to_string(), None)),
            (_, None) => Err(ClientError::new(400, "No authority in request header".to_string(), None)),
            (Some(scheme), Some(authority)) => {
                Ok(format!("{}://{}", scheme, authority).parse().unwrap())
            }
        }
    }
}

struct OAuthClient {
    config: ServiceConfig,
    client: BasicClient,
}

struct ServiceConfig {
    cookie_name: String,
    redirect_url: url::Url,
    authorization_url: url::Url,
    token_url: url::Url,
    client_id: ClientId,
    client_secret: ClientSecret,
    extra_params: Vec<(String, String)>,
    sign_out_path: String,
    cookie_expire: Duration,
}

pub struct Redirect {
    url: Url,
    headers: Headers
}

impl Redirect {
    fn new(url: Url, headers: Headers) -> Self {
        Redirect { url, headers }
    }
}

#[derive(Debug, Clone)]
struct TokenRequest {
    raw_request: HttpRequest,
}

impl TokenRequest {

    fn new(raw_request: HttpRequest) -> TokenRequest {
        Self { raw_request }
    }

    pub fn headers(&self) -> Vec<(&str, &str)> {
        let mut headers = self.serialize_headers();
        headers.append(&mut vec![
            (":method", "POST"),
            (":path", self.raw_request.url.path()),
            (":authority", self.raw_request.url.host_str().unwrap())]);
        headers
    }
    pub fn body(&self) -> &[u8] {
        self.raw_request.body.as_slice()
    }

    fn serialize_headers(&self) -> Vec<(&str, &str)> {
        self.raw_request.headers.iter()
            .map(
                |( name, value)|
                    { (name.as_str(), value.to_str().unwrap()) }
            ).collect()
    }
}

#[derive(Debug)]
pub enum Access {
    Denied(String),
    Allowed(Headers),
    UnAuthenticated,
}

#[derive(Debug)]
pub enum Action {
    Redirect(Url, Headers, SessionUpdate),

    Allow(Headers)
}

#[derive(Debug)]
struct ClientError {
    status: u64,
    message: String,
    description: Option<String>,
}

impl ClientError {
    fn new(status: u64, message: String, description: Option<String>) -> ClientError {
        ClientError {
            status,
            message,
            description
        }
    }

    pub fn response(&self) -> DownStreamResponse {
        DownStreamResponse::new(vec![], self.status, self.message.clone())
    }
}

impl OAuthClient {

    pub fn new(
        config: FilterConfig,
    ) -> Result<OAuthClient, ParseError> {
        let auther_config = ServiceConfig::from(config);

        let client = BasicClient::new(
            auther_config.client_id.clone(),
            Some(auther_config.client_secret.clone()),
            AuthUrl::from_url(auther_config.authorization_url.clone()),
            Some(TokenUrl::from_url(auther_config.token_url.clone()))
        )
            .set_redirect_url(RedirectUrl::from_url(auther_config.redirect_url.clone()));

        Ok(OAuthClient {
            config: auther_config,
            client,
        })
    }

    pub fn sign_out(&self, session: Option<Session>) -> Result<(DownStreamResponse, SessionUpdate), ClientError> {
        match session {
            None => {
                Err(ClientError::new(200, "No session to sign out from".to_string(), None))
            }
            Some(session) => {
                let header = session.clear_cookie_header_tuple(&self.config.cookie_name);
                Ok((DownStreamResponse::new(vec![header], 200, "Signed Out".to_string()), session.end_session()))
            }
        }
    }

    // Starts a new Authentication Code flow. Note that it does not invalidate any already active sessions in the cache
    pub fn start(&self, request: Request) -> Result<(Redirect, SessionUpdate), ClientError> {
        let (redirect_url, state, verfier) = self.authorization_server_redirect();

        let update = SessionUpdate::auth_request(self.valid_url(request.url).to_string(), state, verfier);
        let header = update.set_cookie_header_tuple(&self.config.cookie_name, self.config.cookie_expire);
        Ok((Redirect::new(redirect_url, vec![header]), update))
    }

    pub fn callback(&self, request: Request, session: Option<Session>) -> Result<TokenRequest, ClientError>{

        let session = if let None = session {
            return Err(ClientError::new(500, "No session for this request".to_string(), None));
        } else {  session.unwrap() };

        let verifiers = if let SessionType::AuthorizationRequest(verifiers) = session.data {
            verifiers
        } else { return Err(ClientError::new(500, "Session for authorization callback is not valid".to_string(), None))};

        let code = request.authorization_code();
        let state = request.state();
        match (code, state) {
            (Some(code), Some(state)) => {
                verifiers.validate_state(state);
                let request = self.create_token_request(code, verifiers.code_verifiers());
                Ok(TokenRequest { raw_request: request})
            }
            _ => {
                log::warn!("Received request={:?} on callback endpoint without required parameters", request);
                Err(ClientError::new(400,"Received request on callback endpoint without required parameters".to_string(), None))
            }
        }
    }

    pub fn token_response(&self, response: TokenResponse, session: Option<Session>) -> Result<(Redirect, SessionUpdate), ClientError>{
        match response {
            TokenResponse::Error(error) =>
                Err(ClientError::new(500, format!("Token endpoint error={}", error.to_error_body().serialize()), None)),
            TokenResponse::Success(response) => {
                let access_token = response.access_token.clone();
                let id_token = response.id_token.clone();
                let expires_in = response.expires_in();
                let refresh_token = response.id_token.clone();

                let session = if let Some(session) = session {
                    session
                } else {
                    return Err(ClientError::new(500, "Token response handling error, no session for the response".to_string(), None));
                };

                match &session.data {
                    SessionType::AuthorizationRequest(verifiers) => {
                        Ok((Redirect::new(
                            verifiers.request_url().parse().unwrap(),
                            vec![]),
                         session.token_response(access_token, expires_in, id_token, refresh_token)))
                    }
                    _ => Err(ClientError::new(500, format!("Token response handling error, session does not contain authorization request verifiers, session type={:?}", session.data.type_id()), None)),
                }
            }
        }
    }

    pub fn proxy(&self, session: Option<Session>) -> Result<Access, ClientError>{
        match session {
            None => Ok(Access::UnAuthenticated),
            Some(session) => {
                match session.data {
                    SessionType::Tokens(tokens) => {
                        match tokens.is_access_token_valid() {
                            Ok(is_valid) => {
                                match is_valid {
                                    true => Ok(Access::Allowed(tokens.upstream_headers_tuple())),
                                    false => {
                                        // TODO use refresh token if valid
                                        Ok(Access::Denied("Tokens expired".to_string()))
                                    }
                                }
                            }
                            Err(err) => Err(ClientError::new(500, format!("Error occurred while getting system time, error={}", err), None)),
                        }
                    }
                    _ => Ok(Access::Denied("UnAuthorized session".to_string()))
                }
            }
        }
    }

    fn authorization_server_redirect(&self) -> (Url, String, String) {
        let verifier = util::new_random_verifier(32);
        let pkce_challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        let mut builder = self.client
            .authorize_url(|| CsrfToken::new(util::new_random_verifier(32).secret().to_string()))
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge);

        // Add extra parameters for Authorization redirect from configuration
        for param in &self.config.extra_params {
            builder = builder.add_extra_param(param.0.as_str(), param.1.as_str());
        }


        let (auth_url, csrf_token) = builder.url();
        let state = csrf_token.secret().clone();

        (auth_url, state, verifier.secret().to_string())
    }

    fn create_token_request(&self, code: String, code_verifier: Option<String>) -> HttpRequest {
        let mut params = vec![("grant_type", "authorization_code"), ("code", code.as_str())];

        // if we have a PKCE verifer we send it in the token request
        let verifier_string;
        if code_verifier.is_some() {
            verifier_string = code_verifier.unwrap();
            params.push(("code_verifier", verifier_string.as_str()))
        }

        util::token_request(
            &AuthType::RequestBody,
            &(self.config.client_id),
            Some(&self.config.client_secret),
            &[],
            Some(&RedirectUrl::from_url(self.config.redirect_url.clone())),
            None,
            &TokenUrl::from_url(self.config.token_url.clone()),
            params
        )
    }

    fn valid_url(&self, mut url: Url) -> Url {
        if url.path().starts_with("/callback") || url.path().starts_with("/auth") || url.path().starts_with("/sign_out") {
            url.set_path("/");
            return url
        }
        url
    }
}


impl ServiceConfig {
    fn from(config: FilterConfig) -> ServiceConfig {
        ServiceConfig {
            cookie_name: config.cookie_name,
            redirect_url: url::Url::parse(config.redirect_uri.as_str())
                .expect("Error parsing FilterConfig redirect_uri when creating OAutherConfig"),
            authorization_url: url::Url::parse(config.auth_uri.as_str())
                .expect("Error parsing FilterConfig auth_uri when creating OAutherConfig"),
            token_url: url::Url::parse(config.token_uri.as_str())
                .expect("Error parsing FilterConfig token_uri when creating OAutherConfig"),
            client_id: ClientId::new(config.client_id),
            client_secret: ClientSecret::new(config.client_secret),
            extra_params: config.extra_params,
            sign_out_path: "/sign_out".to_string(),
            cookie_expire: Duration::seconds(config.cookie_expire as i64)
        }
    }
}





#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::matches;
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use oauth2::{AccessToken, StandardTokenResponse, EmptyExtraTokenFields};
    use oauth2::http::header::{FORWARDED, SET_COOKIE, AUTHORIZATION};
    use oauth2::basic::{BasicTokenResponse, BasicTokenType};
    use crate::session::{AuthorizationTokens, AuthorizationResponseVerifiers, Session, SessionType};
    use std::alloc::System;
    use std::time::SystemTime;
    use std::io::stdin;
    use crate::FilterConfig;
    use crate::messages::{TokenResponse, SuccessfulResponse};


    fn test_config() -> FilterConfig {
        FilterConfig {
            redirect_uri: "http://redirect".to_string(),
            target_header_name: "".to_string(),
            cookie_name: "sessioncookie".to_string(),
            auth_cluster: "some_cluster".to_string(),
            issuer: "".to_string(),
            auth_uri: "http://authorization".to_string(),
            token_uri: "http://token".to_string(),
            client_id: "myclient".to_string(),
            client_secret: "mysecret".to_string(),
            extra_params: Vec::new(),
            cookie_expire: 120,
        }
    }

    fn test_client() -> crate::oauth_clientV2::OAuthClient {
        crate::oauth_clientV2::OAuthClient::new(test_config()).unwrap()
    }

    fn test_valid_session() -> (String, Session) {
        ("testession".to_string(), Session::tokens(
            "testession".to_string(),
            "testaccesstoken".to_string(),
            Some(std::time::Duration::from_secs(120)),
            Some("testidtoken".to_string()),
            None,
        ))
    }

    fn test_callback_session() -> (String, Session) {
        ("testession".to_string(), Session::verifiers(
            "testession".to_string(),
            SystemTime::now(),
            "http://localhost/path".to_string(),
            "123".to_string(),
            Some("abc".to_string()))
        )
    }

    fn test_request() -> Request {
        Request::new( vec![
            ("random_header".to_string(), "value".to_string()),
            ("x-forwarded-proto".to_string(), "http".to_string()),
            (":authority".to_string(), "localhost".to_string()),
            (":path".to_string(), "/test-path".to_string())
        ]).unwrap()
    }

    fn test_callback_request() -> Request {
        Request::new( vec![
            ("random_header".to_string(), "value".to_string()),
            ("x-forwarded-proto".to_string(), "http".to_string()),
            (":authority".to_string(), "localhost".to_string()),
            (":path".to_string(), "/callback?code=1234abcd&state=123".to_string())
        ]).unwrap()
    }

    fn test_authorized_request() -> (Request, Session) {
        (Request::new( vec![
            ("random_header".to_string(), "value".to_string()),
            ("x-forwarded-proto".to_string(), "http".to_string()),
            (":authority".to_string(), "localhost".to_string()),
            (":path".to_string(), "/resource".to_string())
        ]).unwrap(),
        Session::tokens(
            "mysession".to_string(),
            "testaccesstoken".to_string(),
            Some(std::time::Duration::from_secs(120)),
            Some("testidtoken".to_string()),
            None,
        ))
    }

    fn test_successful_token_response() -> TokenResponse {
        TokenResponse::Success(SuccessfulResponse::new(
            "testaccesstoken".to_string(),
            Some("testidtoken".to_string()),
            Some("bearer".to_string()),
            None,
            Some(120)))
    }

    fn contains_set_cookie_header(headers: Vec<(String, String)>)  -> bool {
        for (key, val) in headers {
            if key == SET_COOKIE.to_string() {
                return true;
            }
        }
        false
    }

    #[test]
    fn new() {
        let client = crate::oauth_clientV2::OAuthClient::new(test_config());
        assert!(client.is_ok())
    }

    #[test]
    fn sign_out() {
        let client = test_client();
        let (_, session) = test_valid_session();

        let result = client.sign_out(Some(session));
        assert!(result.is_ok());
        let (response, update) = result.unwrap();
        assert!(contains_set_cookie_header(response.serialize().0))
    }

    #[test]
    fn start() {
        let client = test_client();
        let request = test_request();
        let result = client.start(request);
        assert!(result.is_ok());
        let (redirect, update) = result.unwrap();
        assert_eq!(redirect.url.origin(), client.config.authorization_url.origin());
        // The session we are storing should be an AuthorizationRequest
        assert!(matches!(update.create_session().data, SessionType::AuthorizationRequest(..)));
    }

    #[test]
    fn callback() {
        let client = test_client();
        let request = test_callback_request();
        let (id, callback_session) = test_callback_session();

        let result = client.callback(request, Some(callback_session));
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.clone().raw_request.url, client.config.token_url);
        // The body of the token request should contain the client id and secret
        assert!(String::from_utf8(result.clone().body().to_vec()).unwrap().contains(&client.config.client_secret.secret().to_ascii_lowercase()));
        assert!(String::from_utf8(result.clone().body().to_vec()).unwrap().contains(&client.config.client_id.to_ascii_lowercase()));
    }


    #[test]
    fn token_response() {
        let client = test_client();
        let response = test_successful_token_response();
        let (id, callback_session) = test_callback_session();
        let result = client.token_response(response, Some(callback_session));
        assert!(result.is_ok());
    }

    #[test]
    fn proxy() {
        let client = test_client();
        let (request, session) = test_authorized_request();


        // Authenticated and valid sessions are accepted
        let result = client.proxy(Some(session));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Access::Allowed(..)));

        // Empty (first request) session are unauthenticated
        let result = client.proxy(None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Access::UnAuthenticated));

        // Sessions that are waiting for callback are denied
        let result = client.proxy(Some(test_callback_session().1));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Access::Denied(..)));

    }

}