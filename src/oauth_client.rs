use std::any::Any;

use oauth2::{ClientId, ClientSecret, CsrfToken, HttpRequest, PkceCodeChallenge};
use oauth2::basic::BasicClient;
use time::Duration;
use url::{Url, ParseError};

use crate::util;
use crate::messages::{DownStreamResponse, TokenResponse};
use crate::oauth_client_types::{Access, ClientError, Redirect, Request, TokenRequest};
use crate::session::{Session, SessionType, SessionUpdate};
use crate::config::FilterConfig;
use std::option::Option::Some;


pub static CALLBACK_PATH: &str = "/callback";
pub static START_PATH: &str  = "/auth";
pub static SIGN_OUT_PATH: &str = "/sign_out";
pub static CLIENT_PATHS: (&str, &str, &str) = (CALLBACK_PATH, START_PATH, SIGN_OUT_PATH);


pub(crate) struct OAuthClient
{
    config: FilterConfig,
    client: BasicClient,
}

pub(crate) struct ClientConfig {
    cookie_name: String,
    redirect_url: url::Url,
    authorization_url: url::Url,
    token_url: url::Url,
    client_id: ClientId,
    client_secret: ClientSecret,
    extra_params: Vec<(String, String)>,
    scopes: Vec<String>,
    cookie_expire: Duration,
}

impl OAuthClient
{

    pub fn new(
        config: FilterConfig,
    ) -> Result<OAuthClient, ParseError> {

        let client = config.client();

        Ok(OAuthClient {
            config,
            client,
        })
    }

    pub fn sign_out(&self, session: Option<Session>) -> Result<(DownStreamResponse, SessionUpdate), ClientError> {
        match session {
            None => {
                Err(ClientError::new(400, "No session to sign out from".to_string(), None))
            }
            Some(session) => {
                let header = session.clear_cookie_header_tuple(self.config.cookie_name());
                Ok((DownStreamResponse::new(vec![header], 200, "Signed Out".to_string()), session.end_session()))
            }
        }
    }

    // Starts a new Authentication Code flow. Note that it does not invalidate any already active sessions in the cache
    pub fn start(&self, request: Request) -> Result<(Redirect, SessionUpdate), ClientError> {
        let (redirect_url, state, verifier) = self.authorization_server_redirect();

        let update = SessionUpdate::auth_request(self.valid_url(request.url()).to_string(), state, verifier);
        let header = update.set_cookie_header_tuple(self.config.cookie_name(), self.config.cookie_expire());
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
                Ok(TokenRequest::new(request))
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

                // validate id token
                if let Some(id_token) = &id_token {
                    match self.config.validate_token(id_token) {
                        Ok(_) => {}
                        Err(error) => {
                            return Err(ClientError::new(500, error.to_string(), None))
                        }
                    }
                }
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
                                        Ok(Access::Denied(DownStreamResponse::new(vec![], 403, "Tokens expired".to_string())))
                                    }
                                }
                            }
                            Err(err) => Err(ClientError::new(500, format!("Error occurred while getting system time, error={}", err), None)),
                        }
                    }
                    _ => Ok(Access::Denied(DownStreamResponse::new(vec![], 403, "UnAuthorized session".to_string())))
                }
            }
        }
    }

    fn authorization_server_redirect(&self) -> (Url, String, String) {
        let verifier = util::new_random_verifier(32);
        let pkce_challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        let (auth_url, csrf_token) =
            self.config.authorization_url(
                CsrfToken::new(util::new_random_verifier(32).secret().to_string()),
                pkce_challenge
            );

        let state = csrf_token.secret().clone();

        (auth_url, state, verifier.secret().to_string())
    }

    fn create_token_request(&self, code: String, code_verifier: Option<String>) -> HttpRequest {
        self.config.token_request(code, code_verifier)
    }

    fn valid_url(&self, url: &Url) -> Url {
        let mut url = url.clone();
        if url.path().starts_with(CALLBACK_PATH) ||
            url.path().starts_with(START_PATH) ||
            url.path().starts_with(SIGN_OUT_PATH)
        {
            url.set_path("/");
            return url
        }
        url
    }
}


impl ClientConfig {

    pub fn new(
        cookie_name: &str,
        redirect_url: &str,
        authorization_url: &str,
        token_url: &str,
        client_id: &str,
        client_secret: &str,
        extra_params: Vec<(String, String)>,
        scopes: Vec<String>,
        cookie_expire: u32,
    ) -> ClientConfig {
        ClientConfig {
            cookie_name: cookie_name.to_string(),
            redirect_url: url::Url::parse(redirect_url)
                .expect("Error parsing FilterConfig redirect_uri when creating OAutherConfig"),
            authorization_url: url::Url::parse(authorization_url)
                .expect("Error parsing FilterConfig auth_uri when creating OAutherConfig"),
            token_url: url::Url::parse(token_url)
                .expect("Error parsing FilterConfig token_uri when creating OAutherConfig"),
            client_id: ClientId::new(client_id.to_string()),
            client_secret: ClientSecret::new(client_secret.to_string()),
            extra_params,
            scopes,
            cookie_expire: Duration::seconds(cookie_expire as i64)
        }
    }
}


#[cfg(test)]
mod tests {
    use std::matches;
    use std::time::SystemTime;

    use oauth2::http::header::SET_COOKIE;

    use crate::messages::{SuccessfulResponse, TokenResponse};
    use crate::session::{Session, SessionType};

    use super::*;
    use crate::config::{FilterConfig};
    use time::NumericalDuration;

    fn test_config_extra(scopes: Vec<String>) -> FilterConfig {
        FilterConfig::oauth(
            "sessioncookie",
            "cluster",
            "issuer",
            &"https://redirect".parse().unwrap(),
            &"https://authorization".parse().unwrap(),
            &"https://token".parse().unwrap(),
            "myclient",
            "mysecret",
            scopes,
            1.hours(),
            vec![])
    }

    fn test_config() -> FilterConfig {
        test_config_extra(vec!["openid".to_string()])
    }

    fn test_client() -> crate::oauth_client::OAuthClient {
        crate::oauth_client::OAuthClient::new(test_config()).unwrap()
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
        let client = crate::oauth_client::OAuthClient::new(test_config());
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
        let expected = Url::parse("https://authorization").unwrap().origin();
        assert_eq!(redirect.url().origin(), expected);
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
        assert_eq!(result.clone().url().clone(), Url::parse("https://token").unwrap());
        // The body of the token request should contain the client id and secret
        assert!(String::from_utf8(result.clone().body().to_vec()).unwrap().contains(&client.config.client_secret()));
        assert!(String::from_utf8(result.clone().body().to_vec()).unwrap().contains(&client.config.client_id()));
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

    #[test]
    fn configure_scopes() {

        let scopes = vec!["openid".to_string(),
                          "email".to_string(),
                          "profile".to_string()];
        let config = test_config_extra(scopes.clone());


        let client = crate::oauth_client::OAuthClient::new(config).unwrap();
        let request = test_request();


        // Correct scopes should be in redirect to authorization server
        let result = client.start(request);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(matches!(result, (Redirect {..}, _)));
        for scope in scopes.iter() {
            assert!(result.0.url().query().unwrap().contains(scope),
                    "redirect did not contain scope={}", scope);
        }
    }
}
