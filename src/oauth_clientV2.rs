use oauth2::basic::BasicClient;
use crate::{FilterConfig, util};
use std::string::ParseError;
use oauth2::{AuthUrl, TokenUrl, RedirectUrl, ClientId, ClientSecret, HttpRequest, PkceCodeChallenge, CsrfToken, Scope, PkceCodeVerifier};
use time::Duration;
use crate::session::{Session, SessionUpdate};
use crate::messages::{DownStreamResponse};
use url::Url;

type Headers = Vec<(String, String)>;

struct Request {
    headers: Headers,
    url: Url,
}

impl Request {
    fn new(headers: Headers) -> Result<Self, ClientError> {
        let url = Self::request_url(headers.clone())?;
        Ok(Request { headers, url })
    }

    fn request_url(headers: Headers) -> Result<Url, ClientError> {
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1.clone() });
        let mut host_url = Self::host_url(headers)?;
        host_url.set_path(path.unwrap_or("".to_string()).as_str());
        Ok(host_url)
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


#[derive(Debug)]
pub enum Action {
    Redirect(Url, Headers, SessionUpdate),
    TokenRequest(HttpRequest),
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

    pub fn start(&self, request: Request) -> Result<(Redirect, SessionUpdate), ClientError> {
        let (redirect_url, state, verfier) = self.authorization_server_redirect();

        let update = SessionUpdate::auth_request(self.valid_url(request.url).to_string(), state, verfier);
        let header = update.set_cookie_header_tuple(&self.config.cookie_name, self.config.cookie_expire);
        Ok((Redirect::new(redirect_url, vec![header]), update))
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

    fn test_request() -> Request {
        Request::new( vec![
            ("random_header".to_string(), "value".to_string()),
            ("x-forwarded-proto".to_string(), "http".to_string()),
            (":authority".to_string(), "localhost".to_string()),
            (":path".to_string(), "/test-path".to_string())
        ]).unwrap()
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
}