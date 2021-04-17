use crate::{FilterConfig, util};
use oauth2::{ClientSecret, ClientId, TokenUrl, PkceCodeChallenge, AuthUrl, RedirectUrl, CsrfToken, Scope, PkceCodeVerifier, HttpRequest, AuthType, StandardTokenResponse, EmptyExtraTokenFields, TokenResponse};
use url;
use crate::oauth_client::Response::{NewAction, NewState};
use url::{Url, ParseError};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::http::{HeaderMap};
use std::fmt::Debug;
use crate::session::{Session, SessionUpdate, SessionType};
use crate::messages::SuccessfulResponse;
use std::time::{SystemTimeError};
use time::{Duration, NumericalDuration};


// OAuth 2.0 and OpenID Connect service
// Note that most of the names for structs, functions and methods are borrowed from OAuth 2.0
pub struct OAuthClient {
    config: ServiceConfig,
    state: Box<dyn State>,
    client: BasicClient,
}

#[derive(Debug)]
pub enum Action {
    Redirect(Url, HeaderMap, SessionUpdate),
    TokenRequest(HttpRequest),
    Allow(HeaderMap)
}

trait State: Debug {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthClient, header: &Vec<(&str, &str)>) -> Response;
    fn handle_token_response(
        &self, oauth: &OAuthClient,
        session: &Option<Session>,
        token_response: &SuccessfulResponse
    ) -> Response {
        log::warn!("received token response in state={:?}", self);
        Response::NewState(Box::new(NoValidSession {} ))
    }

    fn debug_entering(&self, session: &Option<Session>, headers: &Vec<(&str, &str)>) {
        log::debug!(
                "Entering {:?} state with session={:?}, headers={:?}",
                self,
                session,
                headers);
    }
}

enum Response {
    NewState(Box<dyn State>),
    NewAction(ServiceAction),
}

enum ServiceAction {
    Redirect(Url, HeaderMap, SessionUpdate),
    TokenRequest(HttpRequest),
    Allow(HeaderMap)
}

#[derive(Debug)]
struct Start { }
#[derive(Debug)]
struct NoValidSession { }
#[derive(Debug)]
struct ActiveSession {
    session: Session,
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
            state: Box::new(Start {}),
            client,
        })
    }

    pub fn handle_request(&mut self, session: Option<Session>, headers: Vec<(&str, &str)>) -> Result<Action, String> {
        match self.state.handle_request(&session, self, &headers) {
            Response::NewState(state) => {
                self.state = state;
                self.handle_request(session, headers)
            }
            Response::NewAction(action) => match action {
                ServiceAction::Redirect(url, headers, update) => {
                    Ok(Action::Redirect(url, headers, update))
                }
                ServiceAction::Allow(headers) => {
                    Ok(Action::Allow(headers))
                },
                ServiceAction::TokenRequest(request) =>
                    Ok(Action::TokenRequest(request)),
            }
        }
    }

    pub fn handle_token_call_response(&mut self, session: Option<Session>, token_response: &SuccessfulResponse) -> Result<Action, String> {
        match self.state.handle_token_response(self, &session, token_response) {
            NewState(state) => Err(format!("ERROR, invalid state returned NewState={:?}", state)),
            NewAction(action) => {
                match action {
                    ServiceAction::Redirect(url, headers, update) => {
                        Ok(Action::Redirect(url, headers, update))
                    }
                    ServiceAction::TokenRequest(request) => Ok(Action::TokenRequest(request)),
                    ServiceAction::Allow(headers) => Ok(Action::Allow(headers)),
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

        let closure_state = csrf_token.secret().clone();
        let closure_verifier = PkceCodeVerifier::new(verifier.secret().clone());

        (auth_url, closure_state, closure_verifier.secret().to_string())
    }

    fn request_auth_code(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
        // TODO this could ben done easier, without needing authority, without lib support and fake scheme
        let authority =
            headers.iter().find(|(name, _)| { *name == ":authority" }).map(|entry| { entry.1 });
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1 });

        let url = (authority, path);
        if let (Some(authority), Some(path)) = url {
            let params = url::Url::parse(format!("http://{}{}", authority, path).as_str()).unwrap();
            for (k, v) in params.query_pairs() {
                if k.to_string() == "code" {
                    return Some(v.to_string())
                }
            }
            return None
        }
        None
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

    fn request_url(&self, headers: &Vec<(&str, &str)>) -> Result<String, String> {
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1 });
        let mut host_url = self.host_url(headers)?;
        host_url.set_path(path.unwrap_or(""));
        Ok(host_url.into_string())
    }

    fn host_url(&self, headers: &Vec<(&str, &str)>) -> Result<Url, String> {
        let scheme =
            headers.iter().find(|(name, _)| { *name == "x-forwarded-proto" }).map(|entry| { entry.1 });
        let authority =
            headers.iter().find(|(name, _)| { *name == ":authority" }).map(|entry| { entry.1 });
        match (scheme, authority) {
            (None, _) => Err("No scheme in request header".to_string()),
            (_, None) => Err("No authority in request header".to_string()),
            (Some(scheme), Some(authority)) => {
                Ok(format!("{}://{}", scheme, authority).parse().unwrap())
            }
        }
    }

    fn sign_out(&self, headers: &Vec<(&str, &str)>) -> bool{
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1 });
        #[feature(option_result_contains)]
        match path.and_then(|path| {
            Some(path.contains(&self.config.sign_out_path))
        }) {
            None => false,
            Some(boolean) => boolean
        }
    }
}

impl State for Start  {

    fn handle_request(&self, session: &Option<Session>, _: &OAuthClient, header: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, header);
        // check cookie
        match session {
            Some( session ) => NewState(Box::new(ActiveSession { session: session.clone() })),
            None => {
                Response::NewState(Box::new(NoValidSession { }))
            },
        }
    }
}

impl State for NoValidSession {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthClient, header: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, header);


        let (url, state, verifier) = oauth.authorization_server_redirect();
        let request_url = oauth.request_url(header)
            .expect("ERROR: No authority in request header");
        let new_session = SessionUpdate::auth_request(request_url, state, verifier);
        let headers = new_session.set_cookie_header(&oauth.config.cookie_name, oauth.config.cookie_expire);
        NewAction(ServiceAction::Redirect(url, headers, new_session))
    }
}

impl State for ActiveSession {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthClient, headers: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, headers);
        let session = session.as_ref().unwrap(); // session must be Some(session) for ActiveSession to be created

        if oauth.sign_out(headers) {
            return Response::NewAction(ServiceAction::Redirect(oauth.host_url(headers).unwrap(), session.clear_cookie_header(&oauth.config.cookie_name), session.end_session()));
        }

        match &session.data {
            SessionType::Empty => Response::NewState( Box::new(NoValidSession {})),
            SessionType::AuthorizationRequest(verifiers) => {
                let code = oauth.request_auth_code(headers);
                match code {
                    None => {
                        log::warn!("Waiting for authorization response but received request without authorization code");
                        Response::NewState( Box::new(NoValidSession {}))
                    }
                    Some(code) => {
                        let request = oauth.create_token_request(code, verifiers.code_verifiers());
                        Response::NewAction(ServiceAction::TokenRequest(request))
                    }
                }
            },
            SessionType::Tokens(tokens) => {
                match tokens.is_access_token_valid() {
                    Ok(is_valid) => {
                        match is_valid {
                            true => Response::NewAction(ServiceAction::Allow(tokens.upstream_headers())),
                            false => {
                                // TODO use refresh token if valid
                                Response::NewState(Box::new(NoValidSession {}))
                            }
                        }
                    }
                    Err(err) => {
                        panic!("Error when getting system time: {}", err);
                    }
                }
            }
        }
    }

    fn handle_token_response(&self, _: &OAuthClient, _: &Option<Session>, token_response: &SuccessfulResponse) -> Response {
        let access_token = token_response.access_token.clone();
        let id_token = token_response.id_token.clone();
        let expires_in = token_response.expires_in();
        let refresh_token = token_response.id_token.clone();


        match &self.session.data {
            SessionType::AuthorizationRequest(verifiers) => {
                Response::NewAction(ServiceAction::Redirect(
                    verifiers.request_url().parse().unwrap(),
                    HeaderMap::new(),
                    self.session.token_response(access_token, expires_in, id_token, refresh_token),
                ))
            }
            _ => unreachable!(),
        }


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
    use crate::oauth_client::ServiceAction::Redirect;
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use oauth2::{AccessToken, StandardTokenResponse, EmptyExtraTokenFields};
    use oauth2::http::header::{FORWARDED, SET_COOKIE, AUTHORIZATION};
    use oauth2::basic::{BasicTokenResponse, BasicTokenType};
    use crate::session::{AuthorizationTokens, AuthorizationResponseVerifiers};
    use std::alloc::System;
    use std::time::SystemTime;
    use std::io::stdin;


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

    fn session_from_header(headers: HeaderMap, session_key: String) -> String {
        let cookies = headers.get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
        let session: Option<String> = cookies.split(";")
            .map(
                | cookie |
                    { (cookie.split("=").next(),cookie.split("=").skip(1).next()) }
            ).find(
            | (name, value)  | {
                { name.unwrap() == session_key }
            }).map( | (name, value)| { value.unwrap().to_string() });
        session.unwrap()
    }

    fn test_client() -> OAuthClient {
        OAuthClient::new(
            test_config(),
        ).unwrap()
    }


    #[test]
    fn new() {
        let oauth= test_client();
        assert_eq!(
            oauth.config.authorization_url.as_str(),
            "http://authorization/"
        );
    }

    #[test]
    fn auth_code_header() {
        let oauth= test_client();
        let authority = oauth.config.authorization_url.origin().unicode_serialization();
        let test_headers = vec![
            ("cookie", "sessioncookie=mysession"),
            (":path", "auth/?code=awesomecode&state=state123"),
            (":authority", authority.as_str())
        ];
        assert_eq!(oauth.request_auth_code(&test_headers).unwrap(), "awesomecode");
    }

    #[test]
    fn unauthorized_request() {
        let mut oauth = test_client();

        let action = oauth.handle_request(
            None,
            vec![
                ("random_header", "value"),
                ("x-forwarded-proto", "http"),
                (":authority", "localhost")
            ]
        );

        if let Ok(Action::Redirect(url, headers, update)) = action {
            assert_eq!(url.origin().unicode_serialization().as_str(), "http://authorization");
            assert!(headers.contains_key("set-cookie"));
        } else { panic!("action was not redirect, action" ) }
    }

    #[test]
    fn session_cookie_present_but_no_token_in_cache_request() {
        let mut oauth= test_client();

        let session= Session::empty("sessionid".to_string());

        let action = oauth.handle_request(
            Some(session),
            vec![("cookie", "sessioncookie=sessionid"), ("x-forwarded-proto", "http"), (":authority", "localhost")]);
        if let Ok(Action::Redirect(url, headers, update )) = action {
            assert_eq!(url.origin().unicode_serialization().as_str(), "http://authorization");
        } else {panic!("actions was not redirect")}
    }

    #[test]
    fn session_cookie_present_and_valid_token_in_cache_request() {
        let mut oauth= test_client();

        let session = Session::tokens(
            "mysession".to_string(),
            "testtoken".to_string(),
            Some(std::time::Duration::from_secs(120)),
            None,
            None,
        );

        let action = oauth.handle_request(
            Some(session),
            vec![
                ("cookie", format!("{}=mysession", oauth.config.cookie_name).as_str()),
                (":authority", oauth.config.authorization_url.origin().unicode_serialization().as_str()),
                ("x-forwarded-proto", "http")
            ]
        );
        if let Ok(Action::Allow( headers )) = action {
            assert!(headers.contains_key(AUTHORIZATION))
        } else {panic!("action should be to allow")}
    }

    #[test]
    fn session_cookie_present_no_valid_token_in_cache_but_auth_code_in_query() {
        let mut oauth= test_client();
        let session = Session::verifiers(
            "mysession".to_string(),
            SystemTime::now(),
            "http://localhost".to_string(),
            "123".to_string(),
            Some("abc".to_string()));

        let action = oauth.handle_request(
            Some(session),
            vec![
                ("cookie", "sessioncookie=mysession"),
                (":path", "auth/?code=awesomecode&state=state123"),
                (":authority", oauth.config.authorization_url.origin().unicode_serialization().as_str()),
                ("x-forwarded-proto", "http")
            ]);
        if let Ok(Action::TokenRequest(http_request )) = action {
            assert_eq!(http_request.url.as_str(), oauth.config.token_url.as_str())
        } else {panic!("action should be to HttpCall")}
    }

    #[test]
    fn handle_valid_token_call_response() {
        let mut oauth= test_client();
        let session_id = "testsession";
        let protected_api = "http://proxy:8081/resource";
        let session = Session::verifiers(
            session_id.to_string(),
            SystemTime::now(),
            protected_api.to_string(),
            "state123".to_string(),
            Some("abc".to_string())
        );

        let action = oauth.handle_request(
            Some(session.clone()),
            vec![
                ("cookie", format!("{}={}", oauth.config.cookie_name, session_id).as_str()),
                (":path", "auth/?code=awesomecode&state=state123"),
                (":authority", oauth.config.authorization_url.origin().unicode_serialization().as_str()),
                ("x-forwarded-proto", "http")
            ]);

        assert!(matches!(&action, Ok(Action::TokenRequest(http_request))));

        let token_call_response = SuccessfulResponse::new(
            "myaccesstoken".to_string(),
            None,
            Some("bearer".to_string()),
            None,
            Some(3600)
        );

        let action = oauth.handle_token_call_response(Some(session), &token_call_response);
        if let Ok(Action::Redirect( url, headers, update)) = action {
            assert_eq!(url.to_string(), protected_api);
        } else {panic!("action should be to HttpCall")}
    }


    #[test]
    fn valid_session() {
        let mut oauth = test_client();

        let session = Session::tokens(
            "testsession".to_string(),
            "myaccesstoken".to_string(),
            Some(std::time::Duration::from_secs(120)),
            None,
            None
        );

        let action = oauth.handle_request(
            Some(session),
            vec![
                 ("cookie", "sessioncookie=testsession"),
                 (":path", "/"),
                 (":authority", oauth.config.authorization_url.origin().unicode_serialization().as_str()),
                 ("x-forwarded-proto", "http")]
        );

        if let Ok(Action::Allow( headers )) = action {
            assert!(headers.contains_key(AUTHORIZATION));
            assert_eq!(headers.get(AUTHORIZATION).unwrap().to_str().unwrap(), "bearer myaccesstoken");
        } else {panic!("action={:?} should be to Allow", action)}
    }
}