use crate::{FilterConfig, util};
use oauth2::{ClientSecret, ClientId, TokenUrl, PkceCodeChallenge, AuthUrl, RedirectUrl, CsrfToken, Scope, PkceCodeVerifier, HttpRequest, AuthType, StandardTokenResponse, EmptyExtraTokenFields, TokenResponse};
use url;
use cookie::{Cookie, CookieBuilder};
use crate::oauth_service::Response::{NewAction, NewState};
use url::{Url, ParseError};
use oauth2::basic::{BasicClient, BasicTokenType};

use serde::{Serialize, Deserialize};
use oauth2::http::{HeaderMap, HeaderValue};
use oauth2::http::header::{SET_COOKIE, AUTHORIZATION};
use std::cell::{RefCell, RefMut};
use std::rc::Rc;
use std::ops::Deref;
use std::fmt::Debug;
use crate::session::{Session, SessionUpdate, SessionType};


pub struct OAuthService {
    config: ServiceConfig,
    state: Box<dyn State>,
    client: BasicClient,
}

#[derive(Debug)]
pub enum Action {
    Redirect(Url, HeaderMap, SessionUpdate),
    HttpCall(HttpRequest),
    Allow(HeaderMap)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub(crate) access_token: String,
    pub(crate) id_token: Option<String>,
}

trait State: Debug {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthService, header: &Vec<(&str, &str)>) -> Response;
    fn handle_token_call_response(
        &self, oauth: &OAuthService,
        session: &Option<Session>,
        token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>
    ) -> Response;

    fn debug_entering(&self, session: &Option<Session>, headers: &Vec<(&str, &str)>) {
        crate::log_debug(
            format!(
                "Entering {:?} state with session={:?}, headers={:?}",
                self,
                session,
                headers).as_str());
    }
}

impl OAuthService {
    pub fn new(
        config: FilterConfig,
    ) -> Result<OAuthService, ParseError> {
        let auther_config = ServiceConfig::from(config);

        let client = BasicClient::new(
                auther_config.client_id.clone(),
                Some(auther_config.client_secret.clone()),
                AuthUrl::from_url(auther_config.authorization_url.clone()),
                Some(TokenUrl::from_url(auther_config.token_url.clone()))
            )
                .set_redirect_url(RedirectUrl::from_url(auther_config.redirect_url.clone()));

        Ok(OAuthService {
            config: auther_config,
            state: Box::new(Start { }),
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
                ServiceAction::HttpCall(request) =>
                    Ok(Action::HttpCall(request)),
            }
        }
    }

    pub fn handle_token_call_response(&mut self, session: Option<Session>, token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Result<Action, String> {
        match self.state.handle_token_call_response(self, &session, token_response) {
            NewState(state) => Err(format!("ERROR, invalid state returned NewState={:?}", state)),
            NewAction( action) => {
                match action {
                    ServiceAction::Redirect(url, headers, update) => {
                        Ok(Action::Redirect(url, headers, update))
                    }
                    ServiceAction::HttpCall(request) => Ok(Action::HttpCall(request)),
                    ServiceAction::Allow(headers) => Ok(Action::Allow(headers)),
                }
            }
        }
    }

    fn session_cookie(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
        let cookies: Option<&(&str, &str)> =
            headers.iter().find( |(name, _ )| { *name == "cookie" } );
        return match cookies {
            Some(cookies) => {
                let cookies: Vec<&str> = cookies.1.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == self.config.cookie_name {
                        return Some(cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_string().to_owned());
                    }
                }
                None
            },
            None => None
        }
    }

    fn authorization_server_redirect(&self) -> (Url, String, String) {
        // TODO cache verifier for use in the token call

        let verifier = util::new_random_verifier(32);
        let pkce_challenge=
            PkceCodeChallenge::from_code_verifier_sha256(&verifier);

        let (auth_url, csrf_token) = self.client
            .authorize_url(|| CsrfToken::new(util::new_random_verifier(32).secret().to_string()))
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        let closure_state = csrf_token.secret().clone();
        let closure_verifier = PkceCodeVerifier::new(verifier.secret().clone());

        (auth_url, closure_state, closure_verifier.secret().to_string())
    }

    fn allow_headers(&self, token: &String) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(format!("bearer {}",token).as_str()).unwrap());
        headers
    }

    fn request_auth_code(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
        // TODO this could ben done easier, without needing authority, without lib support and fake scheme
        let authority =
            headers.iter().find( |(name, _ )| { *name == ":authority"}).map( | entry|{ entry.1 });
        let path =
            headers.iter().find( |(name, _ )| { *name == ":path"}).map( | entry|{ entry.1 });

        let url =  (authority, path);
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

    fn create_token_request(&self, code: String) -> HttpRequest {
        util::token_request(
            &AuthType::RequestBody,
            &(self.config.client_id),
            Some(&self.config.client_secret),
            &[],
            Some(&RedirectUrl::from_url(self.config.redirect_url.clone())),
            None,
            &TokenUrl::from_url(self.config.token_url.clone()),
            vec![("grant_type", "authorization_code"), ("code", code.as_str())])
    }

    fn request_url(&self, headers: &Vec<(&str, &str)>) -> Result<String, String> {
        let scheme =
            headers.iter().find( |(name, _ )| { *name == "x-forwarded-proto"}).map( | entry|{ entry.1 });
        let authority =
            headers.iter().find( |(name, _ )| { *name == ":authority"}).map( | entry|{ entry.1 });
        let path =
            headers.iter().find( |(name, _ )| { *name == ":path"}).map( | entry|{ entry.1 });
        match (scheme, authority) {
            (None, _) => Err("No scheme in request header".to_string()),
            (_, None) => Err("No authority in request header".to_string()),
            (Some(scheme), Some(authority)) => {
                let mut url = format!("{}://{}",scheme, authority);
                url.push_str(path.unwrap_or(""));
                Ok(url)
            }
        }
    }
}

impl State for Start  {

    fn handle_request(&self, session: &Option<Session>, _: &OAuthService, header: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, header);
        // check cookie
        match session {
            Some( session ) => NewState(Box::new(SessionCookiePresent { session: session.clone() })),
            None => {
                Response::NewState(Box::new(NoValidSession { }))
            },
        }
    }

    fn handle_token_call_response(&self, _: &OAuthService, _: &Option<Session>, _: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        unreachable!()
    }
}

impl State for NoValidSession {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthService, header: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, header);


        let (url, state, verifier) = oauth.authorization_server_redirect();
        let request_url = oauth.request_url(header)
            .expect("ERROR: No authority in request header");
        let new_session = SessionUpdate::auth_request(request_url, state, verifier);
        let headers = new_session.set_cookie_header(&oauth.config.cookie_name);
        NewAction(ServiceAction::Redirect(url, headers, new_session))
    }

    fn handle_token_call_response(&self, _: &OAuthService, _: &Option<Session>, _: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        unreachable!()
    }
}

impl State for SessionCookiePresent {
    fn handle_request(&self, session: &Option<Session>, oauth: &OAuthService, header: &Vec<(&str, &str)>) -> Response {
        self.debug_entering(&session, header);

        if let Some(session) = session {
            match &session.data {
                SessionType::Empty => Response::NewState( Box::new(NoValidSession {})),
                SessionType::AuthorizationRequest(..) => {
                    let code = oauth.request_auth_code(header);
                    match code {
                        None => Response::NewState( Box::new(NoValidSession {})),
                        Some(code) => {
                            // TODO include PKCE
                            let request = oauth.create_token_request(code);
                            Response::NewAction(ServiceAction::HttpCall(request))
                        }
                    }
                },
                SessionType::Tokens(tokens) => {
                    // TODO maybe validate expiry? But it is probably RS responsibility
                    // TODO fix hack where we just take the first token in the list
                    Response::NewAction(ServiceAction::Allow(tokens.bearer()))
                }
            }
        } else {
            // TODO fix
            unreachable!()
        }
    }

    fn handle_token_call_response(&self, _: &OAuthService, _: &Option<Session>, token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        let access_token = token_response.access_token().secret().clone();
        let expires_in = token_response.expires_in();
        let refresh_token: Option<String> = token_response.refresh_token()
            .and_then(
                |token|
                    { Some(token.secret().clone())}
            );

        match &self.session.data {
            SessionType::AuthorizationRequest(verifiers) => {
                Response::NewAction(ServiceAction::Redirect(
                    verifiers.request_url().parse().unwrap(),
                    HeaderMap::new(),
                    self.session.token_response(access_token, expires_in, None, refresh_token),
                ))
            }
            SessionType::Tokens(_) => {
                unreachable!()
            }
            SessionType::Empty => {
                unreachable!()
            }
        }


    }
}


enum Response {
    NewState(Box<dyn State>),
    NewAction(ServiceAction),
}

enum ServiceAction {
    Redirect(Url, HeaderMap, SessionUpdate),
    HttpCall(HttpRequest),
    Allow(HeaderMap)
}

#[derive(Debug)]
struct Start { }
#[derive(Debug)]
struct NoValidSession { }
#[derive(Debug)]
struct SessionCookiePresent {
    session: Session,
}

struct ServiceConfig {
    cookie_name: String,
    redirect_url: url::Url,
    authorization_url: url::Url,
    token_url: url::Url,
    client_id: ClientId,
    client_secret: ClientSecret
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
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::matches;
    use crate::oauth_service::ServiceAction::Redirect;
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use oauth2::{AccessToken, StandardTokenResponse, EmptyExtraTokenFields};
    use oauth2::http::header::FORWARDED;
    use crate::TokenResponse;
    use oauth2::basic::{BasicTokenResponse, BasicTokenType};
    use crate::cache::LocalCache;
    use crate::session::{AuthorizationTokens, AuthorizationResponseVerifiers};
    use std::alloc::System;
    use std::time::SystemTime;


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
            client_secret: "mysecret".to_string()
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

    fn test_oauther() -> OAuthService {
        OAuthService::new(
            test_config(),
        ).unwrap()
    }


    #[test]
    fn new() {
        let oauth= test_oauther();
        assert_eq!(
            oauth.config.authorization_url.as_str(),
            "http://authorization/"
        );
    }

    #[test]
    fn session_cookie() {
        let test_headers = vec![("cookie", "sessioncookie=value")];
        let oauth= test_oauther();
        assert_eq!(oauth.session_cookie(&test_headers).unwrap(), "value");
    }

    #[test]
    fn auth_code_header() {
        let oauth= test_oauther();
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
        let mut oauth = test_oauther();

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
        let mut oauth= test_oauther();

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
        let mut oauth= test_oauther();

        let session = Session::tokens(
            "mysession".to_string(),
            "testtoken".to_string(),
            None,
            None,
            None,
        );

        let action = oauth.handle_request(
            Some(session),
            vec![
                ("cookie", format!("{}=mysession", oauth.config.cookie_name).as_str()),
                 ("x-forwarded-proto", "http")
            ]
        );
        if let Ok(Action::Allow( headers )) = action {
            assert!(headers.contains_key(AUTHORIZATION))
        } else {panic!("action should be to allow")}
    }

    #[test]
    fn session_cookie_present_no_valid_token_in_cache_but_auth_code_in_query() {
        let mut oauth= test_oauther();
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
        if let Ok(Action::HttpCall( http_request )) = action {
            assert_eq!(http_request.url.as_str(), oauth.config.token_url.as_str())
        } else {panic!("action should be to HttpCall")}
    }

    #[test]
    fn handle_valid_token_call_response() {
        let mut oauth= test_oauther();
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

        assert!(matches!(action, Ok(Action::HttpCall(http_request))));

        let token_call_response = StandardTokenResponse::new(
            AccessToken::new("myaccesstoken".to_string()),
        BasicTokenType::Bearer,
        EmptyExtraTokenFields { });

        let action = oauth.handle_token_call_response(Some(session), &token_call_response);
        if let Ok(Action::Redirect( url, headers, update)) = action {
            assert_eq!(url.to_string(), protected_api);
        } else {panic!("action should be to HttpCall")}
    }


    #[test]
    fn valid_session() {
        let mut oauth = test_oauther();

        let session = Session::tokens(
            "testsession".to_string(),
            "myaccesstoken".to_string(),
            None,
            None,
            None
        );

        let action = oauth.handle_request(
            Some(session),
            vec![("cookie", "sessioncookie=testsession"), (":path", "/"),]);
        if let Ok(Action::Allow( headers )) = action {
            assert!(headers.contains_key(AUTHORIZATION));
            assert_eq!(headers.get(AUTHORIZATION).unwrap().to_str().unwrap(), "bearer myaccesstoken");
        } else {panic!("action={:?} should be to Allow", action)}
    }
}