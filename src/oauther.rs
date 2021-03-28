use crate::{FilterConfig, util};
use oauth2::{ClientSecret, ClientId, TokenUrl, PkceCodeChallenge, AuthUrl, RedirectUrl, CsrfToken, Scope, PkceCodeVerifier, HttpRequest, AuthType, StandardTokenResponse, EmptyExtraTokenFields, TokenResponse};
use url;
use cookie::{Cookie, CookieBuilder};
use crate::oauther::Response::{NewAction, NewState};
use url::{Url, ParseError};
use oauth2::basic::{BasicClient, BasicTokenType};
use getrandom;

use serde::{Serialize, Deserialize};
use oauth2::http::{HeaderMap, HeaderValue};
use std::time;
use std::time::Duration;
use oauth2::http::header::{SET_COOKIE, HeaderName, AUTHORIZATION};
use std::cell::{RefCell, RefMut};
use std::rc::Rc;
use std::borrow::BorrowMut;
use std::ops::Deref;


pub struct OAuther {
    config: OAutherConfig,
    state: Box<dyn State>,
    client: BasicClient,
    cache: Box<Rc<RefCell<dyn Cache>>>,
}

pub enum Action {
    Noop,
    Redirect(Url, HeaderMap),
    HttpCall(HttpRequest),
    Allow(HeaderMap)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub(crate) access_token: String,
    pub(crate) id_token: Option<String>,
}

pub trait Cache {
    fn get_tokens_for_session(&self, session: &String) -> Option<&SessionData>;
    fn set_tokens_for_session(&mut self, session: &String, access_token: &String, id_token: Option<&String>);

    fn get_verifier_for_state(&self, state: &String) -> Option<&String>;
    fn set_verifier_for_state(&mut self, state: &String, verifier: &String);
}

trait State {
    fn handle_request(&self, oauther: &OAuther, header: &Vec<(&str, &str)>) -> Response;
    fn handle_token_call_response(
        &self, session: &String,
        token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>
    ) -> Response;
}

impl OAuther {
    pub fn new(
        config: FilterConfig,
        cache: Box<Rc<RefCell<dyn Cache>>>,
    ) -> Result<OAuther, ParseError> {
        let auther_config = OAutherConfig::from(config);

        let client = BasicClient::new(
                auther_config.client_id.clone(),
                Some(auther_config.client_secret.clone()),
                AuthUrl::from_url(auther_config.authorization_url.clone()),
                Some(TokenUrl::from_url(auther_config.token_url.clone()))
            )
                .set_redirect_url(RedirectUrl::from_url(auther_config.redirect_url.clone()));

        Ok(OAuther {
            config: auther_config,
            state: Box::new(Start { }),
            client,
            cache,
        })
    }

    pub fn handle_request_header(&mut self, headers: Vec<(&str, &str)>) -> Action {

        match self.state.handle_request(self, &headers) {
            Response::NewState(state) => {
                self.state = state;
                self.handle_request_header(headers)
            }
            Response::NewAction(action) => match action {
                OAutherAction::Redirect(url, headers, update) => {
                    update(self); // run the mutating update
                    Action::Redirect(url, headers)
                }
                OAutherAction::Allow(headers) => {
                    Action::Allow(headers)
                },
                OAutherAction::HttpCall(request) =>
                    Action::HttpCall(request),
                _ => unreachable!(),
            }
        }
    }

    pub fn handle_token_call_response(&mut self, session: &String, token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Action {
        let mut cache: RefMut<dyn Cache> = self.cache.deref().deref().borrow_mut();
        cache.set_tokens_for_session(
            session,
            token_response.access_token().secret(),
            None);
        Action::Allow(self.allow_headers(session))
    }

    fn session_cookie(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
        let cookies: Option<&(&str, &str)> =
            headers.iter().find( |(name, value)| { *name == "cookie" } );
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

    fn create_session_cookie(&self) -> Cookie {
        CookieBuilder::new(
            self.config.cookie_name.as_str().to_owned(),
            util::new_random_verifier(32).secret().to_owned())
            .secure(true)
            .http_only(true)
            .finish()
    }

    fn authorization_server_redirect(&self) -> (Url, Box<dyn Fn(&mut OAuther) -> ()>) {
        // TODO cache verifier for use in the token call

        let verifier = util::new_random_verifier(32);
        let pkce_challenge=
            PkceCodeChallenge::from_code_verifier_sha256(&verifier);

        let (auth_url, csrf_token) = self.client
            .authorize_url(|| CsrfToken::new("state123".to_string()))
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        let closure_state = csrf_token.secret().clone();
        let closure_verifier = PkceCodeVerifier::new(verifier.secret().clone());

        (
            auth_url,
            Box::new(
                move |  oauther|
                    {
                        let mut cache: RefMut<dyn Cache> = oauther.cache.deref().deref().borrow_mut();
                        cache.set_verifier_for_state(&closure_state, closure_verifier.secret())}))
    }

    fn allow_headers(&self, token: &String) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(format!("bearer {}",token).as_str()).unwrap());
        headers
    }

    fn request_auth_code(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
        // TODO this could ben done easier, without needing authority, without lib support
        let authority =
            headers.iter().find( |(name, value)| { *name == ":authority"}).map( | entry|{ entry.1 });
        let path =
            headers.iter().find( |(name, value)| { *name == ":path"}).map( | entry|{ entry.1 });

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
}

impl State for Start  {

    fn handle_request(&self, oauther: &OAuther, headers: &Vec<(&str, &str)>) -> Response {
        // check cookie
        match oauther.session_cookie(headers) {
            Some(_) => NewState(Box::new(SessionCookiePresent { })),
            None => {
                Response::NewState(Box::new(NoValidSession { }))
            },
        }
    }

    fn handle_token_call_response(&self, _session: &String, _token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        unimplemented!()
    }
}

impl State for NoValidSession {
    fn handle_request(&self, oauther: &OAuther, _: &Vec<(&str, &str)>) -> Response {
        let (url, update) = oauther.authorization_server_redirect();
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, oauther.create_session_cookie().to_string().parse().unwrap());
        NewAction(OAutherAction::Redirect(url, headers,  update))
    }

    fn handle_token_call_response(&self, _session: &String, _token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        unimplemented!()
    }
}

impl State for SessionCookiePresent {
    fn handle_request(&self, oauther: &OAuther, headers: &Vec<(&str, &str)>) -> Response {
        let session = oauther.session_cookie(headers)
            .expect("Bad state error, in SessionCookiePresent state, but no cookie found");

        let mut cache: RefMut<dyn Cache> = oauther.cache.deref().deref().borrow_mut();

        let tokens = cache.get_tokens_for_session(&session);
        match tokens {
            None => {
                let code = oauther.request_auth_code(headers);
                match code {
                    None => Response::NewState( Box::new(NoValidSession {})),
                    Some(code) => {
                        // TODO include PKCE
                        let request = oauther.create_token_request(code);
                        Response::NewAction(OAutherAction::HttpCall(request))
                    }
                }

            }
            Some(tokens) => {
                // TODO maybe validate expiry? But it is probably RS responsibility
                // TODO fix hack where we just take the first token in the list
                Response::NewAction(OAutherAction::Allow(oauther.allow_headers(&tokens.access_token)))
            }
        }
    }

    fn handle_token_call_response(&self, session: &String, token_response: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Response {
        unimplemented!()
    }
}


enum Response {
    NewState(Box<dyn State>),
    NewAction(OAutherAction),
}

enum OAutherAction {
    Noop,
    Redirect(Url, HeaderMap, Box<dyn Fn(&mut OAuther) -> ()>),
    HttpCall(HttpRequest),
    Allow(HeaderMap)
}

struct Start { }
struct NoValidSession { }
struct SessionCookiePresent {  }

struct OAutherConfig {
    cookie_name: String,
    auth_cluster: String,
    redirect_url: url::Url,
    authorization_url: url::Url,
    token_url: url::Url,
    client_id: ClientId,
    client_secret: ClientSecret
}

impl OAutherConfig {
    fn from(config: FilterConfig) -> OAutherConfig {
        OAutherConfig {
            cookie_name: config.cookie_name,
            auth_cluster: config.auth_cluster,
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
    use crate::oauther::OAutherAction::Redirect;
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use oauth2::{AccessToken, StandardTokenResponse, EmptyExtraTokenFields};
    use oauth2::http::header::FORWARDED;
    use crate::TokenResponse;
    use oauth2::basic::{BasicTokenResponse, BasicTokenType};
    use crate::cache::LocalCache;


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

    fn test_oauther() -> OAuther {
        OAuther::new(
            test_config(),
            Box::new(Rc::new(RefCell::new(LocalCache::new()))),
        ).unwrap()
    }

    #[test]
    fn new() {
        let oauther= test_oauther();
        assert_eq!(
            oauther.config.authorization_url.as_str(),
            "http://authorization/"
        );
    }

    #[test]
    fn session_cookie() {
        let test_headers = vec![("cookie", "sessioncookie=value")];
        let oauther= test_oauther();
        assert_eq!(oauther.session_cookie(&test_headers).unwrap(), "value");
    }

    #[test]
    fn auth_code_header() {
        let oauther= test_oauther();
        let authority = oauther.config.authorization_url.origin().unicode_serialization();
        let test_headers = vec![
            ("cookie", "sessioncookie=mysession"),
            (":path", "auth/?code=awesomecode&state=state123"),
            (":authority", authority.as_str())
        ];
        assert_eq!(oauther.request_auth_code(&test_headers).unwrap(), "awesomecode");
    }



    #[test]
    fn unauthorized_request() {
        let mut oauther = test_oauther();

        let action = oauther.handle_request_header(vec![("random_header", "value")]);

        if let Action::Redirect(url, headers) = action {
            assert_eq!(url.origin().unicode_serialization().as_str(), "http://authorization");

            let mut cache: RefMut<dyn Cache> = oauther.cache.deref().deref().borrow_mut();

            let result = cache.borrow().get_verifier_for_state(&"state123".to_string());
            assert_ne!(result.unwrap(), "");
            assert!(headers.contains_key("set-cookie"));
        } else { panic!("action was not redirect, action" ) }

    }

    #[test]
    fn session_cookie_present_but_no_token_in_cache_request() {
        let mut oauther= test_oauther();
        let action = oauther.handle_request_header(vec![("cookie", "sessioncookie=value")]);
        if let Action::Redirect(url, headers) = action {
            assert_eq!(url.origin().unicode_serialization().as_str(), "http://authorization");
        } else {panic!("actions was not redirect")}
    }

    #[test]
    fn session_cookie_present_and_valid_token_in_cache_request() {
        let mut oauther= test_oauther();

        {
            let mut cache: RefMut<dyn Cache> = oauther.cache.deref().deref().borrow_mut();
            cache
                .set_tokens_for_session(
                    &"mysession".to_string(),
                    &"cooltoken".to_string(),
                    None
                );
        }


        let action = oauther.handle_request_header(vec![("cookie", "sessioncookie=mysession")]);
        if let Action::Allow( headers ) = action {
            assert!(headers.contains_key(AUTHORIZATION))
        } else {panic!("action should be to allow")}
    }

    #[test]
    fn session_cookie_present_no_valid_token_in_cache_but_auth_code_in_query() {
        let mut oauther= test_oauther();

        let action = oauther.handle_request_header(
            vec![
                ("cookie", "sessioncookie=mysession"),
                (":path", "auth/?code=awesomecode&state=state123"),
                (":authority", oauther.config.authorization_url.origin().unicode_serialization().as_str())
            ]);
        if let Action::HttpCall( http_request ) = action {
            assert_eq!(http_request.url.as_str(), oauther.config.token_url.as_str())
        } else {panic!("action should be to HttpCall")}
    }

    #[test]
    fn handle_valid_token_call_response() {
        let mut oauther= test_oauther();
        let test_session = "testsession".to_string();
        let token_call_response = StandardTokenResponse::new(
            AccessToken::new("myaccesstoken".to_string()),
        BasicTokenType::Bearer,
        EmptyExtraTokenFields { });

        let action = oauther.handle_token_call_response(&test_session, &token_call_response);
        if let Action::Allow( headers ) = action {
            assert!(headers.contains_key(AUTHORIZATION));
        } else {panic!("action should be to HttpCall")}
    }


    #[test]
    fn code_grant_redirect() {
        let mut oauther = test_oauther();
        let action = oauther.handle_request_header(vec![(":path", "auth/?code=awesomecode&state=state123")]);
    }
}