use crate::{FilterConfig, util};
use oauth2::{ClientSecret, ClientId, TokenUrl, PkceCodeChallenge, AuthUrl, RedirectUrl, CsrfToken, Scope};
use url;
use cookie::Cookie;
use crate::oauther::Response::{NewAction, NewState};
use url::{Url, ParseError};
use oauth2::basic::BasicClient;
use getrandom;

pub struct OAuther {
    config: OAutherConfig,
    state: Box<dyn State>,
    client: BasicClient,
}

trait State {
    fn handle_request(&self, oauther: &OAuther, header: &Vec<(&str, &str)>) -> Response;
}

impl OAuther {
    pub fn new(config: FilterConfig) -> Result<OAuther, ParseError> {
        let auther_config = OAutherConfig::from(config);

        let client = BasicClient::new(
                auther_config.client_id.clone(),
                Some(auther_config.client_secret.clone()),
                AuthUrl::from_url(auther_config.authorization_url.clone()),
                Some(TokenUrl::from_url(auther_config.token_url.clone()))
            )
                .set_redirect_url(RedirectUrl::from_url(auther_config.redirect_url.clone()));

        Ok(OAuther { config: auther_config, state: Box::new(Start { }), client })
    }

    fn handle_request_header(&mut self, headers: Vec<(&str, &str)>) -> Action {
        match self.state.handle_request(self, &headers) {
            Response::NewState(state) => {
                self.state = state;
                self.handle_request_header(headers)
            }
            Response::NewAction(action) => action
        }
    }

    pub fn session_cookie(&self, headers: &Vec<(&str, &str)>) -> Option<String> {
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

    fn authorization_server_redirect(&self) -> Url {
        // TODO cache verifier for use in the token call
        let pkce_challenge=
            PkceCodeChallenge::from_code_verifier_sha256(
                &util::new_random_verifier(32)
            );

        let (auth_url, csrf_token) = self.client
            .authorize_url(|| CsrfToken::new("state123".to_string()))
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        auth_url
    }
}

impl State for Start  {

    fn handle_request(&self, oauther: &OAuther, headers: &Vec<(&str, &str)>) -> Response {
        // check cookie
        match oauther.session_cookie(headers) {
            Some(cookie) => NewState(Box::new(CookieFound { })),
            None => NewAction(Action::Redirect(oauther.authorization_server_redirect())),
        }
    }
}

impl State for CookieFound {

    fn handle_request(&self, oauther: &OAuther, header: &Vec<(&str, &str)>) -> Response {
        NewAction(Action::Noop)
    }
}


enum Response {
    NewState(Box<dyn State>),
    NewAction(Action),
}

#[derive(Debug)]
enum Action {
    Noop,
    Redirect(Url),
    HttpCall,
    Allow
}


struct Start { }
struct CookieFound {  }

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
    use crate::oauther::Action::Redirect;

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

    #[test]
    fn new() {
        assert_eq!(
            OAuther::new(test_config()).unwrap().config.authorization_url.as_str(),
            "http://authorization/"
        );
    }

    #[test]
    fn unauthorized_request() {
        let mut oauther = OAuther::new(test_config()).unwrap();
        let action: Action = oauther.handle_request_header(vec![("random_header", "value")]);

        if let Action::Redirect(url) = action {
            assert_eq!(url.origin().unicode_serialization().as_str(), "http://authorization");
        } else { panic!("action was not redirect, action={:?}", action ) }

    }

    #[test]
    fn session_cookie_present_request() {
        let mut oauther = OAuther::new(test_config()).unwrap();
        let action: Action = oauther.handle_request_header(vec![("sessioncookie", "value")]);
        assert_eq!(action.type_id(), Action::Allow.type_id());
    }
}