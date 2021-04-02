use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use crate::cache::SharedCache;

type Seconds = u32;


pub trait SessionCache {
    fn get(&self, id: &String) -> Option<SessionType>;
    fn set(&mut self, session: NewSession);
}


#[derive(Debug, Serialize, Deserialize)]
pub enum Session {
    AuthorizationRequest {
        id: String,
        verifiers: AuthorizationResponseVerifiers,
    },
    Tokens {
        id: String,
        tokens: AuthorizationTokens,
    },
    Empty {
        id: String
    },
    NotSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    AuthorizationRequest(AuthorizationResponseVerifiers),
    Tokens(AuthorizationTokens)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewSession {
    id: String,
    data: SessionType,
}

impl Session {
    fn not_set() -> Session {
        Session::NotSet
    }

    pub fn from_headers(cookie_name: String, headers: Vec<(&str, &str)>, cache: &dyn SessionCache) -> Session {
        let session = Session::parse_cookie(&cookie_name, &headers);
        match session {
            None => Session::not_set(),
            Some(id) => {
                match cache.get(&id) {
                    None => Session::Empty { id },
                    Some(session_type) => {
                        match session_type {
                            SessionType::AuthorizationRequest( verifiers) =>
                                Session::from_verifier(id, verifiers),
                            SessionType::Tokens( tokens) =>
                                Session::from_tokens(id, tokens),
                        }
                    }
                }
            }
        }
    }

    fn from_verifier(id: String, verifiers: AuthorizationResponseVerifiers) -> Session {
        Session::AuthorizationRequest {id, verifiers}
    }
    fn from_tokens(id: String, tokens: AuthorizationTokens) -> Session{
        Session::Tokens { id, tokens }
    }

    fn parse_cookie(id: &String, headers: &Vec<(&str, &str)>) -> Option<String> {
        let cookies: Option<&(&str, &str)> =
            headers.iter().find( |(name, _ )| { *name == "cookie" } );
        return match cookies {
            Some(cookies) => {
                let cookies: Vec<&str> = cookies.1.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == id {
                        return Some(cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_string().to_owned());
                    }
                }
                None
            },
            None => None
        }
    }
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponseVerifiers {
    created_at: SystemTime,
    state: State,
    pcke_verifier: Option<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationTokens {
    created_at: SystemTime,
    access_token: String,
    expires_in: Option<Seconds>,
    id_token: Option<String>,
    refresh_token: Option<String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    path: String,
    csrf_token: String
}

#[cfg(test)]
mod tests {
    use crate::session::{Session, SessionType, SessionCache, NewSession, AuthorizationResponseVerifiers, State, AuthorizationTokens};
    use std::collections::HashMap;
    use std::time::SystemTime;

    pub struct TestCache {
        sessions: HashMap<String, SessionType>,
    }

    impl TestCache {
        pub fn new() -> TestCache {
            TestCache {
                sessions: HashMap::new(),
            }
        }
    }

    impl SessionCache for TestCache {
        fn get(&self, id: &String) -> Option<SessionType> {
            match self.sessions.get(id) {
                None => None,
                Some(session_type ) => Some(session_type.to_owned())
            }
        }

        fn set(&mut self, session: NewSession) {
            self.sessions.insert(session.id, session.data);
        }
    }

    #[test]
    fn empty() {
        let session = Session::not_set();
        assert!(matches!(session, Session::NotSet));
    }

    #[test]
    fn from_headers() {
        let mut cache = TestCache::new();
        let cookie_name="auth_session".to_string();
        let cookie_value = "testsession".to_string();
        let cookie = format!("{}={}", cookie_name, cookie_value);


        let headers: Vec<(&str, &str)> = vec![("cookie", cookie.as_str())];
        let session: Session = Session::from_headers(cookie_name.clone(), headers.clone(), &cache);
        assert!(matches!(session, Session::Empty { id }));

        cache.set(NewSession { id: cookie_value.clone(), data: SessionType::AuthorizationRequest(AuthorizationResponseVerifiers {
            created_at: SystemTime::now(),
            state: State { path: "/secure".to_string(), csrf_token: "1234".to_string() },
            pcke_verifier: Some("1234".to_string())
        } ) });

        let session: Session = Session::from_headers(cookie_name.clone(), headers.clone(), &cache);
        assert!(matches!(session, Session::AuthorizationRequest { .. }));

        cache.set(NewSession { id: cookie_value.clone(), data: SessionType::Tokens(AuthorizationTokens {
            created_at: SystemTime::now(),
            access_token: "SomeJWT".to_string(),
            expires_in: None,
            id_token: None,
            refresh_token: None
        }) });

        let session: Session = Session::from_headers(cookie_name.clone(), headers, &cache);
        assert!(matches!(session, Session::Tokens { .. }));

    }

}