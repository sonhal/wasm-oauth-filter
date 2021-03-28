use std::collections::HashMap;
use oauth2::PkceCodeVerifier;
use crate::oauther::{Cache, SessionData};
use proxy_wasm::traits::Context;
use proxy_wasm::types::Status;
use serde::{Serialize, Deserialize};
use serde::de::Error;
use std::any::Any;


pub struct LocalCache {
    sessions: HashMap<String, SessionData>,
    verifiers: HashMap<String, String>
}

impl LocalCache {
    pub fn new() -> LocalCache {
        LocalCache {
            sessions: HashMap::new(),
            verifiers: HashMap::new()
        }
    }
}

impl Cache for LocalCache {

    fn get_tokens_for_session(&self, session: &String) -> Option<&SessionData> {
        if let Some(tokens) = self.sessions.get(session) {
            return Some(tokens.to_owned())
        };
        None
    }

    fn set_tokens_for_session(&mut self, session: &String, access_token: &String, id_token: Option<&String>) {
        let access_token = access_token.to_string();
        let id_token: Option<String> = match id_token {
            None => None,
            Some(token) => Some(token.to_string()),
        };
        self.sessions.insert(session.to_string(), SessionData { access_token, id_token});
    }


    fn get_verifier_for_state(&self, state: &String) -> Option<&String> {
        if let Some(verifier) = self.verifiers.get(state) {
            return Some(verifier)
        };
        None
    }

    fn set_verifier_for_state(&mut self, state: &String, verifier: &String) {
        self.verifiers.insert(state.to_string(), verifier.to_string());
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SharedCache {
    sessions: HashMap<String, SessionData>,
}

const SHARED_SESSIONS_KEY: &str = "SHARED_SESSIONS";

impl SharedCache {

    pub fn new() -> SharedCache {
        SharedCache {
            sessions: HashMap::new()
        }
    }

    pub fn from_host(context: & dyn Context) -> Result<SharedCache, String> {
        let (bytes, size) = context.get_shared_data(SHARED_SESSIONS_KEY);
        if let (Some(bytes), Some(size)) = (bytes, size) {
            let cache: SharedCache = serde_json::from_slice(bytes.as_slice()).unwrap();
            Ok(cache)
        } else {
            Err("No shared session cache created".to_string())
        }
    }

    pub fn store(&mut self, context: & dyn Context) -> Result<(), String> {
        let serialized = serde_json::to_string(self);
        match serialized {
            Ok(serialized) => {
                let result = context.set_shared_data(SHARED_SESSIONS_KEY, Some(&serialized.as_bytes()), None);
                match result {
                    Ok(_) => Ok(()),
                    Err(status) => {
                        match status {
                            Status::Ok => Ok(()),
                            error => Err("Error from host when attempting to set shared data".to_string())
                        }
                    }
                }
            }
            Err(error) => Err(error.to_string())
        }
    }
}

impl Cache for SharedCache {
    fn get_tokens_for_session(&self, session: &String) -> Option<&SessionData> {
        if let Some(tokens) = self.sessions.get(session) {
            return Some(tokens)
        };
        None
    }

    fn set_tokens_for_session(&mut self, session: &String, access_token: &String, id_token: Option<&String>) {
        let access_token = access_token.to_string();
        let id_token: Option<String> = match id_token {
            None => None,
            Some(token) => Some(token.to_string()),
        };
        self.sessions.insert(session.to_string(), SessionData { access_token, id_token});
    }

    fn get_verifier_for_state(&self, state: &String) -> Option<&String> {
        return None
    }

    fn set_verifier_for_state(&mut self, state: &String, verifier: &String) {
        // Todo
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::SharedCache;
    use proxy_wasm::traits::Context;
    use proxy_wasm::types::{Status, Bytes};
    use crate::oauther::Cache;

    struct TestContext {
        data: Vec<u8>,
    }

    impl Context for TestContext {
        fn get_shared_data(&self, key: &str) -> (Option<Bytes>, Option<u32>) {
            (Some(self.data.clone()),  Some(self.data.len() as u32))
        }

        fn set_shared_data(
            &self,
            key: &str,
            value: Option<&[u8]>,
            cas: Option<u32>,
        ) -> Result<(), Status> {
            Ok(())
        }
    }

    #[test]
    fn serde() {
        let mut cache = SharedCache::new();
        let mut test_context = TestContext { data: Vec::new() };

        cache.set_tokens_for_session(
            &"testsession".to_string(),
            &"testaccces".to_string(),
            None);

        let serialized = serde_json::to_string(&cache).unwrap();
        test_context.data = serialized.into_bytes();

        let new_cache = SharedCache::from_host(&test_context).unwrap();
        let tokens = new_cache.get_tokens_for_session(&"testsession".to_string());
        if let Some(tokens) = tokens {
            assert_eq!(tokens.access_token, "testaccces")
        } else {
            panic!("Bad deserialization")
        }

    }

}