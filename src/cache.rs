use std::collections::HashMap;
use oauth2::PkceCodeVerifier;
use crate::oauther::Cache;
use proxy_wasm::traits::Context;
use proxy_wasm::types::Status;
use serde::{Serialize, Deserialize};
use serde::de::Error;
use std::any::Any;


pub struct LocalCache {
    sessions: HashMap<String, Vec<String>>,
    verifiers: HashMap<String, PkceCodeVerifier>
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
    fn get_tokens_for_session(&self, session: &String) -> Option<Vec<String>> {
        if let Some(tokens) = self.sessions.get(session) {
            return Some(tokens.to_owned())
        };
        None
    }

    fn set_tokens_for_session(&mut self, session: String, tokens: Vec<String>) {
        self.sessions.insert(session, tokens);
    }

    fn get_verfier_for_state(&self, state: &String) -> Option<&PkceCodeVerifier> {
        if let Some(verifier) = self.verifiers.get(state) {
            return Some(verifier)
        };
        None
    }

    fn set_verfier_for_state(&mut self, state: &String, verifier: &PkceCodeVerifier) {
        self.verifiers.insert(state.to_string(), PkceCodeVerifier::new(verifier.secret().to_string()));
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SharedCache {
    sessions: HashMap<String, SessionData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    access_token: String,
    id_token: Option<String>,
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

    pub fn set(&mut self, session: String, access_token: String, id_token: Option<String>, context: & dyn Context) -> Result<(), String> {
        self.sessions.insert(session, SessionData { access_token, id_token });

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

    fn get_tokens_for_session(&self, session: &String) -> Option<&SessionData> {
        if let Some(tokens) = self.sessions.get(session) {
            return Some(tokens)
        };
        None
    }


}

#[cfg(test)]
mod tests {
    use crate::cache::SharedCache;
    use proxy_wasm::traits::Context;
    use proxy_wasm::types::{Status, Bytes};

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

        let result = cache.set(
            "testsession".to_string(),
            "testaccces".to_string(),
            None,
            &test_context);
        if let Ok(result) = result {
            println!("Good")

        } else {
            panic!("Bad result")
        }
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