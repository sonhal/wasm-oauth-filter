use std::collections::HashMap;
use crate::oauth_service::{SessionData};
use proxy_wasm::traits::Context;
use serde::{Serialize, Deserialize};
use crate::session::{SessionCache, SessionUpdate, UpdateType, Session};


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


#[derive(Debug, Serialize, Deserialize)]
pub struct SharedCache {
    sessions: HashMap<String, Session>,
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
        if let (Some(bytes), Some(_)) = (bytes, size) {
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
                    Err(status) => Err(format!("Error from host when attempting to set shared data, status={:?}", status))
                }
            }
            Err(error) => Err(error.to_string())
        }
    }
}

impl SessionCache for SharedCache {
    fn get(&self, id: &String) -> Option<Session> {
        self.sessions.get(id).cloned()
    }

    fn set(&mut self, update: SessionUpdate) {
        self.sessions.insert(update.id.clone(), update.create_session());
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::SharedCache;
    use proxy_wasm::traits::Context;
    use proxy_wasm::types::{Status, Bytes};
    use crate::session::{SessionCache, SessionUpdate, SessionType};

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

        let test_update = SessionUpdate::auth_request(
            "http://proxy/resource".to_string(),
            "abc".to_string(),
            "123".to_string()
        );

        let test_id = test_update.id.clone();
        cache.set(test_update);

        let serialized = serde_json::to_string(&cache).unwrap();
        test_context.data = serialized.into_bytes();

        let new_cache = SharedCache::from_host(&test_context).unwrap();
        let session = new_cache.get(&test_id);
        if let Some(session) = session {
            match session.data {
                SessionType::AuthorizationRequest(verifiers) => {

                }
                SessionType::Tokens(_) => panic!(),
                SessionType::Empty => panic!(),
            }
        } else {
            panic!("Bad deserialization")
        }

    }

}