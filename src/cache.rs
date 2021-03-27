use std::collections::HashMap;
use oauth2::PkceCodeVerifier;
use crate::oauther::Cache;

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