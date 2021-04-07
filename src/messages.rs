use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum TokenResponse {
    Error(ErrorResponse),
    Success(SuccessfulResponse),
}

#[derive(Debug, Deserialize, Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
    error_uri: Option<String>
}

impl ErrorResponse {
    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody {
            status: "500".to_string(),
            error: self.error.clone(),
            error_description: Some(self.error_description.clone())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SuccessfulResponse {
    access_token: String,
    id_token: Option<String>,
    token_type: Option<String>,
    scope: String,
    expires_in: Option<i64>
}


#[derive(Serialize)]
struct ErrorBody {
    status: String,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>
}

impl ErrorBody {
    pub fn new(status: String, error: String, description: Option<String>) -> ErrorBody {
        ErrorBody {status, error, error_description: description}
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use crate::messages::{TokenResponse, ErrorResponse, SuccessfulResponse};

    #[test]
    fn error_response() {
        let test_error = TokenResponse::Error( ErrorResponse{
            error: "500".to_string(),
            error_description: "Bad stuff happened".to_string(),
            error_uri: None
        });
        let serialized = serde_json::to_string(&test_error).unwrap();
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Error(..)))
    }

    #[test]
    fn successful_response() {
        let test_success = TokenResponse::Success(SuccessfulResponse{
            access_token: "cooltoken".to_string(),
            id_token: None,
            token_type: None,
            scope: "openid email profile".to_string(),
            expires_in: None
        });
        let serialized = serde_json::to_string(&test_success).unwrap();
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Success(..)));

        let serialized = "{\"access_token\":\"cooltoken\",\"scope\":\"openid email profile\"}";
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Success(..)));
    }

}