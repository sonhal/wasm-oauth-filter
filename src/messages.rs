use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TokenResponse {
    Error(ErrorResponse),
    Success(SuccessfulResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
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
pub struct SuccessfulResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub expires_in: Option<u64>
}


#[derive(Serialize)]
pub struct ErrorBody {
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
            scope: Some("openid email profile".to_string()),
            expires_in: None
        });
        let serialized = serde_json::to_string(&test_success).unwrap();
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Success(..)));

        let serialized = "{\"access_token\":\"cooltoken\",\"scope\":\"openid email profile\"}";
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Success(..)));
    }

    #[test]
    fn real_case() {
        let serialized =  "{
            \"token_type\" : \"Bearer\",
            \"id_token\" : \"eyJraWQiOiJtb2NrLW9hdXRoMi1zZXJ2ZXIta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ0ZXN0ZXIxIiwiYXVkIjoiYXVkLXRva2VuLXRlc3RlciIsImFjciI6IjEiLCJuYmYiOjE2MTc4Mjg5NjgsImlzcyI6Imh0dHA6XC9cL21vY2stb2F1dGgyLXNlcnZlcjo4MDgwXC9jdXN0b21pc3MiLCJleHAiOjE2MTc4MjkwODgsImlhdCI6MTYxNzgyODk2OCwianRpIjoiODFlOTM3ZjYtMzAxYi00ZWVhLTg2MWQtOTA5YmEzOGJhYzVkIn0.ZwHNg8IOlwOlqzDpSf9G6hcOk_AdIr8vAGy2ciWvGr6-xfYE5ABwiV_4kD6o3dsb_3Ii5DeOD0pcCRFawURWd5vYaaLCGjPVO0R0MtiTGil2LKUOkrAgVxbfFA4o09FxTc7xYe5GcDk371bCpCWfXqciT5OL6-Rl0k8tfRCVaI5Pgh_NhKeRa_v16nbakDpYS2boKkFi8z7EmgckhlKPKbye2-G6-xkUf4zd37ELAlnkFeJB0CU_szkFlGzTVu5o2nj0ew6Yqle4N1LVBlDWuNSX1LxbtpaEzfpXQl2UA2Voojc2jfUyLqwJDaQdg7NrnmyOtapR24hFR_A2Ci4_Jw\",
            \"access_token\" : \"eyJraWQiOiJtb2NrLW9hdXRoMi1zZXJ2ZXIta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ0ZXN0ZXIxIiwiYXVkIjoiYXVkLXRva2VuLXRlc3RlciIsImFjciI6IjEiLCJuYmYiOjE2MTc4Mjg5NjgsImlzcyI6Imh0dHA6XC9cL21vY2stb2F1dGgyLXNlcnZlcjo4MDgwXC9jdXN0b21pc3MiLCJleHAiOjE2MTc4MjkwODgsImlhdCI6MTYxNzgyODk2OCwianRpIjoiMmNiY2Y1NGMtZjYzNi00YzIxLWI3OTUtN2QwNDVmMTkwNGM2In0.Ifet2fTc4a3sPnrRO7y04WkONwhmy7DbCd6_rMKnwnI7oeEdrAfViNbXxh6geI-tefQKwaF4gjm3XdL_S0kB0Cy3cBhMSxYz33qkRx-2FJgUZ497t6lMEvqtcRcaeI3jaQaOFtlX1Xckim6w-cC-qDBDwDRjugd5zNIabn6Ha5gsH9jt837Naf95KmSDxrFOUSFl-967E14i5pFIjnJf8rEKdVp3uCG0mu9LBPZb1ayLuOnYedcxWXH1AqEze0q3TzUjMyPWQZ9DUNkvGFLBIyd9ScWiDn-o8BgGSvfKseuSCj3jhyBZHmZT7EP97s6NpQuBs-hsnCLK5hnkMRc_7Q\",
            \"refresh_token\" : \"2087ea81-6397-482e-80f2-8c11b13a72f5\",
            \"expires_in\" : 119
            }";
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Success(..)));
    }

}