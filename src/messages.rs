use oauth2::http;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

type Headers = Vec<(String, String)>;

// Struct for sending responses directly back to the end-user from the filter
#[derive(Debug, Serialize, Deserialize)]
pub struct DownStreamResponse {
    #[serde(skip_serializing)]
    headers: Headers,

    status: u64,
    body: String,
}

impl DownStreamResponse {
    pub fn new(headers: Headers, status: u64, body: String) -> Self {
        DownStreamResponse {
            headers,
            status,
            body,
        }
    }

    pub fn code(&self) -> u32 {
        self.status as u32
    }

    pub fn headers(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    pub fn serialize(&self) -> (Headers, u64, String) {
        (self.headers.clone(), self.status, self.body.clone())
    }
}

// Response from authorization server token endpoint
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
    error_uri: Option<String>,
}

impl ErrorResponse {
    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody {
            status: "500".to_string(),
            error: self.error.clone(),
            error_description: Some(self.error_description.clone()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessfulResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    expires_in: Option<u64>,
}

impl SuccessfulResponse {
    pub fn new(
        access_token: String,
        id_token: Option<String>,
        token_type: Option<String>,
        scope: Option<String>,
        expires_in: Option<u64>,
    ) -> SuccessfulResponse {
        SuccessfulResponse {
            access_token,
            id_token,
            token_type,
            scope,
            expires_in,
        }
    }

    pub fn expires_in(&self) -> Option<Duration> {
        if self.expires_in.is_none() {
            return None;
        }
        Some(Duration::from_secs(self.expires_in.unwrap()))
    }
}

#[derive(Serialize)]
pub struct ErrorBody {
    status: String,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl ErrorBody {
    pub fn new(status: String, error: String, description: Option<String>) -> ErrorBody {
        ErrorBody {
            status,
            error,
            error_description: description,
        }
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    // These are all owned values so that the request can safely be passed between
    // threads.
    /// URL to which the HTTP request is being made.
    url: Url,
    /// HTTP request headers to send.
    headers: Vec<(String, String)>,
    /// HTTP request body (typically for POST requests only).
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(
        url: Url,
        method: http::method::Method,
        headers: Headers,
        body: Vec<u8>,
    ) -> HttpRequest {
        let mut headers = headers;
        headers.push((":method".to_string(), method.to_string()));
        headers.append(&mut vec![
            (":path".to_string(), url.path().to_string()),
            (
                ":authority".to_string(),
                url.host_str().unwrap().to_string(),
            ),
        ]);
        HttpRequest { url, headers, body }
    }

    pub fn headers(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    pub fn path(&self) -> &str {
        self.url.path()
    }

    pub fn authority(&self) -> &str {
        self.url.host_str().unwrap()
    }

    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }
}

///
/// An HTTP response.
///
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code returned by the server.
    pub status_code: http::status::StatusCode,
    /// HTTP response headers returned by the server.
    pub headers: Headers,
    /// HTTP response body returned by the server.
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::messages::{ErrorResponse, SuccessfulResponse, TokenResponse};

    #[test]
    fn error_response() {
        let test_error = TokenResponse::Error(ErrorResponse {
            error: "500".to_string(),
            error_description: "Bad stuff happened".to_string(),
            error_uri: None,
        });
        let serialized = serde_json::to_string(&test_error).unwrap();
        let deserialized: TokenResponse = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, TokenResponse::Error(..)))
    }

    #[test]
    fn successful_response() {
        let test_success = TokenResponse::Success(SuccessfulResponse {
            access_token: "cooltoken".to_string(),
            id_token: None,
            token_type: None,
            scope: Some("openid email profile".to_string()),
            expires_in: None,
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
