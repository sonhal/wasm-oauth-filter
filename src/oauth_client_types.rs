use oauth2::HttpRequest;
use oauth2::url::Url;

use crate::messages::DownStreamResponse;

pub type Headers = Vec<(String, String)>;

#[derive(Debug)]
pub struct Request {
    headers: Headers,
    url: Url,
}

impl Request {
    pub(crate) fn new(headers: Headers) -> Result<Self, ClientError> {
        let url = Self::request_url(headers.clone())?;
        Ok(Request { headers, url })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn authorization_code(&self) -> Option<String> {
        self.find_query("code")
    }

    pub fn state(&self) -> Option<String>  {
        self.find_query("state")
    }

    fn find_query(&self, name: &str) -> Option<String>  {
        for (key, value ) in self.url.query_pairs() {
            if key == name {
                return Some(value.to_string())
            }
        }
        None
    }

    fn request_url(headers: Headers) -> Result<Url, ClientError> {
        let path =
            headers.iter().find(|(name, _)| { *name == ":path" }).map(|entry| { entry.1.clone() });
        let host_url = Self::host_url(headers)?;
        host_url.join(path.as_ref().unwrap_or(&"".to_string()).as_str())
            .map_err(|err| {
                ClientError::new(500, format!("Could not create URL from base={}, and path={}", host_url, path.unwrap_or_default()),None )
            })
    }

    fn host_url(headers: Headers) -> Result<Url, ClientError> {
        let scheme =
            headers.iter().find(|(name, _)| { *name == "x-forwarded-proto" }).map(|entry| { entry.1.clone() });
        let authority =
            headers.iter().find(|(name, _)| { *name == ":authority" }).map(|entry| { entry.1.clone() });
        match (scheme, authority) {
            (None, _) => Err(ClientError::new(400,"No scheme in request header".to_string(), None)),
            (_, None) => Err(ClientError::new(400, "No authority in request header".to_string(), None)),
            (Some(scheme), Some(authority)) => {
                Ok(format!("{}://{}", scheme, authority).parse().unwrap())
            }
        }
    }
}

pub struct Redirect {
    url: Url,
    headers: Headers
}

impl Redirect {
    pub fn new(url: Url, headers: Headers) -> Self {
        Redirect { url, headers }
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
    raw_request: HttpRequest,
}

impl TokenRequest {

    pub fn new(raw_request: HttpRequest) -> TokenRequest {
        Self { raw_request }
    }

    pub fn headers(&self) -> Vec<(&str, &str)> {
        let mut headers = self.serialize_headers();
        headers.append(&mut vec![
            (":method", "POST"),
            (":path", self.raw_request.url.path()),
            (":authority", self.raw_request.url.host_str().unwrap())]);
        headers
    }

    pub fn url(&self) -> &Url {
        &self.raw_request.url
    }

    pub fn body(&self) -> &[u8] {
        self.raw_request.body.as_slice()
    }

    fn serialize_headers(&self) -> Vec<(&str, &str)> {
        self.raw_request.headers.iter()
            .map(
                |( name, value)|
                    { (name.as_str(), value.to_str().unwrap()) }
            ).collect()
    }
}

#[derive(Debug)]
pub enum Access {
    Denied(DownStreamResponse),
    Allowed(Headers),
    UnAuthenticated,
}

#[derive(Debug)]
pub struct ClientError {
    status: u64,
    message: String,
    description: Option<String>,
}

impl ClientError {
    pub fn new(status: u64, message: String, description: Option<String>) -> ClientError {
        ClientError {
            status,
            message,
            description
        }
    }

    pub fn response(&self) -> DownStreamResponse {
        DownStreamResponse::new(vec![], self.status, self.message.clone())
    }
}
