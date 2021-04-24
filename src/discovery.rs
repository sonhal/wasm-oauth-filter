use serde::{Deserialize, Serialize};
use std::{error, fmt};
use url::{ParseError, Url};
use jwt_simple::prelude::RSAPublicKey;
use jsonwebkey::JsonWebKey;
use crate::messages::{HttpRequest, HttpResponse};
use oauth2::http::{Method, StatusCode};
use oauth2::http::header::ACCEPT;


pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_JWKS: &str = "application/jwk-set+json";
pub const MIME_TYPE_JWT: &str = "application/jwt";
const CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";
const OPENID_SCOPE: &str = "openid";

#[derive(Debug, Clone)]
pub enum ConfigError {
    Response(u32, String),
    Parse(String),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Configuration error")
    }
}

impl error::Error for ConfigError {}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ProviderMetadata {
    issuer: Url,
    authorization_endpoint: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_endpoint: Option<Url>,
    jwks_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes_supported: Option<Vec<String>>,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

impl ProviderMetadata {
    pub fn jwks_url(&self) -> Url {
        self.jwks_uri.clone()
    }
}

pub fn discovery_request(issuer_url: Url) -> Result<HttpRequest, ParseError> {
    let discovery_url = issuer_url.join(CONFIG_URL_SUFFIX)?;

    Ok(HttpRequest::new(
        discovery_url,
        Method::GET,
        vec![(ACCEPT.to_string(), MIME_TYPE_JSON.to_string())],
        Vec::new(),
    ))
}

pub fn jwks_request(jwks_url: Url) -> HttpRequest {
    HttpRequest::new(
        jwks_url,
        Method::GET,
        vec![(ACCEPT.to_string(), MIME_TYPE_JSON.to_string())],
        vec![],
    )
}

pub fn discovery_response(
    issuer_url: Url,
    discovery_response: HttpResponse,
) -> Result<ProviderMetadata, ConfigError> {
    if discovery_response.status_code != StatusCode::OK {
        return Err(ConfigError::Response(
            discovery_response.status_code.as_u16() as u32,
            "Discovery response error".to_string(),
        ));
    }

    let provider_metadata =
        serde_json::from_slice::<ProviderMetadata>(discovery_response.body.as_slice())
            .map_err(|err| ConfigError::Parse(err.to_string()))?;

    if provider_metadata.issuer != issuer_url {
        Err(ConfigError::Validation(format!(
            "Unexpected issuer URI {}, expected {}",
            provider_metadata.issuer, issuer_url
        )))
    } else {
        Ok(provider_metadata)
    }
}


#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct JsonWebKeySet
{
    keys: Vec<JsonWebKey>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct RSAJsonWebKeySet {
    alg: String, // "RS256"
    kty: String, // "RSA"
    _use: String, // "sig"
    n: String, // modulus
    e: String, // exponent
    kid: String, // "sttmy2a1FKl1AAzi7e1zW"
    x5t: String, // "J6LAUO_mZE52KNapwehthok-r0w"
    x5c: Vec<String> // X.509 cert chain
}


pub fn jwks_response(response: HttpResponse) -> Result<JsonWebKeySet, ConfigError> {
    if response.status_code != StatusCode::OK {
        return Err(ConfigError::Response(
            response.status_code.as_u16() as u32,
            "JWKS response error".to_string(),
        ));
    }

    serde_json::from_slice::<JsonWebKeySet>(&response.body)
            .map_err(|err| { ConfigError::Parse(err.to_string())})

}

#[cfg(test)]
mod tests {
    use crate::discovery;
    use crate::discovery::ConfigError;
    use std::borrow::Cow;
    use jsonwebkey::Key;
    use jwt_simple::prelude::{RS384PublicKey, RSAPublicKey, NoCustomClaims};
    use serde::Serialize;
    use oauth2::url::form_urlencoded::ByteSerialize;
    use crate::messages::HttpResponse;
    use oauth2::http::StatusCode;

    #[test]
    fn discovery_request() {
        let result = discovery::discovery_request("https://issuer/customissuer/".parse().unwrap());
        assert!(result.is_ok());
        assert!(result.unwrap().url().to_string().contains("customissuer"))
    }

    #[test]
    fn discovery_response() {
        let body = "{
            \"issuer\" : \"http://localhost:8888/default\",
                \"authorization_endpoint\" : \"http://localhost:8888/default/authorize\",
                \"end_session_endpoint\" : \"http://localhost:8888/default/endsession\",
                \"token_endpoint\" : \"http://localhost:8888/default/token\",
                \"jwks_uri\" : \"http://localhost:8888/default/jwks\",
                \"response_types_supported\" : [ \"query\", \"fragment\", \"form_post\" ],
                \"subject_types_supported\" : [ \"public\" ],
                \"id_token_signing_alg_values_supported\" : [ \"RS256\" ]
                }"
        .to_string()
        .into_bytes();
        let response = HttpResponse {
            status_code: StatusCode::OK,
            headers: vec![],
            body,
        };

        let result = discovery::discovery_response(
            "http://localhost:8888/default".parse().unwrap(),
            response,
        );
        assert!(result.is_ok())
    }

    #[test]
    fn jwks_response() {
        let body = "{
            \"keys\" : [ {
            \"kty\" : \"RSA\",
            \"e\" : \"AQAB\",
            \"use\" : \"sig\",
            \"kid\" : \"mock-oauth2-server-key\",
            \"n\" : \"z21whnWlEMDG8f0aNmXgAqfnu90LNKdhFTP__x6WNPCe_BaOXH_oPHzZVgEZT9aGKUqN5v49rRwj0wiNb8U-7rAJE2oVWKIIyowoR1f-mK2hrKkGf3jLR5OJIyT3J2vdoHwUlSeX5zK7S_xyYb0grRJ52z7mMMhZz7bapNghccb8GOC--D0y-yjhQMh7t8wrAxWVay_JVP1Y5J9-YIk7S-fXHcEyW3k9758vKMrt7vWpKTGI7Kg-GFU1PXu1Y-CTgJVfyO5lrzqZAYs5JoAf5UEka0j7gqDf3m-wjBQMEW4wJNB_NT7ZqblnKDrVv2jplXjwburafuGCEH8EeQO_Uw\"
            } ]
            }".to_string().into_bytes();
        let response = HttpResponse {
            status_code: StatusCode::OK,
            headers: vec![],
            body,
        };

        let result = discovery::jwks_response(
            response,
        );
        assert!(result.is_ok());
        let key = result.unwrap().keys.pop().unwrap().key;
        match *key {
            Key::EC { .. } => {}
            Key::RSA { public, private } => {
                let ser_e = serde_json::to_string(&public.e).unwrap();
                let ser_e = ser_e.strip_prefix("\"").unwrap().to_string();
                let ser_e= ser_e.strip_suffix("\"").unwrap().to_string();
                let ser_e = base64::decode(ser_e).unwrap();
                let public_key = RSAPublicKey::from_components(&public.n, ser_e.as_slice());
                assert!(public_key.is_ok());
                let public_key = public_key.unwrap();
                // public_key.verify_token::<NoCustomClaims>(&token, None)?;
            }
            Key::Symmetric { .. } => {}
        }

    }
}
