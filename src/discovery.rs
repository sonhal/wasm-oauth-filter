use serde::{Deserialize, Serialize};
use std::{error, fmt};
use url::{ParseError, Url};
use jwt_simple::prelude::{RSAPublicKey, RS256PublicKey};
use jsonwebkey::{JsonWebKey, Key};
use crate::messages::{HttpRequest, HttpResponse};
use oauth2::http::{Method, StatusCode};
use oauth2::http::header::ACCEPT;
use crate::oauth_client::ClientConfig;
use crate::RawFilterConfig;


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
    BadState(String)
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

    pub fn new(
        issuer: Url,
        authorization_endpoint: Url,
        token_endpoint: Option<Url>,
        userinfo_endpoint: Option<Url>,
        jwks_uri: Url,
        scopes_supported: Option<Vec<String>>,
        response_types_supported: Vec<String>,
        subject_types_supported: Vec<String>,
        id_token_signing_alg_values_supported: Vec<String>,
    ) -> ProviderMetadata {
        ProviderMetadata {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
            scopes_supported,
            response_types_supported,
            subject_types_supported,
            id_token_signing_alg_values_supported
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<ProviderMetadata, ConfigError> {
        serde_json::from_slice::<ProviderMetadata>(bytes.as_slice())
            .map_err(|err| {
                ConfigError::Parse(err.to_string())
            })
    }

    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    pub fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &Option<Url> {
        &self.token_endpoint
    }

    pub fn jwks_url(&self) -> Url {
        self.jwks_uri.clone()
    }
}

pub fn discovery_request(issuer_url: &Url) -> Result<HttpRequest, ParseError> {
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


#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct JsonWebKeySet
{
    keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {

    pub fn new(keys: Vec<JsonWebKey>) -> JsonWebKeySet {
        JsonWebKeySet {
            keys
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<JsonWebKeySet, ConfigError> {
        serde_json::from_slice::<JsonWebKeySet>(bytes.as_slice())
            .map_err(|err| {
                ConfigError::Parse(err.to_string())
            })
    }

    pub fn keys(&self) -> Vec<RS256PublicKey> {
        self.keys.iter().filter_map(
            |key| {
                if let Key::RSA { public, private } = &*key.key {
                    let ser_e = serde_json::to_string(&public.e).unwrap();
                    let ser_e = ser_e.strip_prefix("\"").unwrap().to_string();
                    let ser_e= ser_e.strip_suffix("\"").unwrap().to_string();
                    let ser_e = base64::decode(ser_e).unwrap();
                    Some(RS256PublicKey::from_components(&public.n, ser_e.as_slice()).unwrap())
                } else { None }
            }
        ).collect()
    }
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
    use jwt_simple::prelude::{RS256PublicKey, RSAPublicKey, NoCustomClaims, RSAPublicKeyLike, VerificationOptions, Duration, Audiences};
    use serde::Serialize;
    use oauth2::url::form_urlencoded::ByteSerialize;
    use crate::messages::HttpResponse;
    use oauth2::http::StatusCode;
    use std::collections::HashSet;
    use std::u64::MAX;

    #[test]
    fn discovery_request() {
        let result = discovery::discovery_request(&"https://issuer/customissuer/".parse().unwrap());
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

    #[test]
    fn keys() {
        const RAW_ID_TOKEN: &str = "eyJraWQiOiJtb2NrLW9hdXRoMi1zZXJ2ZXIta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ0ZXN0ZXIxIiwiYXVkIjoiYXVkLXRva2VuLXRlc3RlciIsImFjciI6IjEiLCJuYmYiOjE2MTkzNjUyMzUsImlzcyI6Imh0dHA6XC9cL21vY2stb2F1dGgyLXNlcnZlcjo4MDgwXC9jdXN0b21pc3MiLCJleHAiOjE2MTkzNjUzNTUsImlhdCI6MTYxOTM2NTIzNSwianRpIjoiZWM5OTgzOTYtOTI2NC00ZTU4LWEyMGEtZTAyMDk3ODU4NDNmIn0.Z0c2Tx15jp2VU1xk3uce9IXAMTG_q4DHGqJvcsO7G3G1QBt1Euob5UbCk4jyPYmpX6dIjTuAmbCYOuKJ732CFh4RIS_NXmO9K-402h61I-JypD2TeZjTvIGTrlubTxieq5b2-J2ZFMXFndt2zaUE8VYdti2MSwNp-IwS1pJGrvbCjw77s61lMn2vw_UUVcBEp99qojfdw97Da-KccBIZYEZXs0RXQkg2--iy-rqv6LNVD3CLrGyr-aXN1jppHX-ZGlukFkSIwLudEhE615R2x7LbYG0-NVoRpQg1oFHywwSUqGm_I-S7VisZHUKxr8pQK1RspOXZZt2mTQaifxFY-A";
        let body = "{
        \"keys\" : [ {
            \"kty\" : \"RSA\",
            \"e\" : \"AQAB\",
            \"use\" : \"sig\",
            \"kid\" : \"mock-oauth2-server-key\",
            \"n\" : \"k38LU5EY3j0s5FMl-Pae_AOXt_bmt-as3C1n9vWVAyCvcuE3i_ootBEMPLQPJEru2NH-cfN7TrmdNy1XeKZVg1Y6AUXTTl0qHdyfSH65t2M1ieS0D2RTiiXmLAbZ72UzNUIo2rOgppltfNhF1tG29cNg5dsmecszrOPOfcnxUcNNewkIF-FZxL_xPhuefqhoUA89unVZHuh6ZUuesusdK0i-VqsapNpSj7ba0OORDNciMbaG3R5fWj4k1LdpvoPNAjyiF7xvJzIW5BuxKEKUgnXWrK4JexHd9TVDsXoyx_oRBlTaMqn4t2bRYrQn-8aTOQ7uq7AYeHPLmWXr1FSggw\"
        } ]
    }".to_string().into_bytes();
        let response = HttpResponse {
            status_code: StatusCode::OK,
            headers: vec![],
            body,
        };

        let result = discovery::jwks_response(
            response,
        ).unwrap();

        let keys = result.keys();
        let key = &keys[0];
        let options = VerificationOptions {
            reject_before: None,
            accept_future: false,
            required_subject: None,
            required_key_id: None,
            required_public_key: None,
            required_nonce: None,
            allowed_issuers: None,
            allowed_audiences: Some(HashSet::from(Audiences::AsString("aud-token-tester".to_string()))),
            time_tolerance: Some(Duration::from_days(10_000)), // TODO, will fail someday in the future :P
            max_validity: None};
        let claims = key.verify_token::<NoCustomClaims>(
            RAW_ID_TOKEN,
            Some(options)

        ).unwrap();

    }

}
