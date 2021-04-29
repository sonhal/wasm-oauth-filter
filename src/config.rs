use crate::discovery::{JsonWebKeySet, ProviderMetadata};
use crate::oauth_client::ClientConfig;
use jwt_simple::claims::{JWTClaims, NoCustomClaims};
use jwt_simple::prelude::{RSAPublicKeyLike, VerificationOptions};
use jwt_simple::{Error, JWTError};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use time::Duration;
use url::Url;

pub trait ExtraConfig: Debug {
    fn validate_token(&self, token: &str) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub struct FilterConfig<T>
where
    T: ExtraConfig,
{
    cookie_name: String,
    auth_cluster: String,
    issuer: String,
    auth_uri: Url,
    token_uri: Url,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    cookie_expire: Duration,
    extra_authorization_params: Vec<(String, String)>,
    extra: T,
}

impl<T> FilterConfig<T>
where
    T: ExtraConfig,
{
    pub fn new(
        cookie_name: &str,
        auth_cluster: &str,
        issuer: &str,
        auth_uri: &Url,
        token_uri: &Url,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
        extra: T,
    ) -> FilterConfig<T> {
        FilterConfig {
            cookie_name: cookie_name.to_string(),
            auth_cluster: auth_cluster.to_string(),
            issuer: issuer.to_string(),
            auth_uri: auth_uri.clone(),
            token_uri: token_uri.clone(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            scopes,
            cookie_expire,
            extra_authorization_params,
            extra,
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<(), Error> {
        self.extra.validate_token(token)
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn auth_cluster(&self) -> &str {
        &self.auth_cluster
    }

    // Stub to be removed after integration
    pub(crate) fn client(&self) -> ClientConfig {
        ClientConfig::new("", "", "", "", "", "", vec![], vec![], 0)
    }
}

impl FilterConfig<BasicOAuth> {
    pub fn oauth(
        cookie_name: &str,
        auth_cluster: &str,
        issuer: &str,
        auth_uri: &Url,
        token_uri: &Url,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
    ) -> FilterConfig<BasicOAuth> {
        FilterConfig::new(
            cookie_name,
            auth_cluster,
            issuer,
            auth_uri,
            token_uri,
            client_id,
            client_secret,
            scopes,
            cookie_expire,
            extra_authorization_params,
            BasicOAuth {},
        )
    }
}

impl FilterConfig<OIDC> {
    pub fn oidc(
        cookie_name: &str,
        auth_cluster: &str,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
        jwks: JsonWebKeySet,
        provider_metadata: ProviderMetadata,
    ) -> FilterConfig<OIDC> {
        FilterConfig {
            cookie_name: cookie_name.to_string(),
            auth_cluster: auth_cluster.to_string(),
            issuer: provider_metadata.issuer().to_string(),
            auth_uri: provider_metadata.authorization_endpoint().clone(),
            token_uri: provider_metadata.token_endpoint().clone().unwrap(), // TODO FIX
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            scopes,
            cookie_expire,
            extra_authorization_params,
            extra: OIDC {
                jwks,
                provider_metadata,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct BasicOAuth {}

impl ExtraConfig for BasicOAuth {
    // Clients dont validate tokens in basic OAuth
    fn validate_token(&self, _token: &str) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OIDC {
    jwks: JsonWebKeySet,
    provider_metadata: ProviderMetadata,
}

impl OIDC {
    // Validates OIDC token according to OpenID Connect Core 1.0
    fn validate(&self, token: &str, options: Option<VerificationOptions>) -> Result<(), Error> {
        let mut errors = vec![];
        for key in self.jwks.keys().iter() {
            match key.verify_token::<NoCustomClaims>(token, options.clone()) {
                Ok(claims) => return Ok(()),
                Err(error) => errors.push(error),
            }
        }
        Err(errors.pop().unwrap()) // TODO FIX
    }
}

impl ExtraConfig for OIDC {
    fn validate_token(&self, token: &str) -> Result<(), Error> {
        self.validate(token, None)
    }
}

// Enums representing the raw configuration passed from the proxy
// Serves as a protection layer between external and internal representation of configuration
#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum RawFilterConfig {
    OAuth(RawOAuth),
    OIDC(RawOIDC)
}

#[derive(Deserialize, Clone, Debug)]
pub struct RawOAuth {
    #[serde(default = "default_redirect_uri")]
    redirect_uri: String,
    #[serde(default = "default_target_header_name")]
    target_header_name: String,
    #[serde(default = "default_oidc_cookie_name")]
    cookie_name: String,
    auth_cluster: String,
    issuer: String,
    auth_uri: String,
    token_uri: String,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_cookie_expire")]
    cookie_expire: u64, // in seconds
    #[serde(default = "default_extra_params")]
    extra_params: Vec<(String, String)>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RawOIDC {
    #[serde(default = "default_oidc_cookie_name")]
    cookie_name: String,
    auth_cluster: String,
    issuer: Url,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_cookie_expire")]
    cookie_expire: u64, // in seconds
    #[serde(default = "default_extra_params")]
    extra_params: Vec<(String, String)>,
}

impl RawFilterConfig {
    pub fn cluster(&self) -> &str{
        match self {
            RawFilterConfig::OAuth(raw) => raw.cluster(),
            RawFilterConfig::OIDC(raw) => raw.cluster()
        }
    }
}

impl RawOAuth {
    // Convert Raw config to filter config with rich types
    pub fn filter_config(&self) -> Result<FilterConfig<BasicOAuth>, Error> {
        Ok(FilterConfig::oauth(
            &self.cookie_name,
            &self.auth_cluster,
            &self.issuer,
            &self.auth_uri.parse().unwrap(),  // TODO FIX
            &self.token_uri.parse().unwrap(), // TODO FIX
            &self.client_id,
            &self.client_secret,
            self.scopes.clone(),
            time::Duration::seconds(self.cookie_expire as i64),
            self.extra_params.clone(),
        ))
    }

    pub fn cluster(&self) -> &str {
        &self.auth_cluster
    }
}

impl RawOIDC {
    // Convert Raw config to filter config with rich types and completed discovery
    pub fn filter_config(&self, provider_metadata: &ProviderMetadata , jwks: &JsonWebKeySet) -> Result<FilterConfig<OIDC>, Error> {
        Ok(FilterConfig::oidc(
            &self.cookie_name,
            &self.auth_cluster,
            &self.client_id,
            &self.client_secret,
            self.scopes.clone(),
            time::Duration::seconds(self.cookie_expire as i64),
            self.extra_params.clone(),
            jwks.clone(),
            provider_metadata.clone(),
        ))
    }

    pub fn issuer(&self) -> &Url{
        &self.issuer
    }

    pub fn cluster(&self) -> &str {
        &self.auth_cluster
    }
}

fn default_redirect_uri() -> String {
    "{proto}://{authority}{path}".to_owned()
}

fn default_oidc_cookie_name() -> String {
    "oidcSession".to_owned()
}

fn default_target_header_name() -> String {
    "Authorization".to_owned()
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

fn default_extra_params() -> Vec<(String, String)> {
    Vec::new()
}

fn default_cookie_expire() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use crate::config::{BasicOAuth, FilterConfig, RawFilterConfig, OIDC};
    use crate::discovery::{JsonWebKeySet, ProviderMetadata};
    use jwt_simple::prelude;
    use jwt_simple::prelude::{Audiences, VerificationOptions};
    use std::collections::HashSet;
    use time::Duration;
    use url::Url;

    #[test]
    fn new() {
        let oauth2_config = FilterConfig::oauth(
            "cookiename",
            "some_cluster",
            "test_issuer",
            &"https://localhost/auth".parse().unwrap(),
            &"https://localhost/token".parse().unwrap(),
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
        );

        let oidc_config = FilterConfig::oidc(
            "cookiename",
            "some_cluster",
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
            JsonWebKeySet::new(vec![]),
            ProviderMetadata::new(
                "https://localhost/".parse().unwrap(),
                "https://localhost/auth".parse().unwrap(),
                Some("https://localhost/token".parse().unwrap()),
                Some("https://localhost/userinfo".parse().unwrap()),
                "https://localhost/jwks".parse().unwrap(),
                None,
                vec!["code".to_string()],
                vec!["public".to_string()],
                vec!["RS256".to_string()],
            ),
        );

        let result = format!("{:?}", oidc_config);
    }

    #[test]
    fn validate_token() {
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

        let oidc_config = FilterConfig::oidc(
            "cookiename",
            "some_cluster",
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
            JsonWebKeySet::from_bytes(body).unwrap(),
            ProviderMetadata::new(
                "https://localhost/".parse().unwrap(),
                "https://localhost/auth".parse().unwrap(),
                Some("https://localhost/token".parse().unwrap()),
                Some("https://localhost/userinfo".parse().unwrap()),
                "https://localhost/jwks".parse().unwrap(),
                None,
                vec!["code".to_string()],
                vec!["public".to_string()],
                vec!["RS256".to_string()],
            ),
        );
        let options = VerificationOptions {
            reject_before: None,
            accept_future: false,
            required_subject: None,
            required_key_id: None,
            required_public_key: None,
            required_nonce: None,
            allowed_issuers: None,
            allowed_audiences: Some(HashSet::from(Audiences::AsString(
                "aud-token-tester".to_string(),
            ))),
            time_tolerance: Some(jwt_simple::prelude::Duration::from_days(10_000)), // TODO, will fail someday in the future :P
            max_validity: None,
        };
        let result = oidc_config.extra.validate(RAW_ID_TOKEN, Some(options));
        assert!(result.is_ok())
    }

    #[test]
    fn raw_config() {
        let text = "
        {
         \"redirect_uri\": \"http://localhost:8090/callback\",
        \"auth_cluster\": \"cluster_mock_auth\",
        \"issuer\": \"http://mock-oauth2-server:8080/customiss\",
        \"token_uri\": \"http://mock-oauth2-server:8888/customiss/token\",
        \"auth_uri\": \"http://localhost:8888/customiss/authorize\",
        \"client_id\": \"mycoolclientid\",
        \"client_secret\": \"mycoolclientsecret\",
        \"scopes\": [\"openid\", \"email\", \"profile\"],
        \"cookie_expire\": 120
        }";

        let oauth_config: RawFilterConfig = serde_json::from_str(text).unwrap();
        assert!(matches!(oauth_config, RawFilterConfig::OAuth { .. }));

        let text = "
        {
        \"auth_cluster\": \"cluster_mock_auth\",
        \"issuer\": \"http://mock-oauth2-server:8080/customiss\",
        \"client_id\": \"mycoolclientid\",
        \"client_secret\": \"mycoolclientsecret\",
        \"scopes\": [\"openid\", \"email\", \"profile\"],
        \"cookie_expire\": 120
        }";

        let oauth_config: RawFilterConfig = serde_json::from_str(text).unwrap();
        assert!(matches!(oauth_config, RawFilterConfig::OIDC { .. }));
    }
}
