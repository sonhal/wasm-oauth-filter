use crate::discovery::ConfigError::BadState;
use crate::discovery::{JsonWebKeySet, ProviderMetadata};
use crate::util;
use jwt_simple::claims::NoCustomClaims;
use jwt_simple::prelude::{JWTClaims, RSAPublicKeyLike, VerificationOptions};
use jwt_simple::Error;
use oauth2::basic::{BasicClient, BasicErrorResponse, BasicTokenResponse, BasicTokenType};
use oauth2::{
    AuthType, AuthUrl, Client, ClientId, ClientSecret, CsrfToken, HttpRequest, PkceCodeChallenge,
    RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::Debug;
use time::Duration;
use url::Url;


#[derive(Clone, Debug)]
pub struct FilterConfig {
    cookie_name: String,
    auth_cluster: String,
    issuer: String,
    redirect_uri: Url,
    auth_uri: Url,
    token_uri: Url,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    cookie_expire: Duration,
    extra_authorization_params: Vec<(String, String)>,
    extra: ExtraConfig,
}

impl FilterConfig {
    pub fn new(
        cookie_name: &str,
        auth_cluster: &str,
        issuer: &str,
        redirect_uri: &Url,
        auth_uri: &Url,
        token_uri: &Url,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
        extra: ExtraConfig,
    ) -> FilterConfig {
        FilterConfig {
            cookie_name: cookie_name.to_string(),
            auth_cluster: auth_cluster.to_string(),
            issuer: issuer.to_string(),
            redirect_uri: redirect_uri.clone(),
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

    pub fn oauth(
        cookie_name: &str,
        auth_cluster: &str,
        issuer: &str,
        redirect_uri: &Url,
        auth_uri: &Url,
        token_uri: &Url,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
    ) -> FilterConfig {
        FilterConfig::new(
            cookie_name,
            auth_cluster,
            issuer,
            redirect_uri,
            auth_uri,
            token_uri,
            client_id,
            client_secret,
            scopes,
            cookie_expire,
            extra_authorization_params,
            ExtraConfig::BasicOAuth,
        )
    }

    pub fn oidc(
        cookie_name: &str,
        auth_cluster: &str,
        issuer: &str,
        redirect_uri: &Url,
        auth_uri: &Option<Url>,
        token_uri: &Option<Url>,
        client_id: &str,
        client_secret: &str,
        scopes: Vec<String>,
        cookie_expire: Duration,
        extra_authorization_params: Vec<(String, String)>,
        jwks: JsonWebKeySet,
        provider_metadata: ProviderMetadata,
    ) -> FilterConfig {
        FilterConfig {
            cookie_name: cookie_name.to_string(),
            auth_cluster: auth_cluster.to_string(),
            issuer: issuer.to_string(),
            redirect_uri: redirect_uri.clone(),
            auth_uri: auth_uri
                .as_ref()
                .map_or(provider_metadata.authorization_endpoint().clone(), |url| {
                    url.clone()
                }),
            token_uri: token_uri
                .as_ref()
                .map_or(provider_metadata.token_endpoint().clone().unwrap(), |url| {
                    url.clone()
                }), // TODO FIX
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            scopes,
            cookie_expire,
            extra_authorization_params,
            extra: ExtraConfig::OIDC {
                jwks,
                provider_metadata,
            },
        }
    }

    pub fn authorization_url(
        &self,
        pkce_challenge: PkceCodeChallenge,
    ) -> (Url, CsrfToken) {
        let builder = self.client();
        let mut builder = builder
            .authorize_url(|| CsrfToken::new(util::new_random_verifier(32).secret().to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge);

        // Add extra parameters for Authorization redirect from configuration
        for param in &self.extra_authorization_params {
            builder = builder.add_extra_param(param.0.as_str(), param.1.as_str());
        }

        // Add configured scopes
        for scope in &self.scopes {
            builder = builder.add_scope(Scope::new(scope.clone()))
        }

        builder.url()
    }

    pub fn token_request(&self, code: String, code_verifier: Option<String>) -> HttpRequest {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
        ];

        // if we have a PKCE verifer we send it in the token request
        let verifier_string;
        if code_verifier.is_some() {
            verifier_string = code_verifier.unwrap();
            params.push(("code_verifier", verifier_string.as_str()))
        }

        util::token_request(
            &AuthType::RequestBody,
            &ClientId::new(self.client_id().to_string()),
            Some(&ClientSecret::new(self.client_secret().to_string())),
            &[],
            Some(&RedirectUrl::from_url(self.redirect_uri.clone())),
            None,
            &TokenUrl::from_url(self.token_uri.clone()),
            params,
        )
    }

    pub fn validate_token(&self, token: &str) -> Result<(), Error> {
        let allowed_issuers: HashSet<String> =
            vec![&self.issuer].iter().map(|s| s.to_string()).collect();

        // Allowed audiences for ID token is client id and the issuer (for userinfo fetching)
        let mut allowed_audiences = allowed_issuers.clone();
        allowed_audiences.insert(self.client_id.clone());

        let option = VerificationOptions {
            reject_before: None,
            accept_future: false,
            required_subject: None,
            required_key_id: None,
            required_public_key: None,
            required_nonce: None,
            allowed_issuers: Some(allowed_issuers),
            allowed_audiences: Some(allowed_audiences),
            time_tolerance: None,
            max_validity: None,
        };
        let _ = self.extra.validate_id_token(token, Some(option))?;
        Ok(())
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn cookie_expire(&self) -> &Duration {
        &self.cookie_expire
    }

    pub fn auth_cluster(&self) -> &str {
        &self.auth_cluster
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn client(&self) -> Client<BasicErrorResponse, BasicTokenResponse, BasicTokenType> {
        BasicClient::new(
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
            AuthUrl::from_url(self.auth_uri.clone()),
            Some(TokenUrl::from_url(self.token_uri.clone())),
        )
        .set_redirect_url(RedirectUrl::from_url(self.redirect_uri.clone()))
    }
}


#[derive(Clone, Debug)]
pub enum ExtraConfig {
    BasicOAuth,
    OIDC {
        jwks: JsonWebKeySet,
        provider_metadata: ProviderMetadata,
    },
}

impl ExtraConfig {
    // Validates OIDC token according to OpenID Connect Core 1.0
    fn validate(
        &self,
        token: &str,
        jwks: &JsonWebKeySet,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        log::debug!("validating id token = {}", token);
        let mut errors = vec![];
        for key in jwks.keys().iter() {
            match key.verify_token::<NoCustomClaims>(token, options.clone()) {
                Ok(claims) => return Ok(claims),
                Err(error) => errors.push(error),
            }
        }
        log::error!("ERROR not valid token = {}, errors = {:?}", token, errors);
        Err(errors.pop().unwrap()) // TODO FIX
    }

    pub fn validate_id_token(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        match self {
            ExtraConfig::BasicOAuth => Err(Error::new(BadState(
                "Asked to validate ID token, but configured for OAuth".to_string(),
            ))),
            ExtraConfig::OIDC { jwks, .. } => self.validate(token, jwks, options),
        }
    }
}

// Struct representing the raw configuration passed from the proxy
// Serves as a protection layer between external and internal representation of configuration
#[derive(Deserialize, Clone, Debug)]
pub struct RawFilterConfig {
    #[serde(default = "default_redirect_uri")]
    redirect_uri: String,
    #[serde(default = "default_target_header_name")]
    target_header_name: String,
    #[serde(default = "default_oidc_cookie_name")]
    cookie_name: String,
    auth_cluster: String,
    issuer: String,
    auth_uri: Option<String>,
    token_uri: Option<String>,
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
    // Convert Raw config to filter config with rich types
    pub fn oauth_config(&self) -> Result<FilterConfig, Error> {
        Ok(FilterConfig::oauth(
            &self.cookie_name,
            &self.auth_cluster,
            &self.issuer,
            &self.redirect_uri.parse().unwrap(),
            &self.auth_uri.as_ref().unwrap().parse().unwrap(), // TODO FIX
            &self.token_uri.as_ref().unwrap().parse().unwrap(), // TODO FIX
            &self.client_id,
            &self.client_secret,
            self.scopes.clone(),
            time::Duration::seconds(self.cookie_expire as i64),
            self.extra_params.clone(),
        ))
    }

    // Convert Raw config to filter config with rich types and completed discovery
    pub fn oidc_config(
        &self,
        provider_metadata: &ProviderMetadata,
        jwks: &JsonWebKeySet,
    ) -> Result<FilterConfig, Error> {
        Ok(FilterConfig::oidc(
            &self.cookie_name,
            &self.auth_cluster,
            &self.issuer,
            &self.redirect_uri.parse().unwrap(), // TODD FIX
            &self.auth_uri.as_ref().map(|url| url.parse().unwrap()),
            &self.token_uri.as_ref().map(|url| url.parse().unwrap()),
            &self.client_id,
            &self.client_secret,
            self.scopes.clone(),
            time::Duration::seconds(self.cookie_expire as i64),
            self.extra_params.clone(),
            jwks.clone(),
            provider_metadata.clone(),
        ))
    }

    pub fn is_oidc(&self) -> bool {
        self.scopes.contains(&"openid".to_string())
    }

    pub fn cluster(&self) -> &str {
        &self.auth_cluster
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
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
    use crate::config::{FilterConfig, RawFilterConfig};
    use crate::discovery::{JsonWebKeySet, ProviderMetadata};
    use jwt_simple::prelude::{Audiences, VerificationOptions};
    use std::collections::HashSet;
    use time::Duration;

    #[test]
    fn new() {
        let oauth2_config = FilterConfig::oauth(
            "cookiename",
            "some_cluster",
            "test_issuer",
            &"https://localhost/callback".parse().unwrap(),
            &"https://issuer/auth".parse().unwrap(),
            &"https://issuer/token".parse().unwrap(),
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
        );

        let oidc_config = FilterConfig::oidc(
            "cookiename",
            "some_cluster",
            "test_issuer",
            &"https://localhost/callback".parse().unwrap(),
            &Some("https://issuer/auth".parse().unwrap()),
            &Some("https://issuer/token".parse().unwrap()),
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
            JsonWebKeySet::new(vec![]),
            ProviderMetadata::new(
                "https://localhost/".parse().unwrap(),
                "https://issuer/auth".parse().unwrap(),
                Some("https://issuer/token".parse().unwrap()),
                Some("https://issuer/userinfo".parse().unwrap()),
                "https://issuer/jwks".parse().unwrap(),
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
            "http://mock-oauth2-server:8080/customiss",
            &"https://localhost/callback".parse().unwrap(),
            &None,
            &None,
            "clientid",
            "clientsecret",
            vec![],
            Duration::hour(),
            vec![],
            JsonWebKeySet::from_bytes(body).unwrap(),
            ProviderMetadata::new(
                "https://localhost/".parse().unwrap(),
                "https://issuer/auth".parse().unwrap(),
                Some("https://issuer/token".parse().unwrap()),
                Some("https://issuer/userinfo".parse().unwrap()),
                "https://issuer/jwks".parse().unwrap(),
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
        let result = oidc_config
            .extra
            .validate_id_token(RAW_ID_TOKEN, Some(options));
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
        \"scopes\": [\"email\", \"profile\"],
        \"cookie_expire\": 120
        }";

        let oauth_config: RawFilterConfig = serde_json::from_str(text).unwrap();
        assert!(!oauth_config.is_oidc());

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
        assert!(oauth_config.is_oidc());
    }
}
