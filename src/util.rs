use oauth2::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use oauth2::http::{HeaderMap, HeaderValue};
use oauth2::{
    http, AuthType, ClientId, ClientSecret, HttpRequest, PkceCodeVerifier, RedirectUrl, Scope,
    TokenUrl,
};
use std::borrow::Cow;
use url::form_urlencoded;

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

#[allow(clippy::too_many_arguments)]
pub fn token_request<'a>(
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: &'a [(Cow<'a, str>, Cow<'a, str>)],
    redirect_url: Option<&'a RedirectUrl>,
    scopes: Option<&'a Vec<Cow<'a, Scope>>>,
    token_url: &'a TokenUrl,
    params: Vec<(&'a str, &'a str)>,
) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_FORMENCODED),
    );

    let scopes_opt = scopes.and_then(|scopes| {
        if !scopes.is_empty() {
            Some(
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            None
        }
    });

    let mut params: Vec<(&str, &str)> = params;
    if let Some(ref scopes) = scopes_opt {
        params.push(("scope", scopes));
    }

    // FIXME: add support for auth extensions? e.g., client_secret_jwt and private_key_jwt
    match auth_type {
        AuthType::RequestBody => {
            params.push(("client_id", client_id));
            if let Some(ref client_secret) = client_secret {
                params.push(("client_secret", client_secret.secret()));
            }
        }
        AuthType::BasicAuth => {
            // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
            // before using them as HTTP Basic auth username and password. Note that this is
            // not standard for ordinary Basic auth, so curl won't do it for us.
            let urlencoded_id: String =
                form_urlencoded::byte_serialize(&client_id.as_bytes()).collect();

            let urlencoded_secret = client_secret.map(|secret| {
                form_urlencoded::byte_serialize(secret.secret().as_bytes()).collect::<String>()
            });
            let b64_credential = base64::encode(&format!(
                "{}:{}",
                &urlencoded_id,
                urlencoded_secret
                    .as_ref()
                    .map(|secret| secret.as_str())
                    .unwrap_or("")
            ));
            headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
            );
        }
    }

    if let Some(ref redirect_url) = redirect_url {
        params.push(("redirect_uri", redirect_url.as_ref()));
    }

    params.extend_from_slice(
        extra_params
            .iter()
            .map(|&(ref k, ref v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    HttpRequest {
        url: token_url.url().to_owned(),
        method: http::method::Method::POST,
        headers,
        body,
    }
}

pub fn new_random_verifier(num_bytes: u32) -> PkceCodeVerifier {
    let random_bytes: Vec<u8> = (0..num_bytes)
        .map(|_| {
            let mut buf = [0u8; 1];
            getrandom::getrandom(&mut buf).unwrap();
            buf[0]
        })
        .collect();
    PkceCodeVerifier::new(base64::encode_config(
        &random_bytes,
        base64::URL_SAFE_NO_PAD,
    ))
}
