# OpenID Connect WASM Filter

An [Envoy](https://www.envoyproxy.io/) proxy extension that handles end-user authentication using 
[OpenID Connect(OIDC)](https://openid.net/connect/). Only Authorization code flow is supported.

## Deployment
Filter builds are hosted on [WebAssemblyHub](https://webassemblyhub.io/repositories/576/authn_filter)

## Extension overview
The extension is written in Rust and the compile target is `wasm32-wasi`. The filter is written against the [WebAssembly for Proxies (ABI specification)
](https://github.com/proxy-wasm/spec). Tested with envoy:v1.17. 


## Extension Paths
The extension will handle request to these paths differently and applications should not use the same paths.

| Path | Description |
| ------------- | --- |
| /callback  |  path on the proxy the authorization server redirects the end-user back to after authentication. |
| /start  | Starts a OpenID Connect Authorization flow |
| /sign_out  | Clears the session with the extension, does not clear the session with the IdP |


## Usage

### Configuration
The filter can be configured through. Note that some fields are optional with default values.

| Field  | Type | Default | Description |
| ------------- | ------------- | --- | --- |
| redirect_uri  | String  | /callback | URL the authorization server redirects the end-user back to after authentication |
| cookie_name  | String  | oidcSession | Cookie name that holds the session cookie for the user |
| scopes  | list[String]  | ["openid"] | Scopes the filter will request from the authorization server |
| auth_cluster  | String  | auth_server_cluster | Envoy cluster that the filter will use to issue token request to the authorization server |
| auth_url  | String  | **Required** | The URL that unauthenticated end-users will be redirected to. |
| token_url  | String  | **Required** | The URL that the filter will issue token requests against |
| client_id  | String  | **Required** | OAuth 2.0 / OIDC client ID |
| client_secret  | String  | **Required** | OAuth 2.0 / OIDC client secret |
| extra_params | list[[String, String]]  | [] | Extra query parameters the filter will add to the authorization redirect to the authorization server |

### Upstream Request Headers
The filter will add the received tokens from the authorization server to request headers. *Upstream* application will 
receive request with tokens in the following request headers. **NOTE:** Upstream applications are responsible for 
validation of the received tokens.

| Header  | Token | Description |
| ------------- | ------------- | --- |
| Authorization | Access token | The access token from the successful authoriziation flow will be added by the filter to request in the Authorization header. The token will be added as a `bearer` token |
| X-Forwarded-ID-Token | id token | The ID token, if returned from the authorization server, will be added as a value to the `X-Forwarded-ID-Token` header |
