# OpenID Connect WASM Filter

An [Envoy](https://www.envoyproxy.io/) proxy extension that handles end-user authentication using 
[OpenID Connect(OIDC)](https://openid.net/connect/). Only Authorization code flow is supported.

### Extension overview
The extension is written in Rust and the compile target is `wasm32-wasi`. The filter is written against the [WebAssembly for Proxies (ABI specification)
](https://github.com/proxy-wasm/spec). Tested with envoy:v1.17. 


### Usage

#### Configuration
The filter can be configured through. Note that some of the fields are optional with default values.

| Field  | Type | Default | Description |
| ------------- | ------------- | --- | --- |
| redirect_uri  | String  | /callback | URL the authorization server redirects the end-user back to after authentication. |
| cookie_name  | String  | oidcSession | Cookie name that holds the session cookie for the user. |
| auth_cluster  | String  | auth_server_cluster | Envoy cluster that the filter will use to issue token request to the authorization server |
| auth_url  | String  | N/A | The URL that unauthenticated end-users will be redirected to |
| token_url  | String  | N/A | The URL that the filter will issue token requests against |
| client_id  | String  | N/A | OAuth 2.0 / OIDC client ID |
| client_secret  | String  | N/A | OAuth 2.0 / OIDC client secret |
| extra_params | list[[String, String]]  | [] | Extra query parameters the filter will add to the authorization redirect to the authorization server. |


