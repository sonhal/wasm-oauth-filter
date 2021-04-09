# OpenID Connect WASM Filter

An [Envoy](https://www.envoyproxy.io/) proxy extension that handles end-user authentication using 
[OpenID Connect(OIDC)](https://openid.net/connect/). Only Authorization code flow is supported.

### Extension overview
The extension is written in Rust and the compile target is `wasm32-wasi`. The filter is written against the [WebAssembly for Proxies (ABI specification)
](https://github.com/proxy-wasm/spec).


### Usage
//TODO