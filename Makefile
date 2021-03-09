.PHONY: release build-image image deploy-envoy

FILTER_NAME=authn_filter

release:
	cargo build --target wasm32-unknown-unknown --release

build-image:
	wasme build precompiled target/wasm32-unknown-unknown/release/$(FILTER_NAME).wasm --tag $(FILTER_NAME):v0.1

build-release-image: release build-image

deploy-envoy:
	wasme deploy envoy $(FILTER_NAME):v0.1 --envoy-image=istio/proxyv2:1.5.1 --bootstrap=envoy-bootstrap.yml

push-image:
	wasme tag $(FILTER_NAME):v0.1 webassemblyhub.io/sonhal/$(FILTER_NAME):v0.1
	wasme push webassemblyhub.io/sonhal/$(FILTER_NAME):v0.1