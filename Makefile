.PHONY: release build-image image deploy-envoy clean

FILTER_NAME=authn_filter
FILTER_TAG=v0.1
IMAGE ?= webassemblyhub.io/thesisworker/$(FILTER_TAG):$(FILTER_TAG)

release:
	cargo build --target wasm32-unknown-unknown --release

build-image:
	wasme build precompiled target/wasm32-unknown-unknown/release/$(FILTER_NAME).wasm --tag $(IMAGE)

build-release-image: release build-image

deploy-envoy:
	wasme deploy envoy $(IMAGE) --envoy-image=istio/proxyv2:1.5.1 --bootstrap=envoy-bootstrap.yml

push-image:
	wasme push $(IMAGE)

clean:
	cargo clean
