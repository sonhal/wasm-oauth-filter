.PHONY: release build-image image deploy-envoy clean

FILTER_NAME=authn_filter
FILTER_TAG=v0.1
IMAGE ?= webassemblyhub.io/thesisworker/$(FILTER_NAME):$(FILTER_TAG)

release:
	cargo wasi build --release

build-image:
	wasme build precompiled target/wasm32-wasi/release/$(FILTER_NAME).wasm --tag $(IMAGE)

build-release-image: release build-image

deploy-envoy:
	wasme deploy envoy $(IMAGE) --envoy-image=envoyproxy/envoy:v1.17-latest  --bootstrap=envoy-bootstrap-new.yml

push-image:
	wasme push $(IMAGE)

wasme-login:
	wasme login -u $(WASME_USERNAME) -p $(WASME_PASSWORD)

clean:
	cargo clean
