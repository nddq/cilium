# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= docker.io/cilium
ACN_REGISTRIES ?= acnpublic.azurecr.io/cilium
# quay.io is not enabled, see https://github.com/cilium/image-tools/issues/11
# REGISTRIES ?= docker.io/cilium quay.io/cilium

PUSH ?= false
TEST ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

PLATFORMS=linux/amd64,linux/arm64
RUNTIME_IMAGE=quay.io/cilium/cilium-runtime
ACN_RUNTIME_IMAGE=acnpublic.azurecr.io/cilium/cilium-runtime-distroless
RUNTIME_DIRECTORY?=images/runtime
DISTROLESS_RUNTIME_DIRECTORY?=images/distroless/runtime


## ACN Recipes

distroless-runtime-image: .buildx_builder
	TEST=$(TEST) ROOT_CONTEXT=true scripts/build-image.sh cilium-runtime-distroless $(DISTROLESS_RUNTIME_DIRECTORY) $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(ACN_REGISTRIES)

update-distroless-runtime-image:
	distroless/scripts/update-cilium-runtime-image.sh $(ACN_RUNTIME_IMAGE) $(DISTROLESS_RUNTIME_DIRECTORY)

distroless-builder-image: .buildx_builder
	TEST=$(TEST) ROOT_CONTEXT=true scripts/build-image.sh cilium-builder-distroless images/distroless/builder $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(ACN_REGISTRIES)

update-distroless-builder-image:
	distroless/scripts/update-cilium-builder-image.sh

## Upstream Recipes

all-images: lint runtime-image builder-image cilium-image operator-image hubble-relay-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --platform $(PLATFORMS) --buildkitd-flags '--debug' > $@

runtime-image: .buildx_builder
	TEST=true scripts/build-image.sh cilium-runtime-dev $(RUNTIME_DIRECTORY) $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

update-runtime-image:
	scripts/update-cilium-runtime-image.sh $(RUNTIME_IMAGE) $(RUNTIME_DIRECTORY)

check-runtime-image:
	CHECK=true scripts/update-cilium-runtime-image.sh $(RUNTIME_IMAGE) $(RUNTIME_DIRECTORY)

builder-image: .buildx_builder
	TEST=true scripts/build-image.sh cilium-builder-dev images/builder $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

update-builder-image:
	scripts/update-cilium-builder-image.sh

check-builder-image:
	CHECK=true scripts/update-cilium-builder-image.sh

cilium-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh cilium-dev images/cilium $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

operator-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh operator-dev images/operator $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

hubble-relay-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh hubble-relay-dev images/hubble-relay $(PLATFORMS) $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

update-envoy-image:
	scripts/update-cilium-envoy-image.sh

check-envoy-image:
	scripts/check-cilium-envoy-image.sh

