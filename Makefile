.PHONY: help build build-image build-base push-image

DEFAULT_GOAL: help

VERSION ?= $(shell grep "^version:" wai-middleware-auth.cabal | cut -d " " -f14)
IMAGE_NAME := fpco/wai-auth

dinamo:
	@echo ${VERSION}

## Build stack project (natively)
build:
	@stack build

## Builds base image
build-base:
	@docker build -t fpco/wai-auth-base-image -f Dockerfile.base .

## Build docker image (builds project in a container first)
build-image: build-base
	@stack --stack-yaml stack-docker.yaml build
	@stack --stack-yaml stack-docker.yaml image container
	@docker tag ${IMAGE_NAME} ${IMAGE_NAME}:${VERSION}

## Push docker image
push-image:
	@echo docker push ${IMAGE_NAME}:${VERSION}
	@echo docker push ${IMAGE_NAME}

## Show help screen.
help:
	@echo "Please use \`make <target>' where <target> is one of\n\n"
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "%-30s %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

