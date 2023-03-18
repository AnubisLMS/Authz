IMAGE_NAME ?= registry.digitalocean.com/anubis/anubis-authz
PACKAGES=$(shell go list ./...)
SRCS = $(shell git ls-files '*.go' | grep -v '^vendor/')
GIT_TAG ?= $(shell git log -1 --pretty=%h)

export GIT_TAG
export IMAGE_VERSION ?= $(VERSION)
export CGO_ENABLED=off
export GO111MODULE=on

.PHONY: all bin/anubis-authz test image clean

default: bin/anubis-authz

all: image
	docker build .

fmt:
	gofmt -w $(SRCS)

build:
	docker build -t ${IMAGE_NAME}:${GIT_TAG} .
	docker tag ${IMAGE_NAME}:${GIT_TAG} ${IMAGE_NAME}:latest

push:
	docker push ${IMAGE_NAME}:${GIT_TAG}
	docker push ${IMAGE_NAME}:latest

deploy: build push

bin/anubis-authz:
	mkdir -p bin/
	go build -o bin/anubis-authz --ldflags "-X \"main.version=$(VERSION)\"" -a -installsuffix cgo main.go

test: bin/anubis-authz
	go test -v ${PACKAGES}

clean:
	rm -rf bin/ main
