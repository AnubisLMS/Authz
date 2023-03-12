IMAGE_NAME ?= registry.digitalocean.com/anubis/authz-broker
PACKAGES=$(shell go list ./...)
export VERSION ?= v1.0.0
export IMAGE_VERSION ?= $(VERSION)
export CGO_ENABLED=off
export GO111MODULE=on

.PHONY: all bin/authz-broker test image clean

default: bin/authz-broker

all: image
	docker build .

fmt:
	gofmt -w $(SRCS)

image: bin/authz-broker test
	docker build -t ${IMAGE_NAME}:${IMAGE_VERSION} .

bin/authz-broker:
	mkdir -p bin/
	go build -o bin/authz-broker --ldflags "-X \"main.version=$(VERSION)\"" -a -installsuffix cgo main.go

test: bin/authz-broker
	go test -v ${PACKAGES}

clean:
	rm -rf bin/
