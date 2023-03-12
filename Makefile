IMAGE_NAME ?= registry.digitalocean.com/anubis/anubis-authz
PACKAGES=$(shell go list ./...)

export VERSION ?= v1.0.0
export IMAGE_VERSION ?= $(VERSION)
export CGO_ENABLED=off
export GO111MODULE=on

.PHONY: all bin/anubis-authz test image clean

default: bin/anubis-authz

all: image
	docker build .

fmt:
	gofmt -w $(SRCS)

image: bin/anubis-authz test
	docker build -t ${IMAGE_NAME}:${IMAGE_VERSION} .

bin/anubis-authz:
	mkdir -p bin/
	go build -o bin/anubis-authz --ldflags "-X \"main.version=$(VERSION)\"" -a -installsuffix cgo main.go

test: bin/anubis-authz
	go test -v ${PACKAGES}

clean:
	rm -rf bin/
