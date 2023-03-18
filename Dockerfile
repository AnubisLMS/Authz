ARG GOLANG_VERSION="1.20"

FROM golang:${GOLANG_VERSION}-alpine AS build

ENV GO111MODULE=on
WORKDIR /build

COPY go.mod ./
COPY go.sum ./
RUN set -eux; \
    go mod download; \
    apk add --no-cache --purge --upgrade make

COPY . .
RUN make bin/anubis-authz

FROM alpine

# Indicates basic authorization is enforced
ARG AUTHORIZER=anubis
# Indicates basic auditor type is used (log to console)
ARG AUDITOR=basic
# Indicates audit logs are streamed to STDOUT
ARG AUDITOR_HOOK=""

ENV AUTHORIZER=${AUTHORIZER}
ENV AUDITOR=${AUDITOR}
ENV AUDITOR_HOOK=${AUDITOR_HOOK}

COPY authz/policy-anubis.yaml /var/lib/anubis/policy.yaml
VOLUME /run/docker/plugins/

COPY --from=build /build/bin/anubis-authz /usr/bin/anubis-authz
RUN adduser -D -u 1001 anubis 

USER anubis
ENTRYPOINT ["/usr/bin/anubis-authz"]
CMD ["--policy", "/var/lib/anubis/policy.yaml"]
