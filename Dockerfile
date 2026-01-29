FROM docker.io/library/golang:1.25.4-alpine3.21 AS builder-base

ENV GOOS=linux GOARCH=amd64

WORKDIR $GOPATH/src/github.com/dependabot/proxy

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG GIT_COMMIT=""
ENV INJECTED_VARS="-X github.com/dependabot/proxy/internal/version.GitCommit=${GIT_COMMIT}"

# ============================================================================
FROM builder-base AS builder-tests

# For testing, `go vet` and `-race` require `gcc`, whereas we don't need these in builder-prod:
RUN apk add --update --no-cache build-base

RUN go build -o $GOPATH/bin/dependabot-proxy -ldflags="-w ${INJECTED_VARS} -s"

# ============================================================================
FROM builder-base AS builder-prod

RUN apk add --update --no-cache gcc musl-dev upx && \
    go build -o $GOPATH/bin/dependabot-proxy -ldflags="-w ${INJECTED_VARS} -s" && \
    upx --best $GOPATH/bin/dependabot-proxy

# ============================================================================

FROM docker.io/library/alpine:3.22.2

LABEL org.opencontainers.image.source="https://github.com/dependabot/proxy"

RUN apk add --update --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

COPY --from=builder-prod /go/bin/dependabot-proxy /dependabot-proxy

ENTRYPOINT ["/dependabot-proxy"]
