# BUILD IMAGE --------------------------------------------------------
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

# Get build tools and required header files
RUN apk add --no-cache build-base

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build the final server binary
ARG GIT_COMMIT=unknown
ARG XMTP_GO_CLIENT_VERSION=unknown
RUN go build \
    -o bin/notifications-server \
    -ldflags="-X 'main.GitCommit=$GIT_COMMIT' -X 'main.XMTPGoClientVersion=$XMTP_GO_CLIENT_VERSION'" \
    ./cmd/server

# ACTUAL IMAGE -------------------------------------------------------

FROM alpine:3@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL maintainer="engineering@xmtp.com"
LABEL source="https://github.com/xmtp/example-notification-server-go"
LABEL description="XMTP Example Notification Server"

# color, nocolor, json
ENV GOLOG_LOG_FMT=nocolor
# Raw-processing paths use fixed-message recover boundaries. GOTRACEBACK is a
# defense-in-depth control for unrecoverable runtime faults: it suppresses
# argument-bearing goroutine stacks but is not itself the panic-value scrubber.
ENV GOTRACEBACK=none

# go-waku default port
EXPOSE 8080

RUN apk add --no-cache ca-certificates su-exec \
    && addgroup -S -g 10001 bridge \
    && adduser -S -D -H -u 10001 -G bridge bridge \
    && mkdir -p /var/lib/notifications-server/a9 \
    && chown bridge:bridge /var/lib/notifications-server/a9 \
    && chmod 0700 /var/lib/notifications-server/a9

COPY --from=builder --chown=bridge:bridge /app/bin/notifications-server /usr/bin/
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/bridge-entrypoint

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/bridge-entrypoint"]
# By default just show help if called without arguments
CMD ["--help"]
