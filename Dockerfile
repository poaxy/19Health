FROM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GIT_TAG=unknown
ARG GIT_COMMIT=unknown
ARG USERNAME=remnawave
ARG REPOSITORY_NAME=19health
ARG ENABLE_UPX=false
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=sum.golang.org

ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}

# Install UPX for binary compression
RUN apk add --no-cache upx

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum
RUN set -eux; \
  go mod download; \
  go mod verify

COPY . .

RUN set -eux; \
  goos="${TARGETOS:-$(go env GOOS)}"; \
  goarch="${TARGETARCH:-$(go env GOARCH)}"; \
  git_tag="${GIT_TAG:-unknown}"; \
  git_commit="${GIT_COMMIT:-unknown}"; \
  CGO_ENABLED="${CGO_ENABLED}" GOOS="${goos}" GOARCH="${goarch}" \
  go build -ldflags="-s -w -X main.version=${git_tag} -X main.commit=${git_commit}" -a -installsuffix cgo -o /usr/bin/19health .; \
  if [ "${ENABLE_UPX}" = "true" ]; then \
    upx --best --lzma /usr/bin/19health; \
  fi

FROM alpine:3.21

ARG USERNAME=remnawave
ARG REPOSITORY_NAME=19health

LABEL org.opencontainers.image.source=https://github.com/${USERNAME}/${REPOSITORY_NAME}

RUN apk add --no-cache ca-certificates curl tzdata && \
    adduser -D -u 1000 appuser && \
    mkdir -p /app/geo && \
    chown -R appuser:appuser /app

WORKDIR /app
COPY --from=builder /usr/bin/19health /usr/bin/19health

USER appuser

ENTRYPOINT ["/usr/bin/19health"]
