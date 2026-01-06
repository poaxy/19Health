FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG GIT_TAG
ARG GIT_COMMIT
ARG USERNAME=remnawave
ARG REPOSITORY_NAME=19health

ENV CGO_ENABLED=0
ENV GO111MODULE=on

# Install UPX for binary compression
RUN apk add --no-cache upx

WORKDIR /go/src/github.com/${USERNAME}/${REPOSITORY_NAME}

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags="-s -w -X main.version=${GIT_TAG} -X main.commit=${GIT_COMMIT}" -a -installsuffix cgo -o /usr/bin/19health . && \
  upx --best --lzma /usr/bin/19health

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
