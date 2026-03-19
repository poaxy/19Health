# 19Health

19Health is a tool for monitoring proxy server availability with support for VLESS, VMess, Trojan, and Shadowsocks protocols. It automatically tests connections through Xray Core and provides metrics for Prometheus, as well as API endpoints for integration with monitoring systems.

<div align="center">
  <img src=".github/screen/xray-checker.webp" alt="Dashboard Screenshot">
</div>

## 🚀 Key Features

- 🔍 Monitoring of Xray proxy servers (VLESS, VMess, Trojan, Shadowsocks)
- 🔄 Automatic configuration updates from subscription (multiple subscriptions supported)
- 📊 Prometheus metrics export with Pushgateway support
- 🌐 REST API with OpenAPI/Swagger documentation
- 🌓 Web interface with dark/light theme
- 📥 Endpoints for monitoring system integration (Uptime Kuma, etc.)
- 🔒 Basic Auth protection for metrics and web interface
- 🐳 Docker and Docker Compose support
- 🌍 Automatic geo files management (geoip.dat, geosite.dat)
- 📝 Flexible configuration loading:
  - URL subscriptions (base64, JSON)
  - Share links (vless://, vmess://, trojan://, ss://)
  - JSON configuration files
  - Folders with configurations

Full list of features available in the documentation.

## 🚀 Quick Start

### Docker

```bash
docker run -d \
  -e SUBSCRIPTION_URL=https://your-subscription-url/sub \
  -p 2112:2112 \
  remnawave/19health
```

### Podman

```bash
podman run -d \
  -e SUBSCRIPTION_URL=https://your-subscription-url/sub \
  -p 2112:2112 \
  docker.io/remnawave/19health
```

### Docker Compose

```yaml
services:
  19health:
    image: remnawave/19health
    environment:
      - SUBSCRIPTION_URL=https://your-subscription-url/sub
    ports:
      - "2112:2112"
```

Detailed installation and configuration documentation is available in the docs directory.

## Container Build Notes (Docker + Podman)

- The project image is built from a single `Dockerfile` that works with both engines.
- Build arguments `TARGETOS` and `TARGETARCH` are optional; if omitted, the build uses the builder image defaults.
- Binary compression is optional and disabled by default for best compatibility.

Build with Docker:

```bash
docker build -t remnawave/19health:local .
```

Build with Podman:

```bash
podman build -t remnawave/19health:local .
```

Enable UPX compression explicitly (optional):

```bash
podman build --build-arg ENABLE_UPX=true -t remnawave/19health:local .
```

### Podman Troubleshooting

- Warnings like `can't raise ambient capability ... operation not permitted` are common in rootless/restricted environments and usually do not indicate a build failure by themselves.
- If build appears to hang at `go mod download`, your host likely has limited access to Go module mirrors.

Try:

```bash
podman build \
  --build-arg GOPROXY=https://proxy.golang.org,direct \
  --build-arg GOSUMDB=sum.golang.org \
  -t remnawave/19health:local .
```

If your network blocks public Go mirrors, set an internal proxy:

```bash
podman build \
  --build-arg GOPROXY=https://your-internal-go-proxy,direct \
  --build-arg GOSUMDB=off \
  -t remnawave/19health:local .
```

## 🤝 Contributing

We welcome any contributions to 19Health! If you want to help:

1. Fork the repository
2. Create a branch for your changes
3. Make and test your changes
4. Create a Pull Request

For more details on how to contribute, read the contributor's guide in the docs directory.
