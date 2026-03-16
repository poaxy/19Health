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

### Docker (use published image)

```bash
docker run -d \
  -e SUBSCRIPTION_URL=https://your-subscription-url/sub \
  -p 2112:2112 \
  remnawave/19health
```

### Docker Compose (use published image)

```yaml
services:
  19health:
    image: remnawave/19health
    environment:
      - SUBSCRIPTION_URL=https://your-subscription-url/sub
    ports:
      - "2112:2112"
```

### Docker Compose (build from source)

This repository includes a `docker-compose.yml` that builds the image from the local source tree using the provided `Dockerfile`:

```bash
docker compose up --build
```

You can override configuration with environment variables, for example:

```bash
SUBSCRIPTION_URL=https://your-subscription-url/sub docker compose up --build
```

Detailed installation and configuration documentation is available in the docs directory.

## 🤝 Contributing

We welcome any contributions to 19Health! If you want to help:

1. Fork the repository
2. Create a branch for your changes
3. Make and test your changes
4. Create a Pull Request

For more details on how to contribute, read the contributor's guide in the docs directory.
