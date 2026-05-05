# 19Health

19Health is a Prometheus-friendly proxy availability monitor for VLESS, VMess, Trojan, and Shadowsocks proxies. It connects to your proxies through Xray Core, runs periodic health checks, and exposes the results as Prometheus metrics, a web dashboard, and a REST API.

This project is a fork of [kutovoys/xray-checker](https://github.com/kutovoys/xray-checker), rebranded and maintained as 19Health.

## Features

- Monitor VLESS, VMess, Trojan, and Shadowsocks proxies through Xray Core
- Automatic configuration updates from one or more subscriptions
- Three check methods: IP-change verification, HTTP-status, or download throughput
- Prometheus `/metrics` endpoint, with optional Pushgateway support
- REST API with OpenAPI/Swagger docs
- Web dashboard (dark/light themes), with optional public status-page mode
- Endpoints for integration with Uptime Kuma and other monitoring systems
- Automatic geoip/geosite file management
- Optional basic-auth protection
- Multi-arch container images (`linux/amd64`, `linux/arm64`)

## Quick start (Docker)

```bash
docker run -d \
  --name 19health \
  --restart unless-stopped \
  -e SUBSCRIPTION_URL='https://your-subscription-url/sub' \
  -p 2112:2112 \
  ghcr.io/poaxy/19health:latest
```

Then open <http://localhost:2112> for the dashboard, <http://localhost:2112/metrics> for Prometheus metrics, and <http://localhost:2112/api/v1/docs> for the API docs.

## Docker Compose (recommended)

A ready-to-use `docker-compose.yml` is included in this repository.

1. Clone (or download) the repo:

   ```bash
   git clone https://github.com/poaxy/19Health.git
   cd 19Health
   ```

2. Copy the example env file and fill in your subscription URL:

   ```bash
   cp .env.example .env
   $EDITOR .env   # set SUBSCRIPTION_URL=...
   ```

3. Pre-create the geo volume directory with the right ownership (the container runs as UID 1000, so a fresh host directory created by Docker as root will not be writable):

   ```bash
   mkdir -p ./geo
   sudo chown 1000:1000 ./geo
   ```

   Alternatively, edit `docker-compose.yml` to use a Docker named volume instead of the bind mount:

   ```yaml
       volumes:
         - geo:/app/geo
   volumes:
     geo:
   ```

4. Start it:

   ```bash
   docker compose up -d
   ```

5. Check it:

   ```bash
   docker compose logs -f
   curl -s http://localhost:2112/health   # should print {"status":"ok"}
   ```

6. Stop / update:

   ```bash
   docker compose down            # stop
   docker compose pull            # pull new image
   docker compose up -d           # restart on new image
   ```

## Installation alternatives

### Prebuilt binary

Download a release tarball from <https://github.com/poaxy/19Health/releases>, extract it, and run:

```bash
SUBSCRIPTION_URL='https://your-subscription-url/sub' ./19health
```

### From source

Requires Go 1.25+:

```bash
git clone https://github.com/poaxy/19Health.git
cd 19Health
go build -o 19health .
SUBSCRIPTION_URL='https://your-subscription-url/sub' ./19health
```

## Configuration

Common environment variables (full list in [`.env.example`](.env.example)):

| Variable | Default | Purpose |
|---|---|---|
| `SUBSCRIPTION_URL` | *(required)* | Subscription URL (or comma-separated list of URLs) |
| `PROXY_CHECK_INTERVAL` | `300` | Seconds between proxy checks |
| `PROXY_CHECK_METHOD` | `ip` | `ip`, `status`, or `download` |
| `METRICS_PORT` | `2112` | Listen port |
| `METRICS_PROTECTED` | `false` | Require basic auth on `/metrics` and `/api` |
| `METRICS_USERNAME` | `metricsUser` | Basic-auth user (when protected) |
| `METRICS_PASSWORD` | `MetricsVeryHardPassword` | Basic-auth password (when protected — change this!) |
| `WEB_PUBLIC` | `false` | Public status page (requires `METRICS_PROTECTED=true`) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`, or `none` |

CLI flags are also accepted; run `19health --help` for the full list.

## Endpoints

| Path | Purpose |
|---|---|
| `/` | Web dashboard |
| `/health` | Liveness probe — returns 200 when the server is up |
| `/metrics` | Prometheus metrics (basic-auth-gated when `METRICS_PROTECTED=true`) |
| `/api/v1/proxies` | List of proxies with status |
| `/api/v1/public/proxies` | Public-safe proxy list (no IPs/ports) |
| `/api/v1/docs` | Swagger UI |
| `/api/v1/openapi.yaml` | OpenAPI spec |
| `/config/<id>` | Per-proxy detail page |

## Container image visibility

The first time the publish workflow runs on a fresh `poaxy/19Health` repo, the resulting `ghcr.io/poaxy/19health` package will be **private**. To make it public (so users can `docker pull` without authenticating), visit:

<https://github.com/users/poaxy/packages/container/19health/settings>

and switch "Package visibility" to **Public**. This is a one-time step.

## License & attribution

Distributed under the terms of the upstream project's [LICENSE](LICENSE) file. 19Health is a fork of [kutovoys/xray-checker](https://github.com/kutovoys/xray-checker); thanks to the original author and contributors.
