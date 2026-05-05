# 19Health Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project from `xray-checker` to `19Health` everywhere (Go module, binary, branding, docs), publish prebuilt Docker images on ghcr.io, ship a `docker-compose.yml`, and rewrite the README with a self-contained installation tutorial.

**Architecture:** This is a refactor + asset swap + workflow change, not a feature. There are no unit tests in this codebase, so the verification strategy is: `go build ./...` after each compile-affecting change, `grep` sweeps for stale references, and a container smoke test (build → run → curl `/health`, `/`, `/metrics`) at the end.

**Tech Stack:** Go 1.25, Xray Core, Prometheus, Alpine.js, Tailwind CSS (precompiled), GitHub Actions, Docker (multi-arch via buildx), GoReleaser. macOS host for asset generation (`sips` + ImageMagick).

**Spec:** [docs/superpowers/specs/2026-05-05-19health-rebrand-design.md](../specs/2026-05-05-19health-rebrand-design.md)

---

## Conventions used by this plan

- Working directory: `/Users/david/Projects/Claude/19VPN/19Health` (the repo root). All paths are repo-relative unless prefixed with `~`.
- After every code-touching task, run `go build ./...` from the repo root to ensure the tree compiles before committing.
- Each task ends in a commit. Use the commit message shown in the step.
- If a step's verification fails, **stop** and surface the failure rather than masking it.

---

## Task 1: Verify Go module rename works (gated pre-flight)

**Why first:** Go modules with names beginning with a digit are technically legal but a few tools historically misbehave. We confirm `19health` works before doing anything else; if it fails, we fall back to `nineteenhealth`.

**Files:**
- Modify: `go.mod` (line 1)
- Modify: every `*.go` file (imports starting with `xray-checker/`)

- [ ] **Step 1: Make sure the working tree is clean**

```bash
git -C /Users/david/Projects/Claude/19VPN/19Health status --short
```
Expected output: empty (no modified files). If not empty, stash or commit existing changes first.

- [ ] **Step 2: Edit `go.mod` line 1**

Change:
```go
module xray-checker
```
to:
```go
module 19health
```

- [ ] **Step 3: Rewrite all imports across `.go` files**

Run from the repo root:
```bash
grep -rl '"xray-checker/' --include='*.go' . | xargs sed -i '' 's|"xray-checker/|"19health/|g'
```

(`-i ''` is the BSD-sed form on macOS. On Linux, use `-i` without the quoted argument.)

- [ ] **Step 4: Verify the import sweep is complete**

```bash
grep -rn '"xray-checker/' --include='*.go' .
```
Expected output: empty (no matches). If anything matches, fix it manually before continuing.

- [ ] **Step 5: Build**

```bash
go build ./...
```
Expected: exits 0 with no output.

If it fails with a module-name error like `malformed module path "19health": invalid char` or similar, the leading-digit fallback kicks in:
- Revert `go.mod` to `module nineteenhealth`
- Re-run the sed sweep replacing `"xray-checker/"` with `"nineteenhealth/"`
- Re-run `go build ./...`
- Update the spec to reflect the fallback name and continue using `nineteenhealth` everywhere downstream in this plan.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum **/*.go
git commit -m "refactor: rename Go module to 19health"
```

(If `go build` modified `go.sum`, it's already in the add. If it didn't, omit `go.sum` from the add list.)

---

## Task 2: Rebrand user-visible Go strings

**Files:**
- Modify: `main.go` (line 32)
- Modify: `config/config.go` (lines 15, 16, 83, 85)
- Modify: `subscription/parser.go` (lines 469, 473)

- [ ] **Step 1: Update startup log line in `main.go`**

In [main.go:32](main.go), change:
```go
logger.Startup("Xray Checker %s", version)
```
to:
```go
logger.Startup("19Health %s", version)
```

- [ ] **Step 2: Update kong config in `config/config.go`**

In [config/config.go:15-16](config/config.go), change:
```go
kong.Name("xray-checker"),
kong.Description("Xray Checker: A Prometheus exporter for monitoring Xray proxies"),
```
to:
```go
kong.Name("19health"),
kong.Description("19Health: A Prometheus exporter for monitoring Xray proxies"),
```

- [ ] **Step 3: Update version-print strings in `config/config.go`**

In [config/config.go:83-85](config/config.go), change:
```go
fmt.Println("Xray Checker: A Prometheus exporter for monitoring Xray proxies")
fmt.Printf("Version:\t %s\n", vars["version"])
fmt.Printf("GitHub: https://github.com/kutovoys/xray-checker\n")
```
to:
```go
fmt.Println("19Health: A Prometheus exporter for monitoring Xray proxies")
fmt.Printf("Version:\t %s\n", vars["version"])
fmt.Printf("GitHub: https://github.com/poaxy/19Health\n")
```

- [ ] **Step 4: Update User-Agent / device-model headers in `subscription/parser.go`**

In [subscription/parser.go:469](subscription/parser.go), change:
```go
req.Header.Set("User-Agent", "Xray-Checker")
```
to:
```go
req.Header.Set("User-Agent", "19Health")
```

In [subscription/parser.go:473](subscription/parser.go), change:
```go
req.Header.Set("X-Device-Model", "Xray-Checker Pro Max")
```
to:
```go
req.Header.Set("X-Device-Model", "19Health Pro Max")
```

**Risk note:** Some subscription providers whitelist specific User-Agents. If subscription updates start failing after this change, revert these two lines and accept that the User-Agent still says "Xray-Checker" for compatibility.

- [ ] **Step 5: Build and verify no other Go-level rebrand sites remain**

```bash
go build ./...
grep -rni 'xray.checker\|xray checker' --include='*.go' .
```
Expected: build exits 0; grep returns no matches.

- [ ] **Step 6: Commit**

```bash
git add main.go config/config.go subscription/parser.go
git commit -m "refactor: rebrand user-visible Go strings to 19Health"
```

---

## Task 3: Rebrand web templates and OpenAPI

**Files:**
- Modify: `web/templates/index.html` (lines 11, 27, 526; drop upstream Docs button at ~711-734; rebrand footer at 967-1006)
- Modify: `web/openapi.yaml` (line 3)
- Modify: `web/api.go` (line 339)
- Modify: `web/static/site.webmanifest` (lines 2-3)

- [ ] **Step 1: Update page title in `web/templates/index.html`**

In [web/templates/index.html:9-12](web/templates/index.html), change:
```html
<title>
  {{ if and .IsPublic .SubscriptionName }}{{ .SubscriptionName }}{{ else
  }}Xray Checker{{ end }}
</title>
```
to:
```html
<title>
  {{ if and .IsPublic .SubscriptionName }}{{ .SubscriptionName }}{{ else
  }}19Health{{ end }}
</title>
```

- [ ] **Step 2: Update apple-mobile-web-app-title meta tag**

In [web/templates/index.html:27](web/templates/index.html), change:
```html
<meta name="apple-mobile-web-app-title" content="Xray Checker" />
```
to:
```html
<meta name="apple-mobile-web-app-title" content="19Health" />
```

- [ ] **Step 3: Update header brand h1**

In [web/templates/index.html:524-527](web/templates/index.html), change:
```html
<h1 class="text-base font-semibold text-primary">
  {{ if and .IsPublic .SubscriptionName }}{{ .SubscriptionName }}{{
  else }}Xray Checker{{ end }}
</h1>
```
to:
```html
<h1 class="text-base font-semibold text-primary">
  {{ if and .IsPublic .SubscriptionName }}{{ .SubscriptionName }}{{
  else }}19Health{{ end }}
</h1>
```

- [ ] **Step 4: Drop the upstream Docs button**

In [web/templates/index.html](web/templates/index.html), find the `<a href="https://xray-checker.kutovoy.dev"...>Docs</a>` block (starts around line 711, ends around line 734 with `</a>`). Delete the entire `<a>...</a>` block including the surrounding whitespace.

A quick way to locate the exact range:
```bash
grep -n 'xray-checker.kutovoy.dev' web/templates/index.html
```

Open the file, navigate to that line, find the enclosing `<a` opening tag (a few lines above) and the matching `</a>` (a few lines below), and delete everything in between, inclusive of both tags.

- [ ] **Step 5: Rebrand the footer (public mode)**

In [web/templates/index.html](web/templates/index.html), find the footer block. The "Powered by" public-mode block (around lines 971-980) currently reads:
```html
{{ if .IsPublic }}
<div>
  Powered by
  <a
    href="https://github.com/kutovoys/xray-checker"
    target="_blank"
    class="hover:text-secondary"
    >Xray Checker</a
  >
</div>
```
Replace with:
```html
{{ if .IsPublic }}
<div>
  Powered by
  <a
    href="https://github.com/poaxy/19Health"
    target="_blank"
    class="hover:text-secondary"
    >19Health</a
  >
</div>
```

- [ ] **Step 6: Rebrand the footer (non-public mode) and drop Telegram + "Made with ❤️"**

In [web/templates/index.html](web/templates/index.html), the non-public footer block (around lines 981-1006) currently reads:
```html
{{ else }}
<div>
  <a
    href="https://github.com/kutovoys/xray-checker"
    target="_blank"
    class="hover:text-secondary"
    >GitHub</a
  >
  <span class="mx-2">·</span>
  <a
    href="https://t.me/+Ux5gQhAY8KA2OTdi"
    target="_blank"
    class="hover:text-secondary"
    >Telegram Chat</a
  >
</div>
<div class="mt-2">
  Made with ❤️ by
  <a
    href="https://github.com/kutovoys"
    target="_blank"
    class="hover:text-secondary"
    >kutovoys</a
  >
</div>
{{ end }}
```
Replace with:
```html
{{ else }}
<div>
  <a
    href="https://github.com/poaxy/19Health"
    target="_blank"
    class="hover:text-secondary"
    >GitHub</a
  >
</div>
{{ end }}
```

(Telegram link and the "Made with ❤️" credit line are both dropped.)

- [ ] **Step 7: Update OpenAPI title**

In [web/openapi.yaml:3](web/openapi.yaml), change:
```yaml
  title: Xray Checker API
```
to:
```yaml
  title: 19Health API
```

- [ ] **Step 8: Update Swagger UI HTML title in `web/api.go`**

In [web/api.go:339](web/api.go), change:
```html
<title>Xray Checker API</title>
```
to:
```html
<title>19Health API</title>
```

- [ ] **Step 9: Update site.webmanifest**

Replace the contents of [web/static/site.webmanifest](web/static/site.webmanifest) with:
```json
{
  "name": "19Health",
  "short_name": "19Health",
  "icons": [
    {
      "src": "./static/web-app-manifest-192x192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "./static/web-app-manifest-512x512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "maskable"
    }
  ],
  "theme_color": "#000000",
  "background_color": "#000000",
  "display": "standalone"
}
```

(Theme/background colors changed from white to black to match the icon's dark background.)

- [ ] **Step 10: Build + grep to verify**

```bash
go build ./...
grep -rni 'xray.checker\|xray checker' --include='*.go' --include='*.html' --include='*.yaml' --include='*.json' --include='*.webmanifest' . | grep -v '^./docs/superpowers/'
```
Expected: build succeeds; grep returns matches **only** in `.goreleaser.yaml`, `.github/workflows/`, `Dockerfile`, `README.md`, `README_RU.md` (handled in later tasks). No matches in `web/`, `*.go` files, or `site.webmanifest`.

- [ ] **Step 11: Commit**

```bash
git add web/templates/index.html web/openapi.yaml web/api.go web/static/site.webmanifest
git commit -m "refactor: rebrand web templates, OpenAPI, and webmanifest to 19Health"
```

---

## Task 4: Generate icon assets from source

**Files:**
- Source: `branding/icon-source.png` (already in repo, JPEG-encoded despite `.png` extension, 2752×1536)
- Create: `branding/icon-1536.png` (1536×1536 center-crop, true PNG)
- Replace: `web/static/favicon-96x96.png`
- Replace: `web/static/apple-touch-icon.png`
- Replace: `web/static/web-app-manifest-192x192.png`
- Replace: `web/static/web-app-manifest-512x512.png`
- Replace: `web/static/favicon.ico`
- Replace: `web/static/favicon.svg`
- Replace: `web/static/logo-light.svg`
- Replace: `web/static/logo-dark.svg`

Tools: `sips` (built-in macOS) handles cropping/resizing/PNG conversion. `.ico` generation needs ImageMagick — installed via Homebrew if not present.

- [ ] **Step 1: Install ImageMagick if missing**

```bash
command -v magick || brew install imagemagick
```

- [ ] **Step 2: Center-crop the source to 1536×1536 (true PNG)**

The source is 2752×1536 (landscape with black padding). Center-crop the central 1536-wide square:
```bash
cd /Users/david/Projects/Claude/19VPN/19Health
sips -s format png branding/icon-source.png --out branding/icon-temp.png
sips -c 1536 1536 branding/icon-temp.png --out branding/icon-1536.png
rm branding/icon-temp.png
```

Verify:
```bash
file branding/icon-1536.png
```
Expected: `PNG image data, 1536 x 1536, ...`

- [ ] **Step 3: Generate raster sizes**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
sips -z 96 96 branding/icon-1536.png --out web/static/favicon-96x96.png
sips -z 180 180 branding/icon-1536.png --out web/static/apple-touch-icon.png
sips -z 192 192 branding/icon-1536.png --out web/static/web-app-manifest-192x192.png
sips -z 512 512 branding/icon-1536.png --out web/static/web-app-manifest-512x512.png
```

(`sips -z` resizes preserving aspect ratio; since the source is already square here, the result is exact.)

Verify:
```bash
for f in web/static/favicon-96x96.png web/static/apple-touch-icon.png web/static/web-app-manifest-192x192.png web/static/web-app-manifest-512x512.png; do
  echo "$f: $(file "$f" | grep -oE '[0-9]+ x [0-9]+')"
done
```
Expected: `96 x 96`, `180 x 180`, `192 x 192`, `512 x 512` respectively.

- [ ] **Step 4: Generate multi-size `favicon.ico`**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
magick branding/icon-1536.png -define icon:auto-resize=16,32,48 web/static/favicon.ico
```

Verify:
```bash
file web/static/favicon.ico
```
Expected: `MS Windows icon resource - 3 icons, ...`

- [ ] **Step 5: Wrap PNG in SVG for `favicon.svg`, `logo-light.svg`, `logo-dark.svg`**

The HTML template references SVGs by name. Rather than rewriting the template, embed the PNG inside an SVG wrapper so existing `<img src="...svg">` references keep working.

Generate the wrapper:
```bash
cd /Users/david/Projects/Claude/19VPN/19Health
B64=$(base64 < web/static/web-app-manifest-512x512.png | tr -d '\n')
SVG="<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 512 512\"><image href=\"data:image/png;base64,${B64}\" width=\"512\" height=\"512\"/></svg>"
printf '%s' "$SVG" > web/static/favicon.svg
printf '%s' "$SVG" > web/static/logo-light.svg
printf '%s' "$SVG" > web/static/logo-dark.svg
```

Verify:
```bash
head -c 200 web/static/favicon.svg
```
Expected: starts with `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><image href="data:image/png;base64,iVBORw0KGgo...`.

- [ ] **Step 6: Commit**

```bash
git add branding/icon-1536.png web/static/favicon-96x96.png web/static/apple-touch-icon.png web/static/web-app-manifest-192x192.png web/static/web-app-manifest-512x512.png web/static/favicon.ico web/static/favicon.svg web/static/logo-light.svg web/static/logo-dark.svg
git commit -m "feat: replace icon and logo assets with 19Health branding"
```

---

## Task 5: Update Dockerfile

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Replace the Dockerfile contents**

Open [Dockerfile](Dockerfile) and replace its full contents with:
```dockerfile
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG GIT_TAG
ARG GIT_COMMIT
ARG USERNAME=poaxy
ARG REPOSITORY_NAME=19Health

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

ARG USERNAME=poaxy
ARG REPOSITORY_NAME=19Health

LABEL org.opencontainers.image.source=https://github.com/${USERNAME}/${REPOSITORY_NAME}

RUN apk add --no-cache ca-certificates curl tzdata && \
    adduser -D -u 1000 appuser && \
    mkdir -p /app/geo && \
    chown -R appuser:appuser /app

WORKDIR /app
COPY --from=builder /usr/bin/19health /usr/bin/19health

USER appuser

ENTRYPOINT ["/usr/bin/19health"]
```

- [ ] **Step 2: Verify the Dockerfile builds locally**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
docker build -t 19health-local:dev .
```
Expected: build succeeds, ends with `naming to docker.io/library/19health-local:dev`.

If `upx` errors out for any reason on certain architectures, that's existing upstream behavior — try a clean rebuild with `--no-cache`. If it still fails, mention it in the commit message and skip the Docker smoke test until later.

- [ ] **Step 3: Smoke-test the local container**

```bash
docker run --rm -d --name 19health-test -p 2112:2112 -e SUBSCRIPTION_URL='https://example.invalid/sub' 19health-local:dev || true
sleep 2
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2112/health
docker stop 19health-test 2>/dev/null
```
Expected: `curl` prints `200`.

(The container will fail to fetch the dummy subscription, which is fine — `/health` doesn't depend on subs.)

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "build: rebrand Dockerfile to 19Health, build binary as /usr/bin/19health"
```

---

## Task 6: Update `.goreleaser.yaml`

**Files:**
- Modify: `.goreleaser.yaml` (lines 14, 30)

- [ ] **Step 1: Edit binary name and archive id**

In [.goreleaser.yaml:14](.goreleaser.yaml), change:
```yaml
    binary: xray-checker
```
to:
```yaml
    binary: 19health
```

In [.goreleaser.yaml:30](.goreleaser.yaml), change:
```yaml
  - id: xray-checker
```
to:
```yaml
  - id: 19health
```

- [ ] **Step 2: Verify**

```bash
grep -ni 'xray-checker\|xray checker' .goreleaser.yaml
```
Expected: no matches.

- [ ] **Step 3: Commit**

```bash
git add .goreleaser.yaml
git commit -m "build: rebrand goreleaser binary and archive id to 19health"
```

---

## Task 7: Convert build-publish workflow to ghcr.io

**Files:**
- Replace: `.github/workflows/build-publish.yml`
- Delete: `.github/workflows/dockerhub-description.yml`

- [ ] **Step 1: Replace `build-publish.yml`**

Open [.github/workflows/build-publish.yml](.github/workflows/build-publish.yml) and replace its full contents with:
```yaml
name: Build and publish container image

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:

permissions:
  contents: read
  packages: write

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Compute image tags
        id: tags
        run: |
          OWNER_LC=$(echo "${{ github.repository_owner }}" | tr '[:upper:]' '[:lower:]')
          IMAGE="ghcr.io/${OWNER_LC}/19health"
          if [ "${{ github.event_name }}" = "push" ]; then
            REF_NAME="${{ github.ref_name }}"
            echo "tags=${IMAGE}:latest,${IMAGE}:${REF_NAME}" >> "$GITHUB_OUTPUT"
            echo "version=${REF_NAME}" >> "$GITHUB_OUTPUT"
          else
            echo "tags=${IMAGE}:latest" >> "$GITHUB_OUTPUT"
            echo "version=manual" >> "$GITHUB_OUTPUT"
          fi
          echo "image=${IMAGE}" >> "$GITHUB_OUTPUT"

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          build-args: |
            GIT_TAG=${{ steps.tags.outputs.version }}
            GIT_COMMIT=${{ github.sha }}
            USERNAME=${{ github.repository_owner }}
            REPOSITORY_NAME=${{ github.event.repository.name }}
          tags: ${{ steps.tags.outputs.tags }}
          labels: |
            org.opencontainers.image.source=https://github.com/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.version=${{ steps.tags.outputs.version }}
            org.opencontainers.image.licenses=MIT
```

Notes on this rewrite:
- Auth uses the built-in `${{ secrets.GITHUB_TOKEN }}`. No additional secrets to configure.
- Image owner is forced to lowercase via `tr` because GHCR rejects uppercase package names (the user is `poaxy` which is already lowercase, but this guards against future renames).
- A `workflow_dispatch` trigger lets you publish on demand without a tag.
- OCI labels are added so the package page shows source/revision/version/license.

- [ ] **Step 2: Delete `dockerhub-description.yml`**

```bash
git rm .github/workflows/dockerhub-description.yml
```

- [ ] **Step 3: YAML lint**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build-publish.yml'))" && echo "OK"
```
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build-publish.yml
git commit -m "ci: publish container images to ghcr.io instead of Docker Hub"
```

(`git rm` already staged the deletion in Step 2; if you wrote the deletion that way it's part of this commit.)

**Manual one-time follow-up (after first successful workflow run):** Visit https://github.com/users/poaxy/packages/container/19health/settings and flip "Package visibility" from Private to Public. The README will document this.

---

## Task 8: Add `docker-compose.yml` and `.env.example`

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`

- [ ] **Step 1: Create `docker-compose.yml` at the repo root**

Write [docker-compose.yml](docker-compose.yml) with:
```yaml
services:
  19health:
    image: ghcr.io/poaxy/19health:latest
    container_name: 19health
    restart: unless-stopped
    ports:
      - "2112:2112"
    env_file:
      - .env
    volumes:
      - ./geo:/app/geo
```

(`env_file: .env` lets users put their config in a separate file. The `geo` volume persists `geoip.dat` and `geosite.dat` across restarts so they aren't re-downloaded each time.)

- [ ] **Step 2: Create `.env.example` at the repo root**

Write [.env.example](.env.example) with:
```dotenv
# 19Health configuration. Copy this file to `.env` and fill in your values.
# All variables are optional except SUBSCRIPTION_URL.

# --- Subscriptions ---
# URL of your proxy subscription (base64, JSON, or share-link list).
# For multiple subscriptions, separate with commas: URL1,URL2,URL3
SUBSCRIPTION_URL=

# Re-fetch subscriptions periodically (default: true).
# SUBSCRIPTION_UPDATE=true

# Subscription update interval, seconds (default: 300).
# SUBSCRIPTION_UPDATE_INTERVAL=300

# --- Proxy checks ---
# Check interval per proxy, seconds (default: 300).
# PROXY_CHECK_INTERVAL=300

# Check method: ip | status | download (default: ip).
# PROXY_CHECK_METHOD=ip

# IP-check service URL (default: https://api.ipify.org?format=text).
# PROXY_IP_CHECK_URL=

# Status-generator URL for status method (default: http://cp.cloudflare.com/generate_204).
# PROXY_STATUS_CHECK_URL=

# Download-test URL for download method (default: https://proof.ovh.net/files/1Mb.dat).
# PROXY_DOWNLOAD_URL=

# Download timeout, seconds (default: 60).
# PROXY_DOWNLOAD_TIMEOUT=60

# Minimum bytes for a successful download check (default: 51200).
# PROXY_DOWNLOAD_MIN_SIZE=51200

# IP-check timeout, seconds (default: 30).
# PROXY_TIMEOUT=30

# Resolve proxy domains into IPs and expand into per-IP configs (default: false).
# PROXY_RESOLVE_DOMAINS=false

# --- Xray ---
# Starting port for per-proxy local Xray inbounds (default: 10000).
# XRAY_START_PORT=10000

# Xray log level: debug | info | warning | error | none (default: none).
# XRAY_LOG_LEVEL=none

# --- Metrics / web server ---
# Listen host (default: 0.0.0.0).
# METRICS_HOST=0.0.0.0

# Listen port (default: 2112).
# METRICS_PORT=2112

# Require basic auth for /metrics, /api, and /config (default: false).
# METRICS_PROTECTED=false

# Basic-auth credentials (used only if METRICS_PROTECTED=true).
# METRICS_USERNAME=metricsUser
# METRICS_PASSWORD=changeMe

# Instance label attached to Prometheus metrics (default: empty).
# METRICS_INSTANCE=

# Optional Pushgateway URL: https://user:pass@host:port
# METRICS_PUSH_URL=

# URL prefix for /metrics (default: empty).
# METRICS_BASE_PATH=

# --- Web UI ---
# Show server IPs/ports on the dashboard (default: false).
# WEB_SHOW_DETAILS=false

# Make the dashboard public (requires METRICS_PROTECTED=true) (default: false).
# WEB_PUBLIC=false

# Path to a directory of custom assets (logo.svg, favicon.ico, custom.css, index.html).
# WEB_CUSTOM_ASSETS_PATH=

# --- Misc ---
# Run a single check cycle and exit (default: false).
# RUN_ONCE=false

# Application log level: debug | info | warn | error | none (default: info).
# LOG_LEVEL=info
```

- [ ] **Step 3: Verify the compose file is valid**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
docker compose -f docker-compose.yml config > /dev/null && echo "OK"
```
Expected: `OK`.

(Docker may complain that `.env` doesn't exist; that's fine, `env_file` is only loaded at run time.)

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "feat: add docker-compose.yml and .env.example"
```

---

## Task 9: Rewrite `README.md`

**Files:**
- Replace: `README.md`
- Delete: `README_RU.md`

- [ ] **Step 1: Replace `README.md` with new content**

Write [README.md](README.md) with:
````markdown
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

3. Start it:

   ```bash
   docker compose up -d
   ```

4. Check it:

   ```bash
   docker compose logs -f
   curl -s http://localhost:2112/health   # should print {"status":"ok"}
   ```

5. Stop / update:

   ```bash
   docker compose down            # stop
   docker compose pull            # pull new image
   docker compose up -d           # restart on new image
   ```

The compose file mounts `./geo` as a volume so geoip/geosite files persist across restarts.

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
| `METRICS_PASSWORD` | `MetricsVeryHardPassword` | Basic-auth password (when protected) |
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
````

- [ ] **Step 2: Delete `README_RU.md`**

```bash
git rm README_RU.md
```

- [ ] **Step 3: Verify**

```bash
grep -ni 'xray.checker\|xray checker' README.md
```
Expected: matches only the two intentional attribution mentions of `kutovoys/xray-checker` in the intro paragraph and the License & attribution section.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for 19Health with docker-compose tutorial"
```

---

## Task 10: Delete the upstream Astro docs site

**Files (all deletions):**
- `docs/README.md`
- `docs/astro.config.mjs`
- `docs/package.json`
- `docs/package-lock.json`
- `docs/pnpm-lock.yaml`
- `docs/public/`
- `docs/src/`
- `docs/tsconfig.json`

**Keep:** `docs/superpowers/` (this plan and the spec live there).

- [ ] **Step 1: Delete the Astro site files**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
git rm -r docs/README.md docs/astro.config.mjs docs/package.json docs/package-lock.json docs/pnpm-lock.yaml docs/public docs/src docs/tsconfig.json
```

- [ ] **Step 2: Verify `docs/superpowers/` survived**

```bash
ls docs/
```
Expected: only `superpowers` listed.

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: remove upstream Astro docs site"
```

---

## Task 11: Update `CONTRIBUTING.md`, `SECURITY.md`, and remove screenshot

**Files:**
- Modify: `CONTRIBUTING.md` (only if it mentions Xray Checker)
- Modify: `SECURITY.md` (only if it mentions Xray Checker)
- Delete: `.github/screen/xray-checker.webp` (and any other files in that folder)

- [ ] **Step 1: Find branding mentions**

```bash
grep -ni 'xray.checker\|xray checker' CONTRIBUTING.md SECURITY.md
```

- [ ] **Step 2: Edit each match**

For each match the previous grep returned, open the file and replace `Xray Checker` with `19Health` (preserving capitalization conventions). If a match is a URL like `kutovoys/xray-checker`, replace with `poaxy/19Health`. If a match is a contact email tied to the upstream maintainer, replace with a contact appropriate for poaxy or remove it.

- [ ] **Step 3: Delete the screenshot**

```bash
git rm -r .github/screen
```

- [ ] **Step 4: Verify**

```bash
grep -rni 'xray.checker\|xray checker' . --exclude-dir=.git --exclude-dir=docs/superpowers --exclude-dir=node_modules
```
Expected: matches only in `LICENSE` (do not touch — license attribution) and the two intentional `kutovoys/xray-checker` references in `README.md`.

- [ ] **Step 5: Commit**

```bash
git add CONTRIBUTING.md SECURITY.md
git commit -m "docs: rebrand CONTRIBUTING/SECURITY mentions and drop upstream screenshot"
```

(If `CONTRIBUTING.md` and `SECURITY.md` had no matches in Step 1, skip the `git add` for those files; the commit will still cover the screenshot deletion staged via `git rm` in Step 3.)

---

## Task 12: Final smoke test

**Files:** none modified — verification only.

- [ ] **Step 1: Build the binary natively**

```bash
cd /Users/david/Projects/Claude/19VPN/19Health
go build -o 19health-smoketest .
./19health-smoketest --version
```
Expected: prints `19Health: A Prometheus exporter for monitoring Xray proxies`, a version line, and `GitHub: https://github.com/poaxy/19Health`. Exit 0.

- [ ] **Step 2: Build the container**

```bash
docker build -t 19health-local:smoketest .
```
Expected: build succeeds.

- [ ] **Step 3: Run the container and hit the endpoints**

```bash
docker run --rm -d --name 19health-smoketest -p 2112:2112 -e SUBSCRIPTION_URL='https://example.invalid/sub' 19health-local:smoketest
sleep 3
curl -s -o /dev/null -w 'health: %{http_code}\n' http://127.0.0.1:2112/health
curl -s http://127.0.0.1:2112/ | grep -o '<title>[^<]*</title>'
docker stop 19health-smoketest
```
Expected:
- `health: 200`
- `<title>19Health</title>` (with leading/trailing whitespace; the grep strips it)

- [ ] **Step 4: Final repo-wide grep**

```bash
grep -rni 'xray.checker\|xray checker\|kutovoys' . --exclude-dir=.git --exclude-dir=docs/superpowers --exclude-dir=node_modules
```
Expected: matches **only** in `README.md` (the two intentional attribution lines) and possibly `LICENSE`. No matches in any other file.

If anything else matches, open it and decide whether to rebrand or leave. Stale upstream URLs (e.g. `kutovoys/xray-checker` GitHub URLs in code or templates) should be replaced with `poaxy/19Health`.

- [ ] **Step 5: Clean up local artifacts**

```bash
rm -f 19health-smoketest
docker image rm 19health-local:dev 19health-local:smoketest 2>/dev/null || true
```

- [ ] **Step 6: Final commit (if smoke test required any fixes)**

If Step 4 found additional matches and you fixed them:
```bash
git add -u
git commit -m "chore: clean up final stray xray-checker / kutovoys references"
```

If everything was already clean, no commit is needed for this task.

---

## Done state

- `19health` Go binary builds and runs.
- Container builds locally and serves a rebranded UI on port 2112.
- `git log` since the rebrand started shows ~10-12 focused commits.
- No `xray-checker` or `kutovoys` references remain outside the intentional attribution lines in `README.md` and the `LICENSE` file.
- A tag push (`git tag v0.0.1 && git push origin v0.0.1`) will trigger the `build-publish.yml` workflow and produce `ghcr.io/poaxy/19health:v0.0.1` plus `ghcr.io/poaxy/19health:latest`. The first such run will publish a private package; flip it to public via the GitHub UI as documented in the README.
