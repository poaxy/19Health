# 19Health Rebrand & Docker Publish — Design

**Date:** 2026-05-05
**Author:** poaxy (assisted by Claude)
**Repo:** [poaxy/19Health](https://github.com/poaxy/19Health)

## Goal

Rebrand the upstream `kutovoys/xray-checker` fork to **19Health**, rewrite the README, ship a `docker-compose.yml`, and publish prebuilt Docker images to GitHub Container Registry so users don't have to build from source.

## Non-goals

- No changes to runtime behavior, API surface, metric names, or default port.
- No translation of the README into other languages.
- No custom docs site (using the README only).
- No rename of the runtime config file `xray_config.json` — it is literally an Xray Core config and the name is descriptive.

## Naming canon

| Context | Value |
|---|---|
| Display name | `19Health` |
| Go module path | `19health` |
| Binary name | `19health` |
| CLI env var prefix | `19HEALTH_*` (replaces `XRAY_CHECKER_*`) |
| Docker image | `ghcr.io/poaxy/19health` |
| Container name (compose default) | `19health` |
| Runtime Xray config file | `xray_config.json` (unchanged) |

**Pre-flight check:** Go modules whose first path segment starts with a digit are legal per the spec, but a few tools have historically had issues. The first implementation step is `go build` after the rename — if it fails, fall back to `nineteenhealth`. This is the only branching point in the plan.

## File-by-file changes

### Code (Go)

| File | Change |
|---|---|
| `go.mod` | `module xray-checker` → `module 19health` |
| All `*.go` files | Update imports: `xray-checker/<pkg>` → `19health/<pkg>` |
| `main.go` | `logger.Startup("Xray Checker %s", version)` → `19Health` |
| `config/config.go` | Update kong env-var prefix from `XRAY_CHECKER_` to `19HEALTH_`; update CLI help text and any version-print string referencing "Xray Checker" |
| Other Go source | Replace any user-facing strings or comments mentioning "Xray Checker" / "xray-checker" branding; leave references to "xray" the protocol/binary alone |

Implementation order: edit `go.mod` first, then a single `find` + `sed` pass to rewrite all imports, then `go build` to verify. Manual edits for the user-visible strings caught by `grep -ri 'xray.checker\|xray checker' --include='*.go'`.

### Web templates / static / OpenAPI

| File | Change |
|---|---|
| `web/templates/index.html` | `<title>`, header brand text, `Powered by Xray Checker` footer → `19Health` |
| `web/openapi.yaml` | API title, description, contact info |
| `web/static/site.webmanifest` | `name`, `short_name`, theme colors if branded |
| `web/static/favicon.ico` | Regenerated from icon source (16/32/48 multi-size) |
| `web/static/favicon.svg` | Replaced with SVG wrapper embedding the new PNG |
| `web/static/favicon-96x96.png` | Regenerated at 96×96 |
| `web/static/apple-touch-icon.png` | Regenerated at 180×180 |
| `web/static/web-app-manifest-192x192.png` | Regenerated at 192×192 |
| `web/static/web-app-manifest-512x512.png` | Regenerated at 512×512 |
| `web/static/logo-light.svg` | Replaced with SVG wrapper embedding the new PNG |
| `web/static/logo-dark.svg` | Replaced with SVG wrapper embedding the new PNG |

Light and dark logos use the same artwork (icon has a dark background with a gold accent that reads on both themes).

### Icon generation pipeline

Source: `branding/icon-source.png` (already copied into the repo, originally `/Users/david/Pictures/Icon Black.png` — JPEG-encoded despite the `.png` extension, 2752×1536).

Steps (using `sips` for cropping/resizing on macOS, or `ImageMagick` if installed; both are listed because either works):

1. **Center-crop to square**: take the central 1536×1536 region, save as `branding/icon-1536.png` (re-encoded to true PNG).
2. **Generate raster sizes** with `sips -Z` or `magick convert`:
   - 96, 180, 192, 512 PNG outputs.
3. **Generate `.ico`**: requires `ImageMagick`; if unavailable, install or use a one-off `png2ico`-style tool. Multi-size: 16, 32, 48.
4. **Wrap PNG in SVG** for `favicon.svg`, `logo-light.svg`, `logo-dark.svg`. The SVG file embeds the PNG (base64-encoded) so existing `<img src="...svg">` references in the template don't have to change.

Source PNG (`branding/icon-source.png`) and the cropped intermediate (`branding/icon-1536.png`) are kept in `branding/` for future regeneration.

### Build / release

| File | Change |
|---|---|
| `Dockerfile` | `xray-checker` → `19health` in `WORKDIR`, `go build -o`, `COPY`, `ENTRYPOINT`. `ARG USERNAME=kutovoys` → `poaxy`. `ARG REPOSITORY_NAME=xray-checker` → `19Health`. |
| `.goreleaser.yaml` | `binary: xray-checker` → `19health`. Archive `id` and `name_template` to use new project name. |
| `.github/workflows/build-publish.yml` | Switch from Docker Hub → ghcr.io. Use `${{ secrets.GITHUB_TOKEN }}` for auth (no extra secrets). Image tags: `ghcr.io/poaxy/19health:latest`, `ghcr.io/poaxy/19health:${{ github.ref_name }}`. Add `workflow_dispatch` trigger for manual publishes. Add OCI labels (`org.opencontainers.image.source`, `.version`, `.revision`, `.licenses`). |
| `.github/workflows/dockerhub-description.yml` | **Delete** — Docker Hub no longer used. |
| `.github/workflows/release.yaml` | Keep as-is (already uses `GITHUB_TOKEN` + goreleaser for GitHub Releases). |

After the first successful workflow run, the user must visit GitHub → Profile → Packages → `19health` → Package settings, and flip visibility to **Public**. README will document this one-time step.

### Docs / metadata / cleanup

| File / Dir | Change |
|---|---|
| `README.md` | Rewrite from scratch (structure below). |
| `README_RU.md` | Delete. |
| `docs/` (Astro docs site) | Delete site files only: `docs/README.md`, `docs/astro.config.mjs`, `docs/package.json`, `docs/package-lock.json`, `docs/pnpm-lock.yaml`, `docs/public/`, `docs/src/`, `docs/tsconfig.json`. **Keep** `docs/superpowers/` (this spec lives there). |
| `.github/screen/` | Delete `xray-checker.webp` (and any other upstream screenshots). New screenshot to be added later when one exists. |
| `CODE_OF_CONDUCT.md` | Leave as-is (generic Contributor Covenant). |
| `CONTRIBUTING.md` | Replace any "Xray Checker" mentions with "19Health". |
| `SECURITY.md` | Replace any "Xray Checker" mentions; verify report email/URL is reasonable. |
| `LICENSE` | **Keep upstream's existing license file as-is** — fork's source-license obligation. |

### New file: `docker-compose.yml` (repo root)

```yaml
services:
  19health:
    image: ghcr.io/poaxy/19health:latest
    container_name: 19health
    restart: unless-stopped
    ports:
      - "2112:2112"
    environment:
      SUBSCRIPTION_URL: https://your-subscription-url/sub
      # METRICS_USERNAME: admin
      # METRICS_PASSWORD: changeme
      # PROXY_CHECK_INTERVAL: 60
    volumes:
      - ./geo:/app/geo
```

### New file: `.env.example` (repo root)

Documents every supported env var (extracted from `config/config.go`) with sensible defaults and one-line descriptions. Referenced from the README.

### README structure

```
# 19Health

[One paragraph: 19Health is a Prometheus-friendly proxy availability monitor
supporting VLESS, VMess, Trojan, and Shadowsocks. Originally forked from
kutovoys/xray-checker, rebranded and maintained as 19Health.]

## Features
[bullet list, no badges]

## Quick start (Docker)
docker run -d \
  -e SUBSCRIPTION_URL=https://your-sub-url/sub \
  -p 2112:2112 \
  ghcr.io/poaxy/19health:latest

## Docker Compose
[full docker-compose.yml example referencing the file in this repo]

## Installation
- Docker (recommended)
- Binary release (download from GitHub Releases, run with flags/env vars)
- From source (git clone, go build)

## Configuration
[table of common env vars, link to .env.example for full list]

## Endpoints
[brief list: /, /metrics, /health, /api/v1/*, /api/v1/docs]

## License & attribution
[reference upstream license + acknowledgement that this is a fork of
kutovoys/xray-checker]
```

## Implementation order

The plan will sequence these as discrete, independently-verifiable steps:

1. Verify Go module rename works → `go.mod` rename + import sweep + `go build` smoke test.
2. Rebrand env-var prefix and user-visible strings in Go code.
3. Rebrand web templates + OpenAPI spec.
4. Generate icon assets + replace static files.
5. Update `Dockerfile` and `.goreleaser.yaml`.
6. Convert `build-publish.yml` to ghcr.io; delete `dockerhub-description.yml`.
7. Add `docker-compose.yml` and `.env.example`.
8. Rewrite `README.md`; delete `README_RU.md`.
9. Delete upstream `docs/` Astro site (preserving `docs/superpowers/`).
10. Update `CONTRIBUTING.md` / `SECURITY.md` mentions; delete `.github/screen/`.
11. Final `go build` + run smoke test (start binary, hit `/health`, hit `/`).

## Verification

- `go build ./...` succeeds.
- Container builds locally: `docker build -t 19health-local .`
- Container runs and serves: `docker run --rm -p 2112:2112 19health-local` → `curl :2112/health` returns 200, `curl :2112/` returns rebranded HTML.
- `grep -rni 'xray.checker\|xray checker' .` returns no results outside of `LICENSE`, the upstream-attribution paragraph in `README.md`, and any code paths that legitimately reference Xray Core's protocol artifacts.
- ghcr.io workflow can be triggered via `workflow_dispatch` once merged.

## Risks

- **Module name with leading digit**: covered by the pre-flight check above. Fallback name reserved.
- **Icon SVG wrapping**: embedding a PNG inside an SVG works, but quality at very large display sizes is bounded by the source resolution (1536×1536 is plenty for current uses).
- **First ghcr.io publish requires manual visibility flip**: documented in README; not a code risk but a setup step the user has to do once.

## Out of scope (re-confirmed)

- Translations.
- A custom docs site beyond the README.
- New dashboard screenshot (will be added later).
- Renaming `xray_config.json`.
