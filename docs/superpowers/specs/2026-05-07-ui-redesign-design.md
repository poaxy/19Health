# 19Health UI Redesign — Design Spec

**Status:** Draft
**Date:** 2026-05-07
**Branch:** `claude/epic-newton-ecd022`

## Goal

Replace the current dashboard with a more visually distinctive, more informative single page that reads like Uptime Kuma at a glance: per-server uptime bars, a 24-hour latency sparkline, and quick-scan stats. Keep the existing single-page architecture (Go templates + Alpine.js + Tailwind, no SPA framework).

## Non-goals

- No persistence layer. History is in-memory only and resets on restart.
- No per-server detail page or drawer. The card is the whole story.
- No multi-day timespan switcher. 24h is the only window.
- No certificate-expiry tracking, recent-events log, or notification system.
- No changes to the metrics, health, or REST API endpoints (only UI buttons removed).
- Badge-mode embed (`?badge=...`) is unchanged.

## Visual design

Palette (dark theme — light theme mirrors with same accent):

| Token | Value | Use |
|---|---|---|
| `--bg-primary` | `#0d1421` | Page background |
| `--bg-card` | `#161e2e` | Card surface |
| `--bg-card-elevated` | `#11192a` | Footer / nested surfaces |
| `--border` | `#243049` | All borders |
| `--text-primary` | `#e8eef7` | Headings, server names |
| `--text-secondary` | `#b8c2d4` | Strip values, body text |
| `--text-muted` | `#6b7790` | Labels, footer |
| `--accent` | `#f0b429` | Brand, latency, sparkline, active states |
| `--accent-hover` | `#d49317` | Hover variant |
| `--ok` | `#22c55e` | Online status, healthy heartbeat cells |
| `--warn` | `#f0b429` | Degraded heartbeat cells (latency over threshold) |
| `--bad` | `#ef4444` | Offline status, failed heartbeat cells |
| `--link` | `#4a8cd6` | Inline links |

Layout shell: `min-h-screen flex flex-col`, main content `flex-1`, footer `mt-auto`. The footer is always pinned to the bottom of the viewport, regardless of how few servers are rendered.

Per-card composition (top to bottom):

1. **Top row:** status dot · server name · current latency (right-aligned, accent color)
2. **Meta line:** 24h uptime % · `· 24h ·` · last incident phrase (`last incident 2h ago` / `no incidents` / `down for 4h 12m`)
3. **Heartbeat bar:** ~60 cells, 14px tall, 1px gaps, full card width
4. **Sparkline:** SVG polyline + soft amber gradient fill, ~80 points, 32px tall
5. **Footer strip:** `min · avg · max` latency over the 24h window, separated by a top border

Removed from the current UI:

- Top stats row (Total / Online / Offline / Avg latency cards)
- Metrics, Health, API buttons in the header
- Per-card Copy URL button
- Protocol pill on cards (no `vless`/`vmess`/`trojan`/`ss` badge)

Retained from the current UI:

- Auto-refresh toggle with countdown
- Dark/light theme toggle
- Search input
- Status filter (All / Online / Offline)
- Sort control
- Public mode (anonymized — server name only, no host/port)
- Basic-auth gate
- Badge-mode embed (`?badge=...`) — pixel-identical to today

## Data model

### History store

A new package `history` provides a per-proxy ring buffer of check results.

```go
package history

type Sample struct {
    Timestamp time.Time
    Online    bool
    LatencyMs int64
}

type Store struct {
    // keyed by proxy.StableID
    // ring buffers sized to hold WindowHours * 3600s / CheckIntervalSec
}

func NewStore(windowHours int, checkIntervalSec int) *Store
func (s *Store) Append(stableID string, sample Sample)
func (s *Store) Snapshot(stableID string, now time.Time) Snapshot
func (s *Store) Drop(stableID string) // for proxy churn
```

`Snapshot` is the read-side view consumed by the API:

```go
type Snapshot struct {
    Heartbeats     []Bucket // length == BucketCount (~60)
    Sparkline      []int64  // length == SparklinePoints (~80), median latency ms per bucket
    Uptime24h      float64  // 0.0..100.0
    LastIncidentAt *time.Time
    DownSince      *time.Time // set if currently offline; nil otherwise
    LatencyMin     int64
    LatencyAvg     int64
    LatencyMax     int64
}

type Bucket struct {
    State     BucketState // ok | degraded | down | empty
    LatencyMs int64       // median; 0 if empty/down
}
```

### Bucketing rule

Each bucket spans `WindowHours * 3600 / BucketCount` seconds (default: 24h / 60 buckets = 24min per bucket). For each bucket:

- `down` if any sample in the bucket has `Online == false`
- `degraded` if all samples online but median latency > `DegradedLatencyMs`
- `ok` if all samples online and median latency ≤ threshold
- `empty` if no samples in the bucket (e.g., right after startup)

Sparkline points are computed by re-bucketing into `SparklinePoints` (default 80) using median latency per slot. Empty slots render as gaps in the polyline.

### Integration with the checker

In `checker.checkProxyInternal`, after the existing `pc.currentMetrics.Store(metricKey, status)` + `pc.latencyMetrics.Store(metricKey, latency)` calls, also call `pc.history.Append(proxy.StableID, history.Sample{...})`. The history store is constructed in `main.go` alongside the checker and passed in.

On `pc.UpdateProxies(newProxies)` (subscription refresh), proxies that no longer exist must be dropped via `s.Drop(stableID)` to avoid leaking buffers.

## API contract

The existing endpoints stay; only response shapes grow. New fields are additive — existing consumers still parse.

### `GET /api/v1/proxies` (authenticated)

Adds to `ProxyInfo`:

```jsonc
{
  "stableId": "...",
  "name": "...",
  // ... existing fields ...
  "history": {
    "uptime24h": 99.6,
    "lastIncidentAt": "2026-05-07T08:14:00Z",  // ISO; null if no incidents in window
    "downSince": null,                          // set if currently offline
    "latencyMin": 48,
    "latencyAvg": 62,
    "latencyMax": 140,
    "heartbeats": [
      {"state": "ok", "latencyMs": 62},
      {"state": "degraded", "latencyMs": 240},
      {"state": "down", "latencyMs": 0},
      {"state": "empty", "latencyMs": 0}
      // ... 60 entries total
    ],
    "sparkline": [62, 58, 64, 0, 72, ...]      // 80 ints, 0 means empty
  }
}
```

### `GET /api/v1/public/proxies` (no auth)

Same `history` block, but the parent object stays anonymized (no `server`, `port`, `protocol`, `proxyPort`).

### `GET /api/v1/status`

No change. Continues to return aggregate `total/online/offline/avgLatencyMs`. The frontend stops *displaying* this in the redesigned UI but the endpoint is preserved (Uptime Kuma–style health checks may consume it).

### Other endpoints

`/metrics`, `/health`, `/api/v1/system/*`, `/api/v1/config`, `/api/v1/proxies/{stableID}` — unchanged.

## Frontend changes

`web/templates/index.html` (1240 lines today) is rewritten end-to-end:

- New CSS variables for the amber palette; existing dark/light blocks replaced.
- Stats grid removed; the markup that was `<div x-show="showStats" class="grid grid-cols-4 ...">` is deleted along with the `stats` Alpine state.
- Header simplified: brand block + version pill + auto-refresh button + theme toggle. The Metrics/Health/API anchors are deleted.
- Server card markup replaced with the rich layout above. Heartbeats render via `<template x-for="cell in proxy.history.heartbeats">`; sparkline via a single SVG `<polyline>` plus a `<polygon>` fill driven by `proxy.history.sparkline`.
- Per-card copy button deleted; `copyUrl()` JS function deleted.
- Page shell wrapped with `min-h-screen flex flex-col` so the footer pins to the bottom (`mt-auto` on the footer).
- The Alpine `dashboard()` function loses `stats`, `copyUrl`, and gains a small helper `formatIncident(snapshot)` that turns `lastIncidentAt`/`downSince` into the human phrase shown in the meta line.

Public mode and badge mode require minimal additional changes — public mode hides the same fields it always hid (server, port); badge mode never read history and continues to render the inline pill.

## Configuration

Two new env vars (also exposed as Kong CLI flags):

| Name | Default | Purpose |
|---|---|---|
| `HISTORY_WINDOW_HOURS` | `24` | Total time covered by heartbeat bar and sparkline |
| `DEGRADED_LATENCY_MS` | `500` | Latency above which a healthy bucket is marked degraded (amber) |

Bucket counts are not user-configurable. They are constants in the `history` package: `BucketCount = 60`, `SparklinePoints = 80`. Reasoning: changing these would require frontend layout adjustments and offers no real user value.

Memory budget at defaults: with 5-minute checks (the current default `PROXY_CHECK_INTERVAL=300`), the buffer holds 288 samples per proxy ≈ 7 KB. At 50 proxies that's ~350 KB. Negligible.

## Error handling

- **Empty history (cold start):** `Snapshot` returns all-`empty` buckets, `uptime24h: 0`, `lastIncidentAt: null`, `latencyMin/Avg/Max: 0`. Frontend displays a fully grey heartbeat bar and a flat sparkline; meta line shows `— · gathering data` until the first non-empty bucket exists.
- **Currently offline proxy:** `downSince` is set; meta line shows `down for Xh Ym` instead of `last incident X ago`. Latency text shows `offline` in `--bad` color.
- **Sparkline gap rendering:** the SVG polyline is split at empty buckets — the gradient fill drops to baseline so the gap is visually obvious.
- **Subscription refresh adds/removes proxies:** new proxies start with empty history (cold-start behavior). Removed proxies have their buffers freed via `Drop`.
- **Concurrent reads/writes:** `history.Store` uses a `sync.RWMutex`. The check loop holds a write lock briefly per Append; API handlers hold a read lock during Snapshot. Snapshot returns by value (no shared references), so handlers can release the lock immediately.

## Testing strategy

- `history` package: standard table-driven Go tests covering `Append`, ring rollover, `Snapshot` with mixed states, threshold logic, empty buckets, time-window edge cases. Aim for high coverage — this is the only new piece of pure logic.
- `checker` integration: extend the existing checker tests (or add one if absent) to assert that a check result is appended to history.
- API: assert the `history` JSON block is present on both authenticated and public endpoints, and that public mode does not leak server/port/protocol fields.
- Frontend: no automated tests today. Manual verification checklist covering the eight scenarios in the spec (full-history online, fully-online cold-start, currently-offline, recently-recovered, mixed-degraded, public mode, badge mode unchanged, light theme).

## Rollout

The change is a single PR off `main`. The image tag bump that ships it (whatever the next version is — likely `v0.1.0` since it's a meaningful UX change) goes through the existing GHCR publish workflow without modification. Users on `:latest` get it next `docker compose pull`. No env vars are *required* — defaults work for everyone.

## Open trade-offs accepted

- **History is volatile.** A container restart loses 24h of data. We considered SQLite under `/data` but rejected it as scope creep for a personal-deployment fork. Acceptable because most users would not notice a restart-induced reset within their normal check cadence.
- **No detail view.** Some power users may want a per-server detail page (cert expiry, raw history). Explicitly out of scope; revisit only if user demand surfaces.
- **No protocol indication.** A user with mixed VLESS / VMess / Trojan / Shadowsocks subscriptions will not see protocol on the card. The user accepts this; they know their own deployment.
- **`/metrics`, `/health`, `/api/v1/*` routes orphaned from UI.** Discoverability drops. Acceptable: the user does not personally use the UI buttons, and the routes remain documented in the README and OpenAPI spec.
