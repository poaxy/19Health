# UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 19Health dashboard with an Uptime Kuma-style single page: per-server 24h heartbeat bars, latency sparklines, and rich cards in a deep-blue + amber palette. Adds an in-memory 24h history store; no persistence, no detail view, no API breakage.

**Architecture:** New Go package `history` provides a per-proxy ring of check samples. `ProxyChecker` appends a sample after every check and drops buffers when proxies are removed by subscription refresh. Existing API endpoints grow a `history` block in their JSON; the frontend (Go template + Alpine.js + Tailwind) is rewritten to consume it.

**Tech Stack:** Go 1.25, Kong (CLI/env config), gocron (scheduler), Alpine.js, Tailwind CSS (precompiled), Go html/template.

**Spec:** [docs/superpowers/specs/2026-05-07-ui-redesign-design.md](../specs/2026-05-07-ui-redesign-design.md)

---

## File Structure

**New files**
- `history/store.go` — `Store`, `Sample`, `Bucket`, `Snapshot`, `State`, `Config`, `NewStore`, `Append`, `Snapshot`, `Drop`
- `history/store_test.go` — table-driven unit tests covering all Store behaviour

**Modified files**
- `config/config.go` — add `History` config block with `WindowHours` and `DegradedLatencyMs`
- `checker/checker.go` — add `history *history.Store` field; extend constructor; `Append` after status writes; `Drop` in `UpdateProxies`
- `web/api.go` — add `HistorySnapshot` JSON type and `History` field on `ProxyInfo` and `PublicProxyInfo`; populate via the checker's store
- `web/openapi.yaml` — document the new fields on the proxy schemas
- `web/templates/index.html` — full rewrite of palette, layout shell, header, controls, card, footer
- `main.go` — construct `*history.Store` from config and pass it to `NewProxyChecker`

**Untouched (intentional)**
- `/metrics`, `/health`, `/api/v1/system/*`, `/api/v1/config`, `/api/v1/status` — preserved exactly
- Badge mode (`?badge=...`) — no markup or JS changes; the card-rich path is gated on `!badgeMode`

---

## Task 1: `history` package skeleton + types

**Files:**
- Create: `history/store.go`
- Create: `history/store_test.go`

- [ ] **Step 1: Write the failing test for the type surface and `NewStore` defaults**

```go
// history/store_test.go
package history

import (
	"testing"
	"time"
)

func defaultConfig() Config {
	return Config{
		Window:          24 * time.Hour,
		BucketCount:     60,
		SparklinePoints: 80,
		DegradedLatency: 500,
		CheckInterval:   5 * time.Minute,
	}
}

func TestNewStoreDefaults(t *testing.T) {
	s := NewStore(defaultConfig())
	if s == nil {
		t.Fatal("NewStore returned nil")
	}

	now := time.Now()
	snap := s.Snapshot("missing", now)

	if got, want := len(snap.Heartbeats), 60; got != want {
		t.Fatalf("Heartbeats len = %d, want %d", got, want)
	}
	for i, b := range snap.Heartbeats {
		if b.State != StateEmpty {
			t.Fatalf("bucket[%d].State = %q, want %q", i, b.State, StateEmpty)
		}
	}
	if got, want := len(snap.Sparkline), 80; got != want {
		t.Fatalf("Sparkline len = %d, want %d", got, want)
	}
	if snap.Uptime24h != 0 {
		t.Fatalf("Uptime24h = %v, want 0", snap.Uptime24h)
	}
	if snap.LastIncidentAt != nil {
		t.Fatalf("LastIncidentAt = %v, want nil", snap.LastIncidentAt)
	}
	if snap.DownSince != nil {
		t.Fatalf("DownSince = %v, want nil", snap.DownSince)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./history/...`
Expected: `package 19health/history: no Go files` (or compile error after the file is created in step 3 — fine either way; we want red before green).

- [ ] **Step 3: Write minimal implementation**

```go
// history/store.go
package history

import (
	"sync"
	"time"
)

// State is the rendered status of a heartbeat bucket.
type State string

const (
	StateOK       State = "ok"
	StateDegraded State = "degraded"
	StateDown     State = "down"
	StateEmpty    State = "empty"
)

// Sample is a single check result.
type Sample struct {
	Timestamp time.Time
	Online    bool
	LatencyMs int64
}

// Bucket is one cell of the heartbeat bar.
type Bucket struct {
	State     State `json:"state"`
	LatencyMs int64 `json:"latencyMs"`
}

// Snapshot is the read-side view consumed by the API.
type Snapshot struct {
	Heartbeats     []Bucket   `json:"heartbeats"`
	Sparkline      []int64    `json:"sparkline"`
	Uptime24h      float64    `json:"uptime24h"`
	LastIncidentAt *time.Time `json:"lastIncidentAt"`
	DownSince      *time.Time `json:"downSince"`
	LatencyMin     int64      `json:"latencyMin"`
	LatencyAvg     int64      `json:"latencyAvg"`
	LatencyMax     int64      `json:"latencyMax"`
}

// Config holds the tunables for a Store.
type Config struct {
	Window          time.Duration
	BucketCount     int
	SparklinePoints int
	DegradedLatency int64 // ms
	CheckInterval   time.Duration
}

// Store keeps an in-memory ring of recent samples per proxy.
type Store struct {
	cfg     Config
	mu      sync.RWMutex
	buffers map[string]*buffer
}

type buffer struct {
	samples []Sample
}

// NewStore builds an empty Store.
func NewStore(cfg Config) *Store {
	return &Store{cfg: cfg, buffers: make(map[string]*buffer)}
}

// Append records a new sample for the given proxy.
func (s *Store) Append(stableID string, sample Sample) {
	// Implemented in a later task.
}

// Snapshot returns the current view for the given proxy.
// If the proxy has no samples, all buckets are StateEmpty and stats are zero.
func (s *Store) Snapshot(stableID string, now time.Time) Snapshot {
	heartbeats := make([]Bucket, s.cfg.BucketCount)
	for i := range heartbeats {
		heartbeats[i] = Bucket{State: StateEmpty}
	}
	return Snapshot{
		Heartbeats: heartbeats,
		Sparkline:  make([]int64, s.cfg.SparklinePoints),
	}
}

// Drop removes a proxy's buffer, e.g. on subscription refresh.
func (s *Store) Drop(stableID string) {
	// Implemented in a later task.
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./history/...`
Expected: PASS, 1 test.

- [ ] **Step 5: Commit**

```bash
git add history/store.go history/store_test.go
git commit -m "feat(history): add empty Store skeleton and types"
```

---

## Task 2: `Append` + `Snapshot` honor the time window

**Files:**
- Modify: `history/store.go`
- Modify: `history/store_test.go`

- [ ] **Step 1: Write the failing test**

Append the following to `history/store_test.go`:

```go
func TestAppendStoresSamples(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	s.Append("p1", Sample{Timestamp: now.Add(-1 * time.Hour), Online: true, LatencyMs: 50})
	s.Append("p1", Sample{Timestamp: now, Online: true, LatencyMs: 60})

	snap := s.Snapshot("p1", now)

	// At least one bucket should now be StateOK (the most recent one).
	foundOK := false
	for _, b := range snap.Heartbeats {
		if b.State == StateOK {
			foundOK = true
			break
		}
	}
	if !foundOK {
		t.Fatal("expected at least one StateOK bucket after appending online samples")
	}
}

func TestAppendDropsSamplesOlderThanWindow(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	// Two old samples, one in-window.
	s.Append("p1", Sample{Timestamp: now.Add(-25 * time.Hour), Online: true, LatencyMs: 50})
	s.Append("p1", Sample{Timestamp: now.Add(-25 * time.Hour).Add(time.Minute), Online: true, LatencyMs: 50})
	s.Append("p1", Sample{Timestamp: now, Online: true, LatencyMs: 60})

	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.buffers["p1"].samples); got != 1 {
		t.Fatalf("after window trim, samples = %d, want 1", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./history/...`
Expected: `TestAppendStoresSamples` and `TestAppendDropsSamplesOlderThanWindow` FAIL (no buckets are `StateOK`; samples are not pruned).

- [ ] **Step 3: Implement `Append` and a working `Snapshot` for the OK case**

Replace the `Append` and `Snapshot` stubs in `history/store.go`:

```go
// Append records a new sample for the given proxy and trims any sample
// older than the configured window. Safe for concurrent use.
func (s *Store) Append(stableID string, sample Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf, ok := s.buffers[stableID]
	if !ok {
		buf = &buffer{}
		s.buffers[stableID] = buf
	}
	buf.samples = append(buf.samples, sample)

	cutoff := sample.Timestamp.Add(-s.cfg.Window)
	drop := 0
	for drop < len(buf.samples) && buf.samples[drop].Timestamp.Before(cutoff) {
		drop++
	}
	if drop > 0 {
		// Copy to a new slice so the trimmed prefix can be GC'd.
		trimmed := make([]Sample, len(buf.samples)-drop)
		copy(trimmed, buf.samples[drop:])
		buf.samples = trimmed
	}
}

// Snapshot returns the current view for the given proxy.
// If the proxy has no samples, all buckets are StateEmpty and stats are zero.
func (s *Store) Snapshot(stableID string, now time.Time) Snapshot {
	heartbeats := make([]Bucket, s.cfg.BucketCount)
	for i := range heartbeats {
		heartbeats[i] = Bucket{State: StateEmpty}
	}
	snap := Snapshot{
		Heartbeats: heartbeats,
		Sparkline:  make([]int64, s.cfg.SparklinePoints),
	}

	s.mu.RLock()
	buf, ok := s.buffers[stableID]
	if !ok || len(buf.samples) == 0 {
		s.mu.RUnlock()
		return snap
	}
	samples := make([]Sample, len(buf.samples))
	copy(samples, buf.samples)
	s.mu.RUnlock()

	windowStart := now.Add(-s.cfg.Window)
	bucketDur := s.cfg.Window / time.Duration(s.cfg.BucketCount)

	// Group samples by heartbeat bucket.
	hbGroups := make([][]Sample, s.cfg.BucketCount)
	for _, sm := range samples {
		if sm.Timestamp.Before(windowStart) || !sm.Timestamp.Before(now) {
			continue
		}
		idx := int(sm.Timestamp.Sub(windowStart) / bucketDur)
		if idx < 0 || idx >= s.cfg.BucketCount {
			continue
		}
		hbGroups[idx] = append(hbGroups[idx], sm)
	}

	for i, group := range hbGroups {
		snap.Heartbeats[i] = reduceBucket(group, s.cfg.DegradedLatency)
	}
	return snap
}

// reduceBucket collapses a group of samples into a single Bucket.
// down  - any sample is offline
// degraded - all online but median latency above threshold
// ok - all online and median latency at or below threshold
// empty - no samples
func reduceBucket(samples []Sample, degradedMs int64) Bucket {
	if len(samples) == 0 {
		return Bucket{State: StateEmpty}
	}
	for _, sm := range samples {
		if !sm.Online {
			return Bucket{State: StateDown}
		}
	}
	median := medianLatency(samples)
	if median > degradedMs {
		return Bucket{State: StateDegraded, LatencyMs: median}
	}
	return Bucket{State: StateOK, LatencyMs: median}
}

// medianLatency returns the median LatencyMs from samples.
// Caller must guarantee len(samples) > 0.
func medianLatency(samples []Sample) int64 {
	values := make([]int64, len(samples))
	for i, sm := range samples {
		values[i] = sm.LatencyMs
	}
	// Insertion sort - small N, simple, no extra package.
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./history/...`
Expected: PASS, 3 tests total.

- [ ] **Step 5: Commit**

```bash
git add history/store.go history/store_test.go
git commit -m "feat(history): implement Append and Snapshot bucketing"
```

---

## Task 3: Bucket states (degraded + down) and derived stats

**Files:**
- Modify: `history/store.go`
- Modify: `history/store_test.go`

- [ ] **Step 1: Write the failing test for degraded/down/derived stats**

Append to `history/store_test.go`:

```go
func TestBucketDegradedAndDown(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	// Bucket 0 (oldest): degraded — all online but high latency
	t0 := now.Add(-23*time.Hour - 50*time.Minute) // ~10 min into bucket 0
	s.Append("p1", Sample{Timestamp: t0, Online: true, LatencyMs: 800})
	s.Append("p1", Sample{Timestamp: t0.Add(time.Minute), Online: true, LatencyMs: 900})

	// Most recent bucket: down — one offline sample
	s.Append("p1", Sample{Timestamp: now.Add(-time.Minute), Online: false, LatencyMs: 0})

	snap := s.Snapshot("p1", now)

	if got := snap.Heartbeats[0].State; got != StateDegraded {
		t.Errorf("Heartbeats[0].State = %q, want %q", got, StateDegraded)
	}
	if got := snap.Heartbeats[len(snap.Heartbeats)-1].State; got != StateDown {
		t.Errorf("last bucket State = %q, want %q", got, StateDown)
	}
}

func TestSnapshotDerivedStats(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	// 9 online + 1 offline => 90% uptime
	for i := 0; i < 9; i++ {
		s.Append("p1", Sample{
			Timestamp: now.Add(-time.Duration(i+1) * time.Hour),
			Online:    true,
			LatencyMs: int64(40 + i*10), // 40..120
		})
	}
	incident := now.Add(-30 * time.Minute)
	s.Append("p1", Sample{Timestamp: incident, Online: false, LatencyMs: 0})

	snap := s.Snapshot("p1", now)

	if snap.Uptime24h < 89.9 || snap.Uptime24h > 90.1 {
		t.Errorf("Uptime24h = %v, want ~90", snap.Uptime24h)
	}
	if snap.LastIncidentAt == nil || !snap.LastIncidentAt.Equal(incident) {
		t.Errorf("LastIncidentAt = %v, want %v", snap.LastIncidentAt, incident)
	}
	if snap.DownSince != nil {
		t.Errorf("DownSince = %v, want nil (last sample is the offline one but no transition needed since no later online sample)", snap.DownSince)
	}
	if snap.LatencyMin != 40 {
		t.Errorf("LatencyMin = %d, want 40", snap.LatencyMin)
	}
	if snap.LatencyMax != 120 {
		t.Errorf("LatencyMax = %d, want 120", snap.LatencyMax)
	}
	if snap.LatencyAvg < 79 || snap.LatencyAvg > 81 {
		t.Errorf("LatencyAvg = %d, want ~80", snap.LatencyAvg)
	}
}

func TestSnapshotDownSinceWhenCurrentlyOffline(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	// Online up to 2h ago, offline since.
	s.Append("p1", Sample{Timestamp: now.Add(-3 * time.Hour), Online: true, LatencyMs: 50})
	transition := now.Add(-2 * time.Hour)
	s.Append("p1", Sample{Timestamp: transition, Online: false, LatencyMs: 0})
	s.Append("p1", Sample{Timestamp: now.Add(-1 * time.Hour), Online: false, LatencyMs: 0})
	s.Append("p1", Sample{Timestamp: now.Add(-1 * time.Minute), Online: false, LatencyMs: 0})

	snap := s.Snapshot("p1", now)
	if snap.DownSince == nil || !snap.DownSince.Equal(transition) {
		t.Errorf("DownSince = %v, want %v", snap.DownSince, transition)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./history/...`
Expected: the three new tests FAIL (`Uptime24h = 0`, `LastIncidentAt = <nil>`, etc.).

- [ ] **Step 3: Extend `Snapshot` with derived stats and sparkline**

Replace the `Snapshot` function body in `history/store.go` with the version below (the helpers introduced earlier stay):

```go
// Snapshot returns the current view for the given proxy.
// If the proxy has no samples, all buckets are StateEmpty and stats are zero.
func (s *Store) Snapshot(stableID string, now time.Time) Snapshot {
	heartbeats := make([]Bucket, s.cfg.BucketCount)
	for i := range heartbeats {
		heartbeats[i] = Bucket{State: StateEmpty}
	}
	snap := Snapshot{
		Heartbeats: heartbeats,
		Sparkline:  make([]int64, s.cfg.SparklinePoints),
	}

	s.mu.RLock()
	buf, ok := s.buffers[stableID]
	if !ok || len(buf.samples) == 0 {
		s.mu.RUnlock()
		return snap
	}
	samples := make([]Sample, len(buf.samples))
	copy(samples, buf.samples)
	s.mu.RUnlock()

	windowStart := now.Add(-s.cfg.Window)
	bucketDur := s.cfg.Window / time.Duration(s.cfg.BucketCount)
	sparkDur := s.cfg.Window / time.Duration(s.cfg.SparklinePoints)

	// Filter and group samples for both heartbeat and sparkline buckets.
	hbGroups := make([][]Sample, s.cfg.BucketCount)
	sparkGroups := make([][]Sample, s.cfg.SparklinePoints)

	var inWindow []Sample
	for _, sm := range samples {
		if sm.Timestamp.Before(windowStart) || !sm.Timestamp.Before(now) {
			continue
		}
		inWindow = append(inWindow, sm)

		hbIdx := int(sm.Timestamp.Sub(windowStart) / bucketDur)
		if hbIdx >= 0 && hbIdx < s.cfg.BucketCount {
			hbGroups[hbIdx] = append(hbGroups[hbIdx], sm)
		}
		spIdx := int(sm.Timestamp.Sub(windowStart) / sparkDur)
		if spIdx >= 0 && spIdx < s.cfg.SparklinePoints {
			sparkGroups[spIdx] = append(sparkGroups[spIdx], sm)
		}
	}

	for i, group := range hbGroups {
		snap.Heartbeats[i] = reduceBucket(group, s.cfg.DegradedLatency)
	}
	for i, group := range sparkGroups {
		// Sparkline records median latency of online samples; 0 if no online samples.
		var online []Sample
		for _, sm := range group {
			if sm.Online && sm.LatencyMs > 0 {
				online = append(online, sm)
			}
		}
		if len(online) > 0 {
			snap.Sparkline[i] = medianLatency(online)
		}
	}

	if len(inWindow) == 0 {
		return snap
	}

	// Uptime % over the in-window samples.
	var onlineCount int
	for _, sm := range inWindow {
		if sm.Online {
			onlineCount++
		}
	}
	snap.Uptime24h = float64(onlineCount) / float64(len(inWindow)) * 100

	// Latency min/avg/max over in-window online samples.
	var latencies []int64
	for _, sm := range inWindow {
		if sm.Online && sm.LatencyMs > 0 {
			latencies = append(latencies, sm.LatencyMs)
		}
	}
	if len(latencies) > 0 {
		snap.LatencyMin = latencies[0]
		snap.LatencyMax = latencies[0]
		var sum int64
		for _, v := range latencies {
			if v < snap.LatencyMin {
				snap.LatencyMin = v
			}
			if v > snap.LatencyMax {
				snap.LatencyMax = v
			}
			sum += v
		}
		snap.LatencyAvg = sum / int64(len(latencies))
	}

	// LastIncidentAt = most recent offline sample.
	for i := len(inWindow) - 1; i >= 0; i-- {
		if !inWindow[i].Online {
			t := inWindow[i].Timestamp
			snap.LastIncidentAt = &t
			break
		}
	}

	// DownSince = if currently offline, walk back to the transition.
	last := inWindow[len(inWindow)-1]
	if !last.Online {
		transition := last.Timestamp
		for i := len(inWindow) - 2; i >= 0; i-- {
			if inWindow[i].Online {
				break
			}
			transition = inWindow[i].Timestamp
		}
		snap.DownSince = &transition
	}

	return snap
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./history/...`
Expected: PASS, 6 tests total.

- [ ] **Step 5: Commit**

```bash
git add history/store.go history/store_test.go
git commit -m "feat(history): bucket states, derived stats, sparkline"
```

---

## Task 4: `Drop` removes a proxy's buffer

**Files:**
- Modify: `history/store.go`
- Modify: `history/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `history/store_test.go`:

```go
func TestDropRemovesBuffer(t *testing.T) {
	s := NewStore(defaultConfig())
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	s.Append("p1", Sample{Timestamp: now, Online: true, LatencyMs: 50})
	s.Append("p2", Sample{Timestamp: now, Online: true, LatencyMs: 50})

	s.Drop("p1")

	s.mu.RLock()
	_, p1Exists := s.buffers["p1"]
	_, p2Exists := s.buffers["p2"]
	s.mu.RUnlock()

	if p1Exists {
		t.Error("expected p1 buffer to be removed")
	}
	if !p2Exists {
		t.Error("expected p2 buffer to still exist")
	}

	// Snapshot of dropped proxy returns the empty default.
	snap := s.Snapshot("p1", now)
	for i, b := range snap.Heartbeats {
		if b.State != StateEmpty {
			t.Errorf("after Drop, Heartbeats[%d].State = %q, want %q", i, b.State, StateEmpty)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./history/...`
Expected: `TestDropRemovesBuffer` FAIL (`Drop` is still a stub, p1 buffer remains).

- [ ] **Step 3: Implement `Drop`**

Replace the `Drop` stub in `history/store.go`:

```go
// Drop removes a proxy's buffer. Safe to call for missing IDs.
func (s *Store) Drop(stableID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buffers, stableID)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./history/...`
Expected: PASS, 7 tests total.

- [ ] **Step 5: Commit**

```bash
git add history/store.go history/store_test.go
git commit -m "feat(history): Drop removes buffer for retired proxies"
```

---

## Task 5: Config — `HistoryWindowHours` and `DegradedLatencyMs`

**Files:**
- Modify: `config/config.go`

- [ ] **Step 1: Add the new config block**

Open `config/config.go`. Locate the `Web` block (around `web-public`). Immediately after the closing `} \`embed:"" prefix:""\`` of the `Web` block, before the `Version` field, insert a new `History` block:

```go
	History struct {
		WindowHours       int   `name:"history-window-hours" help:"Hours of per-proxy history to retain in memory" default:"24" env:"HISTORY_WINDOW_HOURS"`
		DegradedLatencyMs int64 `name:"degraded-latency-ms" help:"Latency above which a healthy bucket is marked degraded (ms)" default:"500" env:"DEGRADED_LATENCY_MS"`
	} `embed:"" prefix:""`
```

The relevant slice now reads (showing the lines around the insert):

```go
	Web struct {
		ShowServerDetails bool   `name:"web-show-details" help:"Show server IP addresses and ports in web UI" default:"false" env:"WEB_SHOW_DETAILS"`
		Public            bool   `name:"web-public" help:"Make dashboard public (requires --metrics-protected)" default:"false" env:"WEB_PUBLIC"`
		CustomAssetsPath  string `name:"web-custom-assets-path" help:"Path to custom assets directory (logo.svg, favicon.ico, custom.css, index.html)" default:"" env:"WEB_CUSTOM_ASSETS_PATH"`
	} `embed:"" prefix:""`

	History struct {
		WindowHours       int   `name:"history-window-hours" help:"Hours of per-proxy history to retain in memory" default:"24" env:"HISTORY_WINDOW_HOURS"`
		DegradedLatencyMs int64 `name:"degraded-latency-ms" help:"Latency above which a healthy bucket is marked degraded (ms)" default:"500" env:"DEGRADED_LATENCY_MS"`
	} `embed:"" prefix:""`

	Version  VersionFlag `name:"version" help:"Print version information and quit"`
```

- [ ] **Step 2: Verify the package still builds**

Run: `go build ./...`
Expected: successful build, no output.

- [ ] **Step 3: Smoke-test the new flags via `--help`**

Run: `go run . --help 2>&1 | grep -E 'history-window-hours|degraded-latency-ms'`
Expected (output order may differ slightly):

```
  --history-window-hours=24             Hours of per-proxy history to retain in memory ($HISTORY_WINDOW_HOURS)
  --degraded-latency-ms=500             Latency above which a healthy bucket is marked degraded (ms) ($DEGRADED_LATENCY_MS)
```

If the binary errors on missing `--subscription-url`, the help output will still print first — read the lines above the error.

- [ ] **Step 4: Commit**

```bash
git add config/config.go
git commit -m "feat(config): add HISTORY_WINDOW_HOURS and DEGRADED_LATENCY_MS"
```

---

## Task 6: Wire `history.Store` into `ProxyChecker`

**Files:**
- Modify: `checker/checker.go`
- Modify: `main.go`

- [ ] **Step 1: Add a `history` field and an Append call to the checker**

Open `checker/checker.go`. Update the import block to include the new package:

```go
import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"19health/history"
	"19health/logger"
	"19health/metrics"
	"19health/models"
)
```

Add a `history *history.Store` field to the struct (insert after `generation uint64`):

```go
type ProxyChecker struct {
	proxies         []*models.ProxyConfig
	startPort       int
	ipCheck         string
	currentIP       string
	httpClient      *http.Client
	currentMetrics  sync.Map
	latencyMetrics  sync.Map
	ipInitialized   bool
	ipCheckTimeout  int
	genMethodURL    string
	downloadURL     string
	downloadTimeout int
	downloadMinSize int64
	checkMethod     string
	mu              sync.RWMutex
	generation      uint64
	history         *history.Store
}
```

Extend the constructor signature and wire the field. Replace the existing `NewProxyChecker` with:

```go
func NewProxyChecker(
	proxies []*models.ProxyConfig,
	startPort int,
	ipCheckURL string,
	ipCheckTimeout int,
	genMethodURL string,
	downloadURL string,
	downloadTimeout int,
	downloadMinSize int64,
	checkMethod string,
	historyStore *history.Store,
) *ProxyChecker {
	return &ProxyChecker{
		proxies:   proxies,
		startPort: startPort,
		ipCheck:   ipCheckURL,
		httpClient: &http.Client{
			Timeout: time.Second * time.Duration(ipCheckTimeout),
		},
		ipCheckTimeout:  ipCheckTimeout,
		genMethodURL:    genMethodURL,
		downloadURL:     downloadURL,
		downloadTimeout: downloadTimeout,
		downloadMinSize: downloadMinSize,
		checkMethod:     checkMethod,
		history:         historyStore,
	}
}
```

In `checkProxyInternal`, append a sample on each terminal branch. Locate the `setFailedStatus` and `setFailedLatency` closures. Right after `setFailedLatency`, add a small helper:

```go
	recordHistory := func(online bool, latency time.Duration) {
		if pc.history == nil {
			return
		}
		pc.history.Append(proxy.StableID, history.Sample{
			Timestamp: time.Now(),
			Online:    online,
			LatencyMs: latency.Milliseconds(),
		})
	}
```

Then call `recordHistory(false, 0)` in every place we currently call `setFailedStatus()` and `setFailedLatency()` together, and `recordHistory(true, latency)` after the existing successful-write block. Concretely:

- After the URL-parse error handling (where `setFailedStatus(); setFailedLatency(); return` is called), add `recordHistory(false, 0)` immediately before the `return`.
- After the `checkErr != nil` block (same pattern), same insertion.
- After the `if !checkSuccess { setFailedStatus(); setFailedLatency() }` branch, add `recordHistory(false, 0)` (still inside that branch).
- After the success branch — after `pc.currentMetrics.Store(metricKey, true)` — add `recordHistory(true, latency)`.

The relevant section now reads:

```go
	if err != nil {
		logger.Error("Error parsing proxy URL %s: %v", proxyURL, err)
		setFailedStatus()
		setFailedLatency()
		recordHistory(false, 0)

		return
	}

	// ... unchanged ...

	if checkErr != nil {
		logger.Error("%s | %v", proxy.Name, checkErr)
		setFailedStatus()
		setFailedLatency()
		recordHistory(false, 0)

		return
	}

	if !checkSuccess {
		logger.Error("%s | Failed | %s | Latency: %s", proxy.Name, logMessage, latency)
		setFailedStatus()
		setFailedLatency()
		recordHistory(false, 0)
	} else {
		logger.Result("%s | Success | %s | Latency: %s", proxy.Name, logMessage, latency)
		if !isGenerationValid() {
			logger.Debug("%s | Skipping metric update: generation changed", proxy.Name)
			return
		}
		// ... metrics writes unchanged ...
		pc.latencyMetrics.Store(metricKey, latency)
		pc.currentMetrics.Store(metricKey, true)
		recordHistory(true, latency)
	}
```

- [ ] **Step 2: Drop history buffers when `UpdateProxies` retires a proxy**

Locate the `UpdateProxies` method in `checker/checker.go`. At the start of the method, capture the previous proxies' StableIDs, run the existing logic, then drop history for IDs that no longer exist. Replace the body so it reads:

```go
func (pc *ProxyChecker) UpdateProxies(newProxies []*models.ProxyConfig) {
	pc.mu.Lock()

	oldIDs := make(map[string]struct{}, len(pc.proxies))
	for _, p := range pc.proxies {
		if p.StableID != "" {
			oldIDs[p.StableID] = struct{}{}
		}
	}
	for _, p := range newProxies {
		if p.StableID == "" {
			p.StableID = p.GenerateStableID()
		}
		delete(oldIDs, p.StableID)
	}

	atomic.AddUint64(&pc.generation, 1)
	pc.proxies = newProxies
	pc.currentMetrics = sync.Map{}
	pc.latencyMetrics = sync.Map{}

	pc.mu.Unlock()

	if pc.history != nil {
		for id := range oldIDs {
			pc.history.Drop(id)
		}
	}
}
```

> **Note:** the existing `UpdateProxies` in `checker.go` is shorter than the snippet above. Read the current implementation first, preserve any other side effects already there, and only insert the `oldIDs` capture and the trailing `Drop` loop. The `atomic.AddUint64`, `pc.proxies = newProxies`, and `sync.Map{}` resets are existing logic.

- [ ] **Step 3: Update `main.go` to construct the store and pass it in**

Open `main.go`. Add an import for `19health/history` (alongside the existing `19health/...` imports):

```go
	"19health/checker"
	"19health/config"
	"19health/history"
	"19health/logger"
```

Right before the existing `proxyChecker := checker.NewProxyChecker(...)` line, build the store:

```go
	historyStore := history.NewStore(history.Config{
		Window:          time.Duration(config.CLIConfig.History.WindowHours) * time.Hour,
		BucketCount:     60,
		SparklinePoints: 80,
		DegradedLatency: config.CLIConfig.History.DegradedLatencyMs,
		CheckInterval:   time.Duration(config.CLIConfig.Proxy.CheckInterval) * time.Second,
	})

	proxyChecker := checker.NewProxyChecker(
		*proxyConfigs,
		config.CLIConfig.Xray.StartPort,
		config.CLIConfig.Proxy.IpCheckUrl,
		config.CLIConfig.Proxy.Timeout,
		config.CLIConfig.Proxy.StatusCheckUrl,
		config.CLIConfig.Proxy.DownloadUrl,
		config.CLIConfig.Proxy.DownloadTimeout,
		config.CLIConfig.Proxy.DownloadMinSize,
		config.CLIConfig.Proxy.CheckMethod,
		historyStore,
	)
```

- [ ] **Step 4: Build and run the existing test suite**

Run: `go build ./...`
Expected: clean build.

Run: `go test ./...`
Expected: PASS — only the `history` tests run today; the build verifies the new wiring compiles.

- [ ] **Step 5: Commit**

```bash
git add checker/checker.go main.go
git commit -m "feat(checker): wire history.Store, append per check, drop on update"
```

---

## Task 7: Expose `history` snapshot on the API

**Files:**
- Modify: `checker/checker.go` (add a getter)
- Modify: `web/api.go`

- [ ] **Step 1: Add a checker accessor for the history store**

In `checker/checker.go`, add this method below `GetCurrentIP`:

```go
// History returns the underlying history.Store. May be nil if the checker
// was constructed without one.
func (pc *ProxyChecker) History() *history.Store {
	return pc.history
}
```

- [ ] **Step 2: Add `History` field to API response types**

Open `web/api.go`. Update the import block to include the history package:

```go
import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"19health/checker"
	"19health/config"
	"19health/history"
	"19health/models"
)
```

Add a `HistorySnapshot` JSON struct just above `ProxyInfo`:

```go
type HistorySnapshot struct {
	Heartbeats     []history.Bucket `json:"heartbeats"`
	Sparkline      []int64          `json:"sparkline"`
	Uptime24h      float64          `json:"uptime24h"`
	LastIncidentAt *time.Time       `json:"lastIncidentAt,omitempty"`
	DownSince      *time.Time       `json:"downSince,omitempty"`
	LatencyMin     int64            `json:"latencyMin"`
	LatencyAvg     int64            `json:"latencyAvg"`
	LatencyMax     int64            `json:"latencyMax"`
}
```

Add a `History` field to both proxy info types:

```go
type ProxyInfo struct {
	Index     int              `json:"index"`
	StableID  string           `json:"stableId"`
	Name      string           `json:"name"`
	SubName   string           `json:"subName"`
	Server    string           `json:"server"`
	Port      int              `json:"port"`
	Protocol  string           `json:"protocol"`
	ProxyPort int              `json:"proxyPort"`
	Online    bool             `json:"online"`
	LatencyMs int64            `json:"latencyMs"`
	History   *HistorySnapshot `json:"history,omitempty"`
}

type PublicProxyInfo struct {
	StableID  string           `json:"stableId"`
	Name      string           `json:"name"`
	Online    bool             `json:"online"`
	LatencyMs int64            `json:"latencyMs"`
	History   *HistorySnapshot `json:"history,omitempty"`
}
```

- [ ] **Step 3: Add a helper that builds `*HistorySnapshot` from the checker**

Add this helper to `web/api.go`, just below `toProxyInfo`:

```go
func snapshotFromChecker(pc *checker.ProxyChecker, stableID string) *HistorySnapshot {
	store := pc.History()
	if store == nil {
		return nil
	}
	snap := store.Snapshot(stableID, time.Now())
	return &HistorySnapshot{
		Heartbeats:     snap.Heartbeats,
		Sparkline:      snap.Sparkline,
		Uptime24h:      snap.Uptime24h,
		LastIncidentAt: snap.LastIncidentAt,
		DownSince:      snap.DownSince,
		LatencyMin:     snap.LatencyMin,
		LatencyAvg:     snap.LatencyAvg,
		LatencyMax:     snap.LatencyMax,
	}
}
```

- [ ] **Step 4: Populate `History` on every relevant handler**

In `APIPublicProxiesHandler`, change the inner loop so each `PublicProxyInfo` is built with a snapshot:

```go
for _, proxy := range proxies {
	status, latency, _ := proxyChecker.GetProxyStatus(proxy.Name)
	result = append(result, PublicProxyInfo{
		StableID:  proxy.StableID,
		Name:      proxy.Name,
		Online:    status,
		LatencyMs: latency.Milliseconds(),
		History:   snapshotFromChecker(proxyChecker, proxy.StableID),
	})
}
```

In `toProxyInfo`, add a parameter so callers pass the snapshot. Replace the existing `toProxyInfo`:

```go
func toProxyInfo(proxy *models.ProxyConfig, online bool, latency time.Duration, startPort int, snap *HistorySnapshot) ProxyInfo {
	return ProxyInfo{
		Index:     proxy.Index,
		StableID:  proxy.StableID,
		Name:      proxy.Name,
		SubName:   proxy.SubName,
		Server:    proxy.Server,
		Port:      proxy.Port,
		Protocol:  proxy.Protocol,
		ProxyPort: startPort + proxy.Index,
		Online:    online,
		LatencyMs: latency.Milliseconds(),
		History:   snap,
	}
}
```

Update both callers in the same file:

```go
// APIProxiesHandler:
for _, proxy := range proxies {
	status, latency, _ := proxyChecker.GetProxyStatus(proxy.Name)
	result = append(result, toProxyInfo(proxy, status, latency, startPort, snapshotFromChecker(proxyChecker, proxy.StableID)))
}

// APIProxyHandler:
status, latency, _ := proxyChecker.GetProxyStatus(proxy.Name)
writeJSON(w, toProxyInfo(proxy, status, latency, startPort, snapshotFromChecker(proxyChecker, proxy.StableID)))
```

- [ ] **Step 5: Build and smoke-test the JSON shape**

Run: `go build ./...`
Expected: clean build.

Run: `go vet ./...`
Expected: no warnings.

Manual smoke (optional but recommended): start the binary against a real subscription, hit `/api/v1/proxies`, confirm the response includes a `history` block with `heartbeats[60]`, `sparkline[80]`, `uptime24h`, and the latency fields. Skip the manual smoke if no subscription is at hand — wiring is verified by the next manual-verification task.

- [ ] **Step 6: Commit**

```bash
git add checker/checker.go web/api.go
git commit -m "feat(api): add history snapshot to proxy responses"
```

---

## Task 8: Update OpenAPI for the new `history` block

**Files:**
- Modify: `web/openapi.yaml`

- [ ] **Step 1: Read the current `ProxyInfo` and `PublicProxyInfo` schema sections**

Run: `grep -n -A 2 "^  ProxyInfo:\|^  PublicProxyInfo:" web/openapi.yaml`
Expected: the line numbers and surrounding context for those two component schemas.

- [ ] **Step 2: Add a `HistorySnapshot` schema component**

Open `web/openapi.yaml` and locate the `components.schemas` section. Add a new schema definition (alphabetised next to `ProxyInfo`):

```yaml
    HistorySnapshot:
      type: object
      properties:
        heartbeats:
          type: array
          items:
            type: object
            properties:
              state:
                type: string
                enum: [ok, degraded, down, empty]
              latencyMs:
                type: integer
                format: int64
        sparkline:
          type: array
          items:
            type: integer
            format: int64
        uptime24h:
          type: number
          format: double
          description: Uptime percentage over the configured history window (default 24h).
        lastIncidentAt:
          type: string
          format: date-time
          nullable: true
        downSince:
          type: string
          format: date-time
          nullable: true
        latencyMin:
          type: integer
          format: int64
        latencyAvg:
          type: integer
          format: int64
        latencyMax:
          type: integer
          format: int64
```

Then add `history` as an optional property on both `ProxyInfo` and `PublicProxyInfo`:

```yaml
        history:
          $ref: '#/components/schemas/HistorySnapshot'
```

- [ ] **Step 3: Validate the YAML still parses**

Run: `go build ./...` (the spec is embedded via `//go:embed` in `web/api.go`, so a build error indicates malformed YAML at compile time only if Go embed validates — confirmation here is just that the file is syntactically loadable).

For a stronger check, if `python3` is available, run:

```bash
python3 -c "import yaml; yaml.safe_load(open('web/openapi.yaml'))" && echo OK
```

Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add web/openapi.yaml
git commit -m "docs(openapi): document history snapshot on proxy responses"
```

---

## Task 9: Frontend — palette + page shell + sticky footer

**Files:**
- Modify: `web/templates/index.html`

- [ ] **Step 1: Replace the dark-theme CSS variables**

Open `web/templates/index.html`. Find the `:root` block under the `Dark theme` comment (currently around line 53). Replace it with the new palette:

```css
      /* Dark theme — 19Health redesign */
      :root {
        --bg-primary: #0d1421;
        --bg-secondary: #161e2e;
        --bg-tertiary: #11192a;
        --border: #243049;
        --border-hover: #2d3a55;
        --text-primary: #e8eef7;
        --text-secondary: #b8c2d4;
        --text-muted: #6b7790;
        --accent: #f0b429;
        --accent-hover: #d49317;
        --hover-bg: rgba(240, 180, 41, 0.06);
        --segment-empty: #243049;
        --status-online: #22c55e;
        --status-offline: #ef4444;
        --status-degraded: #f0b429;
        --link: #4a8cd6;
      }
```

Find the `light` theme block (the `.light { ... }` selector that defines an override). Replace it with the matched light variant:

```css
      .light {
        --bg-primary: #f7f9fc;
        --bg-secondary: #ffffff;
        --bg-tertiary: #f1f4f9;
        --border: #d8def0;
        --border-hover: #b9c4dc;
        --text-primary: #1a1f2e;
        --text-secondary: #3a4459;
        --text-muted: #6b7790;
        --accent: #c9881a;
        --accent-hover: #a87213;
        --hover-bg: rgba(201, 136, 26, 0.08);
        --segment-empty: #e2e7f1;
        --status-online: #16a34a;
        --status-offline: #dc2626;
        --status-degraded: #c9881a;
        --link: #1f5fb0;
      }
```

- [ ] **Step 2: Wrap the page shell in a flex column so the footer pins to the bottom**

Find the `<body class="min-h-screen antialiased" ...>` opening tag (around line 447). Change the class list to add the flex layout:

```html
  <body
    class="min-h-screen flex flex-col antialiased"
    :class="[badgeMode && 'badge-body', hideBackground && 'no-bg']"
  >
```

Find the main wrapper that currently looks like:

```html
    <div x-show="!badgeMode" class="max-w-screen-2xl mx-auto px-4 lg:px-6 py-6">
```

Change it so the wrapper grows to fill remaining space and is itself a flex column whose footer can use `mt-auto`:

```html
    <div x-show="!badgeMode" class="flex-1 w-full max-w-screen-2xl mx-auto px-4 lg:px-6 py-6 flex flex-col">
```

- [ ] **Step 3: Pin the footer with `mt-auto`**

Find the existing `<footer x-show="showFooter" ...>` (around line 948). Change its class list to:

```html
      <footer
        x-show="showFooter"
        class="mt-auto pt-4 border-t border-default text-center text-xs text-muted"
      >
```

This replaces `mt-8 pt-4` with `mt-auto pt-4` so the footer is pushed to the bottom of the flex column even when the server list is short.

- [ ] **Step 4: Manual visual check**

Run the dev binary if convenient (`go run . --subscription-url ...`). Confirm in a browser at the configured port:

- The footer sits at the very bottom of the viewport, even with no servers loaded yet.
- The page background, card backgrounds, and accent text now use the new amber palette.
- Light/dark toggle still works and produces a coherent light theme (no leftover dark colors bleeding through).

If you don't have a subscription handy, skip the visual check and rely on Task 12 — but a screenshot here is cheap insurance.

- [ ] **Step 5: Commit**

```bash
git add web/templates/index.html
git commit -m "feat(web): amber palette and sticky footer shell"
```

---

## Task 10: Frontend — remove deprecated UI elements

**Files:**
- Modify: `web/templates/index.html`

- [ ] **Step 1: Remove the top stats row**

Open `web/templates/index.html`. Find the `<!-- Stats -->` comment (around line 605). Delete the entire `<div x-show="showStats" ...>` block, including all four stat cards and the closing `</div>`. After deletion, the `<!-- Servers header -->` block must directly follow the `</header>` tag (with only blank lines in between).

- [ ] **Step 2: Remove the Metrics, Health, and API anchors from the Servers header**

In the `<!-- Servers header -->` block (around line 643), the inner `<div class="flex flex-wrap items-center gap-2">` contains three `<a>` tags (Metrics, Health, API) plus a closing `</div>`. Delete the entire inner div including all three anchors. The header keeps only its `<h2>Servers</h2>` left side.

After deletion, the `<!-- Servers header -->` block reads:

```html
      <!-- Servers header -->
      <div
        x-show="showServersHeader"
        class="flex flex-wrap items-center justify-between gap-3 mb-4"
      >
        <h2 class="text-base font-semibold text-primary">Servers</h2>
      </div>
```

(The `{{ if not .IsPublic }}` / `{{ end }}` template gate that wrapped the buttons is removed entirely.)

- [ ] **Step 3: Remove the per-card Copy URL button**

Inside the proxy-card `<template x-for="...">` (around line 840), find the `{{ if not .IsPublic }} <!-- Copy --> <button @click="copyUrl(proxy)" ...> ... </button> {{ end }}` block. Delete it in full, including the surrounding `{{ if }} {{ end }}`.

- [ ] **Step 4: Remove the `copyUrl` helper from the Alpine state**

Find the `dashboard()` function (around line 983). Remove the `copyUrl(proxy)` method and any toast helper called only from it. Search for "copyUrl" in the file — every match must be deleted.

If a `toasts` array exists only for copy-confirmation toasts, also remove the `<!-- Toast -->` block at the top of the body (around line 475) and the `toasts` field on the Alpine state. If toasts are used for anything else (e.g. errors), leave them.

- [ ] **Step 5: Build and confirm the template still parses**

Run: `go build ./...`
Expected: clean build.

If you can run the binary, load the page and confirm the header has no Metrics/Health/API buttons and the cards have no copy icon (the protocol pill is removed in Task 11 and may still appear here — that's fine).

- [ ] **Step 6: Commit**

```bash
git add web/templates/index.html
git commit -m "feat(web): remove stats row, header buttons, and copy action"
```

---

## Task 11: Frontend — rich card markup with heartbeat, sparkline, and stats strip

**Files:**
- Modify: `web/templates/index.html`

- [ ] **Step 1: Replace the proxy-card markup**

Find the proxy grid wrapper (`<div ... x-show="showProxies" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2 mb-4">`, around line 836) and the `<template x-for="(proxy, idx) in filteredProxies" ...>` it contains.

Replace the entire `<template>` block (start tag, single child `<div class="proxy-card ...">`, and closing `</template>`) with:

```html
        <template x-for="(proxy, idx) in filteredProxies" :key="proxy.stableId">
          <div
            class="proxy-card group card rounded-lg p-3 transition-all duration-150"
            :class="initialLoad && 'animate'"
          >
            <!-- Top row: dot · name · latency -->
            <div class="flex items-center gap-2">
              <div class="relative flex-shrink-0">
                <div
                  class="w-2 h-2 rounded-full"
                  :class="proxy.online ? 'status-online pulse' : 'status-offline'"
                ></div>
              </div>
              {{ if .IsPublic }}
              <span
                class="flex-1 min-w-0 text-sm font-semibold text-primary truncate"
                x-text="proxy.name"
              ></span>
              {{ else }}
              <a
                :href="proxy.url"
                target="_blank"
                class="flex-1 min-w-0 text-sm font-semibold text-primary link-hover truncate transition-colors"
                x-text="proxy.name"
              ></a>
              {{ end }}
              <span
                class="text-sm font-bold tabular-nums"
                :class="proxy.online ? 'text-accent' : 'text-offline'"
                x-text="proxy.online ? proxy.latency : 'offline'"
              ></span>
            </div>

            <!-- Meta row: uptime % · 24h · incident phrase -->
            <div class="flex flex-wrap items-center gap-1.5 mt-1.5 text-[10px] text-muted">
              <span
                class="font-semibold"
                :class="uptimeClass(proxy)"
                x-text="formatUptime(proxy)"
              ></span>
              <span x-text="formatIncident(proxy)"></span>
            </div>

            <!-- Heartbeat bar -->
            <div class="flex gap-px mt-2 h-3.5">
              <template x-for="(bucket, i) in (proxy.history && proxy.history.heartbeats) || []" :key="i">
                <div
                  class="flex-1 rounded-[1px]"
                  :class="bucketClass(bucket.state)"
                  :title="bucket.state + (bucket.latencyMs ? ' · ' + bucket.latencyMs + 'ms' : '')"
                ></div>
              </template>
            </div>

            <!-- Sparkline -->
            <svg
              class="w-full h-8 mt-1.5"
              viewBox="0 0 100 32"
              preserveAspectRatio="none"
              x-show="proxy.history && proxy.history.sparkline && proxy.history.sparkline.length"
            >
              <defs>
                <linearGradient :id="'spark-' + proxy.stableId" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" style="stop-color: var(--accent); stop-opacity: 0.35"/>
                  <stop offset="1" style="stop-color: var(--accent); stop-opacity: 0"/>
                </linearGradient>
              </defs>
              <polygon
                :fill="'url(#spark-' + proxy.stableId + ')'"
                :points="sparklineArea(proxy)"
              ></polygon>
              <polyline
                fill="none"
                stroke-width="1.5"
                style="stroke: var(--accent)"
                :points="sparklineLine(proxy)"
              ></polyline>
            </svg>

            <!-- Min/avg/max strip -->
            <div
              x-show="proxy.history && proxy.history.latencyMin > 0"
              class="flex justify-between mt-2 pt-2 border-t border-default"
            >
              <div class="flex flex-col">
                <span class="text-[9px] uppercase tracking-wide text-muted">min</span>
                <span class="text-[11px] font-semibold text-secondary tabular-nums" x-text="proxy.history.latencyMin + 'ms'"></span>
              </div>
              <div class="flex flex-col">
                <span class="text-[9px] uppercase tracking-wide text-muted">avg</span>
                <span class="text-[11px] font-semibold text-secondary tabular-nums" x-text="proxy.history.latencyAvg + 'ms'"></span>
              </div>
              <div class="flex flex-col">
                <span class="text-[9px] uppercase tracking-wide text-muted">max</span>
                <span class="text-[11px] font-semibold text-secondary tabular-nums" x-text="proxy.history.latencyMax + 'ms'"></span>
              </div>
            </div>
          </div>
        </template>
```

> **Note:** the new markup uses helper utility classes (`text-accent`, `text-offline`, `status-online`, etc.) and a few new helpers (`bucketClass`, `formatUptime`, `formatIncident`, `uptimeClass`, `sparklineLine`, `sparklineArea`). The first set already exists in the existing `<style>` block — preserve it. The second set is added in Task 12.

- [ ] **Step 2: Add CSS for the heartbeat bucket states**

In the existing `<style>` block in `index.html`, add these classes (alongside `.status-online` etc.):

```css
      .bucket-ok {
        background: var(--status-online);
      }
      .bucket-degraded {
        background: var(--status-degraded);
      }
      .bucket-down {
        background: var(--status-offline);
      }
      .bucket-empty {
        background: var(--segment-empty);
      }
      .text-accent {
        color: var(--accent);
      }
      .text-offline {
        color: var(--status-offline);
      }
      .text-secondary {
        color: var(--text-secondary);
      }
      .border-default {
        border-color: var(--border);
      }
```

If any of these already exist in the file, leave the existing definition — do not duplicate.

- [ ] **Step 3: Build and visually confirm card structure**

Run: `go build ./...`
Expected: clean build. (Helpers referenced in the markup are added next task — runtime errors in Alpine are fine at this checkpoint.)

- [ ] **Step 4: Commit**

```bash
git add web/templates/index.html
git commit -m "feat(web): rewrite card with heartbeat, sparkline, latency strip"
```

---

## Task 12: Frontend — Alpine helpers and final polish

**Files:**
- Modify: `web/templates/index.html`

- [ ] **Step 1: Drop the `stats` aggregate from Alpine state**

In the `dashboard()` Alpine function (around line 983), remove the `stats` field and any code that maintains it. Search for `stats.` and `.stats` in the file — every reference must be deleted (in Task 10 you already removed the markup that used them).

Also remove the now-unused `showStats` getter, if one exists.

- [ ] **Step 2: Add the new card helpers**

Inside the `dashboard()` return object, add the following methods (place them next to the existing helpers like `getSegments`):

```javascript
        bucketClass(state) {
          switch (state) {
            case 'ok':       return 'bucket-ok';
            case 'degraded': return 'bucket-degraded';
            case 'down':     return 'bucket-down';
            default:         return 'bucket-empty';
          }
        },

        formatUptime(proxy) {
          const h = proxy.history;
          if (!h || !h.heartbeats || h.heartbeats.every(b => b.state === 'empty')) {
            return '— ';
          }
          return h.uptime24h.toFixed(1) + '%';
        },

        uptimeClass(proxy) {
          const h = proxy.history;
          if (!h || h.heartbeats.every(b => b.state === 'empty')) return 'text-muted';
          if (h.uptime24h >= 99.5) return 'text-online';
          if (h.uptime24h >= 95)   return 'text-accent';
          return 'text-offline';
        },

        formatIncident(proxy) {
          const h = proxy.history;
          if (!h) return '· gathering data';
          if (h.heartbeats.every(b => b.state === 'empty')) return '· gathering data';
          if (h.downSince) {
            return '· down for ' + this._humanDuration(Date.now() - new Date(h.downSince).getTime());
          }
          if (h.lastIncidentAt) {
            return '· 24h · last incident ' + this._humanDuration(Date.now() - new Date(h.lastIncidentAt).getTime()) + ' ago';
          }
          return '· 24h · no incidents';
        },

        _humanDuration(ms) {
          const min = Math.floor(ms / 60000);
          if (min < 1)   return 'just now';
          if (min < 60)  return min + 'm';
          const hours = Math.floor(min / 60);
          const remM  = min % 60;
          if (hours < 24) return hours + 'h ' + (remM ? remM + 'm' : '');
          const days = Math.floor(hours / 24);
          return days + 'd';
        },

        sparklineLine(proxy) {
          const pts = (proxy.history && proxy.history.sparkline) || [];
          if (!pts.length) return '';
          const max = Math.max(...pts.filter(v => v > 0), 1);
          const stride = 100 / Math.max(pts.length - 1, 1);
          return pts.map((v, i) => {
            const x = (i * stride).toFixed(2);
            const y = v > 0 ? (32 - (v / max) * 28).toFixed(2) : 32;
            return x + ',' + y;
          }).join(' ');
        },

        sparklineArea(proxy) {
          const line = this.sparklineLine(proxy);
          if (!line) return '';
          return '0,32 ' + line + ' 100,32';
        },
```

- [ ] **Step 3: Reconcile `proxy.status` vs `proxy.online`**

The existing template references `proxy.status` (boolean) in many spots; the API returns the same value as `online`. The new card markup added in Task 11 uses `proxy.online`. Pick one canonical name and use it everywhere.

Recommended: standardize on `proxy.online` (matches the API).

Run: `grep -n "proxy\.status\b" web/templates/index.html`
Expected: a list of remaining occurrences (filter logic, possibly a `loadProxies()` mapping, possibly the badge-mode lookup).

For each occurrence:

- If it's an Alpine expression in the template (`:class="proxy.status ? ...`), change `proxy.status` → `proxy.online`.
- If it's inside the `dashboard()` JS (`p.status = data.online` or similar), delete the rename — the API already calls it `online`, so just stop renaming.
- If it's a sort or filter predicate (`proxy.status === true` etc.), update to `proxy.online`.

Re-run the grep after edits to confirm zero matches.

`proxy.name` and `proxy.latencyMs` already match the API and need no change.

- [ ] **Step 4: Run a full build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add web/templates/index.html
git commit -m "feat(web): Alpine helpers for heartbeat, sparkline, uptime"
```

---

## Task 13: Manual verification

**No file changes — verify the running app.**

- [ ] **Step 1: Build the binary**

Run: `go build -o /tmp/19health-redesign ./...`
Expected: clean build, `/tmp/19health-redesign` exists.

- [ ] **Step 2: Run with a real subscription**

Use whichever subscription URL you trust for development:

```bash
SUBSCRIPTION_URL='<your dev subscription>' \
HISTORY_WINDOW_HOURS=24 \
PROXY_CHECK_INTERVAL=60 \
/tmp/19health-redesign
```

`PROXY_CHECK_INTERVAL=60` makes the heartbeat populate visibly within minutes. Open the dashboard at `http://localhost:2112`.

- [ ] **Step 3: Walk the verification checklist**

Confirm each item works:

1. **Cold start** — page loads. Cards show `— · gathering data` and grey heartbeat cells. Sparkline is hidden until data arrives.
2. **First check arrives** — within `PROXY_CHECK_INTERVAL` seconds, at least one heartbeat cell turns green; latency text shows in amber.
3. **Sticky footer** — with N=1 proxy, the footer pins to the very bottom of the viewport (no awkward middle-of-page placement).
4. **Removed elements** — header has no Metrics/Health/API buttons; cards have no copy icon and no protocol pill; no top stats row.
5. **Search / filter / sort** — search box filters by name; All/Online/Offline filter buttons work; sort still works.
6. **Theme toggle** — dark↔light switch produces a coherent theme in both modes (no broken contrast).
7. **Public mode** — restart with `WEB_PUBLIC=true METRICS_PROTECTED=true METRICS_USERNAME=u METRICS_PASSWORD=p`. Confirm cards show only the name (no host/port).
8. **Badge mode** — load `http://localhost:2112/?badge=true&proxy=<stableId>` — pixel-identical inline pill, no heartbeat or sparkline.
9. **Existing routes still respond** — `curl -s http://localhost:2112/health` → `OK`; `curl -s http://localhost:2112/metrics | head -5` → Prometheus text.

- [ ] **Step 4: If anything fails, file it back into the plan**

Add a follow-up task at the end of this document describing what's broken and the fix; do not silently patch.

- [ ] **Step 5: Final commit (only if any small fixes were needed)**

If everything passed, no commit. Otherwise:

```bash
git add web/templates/index.html
git commit -m "fix(web): manual-verification adjustments"
```

---

## Spec coverage notes

- ✅ Visual design (palette, layout shell, card composition, sticky footer): Tasks 9, 11
- ✅ Removed UI elements (stats row, metrics/health/api buttons, copy button, protocol pill): Task 10
- ✅ Retained UI elements (auto-refresh, theme, search, filter, sort, public, basic-auth, badge): Tasks 9–12, verified in Task 13
- ✅ History store (Sample, Bucket, Snapshot, State, Config, NewStore, Append, Snapshot, Drop): Tasks 1–4
- ✅ Bucketing rules (ok/degraded/down/empty, threshold logic): Task 3
- ✅ Sparkline median per bucket, 0 means empty: Task 3
- ✅ Checker integration (Append per check, Drop on UpdateProxies): Task 6
- ✅ API contract (HistorySnapshot on `/api/v1/proxies` and `/api/v1/public/proxies`): Task 7
- ✅ OpenAPI doc update: Task 8
- ✅ Configuration (`HISTORY_WINDOW_HOURS`, `DEGRADED_LATENCY_MS`, defaults): Task 5
- ✅ Error handling (cold start, currently offline, sparkline gaps, churn, concurrency): Tasks 1–4 (logic), Task 12 (UI fallbacks), Task 13 (verified)
- ✅ Testing strategy (table-driven `history` tests + manual checklist): Tasks 1–4, Task 13
- ✅ Rollout: single PR off `main`; no migration, no required env vars. No dedicated task — just merge.
