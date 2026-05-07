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

// Drop removes a proxy's buffer. Safe to call for missing IDs.
func (s *Store) Drop(stableID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buffers, stableID)
}
