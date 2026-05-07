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
