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
