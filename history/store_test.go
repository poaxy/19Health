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
