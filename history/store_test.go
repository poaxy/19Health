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
	// Last sample is offline so the proxy is "currently offline"; DownSince
	// points to the oldest contiguous offline sample, which here is the
	// only offline sample (the incident itself).
	if snap.DownSince == nil || !snap.DownSince.Equal(incident) {
		t.Errorf("DownSince = %v, want %v", snap.DownSince, incident)
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
