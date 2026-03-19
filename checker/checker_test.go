package checker

import (
	"sync"
	"testing"
	"time"

	"19health/metrics"
	"19health/models"
)

var initMetricsOnce sync.Once

func newTestProxyChecker() *ProxyChecker {
	proxies := []*models.ProxyConfig{
		{
			Name:     "p1",
			Protocol: "vmess",
			Server:   "1.1.1.1",
			Port:     443,
			UUID:     "11111111-1111-1111-1111-111111111111",
			StableID: "stable-1",
			Index:    0,
		},
	}

	return NewProxyChecker(
		proxies,
		10000,
		"http://127.0.0.1",
		1,
		"http://127.0.0.1",
		"http://127.0.0.1",
		1,
		1024,
		"status",
		"",
		2,
	)
}

func TestGetProxiesReturnsCopy(t *testing.T) {
	pc := newTestProxyChecker()

	first := pc.GetProxies()
	first[0] = nil

	second := pc.GetProxies()
	if second[0] == nil {
		t.Fatalf("expected GetProxies to return a copy, got shared slice")
	}
}

func TestGetProxyStatusByStableID(t *testing.T) {
	initMetricsOnce.Do(func() {
		metrics.InitMetrics("")
	})
	pc := newTestProxyChecker()
	proxy := pc.GetProxies()[0]

	key := buildMetricKey(proxy)
	pc.currentMetrics.Store(key, true)
	pc.latencyMetrics.Store(key, 42*time.Millisecond)

	status, latency, err := pc.GetProxyStatusByStableID("stable-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status {
		t.Fatalf("expected status=true")
	}
	if latency != 42*time.Millisecond {
		t.Fatalf("expected 42ms latency, got %v", latency)
	}
}

func TestGetProxyStatusByStableIDNotFound(t *testing.T) {
	pc := newTestProxyChecker()
	if _, _, err := pc.GetProxyStatusByStableID("missing"); err == nil {
		t.Fatalf("expected error for missing stable ID")
	}
}
