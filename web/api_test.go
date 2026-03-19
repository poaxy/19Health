package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"19health/checker"
	"19health/models"
)

func newTestProxyChecker() *checker.ProxyChecker {
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

	return checker.NewProxyChecker(
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

func TestAPIStatusHandlerFallbackWhenNoMetrics(t *testing.T) {
	pc := newTestProxyChecker()
	handler := APIStatusHandler(pc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response struct {
		Success bool           `json:"success"`
		Data    StatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Success {
		t.Fatalf("expected success response")
	}
	if response.Data.Total != 1 || response.Data.Offline != 1 || response.Data.Online != 0 {
		t.Fatalf("unexpected status summary: %+v", response.Data)
	}
}
