package web

import (
	"bytes"
	"html"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"19health/checker"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func HealthUIHandler(proxyChecker *checker.ProxyChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proxies := proxyChecker.GetProxies()

		var online, offline int
		var totalLatency int64
		var latencyCount int

		for _, proxy := range proxies {
			status, latency, err := proxyChecker.GetProxyStatusByStableID(proxy.StableID)
			if err != nil {
				status = false
				latency = 0
			}

			if status {
				online++
				if latency > 0 {
					totalLatency += latency.Milliseconds()
					latencyCount++
				}
			} else {
				offline++
			}
		}

		avgLatency := int64(0)
		if latencyCount > 0 {
			avgLatency = totalLatency / int64(latencyCount)
		}

		var buf bytes.Buffer
		buf.WriteString("<!doctype html><html><head><meta charset=\"utf-8\" />")
		buf.WriteString("<title>19Health Health</title>")
		buf.WriteString("<style>body{font-family:Inter,system-ui,sans-serif;margin:24px;line-height:1.4;} table{border-collapse:collapse;} th,td{border:1px solid #ddd;padding:6px 10px;} th{background:#f5f5f5;text-align:left;} .online{color:#0a0;} .offline{color:#d00;}</style>")
		buf.WriteString("</head><body>")
		fmt.Fprintf(&buf, "<h1>19Health Health</h1><p><b>Total</b>: %d &nbsp; <b>Online</b>: %d &nbsp; <b>Offline</b>: %d &nbsp; <b>Avg Latency</b>: %d ms</p>",
			len(proxies), online, offline, avgLatency)

		buf.WriteString("<table><thead><tr><th>Name</th><th>Server</th><th>Status</th><th>Latency (ms)</th></tr></thead><tbody>")
		for _, proxy := range proxies {
			status, latency, err := proxyChecker.GetProxyStatusByStableID(proxy.StableID)
			if err != nil {
				status = false
				latency = 0
			}

			statusText := "offline"
			statusClass := "offline"
			if status {
				statusText = "online"
				statusClass = "online"
			}

			latMs := latency.Milliseconds()
			if latency <= 0 {
				latMs = 0
			}

			fmt.Fprintf(&buf,
				"<tr><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%d</td></tr>",
				html.EscapeString(proxy.Name),
				html.EscapeString(fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)),
				statusClass,
				statusText,
				latMs,
			)
		}
		buf.WriteString("</tbody></table>")

		buf.WriteString("<p style=\"color:#666; font-size:12px;\">Updated: " + html.EscapeString(time.Now().Format(time.RFC1123)) + "</p>")
		buf.WriteString("</body></html>")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

func MetricsUIHandler(registry *prometheus.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metricsHandler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		rec := httptest.NewRecorder()
		metricsHandler.ServeHTTP(rec, r)

		// Prometheus exposition is plain text; wrap it so the user gets a readable page.
		metricsBody := rec.Body.String()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(
			"<!doctype html><html><head><meta charset=\"utf-8\"/>" +
				"<title>19Health Metrics</title>" +
				"<style>body{font-family:Inter,system-ui,sans-serif;margin:24px;} pre{white-space:pre-wrap;word-break:break-word;background:#0b0f14;color:#dcdcdc;padding:16px;border-radius:8px;}</style>" +
				"</head><body><h1>Prometheus Metrics</h1><pre>" +
				html.EscapeString(metricsBody) +
				"</pre></body></html>",
		))
	}
}

