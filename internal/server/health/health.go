// Package health tracks the recent outcome of upstream calls (NVD, OSV,
// ecosyste.ms) so the UI can show a live per-source status dot. State is kept
// in memory — a live signal, not history — and repopulates within a few
// requests after a restart.
package health

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// window is how many recent samples per source feed the status.
const window = 10

// slowThreshold: average latency above this marks a source "slow".
const slowThreshold = 3 * time.Second

// Sources is the fixed set we report, so the UI always shows three dots.
var Sources = []string{"ecosyste.ms", "osv", "nvd", "vulncheck"}

type sample struct {
	status int
	ms     int64
}

// Tracker holds a rolling window of recent samples per source.
type Tracker struct {
	mu      sync.Mutex
	samples map[string][]sample
}

func New() *Tracker {
	return &Tracker{samples: make(map[string][]sample)}
}

// Record appends one upstream result for source, keeping only the last window.
func (t *Tracker) Record(source string, status int, d time.Duration) {
	if source == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := append(t.samples[source], sample{status: status, ms: d.Milliseconds()})
	if len(s) > window {
		s = s[len(s)-window:]
	}
	t.samples[source] = s
}

// SourceHealth is the derived status for one source.
type SourceHealth struct {
	Status  string `json:"status"` // ok | slow | bad | unknown
	AvgMs   int64  `json:"avgMs"`
	Samples int    `json:"samples"`
}

// Snapshot derives the current status for every known source.
func (t *Tracker) Snapshot() map[string]SourceHealth {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]SourceHealth, len(Sources))
	for _, src := range Sources {
		out[src] = derive(t.samples[src])
	}
	return out
}

// derive applies the status rules: any 5xx → bad, else slow if the average
// latency exceeds slowThreshold, else ok; no samples → unknown.
func derive(samples []sample) SourceHealth {
	if len(samples) == 0 {
		return SourceHealth{Status: "unknown"}
	}
	var total int64
	bad := false
	for _, s := range samples {
		total += s.ms
		if s.status >= 500 {
			bad = true
		}
	}
	avg := total / int64(len(samples))
	status := "ok"
	switch {
	case bad:
		status = "bad"
	case avg > slowThreshold.Milliseconds():
		status = "slow"
	}
	return SourceHealth{Status: status, AvgMs: avg, Samples: len(samples)}
}

// Client returns an *http.Client whose transport records every request to a
// known source (NVD, OSV, ecosyste.ms) into t and logs its outcome through
// logger. Pass it to the source fetchers — this is the single place upstream
// errors are logged, so the three clients log uniformly.
func Client(t *Tracker, logger *slog.Logger) *http.Client {
	return &http.Client{Transport: &transport{base: http.DefaultTransport, tracker: t, logger: logger}}
}

type transport struct {
	base    http.RoundTripper
	tracker *Tracker
	logger  *slog.Logger
}

func (rt *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	source := sourceForHost(req.URL.Host)
	if source == "" {
		return rt.base.RoundTrip(req)
	}
	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	took := time.Since(start)

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	if err != nil {
		status = 599 // transport failure counts as bad (>= 500)
	}
	rt.tracker.Record(source, status, took)
	rt.log(source, req.URL.String(), status, took, err)
	return resp, err
}

// log emits one normalized line per upstream call. Transport failures (timeouts,
// hangs) and 4xx/5xx warn; a 404 is a benign "not found" (package/CVE absent),
// so it stays at debug alongside successful calls. Debug also carries latency
// for measuring slow sources (MAGPIE_LOG_LEVEL=debug).
func (rt *transport) log(source, url string, status int, took time.Duration, err error) {
	if rt.logger == nil {
		return
	}
	ms := took.Milliseconds()
	switch {
	case err != nil:
		rt.logger.Warn("upstream request failed", "source", source, "url", url, "ms", ms, "err", err)
	case status >= 400 && status != http.StatusNotFound:
		rt.logger.Warn("upstream error", "source", source, "url", url, "status", status, "ms", ms)
	default:
		rt.logger.Debug("upstream ok", "source", source, "url", url, "status", status, "ms", ms)
	}
}

func sourceForHost(host string) string {
	switch {
	case strings.Contains(host, "nvd.nist.gov"):
		return "nvd"
	case strings.Contains(host, "osv.dev"):
		return "osv"
	case strings.Contains(host, "ecosyste.ms"):
		return "ecosyste.ms"
	case strings.Contains(host, "vulncheck.com"):
		return "vulncheck"
	}
	return ""
}
