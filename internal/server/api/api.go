// Package api exposes the collect.Collect pipeline over HTTP with chi.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/health"
	"github.com/ezequielcamezzana/magpie/internal/server/ui"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Deps struct {
	Config         collect.Config
	Logger         *slog.Logger
	Version        string
	RequestTimeout time.Duration
	Health         *health.Tracker
}

// Mount installs middleware and routes on r.
func Mount(r chi.Router, deps Deps) {
	timeout := deps.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	// WHY http.TimeoutHandler over chi's middleware.Timeout: chi writes a 504 in
	// a defer even when the handler already wrote a response, producing
	// "superfluous WriteHeader" noise on slow upstreams (e.g. NVD). TimeoutHandler
	// buffers the response and writes exactly once — the result or the timeout.
	r.Use(func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, `{"error":"request timed out"}`)
	})

	r.Get("/collect", handleCollect(deps))
	r.Get("/bundle", handleBundle(deps))
	r.Get("/vulnerabilities", handleVulnerabilities(deps))
	r.Get("/vulnerability", handleVulnerability(deps))
	r.Get("/components", handleComponents(deps))
	r.Get("/component", handleComponent(deps))
	r.Get("/cpes", handleCPEs(deps))
	r.Get("/metrics", handleMetrics(deps))

	// WHY: the SPA is mounted under /app so explicit API routes (/collect)
	// stay at the root without the wildcard shadowing them.
	r.Mount("/app", ui.Handler(deps.Version))
	// Public landing: / serves the marketing site (what magpie is, how it
	// works); the app lives under /app.
	r.Get("/", ui.Site(deps.Version).ServeHTTP)
}
