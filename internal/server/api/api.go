// Package api exposes the collect.Collect pipeline over HTTP with chi.
package api

import (
	"log/slog"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/web"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Deps struct {
	Config         collect.Config
	Logger         *slog.Logger
	Version        string
	RequestTimeout time.Duration
}

// Mount installs middleware and routes on r.
func Mount(r chi.Router, deps Deps) {
	timeout := deps.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(timeout))

	r.Get("/collect", handleCollect(deps))
	r.Get("/vulnerabilities", handleVulnerabilities(deps))
	r.Get("/vulnerability", handleVulnerability(deps))
	r.Get("/components", handleComponents(deps))
	r.Get("/component", handleComponent(deps))
	r.Get("/cpes", handleCPEs(deps))

	// WHY: catch-all goes last — chi prioritizes explicit routes (/collect)
	// over the wildcard, so the SPA doesn't shadow them.
	r.Handle("/*", web.Handler(deps.Version))
}
