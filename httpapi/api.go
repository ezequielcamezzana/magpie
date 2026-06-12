// Package httpapi expone el pipeline magpie.Collect sobre HTTP con chi.
package httpapi

import (
	"log/slog"
	"time"

	"github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/web"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Deps struct {
	Config         magpie.Config
	Logger         *slog.Logger
	Version        string
	RequestTimeout time.Duration
}

// Mount instala middleware y rutas sobre r.
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

	// WHY: catch-all al final — chi prioriza las rutas explícitas (/collect)
	// sobre el wildcard, así que la SPA no las pisa.
	r.Handle("/*", web.Handler(deps.Version))
}
