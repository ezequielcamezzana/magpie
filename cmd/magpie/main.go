// Command magpie es el server HTTP del pipeline de recolección.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ezequielcamezzana/magpie/httpapi"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/cper"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/source/ecosystems"
	"github.com/ezequielcamezzana/magpie/internal/server/source/osv"

	"github.com/go-chi/chi/v5"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var handler slog.Handler
	if os.Getenv("MAGPIE_LOG") == "json" {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	addr := getenv("MAGPIE_ADDR", ":8080")
	dbPath := getenv("MAGPIE_DB_PATH", "./magpie.db")
	nvdKey := os.Getenv("NVD_API_KEY")

	maxAge := 24 * time.Hour
	if raw := os.Getenv("MAGPIE_MAX_AGE"); raw != "" {
		if d, err := time.ParseDuration(raw); err != nil {
			logger.Warn("invalid MAGPIE_MAX_AGE, using default", "value", raw, "default", maxAge)
		} else {
			maxAge = d
		}
	}

	requestTimeout := 30 * time.Second
	if raw := os.Getenv("MAGPIE_REQUEST_TIMEOUT"); raw != "" {
		if d, err := time.ParseDuration(raw); err != nil {
			logger.Warn("invalid MAGPIE_REQUEST_TIMEOUT, using default", "value", raw, "default", requestTimeout)
		} else {
			requestTimeout = d
		}
	}

	database, err := db.Open(dbPath)
	if err != nil {
		logger.Error("open store", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer database.Close()

	cfg := collect.Config{
		Store:             database,
		NVDAPIKey:         nvdKey,
		MaxAge:            maxAge,
		EcosystemsFetcher: ecosystems.New(nil, logger),
		OSVFetcher:        osv.New(nil, logger),
		CPER:              cper.Stage,
	}

	r := chi.NewRouter()
	httpapi.Mount(r, httpapi.Deps{Config: cfg, Logger: logger, Version: version, RequestTimeout: requestTimeout})

	srv := &http.Server{Addr: addr, Handler: r}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
	}
	logger.Info("stopped")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
