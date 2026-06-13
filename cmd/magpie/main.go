// Command magpie is the HTTP server for the collection pipeline.
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
	"github.com/ezequielcamezzana/magpie/internal/server/config"
	"github.com/ezequielcamezzana/magpie/internal/server/cper"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/source/ecosystems"
	"github.com/ezequielcamezzana/magpie/internal/server/source/osv"

	"github.com/go-chi/chi/v5"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open store", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer database.Close()

	collectCfg := collect.Config{
		Store:             database,
		NVDAPIKey:         cfg.NVDAPIKey,
		MaxAge:            cfg.MaxAge,
		EcosystemsFetcher: ecosystems.New(nil, logger),
		OSVFetcher:        osv.New(nil, logger),
		CPER:              cper.Stage,
	}

	r := chi.NewRouter()
	httpapi.Mount(r, httpapi.Deps{Config: collectCfg, Logger: logger, Version: version, RequestTimeout: cfg.RequestTimeout})

	srv := &http.Server{Addr: cfg.Listen, Handler: r}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", cfg.Listen)
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
