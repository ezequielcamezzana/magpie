package commands

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/api"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/config"
	"github.com/ezequielcamezzana/magpie/internal/server/cper"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/health"
	"github.com/ezequielcamezzana/magpie/internal/server/source/ecosystems"
	"github.com/ezequielcamezzana/magpie/internal/server/source/nvd"
	"github.com/ezequielcamezzana/magpie/internal/server/source/osv"
	"github.com/ezequielcamezzana/magpie/internal/server/source/vulncheck"
	"github.com/ezequielcamezzana/magpie/internal/server/updater"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"
)

func NewServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Run the HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			var handler slog.Handler
			opts := &slog.HandlerOptions{Level: cfg.LogLevel}
			if cfg.LogFormat == "json" {
				handler = slog.NewJSONHandler(os.Stderr, opts)
			} else {
				handler = slog.NewTextHandler(os.Stderr, opts)
			}
			logger := slog.New(handler)
			slog.SetDefault(logger)

			// Surface key config at startup so a missing NVD key (the usual cause
			// of slow collects) is obvious in the logs.
			logger.Info("starting",
				"nvd_api_key_set", cfg.NVDAPIKey != "",
				"vulncheck_api_key_set", cfg.VulnCheckAPIKey != "",
				"updater_enabled", cfg.UpdaterEnabled,
				"request_timeout", cfg.RequestTimeout)

			database, err := db.Open(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("open store %q: %w", cfg.DBPath, err)
			}
			defer database.Close()

			// Shared HTTP client that records every upstream call's outcome for
			// the per-source health dots.
			tracker := health.New()
			httpc := health.Client(tracker, logger)

			collectCfg := collect.Config{
				Store:             database,
				NVDAPIKey:         cfg.NVDAPIKey,
				MaxAge:            cfg.MaxAge,
				SourceBudget:      cfg.SourceBudget,
				EcosystemsFetcher: ecosystems.New(httpc),
				OSVFetcher:        osv.New(httpc),
				NVDFetcher:        nvd.New(httpc, cfg.NVDAPIKey),
				CPER:              cper.Stage,
			}
			// WHY: VulnCheck requires a token; without it CPER would just spam
			// 401s, so wire its fetcher only when the key is set (CPER stays off).
			if cfg.VulnCheckAPIKey != "" {
				collectCfg.CVEFetcher = vulncheck.New(httpc, cfg.VulnCheckAPIKey)
			}

			r := chi.NewRouter()
			api.Mount(r, api.Deps{Config: collectCfg, Logger: logger, Version: Version, RequestTimeout: cfg.RequestTimeout, Health: tracker})

			srv := &http.Server{Addr: cfg.Listen, Handler: r}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if cfg.UpdaterEnabled {
				w := updater.New(collectCfg, logger, cfg.UpdaterInterval, cfg.UpdaterStaleTime, cfg.UpdaterBatch)
				go w.Run(ctx)
			}

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
			return nil
		},
	}
}
