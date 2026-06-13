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
	"github.com/ezequielcamezzana/magpie/internal/server/source/ecosystems"
	"github.com/ezequielcamezzana/magpie/internal/server/source/osv"

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
			if cfg.LogFormat == "json" {
				handler = slog.NewJSONHandler(os.Stderr, nil)
			} else {
				handler = slog.NewTextHandler(os.Stderr, nil)
			}
			logger := slog.New(handler)
			slog.SetDefault(logger)

			database, err := db.Open(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("open store %q: %w", cfg.DBPath, err)
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
			api.Mount(r, api.Deps{Config: collectCfg, Logger: logger, Version: Version, RequestTimeout: cfg.RequestTimeout})

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
			return nil
		},
	}
}
