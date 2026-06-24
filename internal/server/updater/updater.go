// Package updater keeps cached package data fresh. A background worker picks
// the oldest stale packages on a fixed interval and re-runs the collect
// pipeline for each — without the cache, so every source is refetched.
package updater

import (
	"context"
	"log/slog"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

// Worker refreshes the oldest stale packages on each tick.
type Worker struct {
	store     collect.Store
	forceCfg  collect.Config
	logger    *slog.Logger
	interval  time.Duration
	staleTime time.Duration
	batch     int
}

// New builds a Worker. collectCfg is the same config the HTTP API uses; the
// worker clones it with MaxAge zeroed so Collect runs without the cache.
//
// WHY: collect.IsFresh treats maxAge <= 0 as "never fresh", so zeroing MaxAge
// makes every stage refetch from its source instead of reading the store.
func New(collectCfg collect.Config, logger *slog.Logger, interval, staleTime time.Duration, batch int) *Worker {
	forceCfg := collectCfg
	forceCfg.MaxAge = collect.MaxAge{}
	return &Worker{
		store:     collectCfg.Store,
		forceCfg:  forceCfg,
		logger:    logger,
		interval:  interval,
		staleTime: staleTime,
		batch:     batch,
	}
}

// Run refreshes a batch of stale packages every interval until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.logger.Info("updater started",
		"interval", w.interval, "stale_time", w.staleTime, "batch", w.batch)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("updater stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick refreshes the oldest stale packages. A failed package is logged and
// swallowed — the worker never dies on one bad package.
func (w *Worker) tick(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-w.staleTime)

	spurls, err := w.store.StaleComponents(ctx, cutoff, w.batch)
	if err != nil {
		w.logger.Error("updater pick failed", "err", err)
		return
	}
	if len(spurls) == 0 {
		w.logger.Debug("updater idle: nothing stale")
		return
	}

	for _, spurl := range spurls {
		res, err := collect.Collect(ctx, spurl, w.forceCfg)
		if err != nil {
			w.logger.Warn("updater collect failed", "spurl", spurl, "err", err)
			continue
		}

		// Always advance fetched_at so the package drains from the stale set,
		// whatever the sources returned. A source that only served cached data
		// doesn't re-store the component, so we stamp it here — otherwise the
		// package would be re-picked every tick (the dotenv-sync loop). Source
		// errors are logged, not retried: retrying immediately just hammers a
		// source that's already failing.
		w.stampFresh(ctx, spurl, res.Component)
		if len(res.Errors) > 0 {
			w.logger.Warn("updater refreshed with source errors",
				"spurl", spurl, "vulns", len(res.Groups), "errors", sourceErrors(res.Errors))
			continue
		}
		w.logger.Info("updater refreshed", "spurl", spurl, "vulns", len(res.Groups))
	}
}

// stampFresh re-stores the component with fetched_at = now so a processed package
// drains from the stale set. It keeps the freshest metadata available (the
// collect result, else the stored component) so a served-cached refresh doesn't
// wipe the existing row.
func (w *Worker) stampFresh(ctx context.Context, spurl string, fresh *collect.Component) {
	c := collect.Component{SPURL: spurl}
	if fresh != nil {
		c = *fresh
	} else if r, _ := w.store.GetComponent(ctx, spurl); r.Found {
		c = r.Value
	}
	// WARNING: stamp the row we actually picked, not fresh.SPURL. Collect
	// normalizes the coord via purl.Strip (case-folded for cargo/npm/…), so a
	// legacy non-normalized key like pkg:cargo/Deno is refreshed under
	// pkg:cargo/deno — leaving the picked row stale and re-picked every tick.
	c.SPURL = spurl
	c.FetchedAt = time.Now().UTC()
	_ = w.store.PutComponent(ctx, c)
}

// sourceErrors flattens per-source errors into "source: message" strings so
// the log shows which source failed and why.
func sourceErrors(errs []collect.SourceError) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Source + ": " + e.Err.Error()
	}
	return out
}
