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
		// Capture the previous timestamp before Collect overwrites it, so we
		// can roll it back if the refresh was incomplete (see below).
		prev, _ := w.store.GetComponent(ctx, spurl)

		res, err := collect.Collect(ctx, spurl, w.forceCfg)
		if err != nil {
			w.logger.Warn("updater collect failed", "spurl", spurl, "err", err)
			continue
		}

		// vulns = distinct vulnerabilities found (one per canonical ID).
		if coreSourceFailed(res.Errors) {
			// A core source (ecosyste.ms / OSV) failed, so the package's own
			// metadata and vulns may be incomplete. Roll fetched_at back to its
			// previous value so the package stays "stale" and gets retried next
			// cycle instead of counting as freshly updated.
			//
			// WHY only core sources: NVD/CPER errors are routine — NVD returns
			// transient 503s and rate-limits under the updater's load. Blocking
			// on those would loop the updater on the same few packages forever
			// and never drain the stale set. So we keep whatever data we got and
			// only retry when the essential fetch failed.
			w.revertTimestamp(ctx, prev, res.Component)
			w.logger.Warn("updater refresh incomplete, will retry",
				"spurl", spurl, "vulns", len(res.Groups), "errors", sourceErrors(res.Errors))
			continue
		}
		if len(res.Errors) > 0 {
			w.logger.Warn("updater refreshed with source errors",
				"spurl", spurl, "vulns", len(res.Groups), "errors", sourceErrors(res.Errors))
			continue
		}
		w.logger.Info("updater refreshed", "spurl", spurl, "vulns", len(res.Groups))
	}
}

// revertTimestamp re-stores the component keeping the freshest data available
// but with its previous fetched_at, so the package remains eligible for the
// updater's next pass.
func (w *Worker) revertTimestamp(ctx context.Context, prev collect.StoreResult[collect.Component], fresh *collect.Component) {
	if !prev.Found {
		return
	}
	c := prev.Value
	if fresh != nil {
		c = *fresh
	}
	c.FetchedAt = prev.FetchedAt
	_ = w.store.PutComponent(ctx, c)
}

// coreSourceFailed reports whether a primary source (ecosyste.ms or OSV) errored.
func coreSourceFailed(errs []collect.SourceError) bool {
	for _, e := range errs {
		if e.Source == collect.SourceEcosystems || e.Source == collect.SourceOSV {
			return true
		}
	}
	return false
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
