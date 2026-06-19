package updater

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// stubEco records which spurls it was asked to fetch.
type stubEco struct {
	fetched []string
}

func (s *stubEco) Fetch(ctx context.Context, spurl string) (collect.Component, *collect.Repository, []collect.VulnRecord, error) {
	s.fetched = append(s.fetched, spurl)
	// Mirror the real client: stamp FetchedAt so a refreshed package stops
	// being stale (the self-draining property the updater relies on).
	return collect.Component{SPURL: spurl, Name: spurl, FetchedAt: time.Now().UTC()}, nil, nil, nil
}

type stubOSV struct{}

func (stubOSV) Query(ctx context.Context, q purl.OSVQuery) ([]collect.VulnRecord, error) {
	return nil, nil
}

type errOSV struct{}

func (errOSV) Query(ctx context.Context, q purl.OSVQuery) ([]collect.VulnRecord, error) {
	return nil, errors.New("osv down")
}

func newWorker(t *testing.T, eco collect.EcosystemsFetcher, batch int) *Worker {
	t.Helper()
	store, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	cfg := collect.Config{Store: store, EcosystemsFetcher: eco, OSVFetcher: stubOSV{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, logger, time.Minute, 12*time.Hour, batch)
}

func TestNewZeroesMaxAge(t *testing.T) {
	cfg := collect.Config{MaxAge: collect.DefaultMaxAge()}
	w := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Minute, 12*time.Hour, 1)
	assert.Equal(t, collect.MaxAge{}, w.forceCfg.MaxAge, "force config must run without cache")
}

func TestTickRefreshesOldestStaleUpToBatch(t *testing.T) {
	eco := &stubEco{}
	w := newWorker(t, eco, 2)
	ctx := context.Background()
	now := time.Now().UTC()

	put := func(spurl string, age time.Duration) {
		require.NoError(t, w.store.PutComponent(ctx, collect.Component{SPURL: spurl, FetchedAt: now.Add(-age)}))
	}
	put("pkg:npm/fresh", 1*time.Hour)
	put("pkg:npm/old", 13*time.Hour)
	put("pkg:npm/oldest", 30*time.Hour)

	w.tick(ctx)

	// Batch of 2: the two oldest stale packages, oldest first; fresh untouched.
	assert.Equal(t, []string{"pkg:npm/oldest", "pkg:npm/old"}, eco.fetched)

	// Both refreshed, so nothing remains stale.
	stale, err := w.store.StaleComponents(ctx, now.Add(-12*time.Hour), 10)
	require.NoError(t, err)
	assert.Empty(t, stale)
}

func TestTickKeepsStaleWhenCoreSourceFails(t *testing.T) {
	store, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	cfg := collect.Config{Store: store, EcosystemsFetcher: &stubEco{}, OSVFetcher: errOSV{}}
	w := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Minute, 12*time.Hour, 1)

	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, store.PutComponent(ctx, collect.Component{SPURL: "pkg:npm/axios", FetchedAt: now.Add(-30 * time.Hour)}))

	w.tick(ctx)

	// OSV is a core source, so its failure must NOT advance fetched_at — the
	// package stays stale and gets retried next cycle.
	stale, err := store.StaleComponents(ctx, now.Add(-12*time.Hour), 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"pkg:npm/axios"}, stale, "core failure keeps the package stale")
}

func TestTickIdleWhenNothingStale(t *testing.T) {
	eco := &stubEco{}
	w := newWorker(t, eco, 1)
	ctx := context.Background()

	require.NoError(t, w.store.PutComponent(ctx, collect.Component{SPURL: "pkg:npm/fresh", FetchedAt: time.Now().UTC()}))

	w.tick(ctx)

	assert.Empty(t, eco.fetched, "no fetch when nothing is stale")
}
