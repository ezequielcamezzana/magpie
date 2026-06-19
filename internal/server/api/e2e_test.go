package api_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/api"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/source/ecosystems"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUpstream serves the real ecosyste.ms fixtures by path and counts hits.
// The real client builds {BaseURL}{registry}/packages/{name}, so we match the
// final path against the corresponding fixture.
//
// WHY: we read the existing fixtures via a cross-package relative path
// (../source/ecosystems/testdata) instead of duplicating them in api/testdata;
// the path resolves because go test runs with cwd at the package dir.
func fakeUpstream(t *testing.T, calls *int64) *httptest.Server {
	t.Helper()
	byPath := map[string]string{
		"/npmjs.org/packages/chalk":    "../source/ecosystems/testdata/chalk.json",
		"/npmjs.org/packages/minimist": "../source/ecosystems/testdata/minimist.json",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(calls, 1)
		file, ok := byPath[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("read fixture %s: %v", file, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// realEcosystems builds the REAL ecosyste.ms client pointed at the fake
// upstream.
func realEcosystems(upstreamURL string) *ecosystems.Client {
	c := ecosystems.New(nil)
	// BaseURL is concatenated with "{registry}/packages/{name}", so the
	// trailing slash makes the final URL /{registry}/packages/{name}.
	c.BaseURL = upstreamURL + "/"
	return c
}

func newE2EServer(t *testing.T, db collect.Store, eco collect.EcosystemsFetcher, maxAge time.Duration) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	api.Mount(r, api.Deps{
		Config: collect.Config{Store: db, MaxAge: collect.UniformMaxAge(maxAge), EcosystemsFetcher: eco, OSVFetcher: noopOSV{}},
		Logger: slog.Default(),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func openMemStore(t *testing.T) collect.Store {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err, "db.Open")
	t.Cleanup(func() { database.Close() })
	return database
}

func TestE2ECollectChalk(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	srv := newE2EServer(t, openMemStore(t), realEcosystems(upstream.URL), time.Hour)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var res collect.Result
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	require.NotNil(t, res.Component)
	assert.Equal(t, "chalk", res.Component.Name)
	assert.NotNil(t, res.Repository)
	assert.Empty(t, res.Errors)
}

func TestE2ECacheHit(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	// Same in-memory store between both requests → the second must be a cache hit.
	srv := newE2EServer(t, openMemStore(t), realEcosystems(upstream.URL), time.Hour)

	for i := 0; i < 2; i++ {
		resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d", i)
	}

	assert.Equal(t, int64(1), atomic.LoadInt64(&calls), "second request should come from the cache")
}

func TestE2ECollectMinimist(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	db := openMemStore(t)
	srv := newE2EServer(t, db, realEcosystems(upstream.URL), time.Hour)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/minimist@1.2.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var res collect.Result
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	require.NotNil(t, res.Component)
	assert.Equal(t, "minimist", res.Component.Name)

	// Stage 1 persists the raw vulns even though Groups doesn't show them yet.
	got, err := db.GetVulns(context.Background(), collect.SourceEcosystems, "pkg:npm/minimist")
	require.NoError(t, err, "GetVulns")
	require.True(t, got.Found, "GetVulns Found")
	assert.Len(t, got.Value, 3)
}
