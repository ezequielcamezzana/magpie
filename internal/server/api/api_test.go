package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ezequielcamezzana/magpie/internal/server/api"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubFetchErr controls whether the stub fetcher returns an error (partial failure).
var stubFetchErr error

type stubFetcher struct{}

func (stubFetcher) Fetch(ctx context.Context, spurl string) (collect.Component, *collect.Repository, []collect.VulnRecord, error) {
	if stubFetchErr != nil {
		return collect.Component{}, nil, nil, stubFetchErr
	}
	return collect.Component{Name: "chalk", SPURL: spurl}, nil, nil, nil
}

// noopOSV is an OSVFetcher that returns nothing, so tests expecting empty
// Errors don't fail on the stage-2 "not registered" error.
type noopOSV struct{}

func (noopOSV) Query(ctx context.Context, q purl.OSVQuery) ([]collect.VulnRecord, error) {
	return nil, nil
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err, "db.Open")
	t.Cleanup(func() { database.Close() })

	r := chi.NewRouter()
	api.Mount(r, api.Deps{
		Config: collect.Config{Store: database, EcosystemsFetcher: stubFetcher{}, OSVFetcher: noopOSV{}},
		Logger: slog.Default(),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestCollectOK(t *testing.T) {
	stubFetchErr = nil
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var res collect.Result
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	require.NotNil(t, res.Component)
	assert.Equal(t, "chalk", res.Component.Name)
	assert.Empty(t, res.Errors)
}

func TestCollectSpurlParam(t *testing.T) {
	stubFetchErr = nil
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?spurl=pkg:npm/chalk")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCollectMissingParam(t *testing.T) {
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCollectInvalidPurl(t *testing.T) {
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?purl=not-a-purl")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSPADoesNotShadowAPI(t *testing.T) {
	stubFetchErr = nil
	srv := newServer(t)

	// GET / serves the landing site.
	resp, err := http.Get(srv.URL + "/")
	require.NoError(t, err)
	siteBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "html")
	assert.Contains(t, string(siteBody), "magpie")

	// GET /app serves the embedded HTML.
	resp, err = http.Get(srv.URL + "/app")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "magpie")

	// GET /app/static/app.css serves the asset with a css content-type.
	resp, err = http.Get(srv.URL + "/app/static/app.css")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "css")

	// GET /collect still returns JSON — the wildcard doesn't shadow it.
	resp, err = http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var res collect.Result
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	require.NotNil(t, res.Component)
	assert.Equal(t, "chalk", res.Component.Name)
}

func TestCollectPartialFailureIs200(t *testing.T) {
	stubFetchErr = errors.New("upstream boom")
	defer func() { stubFetchErr = nil }()
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var res collect.Result
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	assert.NotEmpty(t, res.Errors, "want non-empty Errors on partial failure")
}
