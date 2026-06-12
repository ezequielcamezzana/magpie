package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ezequielcamezzana/magpie/httpapi"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
	"github.com/ezequielcamezzana/magpie/store/sqlite"

	"github.com/go-chi/chi/v5"
)

// stubFetchErr controla si el stub fetcher devuelve error (partial failure).
var stubFetchErr error

type stubFetcher struct{}

func (stubFetcher) Fetch(ctx context.Context, spurl string) (collect.Component, *collect.Repository, []collect.VulnRecord, error) {
	if stubFetchErr != nil {
		return collect.Component{}, nil, nil, stubFetchErr
	}
	return collect.Component{Name: "chalk", SPURL: spurl}, nil, nil, nil
}

// noopOSV es un OSVFetcher que no devuelve nada, para que los tests que esperan
// Errors vacío no fallen por el "not registered" de stage 2.
type noopOSV struct{}

func (noopOSV) Query(ctx context.Context, q purl.OSVQuery) ([]collect.VulnRecord, error) {
	return nil, nil
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	r := chi.NewRouter()
	httpapi.Mount(r, httpapi.Deps{
		Config: collect.Config{Store: db, EcosystemsFetcher: stubFetcher{}, OSVFetcher: noopOSV{}},
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
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var res collect.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Component == nil || res.Component.Name != "chalk" {
		t.Fatalf("Component.Name = %+v, want chalk", res.Component)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Errors = %v, want empty", res.Errors)
	}
}

func TestCollectSpurlParam(t *testing.T) {
	stubFetchErr = nil
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?spurl=pkg:npm/chalk")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestCollectMissingParam(t *testing.T) {
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCollectInvalidPurl(t *testing.T) {
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?purl=not-a-purl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSPADoesNotShadowAPI(t *testing.T) {
	stubFetchErr = nil
	srv := newServer(t)

	// GET / sirve el HTML embebido.
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "magpie") {
		t.Fatalf("GET / body does not contain \"magpie\"")
	}

	// GET /static/app.css sirve el asset con content-type css.
	resp, err = http.Get(srv.URL + "/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /static/app.css status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Fatalf("GET /static/app.css Content-Type = %q, want css", ct)
	}

	// GET /collect sigue devolviendo JSON — el wildcard no lo pisa.
	resp, err = http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /collect status = %d, want 200", resp.StatusCode)
	}
	var res collect.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("GET /collect: decode JSON: %v", err)
	}
	if res.Component == nil || res.Component.Name != "chalk" {
		t.Fatalf("GET /collect Component = %+v, want chalk", res.Component)
	}
}

func TestCollectPartialFailureIs200(t *testing.T) {
	stubFetchErr = errors.New("upstream boom")
	defer func() { stubFetchErr = nil }()
	srv := newServer(t)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var res collect.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) == 0 {
		t.Fatal("Errors = empty, want non-empty on partial failure")
	}
}
