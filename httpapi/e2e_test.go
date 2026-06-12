package httpapi_test

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

	"github.com/ezequielcamezzana/magpie/httpapi"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/source/ecosystems"
	"github.com/ezequielcamezzana/magpie/store/sqlite"

	"github.com/go-chi/chi/v5"
)

// fakeUpstream sirve los fixtures reales de ecosyste.ms por path y cuenta hits.
// El client real arma {BaseURL}{registry}/packages/{name}, así que matcheamos
// el path final contra el fixture correspondiente.
//
// WHY: leemos los fixtures existentes con path relativo cruzado
// (../source/ecosystems/testdata) en vez de duplicarlos en httpapi/testdata;
// el path resuelve porque go test corre con cwd en el dir del package.
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

// useRealEcosystems registra el cliente ecosyste.ms REAL apuntado al upstream
// fake y restaura el stub de api_test.go al terminar.
func useRealEcosystems(t *testing.T, upstreamURL string) {
	t.Helper()
	collect.RegisterEcosystemsFetcher(func(httpc *http.Client, logger *slog.Logger) collect.EcosystemsFetcher {
		c := ecosystems.New(httpc, logger)
		// BaseURL se concatena con "{registry}/packages/{name}", por eso el
		// trailing slash deja la URL final en /{registry}/packages/{name}.
		c.BaseURL = upstreamURL + "/"
		return c
	})
	t.Cleanup(func() {
		collect.RegisterEcosystemsFetcher(func(httpc *http.Client, logger *slog.Logger) collect.EcosystemsFetcher {
			return stubFetcher{}
		})
	})
}

func newE2EServer(t *testing.T, db collect.Store, maxAge time.Duration) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	httpapi.Mount(r, httpapi.Deps{
		Config: collect.Config{Store: db, MaxAge: maxAge},
		Logger: slog.Default(),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func openMemStore(t *testing.T) collect.Store {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestE2ECollectChalk(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	useRealEcosystems(t, upstream.URL)
	srv := newE2EServer(t, openMemStore(t), time.Hour)

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
		t.Fatalf("Component = %+v, want name=chalk", res.Component)
	}
	if res.Repository == nil {
		t.Fatal("Repository = nil, want non-nil")
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Errors = %v, want empty", res.Errors)
	}
}

func TestE2ECacheHit(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	useRealEcosystems(t, upstream.URL)
	// Mismo store in-memory entre ambos requests → el segundo debe ser cache hit.
	srv := newE2EServer(t, openMemStore(t), time.Hour)

	for i := 0; i < 2; i++ {
		resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/chalk@5.0.0")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (segundo request debe venir del cache)", got)
	}
}

func TestE2ECollectMinimist(t *testing.T) {
	var calls int64
	upstream := fakeUpstream(t, &calls)
	useRealEcosystems(t, upstream.URL)
	db := openMemStore(t)
	srv := newE2EServer(t, db, time.Hour)

	resp, err := http.Get(srv.URL + "/collect?purl=pkg:npm/minimist@1.2.0")
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
	if res.Component == nil || res.Component.Name != "minimist" {
		t.Fatalf("Component = %+v, want name=minimist", res.Component)
	}

	// Stage 1 persiste las vulns crudas aunque Groups todavía no las muestre.
	got, err := db.GetVulns(context.Background(), collect.SourceEcosystems, "pkg:npm/minimist")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	if !got.Found {
		t.Fatal("GetVulns Found = false, want true")
	}
	if len(got.Value) != 3 {
		t.Fatalf("vulns persisted = %d, want 3", len(got.Value))
	}
}
