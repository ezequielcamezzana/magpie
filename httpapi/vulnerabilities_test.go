package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/httpapi"
	"github.com/ezequielcamezzana/magpie/store/sqlite"

	"github.com/go-chi/chi/v5"
)

type vulnsResponse struct {
	Records []magpie.VulnRecord `json:"records"`
	Page    int                 `json:"page"`
	Limit   int                 `json:"limit"`
	Total   int                 `json:"total"`
}

// newVulnsServer levanta un server con el store seedeado por seed (puede ser nil).
func newVulnsServer(t *testing.T, seed func(t *testing.T, db magpie.Store)) *httptest.Server {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if seed != nil {
		seed(t, db)
	}

	r := chi.NewRouter()
	httpapi.Mount(r, httpapi.Deps{
		Config: magpie.Config{Store: db},
		Logger: slog.Default(),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func getVulns(t *testing.T, srv *httptest.Server, query string) (*http.Response, vulnsResponse) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/vulnerabilities" + query)
	if err != nil {
		t.Fatal(err)
	}
	var out vulnsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	return resp, out
}

func TestVulnsFilterByOriginalID(t *testing.T) {
	srv := newVulnsServer(t, func(t *testing.T, db magpie.Store) {
		if err := db.PutVulns(context.Background(), "ecosyste.ms", "k1", []magpie.VulnRecord{
			{OriginalID: "GHSA-abc", CanonicalID: "CVE-2024-1", Source: "ecosyste.ms", FetchedAt: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.PutVulns(context.Background(), "osv", "k2", []magpie.VulnRecord{
			{OriginalID: "CVE-2024-1", CanonicalID: "CVE-2024-1", Source: "osv", FetchedAt: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
	})

	resp, out := getVulns(t, srv, "?id=GHSA-abc")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if out.Total != 1 {
		t.Fatalf("total = %d, want 1", out.Total)
	}
	if len(out.Records) != 1 || out.Records[0].OriginalID != "GHSA-abc" {
		t.Fatalf("records = %+v, want single GHSA-abc", out.Records)
	}
}

func TestVulnsFilterByCanonicalID(t *testing.T) {
	srv := newVulnsServer(t, func(t *testing.T, db magpie.Store) {
		if err := db.PutVulns(context.Background(), "ecosyste.ms", "k1", []magpie.VulnRecord{
			{OriginalID: "GHSA-abc", CanonicalID: "CVE-2024-1", Source: "ecosyste.ms", FetchedAt: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.PutVulns(context.Background(), "osv", "k2", []magpie.VulnRecord{
			{OriginalID: "CVE-2024-1", CanonicalID: "CVE-2024-1", Source: "osv", FetchedAt: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
	})

	resp, out := getVulns(t, srv, "?id=CVE-2024-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if out.Total < 2 {
		t.Fatalf("total = %d, want >= 2", out.Total)
	}
	if len(out.Records) < 2 {
		t.Fatalf("len(records) = %d, want >= 2", len(out.Records))
	}
}

func TestVulnsPagination(t *testing.T) {
	const n = 5
	srv := newVulnsServer(t, func(t *testing.T, db magpie.Store) {
		base := time.Now()
		var recs []magpie.VulnRecord
		for i := 0; i < n; i++ {
			recs = append(recs, magpie.VulnRecord{
				OriginalID:  "OSV-" + string(rune('a'+i)),
				CanonicalID: "OSV-" + string(rune('a'+i)),
				Source:      "osv",
				FetchedAt:   base.Add(time.Duration(i) * time.Second),
			})
		}
		if err := db.PutVulns(context.Background(), "osv", "k", recs); err != nil {
			t.Fatal(err)
		}
	})

	_, p1 := getVulns(t, srv, "?page=1&limit=2")
	if p1.Total != n {
		t.Fatalf("page1 total = %d, want %d", p1.Total, n)
	}
	if len(p1.Records) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(p1.Records))
	}

	_, p2 := getVulns(t, srv, "?page=2&limit=2")
	if len(p2.Records) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(p2.Records))
	}

	seen := map[string]bool{}
	for _, r := range p1.Records {
		seen[r.OriginalID] = true
	}
	for _, r := range p2.Records {
		if seen[r.OriginalID] {
			t.Fatalf("page2 overlaps page1 on %q", r.OriginalID)
		}
	}
}

func TestVulnsLimitClamp(t *testing.T) {
	srv := newVulnsServer(t, nil)

	resp, out := getVulns(t, srv, "?limit=999")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if out.Limit != 100 {
		t.Fatalf("limit = %d, want clamped to 100", out.Limit)
	}
}

func TestVulnsEmptyIsArray(t *testing.T) {
	srv := newVulnsServer(t, nil)

	resp, err := http.Get(srv.URL + "/vulnerabilities")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"records":[]`) {
		t.Fatalf("records should serialize as [], got: %s", body)
	}

	var out vulnsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 0 {
		t.Fatalf("total = %d, want 0", out.Total)
	}
}

func TestVulnsDefaults(t *testing.T) {
	srv := newVulnsServer(t, nil)

	_, out := getVulns(t, srv, "")
	if out.Page != 1 {
		t.Fatalf("page = %d, want 1", out.Page)
	}
	if out.Limit != 25 {
		t.Fatalf("limit = %d, want 25", out.Limit)
	}
}
