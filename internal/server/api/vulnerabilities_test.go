package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/api"
	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/db"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type vulnsResponse struct {
	Records []collect.VulnRecord `json:"records"`
	Page    int                  `json:"page"`
	Limit   int                  `json:"limit"`
	Total   int                  `json:"total"`
}

// newVulnsServer brings up a server with the store seeded by seed (may be nil).
func newVulnsServer(t *testing.T, seed func(t *testing.T, db collect.Store)) *httptest.Server {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err, "db.Open")
	t.Cleanup(func() { database.Close() })

	if seed != nil {
		seed(t, database)
	}

	r := chi.NewRouter()
	api.Mount(r, api.Deps{
		Config: collect.Config{Store: database},
		Logger: slog.Default(),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func getVulns(t *testing.T, srv *httptest.Server, query string) (*http.Response, vulnsResponse) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/vulnerabilities" + query)
	require.NoError(t, err)
	var out vulnsResponse
	err = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	require.NoError(t, err, "decode")
	return resp, out
}

func TestVulnsFilterByOriginalID(t *testing.T) {
	srv := newVulnsServer(t, func(t *testing.T, db collect.Store) {
		require.NoError(t, db.PutVulns(context.Background(), "ecosyste.ms", "k1", []collect.VulnRecord{
			{OriginalID: "GHSA-abc", CanonicalID: "CVE-2024-1", Source: "ecosyste.ms", FetchedAt: time.Now()},
		}))
		require.NoError(t, db.PutVulns(context.Background(), "osv", "k2", []collect.VulnRecord{
			{OriginalID: "CVE-2024-1", CanonicalID: "CVE-2024-1", Source: "osv", FetchedAt: time.Now()},
		}))
	})

	resp, out := getVulns(t, srv, "?id=GHSA-abc")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, out.Total)
	require.Len(t, out.Records, 1)
	assert.Equal(t, "GHSA-abc", out.Records[0].OriginalID)
}

func TestVulnsFilterByCanonicalID(t *testing.T) {
	srv := newVulnsServer(t, func(t *testing.T, db collect.Store) {
		require.NoError(t, db.PutVulns(context.Background(), "ecosyste.ms", "k1", []collect.VulnRecord{
			{OriginalID: "GHSA-abc", CanonicalID: "CVE-2024-1", Source: "ecosyste.ms", FetchedAt: time.Now()},
		}))
		require.NoError(t, db.PutVulns(context.Background(), "osv", "k2", []collect.VulnRecord{
			{OriginalID: "CVE-2024-1", CanonicalID: "CVE-2024-1", Source: "osv", FetchedAt: time.Now()},
		}))
	})

	// GHSA-abc (ecosyste.ms) and CVE-2024-1 (osv) share canonical CVE-2024-1:
	// the list collapses them into a single logical vuln.
	resp, out := getVulns(t, srv, "?id=CVE-2024-1")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, out.Total)
	require.Len(t, out.Records, 1)
	assert.Equal(t, "CVE-2024-1", out.Records[0].CanonicalID)
}

func TestVulnsPagination(t *testing.T) {
	const n = 5
	srv := newVulnsServer(t, func(t *testing.T, db collect.Store) {
		base := time.Now()
		var recs []collect.VulnRecord
		for i := 0; i < n; i++ {
			recs = append(recs, collect.VulnRecord{
				OriginalID:  "OSV-" + string(rune('a'+i)),
				CanonicalID: "OSV-" + string(rune('a'+i)),
				Source:      "osv",
				FetchedAt:   base.Add(time.Duration(i) * time.Second),
			})
		}
		require.NoError(t, db.PutVulns(context.Background(), "osv", "k", recs))
	})

	_, p1 := getVulns(t, srv, "?page=1&limit=2")
	assert.Equal(t, n, p1.Total)
	require.Len(t, p1.Records, 2)

	_, p2 := getVulns(t, srv, "?page=2&limit=2")
	require.Len(t, p2.Records, 2)

	seen := map[string]bool{}
	for _, r := range p1.Records {
		seen[r.OriginalID] = true
	}
	for _, r := range p2.Records {
		assert.False(t, seen[r.OriginalID], "page2 overlaps page1 on %q", r.OriginalID)
	}
}

func TestVulnsLimitClamp(t *testing.T) {
	srv := newVulnsServer(t, nil)

	resp, out := getVulns(t, srv, "?limit=999")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 100, out.Limit, "limit should be clamped to 100")
}

func TestVulnsEmptyIsArray(t *testing.T) {
	srv := newVulnsServer(t, nil)

	resp, err := http.Get(srv.URL + "/vulnerabilities")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"records":[]`, "records should serialize as []")

	var out vulnsResponse
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, 0, out.Total)
}

func TestVulnsDefaults(t *testing.T) {
	srv := newVulnsServer(t, nil)

	_, out := getVulns(t, srv, "")
	assert.Equal(t, 1, out.Page)
	assert.Equal(t, 25, out.Limit)
}
