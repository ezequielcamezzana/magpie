package vulncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

func newTestClient(baseURL string) *Client {
	c := New(nil, "")
	c.BaseURL = baseURL
	return c
}

func TestFetchCVE(t *testing.T) {
	body, err := os.ReadFile("testdata/cve-2026-44494.json")
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	recs, err := c.FetchCVE(context.Background(), "CVE-2026-44494")
	require.NoError(t, err)
	require.NotEmpty(t, recs)

	hasMatch := false
	for _, r := range recs {
		assert.Equal(t, collect.SourceNVD, r.Source)
		assert.Equal(t, "CVE-2026-44494", r.CanonicalID)
		if r.MatchedOn != "" {
			hasMatch = true
		}
	}
	assert.True(t, hasMatch, "expected at least one record with a non-empty MatchedOn")
}

// An empty data array (CVE not in VulnCheck's NVD2 index) is not an error —
// it means "no NVD2 data for this CVE", so CPER must not treat it as a failure.
func TestFetchCVEEmptyIsNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	recs, err := c.FetchCVE(context.Background(), "CVE-2026-00000")
	require.NoError(t, err)
	assert.Empty(t, recs)
}
