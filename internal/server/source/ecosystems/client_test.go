package ecosystems

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var file string
		switch {
		case strings.HasSuffix(r.URL.Path, "/packages/chalk"):
			file = "testdata/chalk.json"
		case strings.HasSuffix(r.URL.Path, "/packages/minimist"):
			file = "testdata/minimist.json"
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(file)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T) *Client {
	srv := newTestServer(t)
	c := New(srv.Client())
	c.BaseURL = srv.URL + "/"
	return c
}

func TestFetchChalk(t *testing.T) {
	c := newTestClient(t)
	comp, repo, vulns, err := c.Fetch(context.Background(), "pkg:npm/chalk")
	require.NoError(t, err)
	assert.Equal(t, "chalk", comp.Name)
	assert.Contains(t, comp.Licenses, "MIT")
	assert.Equal(t, "5.6.2", comp.LatestVersion)
	assert.False(t, comp.FetchedAt.IsZero(), "FetchedAt is zero")
	require.NotNil(t, repo)
	assert.Greater(t, repo.Stars, 0)
	assert.Equal(t, "JavaScript", repo.Language)
	assert.Empty(t, vulns)
}

func TestFetchMinimistAdvisories(t *testing.T) {
	c := newTestClient(t)
	_, _, vulns, err := c.Fetch(context.Background(), "pkg:npm/minimist")
	require.NoError(t, err)
	require.Len(t, vulns, 3)

	var found bool
	for i := range vulns {
		rec := vulns[i]
		if rec.OriginalID != "GHSA-xvch-5gv4-984h" {
			continue
		}
		found = true
		assert.Contains(t, rec.Aliases, "GHSA-xvch-5gv4-984h")
		assert.Contains(t, rec.Aliases, "CVE-2021-44906")
		assert.Equal(t, "CRITICAL", rec.Severity)
		assert.Equal(t, 9.8, rec.Score)
		assert.Empty(t, rec.CanonicalID)
		assert.Contains(t, rec.AffectedRanges, "[1.0.0, 1.2.6)")
		assert.Contains(t, rec.AffectedRanges, "(*, 0.2.4)")
		assert.Contains(t, rec.FixedVersions, "1.2.6")
		assert.Contains(t, rec.FixedVersions, "0.2.4")
		assert.NotEmpty(t, rec.Payload)
		assert.Equal(t, "ecosyste.ms", string(rec.Source))
		assert.Equal(t, "pkg:npm/minimist", rec.QueryKey)
	}
	require.True(t, found, "advisory GHSA-xvch-5gv4-984h not found")
}

func TestFetchRangeParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{">= 1.0.0, < 1.2.6", "[1.0.0, 1.2.6)"},
		{"< 0.2.4", "(*, 0.2.4)"},
		{"<= 2.0.1", "(*, 2.0.1]"},
		{">= 1.8.0", "[1.8.0, *)"},
	}
	for _, tc := range cases {
		assert.Equal(t, []string{tc.want}, parseEcosystemsRange(tc.in), "parseEcosystemsRange(%q)", tc.in)
	}
}

func TestFetchHTTPError(t *testing.T) {
	c := newTestClient(t)
	_, _, _, err := c.Fetch(context.Background(), "pkg:npm/does-not-exist")
	require.Error(t, err, "expected error for 404")
}
