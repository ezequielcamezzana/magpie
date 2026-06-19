package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// fixtureServer responds with a testdata fixture chosen by the queried package name.
func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/lodash_npm.json")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		if strings.Contains(string(buf), `"chalk"`) {
			body, _ = os.ReadFile("testdata/chalk_npm.json")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

func newTestClient(t *testing.T, baseURL string) *Client {
	c := New(nil)
	c.BaseURL = baseURL
	return c
}

func TestQueryChalk(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	recs, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:      purl.KindLanguage,
		Ecosystem: "npm",
		Name:      "chalk",
	})
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "MAL-2025-46969", r.OriginalID)
	assert.Contains(t, r.Aliases, "GHSA-2v46-p5h4-248w")
	assert.Equal(t, "npm:chalk", r.QueryKey)
	assert.Contains(t, r.AffectedVersions, "5.6.1")
	assert.Zero(t, r.Score)
	assert.NotEmpty(t, r.Payload)
	assert.Empty(t, r.CanonicalID)
}

func TestQueryLodashCVEandRanges(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	recs, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:      purl.KindLanguage,
		Ecosystem: "npm",
		Name:      "lodash",
	})
	require.NoError(t, err)
	require.Len(t, recs, 10)

	var found bool
	for _, r := range recs {
		if r.OriginalID != "GHSA-29mw-wpgm-hmr9" {
			continue
		}
		found = true
		assert.Contains(t, r.Aliases, "CVE-2020-28500")
		assert.Contains(t, r.AffectedRanges, "[4.0.0, 4.17.21)")
		assert.Contains(t, r.FixedVersions, "4.17.21")
		assert.Equal(t, 5.3, r.Score)
		assert.NotEmpty(t, r.Severity)
	}
	require.True(t, found, "GHSA-29mw-wpgm-hmr9 not found")
}

func TestQueryGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		assert.Contains(t, string(buf), `"GIT"`, "GIT query body must use ecosystem GIT")
		body, _ := os.ReadFile("testdata/curl_git.json")
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	recs, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:    purl.KindGitHub,
		RepoURL: "https://github.com/curl/curl",
	})
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "CURL-CVE-2024-2398", r.OriginalID)
	assert.Equal(t, "https://github.com/curl/curl", r.QueryKey)
	assert.Contains(t, r.Aliases, "CVE-2024-2398")
	assert.Contains(t, r.AffectedRanges, "[8.1.0, 8.7.0)")
	assert.Contains(t, r.FixedVersions, "8.7.0")
	assert.Contains(t, r.AffectedVersions, "8.6.0")
}

// A GIT range pointing to another repo must not be attributed to this repo.
func TestQueryGitHubExcludesOtherRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/curl_git.json")
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	recs, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:    purl.KindGitHub,
		RepoURL: "https://github.com/curl/curl",
	})
	require.NoError(t, err)
	for _, r := range recs {
		require.NotEqual(t, "OTHER-REPO-CVE-2024-9999", r.OriginalID, "record for another repo leaked in")
	}
}

// stripDotGit: a query without .git must match an affected entry whose GIT range
// repo carries the .git suffix.
func TestPickAffectedGitDotGit(t *testing.T) {
	affected := []rawAffected{
		{Ranges: []rawRange{{Type: "GIT", Repo: "https://github.com/curl/curl.git"}}},
	}
	q := purl.OSVQuery{Kind: purl.KindGitHub, RepoURL: "https://github.com/curl/curl"}
	require.NotNil(t, pickAffected(affected, q), "want match despite .git suffix")
}

func TestQueryLinuxDebian(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/curl_debian.json")
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	recs, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:          purl.KindLinux,
		Ecosystem:     "Debian:12",
		BaseEcosystem: "Debian",
		ReleaseToken:  "12",
		Name:          "curl",
	})
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "debian:12:curl", r.QueryKey)
	require.NotEmpty(t, r.AffectedRanges)
	assert.Contains(t, r.AffectedRanges, "[*, 7.88.1-10+deb12u6)")
	assert.Contains(t, r.FixedVersions, "7.88.1-10+deb12u6")
}

func TestQueryHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Query(context.Background(), purl.OSVQuery{
		Kind:      purl.KindLanguage,
		Ecosystem: "npm",
		Name:      "lodash",
	})
	require.Error(t, err, "expected error on HTTP 500")
}

func TestPickAffectedLinuxMultiRelease(t *testing.T) {
	affected := []rawAffected{
		{Package: rawPackage{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS", Purl: "pkg:deb/ubuntu/openssl?ecosystem=22.04"}},
		{Package: rawPackage{Name: "openssl", Ecosystem: "Ubuntu:24.04:LTS", Purl: "pkg:deb/ubuntu/openssl?ecosystem=24.04"}},
		{Package: rawPackage{Name: "openssl", Ecosystem: "Debian:12", Purl: "pkg:deb/debian/openssl"}},
	}

	q := purl.OSVQuery{
		Kind:          purl.KindLinux,
		Name:          "openssl",
		Ecosystem:     "Ubuntu:24.04:LTS",
		BaseEcosystem: "Ubuntu",
		ReleaseToken:  "24.04",
	}
	aff := pickAffected(affected, q)
	require.NotNil(t, aff, "want the 24.04 entry")
	assert.Equal(t, "Ubuntu:24.04:LTS", aff.Package.Ecosystem)
}

func TestPickAffectedLinuxNoMatchNil(t *testing.T) {
	affected := []rawAffected{
		{Package: rawPackage{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS"}},
		{Package: rawPackage{Name: "openssl", Ecosystem: "Debian:12"}},
	}

	q := purl.OSVQuery{
		Kind:          purl.KindLinux,
		Name:          "openssl",
		Ecosystem:     "Ubuntu:24.04:LTS",
		BaseEcosystem: "Ubuntu",
		ReleaseToken:  "24.04",
	}
	assert.Nil(t, pickAffected(affected, q), "want nil (no real match)")
}

// ReleaseToken empty (redhat/suse/fedora) → prefix match only.
func TestPickAffectedLinuxPrefixOnly(t *testing.T) {
	affected := []rawAffected{
		{Package: rawPackage{Name: "openssl", Ecosystem: "Debian:12"}},
		{Package: rawPackage{Name: "openssl", Ecosystem: "Red Hat:rhel_eus:9.0"}},
	}

	q := purl.OSVQuery{
		Kind:          purl.KindLinux,
		Name:          "openssl",
		Ecosystem:     "Red Hat",
		BaseEcosystem: "Red Hat",
		ReleaseToken:  "",
	}
	aff := pickAffected(affected, q)
	require.NotNil(t, aff, "want the Red Hat entry")
	assert.Equal(t, "Red Hat:rhel_eus:9.0", aff.Package.Ecosystem)
}

func TestMapVulnMergesUpstream(t *testing.T) {
	v := &rawVuln{
		ID:       "DEBIAN-CVE-2023-1",
		Aliases:  []string{},
		Upstream: []string{"CVE-2023-1"},
	}
	q := purl.OSVQuery{Kind: purl.KindLinux, Name: "curl", Ecosystem: "Debian:12"}
	rec := mapVuln(v, nil, q, "debian:12:curl")
	assert.Equal(t, []string{"CVE-2023-1"}, rec.Aliases)
}

func TestMapVulnMergesUpstreamDedup(t *testing.T) {
	v := &rawVuln{
		ID:       "DEBIAN-CVE-2023-2",
		Aliases:  []string{"CVE-2023-2", "GHSA-x"},
		Upstream: []string{"CVE-2023-2", "CVE-2023-3"},
	}
	q := purl.OSVQuery{Kind: purl.KindLinux, Name: "curl", Ecosystem: "Debian:12"}
	rec := mapVuln(v, nil, q, "debian:12:curl")
	assert.Equal(t, []string{"CVE-2023-2", "GHSA-x", "CVE-2023-3"}, rec.Aliases)
}

func TestPickAffectedLanguageFallback(t *testing.T) {
	affected := []rawAffected{
		{Package: rawPackage{Name: "other", Ecosystem: "npm"}},
		{Package: rawPackage{Name: "chalk", Ecosystem: "npm"}},
	}

	q := purl.OSVQuery{Kind: purl.KindLanguage, Name: "chalk", Ecosystem: "npm"}
	aff := pickAffected(affected, q)
	require.NotNil(t, aff)
	assert.Equal(t, "chalk", aff.Package.Name)

	// No exact match → falls back to affected[0] (current behavior).
	qNo := purl.OSVQuery{Kind: purl.KindLanguage, Name: "missing", Ecosystem: "npm"}
	aff = pickAffected(affected, qNo)
	require.NotNil(t, aff, "want affected[0] fallback")
	assert.Equal(t, "other", aff.Package.Name)
}
