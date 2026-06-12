package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ezequielcamezzana/magpie/pkg/purl"
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
	c := New(nil, nil)
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
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.OriginalID != "MAL-2025-46969" {
		t.Errorf("OriginalID = %q", r.OriginalID)
	}
	if !slices.Contains(r.Aliases, "GHSA-2v46-p5h4-248w") {
		t.Errorf("Aliases = %v", r.Aliases)
	}
	if r.QueryKey != "npm:chalk" {
		t.Errorf("QueryKey = %q", r.QueryKey)
	}
	if !slices.Contains(r.AffectedVersions, "5.6.1") {
		t.Errorf("AffectedVersions = %v", r.AffectedVersions)
	}
	if r.Score != 0 {
		t.Errorf("Score = %v, want 0", r.Score)
	}
	if len(r.Payload) == 0 {
		t.Error("Payload empty")
	}
	if r.CanonicalID != "" {
		t.Errorf("CanonicalID = %q, want empty", r.CanonicalID)
	}
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
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(recs) != 10 {
		t.Fatalf("expected 10 records, got %d", len(recs))
	}

	var found bool
	for _, r := range recs {
		if r.OriginalID != "GHSA-29mw-wpgm-hmr9" {
			continue
		}
		found = true
		if !slices.Contains(r.Aliases, "CVE-2020-28500") {
			t.Errorf("Aliases = %v", r.Aliases)
		}
		if !slices.Contains(r.AffectedRanges, "[4.0.0, 4.17.21)") {
			t.Errorf("AffectedRanges = %v", r.AffectedRanges)
		}
		if !slices.Contains(r.FixedVersions, "4.17.21") {
			t.Errorf("FixedVersions = %v", r.FixedVersions)
		}
		if r.Score != 5.3 {
			t.Errorf("Score = %v, want 5.3", r.Score)
		}
		if r.Severity == "" {
			t.Error("Severity empty")
		}
	}
	if !found {
		t.Fatal("GHSA-29mw-wpgm-hmr9 not found")
	}
}

func TestQueryGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		if !strings.Contains(string(buf), `"GIT"`) {
			t.Errorf("GIT query body = %q, want ecosystem GIT", string(buf))
		}
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
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.OriginalID != "CURL-CVE-2024-2398" {
		t.Errorf("OriginalID = %q, want CURL-CVE-2024-2398", r.OriginalID)
	}
	if r.QueryKey != "https://github.com/curl/curl" {
		t.Errorf("QueryKey = %q", r.QueryKey)
	}
	if !slices.Contains(r.Aliases, "CVE-2024-2398") {
		t.Errorf("Aliases = %v", r.Aliases)
	}
	if !slices.Contains(r.AffectedRanges, "[8.1.0, 8.7.0)") {
		t.Errorf("AffectedRanges = %v, want SEMVER range", r.AffectedRanges)
	}
	if !slices.Contains(r.FixedVersions, "8.7.0") {
		t.Errorf("FixedVersions = %v", r.FixedVersions)
	}
	if !slices.Contains(r.AffectedVersions, "8.6.0") {
		t.Errorf("AffectedVersions = %v", r.AffectedVersions)
	}
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
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, r := range recs {
		if r.OriginalID == "OTHER-REPO-CVE-2024-9999" {
			t.Fatalf("record for another repo leaked in: %q", r.OriginalID)
		}
	}
}

// stripDotGit: a query without .git must match an affected entry whose GIT range
// repo carries the .git suffix.
func TestPickAffectedGitDotGit(t *testing.T) {
	affected := []rawAffected{
		{Ranges: []rawRange{{Type: "GIT", Repo: "https://github.com/curl/curl.git"}}},
	}
	q := purl.OSVQuery{Kind: purl.KindGitHub, RepoURL: "https://github.com/curl/curl"}
	if aff := pickAffected(affected, q); aff == nil {
		t.Fatal("pickAffected = nil, want match despite .git suffix")
	}
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
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.QueryKey != "debian:12:curl" {
		t.Errorf("QueryKey = %q, want debian:12:curl", r.QueryKey)
	}
	if len(r.AffectedRanges) == 0 {
		t.Fatalf("AffectedRanges empty, want at least one")
	}
	if !slices.Contains(r.AffectedRanges, "[*, 7.88.1-10+deb12u6)") {
		t.Errorf("AffectedRanges = %v", r.AffectedRanges)
	}
	if !slices.Contains(r.FixedVersions, "7.88.1-10+deb12u6") {
		t.Errorf("FixedVersions = %v", r.FixedVersions)
	}
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
	if err == nil {
		t.Fatal("expected error on HTTP 500")
	}
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
	if aff == nil {
		t.Fatal("pickAffected returned nil, want the 24.04 entry")
	}
	if aff.Package.Ecosystem != "Ubuntu:24.04:LTS" {
		t.Errorf("picked Ecosystem = %q, want Ubuntu:24.04:LTS", aff.Package.Ecosystem)
	}
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
	if aff := pickAffected(affected, q); aff != nil {
		t.Errorf("pickAffected = %+v, want nil (no real match)", aff.Package)
	}
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
	if aff == nil {
		t.Fatal("pickAffected returned nil, want the Red Hat entry")
	}
	if aff.Package.Ecosystem != "Red Hat:rhel_eus:9.0" {
		t.Errorf("picked Ecosystem = %q, want Red Hat:rhel_eus:9.0", aff.Package.Ecosystem)
	}
}

func TestMapVulnMergesUpstream(t *testing.T) {
	v := &rawVuln{
		ID:       "DEBIAN-CVE-2023-1",
		Aliases:  []string{},
		Upstream: []string{"CVE-2023-1"},
	}
	q := purl.OSVQuery{Kind: purl.KindLinux, Name: "curl", Ecosystem: "Debian:12"}
	rec := mapVuln(v, nil, q, "debian:12:curl")
	if !slices.Equal(rec.Aliases, []string{"CVE-2023-1"}) {
		t.Errorf("Aliases = %v, want [CVE-2023-1]", rec.Aliases)
	}
}

func TestMapVulnMergesUpstreamDedup(t *testing.T) {
	v := &rawVuln{
		ID:       "DEBIAN-CVE-2023-2",
		Aliases:  []string{"CVE-2023-2", "GHSA-x"},
		Upstream: []string{"CVE-2023-2", "CVE-2023-3"},
	}
	q := purl.OSVQuery{Kind: purl.KindLinux, Name: "curl", Ecosystem: "Debian:12"}
	rec := mapVuln(v, nil, q, "debian:12:curl")
	want := []string{"CVE-2023-2", "GHSA-x", "CVE-2023-3"}
	if !slices.Equal(rec.Aliases, want) {
		t.Errorf("Aliases = %v, want %v", rec.Aliases, want)
	}
}

func TestPickAffectedLanguageFallback(t *testing.T) {
	affected := []rawAffected{
		{Package: rawPackage{Name: "other", Ecosystem: "npm"}},
		{Package: rawPackage{Name: "chalk", Ecosystem: "npm"}},
	}

	q := purl.OSVQuery{Kind: purl.KindLanguage, Name: "chalk", Ecosystem: "npm"}
	if aff := pickAffected(affected, q); aff == nil || aff.Package.Name != "chalk" {
		t.Fatalf("pickAffected = %+v, want chalk entry", aff)
	}

	// No exact match → falls back to affected[0] (current behavior).
	qNo := purl.OSVQuery{Kind: purl.KindLanguage, Name: "missing", Ecosystem: "npm"}
	if aff := pickAffected(affected, qNo); aff == nil || aff.Package.Name != "other" {
		t.Fatalf("pickAffected = %+v, want affected[0] fallback", aff)
	}
}
