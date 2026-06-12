package ecosystems

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
	c := New(srv.Client(), nil)
	c.BaseURL = srv.URL + "/"
	return c
}

func TestFetchChalk(t *testing.T) {
	c := newTestClient(t)
	comp, repo, vulns, err := c.Fetch(context.Background(), "pkg:npm/chalk")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if comp.Name != "chalk" {
		t.Errorf("Name = %q, want chalk", comp.Name)
	}
	if !contains(comp.Licenses, "MIT") {
		t.Errorf("Licenses = %v, want MIT", comp.Licenses)
	}
	if comp.LatestVersion != "5.6.2" {
		t.Errorf("LatestVersion = %q, want 5.6.2", comp.LatestVersion)
	}
	if comp.FetchedAt.IsZero() {
		t.Error("FetchedAt is zero")
	}
	if repo == nil {
		t.Fatal("Repository is nil")
	}
	if repo.Stars <= 0 {
		t.Errorf("Stars = %d, want > 0", repo.Stars)
	}
	if repo.Language != "JavaScript" {
		t.Errorf("Language = %q, want JavaScript", repo.Language)
	}
	if len(vulns) != 0 {
		t.Errorf("len(vulns) = %d, want 0", len(vulns))
	}
}

func TestFetchMinimistAdvisories(t *testing.T) {
	c := newTestClient(t)
	_, _, vulns, err := c.Fetch(context.Background(), "pkg:npm/minimist")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(vulns) != 3 {
		t.Fatalf("len(vulns) = %d, want 3", len(vulns))
	}

	var found bool
	for i := range vulns {
		rec := vulns[i]
		if rec.OriginalID != "GHSA-xvch-5gv4-984h" {
			continue
		}
		found = true
		if !contains(rec.Aliases, "GHSA-xvch-5gv4-984h") || !contains(rec.Aliases, "CVE-2021-44906") {
			t.Errorf("Aliases = %v, want both identifiers", rec.Aliases)
		}
		if rec.Severity != "CRITICAL" {
			t.Errorf("Severity = %q, want CRITICAL", rec.Severity)
		}
		if rec.Score != 9.8 {
			t.Errorf("Score = %v, want 9.8", rec.Score)
		}
		if rec.CanonicalID != "" {
			t.Errorf("CanonicalID = %q, want empty", rec.CanonicalID)
		}
		if !contains(rec.AffectedRanges, "[1.0.0, 1.2.6)") {
			t.Errorf("AffectedRanges = %v, want [1.0.0, 1.2.6)", rec.AffectedRanges)
		}
		if !contains(rec.AffectedRanges, "(*, 0.2.4)") {
			t.Errorf("AffectedRanges = %v, want (*, 0.2.4)", rec.AffectedRanges)
		}
		if !contains(rec.FixedVersions, "1.2.6") || !contains(rec.FixedVersions, "0.2.4") {
			t.Errorf("FixedVersions = %v, want 1.2.6 and 0.2.4", rec.FixedVersions)
		}
		if len(rec.Payload) == 0 {
			t.Error("Payload is empty")
		}
		if rec.Source != "ecosyste.ms" {
			t.Errorf("Source = %q, want ecosyste.ms", rec.Source)
		}
		if rec.QueryKey != "pkg:npm/minimist" {
			t.Errorf("QueryKey = %q, want pkg:npm/minimist", rec.QueryKey)
		}
	}
	if !found {
		t.Fatal("advisory GHSA-xvch-5gv4-984h not found")
	}
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
		got := parseEcosystemsRange(tc.in)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("parseEcosystemsRange(%q) = %v, want [%q]", tc.in, got, tc.want)
		}
	}
}

func TestFetchHTTPError(t *testing.T) {
	c := newTestClient(t)
	_, _, _, err := c.Fetch(context.Background(), "pkg:npm/does-not-exist")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
