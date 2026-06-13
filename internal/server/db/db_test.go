package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	require.NoError(t, err, "Open")
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesTables(t *testing.T) {
	s := openTest(t)

	want := []string{"components", "repositories", "vulns", "package_vuln", "cpes"}
	for _, name := range want {
		var got string
		err := s.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
		require.NoError(t, err, "table %q not found", name)
	}

	var idx string
	err := s.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vulns_canonical'`).Scan(&idx)
	require.NoError(t, err, "idx_vulns_canonical not found")
}

func TestComponentRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := collect.Component{
		SPURL:         "pkg:npm/left-pad",
		Name:          "left-pad",
		Description:   "pads on the left",
		Licenses:      []string{"MIT", "Apache-2.0"},
		LatestVersion: "1.3.0",
		RepoURL:       "https://github.com/left-pad/left-pad",
		Icon:          "https://example.com/icon.png",
		FetchedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}

	require.NoError(t, s.PutComponent(ctx, in), "PutComponent")

	res, err := s.GetComponent(ctx, in.SPURL)
	require.NoError(t, err, "GetComponent")
	require.True(t, res.Found, "expected Found=true")

	got := res.Value
	assert.Equal(t, in.SPURL, got.SPURL)
	assert.Equal(t, in.Name, got.Name)
	assert.Equal(t, in.Description, got.Description)
	assert.Equal(t, in.LatestVersion, got.LatestVersion)
	assert.Equal(t, in.RepoURL, got.RepoURL)
	assert.Equal(t, in.Icon, got.Icon)
	assert.Equal(t, in.Licenses, got.Licenses)
	assert.True(t, got.FetchedAt.Equal(in.FetchedAt), "FetchedAt: got %v want %v", got.FetchedAt, in.FetchedAt)
	assert.True(t, res.FetchedAt.Equal(in.FetchedAt), "Result.FetchedAt: got %v want %v", res.FetchedAt, in.FetchedAt)
}

func TestComponentEmptyLicenses(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := collect.Component{SPURL: "pkg:npm/empty", Name: "empty"}
	require.NoError(t, s.PutComponent(ctx, in), "PutComponent")
	res, err := s.GetComponent(ctx, in.SPURL)
	require.NoError(t, err, "GetComponent")
	assert.Empty(t, res.Value.Licenses)
}

func TestComponentNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetComponent(context.Background(), "pkg:npm/nope")
	require.NoError(t, err)
	assert.False(t, res.Found, "expected Found=false")
}

func TestComponentUpsert(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	first := collect.Component{SPURL: "pkg:npm/x", Name: "old", LatestVersion: "1.0.0"}
	second := collect.Component{SPURL: "pkg:npm/x", Name: "new", LatestVersion: "2.0.0", Licenses: []string{"MIT"}}

	require.NoError(t, s.PutComponent(ctx, first), "PutComponent first")
	require.NoError(t, s.PutComponent(ctx, second), "PutComponent second")

	res, err := s.GetComponent(ctx, "pkg:npm/x")
	require.NoError(t, err, "GetComponent")
	assert.Equal(t, "new", res.Value.Name)
	assert.Equal(t, "2.0.0", res.Value.LatestVersion)
}

func TestRepositoryRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := collect.Repository{
		URL:         "https://github.com/foo/bar",
		Stars:       1200,
		Forks:       34,
		Language:    "Go",
		LastPush:    time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond),
		LastRelease: time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond),
		FetchedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}

	require.NoError(t, s.PutRepository(ctx, in), "PutRepository")

	res, err := s.GetRepository(ctx, in.URL)
	require.NoError(t, err, "GetRepository")
	require.True(t, res.Found, "expected Found=true")

	got := res.Value
	assert.Equal(t, in.URL, got.URL)
	assert.Equal(t, in.Stars, got.Stars)
	assert.Equal(t, in.Forks, got.Forks)
	assert.Equal(t, in.Language, got.Language)
	assert.True(t, got.LastPush.Equal(in.LastPush), "LastPush: got %v want %v", got.LastPush, in.LastPush)
	assert.True(t, got.LastRelease.Equal(in.LastRelease), "LastRelease: got %v want %v", got.LastRelease, in.LastRelease)
	assert.True(t, got.FetchedAt.Equal(in.FetchedAt), "FetchedAt: got %v want %v", got.FetchedAt, in.FetchedAt)
}

func TestRepositoryZeroTimes(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := collect.Repository{URL: "https://github.com/zero/times", Stars: 1}
	require.NoError(t, s.PutRepository(ctx, in), "PutRepository")
	res, err := s.GetRepository(ctx, in.URL)
	require.NoError(t, err, "GetRepository")
	assert.True(t, res.Value.LastPush.IsZero(), "expected zero LastPush, got %v", res.Value.LastPush)
	assert.True(t, res.Value.LastRelease.IsZero(), "expected zero LastRelease, got %v", res.Value.LastRelease)
}

func TestRepositoryNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetRepository(context.Background(), "https://github.com/no/pe")
	require.NoError(t, err)
	assert.False(t, res.Found, "expected Found=false")
}

func vulnRecord(id, canonical string, fetchedAt time.Time) collect.VulnRecord {
	return collect.VulnRecord{
		Source:             "osv",
		QueryKey:           "pkg:npm/left-pad",
		AffectedPackage:    "pkg:npm/left-pad",
		OriginalID:         id,
		Aliases:            []string{"CVE-2020-" + id, "GHSA-" + id},
		CanonicalID:        canonical,
		Score:              7.5,
		Severity:           "HIGH",
		AffectedVersions:   []string{"1.0.0", "1.1.0"},
		AffectedRanges:     []string{"[1.0.0, 1.2.0)"},
		FixedVersions:      []string{"1.2.0"},
		UnaffectedVersions: []string{"0.9.0"},
		Published:          fetchedAt.Add(-720 * time.Hour).Truncate(time.Microsecond),
		Modified:           fetchedAt.Add(-24 * time.Hour).Truncate(time.Microsecond),
		Payload:            json.RawMessage(`{"id":"` + id + `","raw":true}`),
		FetchedAt:          fetchedAt,
	}
}

func TestVulnsRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	in := []collect.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now.Add(-time.Hour)),
		vulnRecord("OSV-3", "CVE-2020-3", now.Add(-2*time.Hour)),
	}

	require.NoError(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", in), "PutVulns")

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	require.NoError(t, err, "GetVulns")
	require.True(t, res.Found, "expected Found=true")
	require.Len(t, res.Value, 3)

	byID := map[string]collect.VulnRecord{}
	for _, r := range res.Value {
		byID[r.OriginalID] = r
	}
	for _, want := range in {
		got, ok := byID[want.OriginalID]
		require.True(t, ok, "missing record %q", want.OriginalID)
		assert.Equal(t, want.CanonicalID, got.CanonicalID, want.OriginalID)
		assert.Equal(t, want.Score, got.Score, want.OriginalID)
		assert.Equal(t, want.Severity, got.Severity, want.OriginalID)
		assert.Equal(t, want.AffectedPackage, got.AffectedPackage, want.OriginalID)
		assert.Equal(t, want.Aliases, got.Aliases, want.OriginalID)
		assert.Equal(t, want.AffectedRanges, got.AffectedRanges, want.OriginalID)
		assert.Equal(t, string(want.Payload), string(got.Payload), want.OriginalID)
		assert.True(t, got.FetchedAt.Equal(want.FetchedAt), "%s: FetchedAt: got %v want %v", want.OriginalID, got.FetchedAt, want.FetchedAt)
		assert.True(t, got.Published.Equal(want.Published), "%s: Published: got %v want %v", want.OriginalID, got.Published, want.Published)
		assert.True(t, got.Modified.Equal(want.Modified), "%s: Modified: got %v want %v", want.OriginalID, got.Modified, want.Modified)
	}
}

// TestVulnsEmptyLists locks the store-wide convention: empty list
// columns come back as non-nil empty slices, not nil (matches licenses).
func TestVulnsEmptyLists(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	in := collect.VulnRecord{
		Source: "osv", QueryKey: "k", OriginalID: "OSV-1", CanonicalID: "CVE-2020-1",
		FetchedAt: now,
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "k", []collect.VulnRecord{in}), "PutVulns")
	res, err := s.GetVulns(ctx, "osv", "k")
	require.NoError(t, err, "GetVulns")
	got := res.Value[0]
	for name, list := range map[string][]string{
		"Aliases":            got.Aliases,
		"AffectedVersions":   got.AffectedVersions,
		"FixedVersions":      got.FixedVersions,
		"UnaffectedVersions": got.UnaffectedVersions,
		"AffectedRanges":     got.AffectedRanges,
	} {
		assert.NotNil(t, list, "%s: expected non-nil empty slice", name)
	}
}

func TestGetVulnsNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetVulns(context.Background(), "osv", "pkg:npm/nope")
	require.NoError(t, err)
	assert.False(t, res.Found, "expected Found=false")
}

func TestGetVulnsFetchedAtIsMin(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	oldest := now.Add(-3 * time.Hour)
	in := []collect.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", oldest),
		vulnRecord("OSV-3", "CVE-2020-3", now.Add(-time.Hour)),
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", in), "PutVulns")
	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	require.NoError(t, err, "GetVulns")
	assert.True(t, res.FetchedAt.Equal(oldest), "Result.FetchedAt: got %v want %v (min)", res.FetchedAt, oldest)
}

func TestPutVulnsReplaces(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	setA := []collect.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now),
		vulnRecord("OSV-3", "CVE-2020-3", now),
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setA), "PutVulns A")

	setB := []collect.VulnRecord{vulnRecord("OSV-9", "CVE-2020-9", now)}
	require.NoError(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setB), "PutVulns B")

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	require.NoError(t, err, "GetVulns")
	require.Len(t, res.Value, 1, "expected 1 record after replace")
	assert.Equal(t, "OSV-9", res.Value[0].OriginalID)
}

// TestPutVulnsAtomic verifies that a Put failing midway leaves no state.
// We force the failure by passing two records with the same OriginalID: the
// second INSERT violates the composite PK and aborts the tx after the DELETE.
func TestPutVulnsAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	setA := []collect.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now),
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setA), "PutVulns A")

	bad := []collect.VulnRecord{
		vulnRecord("DUP", "CVE-X", now),
		vulnRecord("DUP", "CVE-Y", now),
	}
	require.Error(t, s.PutVulns(ctx, "osv", "pkg:npm/left-pad", bad), "expected PutVulns to fail on duplicate PK")

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	require.NoError(t, err, "GetVulns")
	require.Len(t, res.Value, 2, "expected set A intact")
}

// TestVulnsDedup is the heart of the change: the same vuln (source,
// original_id) seen from two distinct query_keys stores ONE header in vulns
// and two rows in package_vuln, one per affected package.
func TestVulnsDedup(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(queryKey, affPkg string) collect.VulnRecord {
		r := vulnRecord("GHSA-shared", "CVE-2020-shared", now)
		r.QueryKey = queryKey
		r.AffectedPackage = affPkg
		return r
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:axios", []collect.VulnRecord{mk("npm:axios", "pkg:npm/axios")}), "PutVulns axios")
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:chalk", []collect.VulnRecord{mk("npm:chalk", "pkg:npm/chalk")}), "PutVulns chalk")

	var vulnRows, pvRows int
	require.NoError(t, s.db.QueryRow(`SELECT COUNT(*) FROM vulns`).Scan(&vulnRows), "count vulns")
	require.NoError(t, s.db.QueryRow(`SELECT COUNT(*) FROM package_vuln`).Scan(&pvRows), "count package_vuln")
	assert.Equal(t, 1, vulnRows, "expected 1 vulns header (deduped)")
	assert.Equal(t, 2, pvRows, "expected 2 package_vuln rows")

	// Both queries return the full header plus their own affected_package.
	for _, tc := range []struct{ key, pkg string }{{"npm:axios", "pkg:npm/axios"}, {"npm:chalk", "pkg:npm/chalk"}} {
		res, err := s.GetVulns(ctx, "osv", tc.key)
		require.NoError(t, err, "GetVulns %s", tc.key)
		require.Len(t, res.Value, 1, tc.key)
		got := res.Value[0]
		assert.Equal(t, "CVE-2020-shared", got.CanonicalID, tc.key)
		assert.Equal(t, 7.5, got.Score, tc.key)
		assert.Equal(t, tc.pkg, got.AffectedPackage, tc.key)
	}
}

func seedQueryVulns(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(source, key, id, canonical string, at time.Time) collect.VulnRecord {
		r := vulnRecord(id, canonical, at)
		r.Source = source
		r.QueryKey = key
		return r
	}
	// Two records share canonical CVE-SHARED.
	require.NoError(t, s.PutVulns(ctx, "osv", "k1", []collect.VulnRecord{
		mk("osv", "k1", "OSV-A", "CVE-SHARED", now),
		mk("osv", "k1", "OSV-B", "CVE-2020-B", now.Add(-time.Hour)),
	}), "seed osv")
	require.NoError(t, s.PutVulns(ctx, "nvd", "k2", []collect.VulnRecord{
		mk("nvd", "k2", "CVE-SHARED", "CVE-SHARED", now.Add(-2*time.Hour)),
		mk("nvd", "k2", "CVE-2020-D", "CVE-2020-D", now.Add(-3*time.Hour)),
	}), "seed nvd")
}

func TestQueryVulnsByOriginalID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), collect.VulnQuery{ID: "OSV-B", Page: 1, Limit: 25})
	require.NoError(t, err, "QueryVulns")
	assert.Equal(t, 1, total)
	require.Len(t, recs, 1)
	assert.Equal(t, "OSV-B", recs[0].OriginalID)
}

func TestQueryVulnsByCanonicalID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), collect.VulnQuery{ID: "CVE-SHARED", Page: 1, Limit: 25})
	require.NoError(t, err, "QueryVulns")
	// OSV-A (canonical CVE-SHARED) + CVE-SHARED (original_id == CVE-SHARED).
	assert.Equal(t, 2, total)
	assert.Len(t, recs, 2)
}

func TestQueryVulnsPagination(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	p1, total, err := s.QueryVulns(context.Background(), collect.VulnQuery{Page: 1, Limit: 2})
	require.NoError(t, err, "QueryVulns p1")
	assert.Equal(t, 4, total)
	require.Len(t, p1, 2)

	p2, _, err := s.QueryVulns(context.Background(), collect.VulnQuery{Page: 2, Limit: 2})
	require.NoError(t, err, "QueryVulns p2")
	require.Len(t, p2, 2)
	// Pages must not overlap.
	assert.NotEqual(t, p1[0].OriginalID, p2[0].OriginalID, "pages overlap")
}

func TestQueryVulnsEmptyID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), collect.VulnQuery{Page: 1, Limit: 25})
	require.NoError(t, err, "QueryVulns")
	assert.Equal(t, 4, total)
	assert.Len(t, recs, 4)
}

// TestOpenMigratesOldCPEsTable: a DB created before the
// nvd_ranges/osv_ranges columns is migrated on open (idempotent ALTER).
func TestOpenMigratesOldCPEsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	old, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = old.Exec(`CREATE TABLE cpes (
		spurl TEXT NOT NULL, cpe TEXT NOT NULL,
		vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
		target_sw TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '',
		ecosystem TEXT NOT NULL DEFAULT '',
		matched_name INTEGER NOT NULL DEFAULT 0, matched_vendor INTEGER NOT NULL DEFAULT 0,
		matched_ecosystem INTEGER NOT NULL DEFAULT 0, matched_range INTEGER NOT NULL DEFAULT 0,
		explanation TEXT NOT NULL DEFAULT '', fetched_at TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (spurl, cpe))`)
	require.NoError(t, err)
	old.Close()

	s, err := Open(path)
	require.NoError(t, err, "Open over old schema")
	t.Cleanup(func() { s.Close() })

	ctx := context.Background()
	in := []collect.ResolvedCPE{{CPE: "cpe:2.3:a:x:y", CVE: "CVE-2020-1",
		NVDVendor: "x", NVDProduct: "y", NVDRanges: []string{"[1, 2)"}}}
	require.NoError(t, s.PutCPEs(ctx, "pkg:npm/x", in), "PutCPEs after migration")
	got, err := s.GetCPEs(ctx, "pkg:npm/x")
	require.NoError(t, err, "GetCPEs after migration")
	require.True(t, got.Found, "GetCPEs after migration")
	assert.Equal(t, []string{"[1, 2)"}, got.Value[0].NVDRanges)
}

func TestCPEsRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	in := []collect.ResolvedCPE{
		{CPE: "cpe:2.3:a:lodash:lodash", CVE: "CVE-2021-23337", NVDVendor: "lodash",
			NVDProduct: "lodash", NVDTargetSw: "node.js", Ecosystem: "npm",
			MatchedBy:   []string{"name", "vendor", "ecosystem", "range"},
			NVDRanges:   []string{"[*, 4.17.21)", "[5.0.0, 5.0.1)"},
			OSVRanges:   []string{"[*, 4.17.21)"},
			Explanation: "matched by name lodash, range [*, 4.17.21) (CVE-2021-23337)"},
		{CPE: "cpe:2.3:a:foo:bar", CVE: "CVE-2020-1", NVDVendor: "foo", NVDProduct: "bar",
			MatchedBy: []string{"range"}, Explanation: "matched by range [1.0.0, 2.0.0)"},
	}
	require.NoError(t, s.PutCPEs(ctx, "pkg:npm/lodash", in), "PutCPEs")
	res, err := s.GetCPEs(ctx, "pkg:npm/lodash")
	require.NoError(t, err, "GetCPEs")
	require.True(t, res.Found)
	require.Len(t, res.Value, 2)
	byCPE := map[string]collect.ResolvedCPE{}
	for _, c := range res.Value {
		byCPE[c.CPE] = c
	}
	got := byCPE["cpe:2.3:a:lodash:lodash"]
	assert.Equal(t, "CVE-2021-23337", got.CVE)
	assert.Equal(t, "lodash", got.NVDVendor)
	assert.Equal(t, "node.js", got.NVDTargetSw)
	assert.Equal(t, []string{"[*, 4.17.21)", "[5.0.0, 5.0.1)"}, got.NVDRanges)
	assert.Equal(t, []string{"[*, 4.17.21)"}, got.OSVRanges)
	assert.NotEmpty(t, got.Explanation, "explanation not persisted")
	assert.Len(t, got.MatchedBy, 4)
	assert.Len(t, byCPE["cpe:2.3:a:foo:bar"].MatchedBy, 1)

	// PutCPEs replaces the set per spurl.
	require.NoError(t, s.PutCPEs(ctx, "pkg:npm/lodash", in[:1]), "PutCPEs replace")
	res2, err := s.GetCPEs(ctx, "pkg:npm/lodash")
	require.NoError(t, err)
	assert.Len(t, res2.Value, 1, "expected 1 cpe after replace")
}
