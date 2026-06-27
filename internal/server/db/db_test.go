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

	for _, idx := range []string{"idx_vulns_canonical", "idx_vulns_original", "idx_package_vuln_source_oid", "idx_pv_canon"} {
		var got string
		err := s.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&got)
		require.NoError(t, err, "index %q not found", idx)
	}
}

func TestStaleComponents(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	put := func(spurl string, age time.Duration) {
		require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: spurl, FetchedAt: now.Add(-age)}))
	}
	put("pkg:npm/fresh", 1*time.Hour)
	put("pkg:npm/old", 13*time.Hour)
	put("pkg:npm/oldest", 30*time.Hour)

	cutoff := now.Add(-12 * time.Hour)

	got, err := s.StaleComponents(ctx, cutoff, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"pkg:npm/oldest", "pkg:npm/old"}, got, "oldest first, fresh excluded")

	// Limit caps the result at the oldest.
	got, err = s.StaleComponents(ctx, cutoff, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"pkg:npm/oldest"}, got)
}

func TestFoldLegacyKeysComponents(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Legacy capital-case row beside the canonical lowercase row, plus a legacy
	// row with no canonical sibling (must be renamed, not dropped).
	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: "pkg:cargo/Deno", Name: "old", FetchedAt: now.Add(-30 * time.Hour)}))
	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: "pkg:cargo/deno", Name: "new", FetchedAt: now}))
	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: "pkg:npm/React", Name: "react", FetchedAt: now}))

	require.NoError(t, foldLegacyKeys(s.db))

	all, _, err := s.QueryComponents(ctx, collect.ComponentQuery{Limit: 100})
	require.NoError(t, err)
	var spurls []string
	for _, c := range all {
		spurls = append(spurls, c.SPURL)
	}
	assert.ElementsMatch(t, []string{"pkg:cargo/deno", "pkg:npm/react"}, spurls)

	// The canonical row won the collision: its metadata survived.
	got, _ := s.GetComponent(ctx, "pkg:cargo/deno")
	assert.Equal(t, "new", got.Value.Name)

	// Idempotent: a second run changes nothing.
	require.NoError(t, foldLegacyKeys(s.db))
	all2, _, _ := s.QueryComponents(ctx, collect.ComponentQuery{Limit: 100})
	assert.Len(t, all2, 2)
}

func TestFoldLegacyKeysSatellites(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, s.PutCPEs(ctx, "pkg:cargo/Deno", []collect.ResolvedCPE{{CPE: "cpe:2.3:a:deno:deno", CVE: "CVE-1"}}))
	require.NoError(t, s.PutMissedCPE(ctx, "pkg:npm/React"))
	require.NoError(t, s.PutVulns(ctx, collect.SourceEcosystems, "pkg:cargo/Deno", []collect.VulnRecord{
		{OriginalID: "X-1", AffectedPackage: "pkg:cargo/Deno", FetchedAt: now},
	}))

	require.NoError(t, foldLegacyKeys(s.db))

	cpes, err := s.GetCPEs(ctx, "pkg:cargo/deno")
	require.NoError(t, err)
	assert.True(t, cpes.Found, "cpes re-keyed to canonical")

	miss, err := s.GetMissedCPE(ctx, "pkg:npm/react")
	require.NoError(t, err)
	assert.True(t, miss.Found, "missed_cpe re-keyed")

	vulns, err := s.GetVulns(ctx, collect.SourceEcosystems, "pkg:cargo/deno")
	require.NoError(t, err)
	require.True(t, vulns.Found, "eco vulns re-keyed")
	assert.Equal(t, "pkg:cargo/deno", vulns.Value[0].AffectedPackage, "affected_package re-pointed")

	// Legacy keys are gone.
	old, _ := s.GetCPEs(ctx, "pkg:cargo/Deno")
	assert.False(t, old.Found)
}

func TestDeleteComponent(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	spurl := "pkg:npm/lodash"
	osvKey := "npm:lodash"
	rec := func(id string) collect.VulnRecord {
		return collect.VulnRecord{OriginalID: id, CanonicalID: id, FetchedAt: now}
	}

	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: spurl, Name: "lodash", FetchedAt: now}))
	require.NoError(t, s.PutCPEs(ctx, spurl, []collect.ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash", CVE: "CVE-2021-23337"}}))
	require.NoError(t, s.PutMissedCPE(ctx, spurl))
	require.NoError(t, s.PutVulns(ctx, "ecosyste.ms", spurl, []collect.VulnRecord{rec("GHSA-eco")}))
	require.NoError(t, s.PutVulns(ctx, "osv", osvKey, []collect.VulnRecord{rec("GHSA-osv")}))
	// Shared NVD per-CPE cache — other packages may resolve to the same CPE, so
	// it must survive the delete.
	require.NoError(t, s.PutVulns(ctx, "nvd", "nvd:cpe:2.3:a:lodash:lodash", []collect.VulnRecord{rec("CVE-2021-23337")}))

	r, err := s.DeleteComponent(ctx, spurl, osvKey)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Component)
	assert.Equal(t, 1, r.CPEs)
	assert.Equal(t, 1, r.MissedCPE)
	assert.Equal(t, 1, r.EcoVulns)
	assert.Equal(t, 1, r.OSVVulns)

	// Package-specific rows are gone.
	c, _ := s.GetComponent(ctx, spurl)
	assert.False(t, c.Found, "component")
	cp, _ := s.GetCPEs(ctx, spurl)
	assert.False(t, cp.Found, "cpes")
	m, _ := s.GetMissedCPE(ctx, spurl)
	assert.False(t, m.Found, "missed_cpes")
	eco, _ := s.GetVulns(ctx, "ecosyste.ms", spurl)
	assert.False(t, eco.Found, "eco vulns")
	osv, _ := s.GetVulns(ctx, "osv", osvKey)
	assert.False(t, osv.Found, "osv vulns")

	// Shared NVD cache survives.
	nvd, _ := s.GetVulns(ctx, "nvd", "nvd:cpe:2.3:a:lodash:lodash")
	assert.True(t, nvd.Found, "shared NVD cache must survive")
}

func TestMetrics(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: "pkg:npm/fresh", FetchedAt: now.Add(-1 * time.Hour)}))
	require.NoError(t, s.PutComponent(ctx, collect.Component{SPURL: "pkg:npm/stale", FetchedAt: now.Add(-30 * time.Hour)}))
	require.NoError(t, s.PutCPEs(ctx, "pkg:npm/fresh", []collect.ResolvedCPE{{CPE: "cpe:2.3:a:foo:fresh"}}))
	require.NoError(t, s.PutMissedCPE(ctx, "pkg:npm/stale"))

	m, err := s.Metrics(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 2, m.Components)
	assert.Equal(t, 1, m.CPEs)
	assert.Equal(t, 1, m.ComponentsWithCPE)
	assert.Equal(t, 1, m.MissedCPEs)
	assert.Equal(t, 1, m.StaleComponents, "the 30h-old component is stale")
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
		Summary:            "summary for " + id,
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
		assert.Equal(t, want.Summary, got.Summary, want.OriginalID)
		assert.Equal(t, want.Score, got.Score, want.OriginalID)
		assert.Equal(t, want.Severity, got.Severity, want.OriginalID)
		assert.Equal(t, want.AffectedPackage, got.AffectedPackage, want.OriginalID)
		// matched_on falls back to the affected purl when unset (OSV/eco path).
		assert.Equal(t, want.AffectedPackage, got.MatchedOn, want.OriginalID)
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

// TestQueryVulnsCollapseExcludesUnattached: the collapsed list omits package_vuln
// rows with an empty affected_package (CPER's raw per-CVE cache), while the
// non-collapsed by-id read still returns them.
func TestQueryVulnsCollapseExcludesUnattached(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Real impact: affected_package set.
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:lodash", []collect.VulnRecord{
		{Source: "osv", OriginalID: "OSV-REAL", CanonicalID: "CVE-2021-1", AffectedPackage: "pkg:npm/lodash", FetchedAt: now},
	}), "seed impact")
	// CPER per-CVE cache row: empty affected_package.
	require.NoError(t, s.PutVulns(ctx, "nvd", "cve:CVE-2021-9", []collect.VulnRecord{
		{Source: "nvd", OriginalID: "CVE-2021-9", CanonicalID: "CVE-2021-9", AffectedPackage: "", FetchedAt: now},
	}), "seed cache")

	// Collapsed list: only the real impact.
	recs, total, err := s.QueryVulns(ctx, collect.VulnQuery{Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "collapsed list excludes the unattached cache row")
	require.Len(t, recs, 1)
	assert.Equal(t, "OSV-REAL", recs[0].OriginalID)

	// Non-collapsed by-id read still finds the cache row (the /vuln detail path).
	recs, total, err = s.QueryVulns(ctx, collect.VulnQuery{ID: "CVE-2021-9", Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, recs, 1)
	assert.Equal(t, "CVE-2021-9", recs[0].OriginalID)
}

func TestQueryVulnsSourceFilterAndOrder(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(source, id string, score float64, publishedDay, modifiedDay int) collect.VulnRecord {
		return collect.VulnRecord{
			Source: source, QueryKey: source + ":k", OriginalID: id, CanonicalID: id,
			AffectedPackage: "pkg:npm/x",
			Score:           score,
			Published:       base.AddDate(0, 0, publishedDay),
			Modified:        base.AddDate(0, 0, modifiedDay),
			FetchedAt:       base,
		}
	}
	require.NoError(t, s.PutVulns(ctx, "osv", "osv:k", []collect.VulnRecord{
		mk("osv", "OSV-LOW", 3.1, 1, 2),
	}), "seed osv")
	require.NoError(t, s.PutVulns(ctx, "nvd", "nvd:k", []collect.VulnRecord{
		mk("nvd", "NVD-HIGH", 9.8, 10, 20),
		mk("nvd", "NVD-MED", 5.0, 5, 3),
	}), "seed nvd")

	// The list path is always collapsed; ordering applies there. (Distinct
	// canonicals here, so collapse keeps all three rows.)
	// Source filter: only nvd rows.
	recs, total, err := s.QueryVulns(ctx, collect.VulnQuery{Source: "nvd", Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	for _, r := range recs {
		assert.Equal(t, "nvd", r.Source)
	}

	// Each sort key puts NVD-HIGH first (top CVSS, newest published, newest modified).
	for _, order := range []string{"cvss", "created", "updated"} {
		recs, _, err := s.QueryVulns(ctx, collect.VulnQuery{Order: order, Collapse: true, Page: 1, Limit: 25})
		require.NoError(t, err, order)
		require.Len(t, recs, 3, order)
		assert.Equal(t, "NVD-HIGH", recs[0].OriginalID, "order=%s", order)
	}

	// CVSS order lowest is last.
	recs, _, err = s.QueryVulns(ctx, collect.VulnQuery{Order: "cvss", Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, "OSV-LOW", recs[2].OriginalID)

	// Source + order combine.
	recs, total, err = s.QueryVulns(ctx, collect.VulnQuery{Source: "nvd", Order: "cvss", Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Equal(t, "NVD-HIGH", recs[0].OriginalID)
}

func TestQueryVulnsCollapseAndFuzzy(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(source, qk, matchedOn string, score float64) collect.VulnRecord {
		return collect.VulnRecord{
			Source: source, QueryKey: qk, OriginalID: "GHSA-2026-multi", CanonicalID: "CVE-2026-1234",
			MatchedOn: matchedOn, AffectedPackage: matchedOn, Score: score, FetchedAt: base,
		}
	}
	// The same logical vuln (canonical CVE-2026-1234) seen three ways: two
	// packages under osv, and once more mirrored from ecosyste.ms.
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:a", []collect.VulnRecord{mk("osv", "npm:a", "pkg:npm/a", 7.0)}), "seed a")
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:b", []collect.VulnRecord{mk("osv", "npm:b", "pkg:npm/b", 7.0)}), "seed b")
	require.NoError(t, s.PutVulns(ctx, "ecosyste.ms", "npm:a", []collect.VulnRecord{mk("ecosyste.ms", "npm:a", "pkg:npm/a", 9.1)}), "seed eco")

	// Per-impact (detail): every row.
	_, total, err := s.QueryVulns(ctx, collect.VulnQuery{Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "non-collapsed shows each package/source")

	// Collapsed (list): one row for the vuln, even across packages and sources.
	recs, total, err := s.QueryVulns(ctx, collect.VulnQuery{Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "collapsed shows the vuln once")
	require.Len(t, recs, 1)
	assert.Equal(t, 9.1, recs[0].Score, "representative row is the highest-severity instance")

	// Fuzzy substring matches the canonical CVE; exact does not.
	_, total, err = s.QueryVulns(ctx, collect.VulnQuery{ID: "CVE-2026", Fuzzy: true, Collapse: true, Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "fuzzy 'CVE-2026' matches CVE-2026-1234")

	_, total, err = s.QueryVulns(ctx, collect.VulnQuery{ID: "CVE-2026", Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 0, total, "exact 'CVE-2026' matches nothing")
}

// TestQueryVulnsCollapseSummaryAndOrder: the collapsed list returns one row per
// canonical with its summary (joined from vulns for the page), the representative
// is the top-score instance, and every order key lists the right group first.
func TestQueryVulnsCollapseSummaryAndOrder(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(source, qk, oid, canonical, pkg, summary string, score float64, day int) collect.VulnRecord {
		return collect.VulnRecord{
			Source: source, QueryKey: qk, OriginalID: oid, CanonicalID: canonical,
			MatchedOn: pkg, AffectedPackage: pkg, Summary: summary, Score: score,
			Published: base.AddDate(0, 0, day), Modified: base.AddDate(0, 0, day),
			FetchedAt: base.AddDate(0, 0, day),
		}
	}
	// Group SHARED: two impacts of the same canonical under different sources, so
	// they carry distinct vulns headers; the eco one has the top score.
	require.NoError(t, s.PutVulns(ctx, "osv", "npm:a", []collect.VulnRecord{
		mk("osv", "npm:a", "OSV-A", "CVE-SHARED", "pkg:npm/a", "low summary", 4.0, 1),
	}), "seed osv")
	require.NoError(t, s.PutVulns(ctx, "ecosyste.ms", "npm:b", []collect.VulnRecord{
		mk("ecosyste.ms", "npm:b", "OSV-A", "CVE-SHARED", "pkg:npm/b", "top summary", 9.0, 1),
	}), "seed eco")
	// A distinct, lower-scored vuln that is newer on every date axis.
	require.NoError(t, s.PutVulns(ctx, "nvd", "nvd:k", []collect.VulnRecord{
		mk("nvd", "nvd:k", "CVE-OTHER", "CVE-OTHER", "pkg:npm/c", "other summary", 6.0, 10),
	}), "seed nvd")

	// CVSS: SHARED (max 9.0) first; representative is the top-score member, so its
	// score and joined summary come from the eco instance.
	recs, total, err := s.QueryVulns(ctx, collect.VulnQuery{Collapse: true, Order: "cvss", Page: 1, Limit: 25})
	require.NoError(t, err, "cvss")
	assert.Equal(t, 2, total, "two canonicals")
	require.Len(t, recs, 2)
	assert.Equal(t, "CVE-SHARED", recs[0].CanonicalID)
	assert.Equal(t, 9.0, recs[0].Score, "representative is the top-score instance")
	assert.Equal(t, "top summary", recs[0].Summary, "summary joined from the representative member")
	assert.Equal(t, "CVE-OTHER", recs[1].CanonicalID)

	// Date axes: OTHER is newer, so it leads; total stays stable.
	for _, order := range []string{"created", "updated", ""} {
		recs, total, err := s.QueryVulns(ctx, collect.VulnQuery{Collapse: true, Order: order, Page: 1, Limit: 25})
		require.NoError(t, err, "order=%q", order)
		assert.Equal(t, 2, total, "order=%q", order)
		require.Len(t, recs, 2, "order=%q", order)
		assert.Equal(t, "CVE-OTHER", recs[0].CanonicalID, "order=%q", order)
	}
}

// TestOpenBackfillsPackageVuln: a DB created before the denormalized columns is
// migrated and backfilled from vulns on open, and the collapsed list reads them.
func TestOpenBackfillsPackageVuln(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	old, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = old.Exec(`
		CREATE TABLE vulns (source TEXT NOT NULL, original_id TEXT NOT NULL,
			canonical_id TEXT, aliases TEXT, summary TEXT NOT NULL DEFAULT '',
			score REAL, severity TEXT, published_at TEXT, modified_at TEXT,
			payload TEXT, fetched_at TEXT NOT NULL, PRIMARY KEY (source, original_id));
		CREATE TABLE package_vuln (source TEXT NOT NULL, query_key TEXT NOT NULL,
			affected_package TEXT, matched_on TEXT NOT NULL DEFAULT '',
			original_id TEXT NOT NULL, affected_versions TEXT, affected_ranges TEXT,
			fixed_versions TEXT, unaffected_versions TEXT, fetched_at TEXT NOT NULL,
			PRIMARY KEY (source, query_key, original_id));
		INSERT INTO vulns (source, original_id, canonical_id, aliases, summary, score, severity, published_at, modified_at, payload, fetched_at)
			VALUES ('osv', 'OSV-A', 'CVE-OLD', '[]', 'old summary', 8.8, 'HIGH', '2020-01-01T00:00:00Z', '2020-02-01T00:00:00Z', '', '2020-01-01T00:00:00Z');
		INSERT INTO package_vuln (source, query_key, affected_package, matched_on, original_id, affected_versions, affected_ranges, fixed_versions, unaffected_versions, fetched_at)
			VALUES ('osv', 'npm:a', 'pkg:npm/a', 'pkg:npm/a', 'OSV-A', '[]', '[]', '[]', '[]', '2020-01-01T00:00:00Z');`)
	require.NoError(t, err)
	old.Close()

	s, err := Open(path)
	require.NoError(t, err, "Open over old schema")
	t.Cleanup(func() { s.Close() })

	// Backfill copied the header fields into the new columns.
	var canon, sev string
	var score float64
	require.NoError(t, s.db.QueryRow(
		`SELECT canonical_id, score, severity FROM package_vuln WHERE original_id = 'OSV-A'`).Scan(&canon, &score, &sev))
	assert.Equal(t, "CVE-OLD", canon)
	assert.Equal(t, 8.8, score)
	assert.Equal(t, "HIGH", sev)

	// The collapsed list reads the denormalized columns and still joins summary.
	recs, total, err := s.QueryVulns(context.Background(), collect.VulnQuery{Collapse: true, Order: "cvss", Page: 1, Limit: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, recs, 1)
	assert.Equal(t, "CVE-OLD", recs[0].CanonicalID)
	assert.Equal(t, "old summary", recs[0].Summary)
	assert.Equal(t, 8.8, recs[0].Score)
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
