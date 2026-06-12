package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	magpie "github.com/ezequielcamezzana/magpie"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
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
		if err != nil {
			t.Fatalf("table %q not found: %v", name, err)
		}
	}

	var idx string
	err := s.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vulns_canonical'`).Scan(&idx)
	if err != nil {
		t.Fatalf("idx_vulns_canonical not found: %v", err)
	}
}

func TestComponentRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := magpie.Component{
		SPURL:         "pkg:npm/left-pad",
		Name:          "left-pad",
		Description:   "pads on the left",
		Licenses:      []string{"MIT", "Apache-2.0"},
		LatestVersion: "1.3.0",
		RepoURL:       "https://github.com/left-pad/left-pad",
		Icon:          "https://example.com/icon.png",
		FetchedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}

	if err := s.PutComponent(ctx, in); err != nil {
		t.Fatalf("PutComponent: %v", err)
	}

	res, err := s.GetComponent(ctx, in.SPURL)
	if err != nil {
		t.Fatalf("GetComponent: %v", err)
	}
	if !res.Found {
		t.Fatal("expected Found=true")
	}

	got := res.Value
	if got.SPURL != in.SPURL || got.Name != in.Name || got.Description != in.Description ||
		got.LatestVersion != in.LatestVersion || got.RepoURL != in.RepoURL || got.Icon != in.Icon {
		t.Errorf("scalar fields mismatch: %+v", got)
	}
	if len(got.Licenses) != len(in.Licenses) {
		t.Fatalf("licenses len mismatch: got %v want %v", got.Licenses, in.Licenses)
	}
	for i := range in.Licenses {
		if got.Licenses[i] != in.Licenses[i] {
			t.Errorf("license[%d]: got %q want %q", i, got.Licenses[i], in.Licenses[i])
		}
	}
	if !got.FetchedAt.Equal(in.FetchedAt) {
		t.Errorf("FetchedAt: got %v want %v", got.FetchedAt, in.FetchedAt)
	}
	if !res.FetchedAt.Equal(in.FetchedAt) {
		t.Errorf("Result.FetchedAt: got %v want %v", res.FetchedAt, in.FetchedAt)
	}
}

func TestComponentEmptyLicenses(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := magpie.Component{SPURL: "pkg:npm/empty", Name: "empty"}
	if err := s.PutComponent(ctx, in); err != nil {
		t.Fatalf("PutComponent: %v", err)
	}
	res, err := s.GetComponent(ctx, in.SPURL)
	if err != nil {
		t.Fatalf("GetComponent: %v", err)
	}
	if len(res.Value.Licenses) != 0 {
		t.Errorf("expected empty licenses, got %v", res.Value.Licenses)
	}
}

func TestComponentNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetComponent(context.Background(), "pkg:npm/nope")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if res.Found {
		t.Error("expected Found=false")
	}
}

func TestComponentUpsert(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	first := magpie.Component{SPURL: "pkg:npm/x", Name: "old", LatestVersion: "1.0.0"}
	second := magpie.Component{SPURL: "pkg:npm/x", Name: "new", LatestVersion: "2.0.0", Licenses: []string{"MIT"}}

	if err := s.PutComponent(ctx, first); err != nil {
		t.Fatalf("PutComponent first: %v", err)
	}
	if err := s.PutComponent(ctx, second); err != nil {
		t.Fatalf("PutComponent second: %v", err)
	}

	res, err := s.GetComponent(ctx, "pkg:npm/x")
	if err != nil {
		t.Fatalf("GetComponent: %v", err)
	}
	if res.Value.Name != "new" || res.Value.LatestVersion != "2.0.0" {
		t.Errorf("expected second write, got %+v", res.Value)
	}
}

func TestRepositoryRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := magpie.Repository{
		URL:         "https://github.com/foo/bar",
		Stars:       1200,
		Forks:       34,
		Language:    "Go",
		LastPush:    time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond),
		LastRelease: time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond),
		FetchedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}

	if err := s.PutRepository(ctx, in); err != nil {
		t.Fatalf("PutRepository: %v", err)
	}

	res, err := s.GetRepository(ctx, in.URL)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !res.Found {
		t.Fatal("expected Found=true")
	}

	got := res.Value
	if got.URL != in.URL || got.Stars != in.Stars || got.Forks != in.Forks || got.Language != in.Language {
		t.Errorf("scalar fields mismatch: %+v", got)
	}
	if !got.LastPush.Equal(in.LastPush) {
		t.Errorf("LastPush: got %v want %v", got.LastPush, in.LastPush)
	}
	if !got.LastRelease.Equal(in.LastRelease) {
		t.Errorf("LastRelease: got %v want %v", got.LastRelease, in.LastRelease)
	}
	if !got.FetchedAt.Equal(in.FetchedAt) {
		t.Errorf("FetchedAt: got %v want %v", got.FetchedAt, in.FetchedAt)
	}
}

func TestRepositoryZeroTimes(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	in := magpie.Repository{URL: "https://github.com/zero/times", Stars: 1}
	if err := s.PutRepository(ctx, in); err != nil {
		t.Fatalf("PutRepository: %v", err)
	}
	res, err := s.GetRepository(ctx, in.URL)
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !res.Value.LastPush.IsZero() {
		t.Errorf("expected zero LastPush, got %v", res.Value.LastPush)
	}
	if !res.Value.LastRelease.IsZero() {
		t.Errorf("expected zero LastRelease, got %v", res.Value.LastRelease)
	}
}

func TestRepositoryNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetRepository(context.Background(), "https://github.com/no/pe")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if res.Found {
		t.Error("expected Found=false")
	}
}

func vulnRecord(id, canonical string, fetchedAt time.Time) magpie.VulnRecord {
	return magpie.VulnRecord{
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
	in := []magpie.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now.Add(-time.Hour)),
		vulnRecord("OSV-3", "CVE-2020-3", now.Add(-2*time.Hour)),
	}

	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", in); err != nil {
		t.Fatalf("PutVulns: %v", err)
	}

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	if !res.Found {
		t.Fatal("expected Found=true")
	}
	if len(res.Value) != 3 {
		t.Fatalf("expected 3 records, got %d", len(res.Value))
	}

	byID := map[string]magpie.VulnRecord{}
	for _, r := range res.Value {
		byID[r.OriginalID] = r
	}
	for _, want := range in {
		got, ok := byID[want.OriginalID]
		if !ok {
			t.Fatalf("missing record %q", want.OriginalID)
		}
		if got.CanonicalID != want.CanonicalID || got.Score != want.Score || got.Severity != want.Severity {
			t.Errorf("%s: scalar mismatch: %+v", want.OriginalID, got)
		}
		if got.AffectedPackage != want.AffectedPackage {
			t.Errorf("%s: AffectedPackage: got %q want %q", want.OriginalID, got.AffectedPackage, want.AffectedPackage)
		}
		if len(got.Aliases) != len(want.Aliases) || got.Aliases[0] != want.Aliases[0] {
			t.Errorf("%s: aliases mismatch: %v", want.OriginalID, got.Aliases)
		}
		if len(got.AffectedRanges) != 1 || got.AffectedRanges[0] != want.AffectedRanges[0] {
			t.Errorf("%s: ranges mismatch: %v", want.OriginalID, got.AffectedRanges)
		}
		if string(got.Payload) != string(want.Payload) {
			t.Errorf("%s: payload mismatch: %s", want.OriginalID, got.Payload)
		}
		if !got.FetchedAt.Equal(want.FetchedAt) {
			t.Errorf("%s: FetchedAt: got %v want %v", want.OriginalID, got.FetchedAt, want.FetchedAt)
		}
		if !got.Published.Equal(want.Published) {
			t.Errorf("%s: Published: got %v want %v", want.OriginalID, got.Published, want.Published)
		}
		if !got.Modified.Equal(want.Modified) {
			t.Errorf("%s: Modified: got %v want %v", want.OriginalID, got.Modified, want.Modified)
		}
	}
}

// TestVulnsEmptyListsAreNonNil locks the store-wide convention: empty list
// columns come back as non-nil empty slices, not nil (matches licenses).
func TestVulnsEmptyLists(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	in := magpie.VulnRecord{
		Source: "osv", QueryKey: "k", OriginalID: "OSV-1", CanonicalID: "CVE-2020-1",
		FetchedAt: now,
	}
	if err := s.PutVulns(ctx, "osv", "k", []magpie.VulnRecord{in}); err != nil {
		t.Fatalf("PutVulns: %v", err)
	}
	res, err := s.GetVulns(ctx, "osv", "k")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	got := res.Value[0]
	for name, list := range map[string][]string{
		"Aliases":            got.Aliases,
		"AffectedVersions":   got.AffectedVersions,
		"FixedVersions":      got.FixedVersions,
		"UnaffectedVersions": got.UnaffectedVersions,
	} {
		if list == nil {
			t.Errorf("%s: expected non-nil empty slice, got nil", name)
		}
	}
	if got.AffectedRanges == nil {
		t.Error("AffectedRanges: expected non-nil empty slice, got nil")
	}
}

func TestGetVulnsNotFound(t *testing.T) {
	s := openTest(t)
	res, err := s.GetVulns(context.Background(), "osv", "pkg:npm/nope")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if res.Found {
		t.Error("expected Found=false")
	}
}

func TestGetVulnsFetchedAtIsMin(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	oldest := now.Add(-3 * time.Hour)
	in := []magpie.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", oldest),
		vulnRecord("OSV-3", "CVE-2020-3", now.Add(-time.Hour)),
	}
	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", in); err != nil {
		t.Fatalf("PutVulns: %v", err)
	}
	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	if !res.FetchedAt.Equal(oldest) {
		t.Errorf("Result.FetchedAt: got %v want %v (min)", res.FetchedAt, oldest)
	}
}

func TestPutVulnsReplaces(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	setA := []magpie.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now),
		vulnRecord("OSV-3", "CVE-2020-3", now),
	}
	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setA); err != nil {
		t.Fatalf("PutVulns A: %v", err)
	}

	setB := []magpie.VulnRecord{vulnRecord("OSV-9", "CVE-2020-9", now)}
	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setB); err != nil {
		t.Fatalf("PutVulns B: %v", err)
	}

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	if len(res.Value) != 1 {
		t.Fatalf("expected 1 record after replace, got %d", len(res.Value))
	}
	if res.Value[0].OriginalID != "OSV-9" {
		t.Errorf("expected OSV-9, got %q", res.Value[0].OriginalID)
	}
}

// TestPutVulnsAtomic verifica que un Put que falla a mitad no deja state.
// Provocamos el fallo pasando dos records con el mismo OriginalID: el segundo
// INSERT viola la PK compuesta y aborta la transacción tras el DELETE.
func TestPutVulnsAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	setA := []magpie.VulnRecord{
		vulnRecord("OSV-1", "CVE-2020-1", now),
		vulnRecord("OSV-2", "CVE-2020-2", now),
	}
	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", setA); err != nil {
		t.Fatalf("PutVulns A: %v", err)
	}

	bad := []magpie.VulnRecord{
		vulnRecord("DUP", "CVE-X", now),
		vulnRecord("DUP", "CVE-Y", now),
	}
	if err := s.PutVulns(ctx, "osv", "pkg:npm/left-pad", bad); err == nil {
		t.Fatal("expected PutVulns to fail on duplicate PK")
	}

	res, err := s.GetVulns(ctx, "osv", "pkg:npm/left-pad")
	if err != nil {
		t.Fatalf("GetVulns: %v", err)
	}
	if len(res.Value) != 2 {
		t.Fatalf("expected set A intact (2 records), got %d", len(res.Value))
	}
}

// TestVulnsDedup es el corazón del cambio: la misma vuln (source, original_id)
// vista desde dos query_key distintos guarda UN solo header en vulns y dos
// filas en package_vuln, una por paquete afectado.
func TestVulnsDedup(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(queryKey, affPkg string) magpie.VulnRecord {
		r := vulnRecord("GHSA-shared", "CVE-2020-shared", now)
		r.QueryKey = queryKey
		r.AffectedPackage = affPkg
		return r
	}
	if err := s.PutVulns(ctx, "osv", "npm:axios", []magpie.VulnRecord{mk("npm:axios", "pkg:npm/axios")}); err != nil {
		t.Fatalf("PutVulns axios: %v", err)
	}
	if err := s.PutVulns(ctx, "osv", "npm:chalk", []magpie.VulnRecord{mk("npm:chalk", "pkg:npm/chalk")}); err != nil {
		t.Fatalf("PutVulns chalk: %v", err)
	}

	var vulnRows, pvRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM vulns`).Scan(&vulnRows); err != nil {
		t.Fatalf("count vulns: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM package_vuln`).Scan(&pvRows); err != nil {
		t.Fatalf("count package_vuln: %v", err)
	}
	if vulnRows != 1 {
		t.Errorf("expected 1 vulns header (deduped), got %d", vulnRows)
	}
	if pvRows != 2 {
		t.Errorf("expected 2 package_vuln rows, got %d", pvRows)
	}

	// Ambas queries devuelven el header completo + su propio affected_package.
	for _, tc := range []struct{ key, pkg string }{{"npm:axios", "pkg:npm/axios"}, {"npm:chalk", "pkg:npm/chalk"}} {
		res, err := s.GetVulns(ctx, "osv", tc.key)
		if err != nil {
			t.Fatalf("GetVulns %s: %v", tc.key, err)
		}
		if len(res.Value) != 1 {
			t.Fatalf("%s: expected 1 record, got %d", tc.key, len(res.Value))
		}
		got := res.Value[0]
		if got.CanonicalID != "CVE-2020-shared" || got.Score != 7.5 {
			t.Errorf("%s: header mismatch: %+v", tc.key, got)
		}
		if got.AffectedPackage != tc.pkg {
			t.Errorf("%s: AffectedPackage: got %q want %q", tc.key, got.AffectedPackage, tc.pkg)
		}
	}
}

func seedQueryVulns(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(source, key, id, canonical string, at time.Time) magpie.VulnRecord {
		r := vulnRecord(id, canonical, at)
		r.Source = source
		r.QueryKey = key
		return r
	}
	// Two records share canonical CVE-SHARED.
	if err := s.PutVulns(ctx, "osv", "k1", []magpie.VulnRecord{
		mk("osv", "k1", "OSV-A", "CVE-SHARED", now),
		mk("osv", "k1", "OSV-B", "CVE-2020-B", now.Add(-time.Hour)),
	}); err != nil {
		t.Fatalf("seed osv: %v", err)
	}
	if err := s.PutVulns(ctx, "nvd", "k2", []magpie.VulnRecord{
		mk("nvd", "k2", "CVE-SHARED", "CVE-SHARED", now.Add(-2*time.Hour)),
		mk("nvd", "k2", "CVE-2020-D", "CVE-2020-D", now.Add(-3*time.Hour)),
	}); err != nil {
		t.Fatalf("seed nvd: %v", err)
	}
}

func TestQueryVulnsByOriginalID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), magpie.VulnQuery{ID: "OSV-B", Page: 1, Limit: 25})
	if err != nil {
		t.Fatalf("QueryVulns: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
	if len(recs) != 1 || recs[0].OriginalID != "OSV-B" {
		t.Errorf("expected OSV-B, got %+v", recs)
	}
}

func TestQueryVulnsByCanonicalID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), magpie.VulnQuery{ID: "CVE-SHARED", Page: 1, Limit: 25})
	if err != nil {
		t.Fatalf("QueryVulns: %v", err)
	}
	// OSV-A (canonical CVE-SHARED) + CVE-SHARED (original_id == CVE-SHARED).
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
}

func TestQueryVulnsPagination(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	p1, total, err := s.QueryVulns(context.Background(), magpie.VulnQuery{Page: 1, Limit: 2})
	if err != nil {
		t.Fatalf("QueryVulns p1: %v", err)
	}
	if total != 4 {
		t.Fatalf("expected total 4, got %d", total)
	}
	if len(p1) != 2 {
		t.Fatalf("expected 2 on page 1, got %d", len(p1))
	}

	p2, _, err := s.QueryVulns(context.Background(), magpie.VulnQuery{Page: 2, Limit: 2})
	if err != nil {
		t.Fatalf("QueryVulns p2: %v", err)
	}
	if len(p2) != 2 {
		t.Fatalf("expected 2 on page 2, got %d", len(p2))
	}
	// Pages must not overlap.
	if p1[0].OriginalID == p2[0].OriginalID {
		t.Errorf("pages overlap: %q", p1[0].OriginalID)
	}
}

func TestQueryVulnsEmptyID(t *testing.T) {
	s := openTest(t)
	seedQueryVulns(t, s)

	recs, total, err := s.QueryVulns(context.Background(), magpie.VulnQuery{Page: 1, Limit: 25})
	if err != nil {
		t.Fatalf("QueryVulns: %v", err)
	}
	if total != 4 {
		t.Fatalf("expected total 4, got %d", total)
	}
	if len(recs) != 4 {
		t.Fatalf("expected 4 records, got %d", len(recs))
	}
}

// TestOpenMigratesOldCPEsTable: una DB creada antes de las columnas
// nvd_ranges/osv_ranges se migra al abrir (ALTER idempotente).
func TestOpenMigratesOldCPEsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE cpes (
		spurl TEXT NOT NULL, cpe TEXT NOT NULL,
		vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
		target_sw TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '',
		ecosystem TEXT NOT NULL DEFAULT '',
		matched_name INTEGER NOT NULL DEFAULT 0, matched_vendor INTEGER NOT NULL DEFAULT 0,
		matched_ecosystem INTEGER NOT NULL DEFAULT 0, matched_range INTEGER NOT NULL DEFAULT 0,
		explanation TEXT NOT NULL DEFAULT '', fetched_at TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (spurl, cpe))`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open over old schema: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ctx := context.Background()
	in := []magpie.ResolvedCPE{{CPE: "cpe:2.3:a:x:y", CVE: "CVE-2020-1",
		NVDVendor: "x", NVDProduct: "y", NVDRanges: []string{"[1, 2)"}}}
	if err := s.PutCPEs(ctx, "pkg:npm/x", in); err != nil {
		t.Fatalf("PutCPEs after migration: %v", err)
	}
	got, err := s.GetCPEs(ctx, "pkg:npm/x")
	if err != nil || !got.Found {
		t.Fatalf("GetCPEs after migration: %v %+v", err, got)
	}
	if len(got.Value[0].NVDRanges) != 1 || got.Value[0].NVDRanges[0] != "[1, 2)" {
		t.Errorf("NVDRanges = %v", got.Value[0].NVDRanges)
	}
}

func TestCPEsRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	in := []magpie.ResolvedCPE{
		{CPE: "cpe:2.3:a:lodash:lodash", CVE: "CVE-2021-23337", NVDVendor: "lodash",
			NVDProduct: "lodash", NVDTargetSw: "node.js", Ecosystem: "npm",
			MatchedBy:   []string{"name", "vendor", "ecosystem", "range"},
			NVDRanges:   []string{"[*, 4.17.21)", "[5.0.0, 5.0.1)"},
			OSVRanges:   []string{"[*, 4.17.21)"},
			Explanation: "matched by name lodash, range [*, 4.17.21) (CVE-2021-23337)"},
		{CPE: "cpe:2.3:a:foo:bar", CVE: "CVE-2020-1", NVDVendor: "foo", NVDProduct: "bar",
			MatchedBy: []string{"range"}, Explanation: "matched by range [1.0.0, 2.0.0)"},
	}
	if err := s.PutCPEs(ctx, "pkg:npm/lodash", in); err != nil {
		t.Fatalf("PutCPEs: %v", err)
	}
	res, err := s.GetCPEs(ctx, "pkg:npm/lodash")
	if err != nil {
		t.Fatalf("GetCPEs: %v", err)
	}
	if !res.Found || len(res.Value) != 2 {
		t.Fatalf("expected 2 cpes, got %+v", res)
	}
	byCPE := map[string]magpie.ResolvedCPE{}
	for _, c := range res.Value {
		byCPE[c.CPE] = c
	}
	got := byCPE["cpe:2.3:a:lodash:lodash"]
	if got.CVE != "CVE-2021-23337" || got.NVDVendor != "lodash" || got.NVDTargetSw != "node.js" {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if len(got.NVDRanges) != 2 || got.NVDRanges[0] != "[*, 4.17.21)" {
		t.Errorf("NVDRanges = %v", got.NVDRanges)
	}
	if len(got.OSVRanges) != 1 || got.OSVRanges[0] != "[*, 4.17.21)" {
		t.Errorf("OSVRanges = %v", got.OSVRanges)
	}
	if got.Explanation == "" {
		t.Error("explanation not persisted")
	}
	if len(got.MatchedBy) != 4 {
		t.Errorf("matchedBy = %v", got.MatchedBy)
	}
	if len(byCPE["cpe:2.3:a:foo:bar"].MatchedBy) != 1 {
		t.Errorf("foo matchedBy = %v", byCPE["cpe:2.3:a:foo:bar"].MatchedBy)
	}

	// PutCPEs replaces the set per spurl.
	if err := s.PutCPEs(ctx, "pkg:npm/lodash", in[:1]); err != nil {
		t.Fatalf("PutCPEs replace: %v", err)
	}
	res2, _ := s.GetCPEs(ctx, "pkg:npm/lodash")
	if len(res2.Value) != 1 {
		t.Fatalf("expected 1 cpe after replace, got %d", len(res2.Value))
	}
}
