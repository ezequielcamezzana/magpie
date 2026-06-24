package cper

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// nvdRec builds an NVD VulnRecord for a CPE (vendor/product/target_sw encoded in
// the CPE 2.3 string in MatchedOn, as the real parser emits) with its ranges.
func nvdRec(vendor, product, targetSw string, ranges ...string) collect.VulnRecord {
	return collect.VulnRecord{
		Source:         collect.SourceNVD,
		MatchedOn:      collect.BuildCPE(vendor, product, targetSw),
		AffectedRanges: ranges,
	}
}

func acceptOne(t *testing.T, records []collect.VulnRecord, names, vendors, osvRanges []string, wantSw, eco string) []collect.ResolvedCPE {
	t.Helper()
	osvIntervals, osvOk := match.ParseIntervals(osvRanges)
	return acceptCPEs(records, "CVE-2020-1", names, vendors, osvRanges,
		lowerSet(names), lowerSet(vendors), wantSw, eco, osvIntervals, osvOk, map[string]bool{})
}

func TestAcceptCPE_NameAndVendor(t *testing.T) {
	recs := []collect.VulnRecord{nvdRec("lodash", "lodash", "", "[9.0.0, 9.9.9)")}
	// OSV brings a range that does NOT coincide with NVD's: accepted by name∧vendor.
	got := acceptOne(t, recs, []string{"lodash"}, []string{"lodash", "npm"},
		[]string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	require.Len(t, got, 1)
	assert.Subset(t, got[0].MatchedBy, []string{"name", "vendor"})
	assert.NotContains(t, got[0].MatchedBy, "range")
	// Ranges are stamped even when the range signal didn't match.
	assert.Equal(t, []string{"[9.0.0, 9.9.9)"}, got[0].NVDRanges)
	assert.Equal(t, []string{"[1.0.0, 2.0.0)"}, got[0].OSVRanges)
}

func TestAcceptCPE_NameAndEcosystem(t *testing.T) {
	// product matches a name, vendor does NOT, but target_sw pins node.js.
	recs := []collect.VulnRecord{nvdRec("acme", "chalk", "node.js")}
	got := acceptOne(t, recs, []string{"chalk"}, []string{"npm"}, nil, "node.js", "npm")
	require.Len(t, got, 1)
	assert.Subset(t, got[0].MatchedBy, []string{"name", "ecosystem"})
	assert.Equal(t, "node.js", got[0].NVDTargetSw)
}

func TestAcceptCPE_RangeSubsetWhenNoName(t *testing.T) {
	// neither name nor vendor match; OSV ⊆ NVD range bridges it.
	recs := []collect.VulnRecord{nvdRec("other", "thing", "", "[1.0.0, 2.0.0)")}
	got := acceptOne(t, recs, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	require.Len(t, got, 1)
	assert.Contains(t, got[0].MatchedBy, "range")
}

func TestAcceptCPE_RejectsUnrelated(t *testing.T) {
	// None matches name/vendor/ecosystem/range.
	recs := []collect.VulnRecord{
		nvdRec("other", "thing", "", "[5.0.0, 6.0.0)"),
		nvdRec("more", "stuff", "", "[7.0.0, 8.0.0)"),
	}
	got := acceptOne(t, recs, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	assert.Empty(t, got)
}

func TestAcceptCPE_SeparatorInsensitive(t *testing.T) {
	// purl name/vendor "7zip" vs NVD CPE "7-zip": the separator must not block
	// the name∧vendor acceptance (pkg:github.com/ip7z/7zip ↔ cpe:a:7-zip:7-zip).
	recs := []collect.VulnRecord{nvdRec("7-zip", "7-zip", "", "[0, 24.08)")}
	got := acceptOne(t, recs, []string{"7zip"}, []string{"7zip", "ip7z"}, nil, "", "")
	require.Len(t, got, 1)
	assert.Subset(t, got[0].MatchedBy, []string{"name", "vendor"})
}

func TestCandidatesFrom(t *testing.T) {
	id := purl.Identity{Type: "npm", Name: "lodash"}
	names, vendors := candidatesFrom(id, "https://github.com/lodash/lodash")
	assert.Contains(t, names, "lodash")
	assert.Contains(t, vendors, "npm")
	assert.Contains(t, vendors, "lodash")
}

// fakeStore is a minimal in-memory collect.Store: only cpes and vulns have
// real behavior; the rest are no-ops (Run doesn't touch them).
type fakeStore struct {
	cpes   map[string]collect.StoreResult[[]collect.ResolvedCPE]
	vulns  map[string]collect.StoreResult[[]collect.VulnRecord]
	missed map[string]time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cpes:   map[string]collect.StoreResult[[]collect.ResolvedCPE]{},
		vulns:  map[string]collect.StoreResult[[]collect.VulnRecord]{},
		missed: map[string]time.Time{},
	}
}

func (s *fakeStore) GetMissedCPE(ctx context.Context, spurl string) (collect.StoreResult[bool], error) {
	if t, ok := s.missed[spurl]; ok {
		return collect.StoreResult[bool]{Value: true, FetchedAt: t, Found: true}, nil
	}
	return collect.StoreResult[bool]{}, nil
}
func (s *fakeStore) PutMissedCPE(ctx context.Context, spurl string) error {
	s.missed[spurl] = time.Now().UTC()
	return nil
}
func (s *fakeStore) DeleteMissedCPE(ctx context.Context, spurl string) error {
	delete(s.missed, spurl)
	return nil
}

func (s *fakeStore) GetCPEs(ctx context.Context, spurl string) (collect.StoreResult[[]collect.ResolvedCPE], error) {
	return s.cpes[spurl], nil
}
func (s *fakeStore) PutCPEs(ctx context.Context, spurl string, cpes []collect.ResolvedCPE) error {
	if len(cpes) == 0 {
		return nil
	}
	s.cpes[spurl] = collect.StoreResult[[]collect.ResolvedCPE]{Value: cpes, FetchedAt: time.Now().UTC(), Found: true}
	return nil
}
func (s *fakeStore) GetVulns(ctx context.Context, source, queryKey string) (collect.StoreResult[[]collect.VulnRecord], error) {
	return s.vulns[source+"|"+queryKey], nil
}
func (s *fakeStore) PutVulns(ctx context.Context, source, queryKey string, vs []collect.VulnRecord) error {
	fetched := time.Now().UTC()
	if len(vs) > 0 && !vs[0].FetchedAt.IsZero() {
		fetched = vs[0].FetchedAt
	}
	s.vulns[source+"|"+queryKey] = collect.StoreResult[[]collect.VulnRecord]{Value: vs, FetchedAt: fetched, Found: true}
	return nil
}
func (s *fakeStore) GetComponent(context.Context, string) (collect.StoreResult[collect.Component], error) {
	return collect.StoreResult[collect.Component]{}, nil
}
func (s *fakeStore) PutComponent(context.Context, collect.Component) error { return nil }
func (s *fakeStore) GetRepository(context.Context, string) (collect.StoreResult[collect.Repository], error) {
	return collect.StoreResult[collect.Repository]{}, nil
}
func (s *fakeStore) PutRepository(context.Context, collect.Repository) error { return nil }
func (s *fakeStore) StaleComponents(context.Context, time.Time, int) ([]string, error) {
	return nil, nil
}
func (s *fakeStore) Metrics(context.Context, time.Time) (collect.Metrics, error) {
	return collect.Metrics{}, nil
}
func (s *fakeStore) QueryComponents(context.Context, collect.ComponentQuery) ([]collect.Component, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryCPEs(context.Context, collect.CPEQuery) ([]collect.ResolvedCPE, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryVulns(context.Context, collect.VulnQuery) ([]collect.VulnRecord, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) Close() error { return nil }

// stubNVD records which CVEs were requested, answering from a map of
// per-CPE records keyed by CVE. asked is mutex-guarded: Run fetches the
// candidate CVEs concurrently.
type stubNVD struct {
	byCVE map[string][]collect.VulnRecord
	mu    sync.Mutex
	asked []string
	fail  bool // when true, every FetchCVE errors (simulates NVD down/hung)
}

func (s *stubNVD) FetchCVE(ctx context.Context, cve string) ([]collect.VulnRecord, error) {
	s.mu.Lock()
	s.asked = append(s.asked, cve)
	s.mu.Unlock()
	if s.fail {
		return nil, fmt.Errorf("nvd: unavailable")
	}
	return s.byCVE[cve], nil
}

func identityFor(t *testing.T, coord string) purl.Identity {
	t.Helper()
	p, err := purl.Parse(coord)
	require.NoError(t, err)
	return purl.Decompose(p)
}

// TestRunResolvesCPE: the CVE linked by ecosyste.ms resolves to a CPE via the
// NVD stub; the CPE is persisted and the CVE's NVD records are cached per-CVE.
func TestRunResolvesCPE(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}
	records := []collect.VulnRecord{{
		Source: collect.SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x",
		Aliases: []string{"CVE-2021-23337"}, AffectedRanges: []string{"[*, 4.17.21)"},
	}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{
		"CVE-2021-23337": {nvdRec("lodash", "lodash", "node.js", "[*, 4.17.21)")},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl),
		spurl, "https://github.com/lodash/lodash", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found)
	require.Len(t, got.Value, 1)
	cpe := got.Value[0]
	assert.Equal(t, "cpe:2.3:a:lodash:lodash", cpe.CPE)
	assert.Equal(t, "CVE-2021-23337", cpe.CVE)
	assert.NotEmpty(t, cpe.Explanation)
	assert.Subset(t, cpe.MatchedBy, []string{"name", "ecosystem"})

	// The CVE's NVD records were cached under the per-CVE key.
	cached, _ := st.GetVulns(context.Background(), collect.SourceNVD, collect.NVDCVEKey("CVE-2021-23337"))
	require.True(t, cached.Found)
	require.Len(t, cached.Value, 1)
}

// TestRunServesStaleOnFetchError: when the VulnCheck fetch fails but a stale
// per-CVE cache exists, CPER resolves from the stale records and surfaces a
// non-fatal "vulncheck ... returning stale data" SourceError.
func TestRunServesStaleOnFetchError(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}

	cve := "CVE-2021-23337"
	records := []collect.VulnRecord{{OriginalID: cve, AffectedRanges: []string{"[*, 4.17.21)"}}}

	// Stale per-CVE cache (fetched 72h ago > MaxAge) so the fetch is attempted.
	stale := nvdRec("lodash", "lodash", "node.js", "[*, 4.17.21)")
	stale.FetchedAt = time.Now().Add(-72 * time.Hour)
	require.NoError(t, st.PutVulns(context.Background(), collect.SourceNVD,
		collect.NVDCVEKey(cve), []collect.VulnRecord{stale}))

	fetcher := &stubNVD{fail: true} // every FetchCVE errors

	errs := Run(context.Background(), fetcher, cfg, identityFor(t, spurl),
		spurl, "https://github.com/lodash/lodash", records, time.Now().UTC())

	// Resolved from the stale cache despite the failure.
	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found, "want CPE resolved from stale cache")
	assert.Equal(t, "cpe:2.3:a:lodash:lodash", got.Value[0].CPE)

	// Non-fatal vulncheck error noting stale data was served.
	require.Len(t, errs, 1)
	assert.Equal(t, collect.SourceVulnCheck, errs[0].Source)
	assert.Contains(t, errs[0].Err.Error(), "returning stale data")
}

// TestRunPerCVECacheSkipsRefetch: a second run with the per-CVE cache fresh
// doesn't hit NVD again (NVD's by-id endpoint is slow/rate-limited).
func TestRunPerCVECacheSkipsRefetch(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	// MaxAge=0 would force CPE refetch; use a real window so CPEs are NOT the
	// short-circuit — we want to exercise the per-CVE cache specifically.
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2021-23337", AffectedRanges: []string{"[*, 4.17.21)"}}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{
		"CVE-2021-23337": {nvdRec("lodash", "lodash", "node.js", "[*, 4.17.21)")},
	}}
	now := time.Now().UTC()

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now)
	require.Equal(t, []string{"CVE-2021-23337"}, fetcher.asked)

	// Wipe the resolved CPEs so the GetCPEs short-circuit can't hide the per-CVE
	// cache, then re-run: the CVE must come from cache, not NVD.
	st.cpes = map[string]collect.StoreResult[[]collect.ResolvedCPE]{}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now)
	assert.Equal(t, []string{"CVE-2021-23337"}, fetcher.asked, "second run must not re-fetch the cached CVE")
}

// TestRunFreshCPEsShortCircuit: fresh CPEs in the store → NVD is not touched.
func TestRunFreshCPEsShortCircuit(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	_ = st.PutCPEs(context.Background(), spurl, []collect.ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash"}})

	fetcher := &stubNVD{}
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2021-23337"}}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	assert.Empty(t, fetcher.asked, "fresh CPEs: want no NVD fetches")
}

// TestRunDoesNotWipeOnEmpty: a run that resolves nothing must not delete
// previously resolved CPEs (the axios disappearing-CPE bug, cpers/001).
func TestRunDoesNotWipeOnEmpty(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/axios"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(0)} // always re-resolve

	// Seed a previously resolved CPE.
	st.cpes[spurl] = collect.StoreResult[[]collect.ResolvedCPE]{
		Value: []collect.ResolvedCPE{{CPE: "cpe:2.3:a:axios:axios"}}, Found: true, FetchedAt: time.Now(),
	}

	// New run: the candidate CVEs are un-analyzed (NVD returns nothing).
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{}}
	records := []collect.VulnRecord{{OriginalID: "CVE-2026-44496"}, {OriginalID: "CVE-2026-44488"}}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found, "previously resolved CPE must survive an empty run")
	assert.Equal(t, "cpe:2.3:a:axios:axios", got.Value[0].CPE)
}

// TestRunResilientBudget: un-analyzed CVEs (no NVD data) don't burn the useful
// lookup budget — an older, analyzed CVE below the newest 5 still gets reached
// and resolved (cpers/002). 7 newest CVEs are empty; the 8th has data.
func TestRunResilientBudget(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []collect.VulnRecord
	byCVE := map[string][]collect.VulnRecord{}
	for i := 0; i < 8; i++ {
		cve := fmt.Sprintf("CVE-2026-%d", i)
		records = append(records, collect.VulnRecord{OriginalID: cve, Published: base.AddDate(0, 0, i)})
	}
	// Only the OLDEST (i=0, lowest Published) has analyzed NVD data.
	byCVE["CVE-2026-0"] = []collect.VulnRecord{nvdRec("lodash", "lodash", "node.js", "[*, 4.17.21)")}
	fetcher := &stubNVD{byCVE: byCVE}

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found, "the analyzed CVE below the newest 5 must still resolve")
	assert.Equal(t, "cpe:2.3:a:lodash:lodash", got.Value[0].CPE)
}

// TestRunReachesOldAnalyzedCVE: with many recent CVEs NVD hasn't analyzed (no
// CPE config) and the CPE living only on the oldest CVE, sampling new+old
// reaches it within the request budget. A flat newest-first walk spends all
// maxRequests on the recent un-analyzed CVEs and never reaches the old analyzed
// one (the hono bug, cpers/003).
func TestRunReachesOldAnalyzedCVE(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/hono"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []collect.VulnRecord
	byCVE := map[string][]collect.VulnRecord{}
	const total = 15 // well over maxRequests, like hono's 28 recent CVEs
	for i := 0; i < total; i++ {
		cve := fmt.Sprintf("CVE-2026-%02d", i)
		records = append(records, collect.VulnRecord{OriginalID: cve, Published: base.AddDate(0, 0, i)})
	}
	// Only the OLDEST (i=0) is analyzed and carries the CPE; the 14 newer CVEs
	// are un-analyzed (NVD returns nothing).
	byCVE["CVE-2026-00"] = []collect.VulnRecord{nvdRec("hono", "hono", "node.js", "[*, 4.9.7)")}
	fetcher := &stubNVD{byCVE: byCVE}

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl),
		spurl, "https://github.com/honojs/hono", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found, "the oldest analyzed CVE must be reached and resolved")
	assert.Equal(t, "cpe:2.3:a:hono:hono", got.Value[0].CPE)
}

// TestRunCachesMiss: a package whose search resolves no CPE records a miss, and
// a second run within MaxAge short-circuits without re-hitting NVD (the
// re-search-every-request slowness, cpers/005). The candidate CVE is
// un-analyzed (empty NVD), so absent the miss cache it would be re-fetched.
func TestRunCachesMiss(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:pypi/ansible"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2026-9999"}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{}} // un-analyzed → empty
	now := time.Now().UTC()

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now)
	require.Equal(t, []string{"CVE-2026-9999"}, fetcher.asked)
	got, _ := st.GetCPEs(context.Background(), spurl)
	require.False(t, got.Found, "no CPE resolved")
	miss, _ := st.GetMissedCPE(context.Background(), spurl)
	require.True(t, miss.Found, "a miss must be recorded")

	// Second run within MaxAge: the miss short-circuits, NVD is not touched.
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now)
	assert.Equal(t, []string{"CVE-2026-9999"}, fetcher.asked, "fresh miss: no NVD re-fetch")
}

// TestRunNoMissOnFetchFailure: when every NVD fetch fails (NVD down/hung), Run
// must NOT record a miss — otherwise the package freezes CPE-less until the miss
// expires, even after NVD recovers (the axios poisoned-miss bug). Contrast with
// TestRunCachesMiss, where NVD answers (empty) and a miss IS recorded.
func TestRunNoMissOnFetchFailure(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/axios"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2021-3749"}, {OriginalID: "CVE-2020-28168"}}
	fetcher := &stubNVD{fail: true} // NVD errors on every fetch

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	require.NotEmpty(t, fetcher.asked, "NVD was attempted")
	miss, _ := st.GetMissedCPE(context.Background(), spurl)
	assert.False(t, miss.Found, "a run where every fetch failed must not record a miss")
}

// TestRunRetriesExpiredMiss: once the miss is older than MaxAge, the next run
// searches again (NVD may have analyzed the CVE since).
func TestRunRetriesExpiredMiss(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:pypi/ansible"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2026-9999"}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{}}
	now := time.Now().UTC()

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now)
	require.Len(t, fetcher.asked, 1)

	// A run two hours later: the miss (stamped ~now) is stale → re-search.
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, now.Add(2*time.Hour))
	assert.Len(t, fetcher.asked, 2, "expired miss: must retry the search")
}

// TestRunClearsMissOnResolve: a later run that resolves a CPE drops the miss.
func TestRunClearsMissOnResolve(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(time.Hour)}
	st.missed[spurl] = time.Now().Add(-2 * time.Hour).UTC() // a stale prior miss
	records := []collect.VulnRecord{{OriginalID: "CVE-2021-23337", AffectedRanges: []string{"[*, 4.17.21)"}}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{
		"CVE-2021-23337": {nvdRec("lodash", "lodash", "node.js", "[*, 4.17.21)")},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl),
		spurl, "https://github.com/lodash/lodash", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	require.True(t, got.Found, "CPE resolved")
	miss, _ := st.GetMissedCPE(context.Background(), spurl)
	assert.False(t, miss.Found, "resolving a CPE must clear the miss")
}

// TestRunSkipsDistro: a distro purl (KindLinux) never resolves CPEs, even with
// a stub that would match. NVD-by-CPE is backport-unaware.
func TestRunSkipsDistro(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:deb/debian/curl"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}
	records := []collect.VulnRecord{{OriginalID: "CVE-2023-38545", AffectedRanges: []string{"[*, 8.4.0)"}}}
	fetcher := &stubNVD{byCVE: map[string][]collect.VulnRecord{
		"CVE-2023-38545": {nvdRec("curl", "curl", "", "[*, 8.4.0)")},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, "pkg:deb/debian/curl@7.88.1-10+deb12u4"),
		spurl, "https://github.com/curl/curl", records, time.Now().UTC())

	assert.Empty(t, fetcher.asked, "distro: want no NVD fetches")
	got, _ := st.GetCPEs(context.Background(), spurl)
	assert.False(t, got.Found, "distro: want 0 CPEs")
}

// TestRunSamplesNewestAndOldest: with more candidate CVEs than fit, Run fetches
// the maxLookups newest + maxLookups oldest by Published, skipping the middle
// (newestAndOldest). Parametric on maxLookups: 2*maxLookups+3 CVEs → the 3
// median ones are skipped.
func TestRunSamplesNewestAndOldest(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, MaxAge: collect.UniformMaxAge(24 * time.Hour)}

	const total = 2*maxLookups + 3 // enough to leave a 3-CVE median gap
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []collect.VulnRecord
	byCVE := map[string][]collect.VulnRecord{}
	cveFor := func(i int) string { return fmt.Sprintf("CVE-%d-1", 2010+i) }
	for i := 0; i < total; i++ {
		cve := cveFor(i)
		records = append(records, collect.VulnRecord{
			OriginalID: cve, Published: base.AddDate(0, 0, i),
		})
		byCVE[cve] = []collect.VulnRecord{nvdRec("x", "y", "")}
	}
	fetcher := &stubNVD{byCVE: byCVE}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	// Fetches run concurrently, so compare the set, not the order: oldest
	// maxLookups + newest maxLookups, with the median (indices [maxLookups,
	// total-maxLookups)) skipped.
	var want, median []string
	for i := 0; i < total; i++ {
		if i < maxLookups || i >= total-maxLookups {
			want = append(want, cveFor(i))
		} else {
			median = append(median, cveFor(i))
		}
	}
	assert.ElementsMatch(t, want, fetcher.asked)
	for _, cve := range median {
		assert.NotContains(t, fetcher.asked, cve, "median CVEs are not sampled")
	}
}
