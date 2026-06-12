package cper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

func acceptOne(t *testing.T, cve *collect.NVDCVE, names, vendors, osvRanges []string, wantSw, eco string) []collect.ResolvedCPE {
	t.Helper()
	osvIntervals, osvOk := match.ParseIntervals(osvRanges)
	return acceptCPEs(cve, "CVE-2020-1", names, vendors, osvRanges,
		lowerSet(names), lowerSet(vendors), wantSw, eco, osvIntervals, osvOk, map[string]bool{})
}

func TestAcceptCPE_NameAndVendor(t *testing.T) {
	cve := &collect.NVDCVE{Matches: []collect.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:lodash:lodash", Vendor: "lodash", Product: "lodash",
			AffectedRanges: []string{"[9.0.0, 9.9.9)"}},
	}}
	// OSV brings a range that does NOT coincide with NVD's: accepted by name∧vendor.
	got := acceptOne(t, cve, []string{"lodash"}, []string{"lodash", "npm"},
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
	cve := &collect.NVDCVE{Matches: []collect.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:acme:chalk", Vendor: "acme", Product: "chalk", TargetSw: "node.js"},
	}}
	got := acceptOne(t, cve, []string{"chalk"}, []string{"npm"}, nil, "node.js", "npm")
	require.Len(t, got, 1)
	assert.Subset(t, got[0].MatchedBy, []string{"name", "ecosystem"})
	assert.Equal(t, "node.js", got[0].NVDTargetSw)
}

func TestAcceptCPE_RangeSubsetWhenNoName(t *testing.T) {
	// neither name nor vendor match; OSV ⊆ NVD range bridges it.
	cve := &collect.NVDCVE{Matches: []collect.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:other:thing", Vendor: "other", Product: "thing",
			AffectedRanges: []string{"[1.0.0, 2.0.0)"}},
	}}
	got := acceptOne(t, cve, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	require.Len(t, got, 1)
	assert.Contains(t, got[0].MatchedBy, "range")
}

func TestAcceptCPE_RejectsUnrelated(t *testing.T) {
	// None matches name/vendor/ecosystem/range.
	cve := &collect.NVDCVE{Matches: []collect.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:other:thing", Vendor: "other", Product: "thing",
			TargetSw: "*", AffectedRanges: []string{"[5.0.0, 6.0.0)"}},
		{PartialCPE: "cpe:2.3:a:more:stuff", Vendor: "more", Product: "stuff",
			TargetSw: "*", AffectedRanges: []string{"[7.0.0, 8.0.0)"}},
	}}
	got := acceptOne(t, cve, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	assert.Empty(t, got)
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
	cpes  map[string]collect.StoreResult[[]collect.ResolvedCPE]
	vulns map[string]collect.StoreResult[[]collect.VulnRecord]
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cpes:  map[string]collect.StoreResult[[]collect.ResolvedCPE]{},
		vulns: map[string]collect.StoreResult[[]collect.VulnRecord]{},
	}
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
	s.vulns[source+"|"+queryKey] = collect.StoreResult[[]collect.VulnRecord]{Value: vs, Found: true}
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

// stubNVD records which CVEs were requested, besides answering from a map.
type stubNVD struct {
	byCVE map[string]*collect.NVDCVE
	asked []string
}

func (s *stubNVD) FetchCVE(ctx context.Context, cve string) (*collect.NVDCVE, error) {
	s.asked = append(s.asked, cve)
	return s.byCVE[cve], nil
}

func identityFor(t *testing.T, coord string) purl.Identity {
	t.Helper()
	p, err := purl.Parse(coord)
	require.NoError(t, err)
	return purl.Decompose(p)
}

// TestRunResolvesCPE: the CVE linked by ecosyste.ms resolves to a CPE via the
// NVD stub; the CPE and the source=nvd vuln record end up persisted.
func TestRunResolvesCPE(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []collect.VulnRecord{{
		Source: collect.SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x",
		Aliases: []string{"CVE-2021-23337"}, AffectedRanges: []string{"[*, 4.17.21)"},
	}}
	fetcher := &stubNVD{byCVE: map[string]*collect.NVDCVE{
		"CVE-2021-23337": {
			ID: "CVE-2021-23337", Score: 7.2, Severity: "HIGH",
			Matches: []collect.NVDCPEMatch{{
				PartialCPE: "cpe:2.3:a:lodash:lodash", Vendor: "lodash", Product: "lodash",
				TargetSw: "node.js", AffectedRanges: []string{"[*, 4.17.21)"}, FixedVersions: []string{"4.17.21"},
			}},
		},
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

	vulns, _ := st.GetVulns(context.Background(), collect.SourceNVD, spurl)
	require.True(t, vulns.Found)
	require.Len(t, vulns.Value, 1)
	assert.Equal(t, "CVE-2021-23337", vulns.Value[0].OriginalID)
}

// TestRunFreshCPEsShortCircuit: fresh CPEs in the store → NVD is not touched.
func TestRunFreshCPEsShortCircuit(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	_ = st.PutCPEs(context.Background(), spurl, []collect.ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash"}})

	fetcher := &stubNVD{}
	cfg := collect.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []collect.VulnRecord{{OriginalID: "CVE-2021-23337"}}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	assert.Empty(t, fetcher.asked, "fresh CPEs: want no NVD fetches")
}

// TestRunSkipsDistro: a distro purl (KindLinux) never resolves CPEs or
// source=nvd records, even with NVDAPIKey and a stub that would match.
// NVD-by-CPE is backport-unaware → false positives on distros.
func TestRunSkipsDistro(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:deb/debian/curl"
	cfg := collect.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []collect.VulnRecord{{
		OriginalID: "CVE-2023-38545", AffectedRanges: []string{"[*, 8.4.0)"},
	}}
	fetcher := &stubNVD{byCVE: map[string]*collect.NVDCVE{
		"CVE-2023-38545": {
			ID: "CVE-2023-38545", Score: 9.8, Severity: "CRITICAL",
			Matches: []collect.NVDCPEMatch{{
				PartialCPE: "cpe:2.3:a:curl:curl", Vendor: "curl", Product: "curl",
				AffectedRanges: []string{"[*, 8.4.0)"}, FixedVersions: []string{"8.4.0"},
			}},
		},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, "pkg:deb/debian/curl@7.88.1-10+deb12u4"),
		spurl, "https://github.com/curl/curl", records, time.Now().UTC())

	assert.Empty(t, fetcher.asked, "distro: want no NVD fetches")
	got, _ := st.GetCPEs(context.Background(), spurl)
	assert.False(t, got.Found, "distro: want 0 CPEs, got %+v", got.Value)
}

// TestRunPicksMostRecentlyPublished: with more CVEs than maxLookups, the
// maxLookups with the most recent Published are queried, not the first ones
// in the list. Modified has no influence: an old CVE freshly re-enriched
// doesn't earn a spot.
func TestRunPicksMostRecentlyPublished(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := collect.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}

	// 7 CVEs in appearance order 2010..2016, increasing Published: the 5
	// newest are the LAST of the list (2012..2016). The oldest (2010) carries
	// the most recent Modified of all — it still stays out.
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []collect.VulnRecord
	for i := 0; i < 7; i++ {
		records = append(records, collect.VulnRecord{
			OriginalID: fmt.Sprintf("CVE-%d-1", 2010+i),
			Published:  base.AddDate(0, 0, i),
			Modified:   base.AddDate(0, 0, 7-i),
		})
	}

	fetcher := &stubNVD{}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	want := []string{"CVE-2016-1", "CVE-2015-1", "CVE-2014-1", "CVE-2013-1", "CVE-2012-1"}
	assert.Equal(t, want, fetcher.asked)
}
