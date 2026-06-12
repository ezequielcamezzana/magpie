package cper

import (
	"context"
	"fmt"
	"testing"
	"time"

	magpie "github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

func acceptOne(t *testing.T, cve *magpie.NVDCVE, names, vendors, osvRanges []string, wantSw, eco string) []magpie.ResolvedCPE {
	t.Helper()
	osvIntervals, osvOk := match.ParseIntervals(osvRanges)
	return acceptCPEs(cve, "CVE-2020-1", names, vendors, osvRanges,
		lowerSet(names), lowerSet(vendors), wantSw, eco, osvIntervals, osvOk, map[string]bool{})
}

func TestAcceptCPE_NameAndVendor(t *testing.T) {
	cve := &magpie.NVDCVE{Matches: []magpie.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:lodash:lodash", Vendor: "lodash", Product: "lodash",
			AffectedRanges: []string{"[9.0.0, 9.9.9)"}},
	}}
	// OSV trae un range que NO coincide con el de NVD: acepta por name∧vendor.
	got := acceptOne(t, cve, []string{"lodash"}, []string{"lodash", "npm"},
		[]string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	if len(got) != 1 {
		t.Fatalf("want 1 accepted, got %d", len(got))
	}
	if !hasAll(got[0].MatchedBy, "name", "vendor") {
		t.Errorf("MatchedBy = %v, want name+vendor", got[0].MatchedBy)
	}
	if contains(got[0].MatchedBy, "range") {
		t.Errorf("MatchedBy = %v, range must not match", got[0].MatchedBy)
	}
	// Los ranges se estampan igual aunque la señal range no haya matcheado.
	if len(got[0].NVDRanges) != 1 || got[0].NVDRanges[0] != "[9.0.0, 9.9.9)" {
		t.Errorf("NVDRanges = %v", got[0].NVDRanges)
	}
	if len(got[0].OSVRanges) != 1 || got[0].OSVRanges[0] != "[1.0.0, 2.0.0)" {
		t.Errorf("OSVRanges = %v", got[0].OSVRanges)
	}
}

func TestAcceptCPE_NameAndEcosystem(t *testing.T) {
	// product matches a name, vendor does NOT, but target_sw pins node.js.
	cve := &magpie.NVDCVE{Matches: []magpie.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:acme:chalk", Vendor: "acme", Product: "chalk", TargetSw: "node.js"},
	}}
	got := acceptOne(t, cve, []string{"chalk"}, []string{"npm"}, nil, "node.js", "npm")
	if len(got) != 1 {
		t.Fatalf("want 1 accepted, got %d", len(got))
	}
	if !hasAll(got[0].MatchedBy, "name", "ecosystem") {
		t.Errorf("MatchedBy = %v, want name+ecosystem", got[0].MatchedBy)
	}
	if got[0].NVDTargetSw != "node.js" {
		t.Errorf("NVDTargetSw = %q", got[0].NVDTargetSw)
	}
}

func TestAcceptCPE_RangeSubsetWhenNoName(t *testing.T) {
	// neither name nor vendor match; OSV ⊆ NVD range bridges it.
	cve := &magpie.NVDCVE{Matches: []magpie.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:other:thing", Vendor: "other", Product: "thing",
			AffectedRanges: []string{"[1.0.0, 2.0.0)"}},
	}}
	got := acceptOne(t, cve, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	if len(got) != 1 {
		t.Fatalf("want 1 accepted via range, got %d", len(got))
	}
	if !hasAll(got[0].MatchedBy, "range") {
		t.Errorf("MatchedBy = %v, want range", got[0].MatchedBy)
	}
}

func TestAcceptCPE_RejectsUnrelated(t *testing.T) {
	// Ninguno matchea name/vendor/ecosystem/range.
	cve := &magpie.NVDCVE{Matches: []magpie.NVDCPEMatch{
		{PartialCPE: "cpe:2.3:a:other:thing", Vendor: "other", Product: "thing",
			TargetSw: "*", AffectedRanges: []string{"[5.0.0, 6.0.0)"}},
		{PartialCPE: "cpe:2.3:a:more:stuff", Vendor: "more", Product: "stuff",
			TargetSw: "*", AffectedRanges: []string{"[7.0.0, 8.0.0)"}},
	}}
	got := acceptOne(t, cve, []string{"lodash"}, []string{"npm"}, []string{"[1.0.0, 2.0.0)"}, "node.js", "npm")
	if len(got) != 0 {
		t.Fatalf("want 0 accepted, got %d (%v)", len(got), got)
	}
}

func TestCandidatesFrom(t *testing.T) {
	id := purl.Identity{Type: "npm", Name: "lodash"}
	names, vendors := candidatesFrom(id, "https://github.com/lodash/lodash")
	if !contains(names, "lodash") {
		t.Errorf("names = %v, want lodash", names)
	}
	if !contains(vendors, "npm") || !contains(vendors, "lodash") {
		t.Errorf("vendors = %v, want npm+lodash", vendors)
	}
}

// fakeStore es un magpie.Store in-memory mínimo: solo cpes y vulns tienen
// comportamiento real; el resto son no-ops (Run no los toca).
type fakeStore struct {
	cpes  map[string]magpie.StoreResult[[]magpie.ResolvedCPE]
	vulns map[string]magpie.StoreResult[[]magpie.VulnRecord]
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cpes:  map[string]magpie.StoreResult[[]magpie.ResolvedCPE]{},
		vulns: map[string]magpie.StoreResult[[]magpie.VulnRecord]{},
	}
}

func (s *fakeStore) GetCPEs(ctx context.Context, spurl string) (magpie.StoreResult[[]magpie.ResolvedCPE], error) {
	return s.cpes[spurl], nil
}
func (s *fakeStore) PutCPEs(ctx context.Context, spurl string, cpes []magpie.ResolvedCPE) error {
	if len(cpes) == 0 {
		return nil
	}
	s.cpes[spurl] = magpie.StoreResult[[]magpie.ResolvedCPE]{Value: cpes, FetchedAt: time.Now().UTC(), Found: true}
	return nil
}
func (s *fakeStore) GetVulns(ctx context.Context, source, queryKey string) (magpie.StoreResult[[]magpie.VulnRecord], error) {
	return s.vulns[source+"|"+queryKey], nil
}
func (s *fakeStore) PutVulns(ctx context.Context, source, queryKey string, vs []magpie.VulnRecord) error {
	s.vulns[source+"|"+queryKey] = magpie.StoreResult[[]magpie.VulnRecord]{Value: vs, Found: true}
	return nil
}
func (s *fakeStore) GetComponent(context.Context, string) (magpie.StoreResult[magpie.Component], error) {
	return magpie.StoreResult[magpie.Component]{}, nil
}
func (s *fakeStore) PutComponent(context.Context, magpie.Component) error { return nil }
func (s *fakeStore) GetRepository(context.Context, string) (magpie.StoreResult[magpie.Repository], error) {
	return magpie.StoreResult[magpie.Repository]{}, nil
}
func (s *fakeStore) PutRepository(context.Context, magpie.Repository) error { return nil }
func (s *fakeStore) QueryComponents(context.Context, magpie.ComponentQuery) ([]magpie.Component, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryCPEs(context.Context, magpie.CPEQuery) ([]magpie.ResolvedCPE, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryVulns(context.Context, magpie.VulnQuery) ([]magpie.VulnRecord, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) Close() error { return nil }

// stubNVD registra qué CVEs se le pidieron, además de responder por mapa.
type stubNVD struct {
	byCVE map[string]*magpie.NVDCVE
	asked []string
}

func (s *stubNVD) FetchCVE(ctx context.Context, cve string) (*magpie.NVDCVE, error) {
	s.asked = append(s.asked, cve)
	return s.byCVE[cve], nil
}

func identityFor(t *testing.T, coord string) purl.Identity {
	t.Helper()
	p, err := purl.Parse(coord)
	if err != nil {
		t.Fatal(err)
	}
	return purl.Decompose(p)
}

// TestRunResolvesCPE: el CVE linkeado por ecosyste.ms se resuelve a un CPE vía
// el stub NVD; quedan persistidos el CPE y el vuln record source=nvd.
func TestRunResolvesCPE(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := magpie.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []magpie.VulnRecord{{
		Source: magpie.SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x",
		Aliases: []string{"CVE-2021-23337"}, AffectedRanges: []string{"[*, 4.17.21)"},
	}}
	fetcher := &stubNVD{byCVE: map[string]*magpie.NVDCVE{
		"CVE-2021-23337": {
			ID: "CVE-2021-23337", Score: 7.2, Severity: "HIGH",
			Matches: []magpie.NVDCPEMatch{{
				PartialCPE: "cpe:2.3:a:lodash:lodash", Vendor: "lodash", Product: "lodash",
				TargetSw: "node.js", AffectedRanges: []string{"[*, 4.17.21)"}, FixedVersions: []string{"4.17.21"},
			}},
		},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, spurl),
		spurl, "https://github.com/lodash/lodash", records, time.Now().UTC())

	got, _ := st.GetCPEs(context.Background(), spurl)
	if !got.Found || len(got.Value) != 1 {
		t.Fatalf("want 1 resolved CPE, got %+v", got)
	}
	cpe := got.Value[0]
	if cpe.CPE != "cpe:2.3:a:lodash:lodash" || cpe.CVE != "CVE-2021-23337" {
		t.Errorf("cpe = %+v", cpe)
	}
	if cpe.Explanation == "" {
		t.Error("want non-empty explanation")
	}
	if !hasAll(cpe.MatchedBy, "name", "ecosystem") {
		t.Errorf("matchedBy = %v", cpe.MatchedBy)
	}

	vulns, _ := st.GetVulns(context.Background(), magpie.SourceNVD, spurl)
	if !vulns.Found || len(vulns.Value) != 1 {
		t.Fatalf("want 1 nvd record persisted, got %+v", vulns)
	}
	if vulns.Value[0].OriginalID != "CVE-2021-23337" {
		t.Errorf("nvd record = %+v", vulns.Value[0])
	}
}

// TestRunFreshCPEsShortCircuit: CPEs frescos en el store → no se toca NVD.
func TestRunFreshCPEsShortCircuit(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	_ = st.PutCPEs(context.Background(), spurl, []magpie.ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash"}})

	fetcher := &stubNVD{}
	cfg := magpie.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []magpie.VulnRecord{{OriginalID: "CVE-2021-23337"}}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	if len(fetcher.asked) != 0 {
		t.Fatalf("fresh CPEs: want no NVD fetches, got %v", fetcher.asked)
	}
}

// TestRunSkipsDistro: un purl distro (KindLinux) nunca resuelve CPE ni records
// source=nvd, aun con NVDAPIKey y un stub que matchearía. NVD-by-CPE es
// backport-unaware → falsos positivos en distros.
func TestRunSkipsDistro(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:deb/debian/curl"
	cfg := magpie.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}
	records := []magpie.VulnRecord{{
		OriginalID: "CVE-2023-38545", AffectedRanges: []string{"[*, 8.4.0)"},
	}}
	fetcher := &stubNVD{byCVE: map[string]*magpie.NVDCVE{
		"CVE-2023-38545": {
			ID: "CVE-2023-38545", Score: 9.8, Severity: "CRITICAL",
			Matches: []magpie.NVDCPEMatch{{
				PartialCPE: "cpe:2.3:a:curl:curl", Vendor: "curl", Product: "curl",
				AffectedRanges: []string{"[*, 8.4.0)"}, FixedVersions: []string{"8.4.0"},
			}},
		},
	}}

	Run(context.Background(), fetcher, cfg, identityFor(t, "pkg:deb/debian/curl@7.88.1-10+deb12u4"),
		spurl, "https://github.com/curl/curl", records, time.Now().UTC())

	if len(fetcher.asked) != 0 {
		t.Errorf("distro: want no NVD fetches, got %v", fetcher.asked)
	}
	if got, _ := st.GetCPEs(context.Background(), spurl); got.Found {
		t.Errorf("distro: want 0 CPEs, got %+v", got.Value)
	}
}

// TestRunPicksMostRecentlyPublished: con más CVEs que maxLookups, se consultan
// los maxLookups con Published más reciente, no los primeros de la lista.
// Modified no influye: un CVE viejo recién re-enriquecido no gana lugar.
func TestRunPicksMostRecentlyPublished(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cfg := magpie.Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour}

	// 7 CVEs en orden de aparición 2010..2016, Published creciente: los 5 más
	// nuevos son los ÚLTIMOS de la lista (2012..2016). El más viejo (2010) trae
	// el Modified más reciente de todos — igual queda afuera.
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []magpie.VulnRecord
	for i := 0; i < 7; i++ {
		records = append(records, magpie.VulnRecord{
			OriginalID: fmt.Sprintf("CVE-%d-1", 2010+i),
			Published:  base.AddDate(0, 0, i),
			Modified:   base.AddDate(0, 0, 7-i),
		})
	}

	fetcher := &stubNVD{}
	Run(context.Background(), fetcher, cfg, identityFor(t, spurl), spurl, "", records, time.Now().UTC())

	want := []string{"CVE-2016-1", "CVE-2015-1", "CVE-2014-1", "CVE-2013-1", "CVE-2012-1"}
	if len(fetcher.asked) != len(want) {
		t.Fatalf("asked = %v, want %v", fetcher.asked, want)
	}
	for i := range want {
		if fetcher.asked[i] != want[i] {
			t.Fatalf("asked = %v, want %v", fetcher.asked, want)
		}
	}
}

func hasAll(xs []string, want ...string) bool {
	for _, w := range want {
		if !contains(xs, w) {
			return false
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
