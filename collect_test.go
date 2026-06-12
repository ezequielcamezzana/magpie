package magpie

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ezequielcamezzana/magpie/pkg/purl"
)

type stubFetcher struct {
	comp  Component
	repo  *Repository
	vulns []VulnRecord
	err   error
	calls int
}

func (f *stubFetcher) Fetch(ctx context.Context, spurl string) (Component, *Repository, []VulnRecord, error) {
	f.calls++
	if f.err != nil {
		return Component{}, nil, nil, f.err
	}
	return f.comp, f.repo, f.vulns, nil
}

// stubOSV es un OSVFetcher de test que devuelve records fijos.
type stubOSV struct {
	records []VulnRecord
	err     error
}

func (s stubOSV) Query(ctx context.Context, q purl.OSVQuery) ([]VulnRecord, error) {
	return s.records, s.err
}

// registerOSV instala un OSVFetcher para la duración del test, restaurando el
// no-op por defecto al terminar.
func registerOSV(t *testing.T, f OSVFetcher) {
	t.Helper()
	RegisterOSVFetcher(func(*http.Client, *slog.Logger) OSVFetcher { return f })
	t.Cleanup(func() {
		RegisterOSVFetcher(func(*http.Client, *slog.Logger) OSVFetcher { return stubOSV{} })
	})
}

func TestMain(m *testing.M) {
	// Default: stage 1 stub + no-op OSV, así los tests que esperan Errors vacío
	// no fallan por el "not registered" de stage 2.
	RegisterEcosystemsFetcher(func(*http.Client, *slog.Logger) EcosystemsFetcher {
		return &stubFetcher{comp: Component{Name: "x"}}
	})
	RegisterOSVFetcher(func(*http.Client, *slog.Logger) OSVFetcher { return stubOSV{} })
	os.Exit(m.Run())
}

// fakeStore is an in-memory Store for tests.
//
// WHY: el Store real (store/sqlite) importa este package magpie, así que un
// test in-package que lo importara crearía un ciclo. El fake vive acá.
type fakeStore struct {
	comps map[string]StoreResult[Component]
	repos map[string]StoreResult[Repository]
	vulns map[string]StoreResult[[]VulnRecord]
	cpes  map[string]StoreResult[[]ResolvedCPE]
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		comps: map[string]StoreResult[Component]{},
		repos: map[string]StoreResult[Repository]{},
		vulns: map[string]StoreResult[[]VulnRecord]{},
		cpes:  map[string]StoreResult[[]ResolvedCPE]{},
	}
}

func (s *fakeStore) GetComponent(ctx context.Context, spurl string) (StoreResult[Component], error) {
	return s.comps[spurl], nil
}
func (s *fakeStore) PutComponent(ctx context.Context, c Component) error {
	s.comps[c.SPURL] = StoreResult[Component]{Value: c, FetchedAt: c.FetchedAt, Found: true}
	return nil
}
func (s *fakeStore) GetRepository(ctx context.Context, repoURL string) (StoreResult[Repository], error) {
	return s.repos[repoURL], nil
}
func (s *fakeStore) PutRepository(ctx context.Context, r Repository) error {
	s.repos[r.URL] = StoreResult[Repository]{Value: r, FetchedAt: r.FetchedAt, Found: true}
	return nil
}
func (s *fakeStore) GetCPEs(ctx context.Context, spurl string) (StoreResult[[]ResolvedCPE], error) {
	return s.cpes[spurl], nil
}
func (s *fakeStore) PutCPEs(ctx context.Context, spurl string, cpes []ResolvedCPE) error {
	if len(cpes) == 0 {
		return nil
	}
	s.cpes[spurl] = StoreResult[[]ResolvedCPE]{Value: cpes, FetchedAt: time.Now().UTC(), Found: true}
	return nil
}
func (s *fakeStore) GetVulns(ctx context.Context, source, queryKey string) (StoreResult[[]VulnRecord], error) {
	return s.vulns[source+"|"+queryKey], nil
}
func (s *fakeStore) PutVulns(ctx context.Context, source, queryKey string, vs []VulnRecord) error {
	var fetched time.Time
	if len(vs) > 0 {
		fetched = vs[0].FetchedAt
	}
	s.vulns[source+"|"+queryKey] = StoreResult[[]VulnRecord]{Value: vs, FetchedAt: fetched, Found: true}
	return nil
}
func (s *fakeStore) QueryVulns(ctx context.Context, q VulnQuery) ([]VulnRecord, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryComponents(ctx context.Context, q ComponentQuery) ([]Component, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryCPEs(ctx context.Context, q CPEQuery) ([]ResolvedCPE, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) Close() error { return nil }

// registerEco instala un EcosystemsFetcher para la duración del test.
func registerEco(t *testing.T, f EcosystemsFetcher) {
	t.Helper()
	RegisterEcosystemsFetcher(func(*http.Client, *slog.Logger) EcosystemsFetcher { return f })
	t.Cleanup(func() {
		RegisterEcosystemsFetcher(func(*http.Client, *slog.Logger) EcosystemsFetcher {
			return &stubFetcher{comp: Component{Name: "x"}}
		})
	})
}

func TestCollectInvalidCoord(t *testing.T) {
	res, err := Collect(context.Background(), "not-a-purl", Config{Store: newFakeStore()})
	if err == nil {
		t.Fatal("want error for invalid coord, got nil")
	}
	if res != nil {
		t.Fatalf("want nil result, got %+v", res)
	}
}

func TestCollectNilStore(t *testing.T) {
	_, err := Collect(context.Background(), "pkg:npm/lodash@4.17.21", Config{})
	if err == nil {
		t.Fatal("want error for nil store, got nil")
	}
}

func TestCollectStage1CacheMiss(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	f := &stubFetcher{
		comp:  Component{SPURL: spurl, Name: "lodash", RepoURL: "https://github.com/lodash/lodash"},
		repo:  &Repository{URL: "https://github.com/lodash/lodash", Stars: 100},
		vulns: []VulnRecord{{Source: SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x"}},
	}

	now := time.Now().UTC()
	res, errs := collectStage1(context.Background(), f, st, spurl, 24*time.Hour, now)
	if len(errs) != 0 {
		t.Fatalf("want no errors, got %+v", errs)
	}
	if f.calls != 1 {
		t.Fatalf("want fetcher called once, got %d", f.calls)
	}
	if res.Component == nil || res.Component.Name != "lodash" {
		t.Fatalf("want component lodash, got %+v", res.Component)
	}

	got, _ := st.GetComponent(context.Background(), spurl)
	if !got.Found || got.Value.Name != "lodash" {
		t.Fatalf("component not persisted: %+v", got)
	}
}

func TestCollectStage1CacheHit(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()
	ctx := context.Background()

	_ = st.PutComponent(ctx, Component{SPURL: spurl, Name: "lodash", RepoURL: "https://github.com/lodash/lodash", FetchedAt: now})
	_ = st.PutRepository(ctx, Repository{URL: "https://github.com/lodash/lodash", Stars: 100, FetchedAt: now})
	_ = st.PutVulns(ctx, SourceEcosystems, spurl, []VulnRecord{{Source: SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x", FetchedAt: now}})

	f := &stubFetcher{}
	res, errs := collectStage1(ctx, f, st, spurl, 24*time.Hour, now)
	if len(errs) != 0 {
		t.Fatalf("want no errors, got %+v", errs)
	}
	if f.calls != 0 {
		t.Fatalf("want fetcher not called, got %d", f.calls)
	}
	if res.Component == nil || res.Component.Name != "lodash" {
		t.Fatalf("want component from cache, got %+v", res.Component)
	}
	if res.Repository == nil || res.Repository.Stars != 100 {
		t.Fatalf("want repository from cache, got %+v", res.Repository)
	}
}

func TestCollectStage1MaxAgeZeroRefetch(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()
	ctx := context.Background()

	_ = st.PutComponent(ctx, Component{SPURL: spurl, Name: "lodash", FetchedAt: now})

	f := &stubFetcher{comp: Component{SPURL: spurl, Name: "lodash"}}
	_, errs := collectStage1(ctx, f, st, spurl, 0, now)
	if len(errs) != 0 {
		t.Fatalf("want no errors, got %+v", errs)
	}
	if f.calls != 1 {
		t.Fatalf("want fetcher called once (MaxAge=0 always refetch), got %d", f.calls)
	}
}

func TestCollectStage1StaleRefetch(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()
	ctx := context.Background()

	_ = st.PutComponent(ctx, Component{SPURL: spurl, Name: "lodash", FetchedAt: now.Add(-48 * time.Hour)})

	f := &stubFetcher{comp: Component{SPURL: spurl, Name: "lodash"}}
	_, errs := collectStage1(ctx, f, st, spurl, 24*time.Hour, now)
	if len(errs) != 0 {
		t.Fatalf("want no errors, got %+v", errs)
	}
	if f.calls != 1 {
		t.Fatalf("want fetcher called once (stale), got %d", f.calls)
	}
}

func TestCollectStage1FetchErrorNotFatal(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()

	f := &stubFetcher{err: errors.New("boom")}
	res, errs := collectStage1(context.Background(), f, st, spurl, 24*time.Hour, now)
	if len(errs) != 1 {
		t.Fatalf("want 1 source error, got %+v", errs)
	}
	if errs[0].Source != SourceEcosystems {
		t.Fatalf("want source %q, got %q", SourceEcosystems, errs[0].Source)
	}
	_ = res
}

func TestCollectStage2Matching(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}})
	registerOSV(t, stubOSV{records: []VulnRecord{{
		Source:         SourceOSV,
		OriginalID:     "GHSA-x",
		AffectedRanges: []string{"[4.0.0, 6.0.0)"},
	}}})

	res, err := Collect(context.Background(), "pkg:npm/x@5.0.0", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("want no errors, got %+v", res.Errors)
	}
	if len(res.Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(res.Groups))
	}
	g := res.Groups[0]
	if !g.Affected {
		t.Fatal("want group Affected=true")
	}
	if len(g.Members) != 1 {
		t.Fatalf("want 1 member, got %d", len(g.Members))
	}
	if g.Members[0].Verdict.Reason != ReasonInAffectedRange {
		t.Fatalf("Reason = %q, want %q", g.Members[0].Verdict.Reason, ReasonInAffectedRange)
	}
}

func TestCollectNoVersionMatchesAll(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}})
	registerOSV(t, stubOSV{records: []VulnRecord{{
		Source:         SourceOSV,
		OriginalID:     "GHSA-x",
		AffectedRanges: []string{"[4.0.0, 6.0.0)"},
	}}})

	res, err := Collect(context.Background(), "pkg:npm/x", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(res.Groups))
	}
	g := res.Groups[0]
	if !g.Affected {
		t.Fatal("want group Affected=true")
	}
	for _, m := range g.Members {
		if !m.Verdict.Matched {
			t.Fatalf("want all members matched, got %+v", m.Verdict)
		}
		if m.Verdict.Reason != ReasonNoVersionSpecified {
			t.Fatalf("Reason = %q, want %q", m.Verdict.Reason, ReasonNoVersionSpecified)
		}
	}
}

func TestCollectVersionNotAffected(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}})
	registerOSV(t, stubOSV{records: []VulnRecord{{
		Source:         SourceOSV,
		OriginalID:     "GHSA-x",
		AffectedRanges: []string{"[4.0.0, 6.0.0)"},
	}}})

	res, err := Collect(context.Background(), "pkg:npm/x@7.0.0", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(res.Groups))
	}
	g := res.Groups[0]
	if g.Affected {
		t.Fatal("want group Affected=false")
	}
	if g.Members[0].Verdict.Reason != ReasonNotInAffectedRange {
		t.Fatalf("Reason = %q, want %q", g.Members[0].Verdict.Reason, ReasonNotInAffectedRange)
	}
}

func TestCollectSyntheticComponentGitHub(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:github/curl/curl"
	registerEco(t, &stubFetcher{err: ErrSourceNotApplicable})
	registerOSV(t, stubOSV{records: []VulnRecord{{
		Source: SourceOSV, OriginalID: "CVE-2023-1",
	}}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if res.Component == nil {
		t.Fatal("want synthetic component, got nil")
	}
	if res.Component.Name != "curl" {
		t.Fatalf("Name = %q, want curl", res.Component.Name)
	}
	if res.Component.RepoURL != "https://github.com/curl/curl" {
		t.Fatalf("RepoURL = %q, want https://github.com/curl/curl", res.Component.RepoURL)
	}

	got, _ := st.GetComponent(context.Background(), spurl)
	if !got.Found || got.Value.Name != "curl" {
		t.Fatalf("synthetic component not persisted: %+v", got)
	}
}

func TestCollectStampsAffectedPackageWhenEmpty(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{err: ErrSourceNotApplicable})
	// OSV-GIT viene con package vacío (AffectedPackage == "").
	registerOSV(t, stubOSV{records: []VulnRecord{
		{Source: SourceOSV, OriginalID: "CVE-2023-1"},
		{Source: SourceOSV, OriginalID: "CVE-2023-2"},
	}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}

	var seen int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			seen++
			if m.Record.AffectedPackage != "pkg:github/curl/curl" {
				t.Fatalf("AffectedPackage = %q, want pkg:github/curl/curl", m.Record.AffectedPackage)
			}
		}
	}
	if seen == 0 {
		t.Fatal("want at least one vuln member")
	}
}

func TestCollectPreservesAffectedPackageFromOSV(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{err: ErrSourceNotApplicable})
	// OSV sí reporta un purl: se conserva, no se pisa con el spurl.
	registerOSV(t, stubOSV{records: []VulnRecord{
		{Source: SourceOSV, OriginalID: "CVE-2023-1", AffectedPackage: "pkg:generic/curl"},
	}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}

	var seen int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			seen++
			if m.Record.AffectedPackage != "pkg:generic/curl" {
				t.Fatalf("AffectedPackage = %q, want pkg:generic/curl", m.Record.AffectedPackage)
			}
		}
	}
	if seen == 0 {
		t.Fatal("want at least one vuln member")
	}
}

func TestCollectNoSynthWithoutVulns(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{err: ErrSourceNotApplicable})
	registerOSV(t, stubOSV{})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if res.Component != nil {
		t.Fatalf("want nil component (no vulns), got %+v", res.Component)
	}
	got, _ := st.GetComponent(context.Background(), "pkg:github/curl/curl")
	if got.Found {
		t.Fatalf("want nothing persisted, got %+v", got)
	}
}

func TestCollectRealComponentNotOverwritten(t *testing.T) {
	st := newFakeStore()
	registerEco(t, &stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x", RepoURL: "https://github.com/x/x"}})
	registerOSV(t, stubOSV{records: []VulnRecord{{Source: SourceOSV, OriginalID: "CVE-2020-1"}}})

	res, err := Collect(context.Background(), "pkg:npm/x@1.0.0", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if res.Component == nil || res.Component.Name != "x" {
		t.Fatalf("want real component x, got %+v", res.Component)
	}
	if res.Component.RepoURL != "https://github.com/x/x" {
		t.Fatalf("RepoURL = %q, want real repo url", res.Component.RepoURL)
	}
}

func TestCollectGroupsByCanonical(t *testing.T) {
	st := newFakeStore()
	// ecosystems devuelve un record con el CVE en Aliases; osv devuelve otro con
	// el CVE como OriginalID → mismo canonical → 1 grupo, 2 members.
	registerEco(t, &stubFetcher{
		comp:  Component{SPURL: "pkg:npm/x", Name: "x"},
		vulns: []VulnRecord{{Source: SourceEcosystems, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}}},
	})
	registerOSV(t, stubOSV{records: []VulnRecord{{
		Source: SourceOSV, OriginalID: "CVE-2020-1",
	}}})

	res, err := Collect(context.Background(), "pkg:npm/x@1.0.0", Config{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(res.Groups))
	}
	g := res.Groups[0]
	if g.CanonicalID != "CVE-2020-1" {
		t.Fatalf("CanonicalID = %q, want CVE-2020-1", g.CanonicalID)
	}
	if len(g.Members) != 2 {
		t.Fatalf("want 2 members, got %d", len(g.Members))
	}

	// canonical_id quedó stampeado en los records persistidos.
	for _, source := range []string{SourceEcosystems, SourceOSV} {
		key := source + "|"
		if source == SourceEcosystems {
			key += "pkg:npm/x"
		} else {
			key += "npm:x"
		}
		got := st.vulns[key]
		if !got.Found || len(got.Value) == 0 {
			t.Fatalf("%s: no records persisted", source)
		}
		if got.Value[0].CanonicalID != "CVE-2020-1" {
			t.Fatalf("%s: CanonicalID = %q, want CVE-2020-1", source, got.Value[0].CanonicalID)
		}
	}
}
