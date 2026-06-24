package collect

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
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

// stubOSV is a test OSVFetcher that returns fixed records.
type stubOSV struct {
	records []VulnRecord
	err     error
}

func (s stubOSV) Query(ctx context.Context, q purl.OSVQuery) ([]VulnRecord, error) {
	return s.records, s.err
}

// testConfig builds a Config with the stubs injected.
func testConfig(st Store, eco EcosystemsFetcher, osvF OSVFetcher) Config {
	return Config{Store: st, EcosystemsFetcher: eco, OSVFetcher: osvF}
}

// fakeStore is an in-memory Store for tests.
//
// WHY: the real Store (store/sqlite) imports this package, so an in-package
// test importing it would create a cycle. The fake lives here.
type fakeStore struct {
	comps  map[string]StoreResult[Component]
	repos  map[string]StoreResult[Repository]
	vulns  map[string]StoreResult[[]VulnRecord]
	cpes   map[string]StoreResult[[]ResolvedCPE]
	missed map[string]time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		comps:  map[string]StoreResult[Component]{},
		repos:  map[string]StoreResult[Repository]{},
		vulns:  map[string]StoreResult[[]VulnRecord]{},
		cpes:   map[string]StoreResult[[]ResolvedCPE]{},
		missed: map[string]time.Time{},
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
func (s *fakeStore) GetMissedCPE(ctx context.Context, spurl string) (StoreResult[bool], error) {
	if t, ok := s.missed[spurl]; ok {
		return StoreResult[bool]{Value: true, FetchedAt: t, Found: true}, nil
	}
	return StoreResult[bool]{}, nil
}
func (s *fakeStore) PutMissedCPE(ctx context.Context, spurl string) error {
	s.missed[spurl] = time.Now().UTC()
	return nil
}
func (s *fakeStore) DeleteMissedCPE(ctx context.Context, spurl string) error {
	delete(s.missed, spurl)
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
func (s *fakeStore) StaleComponents(ctx context.Context, olderThan time.Time, limit int) ([]string, error) {
	var stale []Component
	for _, res := range s.comps {
		if res.FetchedAt.Before(olderThan) {
			stale = append(stale, res.Value)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].FetchedAt.Before(stale[j].FetchedAt) })

	var spurls []string
	for _, c := range stale {
		if len(spurls) >= limit {
			break
		}
		spurls = append(spurls, c.SPURL)
	}
	return spurls, nil
}
func (s *fakeStore) Metrics(ctx context.Context, staleBefore time.Time) (Metrics, error) {
	return Metrics{}, nil
}
func (s *fakeStore) QueryComponents(ctx context.Context, q ComponentQuery) ([]Component, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) QueryCPEs(ctx context.Context, q CPEQuery) ([]ResolvedCPE, int, error) {
	return nil, 0, nil
}
func (s *fakeStore) Close() error { return nil }

func TestCollectNVDBudgetTimeout(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	eco := &stubFetcher{
		comp:  Component{SPURL: spurl, Name: "lodash"},
		vulns: []VulnRecord{{Source: SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x", CanonicalID: "CVE-2020-1"}},
	}
	cfg := Config{
		Store:             st,
		EcosystemsFetcher: eco,
		OSVFetcher:        stubOSV{},
		SourceBudget:      20 * time.Millisecond,
		// A CPER that hangs until the budget fires.
		CPER: func(ctx context.Context, _ Config, _ purl.Identity, _, _ string, _ []VulnRecord, _ time.Time) []SourceError {
			<-ctx.Done()
			return nil
		},
	}

	res, err := Collect(context.Background(), "pkg:npm/lodash@4.0.0", cfg)
	require.NoError(t, err)

	var timedOut bool
	for _, e := range res.Errors {
		if e.Source == SourceVulnCheck && e.Kind == "timeout" {
			timedOut = true
		}
	}
	assert.True(t, timedOut, "want a non-fatal vulncheck (cper) timeout error")
	assert.NotEmpty(t, res.Groups, "eco/OSV vulns must survive the NVD/CPER timeout")
}

func TestCollectInvalidCoord(t *testing.T) {
	res, err := Collect(context.Background(), "not-a-purl", testConfig(newFakeStore(), &stubFetcher{}, stubOSV{}))
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestStaleMessage(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		stale bool
		want  string
	}{
		{"4xx", &HTTPError{Status: 404}, false, "osv not able to process the data"},
		{"4xx stale", &HTTPError{Status: 429}, true, "osv not able to process the data, returning stale data"},
		{"5xx", &HTTPError{Status: 503}, false, "osv is not available"},
		{"5xx stale", &HTTPError{Status: 500}, true, "osv is not available, returning stale data"},
		{"transport", &HTTPError{Err: errors.New("conn refused")}, false, "osv is not available"},
		{"nil err stale", nil, true, "osv is not available, returning stale data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StaleMessage("osv", tc.err, tc.stale))
		})
	}
}

func TestCollectNilFetchers(t *testing.T) {
	st := newFakeStore()
	_, err := Collect(context.Background(), "pkg:npm/lodash@4.17.21", testConfig(st, nil, stubOSV{}))
	require.Error(t, err)
	_, err = Collect(context.Background(), "pkg:npm/lodash@4.17.21", testConfig(st, &stubFetcher{}, nil))
	require.Error(t, err)
}

func TestCollectNilStore(t *testing.T) {
	_, err := Collect(context.Background(), "pkg:npm/lodash@4.17.21", Config{})
	require.Error(t, err)
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
	res, errs := collectStage1(context.Background(), f, st, spurl, 24*time.Hour, now, 0)
	require.Empty(t, errs)
	assert.Equal(t, 1, f.calls)
	require.NotNil(t, res.Component)
	assert.Equal(t, "lodash", res.Component.Name)

	got, _ := st.GetComponent(context.Background(), spurl)
	require.True(t, got.Found, "component not persisted")
	assert.Equal(t, "lodash", got.Value.Name)
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
	res, errs := collectStage1(ctx, f, st, spurl, 24*time.Hour, now, 0)
	require.Empty(t, errs)
	assert.Equal(t, 0, f.calls, "want fetcher not called")
	require.NotNil(t, res.Component)
	assert.Equal(t, "lodash", res.Component.Name)
	require.NotNil(t, res.Repository)
	assert.Equal(t, 100, res.Repository.Stars)
}

func TestCollectStage1MaxAgeZeroRefetch(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()
	ctx := context.Background()

	_ = st.PutComponent(ctx, Component{SPURL: spurl, Name: "lodash", FetchedAt: now})

	f := &stubFetcher{comp: Component{SPURL: spurl, Name: "lodash"}}
	_, errs := collectStage1(ctx, f, st, spurl, 0, now, 0)
	require.Empty(t, errs)
	assert.Equal(t, 1, f.calls, "MaxAge=0 always refetches")
}

func TestCollectStage1StaleRefetch(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()
	ctx := context.Background()

	_ = st.PutComponent(ctx, Component{SPURL: spurl, Name: "lodash", FetchedAt: now.Add(-48 * time.Hour)})

	f := &stubFetcher{comp: Component{SPURL: spurl, Name: "lodash"}}
	_, errs := collectStage1(ctx, f, st, spurl, 24*time.Hour, now, 0)
	require.Empty(t, errs)
	assert.Equal(t, 1, f.calls, "stale entry must refetch")
}

func TestCollectStage1FetchErrorNotFatal(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	now := time.Now().UTC()

	f := &stubFetcher{err: errors.New("boom")}
	_, errs := collectStage1(context.Background(), f, st, spurl, 24*time.Hour, now, 0)
	require.Len(t, errs, 1)
	assert.Equal(t, SourceEcosystems, errs[0].Source)
}

func TestCollectStage2Matching(t *testing.T) {
	st := newFakeStore()
	cfg := testConfig(st,
		&stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}},
		stubOSV{records: []VulnRecord{{
			Source:         SourceOSV,
			OriginalID:     "GHSA-x",
			AffectedRanges: []string{"[4.0.0, 6.0.0)"},
		}}})

	res, err := Collect(context.Background(), "pkg:npm/x@5.0.0", cfg)
	require.NoError(t, err)
	require.Empty(t, res.Errors)
	require.Len(t, res.Groups, 1)
	g := res.Groups[0]
	assert.True(t, g.Affected)
	require.Len(t, g.Members, 1)
	assert.Equal(t, ReasonInAffectedRange, g.Members[0].Verdict.Reason)
}

func TestCollectNoVersionMatchesAll(t *testing.T) {
	st := newFakeStore()
	cfg := testConfig(st,
		&stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}},
		stubOSV{records: []VulnRecord{{
			Source:         SourceOSV,
			OriginalID:     "GHSA-x",
			AffectedRanges: []string{"[4.0.0, 6.0.0)"},
		}}})

	res, err := Collect(context.Background(), "pkg:npm/x", cfg)
	require.NoError(t, err)
	require.Len(t, res.Groups, 1)
	g := res.Groups[0]
	assert.True(t, g.Affected)
	for _, m := range g.Members {
		assert.True(t, m.Verdict.Matched, "want all members matched, got %+v", m.Verdict)
		assert.Equal(t, ReasonNoVersionSpecified, m.Verdict.Reason)
	}
}

func TestCollectVersionNotAffected(t *testing.T) {
	st := newFakeStore()
	cfg := testConfig(st,
		&stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x"}},
		stubOSV{records: []VulnRecord{{
			Source:         SourceOSV,
			OriginalID:     "GHSA-x",
			AffectedRanges: []string{"[4.0.0, 6.0.0)"},
		}}})

	res, err := Collect(context.Background(), "pkg:npm/x@7.0.0", cfg)
	require.NoError(t, err)
	require.Len(t, res.Groups, 1)
	g := res.Groups[0]
	assert.False(t, g.Affected)
	assert.Equal(t, ReasonNotInAffectedRange, g.Members[0].Verdict.Reason)
}

func TestCollectSyntheticComponentGitHub(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:github/curl/curl"
	cfg := testConfig(st,
		&stubFetcher{err: ErrSourceNotApplicable},
		stubOSV{records: []VulnRecord{{
			Source: SourceOSV, OriginalID: "CVE-2023-1",
		}}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", cfg)
	require.NoError(t, err)
	require.NotNil(t, res.Component, "want synthetic component")
	assert.Equal(t, "curl", res.Component.Name)
	assert.Equal(t, "https://github.com/curl/curl", res.Component.RepoURL)

	got, _ := st.GetComponent(context.Background(), spurl)
	require.True(t, got.Found, "synthetic component not persisted")
	assert.Equal(t, "curl", got.Value.Name)
}

func TestCollectStampsAffectedPackageWhenEmpty(t *testing.T) {
	st := newFakeStore()
	// OSV-GIT comes with an empty package (AffectedPackage == "").
	cfg := testConfig(st,
		&stubFetcher{err: ErrSourceNotApplicable},
		stubOSV{records: []VulnRecord{
			{Source: SourceOSV, OriginalID: "CVE-2023-1"},
			{Source: SourceOSV, OriginalID: "CVE-2023-2"},
		}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", cfg)
	require.NoError(t, err)

	var seen int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			seen++
			assert.Equal(t, "pkg:github/curl/curl", m.Record.AffectedPackage)
		}
	}
	require.NotZero(t, seen, "want at least one vuln member")
}

func TestCollectPreservesAffectedPackageFromOSV(t *testing.T) {
	st := newFakeStore()
	// OSV does report a purl: it is preserved, not overwritten with the spurl.
	cfg := testConfig(st,
		&stubFetcher{err: ErrSourceNotApplicable},
		stubOSV{records: []VulnRecord{
			{Source: SourceOSV, OriginalID: "CVE-2023-1", AffectedPackage: "pkg:generic/curl"},
		}})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", cfg)
	require.NoError(t, err)

	var seen int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			seen++
			assert.Equal(t, "pkg:generic/curl", m.Record.AffectedPackage)
		}
	}
	require.NotZero(t, seen, "want at least one vuln member")
}

func TestCollectNoSynthWithoutVulns(t *testing.T) {
	st := newFakeStore()
	cfg := testConfig(st, &stubFetcher{err: ErrSourceNotApplicable}, stubOSV{})

	res, err := Collect(context.Background(), "pkg:github/curl/curl", cfg)
	require.NoError(t, err)
	assert.Nil(t, res.Component, "want nil component (no vulns)")
	got, _ := st.GetComponent(context.Background(), "pkg:github/curl/curl")
	assert.False(t, got.Found, "want nothing persisted")
}

func TestCollectRealComponentNotOverwritten(t *testing.T) {
	st := newFakeStore()
	cfg := testConfig(st,
		&stubFetcher{comp: Component{SPURL: "pkg:npm/x", Name: "x", RepoURL: "https://github.com/x/x"}},
		stubOSV{records: []VulnRecord{{Source: SourceOSV, OriginalID: "CVE-2020-1"}}})

	res, err := Collect(context.Background(), "pkg:npm/x@1.0.0", cfg)
	require.NoError(t, err)
	require.NotNil(t, res.Component)
	assert.Equal(t, "x", res.Component.Name)
	assert.Equal(t, "https://github.com/x/x", res.Component.RepoURL)
}

func TestCollectGroupsByCanonical(t *testing.T) {
	st := newFakeStore()
	// ecosystems returns a record with the CVE in Aliases; osv returns another
	// with the CVE as OriginalID → same canonical → 1 group, 2 members.
	cfg := testConfig(st,
		&stubFetcher{
			comp:  Component{SPURL: "pkg:npm/x", Name: "x"},
			vulns: []VulnRecord{{Source: SourceEcosystems, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}}},
		},
		stubOSV{records: []VulnRecord{{
			Source: SourceOSV, OriginalID: "CVE-2020-1",
		}}})

	res, err := Collect(context.Background(), "pkg:npm/x@1.0.0", cfg)
	require.NoError(t, err)
	require.Len(t, res.Groups, 1)
	g := res.Groups[0]
	assert.Equal(t, "CVE-2020-1", g.CanonicalID)
	assert.Len(t, g.Members, 2)

	// canonical_id got stamped on the persisted records.
	for _, source := range []string{SourceEcosystems, SourceOSV} {
		key := source + "|"
		if source == SourceEcosystems {
			key += "pkg:npm/x"
		} else {
			key += "npm:x"
		}
		got := st.vulns[key]
		require.True(t, got.Found, "%s: no records persisted", source)
		require.NotEmpty(t, got.Value, "%s: no records persisted", source)
		assert.Equal(t, "CVE-2020-1", got.Value[0].CanonicalID, "%s", source)
	}
}
