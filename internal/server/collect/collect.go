package collect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// ErrSourceNotApplicable is returned by a fetcher when it has no data path for
// this purl type (e.g. ecosyste.ms has no registry for deb/rpm). Not a
// failure: the stage is skipped without emitting a SourceError.
var ErrSourceNotApplicable = errors.New("source not applicable for purl type")

// EcosystemsFetcher is the stage 1 dependency; *ecosystems.Client satisfies
// it. Injected via Config so it can be stubbed in tests.
type EcosystemsFetcher interface {
	Fetch(ctx context.Context, spurl string) (Component, *Repository, []VulnRecord, error)
}

// OSVFetcher is the stage 2 dependency; *osv.Client satisfies it. Injected
// via Config so it can be stubbed in tests.
type OSVFetcher interface {
	Query(ctx context.Context, q purl.OSVQuery) ([]VulnRecord, error)
}

// CPERStage is stage 3 (CPE resolution); cper.Stage satisfies it. Optional:
// nil in Config skips the stage.
type CPERStage func(ctx context.Context, httpc *http.Client, cfg Config, id purl.Identity, spurl, repoURL string, records []VulnRecord, now time.Time)

// Collect orchestrates the collection pipeline for one coordinate: stage 1
// (ecosyste.ms), stage 2 (OSV), then assembly + matching + roll-up.
func Collect(ctx context.Context, coord string, cfg Config) (*Result, error) {
	if cfg.Store == nil {
		return nil, errors.New("collect: cfg.Store is nil")
	}
	if cfg.EcosystemsFetcher == nil {
		return nil, errors.New("collect: cfg.EcosystemsFetcher is nil")
	}
	if cfg.OSVFetcher == nil {
		return nil, errors.New("collect: cfg.OSVFetcher is nil")
	}
	if coord == "" {
		return nil, errors.New("collect: empty coord")
	}
	p, err := purl.Parse(coord)
	if err != nil {
		return nil, err
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	identity := purl.Decompose(p)
	spurl := purl.Strip(p)
	q := identity.OSVQuery()
	osvKey := q.StoreKey()
	now := time.Now().UTC()

	res, errs := collectStage1(ctx, cfg.EcosystemsFetcher, cfg.Store, spurl, cfg.MaxAge, now)

	errs = append(errs, runOSV(ctx, cfg.OSVFetcher, cfg.Store, q, osvKey, spurl, cfg.MaxAge, now)...)

	// Assembly: reading from the store unifies cache-hit and fresh-fetch.
	var allRecords []VulnRecord
	if r, _ := cfg.Store.GetVulns(ctx, SourceEcosystems, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if osvKey != "" {
		if r, _ := cfg.Store.GetVulns(ctx, SourceOSV, osvKey); r.Found {
			allRecords = append(allRecords, r.Value...)
		}
	}

	// Stage 3: CPER — resolves CPE(s) from the CVEs in allRecords and persists
	// the NVD CVEs as vuln records (source=nvd, key=spurl).
	repoURL := ""
	if res.Component != nil {
		repoURL = res.Component.RepoURL
	}
	if cfg.CPER != nil {
		cfg.CPER(ctx, httpClient, cfg, identity, spurl, repoURL, allRecords, now)
	}

	// The NVD records CPER left behind join the bundle (3rd source of the canonical).
	if r, _ := cfg.Store.GetVulns(ctx, SourceNVD, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if c, _ := cfg.Store.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}

	// If the pipeline produced no Component (ecosyste.ms doesn't cover this
	// purl) but there are vulns, synthesize one from the parsed purl so the UI
	// has a name and repo. Only github carries RepoURL here (via Decompose).
	if res.Component == nil && len(allRecords) > 0 {
		comp := syntheticComponent(identity, spurl, now)
		_ = cfg.Store.PutComponent(ctx, comp)
		res.Component = &comp
	}

	res.Groups = matchGroups(Group(allRecords), identity, identity.Version)
	orderGroups(res.Groups)
	res.Coord = coord
	res.Errors = errs
	return res, nil
}

// syntheticComponent builds a minimal Component from the decomposed purl, for
// purls with vulns that ecosyste.ms doesn't cover (e.g. pkg:github/...).
// RepoURL is already set by Decompose for github; empty for the rest.
func syntheticComponent(id purl.Identity, spurl string, now time.Time) Component {
	return Component{
		SPURL:     spurl,
		Name:      id.Name,
		RepoURL:   id.RepoURL,
		FetchedAt: now,
	}
}

// FromStore assembles a Result for coord using ONLY the cache (store), no
// fetchers or network. Used by the component page, which must not re-scrape.
// If coord has no version, matching marks every vuln as affected.
func FromStore(ctx context.Context, coord string, st Store) (*Result, error) {
	if st == nil {
		return nil, errors.New("fromstore: store is nil")
	}
	p, err := purl.Parse(coord)
	if err != nil {
		return nil, err
	}

	identity := purl.Decompose(p)
	spurl := purl.Strip(p)
	osvKey := identity.OSVQuery().StoreKey()

	res := &Result{Coord: coord}
	if c, _ := st.GetComponent(ctx, spurl); c.Found {
		comp := c.Value
		res.Component = &comp
		if comp.RepoURL != "" {
			if r, _ := st.GetRepository(ctx, comp.RepoURL); r.Found {
				rv := r.Value
				res.Repository = &rv
			}
		}
	}

	var allRecords []VulnRecord
	if r, _ := st.GetVulns(ctx, SourceEcosystems, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if osvKey != "" {
		if r, _ := st.GetVulns(ctx, SourceOSV, osvKey); r.Found {
			allRecords = append(allRecords, r.Value...)
		}
	}
	// NVD records + already-resolved CPEs (store-only, no network).
	if r, _ := st.GetVulns(ctx, SourceNVD, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if c, _ := st.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}

	res.Groups = matchGroups(Group(allRecords), identity, identity.Version)
	orderGroups(res.Groups)
	return res, nil
}

// orderGroups sorts groups so the most dangerous and newest win: MaxScore
// (CVSS) desc, and on equal score the most recently Updated first.
func orderGroups(groups []VulnGroup) {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].MaxScore != groups[j].MaxScore {
			return groups[i].MaxScore > groups[j].MaxScore
		}
		return groups[i].Updated.After(groups[j].Updated)
	})
}

// runOSV resolves stage 2 (cache-aware, same pattern as stage 1). Returns
// non-fatal SourceErrors; never aborts the pipeline.
func runOSV(ctx context.Context, fetcher OSVFetcher, st Store, q purl.OSVQuery, osvKey string, spurl string, maxAge time.Duration, now time.Time) []SourceError {
	if osvKey == "" {
		return nil
	}

	if cached, _ := st.GetVulns(ctx, SourceOSV, osvKey); cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		return nil
	}

	records, err := fetcher.Query(ctx, q)
	if err != nil {
		return []SourceError{{Source: SourceOSV, Kind: "other", Err: fmt.Errorf("osv query: %w", err)}}
	}

	// WHY: stamping the canonical per-record before persisting populates the
	// store's canonical_id column (DD §7 indexes it for /vulnerabilities).
	// FetchedAt goes here (the client doesn't know it) and feeds cache freshness.
	for i := range records {
		records[i].CanonicalID = CanonicalIDFor(records[i])
		records[i].FetchedAt = now
		// WHY: OSV-GIT (github/curl/curl) comes with an empty package → without
		// a purl the vuln isn't associated to the package via affected_package.
		// We stamp the queried spurl only when OSV doesn't report one
		// (preserves the real one).
		if records[i].AffectedPackage == "" {
			records[i].AffectedPackage = spurl
		}
	}
	_ = st.PutVulns(ctx, SourceOSV, osvKey, records)
	return nil
}

// matchGroups runs per-record matching over each CanonicalGroup and does the
// binary per-group roll-up.
func matchGroups(groups []CanonicalGroup, identity purl.Identity, version string) []VulnGroup {
	out := make([]VulnGroup, 0, len(groups))
	for _, g := range groups {
		vg := VulnGroup{CanonicalID: g.CanonicalID, MaxScore: g.MaxScore}
		for _, r := range g.Records {
			// Created = oldest Published; Updated = newest Modified.
			if !r.Published.IsZero() && (vg.Created.IsZero() || r.Published.Before(vg.Created)) {
				vg.Created = r.Published
			}
			if r.Modified.After(vg.Updated) {
				vg.Updated = r.Modified
			}

			ev := match.Evidence{
				AffectedVersions:   r.AffectedVersions,
				AffectedRanges:     r.AffectedRanges,
				FixedVersions:      r.FixedVersions,
				UnaffectedVersions: r.UnaffectedVersions,
			}
			mr := match.For(r.Source, identity.Ecosystem).Match(version, ev)
			vg.Members = append(vg.Members, VulnMember{
				Record: r,
				Verdict: MatchVerdict{
					Matched:  mr.Matched,
					Reason:   mr.Reason,
					Range:    mr.Range,
					NextFix:  mr.NextFix,
					Warnings: mr.Warnings,
				},
			})
			// WHY: OR roll-up (DD §6 level 2) — the group is affected if ANY
			// record matched.
			if mr.Matched {
				vg.Affected = true
			}
		}
		out = append(out, vg)
	}
	return out
}

// collectStage1 resolves Component/Repository/Vulns from ecosyste.ms, reading
// from the store when the data is fresh and fetching+persisting when not.
func collectStage1(ctx context.Context, fetcher EcosystemsFetcher, st Store, spurl string, maxAge time.Duration, now time.Time) (*Result, []SourceError) {
	var errs []SourceError

	cached, _ := st.GetComponent(ctx, spurl)
	if cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		comp := cached.Value
		var repo *Repository
		if comp.RepoURL != "" {
			if r, _ := st.GetRepository(ctx, comp.RepoURL); r.Found {
				rv := r.Value
				repo = &rv
			}
		}
		return &Result{Component: &comp, Repository: repo}, errs
	}

	comp, repo, vulns, err := fetcher.Fetch(ctx, spurl)
	if errors.Is(err, ErrSourceNotApplicable) {
		// ecosyste.ms doesn't cover this purl type (deb/rpm/apk/…): not an
		// error, distro data arrives via OSV. Clean skip, no SourceError.
		return &Result{}, errs
	}
	if err != nil {
		// TODO: classify the error (Kind is still always "other").
		errs = append(errs, SourceError{Source: SourceEcosystems, Kind: "other", Err: err})
		return &Result{}, errs
	}

	_ = st.PutComponent(ctx, comp)
	if repo != nil {
		_ = st.PutRepository(ctx, *repo)
	}
	// WHY: stamping the canonical per-record populates the store's
	// canonical_id column (DD §7). Group re-derives it on read anyway —
	// idempotent. FetchedAt goes here (the client doesn't know it) and feeds
	// cache freshness.
	for i := range vulns {
		vulns[i].CanonicalID = CanonicalIDFor(vulns[i])
		vulns[i].FetchedAt = now
	}
	_ = st.PutVulns(ctx, SourceEcosystems, spurl, vulns)

	return &Result{Component: &comp, Repository: repo}, errs
}

// IsFresh reports whether fetchedAt is within maxAge relative to now. It is
// the pipeline's freshness rule (the Store only keeps FetchedAt); exported
// because the cper package shares it.
//
// WHY: maxAge<=0 means "always refetch" (design decision), hence it returns
// false in that case even if the data is recent.
func IsFresh(fetchedAt time.Time, maxAge time.Duration, now time.Time) bool {
	if maxAge <= 0 {
		return false
	}
	return now.Sub(fetchedAt) <= maxAge
}
