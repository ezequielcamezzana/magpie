package collect

import (
	"context"
	"errors"
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

// NVDFetcher is the NVD seam; *nvd.Client satisfies it. QueryCPE returns one
// record per CVE affecting a CPE (stage 4) as VulnRecords (NVD is just another
// source). Injected via Config so it can be stubbed.
type NVDFetcher interface {
	QueryCPE(ctx context.Context, cpe string) ([]VulnRecord, error)
}

// CVEFetcher resolves a CVE by id into VulnRecords. *vulncheck.Client
// satisfies it; CPER (stage 3) uses it to fetch the CVEs it cross-checks.
type CVEFetcher interface {
	FetchCVE(ctx context.Context, cveID string) ([]VulnRecord, error)
}

// CPERStage is stage 3 (CPE resolution); cper.Stage satisfies it. Optional:
// nil in Config skips the stage. Uses cfg.CVEFetcher. Returns non-fatal
// SourceErrors (e.g. VulnCheck unreachable) for the result.
type CPERStage func(ctx context.Context, cfg Config, id purl.Identity, spurl, repoURL string, records []VulnRecord, now time.Time) []SourceError

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

	identity := purl.Decompose(p)
	spurl := purl.Strip(p)
	q := identity.OSVQuery()
	osvKey := q.StoreKey()
	now := time.Now().UTC()

	res, errs := collectStage1(ctx, cfg.EcosystemsFetcher, cfg.Store, spurl, cfg.MaxAge.Components, now, cfg.SourceBudget)

	errs = append(errs, runOSV(ctx, cfg.OSVFetcher, cfg.Store, q, osvKey, spurl, cfg.MaxAge.Vulns, now, cfg.SourceBudget)...)

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

	// Stage 3: CPER — resolves the package's CPE(s) by cross-checking the CVEs
	// in allRecords against NVD's CPE configurations. Caches per-CVE; writes the
	// resolved CPEs only.
	repoURL := ""
	if res.Component != nil {
		repoURL = res.Component.RepoURL
	}
	if cfg.CPER != nil {
		cctx, cancel := budgetCtx(ctx, cfg.SourceBudget)
		cperErrs := cfg.CPER(cctx, cfg, identity, spurl, repoURL, allRecords, now)
		// Only our budget firing (not the request being cancelled) is a
		// "timed out" we report; the eco/OSV data already collected still ships.
		if ctx.Err() == nil && cctx.Err() == context.DeadlineExceeded {
			errs = append(errs, SourceError{Source: SourceVulnCheck, Kind: "timeout", Err: errors.New(StaleMessage(SourceVulnCheck, nil, false))})
		} else {
			errs = append(errs, cperErrs...)
		}
		cancel()
	}
	if c, _ := cfg.Store.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}

	// Stage 4: for each resolved CPE, query NVD by CPE for every CVE affecting
	// it (cache-aware) and join those NVD records to the bundle. The CVE that
	// resolved the CPE reappears here, so stage 4 alone covers the package's NVD
	// vulns — CPER doesn't persist package records. Bounded so a slow/down NVD
	// can't block the request: on timeout we report it and keep eco/OSV vulns.
	nctx, cancel := budgetCtx(ctx, cfg.SourceBudget)
	nvdErrs := runNVDByCPE(nctx, cfg, res.CPEs, spurl, cfg.MaxAge.Vulns, now)
	if ctx.Err() == nil && nctx.Err() == context.DeadlineExceeded {
		errs = append(errs, SourceError{Source: SourceNVD, Kind: "timeout", Err: errors.New(StaleMessage(SourceNVD, nil, false))})
	} else {
		errs = append(errs, nvdErrs...)
	}
	cancel()
	for _, c := range res.CPEs {
		if r, _ := cfg.Store.GetVulns(ctx, SourceNVD, NVDCPEKey(c.CPE)); r.Found {
			// Re-stamp the component for THIS package (the per-CPE cache is
			// shared across packages that resolve to the same CPE).
			for i := range r.Value {
				r.Value[i].AffectedPackage = spurl
			}
			allRecords = append(allRecords, r.Value...)
		}
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
	// Already-resolved CPEs and their NVD records (store-only, no network).
	if c, _ := st.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}
	for _, c := range res.CPEs {
		if r, _ := st.GetVulns(ctx, SourceNVD, NVDCPEKey(c.CPE)); r.Found {
			for i := range r.Value {
				r.Value[i].AffectedPackage = spurl
			}
			allRecords = append(allRecords, r.Value...)
		}
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
func runOSV(ctx context.Context, fetcher OSVFetcher, st Store, q purl.OSVQuery, osvKey string, spurl string, maxAge time.Duration, now time.Time, budget time.Duration) []SourceError {
	if osvKey == "" {
		return nil
	}

	cached, _ := st.GetVulns(ctx, SourceOSV, osvKey)
	if cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		return nil
	}

	fctx, cancel := budgetCtx(ctx, budget)
	records, err := fetcher.Query(fctx, q)
	timedOut := ctx.Err() == nil && fctx.Err() == context.DeadlineExceeded
	cancel()
	if err != nil {
		// On failure/timeout the stale OSV vulns stay in the store and are
		// picked up by the assembly step — warn but keep serving them.
		msg := StaleMessage(SourceOSV, err, cached.Found)
		return []SourceError{{Source: SourceOSV, Kind: errKind(timedOut), Err: errors.New(msg)}}
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

// runNVDByCPE is stage 4: for each resolved CPE, query NVD for the CVEs
// affecting it and persist them under the per-CPE key (which the assembly
// reads). Cache-aware and best-effort — a failed query is skipped, never
// aborts. Returns non-fatal SourceErrors.
// budgetCtx bounds a source's live fetch so it can't consume the whole request.
// budget <= 0 disables the bound. The caller must cancel().
func budgetCtx(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, budget)
}

// errKind labels a SourceError: "timeout" when our budget fired, else "other".
func errKind(timedOut bool) string {
	if timedOut {
		return "timeout"
	}
	return "other"
}

// cachedComponentResult builds a Result from a (possibly stale) cached component,
// pulling its repository from the store too.
func cachedComponentResult(ctx context.Context, st Store, comp Component) *Result {
	var repo *Repository
	if comp.RepoURL != "" {
		if r, _ := st.GetRepository(ctx, comp.RepoURL); r.Found {
			rv := r.Value
			repo = &rv
		}
	}
	return &Result{Component: &comp, Repository: repo}
}

func runNVDByCPE(ctx context.Context, cfg Config, cpes []ResolvedCPE, spurl string, maxAge time.Duration, now time.Time) []SourceError {
	if cfg.NVDFetcher == nil {
		return nil
	}
	var errs []SourceError
	for _, c := range cpes {
		key := NVDCPEKey(c.CPE)
		cached, _ := cfg.Store.GetVulns(ctx, SourceNVD, key)
		if cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
			continue // fresh: don't touch NVD
		}
		records, err := cfg.NVDFetcher.QueryCPE(ctx, c.CPE)
		if err != nil {
			// A stale cache entry is still served by the assembly step.
			msg := StaleMessage(SourceNVD, err, cached.Found)
			errs = append(errs, SourceError{Source: SourceNVD, Kind: "other", Err: errors.New(msg)})
			continue
		}
		for i := range records {
			records[i].CanonicalID = records[i].OriginalID // NVD ids are CVEs
			// The affected component is this package; MatchedOn already holds the
			// CPE. (Best-effort in the shared per-CPE cache; assembly re-stamps.)
			records[i].AffectedPackage = spurl
			records[i].FetchedAt = now
		}
		_ = cfg.Store.PutVulns(ctx, SourceNVD, key, records)
	}
	return errs
}

// bestSummary picks the group's display summary by source priority: NVD
// description first, then OSV summary, then ecosyste.ms. A source contributes
// only if it actually has a non-empty summary.
func bestSummary(records []VulnRecord) string {
	for _, src := range []string{SourceNVD, SourceOSV, SourceEcosystems} {
		for _, r := range records {
			if r.Source == src && r.Summary != "" {
				return r.Summary
			}
		}
	}
	return ""
}

// matchGroups runs per-record matching over each CanonicalGroup and does the
// binary per-group roll-up.
func matchGroups(groups []CanonicalGroup, identity purl.Identity, version string) []VulnGroup {
	out := make([]VulnGroup, 0, len(groups))
	for _, g := range groups {
		vg := VulnGroup{CanonicalID: g.CanonicalID, MaxScore: g.MaxScore}
		vg.Summary = bestSummary(g.Records)
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
func collectStage1(ctx context.Context, fetcher EcosystemsFetcher, st Store, spurl string, maxAge time.Duration, now time.Time, budget time.Duration) (*Result, []SourceError) {
	var errs []SourceError

	cached, _ := st.GetComponent(ctx, spurl)
	if cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		return cachedComponentResult(ctx, st, cached.Value), errs
	}

	fctx, cancel := budgetCtx(ctx, budget)
	comp, repo, vulns, err := fetcher.Fetch(fctx, spurl)
	timedOut := ctx.Err() == nil && fctx.Err() == context.DeadlineExceeded
	cancel()

	if errors.Is(err, ErrSourceNotApplicable) {
		// ecosyste.ms doesn't cover this purl type (deb/rpm/apk/…): not an
		// error, distro data arrives via OSV. Clean skip, no SourceError.
		return &Result{}, errs
	}
	if err != nil {
		// Live fetch failed or timed out. Serve the stale component if we have
		// one (collect must stay fast), with a non-fatal warning; otherwise
		// report the error and yield no component.
		msg := StaleMessage(SourceEcosystems, err, cached.Found)
		errs = append(errs, SourceError{Source: SourceEcosystems, Kind: errKind(timedOut), Err: errors.New(msg)})
		if cached.Found {
			return cachedComponentResult(ctx, st, cached.Value), errs
		}
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
