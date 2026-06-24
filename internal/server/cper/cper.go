// Package cper implements stage 3 of the pipeline (CPER): it resolves the
// CPE(s) of a package by reading NVD's CPE configurations for the CVEs that
// OSV/ecosyste.ms already linked, cross-checking 4 signals
// (name/vendor/ecosystem/range, DD §3a). Lifted from Holmes'
// pkg/agents/cpe_nvd_learner.go. The entrypoint wires Stage into
// collect.Config.CPER.
package cper

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// maxLookups caps how many CVEs *with NVD data* CPER analyzes per Run. It also
// bounds NVD traffic: newestAndOldest samples at most 2*maxLookups candidate
// CVEs, and Run fetches no more than that.
const maxLookups = 6

// maxConcurrentFetches caps simultaneous NVD by-id calls. WHY: NVD's by-id
// endpoint chokes on a concurrent burst — 6 at once all hang and time out,
// while 2 actually respond (~5s each). So we trickle them, not flood.
const maxConcurrentFetches = 3

// perRequestTimeout bounds a single CVE fetch (above NVD's typical ~5s latency,
// below the stage budget) so one hung NVD call fails fast and frees its slot,
// instead of holding it until the whole stage budget expires.
const perRequestTimeout = 8 * time.Second

// Stage adapts Run to collect.CPERStage, using cfg.CVEFetcher.
func Stage(ctx context.Context, cfg collect.Config, id purl.Identity, spurl, repoURL string, records []collect.VulnRecord, now time.Time) []collect.SourceError {
	if cfg.CVEFetcher == nil {
		return nil
	}
	return Run(ctx, cfg.CVEFetcher, cfg, id, spurl, repoURL, records, now)
}

// Run resolves the package's CPE(s) by cross-checking the candidate CVEs
// against NVD's CPE configurations, and persists the resolved CPEs. Each CVE's
// NVD records are cached per-CVE (key cve:<CVE>) so a re-resolution doesn't
// re-hit NVD's slow, rate-limited by-id endpoint. Stage 4 (in collect) turns
// the resolved CPEs into the package's NVD vuln records — Run writes none.
// Best-effort: never aborts.
//
// Caches: fresh CPEs (GetCPEs vs MaxAge) short-circuit everything; otherwise
// each candidate CVE is read from the per-CVE cache or fetched from NVD.
func Run(ctx context.Context, fetcher collect.CVEFetcher, cfg collect.Config, id purl.Identity, spurl, repoURL string, records []collect.VulnRecord, now time.Time) []collect.SourceError {
	if fetcher == nil {
		return nil // CPER disabled when no CVE fetcher wired
	}
	// WHY: NVD-by-CPE is backport-unaware. A distro purl points to a build with
	// backported fixes, but NVD's ranges/CPEs describe the upstream → it would
	// flag an already-fixed package as affected (false positive). For distros
	// the authoritative source is OSV.
	if id.Kind == purl.KindLinux {
		return nil
	}
	if cached, _ := cfg.Store.GetCPEs(ctx, spurl); cached.Found && collect.IsFresh(cached.FetchedAt, cfg.MaxAge.CPEs, now) {
		return nil // fresh CPEs: don't touch NVD
	}
	// WHY: a recent search that found no CPE is cached too (negative cache), so
	// CPE-less packages don't re-hit NVD on every request. Expires with MaxAge,
	// then we retry in case NVD analyzed the package's CVEs since.
	if missed, _ := cfg.Store.GetMissedCPE(ctx, spurl); missed.Found && collect.IsFresh(missed.FetchedAt, cfg.MaxAge.MissedCPE, now) {
		return nil
	}

	cves, rangesByCVE := canonicalCVEs(records)
	if len(cves) == 0 {
		return nil
	}
	cves = newestAndOldest(cves, maxLookups)

	names, vendors := candidatesFrom(id, repoURL)
	nameSet, vendorSet := lowerSet(names), lowerSet(vendors)
	wantSw := id.TargetSW()

	// WHY: ctx carries the SourceBudget deadline. NVD's by-id endpoint routinely
	// hangs (no response) and eats the whole budget; when it fires, ctx is
	// cancelled and every cache write below would fail — so the run would make
	// zero forward progress and re-fetch everything next time. wctx detaches the
	// writes from the deadline: whatever DID come back gets cached, so the next
	// run hits the cache and completes. Fetches still use ctx (they must stop at
	// the budget, not keep hammering NVD).
	wctx := context.WithoutCancel(ctx)

	// Fetch every candidate CVE's NVD records up front, in parallel: NVD's
	// by-id endpoint is slow, so doing the (≤2*maxLookups) candidates serially
	// is what makes a Run slow.
	fetched := fetchCVERecords(ctx, fetcher, cfg.Store, cves, cfg.MaxAge.Vulns, now)
	for _, fc := range fetched {
		// Cache every freshly fetched CVE (even ones past the useful budget): the
		// network call already happened, so the next Run shouldn't repeat it.
		if fc.fromNet && len(fc.recs) > 0 {
			_ = cfg.Store.PutVulns(wctx, collect.SourceNVD, collect.NVDCVEKey(fc.cve), fc.recs)
		}
	}

	var resolved []collect.ResolvedCPE
	seen := map[string]bool{} // dedups CPEs repeated across CVEs
	anyFailed := false
	var fetchErr error // first fetch error, for the SourceError message
	servedStale := false

	for _, fc := range fetched {
		// A failed fetch (VulnCheck hung/errored) blocks the negative cache below,
		// so an outage isn't mistaken for "no CPE". If stale records were served
		// for it (fc.recs non-empty), they're still used for resolution.
		if fc.failed {
			anyFailed = true
			if fetchErr == nil {
				fetchErr = fc.err
			}
			servedStale = servedStale || fc.stale
		}
		// No records: either the fetch failed with no cache, or VulnCheck has no
		// CPE configuration for this CVE yet. Nothing to match.
		if len(fc.recs) == 0 {
			continue
		}
		osvIntervals, osvOk := match.ParseIntervals(rangesByCVE[fc.cve])
		accepted := acceptCPEs(fc.recs, fc.cve, names, vendors, rangesByCVE[fc.cve],
			nameSet, vendorSet, wantSw, id.Ecosystem, osvIntervals, osvOk, seen)
		resolved = append(resolved, accepted...)
	}

	// A failed VulnCheck fetch is surfaced as a non-fatal SourceError; stale
	// per-CVE records were still used for resolution when available.
	var errs []collect.SourceError
	if fetchErr != nil {
		errs = append(errs, collect.SourceError{
			Source: collect.SourceVulnCheck,
			Kind:   "other",
			Err:    errors.New(collect.StaleMessage(collect.SourceVulnCheck, fetchErr, servedStale)),
		})
	}

	// WHY: never persist an empty set — a run that resolved nothing must not
	// wipe previously resolved CPEs.
	if len(resolved) > 0 {
		_ = cfg.Store.PutCPEs(wctx, spurl, resolved)
		_ = cfg.Store.DeleteMissedCPE(wctx, spurl)
		return errs
	}
	// Record a miss (negative cache) only when every candidate was consulted
	// without error — a real "no CPE for this package". If any fetch failed
	// (source down/hung, or the budget cancelled it mid-flight), we learned
	// nothing; a miss would freeze the package CPE-less until it expires.
	if !anyFailed {
		_ = cfg.Store.PutMissedCPE(wctx, spurl)
	}
	return errs
}

// fetchedCVE pairs a CVE with its NVD records and how they were obtained:
// fromNet (freshly fetched, needs caching), failed (the fetch errored), and
// stale (records served from a stale cache after a failed fetch).
type fetchedCVE struct {
	cve     string
	recs    []collect.VulnRecord
	fromNet bool
	failed  bool
	stale   bool
	err     error
}

// fetchCVERecords resolves each CVE's NVD records concurrently, cache-first,
// preserving the input order. Concurrency is capped at maxConcurrentFetches so
// NVD's by-id endpoint isn't flooded. The (write-side) caching is left to the
// caller — SQLite serializes writers, so it must stay single-threaded.
func fetchCVERecords(ctx context.Context, fetcher collect.CVEFetcher, st collect.Store, cves []string, maxAge time.Duration, now time.Time) []fetchedCVE {
	out := make([]fetchedCVE, len(cves))
	sem := make(chan struct{}, maxConcurrentFetches)
	var wg sync.WaitGroup
	for i, cve := range cves {
		wg.Add(1)
		go func(i int, cve string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = fetchOneCVE(ctx, fetcher, st, cve, maxAge, now)
		}(i, cve)
	}
	wg.Wait()
	return out
}

// fetchOneCVE returns a CVE's NVD records from the per-CVE cache when fresh,
// otherwise from VulnCheck (stamped now, flagged fromNet so the caller caches
// them). On a failed fetch it falls back to the stale cache when present (still
// usable for CPE resolution) and records the error so Run can surface it.
func fetchOneCVE(ctx context.Context, fetcher collect.CVEFetcher, st collect.Store, cve string, maxAge time.Duration, now time.Time) fetchedCVE {
	key := collect.NVDCVEKey(cve)
	cached, _ := st.GetVulns(ctx, collect.SourceNVD, key)
	if cached.Found && collect.IsFresh(cached.FetchedAt, maxAge, now) {
		return fetchedCVE{cve: cve, recs: cached.Value}
	}
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	recs, err := fetcher.FetchCVE(rctx, cve)
	if err != nil {
		if cached.Found {
			return fetchedCVE{cve: cve, recs: cached.Value, failed: true, stale: true, err: err}
		}
		return fetchedCVE{cve: cve, failed: true, err: err}
	}
	for i := range recs {
		recs[i].FetchedAt = now
	}
	return fetchedCVE{cve: cve, recs: recs, fromNet: true}
}

// acceptCPEs applies the §3a rule over a CVE's NVD records (one per CPE):
//
//	(name ∧ vendor) ∨ (name ∧ ecosystem) ∨ range
//
// with range stratified: if name matches → shared concrete range; otherwise →
// OSV ⊆ NVD (strict subset).
func acceptCPEs(records []collect.VulnRecord, cve string, names, vendors, osvRanges []string,
	nameSet, vendorSet map[string]bool, wantSw, ecosystem string,
	osvIntervals []match.Interval, osvOk bool, seen map[string]bool) []collect.ResolvedCPE {

	var out []collect.ResolvedCPE
	for _, m := range records {
		vendor, product, targetSw := collect.CPEParts(m.MatchedOn)
		if vendor == "" || product == "" {
			continue
		}
		short := collect.ShortCPE(m.MatchedOn)
		productMatch := nameSet[strings.ToLower(product)] || nameSet[normID(product)]
		vendorMatch := vendorMatches(vendor, vendorSet)
		ecoMatch := wantSw != "" && targetSw != "" &&
			strings.EqualFold(targetSw, wantSw)

		rangeMatch := false
		if osvOk {
			if nvdIntervals, ok := match.ParseIntervals(m.AffectedRanges); ok {
				if productMatch {
					rangeMatch = match.IntervalsShareConcreteRange(osvIntervals, nvdIntervals)
				} else {
					rangeMatch = match.IntervalsAreSubsetOf(osvIntervals, nvdIntervals)
				}
			}
		}

		// Valid acceptance rules: (name∧vendor) ∨ (name∧ecosystem) ∨ range.
		// vendor/name/ecosystem ALONE don't accept — only in combination.
		realMatch := (productMatch && vendorMatch) || (productMatch && ecoMatch) || rangeMatch
		if !realMatch {
			continue
		}
		if seen[short] {
			continue
		}
		seen[short] = true

		// Ranges always (whether they match or not): NVDRanges = everything NVD
		// declares for this CPE; OSVRanges = our side of the cross-check. When
		// range doesn't match, the UI can show both to explain why.
		rec := collect.ResolvedCPE{
			CPE: short, CVE: cve, NVDVendor: vendor, NVDProduct: product,
			Ecosystem: ecosystem, Names: names, Vendors: vendors,
			NVDRanges: m.AffectedRanges, OSVRanges: osvRanges,
		}
		// Only list the signals that actually contributed to acceptance.
		var why []string
		if productMatch {
			rec.MatchedBy = append(rec.MatchedBy, "name")
			why = append(why, "name "+product)
		}
		if vendorMatch {
			rec.MatchedBy = append(rec.MatchedBy, "vendor")
			why = append(why, "vendor "+vendor)
		}
		if ecoMatch {
			rec.MatchedBy = append(rec.MatchedBy, "ecosystem")
			rec.NVDTargetSw = targetSw
			why = append(why, "ecosystem "+targetSw)
		}
		if rangeMatch {
			rec.MatchedBy = append(rec.MatchedBy, "range")
			why = append(why, "range "+strings.Join(m.AffectedRanges, " "))
		}
		rec.Explanation = "matched by " + strings.Join(why, ", ") + " (" + cve + ")"
		out = append(out, rec)
	}
	return out
}

// vendorMatches reports whether the NVD vendor matches a candidate — either as
// a whole (separator-insensitive, so "7-zip" matches "7zip"), or by one of its
// '-'/'_'/'.'-separated tokens, so "apache-tomcat" matches the candidate
// "apache".
func vendorMatches(vendor string, vendorSet map[string]bool) bool {
	if vendorSet[strings.ToLower(vendor)] || vendorSet[normID(vendor)] {
		return true
	}
	for _, tok := range strings.FieldsFunc(vendor, isIDSeparator) {
		if vendorSet[strings.ToLower(tok)] || vendorSet[normID(tok)] {
			return true
		}
	}
	return false
}

func isIDSeparator(r rune) bool {
	return r == '-' || r == '_' || r == '.'
}

// normID lowercases an identifier and collapses its '-'/'_'/'.' separators, so
// "7-zip", "7_zip" and "7zip" compare equal. WHY: NVD products/vendors and purl
// names spell the same project with different separators; an exact compare
// misses them. Used both to build the candidate sets and to look CPE parts up.
func normID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if !isIDSeparator(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// canonicalCVEs extracts the canonical CVEs from the records (deduplicated)
// and, per CVE, the union of their affected ranges (OSV side). CVEs come out
// ordered by most recent Published first (the newest Published among their
// records).
//
// WHY: Run cuts off at maxLookups, so the order decides which CVEs get
// analyzed. We sort by Published (newest vulns) and not by Modified: any
// re-enrichment refreshes an old CVE's Modified, which would let it beat
// freshly published vulns.
func canonicalCVEs(records []collect.VulnRecord) (cves []string, rangesByCVE map[string][]string) {
	rangesByCVE = map[string][]string{}
	newest := map[string]time.Time{}
	for _, r := range records {
		cve := collect.CanonicalIDFor(r)
		if !collect.IsCVE(cve) {
			continue
		}
		if m, ok := newest[cve]; !ok {
			cves = append(cves, cve)
			newest[cve] = r.Published
		} else if r.Published.After(m) {
			newest[cve] = r.Published
		}
		rangesByCVE[cve] = append(rangesByCVE[cve], r.AffectedRanges...)
	}
	sort.SliceStable(cves, func(i, j int) bool {
		return newest[cves[i]].After(newest[cves[j]])
	})
	return cves, rangesByCVE
}

// newestAndOldest samples the n newest + n oldest CVEs from a newest-first
// list (deduped when the list is shorter than 2n), preserving newest-first
// order.
//
// WHY: the CPE lives on the CVEs NVD has *analyzed*, which are almost always
// the oldest ones — recent CVEs have no CPE configuration yet. A flat
// newest-first walk spends the whole sample on recent, un-analyzed CVEs and
// never reaches the analyzed ones (the hono bug: 28 recent CVEs, the CPE only
// on the 2023/2024 ones). Sampling both ends reaches an analyzed CVE.
func newestAndOldest(cves []string, n int) []string {
	if len(cves) <= 2*n {
		return cves
	}
	out := make([]string, 0, 2*n)
	out = append(out, cves[:n]...)
	out = append(out, cves[len(cves)-n:]...)
	return out
}

// candidatesFrom builds the package's name/vendor candidates (DD §3a). Lifted
// from Holmes' pkg/detectives/candidates.go.
func candidatesFrom(id purl.Identity, repoURL string) (names, vendors []string) {
	nset, vset := map[string]bool{}, map[string]bool{}
	addName := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !nset[s] {
			nset[s] = true
			names = append(names, s)
		}
	}
	addVendor := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !vset[s] {
			vset[s] = true
			vendors = append(vendors, s)
		}
	}

	addVendor(id.Type)
	addName(id.Name)

	if id.Namespace != "" {
		parts := strings.Split(strings.Trim(id.Namespace, "/"), "/")
		if len(parts) > 0 {
			addVendor(parts[0])
		}
		if len(parts) > 1 {
			addName(parts[len(parts)-1])
		}
	}

	if repoURL != "" {
		if owner, name := ownerNameFromURL(repoURL); owner != "" {
			addVendor(owner)
			addName(name)
		}
	}

	// Self-named upstreams (lodash/lodash, curl/curl): promote each name to
	// vendor candidate.
	for _, n := range names {
		addVendor(n)
	}
	return names, vendors
}

func ownerNameFromURL(repoURL string) (owner, name string) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git")
}

// lowerSet builds the lookup set for a candidate list, holding BOTH the plain
// lowercased form and the separator-collapsed normID form of each candidate.
// Keeping both means a separator-insensitive match never costs an exact one
// (e.g. "node.js" still matches as-is, while "7zip" also matches "7-zip").
func lowerSet(xs []string) map[string]bool {
	out := make(map[string]bool, 2*len(xs))
	for _, x := range xs {
		if s := strings.ToLower(strings.TrimSpace(x)); s != "" {
			out[s] = true
			out[normID(s)] = true
		}
	}
	return out
}
