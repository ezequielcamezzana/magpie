// Package cper implements stage 3 of the pipeline (CPER): it resolves the
// CPE(s) of a package by reading NVD's CPE configurations for the CVEs that
// OSV/ecosyste.ms already linked, cross-checking 4 signals
// (name/vendor/ecosystem/range, DD §3a). Lifted from Holmes'
// pkg/agents/cpe_nvd_learner.go.
//
// WHY a separate package: like the sources, it imports magpie (domain
// types), so magpie cannot import it back — it installs itself via
// collect.RegisterCPER in init().
package cper

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
	"github.com/ezequielcamezzana/magpie/internal/server/source/nvd"
)

// NVDFetcher fetches a CVE from NVD by id; *nvd.Client satisfies it. It is
// a parameter of Run so tests can stub it.
type NVDFetcher interface {
	FetchCVE(ctx context.Context, cveID string) (*collect.NVDCVE, error)
}

// maxLookups caps how many CVEs are looked up in NVD per Run.
const maxLookups = 5

func init() {
	collect.RegisterCPER(func(ctx context.Context, httpc *http.Client, cfg collect.Config, id purl.Identity, spurl, repoURL string, records []collect.VulnRecord, now time.Time) {
		Run(ctx, nvd.New(httpc, slog.Default(), cfg.NVDAPIKey), cfg, id, spurl, repoURL, records, now)
	})
}

// Run resolves CPEs and persists: the CPEs (cpes table) and each NVD CVE it
// resolves as a vuln record (source=nvd, key=spurl). Best-effort: never aborts.
//
// The cache is per package: fresh CPEs (GetCPEs vs MaxAge) short-circuit
// everything; stale or absent → NVD is queried per CVE (up to maxLookups).
func Run(ctx context.Context, fetcher NVDFetcher, cfg collect.Config, id purl.Identity, spurl, repoURL string, records []collect.VulnRecord, now time.Time) {
	if cfg.NVDAPIKey == "" || fetcher == nil {
		return // CPER disabled without API key
	}
	// WHY: NVD-by-CPE is backport-unaware. A distro purl points to a build with
	// backported fixes, but NVD's ranges/CPEs describe the upstream → it would
	// flag an already-fixed package as affected (false positive). For distros
	// the authoritative source is OSV.
	if id.Kind == purl.KindLinux {
		return
	}
	if cached, _ := cfg.Store.GetCPEs(ctx, spurl); cached.Found && collect.IsFresh(cached.FetchedAt, cfg.MaxAge, now) {
		return // fresh CPEs: don't touch NVD
	}

	cves, rangesByCVE := canonicalCVEs(records)
	if len(cves) == 0 {
		return
	}

	names, vendors := candidatesFrom(id, repoURL)
	nameSet, vendorSet := lowerSet(names), lowerSet(vendors)
	wantSw := id.TargetSW()

	var resolved []collect.ResolvedCPE
	var nvdRecords []collect.VulnRecord
	seen := map[string]bool{}

	for i, cve := range cves {
		if i >= maxLookups {
			break
		}
		nvdCVE, err := fetcher.FetchCVE(ctx, cve)
		if err != nil || nvdCVE == nil {
			continue // best-effort: a failed fetch doesn't abort the loop
		}

		osvIntervals, osvOk := match.ParseIntervals(rangesByCVE[cve])
		accepted := acceptCPEs(nvdCVE, cve, names, vendors, rangesByCVE[cve],
			nameSet, vendorSet, wantSw, id.Ecosystem, osvIntervals, osvOk, seen)
		if len(accepted) == 0 {
			continue
		}
		resolved = append(resolved, accepted...)
		nvdRecords = append(nvdRecords, nvdVulnRecord(nvdCVE, accepted, spurl, now))
		// No early-stop: a package can map to several CPEs (one per CVE).
		// `seen` deduplicates CPEs repeated across CVEs.
	}

	_ = cfg.Store.PutCPEs(ctx, spurl, resolved)
	if len(nvdRecords) > 0 {
		_ = cfg.Store.PutVulns(ctx, collect.SourceNVD, spurl, nvdRecords)
	}
}

// acceptCPEs applies the §3a rule over a CVE's matches:
//
//	(name ∧ vendor) ∨ (name ∧ ecosystem) ∨ range
//
// with range stratified: if name matches → shared concrete range; otherwise →
// OSV ⊆ NVD (strict subset).
func acceptCPEs(nvdCVE *collect.NVDCVE, cve string, names, vendors, osvRanges []string,
	nameSet, vendorSet map[string]bool, wantSw, ecosystem string,
	osvIntervals []match.Interval, osvOk bool, seen map[string]bool) []collect.ResolvedCPE {

	var out []collect.ResolvedCPE
	for _, m := range nvdCVE.Matches {
		if m.Vendor == "" || m.Product == "" {
			continue
		}
		productMatch := nameSet[strings.ToLower(m.Product)]
		vendorMatch := vendorSet[strings.ToLower(m.Vendor)]
		ecoMatch := wantSw != "" && m.TargetSw != "" && m.TargetSw != "*" &&
			strings.EqualFold(m.TargetSw, wantSw)

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
		if seen[m.PartialCPE] {
			continue
		}
		seen[m.PartialCPE] = true

		// Ranges always (whether they match or not): NVDRanges = everything NVD
		// declares for this CPE; OSVRanges = our side of the cross-check. When
		// range doesn't match, the UI can show both to explain why.
		rec := collect.ResolvedCPE{
			CPE: m.PartialCPE, CVE: cve, NVDVendor: m.Vendor, NVDProduct: m.Product,
			Ecosystem: ecosystem, Names: names, Vendors: vendors,
			NVDRanges: m.AffectedRanges, OSVRanges: osvRanges,
		}
		// Only list the signals that actually contributed to acceptance.
		var why []string
		if productMatch {
			rec.MatchedBy = append(rec.MatchedBy, "name")
			why = append(why, "name "+m.Product)
		}
		if vendorMatch {
			rec.MatchedBy = append(rec.MatchedBy, "vendor")
			why = append(why, "vendor "+m.Vendor)
		}
		if ecoMatch {
			rec.MatchedBy = append(rec.MatchedBy, "ecosystem")
			rec.NVDTargetSw = m.TargetSw
			why = append(why, "ecosystem "+m.TargetSw)
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

// nvdVulnRecord builds the package's NVD vuln record for a resolved CVE:
// header with NVD metadata, ranges/fixed as the union of the accepted CPEs.
func nvdVulnRecord(nvdCVE *collect.NVDCVE, accepted []collect.ResolvedCPE, spurl string, now time.Time) collect.VulnRecord {
	acceptedCPE := map[string]bool{}
	for _, a := range accepted {
		acceptedCPE[a.CPE] = true
	}
	var ranges, fixed []string
	seenR, seenF := map[string]bool{}, map[string]bool{}
	for _, m := range nvdCVE.Matches {
		if !acceptedCPE[m.PartialCPE] {
			continue
		}
		for _, r := range m.AffectedRanges {
			if !seenR[r] {
				seenR[r] = true
				ranges = append(ranges, r)
			}
		}
		for _, f := range m.FixedVersions {
			if !seenF[f] {
				seenF[f] = true
				fixed = append(fixed, f)
			}
		}
	}
	return collect.VulnRecord{
		Source:          collect.SourceNVD,
		QueryKey:        spurl,
		AffectedPackage: accepted[0].CPE,
		OriginalID:      nvdCVE.ID,
		CanonicalID:     nvdCVE.ID,
		Score:           nvdCVE.Score,
		Severity:        nvdCVE.Severity,
		AffectedRanges:  ranges,
		FixedVersions:   fixed,
		Published:       nvdCVE.Published,
		Modified:        nvdCVE.Modified,
		FetchedAt:       now,
	}
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

func lowerSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		if s := strings.ToLower(strings.TrimSpace(x)); s != "" {
			out[s] = true
		}
	}
	return out
}
