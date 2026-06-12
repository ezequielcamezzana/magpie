// Package cper implementa el stage 3 del pipeline (CPER): resuelve el/los CPE
// de un paquete leyendo las CPE configurations de NVD para los CVE que
// OSV/ecosyste.ms ya linkearon, y cruzando 4 señales (name/vendor/ecosystem/
// range, DD §3a). Lifted de Holmes' pkg/agents/cpe_nvd_learner.go.
//
// WHY package aparte: igual que los sources, importa magpie (tipos de
// dominio), así que magpie no puede importarlo de vuelta — se instala vía
// magpie.RegisterCPER en el init().
package cper

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	magpie "github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/pkg/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
	"github.com/ezequielcamezzana/magpie/source/nvd"
)

// NVDFetcher trae una CVE de NVD por id; *nvd.Client la satisface. Es
// parámetro de Run para poder stubear en tests.
type NVDFetcher interface {
	FetchCVE(ctx context.Context, cveID string) (*magpie.NVDCVE, error)
}

// maxLookups acota cuántas CVE se consultan a NVD por Run.
const maxLookups = 5

func init() {
	magpie.RegisterCPER(func(ctx context.Context, httpc *http.Client, cfg magpie.Config, id purl.Identity, spurl, repoURL string, records []magpie.VulnRecord, now time.Time) {
		Run(ctx, nvd.New(httpc, slog.Default(), cfg.NVDAPIKey), cfg, id, spurl, repoURL, records, now)
	})
}

// Run resuelve CPEs y persiste: los CPEs (tabla cpes) y cada CVE NVD que
// resuelve como vuln record (source=nvd, key=spurl). Best-effort: nunca aborta.
//
// El cache es por paquete: CPEs frescos (GetCPEs vs MaxAge) cortocircuitan
// todo; stale o ausentes → se consulta NVD por CVE (hasta maxLookups).
func Run(ctx context.Context, fetcher NVDFetcher, cfg magpie.Config, id purl.Identity, spurl, repoURL string, records []magpie.VulnRecord, now time.Time) {
	if cfg.NVDAPIKey == "" || fetcher == nil {
		return // CPER deshabilitado sin API key
	}
	// WHY: NVD-by-CPE es backport-unaware. Un purl distro apunta a una build con
	// fixes backporteados, pero los rangos/CPE de NVD describen el upstream → marcaría
	// afectado un paquete ya fixeado (falso positivo). Para distros la fuente
	// autoritativa es OSV.
	if id.Kind == purl.KindLinux {
		return
	}
	if cached, _ := cfg.Store.GetCPEs(ctx, spurl); cached.Found && magpie.IsFresh(cached.FetchedAt, cfg.MaxAge, now) {
		return // CPEs frescos: no tocamos NVD
	}

	cves, rangesByCVE := canonicalCVEs(records)
	if len(cves) == 0 {
		return
	}

	names, vendors := candidatesFrom(id, repoURL)
	nameSet, vendorSet := lowerSet(names), lowerSet(vendors)
	wantSw := id.TargetSW()

	var resolved []magpie.ResolvedCPE
	var nvdRecords []magpie.VulnRecord
	seen := map[string]bool{}

	for i, cve := range cves {
		if i >= maxLookups {
			break
		}
		nvdCVE, err := fetcher.FetchCVE(ctx, cve)
		if err != nil || nvdCVE == nil {
			continue // best-effort: un fetch fallido no aborta el loop
		}

		osvIntervals, osvOk := match.ParseIntervals(rangesByCVE[cve])
		accepted := acceptCPEs(nvdCVE, cve, names, vendors, rangesByCVE[cve],
			nameSet, vendorSet, wantSw, id.Ecosystem, osvIntervals, osvOk, seen)
		if len(accepted) == 0 {
			continue
		}
		resolved = append(resolved, accepted...)
		nvdRecords = append(nvdRecords, nvdVulnRecord(nvdCVE, accepted, spurl, now))
		// Sin early-stop: un paquete puede mapear a varios CPEs (uno por CVE).
		// El `seen` deduplica CPEs repetidos entre CVEs.
	}

	_ = cfg.Store.PutCPEs(ctx, spurl, resolved)
	if len(nvdRecords) > 0 {
		_ = cfg.Store.PutVulns(ctx, magpie.SourceNVD, spurl, nvdRecords)
	}
}

// acceptCPEs aplica la regla §3a sobre los matches de una CVE:
//
//	(name ∧ vendor) ∨ (name ∧ ecosystem) ∨ range
//
// con range estratificado: si name matchea → shared concrete range; si no →
// OSV ⊆ NVD (subset estricto).
func acceptCPEs(nvdCVE *magpie.NVDCVE, cve string, names, vendors, osvRanges []string,
	nameSet, vendorSet map[string]bool, wantSw, ecosystem string,
	osvIntervals []match.Interval, osvOk bool, seen map[string]bool) []magpie.ResolvedCPE {

	var out []magpie.ResolvedCPE
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

		// Reglas de aceptación válidas: (name∧vendor) ∨ (name∧ecosystem) ∨ range.
		// vendor/name/ecosystem SUELTOS no aceptan — solo en combinación.
		realMatch := (productMatch && vendorMatch) || (productMatch && ecoMatch) || rangeMatch
		if !realMatch {
			continue
		}
		if seen[m.PartialCPE] {
			continue
		}
		seen[m.PartialCPE] = true

		// Ranges siempre (matcheen o no): NVDRanges = todo lo que NVD declara
		// para este CPE; OSVRanges = nuestro lado del cruce. Cuando range no
		// matchea, la UI puede mostrar ambos para explicar el porqué.
		rec := magpie.ResolvedCPE{
			CPE: m.PartialCPE, CVE: cve, NVDVendor: m.Vendor, NVDProduct: m.Product,
			Ecosystem: ecosystem, Names: names, Vendors: vendors,
			NVDRanges: m.AffectedRanges, OSVRanges: osvRanges,
		}
		// Solo listamos las señales que de verdad contribuyeron a aceptar.
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

// nvdVulnRecord arma el vuln record NVD del paquete para una CVE resuelta:
// header con metadata de NVD, ranges/fixed unión de los CPE aceptados.
func nvdVulnRecord(nvdCVE *magpie.NVDCVE, accepted []magpie.ResolvedCPE, spurl string, now time.Time) magpie.VulnRecord {
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
	return magpie.VulnRecord{
		Source:          magpie.SourceNVD,
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

// canonicalCVEs extrae los CVE canónicos de los records (deduplicados) y, por
// CVE, la unión de sus affected ranges (lado OSV). Los CVE salen ordenados por
// Published más reciente primero (el Published más nuevo entre sus records).
//
// WHY: Run corta en maxLookups, así que el orden decide qué CVEs se analizan.
// Se ordena por Published (vulns más nuevas) y no por Modified: a un CVE viejo
// cualquier re-enrichment le renueva el Modified y le ganaría a vulns recién
// publicadas.
func canonicalCVEs(records []magpie.VulnRecord) (cves []string, rangesByCVE map[string][]string) {
	rangesByCVE = map[string][]string{}
	newest := map[string]time.Time{}
	for _, r := range records {
		cve := magpie.CanonicalIDFor(r)
		if !magpie.IsCVE(cve) {
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

// candidatesFrom arma los candidatos name/vendor del paquete (DD §3a). Lifted
// de Holmes' pkg/detectives/candidates.go.
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

	// Self-named upstreams (lodash/lodash, curl/curl): promover cada name a
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
