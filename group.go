// Canonical grouping puro (DD §5): agrupa VulnRecords por canonical ID
// derivado. Sin I/O, determinístico, reusable por Collect y read paths.
package magpie

import (
	"regexp"
	"strconv"
)

var cveRe = regexp.MustCompile(`(?i)^CVE-(\d{4})-(\d+)$`)

// IsCVE reporta si id tiene forma de CVE ("CVE-YYYY-NNNN").
func IsCVE(id string) bool {
	return cveRe.MatchString(id)
}

// pickNewestCVE devuelve el CVE más nuevo de la lista (año desc, luego número
// desc), o "" si no hay ninguno.
func pickNewestCVE(ids []string) string {
	best := ""
	bestYear, bestNum := 0, 0
	for _, id := range ids {
		m := cveRe.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		// WHY: comparación entera del número (no lexicográfica), si no
		// "CVE-2020-9999" ganaría a "CVE-2020-10000" al comparar como string.
		year, _ := strconv.Atoi(m[1])
		num, _ := strconv.Atoi(m[2])
		if best == "" || year > bestYear || (year == bestYear && num > bestNum) {
			best, bestYear, bestNum = id, year, num
		}
	}
	return best
}

// CanonicalIDFor deriva el canonical de un record: el CVE más nuevo entre
// OriginalID+Aliases si existe, si no el propio OriginalID. Group la usa
// internamente; Collect la usa para stampear la columna canonical_id por record.
func CanonicalIDFor(r VulnRecord) string {
	ids := make([]string, 0, len(r.Aliases)+1)
	ids = append(ids, r.OriginalID)
	ids = append(ids, r.Aliases...)
	// TODO: el DD §5 menciona el campo upstream de OSV; no lo persistimos como
	// campo (queda en Payload). OriginalID+Aliases cubre OSV/NVD/ecosyste.ms.
	if cve := pickNewestCVE(ids); cve != "" {
		return cve
	}
	return r.OriginalID
}

// Group agrupa records por canonical ID. El orden de los grupos sigue la
// primera aparición del canonical en la entrada (estable, no reordena).
func Group(records []VulnRecord) []CanonicalGroup {
	index := make(map[string]int)
	var groups []CanonicalGroup
	for _, r := range records {
		id := CanonicalIDFor(r)
		i, ok := index[id]
		if !ok {
			i = len(groups)
			index[id] = i
			groups = append(groups, CanonicalGroup{CanonicalID: id})
		}
		g := &groups[i]
		g.Records = append(g.Records, r)
		if r.Score > g.MaxScore {
			g.MaxScore = r.Score
		}
	}
	return groups
}
