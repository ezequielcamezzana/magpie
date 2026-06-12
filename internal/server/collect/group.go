// Pure canonical grouping (DD §5): groups VulnRecords by derived canonical
// ID. No I/O, deterministic, reusable by Collect and read paths.
package collect

import (
	"regexp"
	"strconv"
)

var cveRe = regexp.MustCompile(`(?i)^CVE-(\d{4})-(\d+)$`)

// IsCVE reports whether id has CVE shape ("CVE-YYYY-NNNN").
func IsCVE(id string) bool {
	return cveRe.MatchString(id)
}

// pickNewestCVE returns the newest CVE in the list (year desc, then number
// desc), or "" if there is none.
func pickNewestCVE(ids []string) string {
	best := ""
	bestYear, bestNum := 0, 0
	for _, id := range ids {
		m := cveRe.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		// WHY: integer comparison of the number (not lexicographic), otherwise
		// "CVE-2020-9999" would beat "CVE-2020-10000" when compared as strings.
		year, _ := strconv.Atoi(m[1])
		num, _ := strconv.Atoi(m[2])
		if best == "" || year > bestYear || (year == bestYear && num > bestNum) {
			best, bestYear, bestNum = id, year, num
		}
	}
	return best
}

// CanonicalIDFor derives a record's canonical: the newest CVE among
// OriginalID+Aliases if any, otherwise OriginalID itself. Group uses it
// internally; Collect uses it to stamp the per-record canonical_id column.
func CanonicalIDFor(r VulnRecord) string {
	ids := make([]string, 0, len(r.Aliases)+1)
	ids = append(ids, r.OriginalID)
	ids = append(ids, r.Aliases...)
	// TODO: DD §5 mentions OSV's upstream field; we don't persist it as a
	// field (it stays in Payload). OriginalID+Aliases covers OSV/NVD/ecosyste.ms.
	if cve := pickNewestCVE(ids); cve != "" {
		return cve
	}
	return r.OriginalID
}

// Group groups records by canonical ID. Group order follows the first
// appearance of the canonical in the input (stable, no reordering).
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
