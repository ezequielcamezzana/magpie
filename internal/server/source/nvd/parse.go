package nvd

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

// ParseCVE decodes a raw NVD `cve` object into VulnRecords — one per
// application CPE (vendor:product) the CVE declares vulnerable. Each record
// carries the CVE metadata plus that CPE's ranges; MatchedOn holds the full
// CPE 2.3 string so target_sw survives in the flat VulnRecord.
func ParseCVE(raw []byte) ([]collect.VulnRecord, error) {
	var cve rawCVE
	if err := json.Unmarshal(raw, &cve); err != nil {
		return nil, err
	}
	_, score := bestCVSS(cve.Metrics)
	severity := severityFromScore(score)
	published := parseTime(cve.Published)
	modified := parseTime(cve.LastModified)
	summary := englishDescription(cve.Descriptions)

	out := make([]collect.VulnRecord, 0, len(cve.Configurations))
	for _, m := range extractMatches(cve.Configurations) {
		out = append(out, collect.VulnRecord{
			Source:      collect.SourceNVD,
			OriginalID:  cve.ID,
			CanonicalID: cve.ID,
			// NVD matches on a CPE; the affected component (a purl) is filled by
			// the caller (stage 4 knows the package).
			MatchedOn:      collect.BuildCPE(m.vendor, m.product, m.targetSw),
			Summary:        summary,
			Score:          score,
			Severity:       severity,
			AffectedRanges: m.ranges,
			FixedVersions:  m.fixed,
			Published:      published,
			Modified:       modified,
		})
	}
	return out, nil
}

// englishDescription returns the en description, falling back to the first one.
func englishDescription(ds []rawDescription) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

// cpeMatch is one (vendor:product) the CVE declares vulnerable, with its unioned
// version intervals, the first non-wildcard target_sw, and the fixed versions.
type cpeMatch struct {
	vendor, product, targetSw string
	ranges, fixed             []string
}

// extractMatches collapses every vulnerable cpeMatch into one cpeMatch per
// (vendor:product), preserving first-seen order.
func extractMatches(configs []rawConfig) []cpeMatch {
	type bucket struct {
		m       *cpeMatch
		seenIvl map[string]bool
		seenFix map[string]bool
	}
	var order []string
	buckets := map[string]*bucket{}

	get := func(vendor, product string) *bucket {
		key := vendor + ":" + product
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				m:       &cpeMatch{vendor: vendor, product: product},
				seenIvl: map[string]bool{},
				seenFix: map[string]bool{},
			}
			buckets[key] = b
			order = append(order, key)
		}
		return b
	}

	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				d := parseMatch(cm)
				if d.vendor == "" || d.product == "" {
					continue
				}
				b := get(d.vendor, d.product)
				if d.targetSw != "" && d.targetSw != "*" && b.m.targetSw == "" {
					b.m.targetSw = d.targetSw
				}
				if d.interval != "" && !b.seenIvl[d.interval] {
					b.seenIvl[d.interval] = true
					b.m.ranges = append(b.m.ranges, d.interval)
				}
				if d.fixed != "" && !b.seenFix[d.fixed] {
					b.seenFix[d.fixed] = true
					b.m.fixed = append(b.m.fixed, d.fixed)
				}
			}
		}
	}

	out := make([]cpeMatch, 0, len(order))
	for _, key := range order {
		out = append(out, *buckets[key].m)
	}
	return out
}

type matchData struct {
	vendor, product, targetSw, interval, fixed string
}

// parseMatch decodes one cpeMatch: criteria slots + version bounds → a range
// interval ("[lo, hi)"). target_sw is CPE part 10. Unbounded lower uses "[*"
// to match OSV's convention so range cross-validation lines up.
func parseMatch(m rawMatch) matchData {
	if !m.Vulnerable {
		return matchData{}
	}
	parts := strings.Split(m.Criteria, ":")
	if len(parts) < 5 {
		return matchData{}
	}
	// Application CPEs only (cpe:2.3:a:…); ignore OS/hardware (o/h).
	if len(parts) > 2 && parts[2] != "a" {
		return matchData{}
	}
	d := matchData{vendor: parts[3], product: parts[4]}
	if len(parts) > 10 {
		d.targetSw = parts[10]
	}

	lower, lBracket := "*", "["
	if m.VersionStartIncluding != "" {
		lower, lBracket = m.VersionStartIncluding, "["
	} else if m.VersionStartExcluding != "" {
		lower, lBracket = m.VersionStartExcluding, "("
	}

	switch {
	case m.VersionEndExcluding != "":
		d.interval = lBracket + lower + ", " + m.VersionEndExcluding + ")"
		d.fixed = m.VersionEndExcluding
	case m.VersionEndIncluding != "":
		d.interval = lBracket + lower + ", " + m.VersionEndIncluding + "]"
	case lower != "*":
		d.interval = lBracket + lower + ", *)"
	case parts[5] != "*" && parts[5] != "-" && parts[5] != "" && len(parts) >= 6:
		// pinned single version → point interval (consistent range form).
		d.interval = "[" + parts[5] + ", " + parts[5] + "]"
	}
	return d
}

func bestCVSS(m rawMetrics) (vector string, score float64) {
	for _, entries := range [][]rawCVSS{m.V40, m.V31, m.V30} {
		for _, e := range entries {
			if e.Type == "Primary" {
				return e.CVSSData.VectorString, e.CVSSData.BaseScore
			}
		}
	}
	for _, entries := range [][]rawCVSS{m.V40, m.V31, m.V30, m.V2} {
		if len(entries) > 0 {
			return entries[0].CVSSData.VectorString, entries[0].CVSSData.BaseScore
		}
	}
	return "", 0
}

func severityFromScore(score float64) string {
	switch {
	case score == 0:
		return ""
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MODERATE"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// Raw NVD CVE shapes — only the fields CPER maps.
type rawCVE struct {
	ID             string           `json:"id"`
	Published      string           `json:"published"`
	LastModified   string           `json:"lastModified"`
	Descriptions   []rawDescription `json:"descriptions"`
	Metrics        rawMetrics       `json:"metrics"`
	Configurations []rawConfig      `json:"configurations"`
}

type rawDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type rawMetrics struct {
	V40 []rawCVSS `json:"cvssMetricV40"`
	V31 []rawCVSS `json:"cvssMetricV31"`
	V30 []rawCVSS `json:"cvssMetricV30"`
	V2  []rawCVSS `json:"cvssMetricV2"`
}

type rawCVSS struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type rawConfig struct {
	Nodes []struct {
		CPEMatch []rawMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type rawMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}
