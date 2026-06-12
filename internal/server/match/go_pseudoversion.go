package match

// Bridges two version spaces that describe the same Go vulnerability:
//
//   - Go module proxy: pseudo-versions  0.0.0-YYYYMMDDhhmmss-<12-hex>
//     (used by OSV and the installed go.mod of any pre-tag module like
//     golang.org/x/net)
//   - NVD analyst notes: plain calendar dates  YYYY-MM-DD
//     (the analyst wrote "fix is before July 12, 2018" without knowing the
//     commit hash or pseudo-version encoding)
//
// Without normalization the matcher's semver parsers reject the date, fall
// back to Masterminds which loosely reads "2018-07-12" as ~2018.x, and every
// pseudo-version "0.0.0-..." sorts below it — flagging the whole module as
// vulnerable forever.

import (
	"regexp"
	"strings"
)

var goDateBoundRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})(?:[T\s].*)?$`)

// normalizeGoBound rewrites an NVD-style date bound into a synthetic Go
// pseudo-version. Example: "2018-07-12" → "0.0.0-20180712000000-000000000000".
//
// WHY date → pseudo and not the other direction: the pseudo-version space
// already encodes time monotonically (semver pre-release ordering on the
// embedded timestamp), so the conversion reuses Go's own comparison rules.
// Tagged releases like v0.5.0 have no date, so going the other way would leave
// them unplaceable; this way they keep their natural ordering (v0.5.0 sorts
// above any 0.0.0-* pseudo). The synthetic timestamp is zero-padded and the
// hash all zeros — the most conservative read of "before this day", still a
// valid pseudo-version.
//
// Idempotent on every non-date input.
func normalizeGoBound(s string) string {
	m := goDateBoundRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return s
	}
	return "0.0.0-" + m[1] + m[2] + m[3] + "000000-000000000000"
}

// NormalizeGoIntervals returns ivs with every bound run through
// normalizeGoBound, so cross-source Go interval comparisons see date bounds as
// comparable pseudo-versions. Mutates in place and returns the same slice.
func NormalizeGoIntervals(ivs []Interval) []Interval {
	for i := range ivs {
		ivs[i].Lower = normalizeGoBound(ivs[i].Lower)
		ivs[i].Upper = normalizeGoBound(ivs[i].Upper)
	}
	return ivs
}
