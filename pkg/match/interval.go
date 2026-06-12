package match

import (
	"regexp"
	"strings"

	msemver "github.com/Masterminds/semver/v3"
)

// Interval represents a version range parsed from "[lo, hi)" notation.
// [/] bounds are inclusive, (/) exclusive, "*" is unbounded.
type Interval struct {
	LowerInc bool
	Lower    string
	Upper    string
	UpperInc bool
}

var intervalRe = regexp.MustCompile(`^([\[\(])\s*([^,\s]*)\s*,\s*([^,\]\)]*)\s*([\]\)])$`)

// ParseInterval parses a version interval string like "[1.0.0, 2.0.0)".
func ParseInterval(s string) (*Interval, bool) {
	m := intervalRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil, false
	}
	return &Interval{
		LowerInc: m[1] == "[",
		Lower:    strings.TrimSpace(m[2]),
		Upper:    strings.TrimSpace(m[3]),
		UpperInc: m[4] == "]",
	}, true
}

// ParseIntervals parses every string with ParseInterval. Returns (nil, false)
// if any entry fails. Bound values "0" are normalized to "*" ("from the
// beginning"), matching OSV semantics.
func ParseIntervals(ss []string) ([]Interval, bool) {
	if len(ss) == 0 {
		return nil, false
	}
	out := make([]Interval, 0, len(ss))
	for _, s := range ss {
		ivl, ok := ParseInterval(s)
		if !ok {
			return nil, false
		}
		ivl.Lower = normalizeBound(ivl.Lower)
		ivl.Upper = normalizeBound(ivl.Upper)
		out = append(out, *ivl)
	}
	return out, true
}

func normalizeBound(v string) string {
	if v == "" || v == "0" {
		return "*"
	}
	return v
}

// StripBuildMeta removes the semver build metadata suffix (e.g. "+incompatible").
func StripBuildMeta(s string) string {
	if i := strings.IndexByte(s, '+'); i >= 0 {
		return s[:i]
	}
	return s
}

// mSemverInInterval reports whether version falls within iv.
// WHY: the second return distinguishes "out of range" from "couldn't parse a
// bound" — when a bound is unparseable we must never assume affected, so the
// caller treats !ok as "this interval does not match".
func mSemverInInterval(version string, iv *Interval) (matched bool, ok bool) {
	ver, err := msemver.NewVersion(version)
	if err != nil {
		return false, false
	}

	if iv.Lower != "" && iv.Lower != "*" {
		low, err := msemver.NewVersion(iv.Lower)
		if err != nil {
			return false, false
		}
		cmp := ver.Compare(low)
		if iv.LowerInc && cmp < 0 {
			return false, true
		}
		if !iv.LowerInc && cmp <= 0 {
			return false, true
		}
	}

	if iv.Upper != "" && iv.Upper != "*" {
		up, err := msemver.NewVersion(iv.Upper)
		if err != nil {
			return false, false
		}
		cmp := ver.Compare(up)
		if iv.UpperInc && cmp > 0 {
			return false, true
		}
		if !iv.UpperInc && cmp >= 0 {
			return false, true
		}
	}

	return true, true
}

// mSemverNextFix returns the smallest fixed version strictly greater than
// version, or "" when none parses or qualifies.
func mSemverNextFix(version string, fixedVersions []string) string {
	ver, err := msemver.NewVersion(version)
	if err != nil {
		return ""
	}
	var best *msemver.Version
	bestRaw := ""
	for _, f := range fixedVersions {
		fv, err := msemver.NewVersion(f)
		if err != nil {
			continue
		}
		if fv.Compare(ver) > 0 && (best == nil || fv.Compare(best) < 0) {
			best = fv
			bestRaw = f
		}
	}
	return bestRaw
}
