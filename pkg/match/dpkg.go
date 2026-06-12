package match

import (
	"strconv"
	"strings"
)

// dpkgMatcher implements Debian-policy version ordering (Policy §5.6.12) for
// deb (Debian/Ubuntu) and rpm (RHEL/Rocky/Fedora/SUSE) ecosystems. RPM's
// rpmvercmp differs only at edge cases that don't surface in real package
// versions, so the same comparator serves both.
type dpkgMatcher struct{}

// Match evaluates version against the evidence in the order defined by DD §6,
// using dpkg version comparison for list equality and interval membership.
func (dpkgMatcher) Match(version string, ev Evidence) Result {
	if version == "" {
		return Result{Matched: true, Reason: ReasonNoVersionSpecified}
	}

	// WHY: a deb/rpm version is essentially any non-empty string; there's no
	// "unparseable" case like semver. An empty version is the only reject.
	if strings.TrimSpace(version) == "" {
		return Result{Matched: false, Reason: ReasonUnsupportedVersionScheme}
	}

	if dpkgInList(version, ev.UnaffectedVersions) {
		return Result{Matched: false, Reason: ReasonInUnaffectedList}
	}

	if dpkgInList(version, ev.FixedVersions) {
		return Result{Matched: false, Reason: ReasonInFixedList}
	}

	if dpkgInList(version, ev.AffectedVersions) {
		return Result{
			Matched: true,
			Reason:  ReasonInAffectedList,
			NextFix: dpkgNextFix(version, ev.FixedVersions),
		}
	}

	for _, raw := range ev.AffectedRanges {
		iv, ok := ParseInterval(raw)
		if !ok {
			continue
		}
		if dpkgInInterval(version, iv) {
			return Result{
				Matched: true,
				Reason:  ReasonInAffectedRange,
				Range:   raw,
				NextFix: dpkgNextFix(version, ev.FixedVersions),
			}
		}
	}

	switch {
	case len(ev.AffectedRanges) > 0:
		return Result{Matched: false, Reason: ReasonNotInAffectedRange}
	case len(ev.AffectedVersions) > 0:
		return Result{Matched: false, Reason: ReasonNotInAffectedList}
	default:
		return Result{Matched: false, Reason: ReasonNoEvidence}
	}
}

func dpkgInList(version string, list []string) bool {
	for _, e := range list {
		if dpkgCompare(version, e) == 0 {
			return true
		}
	}
	return false
}

func dpkgInInterval(version string, iv *Interval) bool {
	if iv.Lower != "" && iv.Lower != "*" {
		c := dpkgCompare(version, iv.Lower)
		if iv.LowerInc && c < 0 {
			return false
		}
		if !iv.LowerInc && c <= 0 {
			return false
		}
	}
	if iv.Upper != "" && iv.Upper != "*" {
		c := dpkgCompare(version, iv.Upper)
		if iv.UpperInc && c > 0 {
			return false
		}
		if !iv.UpperInc && c >= 0 {
			return false
		}
	}
	return true
}

func dpkgNextFix(version string, fixed []string) string {
	best := ""
	for _, f := range fixed {
		if dpkgCompare(f, version) <= 0 {
			continue
		}
		if best == "" || dpkgCompare(f, best) < 0 {
			best = f
		}
	}
	return best
}

// dpkgCompare returns -1, 0, or 1 comparing a and b under Debian Policy
// version ordering: epoch, then upstream version, then debian-revision.
func dpkgCompare(a, b string) int {
	epochA, restA := splitEpoch(a)
	epochB, restB := splitEpoch(b)
	if epochA != epochB {
		return signum(epochA - epochB)
	}
	upA, revA := splitRevision(restA)
	upB, revB := splitRevision(restB)
	if c := dpkgCompareSegment(upA, upB); c != 0 {
		return c
	}
	return dpkgCompareSegment(revA, revB)
}

func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			return n, v[i+1:]
		}
	}
	return 0, v
}

func splitRevision(v string) (upstream, revision string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, "0"
}

// dpkgCompareSegment compares two version segments (upstream or revision)
// using the digit/non-digit alternation defined in Debian Policy §5.6.12.
//
// COMPLEX: we alternate strictly — a non-digit run, then a digit run, until
// both strings are exhausted. The two runs use different orderings
// (dpkgCompareNonDigit vs dpkgCompareDigit), which is what makes "1.0~rc1"
// sort below "1.0".
func dpkgCompareSegment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		startA, startB := i, j
		for i < len(a) && !isDigit(a[i]) {
			i++
		}
		for j < len(b) && !isDigit(b[j]) {
			j++
		}
		if c := dpkgCompareNonDigit(a[startA:i], b[startB:j]); c != 0 {
			return c
		}
		startA, startB = i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := dpkgCompareDigit(a[startA:i], b[startB:j]); c != 0 {
			return c
		}
	}
	return 0
}

func dpkgCompareNonDigit(a, b string) int {
	for k := 0; k < len(a) || k < len(b); k++ {
		var ca, cb byte
		if k < len(a) {
			ca = a[k]
		}
		if k < len(b) {
			cb = b[k]
		}
		wa, wb := dpkgWeight(ca), dpkgWeight(cb)
		if wa != wb {
			return signum(wa - wb)
		}
	}
	return 0
}

func dpkgCompareDigit(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return signum(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// dpkgWeight orders characters per Debian Policy: '~' before end-of-string,
// end-of-string before letters, letters before other non-digit characters.
func dpkgWeight(c byte) int {
	switch {
	case c == 0:
		return 0
	case c == '~':
		return -1
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func signum(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
