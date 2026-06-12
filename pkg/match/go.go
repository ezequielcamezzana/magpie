package match

import (
	"strings"

	msemver "github.com/Masterminds/semver/v3"
	"golang.org/x/mod/semver"
)

// goMatcher handles Go module versioning via golang.org/x/mod/semver, with a
// Masterminds fallback for non-standard versions/bounds. It normalizes
// pseudo-versions and NVD date bounds before comparing.
type goMatcher struct{}

// Match evaluates version against the evidence in the order defined by DD §6,
// using Go semver semantics for comparison.
func (goMatcher) Match(version string, ev Evidence) Result {
	if version == "" {
		return Result{Matched: true, Reason: ReasonNoVersionSpecified}
	}

	version = StripBuildMeta(version)

	// WHY: igual que semverMatcher, ante una versión que ni x/mod ni
	// Masterminds parsean devolvemos unsupported en vez de assume-affected.
	if !goValid(version) {
		return Result{Matched: false, Reason: ReasonUnsupportedVersionScheme}
	}

	if goInList(version, ev.UnaffectedVersions) {
		return Result{Matched: false, Reason: ReasonInUnaffectedList}
	}

	if goInList(version, ev.FixedVersions) {
		return Result{Matched: false, Reason: ReasonInFixedList}
	}

	if goInList(version, ev.AffectedVersions) {
		return Result{
			Matched: true,
			Reason:  ReasonInAffectedList,
			NextFix: goNextFix(version, ev.FixedVersions),
		}
	}

	for _, raw := range ev.AffectedRanges {
		iv, ok := ParseInterval(raw)
		if !ok {
			continue
		}
		iv.Lower = normalizeGoBound(StripBuildMeta(iv.Lower))
		iv.Upper = normalizeGoBound(StripBuildMeta(iv.Upper))
		matched, ok := goInInterval(version, iv)
		if ok && matched {
			return Result{
				Matched: true,
				Reason:  ReasonInAffectedRange,
				Range:   raw,
				NextFix: goNextFix(version, ev.FixedVersions),
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

// goVer adds the leading "v" that golang.org/x/mod/semver requires.
func goVer(v string) string { return "v" + strings.TrimPrefix(v, "v") }

// goValid reports whether version parses under x/mod or, failing that, Masterminds.
func goValid(version string) bool {
	if semver.IsValid(goVer(version)) {
		return true
	}
	_, err := msemver.NewVersion(version)
	return err == nil
}

// goInList reports whether version equals any list entry under Go semver,
// falling back to Masterminds for non-standard entries.
func goInList(version string, list []string) bool {
	ver := goVer(version)
	for _, e := range list {
		e = StripBuildMeta(e)
		if semver.IsValid(ver) && semver.IsValid(goVer(e)) {
			if semver.Compare(ver, goVer(e)) == 0 {
				return true
			}
			continue
		}
		if semverEqualLenient(version, e) {
			return true
		}
	}
	return false
}

func semverEqualLenient(a, b string) bool {
	av, err := msemver.NewVersion(a)
	if err != nil {
		return a == b
	}
	bv, err := msemver.NewVersion(b)
	if err != nil {
		return a == b
	}
	return av.Compare(bv) == 0
}

// goInInterval reports whether version falls within iv using x/mod semver,
// falling back to Masterminds when a bound or the version isn't valid x/mod
// semver. The second return is false on an unparseable bound — caller treats
// that as "this interval does not match" (never assume affected).
func goInInterval(version string, iv *Interval) (matched bool, ok bool) {
	ver := goVer(version)

	// COMPLEX: if x/mod can't parse the version or any concrete bound we drop
	// to Masterminds for the whole interval, since mixing comparators would
	// give inconsistent ordering.
	if !semver.IsValid(ver) ||
		(iv.Lower != "" && iv.Lower != "*" && !semver.IsValid(goVer(iv.Lower))) ||
		(iv.Upper != "" && iv.Upper != "*" && !semver.IsValid(goVer(iv.Upper))) {
		return mSemverInInterval(strings.TrimPrefix(version, "v"), iv)
	}

	if iv.Lower != "" && iv.Lower != "*" {
		cmp := semver.Compare(ver, goVer(iv.Lower))
		if iv.LowerInc && cmp < 0 {
			return false, true
		}
		if !iv.LowerInc && cmp <= 0 {
			return false, true
		}
	}

	if iv.Upper != "" && iv.Upper != "*" {
		cmp := semver.Compare(ver, goVer(iv.Upper))
		if iv.UpperInc && cmp > 0 {
			return false, true
		}
		if !iv.UpperInc && cmp >= 0 {
			return false, true
		}
	}

	return true, true
}

// goNextFix returns the smallest fixed version strictly greater than version,
// using Go semver with a Masterminds fallback.
func goNextFix(version string, fixedVersions []string) string {
	ver := goVer(version)
	if !semver.IsValid(ver) {
		return mSemverNextFix(version, fixedVersions)
	}
	best := ""
	for _, f := range fixedVersions {
		fs := StripBuildMeta(f)
		fv := goVer(fs)
		if !semver.IsValid(fv) {
			continue
		}
		if semver.Compare(fv, ver) > 0 {
			if best == "" || semver.Compare(fv, goVer(best)) < 0 {
				best = f
			}
		}
	}
	return best
}
