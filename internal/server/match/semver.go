package match

import (
	msemver "github.com/Masterminds/semver/v3"
)

// semverMatcher is the baseline matcher: semver comparison via Masterminds.
// Used for generic ecosystems and all NVD vulnerabilities (DD §6).
type semverMatcher struct{}

// Match evaluates version against the evidence in the order defined by DD §6.
func (semverMatcher) Match(version string, ev Evidence) Result {
	// 1. SPURL without version matches everything.
	if version == "" {
		return Result{Matched: true, Reason: ReasonNoVersionSpecified}
	}

	version = StripBuildMeta(version)

	// 2. Unparseable version: never assume-affected.
	// WHY: for an invalid version we return unsupported instead of treating it
	// as affected — a silent false positive is worse than an "I don't know".
	if _, err := msemver.NewVersion(version); err != nil {
		return Result{Matched: false, Reason: ReasonUnsupportedVersionScheme}
	}

	// 3. UnaffectedVersions: definitive clear, immediate return.
	if semverInList(version, ev.UnaffectedVersions) {
		return Result{Matched: false, Reason: ReasonInUnaffectedList}
	}

	// 4. FixedVersions: definitive clear, immediate return.
	if semverInList(version, ev.FixedVersions) {
		return Result{Matched: false, Reason: ReasonInFixedList}
	}

	// 5. AffectedVersions: positive finding, immediate return.
	if semverInList(version, ev.AffectedVersions) {
		return Result{
			Matched: true,
			Reason:  ReasonInAffectedList,
			NextFix: mSemverNextFix(version, ev.FixedVersions),
		}
	}

	// 6. AffectedRanges: if the version wasn't in the list, it can still fall
	// within a range. An invalid bound makes THAT interval not match, never
	// assume-affected.
	for _, raw := range ev.AffectedRanges {
		iv, ok := ParseInterval(raw)
		if !ok {
			continue
		}
		iv.Lower = StripBuildMeta(iv.Lower)
		iv.Upper = StripBuildMeta(iv.Upper)
		matched, ok := mSemverInInterval(version, iv)
		if ok && matched {
			return Result{
				Matched: true,
				Reason:  ReasonInAffectedRange,
				Range:   raw,
				NextFix: mSemverNextFix(version, ev.FixedVersions),
			}
		}
	}

	// 7. Nothing matched.
	switch {
	case len(ev.AffectedRanges) > 0:
		return Result{Matched: false, Reason: ReasonNotInAffectedRange}
	case len(ev.AffectedVersions) > 0:
		return Result{Matched: false, Reason: ReasonNotInAffectedList}
	default:
		return Result{Matched: false, Reason: ReasonNoEvidence}
	}
}

// semverInList reports whether version equals any list entry by semver value.
// WHY: we compare parsed versions, not raw strings, so that "1.0.0" ==
// "1.0.0+build". If a list entry doesn't parse, we fall back to string
// equality instead of crashing or skipping it.
func semverInList(version string, list []string) bool {
	ver, err := msemver.NewVersion(version)
	if err != nil {
		return false
	}
	for _, e := range list {
		ev, err := msemver.NewVersion(StripBuildMeta(e))
		if err != nil {
			if version == StripBuildMeta(e) {
				return true
			}
			continue
		}
		if ver.Compare(ev) == 0 {
			return true
		}
	}
	return false
}
