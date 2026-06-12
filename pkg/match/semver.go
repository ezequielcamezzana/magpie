package match

import (
	msemver "github.com/Masterminds/semver/v3"
)

// semverMatcher is the baseline matcher: semver comparison via Masterminds.
// Used for generic ecosystems and all NVD vulnerabilities (DD §6).
type semverMatcher struct{}

// Match evaluates version against the evidence in the order defined by DD §6.
func (semverMatcher) Match(version string, ev Evidence) Result {
	// 1. SPURL sin versión matchea todo.
	if version == "" {
		return Result{Matched: true, Reason: ReasonNoVersionSpecified}
	}

	version = StripBuildMeta(version)

	// 2. Versión no parseable: nunca assume-affected.
	// WHY: ante una versión inválida devolvemos unsupported en vez de tratarla
	// como afectada — un falso positivo silencioso es peor que un "no sé".
	if _, err := msemver.NewVersion(version); err != nil {
		return Result{Matched: false, Reason: ReasonUnsupportedVersionScheme}
	}

	// 3. UnaffectedVersions: clear definitivo, return inmediato.
	if semverInList(version, ev.UnaffectedVersions) {
		return Result{Matched: false, Reason: ReasonInUnaffectedList}
	}

	// 4. FixedVersions: clear definitivo, return inmediato.
	if semverInList(version, ev.FixedVersions) {
		return Result{Matched: false, Reason: ReasonInFixedList}
	}

	// 5. AffectedVersions: finding positivo, return inmediato.
	if semverInList(version, ev.AffectedVersions) {
		return Result{
			Matched: true,
			Reason:  ReasonInAffectedList,
			NextFix: mSemverNextFix(version, ev.FixedVersions),
		}
	}

	// 6. AffectedRanges: si la versión no estaba en la lista, todavía puede
	// caer en un rango. Un bound inválido hace que ESE intervalo no matchee,
	// nunca assume-affected.
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

	// 7. No matcheó nada.
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
// WHY: comparamos versiones parseadas, no strings crudos, para que "1.0.0" ==
// "1.0.0+build". Si un elemento de la lista no parsea, caemos a string-equal
// como fallback en vez de crashear o ignorarlo.
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
