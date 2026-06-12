// Package match decides whether a queried version is affected by a
// vulnerability, given the version evidence (lists + ranges) for that vuln.
package match

import "strings"

type Evidence struct {
	AffectedVersions   []string // versiones exactas
	AffectedRanges     []string // intervalos "[lo, hi)"
	FixedVersions      []string
	UnaffectedVersions []string
}

type Result struct {
	Matched  bool
	Reason   string   // uno de los reason codes de abajo
	Range    string   // el intervalo que matcheó (cuando aplica)
	NextFix  string   // menor fixed version > la pedida (cuando matched y hay fixed)
	Warnings []string
}

type Matcher interface {
	Match(version string, ev Evidence) Result
}

// NOTE: estos reason codes duplican los string values de magpie.ReasonX en
// result.go a propósito. pkg/match no puede importar el root package magpie
// porque collect.go (root) importa pkg/match — importarlo de vuelta crearía un
// ciclo. El mapeo match.Result -> magpie.MatchVerdict lo hace collect.
const (
	ReasonNoVersionSpecified       = "no_version_specified"
	ReasonUnsupportedVersionScheme = "unsupported_version_scheme"
	ReasonInUnaffectedList         = "in_unaffected_list"
	ReasonInFixedList              = "in_fixed_list"
	ReasonInAffectedList           = "in_affected_list"
	ReasonNotInAffectedList        = "not_in_affected_list"
	ReasonInAffectedRange          = "in_affected_range"
	ReasonNotInAffectedRange       = "not_in_affected_range"
	ReasonNoEvidence               = "no_evidence"
)

// For returns the Matcher for a given source and ecosystem. NVD is always
// semver (DD §6). Go ecosystems use goMatcher; Debian/Ubuntu/RPM Linux
// distros use dpkgMatcher; everything else falls back to semver.
//
// WHY the ecosystem strings vary: pkg/purl emits both raw purl types ("go",
// "deb", "rpm") and Linux distro ecosystems ("Debian:12", "Ubuntu:24.04",
// "Red Hat:9"). We match the raw types and the dpkg/rpm distro prefixes.
func For(source, ecosystem string) Matcher {
	// NVD is always semver regardless of the ecosystem field (DD §6).
	if source == "nvd" {
		return semverMatcher{}
	}
	switch {
	case isGoEcosystem(ecosystem):
		return goMatcher{}
	case isDpkgEcosystem(ecosystem):
		return dpkgMatcher{}
	default:
		// TODO: Alpine (apk) usa el mismo algoritmo dpkg en Holmes; por ahora
		// cae a semver hasta confirmar el mapeo de ecosystem que produce purl.
		return semverMatcher{}
	}
}

func isGoEcosystem(e string) bool {
	switch e {
	case "go", "Go", "golang":
		return true
	}
	return false
}

func isDpkgEcosystem(e string) bool {
	switch e {
	case "deb", "rpm":
		return true
	}
	for _, p := range []string{"Debian", "Ubuntu", "Red Hat", "Rocky", "AlmaLinux", "Fedora", "SUSE", "openSUSE"} {
		if strings.HasPrefix(e, p) {
			return true
		}
	}
	return false
}
