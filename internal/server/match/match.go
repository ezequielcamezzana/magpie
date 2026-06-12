// Package match decides whether a queried version is affected by a
// vulnerability, given the version evidence (lists + ranges) for that vuln.
package match

import "strings"

type Evidence struct {
	AffectedVersions   []string // exact versions
	AffectedRanges     []string // intervals "[lo, hi)"
	FixedVersions      []string
	UnaffectedVersions []string
}

type Result struct {
	Matched  bool
	Reason   string // one of the reason codes below
	Range    string // the interval that matched (when applicable)
	NextFix  string // smallest fixed version > the queried one (when matched and fixed exists)
	Warnings []string
}

type Matcher interface {
	Match(version string, ev Evidence) Result
}

// NOTE: these reason codes deliberately duplicate the string values of
// magpie.ReasonX in result.go. This package cannot import the root package
// magpie because collect.go (root) imports this package — importing it back
// would create a cycle. The match.Result -> magpie.MatchVerdict mapping is
// done by collect.
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
// WHY the ecosystem strings vary: the purl package emits both raw purl types ("go",
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
		// TODO: Alpine (apk) uses the same dpkg algorithm in Holmes; for now
		// it falls back to semver until the ecosystem mapping produced by
		// purl is confirmed.
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
