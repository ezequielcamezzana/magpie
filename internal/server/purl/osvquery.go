package purl

import "strings"

type OSVQuery struct {
	Ecosystem     string
	BaseEcosystem string
	Name          string
	RepoURL       string
	Kind          Kind
	ReleaseToken  string
}

// ReleaseToken exposes the numeric release token for this Identity (e.g.
// "24.04" for ubuntu-noble). Empty when the Identity has no release.
func (id Identity) ReleaseToken() string {
	return releaseToken(id.Distro, id.Release)
}

// StoreKey is the per-source store key for these OSV records. Centralizes the
// key so collect and the client don't drift apart.
func (q OSVQuery) StoreKey() string {
	switch q.Kind {
	case KindLanguage, KindLinux:
		// For Linux the Ecosystem already comes suffixed with the release
		// ("Ubuntu:24.04"), so the key is release-scoped on its own.
		return strings.ToLower(q.Ecosystem + ":" + q.Name)
	case KindGitHub:
		return strings.ToLower(q.RepoURL)
	}
	return ""
}

// OSVQuery builds the OSV lookup descriptor for this Identity. Strategy varies
// by Kind so callers don't branch on it.
func (id Identity) OSVQuery() OSVQuery {
	switch id.Kind {
	case KindLanguage:
		return OSVQuery{
			Kind:          KindLanguage,
			Ecosystem:     id.Ecosystem,
			BaseEcosystem: id.Ecosystem,
			Name:          id.Name,
		}
	case KindLinux:
		token := releaseToken(id.Distro, id.Release)
		eco := id.Ecosystem
		if suffix := osvSuffix(id.Distro, token); suffix != "" {
			eco = id.Ecosystem + ":" + suffix
		}
		return OSVQuery{
			Kind:          KindLinux,
			Ecosystem:     eco,
			BaseEcosystem: id.Ecosystem,
			Name:          id.Name,
			ReleaseToken:  token,
		}
	case KindGitHub:
		return OSVQuery{Kind: KindGitHub, RepoURL: id.RepoURL}
	}
	return OSVQuery{Kind: KindOther}
}

// releaseToken normalizes the release to a numeric form (per OSV's query
// vocabulary). Codenames map to their numeric (noble→24.04, bookworm→12);
// "elN" / "fcN" forms drop the prefix; alpine drops the leading "v".
func releaseToken(distro, release string) string {
	if release == "" {
		return ""
	}
	if v, ok := codenameToNumeric[distroKey{distro, release}]; ok {
		return v
	}
	if distro == "alpine" {
		return strings.TrimPrefix(release, "v")
	}
	if rest := strings.TrimPrefix(release, "el"); rest != release {
		return rest
	}
	if rest := strings.TrimPrefix(release, "fc"); rest != release {
		return rest
	}
	return release
}

// osvSuffix formats the suffix OSV expects after the colon in its ecosystem
// string. Empty when the distro is not release-scoped by OSV (SUSE, Fedora).
func osvSuffix(distro, token string) string {
	if token == "" {
		return ""
	}
	switch distro {
	case "alpine", "wolfi", "chainguard":
		if strings.HasPrefix(token, "v") {
			return token
		}
		return "v" + token
	case "ubuntu", "debian", "kali", "rocky", "almalinux", "oraclelinux", "mageia", "openeuler", "photon":
		return token
	case "redhat", "suse", "opensuse", "fedora":
		// OSV does not scope these by release in its ecosystem field.
		return ""
	}
	return token
}

type distroKey struct {
	distro  string
	release string
}

// codenameToNumeric maps Debian/Ubuntu/Kali codenames to the numeric form OSV
// uses (e.g. "Ubuntu:24.04", "Debian:12").
var codenameToNumeric = map[distroKey]string{
	{"ubuntu", "xenial"}: "16.04",
	{"ubuntu", "bionic"}: "18.04",
	{"ubuntu", "focal"}:  "20.04",
	{"ubuntu", "jammy"}:  "22.04",
	{"ubuntu", "noble"}:  "24.04",

	{"debian", "buster"}:   "10",
	{"debian", "bullseye"}: "11",
	{"debian", "bookworm"}: "12",
	{"debian", "trixie"}:   "13",

	{"kali", "buster"}:   "10",
	{"kali", "bullseye"}: "11",
	{"kali", "bookworm"}: "12",
}

// numericToCodename reverses codenameToNumeric: maps a numeric Debian/Kali
// release (e.g. "12") back to its codename ("bookworm"). Empty when unknown.
func numericToCodename(distro, numeric string) string {
	for k, v := range codenameToNumeric {
		if k.distro == distro && v == numeric {
			return k.release
		}
	}
	return ""
}
