package purl

import "strings"

type Kind string

const (
	KindLanguage Kind = "Language"
	KindGitHub   Kind = "GitHub"
	KindLinux    Kind = "Linux"
	KindOther    Kind = "Other"
)

type Identity struct {
	Kind      Kind
	Type      string
	Ecosystem string
	Name      string
	Namespace string
	Version   string
	Distro    string
	Release   string
	RepoURL   string
}

// Decompose classifies a PURL into the normalized Identity used by the
// pipeline. Every kind-specific decision lives here.
func Decompose(p PURL) Identity {
	id := Identity{
		Type:      p.Type,
		Namespace: strings.ToLower(p.Namespace),
		Name:      p.Name,
		Version:   p.Version,
	}

	if isGitHubType(p.Type) {
		id.Kind = KindGitHub
		id.Ecosystem = "GIT"
		if id.Namespace != "" && id.Name != "" {
			id.RepoURL = "https://github.com/" + id.Namespace + "/" + strings.ToLower(id.Name)
		}
		return id
	}
	if info, ok := linuxEcosystemFor(p); ok {
		id.Kind = KindLinux
		id.Ecosystem = info.osv
		id.Distro = info.distro
		id.Release = canonicalRelease(info.distro, extractRelease(p))
		id.Name = osvNameFor(p)
		return id
	}
	if eco, ok := languageEcosystems[p.Type]; ok {
		id.Kind = KindLanguage
		id.Ecosystem = eco
		id.Name = osvNameFor(p)
		return id
	}
	id.Kind = KindOther
	return id
}

// TargetSW returns the CPE target_sw token expected for this Identity's
// ecosystem (CPER §3a). Empty when no mapping applies.
func (id Identity) TargetSW() string {
	return targetSW[id.Type]
}

func isGitHubType(t string) bool {
	return t == "github" || t == "github.com"
}

// DD §2: language ecosystem name as OSV expects it.
var languageEcosystems = map[string]string{
	"npm":      "npm",
	"pypi":     "PyPI",
	"golang":   "Go",
	"cargo":    "crates.io",
	"gem":      "RubyGems",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"composer": "Packagist",

	"conan":        "ConanCenter",
	"hex":          "Hex",
	"pub":          "Pub",
	"cran":         "CRAN",
	"hackage":      "Hackage",
	"bioconductor": "Bioconductor",
	"swift":        "SwiftURL",
}

// DD §3a: target_sw per language ecosystem.
var targetSW = map[string]string{
	"npm":      "node.js",
	"pypi":     "python",
	"gem":      "ruby",
	"cargo":    "rust",
	"composer": "php",
	"nuget":    ".net",
}

type linuxInfo struct {
	osv    string
	distro string
}

var linuxByNamespace = map[string]map[string]linuxInfo{
	"deb": {
		"debian": {"Debian", "debian"},
		"ubuntu": {"Ubuntu", "ubuntu"},
		"kali":   {"Kali", "kali"},
	},
	"apk": {
		"alpine":     {"Alpine", "alpine"},
		"wolfi":      {"Wolfi", "wolfi"},
		"chainguard": {"Chainguard", "chainguard"},
	},
	"rpm": {
		"redhat":      {"Red Hat", "redhat"},
		"rocky":       {"Rocky Linux", "rocky"},
		"almalinux":   {"AlmaLinux", "almalinux"},
		"fedora":      {"Fedora", "fedora"},
		"opensuse":    {"openSUSE", "opensuse"},
		"suse":        {"SUSE", "suse"},
		"oraclelinux": {"Oracle Linux", "oraclelinux"},
		"mageia":      {"Mageia", "mageia"},
		"openeuler":   {"openEuler", "openeuler"},
		"photon":      {"Photon OS", "photon"},
	},
}

// linuxEcosystemFor classifies a PURL as a Linux package, returning the
// matching info. Honors both the namespace (pkg:deb/ubuntu/...) and the
// distro= qualifier (pkg:rpm/.../...?distro=rhel-9).
func linuxEcosystemFor(p PURL) (linuxInfo, bool) {
	byNS, ok := linuxByNamespace[p.Type]
	if !ok {
		return linuxInfo{}, false
	}
	if info, ok := byNS[strings.ToLower(p.Namespace)]; ok {
		return info, true
	}
	if q := p.Qualifiers["distro"]; q != "" {
		name := q
		if dash := strings.Index(q, "-"); dash > 0 {
			name = q[:dash]
		}
		name = strings.ToLower(name)
		if name == "rhel" {
			name = "redhat"
		}
		if info, ok := byNS[name]; ok {
			return info, true
		}
	}
	return linuxInfo{}, false
}

// osvNameFor produces the package name as OSV expects it per DD §2.
func osvNameFor(p PURL) string {
	switch p.Type {
	case "npm":
		if p.Namespace != "" {
			return p.Namespace + "/" + p.Name
		}
		return p.Name
	case "golang":
		if p.Namespace != "" {
			return p.Namespace + "/" + p.Name
		}
		return p.Name
	case "maven":
		if p.Namespace != "" {
			return p.Namespace + ":" + p.Name
		}
		return p.Name
	case "composer":
		if p.Namespace != "" {
			return p.Namespace + "/" + p.Name
		}
		return p.Name
	}
	return p.Name
}

// extractRelease reads the release token from the PURL qualifiers. Accepts
// "distro=<release>" or "distro=<name>-<release>" forms; falls back to other
// known release qualifier keys, and finally to the version string.
func extractRelease(p PURL) string {
	for _, k := range []string{"distro", "distro_version", "release", "os_release", "os_distro"} {
		if v := p.Qualifiers[k]; v != "" {
			if dash := strings.Index(v, "-"); dash > 0 && dash < len(v)-1 {
				return v[dash+1:]
			}
			return v
		}
	}
	return releaseFromVersion(p.Version)
}

// releaseFromVersion derives a release token from the version string, but only
// for unambiguous patterns. Ambiguous suffixes (e.g. "-2ubuntu10.9") return "".
func releaseFromVersion(v string) string {
	if v == "" {
		return ""
	}
	// Debian: "+debNNuM" → debN (12→bookworm, 11→bullseye, 10→buster).
	if i := strings.Index(v, "+deb"); i != -1 {
		if num := leadingDigits(v[i+len("+deb"):]); num != "" {
			return "deb" + num
		}
	}
	// Debian backports: "~bpoN+M".
	if i := strings.Index(v, "~bpo"); i != -1 {
		if num := leadingDigits(v[i+len("~bpo"):]); num != "" {
			return "deb" + num
		}
	}
	// RHEL family: ".elN".
	if i := strings.Index(v, ".el"); i != -1 {
		if num := leadingDigits(v[i+len(".el"):]); num != "" {
			return "el" + num
		}
	}
	// Fedora: ".fcNN".
	if i := strings.Index(v, ".fc"); i != -1 {
		if num := leadingDigits(v[i+len(".fc"):]); num != "" {
			return "fc" + num
		}
	}
	return ""
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// canonicalRelease normalizes a release token to the canonical form per distro.
// Alpine prefers a leading "v"; Debian/Ubuntu/Kali resolve "debNN" shorthand to
// the codename when known; "elN"/"fcN" pass through.
func canonicalRelease(distro, release string) string {
	if release == "" {
		return ""
	}
	r := strings.ToLower(strings.TrimSpace(release))
	if distro == "alpine" && !strings.HasPrefix(r, "v") {
		return "v" + r
	}
	if distro == "debian" || distro == "kali" {
		if rest := strings.TrimPrefix(r, "deb"); rest != r && isDigits(rest) {
			if cn := numericToCodename(distro, rest); cn != "" {
				return cn
			}
		}
	}
	return r
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
