package ecosystems

import "github.com/ezequielcamezzana/magpie/internal/server/purl"

// registryName resolves the ecosyste.ms registry name for an Identity. Language
// types map by PURL type; distro registries are release-scoped (ubuntu-24.04,
// debian-12, alpine-v3.19). Returns "" when ecosyste.ms has no registry for it.
func registryName(id purl.Identity) string {
	switch id.Kind {
	case purl.KindLanguage:
		return registryByType[id.Type]
	case purl.KindLinux:
		token := id.ReleaseToken()
		if token == "" {
			return ""
		}
		switch id.Distro {
		case "ubuntu":
			return "ubuntu-" + token
		case "debian":
			return "debian-" + token
		case "alpine":
			return "alpine-v" + token
		}
	}
	return ""
}
