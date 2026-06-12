package purl

import (
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
)

type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

func Parse(coord string) (PURL, error) {
	p, err := packageurl.FromString(coord)
	if err != nil {
		return PURL{}, err
	}
	q := make(map[string]string, len(p.Qualifiers))
	for _, kv := range p.Qualifiers {
		q[kv.Key] = kv.Value
	}
	return PURL{
		Type:       strings.ToLower(p.Type),
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: q,
	}, nil
}

// Strip returns the SPURL (version-less PURL). For Linux types it embeds the
// canonical release as a distro=<distro>-<release> qualifier (so the key is
// release-aware and round-trips back to the same Release) and preserves arch.
// Qualifiers are sorted alphabetically so the storage key is stable.
//
// NOTE: "Linux type" here means the PURL `type` segment — deb, rpm, apk — i.e.
// the package-manager flavor. Distros (ubuntu, alpine, redhat, ...) live in
// the PURL namespace or distro= qualifier, not in the type. See `linuxByNamespace`
// for the supported distros per type.
func Strip(p PURL) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		b.WriteByte('/')
		b.WriteString(p.Namespace)
	}
	b.WriteByte('/')
	b.WriteString(p.Name)

	if isLinuxType(p.Type) {
		q := map[string]string{}
		if id := Decompose(p); id.Distro != "" && id.Release != "" {
			q["distro"] = id.Distro + "-" + id.Release
		}
		if arch := p.Qualifiers["arch"]; arch != "" {
			q["arch"] = arch
		}
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i == 0 {
				b.WriteByte('?')
			} else {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(q[k])
		}
	}
	return b.String()
}

func isLinuxType(t string) bool {
	switch t {
	case "deb", "rpm", "apk":
		return true
	}
	return false
}
