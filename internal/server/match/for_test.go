package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFor_Selector(t *testing.T) {
	cases := []struct {
		source    string
		ecosystem string
		want      string // type name we expect
	}{
		{"nvd", "go", "match.semverMatcher"}, // nvd always semver
		{"nvd", "Debian:12", "match.semverMatcher"},
		{"osv", "Go", "match.goMatcher"},
		{"osv", "golang", "match.goMatcher"},
		{"osv", "deb", "match.dpkgMatcher"},
		{"osv", "rpm", "match.dpkgMatcher"},
		{"osv", "Debian:12", "match.dpkgMatcher"},
		{"osv", "Ubuntu:24.04", "match.dpkgMatcher"},
		{"osv", "Red Hat", "match.dpkgMatcher"},
		{"osv", "npm", "match.semverMatcher"},
		{"osv", "PyPI", "match.semverMatcher"},
		{"osv", "", "match.semverMatcher"},
	}
	for _, c := range cases {
		got := matcherTypeName(For(c.source, c.ecosystem))
		assert.Equal(t, c.want, got, "For(%q, %q)", c.source, c.ecosystem)
	}
}

func matcherTypeName(m Matcher) string {
	switch m.(type) {
	case semverMatcher:
		return "match.semverMatcher"
	case goMatcher:
		return "match.goMatcher"
	case dpkgMatcher:
		return "match.dpkgMatcher"
	default:
		return "unknown"
	}
}
