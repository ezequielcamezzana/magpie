package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBasic(t *testing.T) {
	p, err := Parse("pkg:npm/chalk@1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "npm", p.Type)
	assert.Equal(t, "chalk", p.Name)
	assert.Equal(t, "1.0.0", p.Version)
	assert.Empty(t, p.Namespace)
}

func TestParseNamespaced(t *testing.T) {
	p, err := Parse("pkg:npm/@scope/foo@1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "@scope", p.Namespace)
	assert.Equal(t, "foo", p.Name)
}

func TestParseInvalid(t *testing.T) {
	_, err := Parse("not-a-purl")
	require.Error(t, err)
}

func TestParseQualifiers(t *testing.T) {
	p, err := Parse("pkg:deb/ubuntu/curl@7.81.0?distro=noble&arch=amd64")
	require.NoError(t, err)
	assert.Equal(t, "noble", p.Qualifiers["distro"])
	assert.Equal(t, "amd64", p.Qualifiers["arch"])
}

func TestStripLanguage(t *testing.T) {
	p, _ := Parse("pkg:npm/chalk@1.0.0")
	assert.Equal(t, "pkg:npm/chalk", Strip(p))
}

func TestStripNamespaced(t *testing.T) {
	p, _ := Parse("pkg:npm/@scope/foo@1.2.3")
	assert.Equal(t, "pkg:npm/@scope/foo", Strip(p))
}

// TestStripFoldsCase: case-insensitive ecosystems fold the key so casing
// variants don't duplicate; case-sensitive types keep their case.
func TestStripFoldsCase(t *testing.T) {
	folded := map[string]string{
		"pkg:cargo/Deno@1.0.0":        "pkg:cargo/deno",
		"pkg:cargo/deno@2.0.0":        "pkg:cargo/deno",
		"pkg:npm/React@18":            "pkg:npm/react",
		"pkg:pypi/Django@5":           "pkg:pypi/django",
		"pkg:github/OctoCat/Hello@v1": "pkg:github/octocat/hello",
	}
	for in, want := range folded {
		p, err := Parse(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, Strip(p), in)
	}

	// maven is case-sensitive and not in the allowlist: Strip must preserve it.
	p, err := Parse("pkg:maven/com.Example/MyLib@1")
	require.NoError(t, err)
	assert.Equal(t, "pkg:maven/com.Example/MyLib", Strip(p))
}

func TestStripGitHub(t *testing.T) {
	p, _ := Parse("pkg:github/octocat/hello-world@v1")
	assert.Equal(t, "pkg:github/octocat/hello-world", Strip(p))
}

func TestStripLinuxCanonicalDistroFromQualifier(t *testing.T) {
	p, _ := Parse("pkg:deb/ubuntu/curl@7.81.0?distro=noble&arch=amd64")
	assert.Equal(t, "pkg:deb/ubuntu/curl?arch=amd64&distro=ubuntu-noble", Strip(p))
}

func TestStripLinuxCanonicalDistroFromVersion(t *testing.T) {
	p, _ := Parse("pkg:deb/debian/curl@7.88.1-10+deb12u5")
	assert.Equal(t, "pkg:deb/debian/curl?distro=debian-bookworm", Strip(p))
}

func TestStripLinuxAlpineCanonicalDistro(t *testing.T) {
	p, _ := Parse("pkg:apk/alpine/curl@8.5.0?distro=v3.19")
	assert.Equal(t, "pkg:apk/alpine/curl?distro=alpine-v3.19", Strip(p))
}

func TestStripLinuxNoRelease(t *testing.T) {
	p, _ := Parse("pkg:deb/debian/openssl@1.1.1")
	assert.Equal(t, "pkg:deb/debian/openssl", Strip(p))
}

func TestStripLinuxRoundTrip(t *testing.T) {
	cases := []string{
		"pkg:deb/debian/curl@7.88.1-10+deb12u5",
		"pkg:deb/ubuntu/curl@7.81.0?distro=noble&arch=amd64",
		"pkg:deb/ubuntu/curl@7.81.0?distro=ubuntu-22.04",
		"pkg:apk/alpine/curl@8.5.0?distro=v3.19",
		"pkg:apk/alpine/curl@8.5.0?distro=alpine-3.19",
	}
	for _, c := range cases {
		orig, err := Parse(c)
		require.NoError(t, err, "Parse(%q)", c)
		stripped, err := Parse(Strip(orig))
		require.NoError(t, err, "Parse(Strip(%q)) = %q", c, Strip(orig))
		want := Decompose(orig).Release
		require.NotEmpty(t, want, "test case %q has no release", c)
		assert.Equal(t, want, Decompose(stripped).Release, "round-trip %q", c)
	}
}
