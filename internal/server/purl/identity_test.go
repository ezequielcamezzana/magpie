package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, s string) PURL {
	t.Helper()
	p, err := Parse(s)
	require.NoError(t, err, "parse %q", s)
	return p
}

// --- DD §2 ecosystem table: one case per row. ---

func TestDecomposeNpm(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	assert.Equal(t, KindLanguage, id.Kind)
	assert.Equal(t, "npm", id.Ecosystem)
	assert.Equal(t, "chalk", id.Name)
}

func TestDecomposeNpmScoped(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/@babel/core@7.0.0"))
	assert.Equal(t, "npm", id.Ecosystem)
	assert.Equal(t, "@babel/core", id.Name)
}

func TestDecomposePyPI(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:pypi/requests@2.31.0"))
	assert.Equal(t, "PyPI", id.Ecosystem)
	assert.Equal(t, "requests", id.Name)
}

func TestDecomposeGolang(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:golang/github.com%2Ffoo/bar@v1.0.0"))
	assert.Equal(t, "Go", id.Ecosystem)
	assert.Equal(t, "github.com/foo/bar", id.Name)
}

func TestDecomposeCargo(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:cargo/serde@1.0"))
	assert.Equal(t, "crates.io", id.Ecosystem)
	assert.Equal(t, "serde", id.Name)
}

func TestDecomposeGem(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:gem/rails@7.0.0"))
	assert.Equal(t, "RubyGems", id.Ecosystem)
	assert.Equal(t, "rails", id.Name)
}

func TestDecomposeMaven(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"))
	assert.Equal(t, "Maven", id.Ecosystem)
	assert.Equal(t, "org.apache.logging.log4j:log4j-core", id.Name)
}

func TestDecomposeNuget(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:nuget/Newtonsoft.Json@13.0.1"))
	assert.Equal(t, "NuGet", id.Ecosystem)
	assert.Equal(t, "Newtonsoft.Json", id.Name)
}

func TestDecomposeComposer(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:composer/symfony/console@5.4.0"))
	assert.Equal(t, "Packagist", id.Ecosystem)
	assert.Equal(t, "symfony/console", id.Name)
}

func TestDecomposeConan(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:conan/zlib@1.3"))
	assert.Equal(t, KindLanguage, id.Kind)
	assert.Equal(t, "ConanCenter", id.Ecosystem)
	assert.Equal(t, "zlib", id.Name)
}

func TestDecomposeDebUbuntu(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0?distro=noble"))
	assert.Equal(t, KindLinux, id.Kind)
	assert.Equal(t, "ubuntu", id.Distro)
	assert.Equal(t, "noble", id.Release)
	assert.Equal(t, "curl", id.Name)
}

func TestDecomposeDebDebian(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/openssl@1.1.1?distro=bookworm"))
	assert.Equal(t, KindLinux, id.Kind)
	assert.Equal(t, "debian", id.Distro)
	assert.Equal(t, "bookworm", id.Release)
}

func TestDecomposeRpmRedhat(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/redhat/openssl@1.1.1?distro=rhel-9"))
	assert.Equal(t, KindLinux, id.Kind)
	assert.Equal(t, "redhat", id.Distro)
}

func TestDecomposeApkAlpine(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:apk/alpine/musl@1.2.3?distro=alpine-3.18"))
	assert.Equal(t, KindLinux, id.Kind)
	assert.Equal(t, "alpine", id.Distro)
	assert.Equal(t, "v3.18", id.Release)
}

// --- Release derived from version (no qualifier) ---

func TestDecomposeReleaseFromVersionDebian(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10+deb12u5"))
	assert.Equal(t, "bookworm", id.Release)
}

func TestDecomposeReleaseFromVersionBackport(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10~bpo11+1"))
	assert.Equal(t, "bullseye", id.Release)
}

func TestDecomposeReleaseFromVersionEL(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))
	assert.Equal(t, "el8", id.Release)
}

func TestDecomposeReleaseFromVersionFedora(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/fedora/openssl@3.0.5-1.fc38"))
	assert.Equal(t, "fc38", id.Release)
}

func TestDecomposeReleaseFromVersionAmbiguous(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.4"))
	assert.Empty(t, id.Release, "ambiguous version must not derive a release")
}

func TestDecomposeQualifierBeatsVersion(t *testing.T) {
	// distro= qualifier should win over the version-derived release.
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10+deb12u5?distro=bullseye"))
	assert.Equal(t, "bullseye", id.Release)
}

func TestReleaseFromVersion(t *testing.T) {
	cases := []struct {
		version string
		want    string
	}{
		{"7.88.1-10+deb12u5", "deb12"},
		{"7.88.1-10~bpo11+1", "deb11"},
		{"1.1.1k-7.el8_6", "el8"},
		{"3.0.5-1.fc38", "fc38"},
		{"7.81.0-1ubuntu1.4", ""},
		{"7.81.0-1", ""},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, releaseFromVersion(c.version), "releaseFromVersion(%q)", c.version)
	}
}

// --- Kind classification ---

func TestDecomposeKindGitHub(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:github/Octocat/Hello-World@v1.0"))
	assert.Equal(t, KindGitHub, id.Kind)
	assert.Equal(t, "https://github.com/octocat/hello-world", id.RepoURL)
}

func TestDecomposeKindOther(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:bitnami/postgres@14"))
	assert.Equal(t, KindOther, id.Kind)
}

// --- TargetSW ---

func TestTargetSW(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:npm/chalk@1.0", "node.js"},
		{"pkg:pypi/requests@2", "python"},
		{"pkg:gem/rails@7", "ruby"},
		{"pkg:cargo/serde@1", "rust"},
		{"pkg:composer/symfony/console@5", "php"},
		{"pkg:nuget/Newtonsoft.Json@13", ".net"},
		{"pkg:maven/g/a@1", ""},
		{"pkg:deb/ubuntu/curl@7", ""},
		{"pkg:github/x/y@v1", ""},
	}
	for _, c := range cases {
		id := Decompose(mustParse(t, c.purl))
		assert.Equal(t, c.want, id.TargetSW(), "%s", c.purl)
	}
}

// --- OSVQuery per Kind ---

func TestOSVQueryLanguage(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	q := id.OSVQuery()
	assert.Equal(t, KindLanguage, q.Kind)
	assert.Equal(t, "npm", q.Ecosystem)
	assert.Equal(t, "chalk", q.Name)
	assert.Empty(t, q.RepoURL)
	assert.Empty(t, q.ReleaseToken)
}

func TestOSVQueryLinuxUbuntu(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0?distro=noble"))
	q := id.OSVQuery()
	assert.Equal(t, KindLinux, q.Kind)
	assert.Equal(t, "Ubuntu:24.04", q.Ecosystem)
	assert.Equal(t, "Ubuntu", q.BaseEcosystem)
	assert.Equal(t, "curl", q.Name)
	assert.Equal(t, "24.04", q.ReleaseToken)
}

func TestOSVQueryLinuxAlpine(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:apk/alpine/musl@1.2.3?distro=alpine-3.18"))
	q := id.OSVQuery()
	assert.Equal(t, "Alpine:v3.18", q.Ecosystem)
	assert.Equal(t, "3.18", q.ReleaseToken)
}

func TestOSVQueryGitHubStub(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:github/octocat/hello-world@v1"))
	q := id.OSVQuery()
	assert.Equal(t, KindGitHub, q.Kind)
	assert.Equal(t, "https://github.com/octocat/hello-world", q.RepoURL)
	assert.Empty(t, q.Ecosystem, "stub must carry only Kind+RepoURL")
	assert.Empty(t, q.Name, "stub must carry only Kind+RepoURL")
	assert.Empty(t, q.ReleaseToken, "stub must carry only Kind+RepoURL")
}

func TestIdentityReleaseToken(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl?distro=ubuntu-24.04"))
	assert.Equal(t, "24.04", id.ReleaseToken())
}

func TestOSVQueryLanguageBaseEcosystem(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	q := id.OSVQuery()
	assert.Equal(t, "npm", q.BaseEcosystem)
}

func TestOSVQueryOther(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:bitnami/postgres@14"))
	q := id.OSVQuery()
	assert.Equal(t, KindOther, q.Kind)
	assert.Empty(t, q.Ecosystem)
	assert.Empty(t, q.Name)
	assert.Empty(t, q.RepoURL)
	assert.Empty(t, q.ReleaseToken)
}
