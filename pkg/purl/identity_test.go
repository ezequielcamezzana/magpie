package purl

import "testing"

func mustParse(t *testing.T, s string) PURL {
	t.Helper()
	p, err := Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

// --- DD §2 ecosystem table: one case per row. ---

func TestDecomposeNpm(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	if id.Kind != KindLanguage {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Ecosystem != "npm" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "chalk" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeNpmScoped(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/@babel/core@7.0.0"))
	if id.Ecosystem != "npm" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "@babel/core" {
		t.Errorf("Name: want @babel/core, got %q", id.Name)
	}
}

func TestDecomposePyPI(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:pypi/requests@2.31.0"))
	if id.Ecosystem != "PyPI" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "requests" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeGolang(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:golang/github.com%2Ffoo/bar@v1.0.0"))
	if id.Ecosystem != "Go" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "github.com/foo/bar" {
		t.Errorf("Name: want github.com/foo/bar, got %q", id.Name)
	}
}

func TestDecomposeCargo(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:cargo/serde@1.0"))
	if id.Ecosystem != "crates.io" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "serde" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeGem(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:gem/rails@7.0.0"))
	if id.Ecosystem != "RubyGems" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "rails" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeMaven(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"))
	if id.Ecosystem != "Maven" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("Name: want org.apache.logging.log4j:log4j-core, got %q", id.Name)
	}
}

func TestDecomposeNuget(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:nuget/Newtonsoft.Json@13.0.1"))
	if id.Ecosystem != "NuGet" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "Newtonsoft.Json" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeComposer(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:composer/symfony/console@5.4.0"))
	if id.Ecosystem != "Packagist" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "symfony/console" {
		t.Errorf("Name: want symfony/console, got %q", id.Name)
	}
}

func TestDecomposeConan(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:conan/zlib@1.3"))
	if id.Kind != KindLanguage {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Ecosystem != "ConanCenter" {
		t.Errorf("Ecosystem: got %q", id.Ecosystem)
	}
	if id.Name != "zlib" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeDebUbuntu(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0?distro=noble"))
	if id.Kind != KindLinux {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Distro != "ubuntu" {
		t.Errorf("Distro: got %q", id.Distro)
	}
	if id.Release != "noble" {
		t.Errorf("Release: got %q", id.Release)
	}
	if id.Name != "curl" {
		t.Errorf("Name: got %q", id.Name)
	}
}

func TestDecomposeDebDebian(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/openssl@1.1.1?distro=bookworm"))
	if id.Kind != KindLinux {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Distro != "debian" {
		t.Errorf("Distro: got %q", id.Distro)
	}
	if id.Release != "bookworm" {
		t.Errorf("Release: got %q", id.Release)
	}
}

func TestDecomposeRpmRedhat(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/redhat/openssl@1.1.1?distro=rhel-9"))
	if id.Kind != KindLinux {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Distro != "redhat" {
		t.Errorf("Distro: got %q", id.Distro)
	}
}

func TestDecomposeApkAlpine(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:apk/alpine/musl@1.2.3?distro=alpine-3.18"))
	if id.Kind != KindLinux {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.Distro != "alpine" {
		t.Errorf("Distro: got %q", id.Distro)
	}
	if id.Release != "v3.18" {
		t.Errorf("Release: want v3.18, got %q", id.Release)
	}
}

// --- Release derived from version (no qualifier) ---

func TestDecomposeReleaseFromVersionDebian(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10+deb12u5"))
	if id.Release != "bookworm" {
		t.Errorf("Release: want bookworm, got %q", id.Release)
	}
}

func TestDecomposeReleaseFromVersionBackport(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10~bpo11+1"))
	if id.Release != "bullseye" {
		t.Errorf("Release: want bullseye, got %q", id.Release)
	}
}

func TestDecomposeReleaseFromVersionEL(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))
	if id.Release != "el8" {
		t.Errorf("Release: want el8, got %q", id.Release)
	}
}

func TestDecomposeReleaseFromVersionFedora(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:rpm/fedora/openssl@3.0.5-1.fc38"))
	if id.Release != "fc38" {
		t.Errorf("Release: want fc38, got %q", id.Release)
	}
}

func TestDecomposeReleaseFromVersionAmbiguous(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.4"))
	if id.Release != "" {
		t.Errorf("Release: want empty for ambiguous version, got %q", id.Release)
	}
}

func TestDecomposeQualifierBeatsVersion(t *testing.T) {
	// distro= qualifier should win over the version-derived release.
	id := Decompose(mustParse(t, "pkg:deb/debian/curl@7.88.1-10+deb12u5?distro=bullseye"))
	if id.Release != "bullseye" {
		t.Errorf("Release: want bullseye (qualifier), got %q", id.Release)
	}
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
		if got := releaseFromVersion(c.version); got != c.want {
			t.Errorf("releaseFromVersion(%q): got %q, want %q", c.version, got, c.want)
		}
	}
}

// --- Kind classification ---

func TestDecomposeKindGitHub(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:github/Octocat/Hello-World@v1.0"))
	if id.Kind != KindGitHub {
		t.Errorf("Kind: got %v", id.Kind)
	}
	if id.RepoURL != "https://github.com/octocat/hello-world" {
		t.Errorf("RepoURL: got %q", id.RepoURL)
	}
}

func TestDecomposeKindOther(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:bitnami/postgres@14"))
	if id.Kind != KindOther {
		t.Errorf("Kind: got %v", id.Kind)
	}
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
		if got := id.TargetSW(); got != c.want {
			t.Errorf("%s: TargetSW got %q, want %q", c.purl, got, c.want)
		}
	}
}

// --- OSVQuery per Kind ---

func TestOSVQueryLanguage(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	q := id.OSVQuery()
	if q.Kind != KindLanguage {
		t.Errorf("Kind: got %v", q.Kind)
	}
	if q.Ecosystem != "npm" {
		t.Errorf("Ecosystem: got %q", q.Ecosystem)
	}
	if q.Name != "chalk" {
		t.Errorf("Name: got %q", q.Name)
	}
	if q.RepoURL != "" || q.ReleaseToken != "" {
		t.Errorf("expected empty RepoURL/ReleaseToken, got %+v", q)
	}
}

func TestOSVQueryLinuxUbuntu(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl@7.81.0?distro=noble"))
	q := id.OSVQuery()
	if q.Kind != KindLinux {
		t.Errorf("Kind: got %v", q.Kind)
	}
	if q.Ecosystem != "Ubuntu:24.04" {
		t.Errorf("Ecosystem: want Ubuntu:24.04, got %q", q.Ecosystem)
	}
	if q.BaseEcosystem != "Ubuntu" {
		t.Errorf("BaseEcosystem: want Ubuntu, got %q", q.BaseEcosystem)
	}
	if q.Name != "curl" {
		t.Errorf("Name: got %q", q.Name)
	}
	if q.ReleaseToken != "24.04" {
		t.Errorf("ReleaseToken: want 24.04, got %q", q.ReleaseToken)
	}
}

func TestOSVQueryLinuxAlpine(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:apk/alpine/musl@1.2.3?distro=alpine-3.18"))
	q := id.OSVQuery()
	if q.Ecosystem != "Alpine:v3.18" {
		t.Errorf("Ecosystem: want Alpine:v3.18, got %q", q.Ecosystem)
	}
	if q.ReleaseToken != "3.18" {
		t.Errorf("ReleaseToken: want 3.18, got %q", q.ReleaseToken)
	}
}

func TestOSVQueryGitHubStub(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:github/octocat/hello-world@v1"))
	q := id.OSVQuery()
	if q.Kind != KindGitHub {
		t.Errorf("Kind: got %v", q.Kind)
	}
	if q.RepoURL != "https://github.com/octocat/hello-world" {
		t.Errorf("RepoURL: got %q", q.RepoURL)
	}
	if q.Ecosystem != "" || q.Name != "" || q.ReleaseToken != "" {
		t.Errorf("expected stub with only Kind+RepoURL, got %+v", q)
	}
}

func TestIdentityReleaseToken(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:deb/ubuntu/curl?distro=ubuntu-24.04"))
	if got := id.ReleaseToken(); got != "24.04" {
		t.Errorf("ReleaseToken: want 24.04, got %q", got)
	}
}

func TestOSVQueryLanguageBaseEcosystem(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:npm/chalk@1.0.0"))
	q := id.OSVQuery()
	if q.BaseEcosystem != "npm" {
		t.Errorf("BaseEcosystem: want npm, got %q", q.BaseEcosystem)
	}
}

func TestOSVQueryOther(t *testing.T) {
	id := Decompose(mustParse(t, "pkg:bitnami/postgres@14"))
	q := id.OSVQuery()
	if q.Kind != KindOther {
		t.Errorf("Kind: got %v", q.Kind)
	}
	if q.Ecosystem != "" || q.Name != "" || q.RepoURL != "" || q.ReleaseToken != "" {
		t.Errorf("expected empty OSVQuery, got %+v", q)
	}
}
