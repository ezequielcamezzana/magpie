package purl

import "testing"

func TestParseBasic(t *testing.T) {
	p, err := Parse("pkg:npm/chalk@1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type != "npm" {
		t.Errorf("Type: want npm, got %q", p.Type)
	}
	if p.Name != "chalk" {
		t.Errorf("Name: want chalk, got %q", p.Name)
	}
	if p.Version != "1.0.0" {
		t.Errorf("Version: want 1.0.0, got %q", p.Version)
	}
	if p.Namespace != "" {
		t.Errorf("Namespace: want empty, got %q", p.Namespace)
	}
}

func TestParseNamespaced(t *testing.T) {
	p, err := Parse("pkg:npm/@scope/foo@1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Namespace != "@scope" {
		t.Errorf("Namespace: want @scope, got %q", p.Namespace)
	}
	if p.Name != "foo" {
		t.Errorf("Name: want foo, got %q", p.Name)
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse("not-a-purl"); err == nil {
		t.Fatal("expected error parsing invalid PURL")
	}
}

func TestParseQualifiers(t *testing.T) {
	p, err := Parse("pkg:deb/ubuntu/curl@7.81.0?distro=noble&arch=amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Qualifiers["distro"] != "noble" {
		t.Errorf("Qualifier distro: want noble, got %q", p.Qualifiers["distro"])
	}
	if p.Qualifiers["arch"] != "amd64" {
		t.Errorf("Qualifier arch: want amd64, got %q", p.Qualifiers["arch"])
	}
}

func TestStripLanguage(t *testing.T) {
	p, _ := Parse("pkg:npm/chalk@1.0.0")
	if got, want := Strip(p), "pkg:npm/chalk"; got != want {
		t.Errorf("Strip npm: got %q, want %q", got, want)
	}
}

func TestStripNamespaced(t *testing.T) {
	p, _ := Parse("pkg:npm/@scope/foo@1.2.3")
	if got, want := Strip(p), "pkg:npm/@scope/foo"; got != want {
		t.Errorf("Strip namespaced: got %q, want %q", got, want)
	}
}

func TestStripGitHub(t *testing.T) {
	p, _ := Parse("pkg:github/octocat/hello-world@v1")
	if got, want := Strip(p), "pkg:github/octocat/hello-world"; got != want {
		t.Errorf("Strip github: got %q, want %q", got, want)
	}
}

func TestStripLinuxCanonicalDistroFromQualifier(t *testing.T) {
	p, _ := Parse("pkg:deb/ubuntu/curl@7.81.0?distro=noble&arch=amd64")
	if got, want := Strip(p), "pkg:deb/ubuntu/curl?arch=amd64&distro=ubuntu-noble"; got != want {
		t.Errorf("Strip linux: got %q, want %q", got, want)
	}
}

func TestStripLinuxCanonicalDistroFromVersion(t *testing.T) {
	p, _ := Parse("pkg:deb/debian/curl@7.88.1-10+deb12u5")
	if got, want := Strip(p), "pkg:deb/debian/curl?distro=debian-bookworm"; got != want {
		t.Errorf("Strip linux from version: got %q, want %q", got, want)
	}
}

func TestStripLinuxAlpineCanonicalDistro(t *testing.T) {
	p, _ := Parse("pkg:apk/alpine/curl@8.5.0?distro=v3.19")
	if got, want := Strip(p), "pkg:apk/alpine/curl?distro=alpine-v3.19"; got != want {
		t.Errorf("Strip alpine: got %q, want %q", got, want)
	}
}

func TestStripLinuxNoRelease(t *testing.T) {
	p, _ := Parse("pkg:deb/debian/openssl@1.1.1")
	if got, want := Strip(p), "pkg:deb/debian/openssl"; got != want {
		t.Errorf("Strip linux no release: got %q, want %q", got, want)
	}
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
		if err != nil {
			t.Fatalf("Parse(%q): %v", c, err)
		}
		stripped, err := Parse(Strip(orig))
		if err != nil {
			t.Fatalf("Parse(Strip(%q)) = %q: %v", c, Strip(orig), err)
		}
		want := Decompose(orig).Release
		if want == "" {
			t.Fatalf("test case %q has no release", c)
		}
		if got := Decompose(stripped).Release; got != want {
			t.Errorf("round-trip %q: Release got %q, want %q", c, got, want)
		}
	}
}
