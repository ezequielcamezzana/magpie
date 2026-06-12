package ecosystems

import (
	"testing"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

func TestRegistryName(t *testing.T) {
	tests := []struct {
		name string
		id   purl.Identity
		want string
	}{
		{
			name: "language type",
			id:   purl.Identity{Kind: purl.KindLanguage, Type: "npm"},
			want: "npmjs.org",
		},
		{
			name: "ubuntu noble",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "ubuntu", Release: "noble"},
			want: "ubuntu-24.04",
		},
		{
			name: "debian bookworm",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "debian", Release: "bookworm"},
			want: "debian-12",
		},
		{
			name: "alpine v3.19",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "alpine", Release: "v3.19"},
			want: "alpine-v3.19",
		},
		{
			name: "fedora has no release-scoped registry",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "fedora", Release: "fc40"},
			want: "",
		},
		{
			name: "rpm redhat",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "redhat", Release: "el9"},
			want: "",
		},
		{
			name: "ubuntu without release",
			id:   purl.Identity{Kind: purl.KindLinux, Distro: "ubuntu"},
			want: "",
		},
		{
			name: "conan",
			id:   purl.Identity{Kind: purl.KindLanguage, Type: "conan"},
			want: "conan.io",
		},
		{
			name: "unknown language type",
			id:   purl.Identity{Kind: purl.KindLanguage, Type: "elixir"},
			want: "",
		},
		{
			name: "other kind",
			id:   purl.Identity{Kind: purl.KindOther, Type: "generic"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registryName(tt.id); got != tt.want {
				t.Errorf("registryName(%+v) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
