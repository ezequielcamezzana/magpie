package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDpkgCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:2.3-4", "2.3-4", 1}, // epoch wins
		{"2.3-4", "2.3-5", -1},  // debian revision order
		{"2.3", "2.3-1", -1},    // missing revision == "0" < "1"
		{"1.0~rc1", "1.0", -1},  // tilde sorts before everything
		{"1.0", "1.0", 0},       // equal
		{"2.3-5", "2.3-4", 1},   // revision order (reverse)
		{"1.0.2k", "1.0.2j", 1}, // letter suffix ordering
	}
	for _, c := range cases {
		assert.Equal(t, c.want, dpkgCompare(c.a, c.b), "dpkgCompare(%q, %q)", c.a, c.b)
	}
}

func TestDpkgMatch_RangeMembership(t *testing.T) {
	m := dpkgMatcher{}

	cases := []struct {
		name        string
		version     string
		ranges      []string
		wantMatched bool
		wantReason  string
	}{
		{
			name:        "deb version inside interval",
			version:     "1.5-2",
			ranges:      []string{"[1.0, 2.0)"},
			wantMatched: true,
			wantReason:  ReasonInAffectedRange,
		},
		{
			name:        "deb version above interval",
			version:     "2.5-1",
			ranges:      []string{"[1.0, 2.0)"},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedRange,
		},
		{
			name:        "tilde prerelease below lower bound is excluded",
			version:     "1.0~rc1",
			ranges:      []string{"[1.0, 2.0)"},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedRange,
		},
		{
			name:        "epoch version inside interval",
			version:     "1:1.5-2",
			ranges:      []string{"[1:1.0, 1:2.0)"},
			wantMatched: true,
			wantReason:  ReasonInAffectedRange,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.Match(c.version, Evidence{AffectedRanges: c.ranges})
			assert.Equal(t, c.wantMatched, got.Matched)
			assert.Equal(t, c.wantReason, got.Reason)
		})
	}
}

func TestDpkgMatch_ListEquality(t *testing.T) {
	m := dpkgMatcher{}
	got := m.Match("2.3-4", Evidence{AffectedVersions: []string{"2.3-4"}})
	require.True(t, got.Matched, "expected dpkg list equality, got %+v", got)
	require.Equal(t, ReasonInAffectedList, got.Reason)
}

func TestDpkgMatch_NextFix(t *testing.T) {
	m := dpkgMatcher{}
	ev := Evidence{
		AffectedRanges: []string{"[1.0, 2.0)"},
		FixedVersions:  []string{"2.0", "1.5-1"},
	}
	got := m.Match("1.2", ev)
	require.True(t, got.Matched, "expected match, got %+v", got)
	assert.Equal(t, "1.5-1", got.NextFix)
}
