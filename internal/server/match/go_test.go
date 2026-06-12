package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoMatch_PseudoVersionInRange(t *testing.T) {
	m := goMatcher{}

	cases := []struct {
		name        string
		version     string
		ranges      []string
		wantMatched bool
		wantReason  string
	}{
		{
			name:        "pseudo before NVD date bound is affected",
			version:     "0.0.0-20180601000000-abc123abc123",
			ranges:      []string{"(*, 2018-07-12]"},
			wantMatched: true,
			wantReason:  ReasonInAffectedRange,
		},
		{
			name:        "pseudo after NVD date bound is not affected",
			version:     "0.0.0-20210226172049-4d5f0f5c73e7",
			ranges:      []string{"(*, 2018-07-12]"},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedRange,
		},
		{
			name:        "tagged release above any pseudo-version bound",
			version:     "v0.5.0",
			ranges:      []string{"(*, 2018-07-12]"},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedRange,
		},
		{
			name:        "normal semver range still works",
			version:     "v0.5.0",
			ranges:      []string{"(*, v1.0.0]"},
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

func TestGoMatch_Prerelease(t *testing.T) {
	m := goMatcher{}
	// v1.2.0-rc1 < v1.2.0, so it falls inside [v1.0.0, v1.2.0).
	got := m.Match("v1.2.0-rc1", Evidence{AffectedRanges: []string{"[v1.0.0, v1.2.0)"}})
	require.True(t, got.Matched, "expected prerelease inside range, got %+v", got)
	require.Equal(t, ReasonInAffectedRange, got.Reason)
}

func TestGoMatch_Incompatible(t *testing.T) {
	m := goMatcher{}
	// +incompatible build metadata is stripped before comparison.
	got := m.Match("v2.0.0+incompatible", Evidence{AffectedVersions: []string{"v2.0.0"}})
	require.True(t, got.Matched, "expected +incompatible stripped to equal v2.0.0, got %+v", got)
	require.Equal(t, ReasonInAffectedList, got.Reason)
}

func TestGoMatch_AffectedAndNotAffectedRange(t *testing.T) {
	m := goMatcher{}

	got := m.Match("v1.5.0", Evidence{AffectedRanges: []string{"[v1.0.0, v2.0.0)"}})
	assert.True(t, got.Matched, "v1.5.0 should be inside [v1.0.0, v2.0.0), got %+v", got)

	got = m.Match("v2.5.0", Evidence{AffectedRanges: []string{"[v1.0.0, v2.0.0)"}})
	assert.False(t, got.Matched, "v2.5.0 should be outside [v1.0.0, v2.0.0), got %+v", got)
}

func TestNormalizeGoIntervals(t *testing.T) {
	in := []Interval{
		{Lower: "*", Upper: "2018-07-12", UpperInc: true},
		{Lower: "0.0.0-20180601000000-abc", Upper: "0.0.0-20180816102801-aaf60122140d"},
	}
	out := NormalizeGoIntervals(in)

	assert.Equal(t, "0.0.0-20180712000000-000000000000", out[0].Upper)
	assert.Equal(t, "0.0.0-20180601000000-abc", out[1].Lower)
}
