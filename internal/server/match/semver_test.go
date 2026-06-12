package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemverMatch_ReasonCodes(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		ev          Evidence
		wantMatched bool
		wantReason  string
	}{
		{
			name:        "no_version_specified",
			version:     "",
			ev:          Evidence{AffectedRanges: []string{"[1.0.0, 2.0.0)"}},
			wantMatched: true,
			wantReason:  ReasonNoVersionSpecified,
		},
		{
			name:        "unsupported_version_scheme",
			version:     "not-a-version",
			ev:          Evidence{AffectedRanges: []string{"[1.0.0, 2.0.0)"}},
			wantMatched: false,
			wantReason:  ReasonUnsupportedVersionScheme,
		},
		{
			name:        "in_unaffected_list",
			version:     "1.5.0",
			ev:          Evidence{UnaffectedVersions: []string{"1.5.0"}, AffectedRanges: []string{"[1.0.0, 2.0.0)"}},
			wantMatched: false,
			wantReason:  ReasonInUnaffectedList,
		},
		{
			name:        "in_fixed_list",
			version:     "2.0.0",
			ev:          Evidence{FixedVersions: []string{"2.0.0"}, AffectedRanges: []string{"[1.0.0, 3.0.0)"}},
			wantMatched: false,
			wantReason:  ReasonInFixedList,
		},
		{
			name:        "in_affected_list",
			version:     "1.5.0",
			ev:          Evidence{AffectedVersions: []string{"1.5.0"}},
			wantMatched: true,
			wantReason:  ReasonInAffectedList,
		},
		{
			name:        "not_in_affected_list",
			version:     "9.9.9",
			ev:          Evidence{AffectedVersions: []string{"1.5.0"}},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedList,
		},
		{
			name:        "in_affected_range",
			version:     "1.2.0",
			ev:          Evidence{AffectedRanges: []string{"[1.0.0, 1.2.6)"}},
			wantMatched: true,
			wantReason:  ReasonInAffectedRange,
		},
		{
			name:        "not_in_affected_range",
			version:     "5.0.0",
			ev:          Evidence{AffectedRanges: []string{"[1.0.0, 1.2.6)"}},
			wantMatched: false,
			wantReason:  ReasonNotInAffectedRange,
		},
		{
			name:        "no_evidence",
			version:     "1.0.0",
			ev:          Evidence{},
			wantMatched: false,
			wantReason:  ReasonNoEvidence,
		},
	}

	m := For("osv", "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Match(tt.version, tt.ev)
			assert.Equal(t, tt.wantMatched, got.Matched)
			assert.Equal(t, tt.wantReason, got.Reason)
		})
	}
}

func TestSemverMatch_RangeSet(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.2.0", Evidence{AffectedRanges: []string{"[1.0.0, 1.2.6)"}})
	require.True(t, got.Matched)
	require.Equal(t, ReasonInAffectedRange, got.Reason)
	assert.Equal(t, "[1.0.0, 1.2.6)", got.Range)
}

// A version absent from the list can still match by range: step 5 (list) and
// step 6 (range) are both evaluated.
func TestSemverMatch_ListMissButRangeHit(t *testing.T) {
	m := semverMatcher{}
	ev := Evidence{
		AffectedVersions: []string{"3.3.3"},
		AffectedRanges:   []string{"[1.0.0, 2.0.0)"},
	}
	got := m.Match("1.5.0", ev)
	require.True(t, got.Matched, "expected match via range, got %+v", got)
	require.Equal(t, ReasonInAffectedRange, got.Reason)
}

func TestSemverMatch_NextFix(t *testing.T) {
	m := semverMatcher{}
	ev := Evidence{
		AffectedRanges: []string{"[1.0.0, 2.0.0)"},
		FixedVersions:  []string{"1.2.6", "2.0.0"},
	}
	got := m.Match("1.1.0", ev)
	require.True(t, got.Matched, "expected match, got %+v", got)
	assert.Equal(t, "1.2.6", got.NextFix)
}

// List equality is semver-parsed, not raw string: "1.0.0+build" == "1.0.0".
func TestSemverMatch_BuildMetaEquality(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.0.0+build", Evidence{AffectedVersions: []string{"1.0.0"}})
	require.True(t, got.Matched, "expected build-meta-stripped equality, got %+v", got)
	require.Equal(t, ReasonInAffectedList, got.Reason)
}

func TestSemverMatch_InvalidBoundNoPanicNoMatch(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.5.0", Evidence{AffectedRanges: []string{"[not-a-version, 2.0.0)"}})
	require.False(t, got.Matched, "invalid bound must not match, got %+v", got)
	assert.Equal(t, ReasonNotInAffectedRange, got.Reason)
}

func TestParseInterval(t *testing.T) {
	iv, ok := ParseInterval("[1.0.0, 1.2.6)")
	require.True(t, ok, "ParseInterval failed")
	assert.True(t, iv.LowerInc)
	assert.Equal(t, "1.0.0", iv.Lower)
	assert.False(t, iv.UpperInc)
	assert.Equal(t, "1.2.6", iv.Upper)

	iv2, ok := ParseInterval("(*, 0.2.4)")
	require.True(t, ok, "ParseInterval (*, 0.2.4) failed")
	assert.False(t, iv2.LowerInc)
	assert.Equal(t, "*", iv2.Lower)
	assert.False(t, iv2.UpperInc)
	assert.Equal(t, "0.2.4", iv2.Upper)
}
