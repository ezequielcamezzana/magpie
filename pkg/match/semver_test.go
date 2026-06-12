package match

import "testing"

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
			if got.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v", got.Matched, tt.wantMatched)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestSemverMatch_RangeSet(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.2.0", Evidence{AffectedRanges: []string{"[1.0.0, 1.2.6)"}})
	if !got.Matched || got.Reason != ReasonInAffectedRange {
		t.Fatalf("got %+v", got)
	}
	if got.Range != "[1.0.0, 1.2.6)" {
		t.Errorf("Range = %q, want %q", got.Range, "[1.0.0, 1.2.6)")
	}
}

// Una versión ausente de la lista puede todavía matchear por rango: el paso 5
// (lista) y el 6 (rango) se evalúan ambos.
func TestSemverMatch_ListMissButRangeHit(t *testing.T) {
	m := semverMatcher{}
	ev := Evidence{
		AffectedVersions: []string{"3.3.3"},
		AffectedRanges:   []string{"[1.0.0, 2.0.0)"},
	}
	got := m.Match("1.5.0", ev)
	if !got.Matched || got.Reason != ReasonInAffectedRange {
		t.Fatalf("expected match via range, got %+v", got)
	}
}

func TestSemverMatch_NextFix(t *testing.T) {
	m := semverMatcher{}
	ev := Evidence{
		AffectedRanges: []string{"[1.0.0, 2.0.0)"},
		FixedVersions:  []string{"1.2.6", "2.0.0"},
	}
	got := m.Match("1.1.0", ev)
	if !got.Matched {
		t.Fatalf("expected match, got %+v", got)
	}
	if got.NextFix != "1.2.6" {
		t.Errorf("NextFix = %q, want %q", got.NextFix, "1.2.6")
	}
}

// Igualdad de lista es semver-parseada, no string crudo: "1.0.0+build" == "1.0.0".
func TestSemverMatch_BuildMetaEquality(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.0.0+build", Evidence{AffectedVersions: []string{"1.0.0"}})
	if !got.Matched || got.Reason != ReasonInAffectedList {
		t.Fatalf("expected build-meta-stripped equality, got %+v", got)
	}
}

func TestSemverMatch_InvalidBoundNoPanicNoMatch(t *testing.T) {
	m := semverMatcher{}
	got := m.Match("1.5.0", Evidence{AffectedRanges: []string{"[not-a-version, 2.0.0)"}})
	if got.Matched {
		t.Fatalf("invalid bound must not match, got %+v", got)
	}
	if got.Reason != ReasonNotInAffectedRange {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonNotInAffectedRange)
	}
}

func TestParseInterval(t *testing.T) {
	iv, ok := ParseInterval("[1.0.0, 1.2.6)")
	if !ok {
		t.Fatal("ParseInterval failed")
	}
	if !iv.LowerInc || iv.Lower != "1.0.0" {
		t.Errorf("lower = %+v, want inclusive 1.0.0", iv)
	}
	if iv.UpperInc || iv.Upper != "1.2.6" {
		t.Errorf("upper = %+v, want exclusive 1.2.6", iv)
	}

	iv2, ok := ParseInterval("(*, 0.2.4)")
	if !ok {
		t.Fatal("ParseInterval (*, 0.2.4) failed")
	}
	if iv2.LowerInc || iv2.Lower != "*" {
		t.Errorf("lower = %+v, want exclusive unbounded *", iv2)
	}
	if iv2.UpperInc || iv2.Upper != "0.2.4" {
		t.Errorf("upper = %+v, want exclusive 0.2.4", iv2)
	}
}
