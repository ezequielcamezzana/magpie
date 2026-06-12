package match

import "testing"

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
			if got.Matched != c.wantMatched {
				t.Errorf("Matched = %v, want %v (%+v)", got.Matched, c.wantMatched, got)
			}
			if got.Reason != c.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, c.wantReason)
			}
		})
	}
}

func TestGoMatch_Prerelease(t *testing.T) {
	m := goMatcher{}
	// v1.2.0-rc1 < v1.2.0, so it falls inside [v1.0.0, v1.2.0).
	got := m.Match("v1.2.0-rc1", Evidence{AffectedRanges: []string{"[v1.0.0, v1.2.0)"}})
	if !got.Matched || got.Reason != ReasonInAffectedRange {
		t.Fatalf("expected prerelease inside range, got %+v", got)
	}
}

func TestGoMatch_Incompatible(t *testing.T) {
	m := goMatcher{}
	// +incompatible build metadata is stripped before comparison.
	got := m.Match("v2.0.0+incompatible", Evidence{AffectedVersions: []string{"v2.0.0"}})
	if !got.Matched || got.Reason != ReasonInAffectedList {
		t.Fatalf("expected +incompatible stripped to equal v2.0.0, got %+v", got)
	}
}

func TestGoMatch_AffectedAndNotAffectedRange(t *testing.T) {
	m := goMatcher{}

	if got := m.Match("v1.5.0", Evidence{AffectedRanges: []string{"[v1.0.0, v2.0.0)"}}); !got.Matched {
		t.Errorf("v1.5.0 should be inside [v1.0.0, v2.0.0), got %+v", got)
	}
	if got := m.Match("v2.5.0", Evidence{AffectedRanges: []string{"[v1.0.0, v2.0.0)"}}); got.Matched {
		t.Errorf("v2.5.0 should be outside [v1.0.0, v2.0.0), got %+v", got)
	}
}

func TestNormalizeGoIntervals(t *testing.T) {
	in := []Interval{
		{Lower: "*", Upper: "2018-07-12", UpperInc: true},
		{Lower: "0.0.0-20180601000000-abc", Upper: "0.0.0-20180816102801-aaf60122140d"},
	}
	out := NormalizeGoIntervals(in)

	if out[0].Upper != "0.0.0-20180712000000-000000000000" {
		t.Errorf("out[0].Upper = %q, want normalized date pseudo-version", out[0].Upper)
	}
	if out[1].Lower != "0.0.0-20180601000000-abc" {
		t.Errorf("out[1].Lower changed unexpectedly: %q", out[1].Lower)
	}
}
