package magpie

import (
	"reflect"
	"testing"
)

func TestPickNewestCVE(t *testing.T) {
	tests := []struct {
		name string
		ids  []string
		want string
	}{
		{"distinct years, newest wins", []string{"CVE-2009-9999", "CVE-2023-0001", "CVE-2015-5"}, "CVE-2023-0001"},
		{"same year, higher number wins", []string{"CVE-2020-100", "CVE-2020-9999"}, "CVE-2020-9999"},
		{"no cves", []string{"GHSA-xxxx", "PYSEC-2020-1", "MAL-2024-1"}, ""},
		{"empty", nil, ""},
		{"integer compare not lexicographic", []string{"CVE-2020-9999", "CVE-2020-10000"}, "CVE-2020-10000"},
		{"single cve", []string{"GHSA-x", "CVE-2021-42"}, "CVE-2021-42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pickNewestCVE(tt.ids); got != tt.want {
				t.Errorf("pickNewestCVE(%v) = %q, want %q", tt.ids, got, tt.want)
			}
		})
	}
}

func TestGroupCanonicalFromAliases(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}},
	}
	groups := Group(recs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].CanonicalID != "CVE-2020-1" {
		t.Errorf("canonical = %q, want CVE-2020-1", groups[0].CanonicalID)
	}
}

func TestGroupCanonicalNoCVE(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "MAL-2024-1", Aliases: []string{"GHSA-y"}},
	}
	groups := Group(recs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].CanonicalID != "MAL-2024-1" {
		t.Errorf("canonical = %q, want MAL-2024-1", groups[0].CanonicalID)
	}
}

func TestGroupSharedCVEMerges(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}},
		{Source: SourceNVD, OriginalID: "CVE-2020-1"},
	}
	groups := Group(recs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].CanonicalID != "CVE-2020-1" {
		t.Errorf("canonical = %q, want CVE-2020-1", groups[0].CanonicalID)
	}
	if len(groups[0].Records) != 2 {
		t.Errorf("expected 2 records, got %d", len(groups[0].Records))
	}
}

func TestGroupMultipleCVEsNewestWins(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2018-5", "CVE-2022-9"}},
	}
	groups := Group(recs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].CanonicalID != "CVE-2022-9" {
		t.Errorf("canonical = %q, want CVE-2022-9", groups[0].CanonicalID)
	}
}

func TestGroupMaxScore(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceNVD, OriginalID: "CVE-2020-1", Score: 5.3},
		{Source: SourceOSV, OriginalID: "GHSA-a", Aliases: []string{"CVE-2020-1"}, Score: 9.8},
		{Source: SourceCPER, OriginalID: "GHSA-b", Aliases: []string{"CVE-2020-1"}, Score: 0},
	}
	groups := Group(recs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].MaxScore != 9.8 {
		t.Errorf("MaxScore = %v, want 9.8", groups[0].MaxScore)
	}
	if len(groups[0].Records) != 3 {
		t.Errorf("expected 3 records retained, got %d", len(groups[0].Records))
	}
}

func TestGroupDeterministic(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceNVD, OriginalID: "CVE-2021-2"},
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}},
		{Source: SourceOSV, OriginalID: "MAL-2024-1"},
		{Source: SourceNVD, OriginalID: "CVE-2020-1"},
	}
	g1 := Group(recs)
	g2 := Group(recs)
	if !reflect.DeepEqual(g1, g2) {
		t.Errorf("Group not deterministic:\n%#v\n%#v", g1, g2)
	}
	// first-appearance order: CVE-2021-2, CVE-2020-1, MAL-2024-1
	want := []string{"CVE-2021-2", "CVE-2020-1", "MAL-2024-1"}
	if len(g1) != len(want) {
		t.Fatalf("expected %d groups, got %d", len(want), len(g1))
	}
	for i, w := range want {
		if g1[i].CanonicalID != w {
			t.Errorf("group[%d] = %q, want %q", i, g1[i].CanonicalID, w)
		}
	}
}
