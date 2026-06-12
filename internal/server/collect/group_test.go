package collect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			assert.Equal(t, tt.want, pickNewestCVE(tt.ids))
		})
	}
}

func TestGroupCanonicalFromAliases(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}},
	}
	groups := Group(recs)
	require.Len(t, groups, 1)
	assert.Equal(t, "CVE-2020-1", groups[0].CanonicalID)
}

func TestGroupCanonicalNoCVE(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "MAL-2024-1", Aliases: []string{"GHSA-y"}},
	}
	groups := Group(recs)
	require.Len(t, groups, 1)
	assert.Equal(t, "MAL-2024-1", groups[0].CanonicalID)
}

func TestGroupSharedCVEMerges(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2020-1"}},
		{Source: SourceNVD, OriginalID: "CVE-2020-1"},
	}
	groups := Group(recs)
	require.Len(t, groups, 1)
	assert.Equal(t, "CVE-2020-1", groups[0].CanonicalID)
	assert.Len(t, groups[0].Records, 2)
}

func TestGroupMultipleCVEsNewestWins(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceOSV, OriginalID: "GHSA-x", Aliases: []string{"CVE-2018-5", "CVE-2022-9"}},
	}
	groups := Group(recs)
	require.Len(t, groups, 1)
	assert.Equal(t, "CVE-2022-9", groups[0].CanonicalID)
}

func TestGroupMaxScore(t *testing.T) {
	recs := []VulnRecord{
		{Source: SourceNVD, OriginalID: "CVE-2020-1", Score: 5.3},
		{Source: SourceOSV, OriginalID: "GHSA-a", Aliases: []string{"CVE-2020-1"}, Score: 9.8},
		{Source: SourceCPER, OriginalID: "GHSA-b", Aliases: []string{"CVE-2020-1"}, Score: 0},
	}
	groups := Group(recs)
	require.Len(t, groups, 1)
	assert.Equal(t, 9.8, groups[0].MaxScore)
	assert.Len(t, groups[0].Records, 3)
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
	assert.Equal(t, g1, g2, "Group not deterministic")
	// first-appearance order: CVE-2021-2, CVE-2020-1, MAL-2024-1
	want := []string{"CVE-2021-2", "CVE-2020-1", "MAL-2024-1"}
	require.Len(t, g1, len(want))
	for i, w := range want {
		assert.Equal(t, w, g1[i].CanonicalID, "group[%d]", i)
	}
}
