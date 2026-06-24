package collect

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

func TestBestSummary(t *testing.T) {
	// Priority nvd > osv > eco, and a source only contributes if non-empty.
	recs := []VulnRecord{
		{Source: SourceEcosystems, Summary: "eco text"},
		{Source: SourceOSV, Summary: "osv text"},
		{Source: SourceNVD, Summary: "nvd text"},
	}
	assert.Equal(t, "nvd text", bestSummary(recs))

	// NVD present but empty → falls through to OSV.
	recs = []VulnRecord{
		{Source: SourceNVD, Summary: ""},
		{Source: SourceOSV, Summary: "osv text"},
		{Source: SourceEcosystems, Summary: "eco text"},
	}
	assert.Equal(t, "osv text", bestSummary(recs))

	assert.Empty(t, bestSummary([]VulnRecord{{Source: SourceOSV}}))
}

// stubNVDFetcher answers QueryCPE from a map keyed by short CPE.
type stubNVDFetcher struct {
	byCPE map[string][]VulnRecord
}

func (s stubNVDFetcher) QueryCPE(_ context.Context, cpe string) ([]VulnRecord, error) {
	return s.byCPE[ShortCPE(cpe)], nil
}

// TestCollectAssemblesStages: stage 3 (CPER, stubbed) resolves a CPE; stage 4
// (real, via the stub NVD fetcher) turns it into the package's NVD record,
// which ends up assembled as the canonical's extra source.
func TestCollectAssemblesStages(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	cpe := "cpe:2.3:a:lodash:lodash"
	cfg := testConfig(st,
		&stubFetcher{
			comp: Component{SPURL: spurl, Name: "lodash"},
			vulns: []VulnRecord{{
				Source: SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x",
				Aliases: []string{"CVE-2021-23337"}, AffectedRanges: []string{"[*, 4.17.21)"},
			}},
		},
		stubOSV{})
	cfg.NVDAPIKey = "test"
	cfg.MaxAge = UniformMaxAge(24 * time.Hour)

	// Stage 3 stub: just resolve the CPE (the real §3a logic is tested in cper).
	cfg.CPER = func(ctx context.Context, cfg Config, _ purl.Identity, sp, _ string, records []VulnRecord, _ time.Time) []SourceError {
		assert.NotEmpty(t, records, "stage 3: want the assembled records")
		_ = cfg.Store.PutCPEs(ctx, sp, []ResolvedCPE{{CPE: cpe, CVE: "CVE-2021-23337"}})
		return nil
	}

	// Stage 4: NVD returns the CVE affecting that CPE (MatchedOn = the CPE; the
	// component purl is filled by the pipeline).
	cfg.NVDFetcher = stubNVDFetcher{byCPE: map[string][]VulnRecord{
		cpe: {{
			Source: SourceNVD, OriginalID: "CVE-2021-23337", CanonicalID: "CVE-2021-23337",
			MatchedOn: cpe + ":*:*:*:*:*:node.js:*:*", Score: 7.2,
			AffectedRanges: []string{"[*, 4.17.21)"},
		}},
	}}

	res, err := Collect(context.Background(), "pkg:npm/lodash@4.17.20", cfg)
	require.NoError(t, err)

	require.Len(t, res.CPEs, 1)
	assert.Equal(t, cpe, res.CPEs[0].CPE)

	// The NVD record (from stage 4) got assembled as a member of the CVE's
	// group, with the component stamped as the package purl and the CPE kept in
	// MatchedOn.
	var nvd *VulnRecord
	for gi := range res.Groups {
		for mi := range res.Groups[gi].Members {
			if res.Groups[gi].Members[mi].Record.Source == SourceNVD {
				nvd = &res.Groups[gi].Members[mi].Record
			}
		}
	}
	require.NotNil(t, nvd, "want 1 nvd member in groups")
	assert.Equal(t, spurl, nvd.AffectedPackage, "component must be the package purl")
	assert.Equal(t, cpe+":*:*:*:*:*:node.js:*:*", nvd.MatchedOn, "matched_on must be the CPE")
}
