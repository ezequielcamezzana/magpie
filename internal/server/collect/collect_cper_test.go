package collect

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// fakeCPERStage adapts a simplified stage func to CPERStage. The real CPER
// logic is tested in the cper package; here only Collect's contract: it
// invokes the stage and assembles whatever it left in the store.
func fakeCPERStage(f func(ctx context.Context, cfg Config, spurl string, records []VulnRecord, now time.Time)) CPERStage {
	return func(ctx context.Context, _ *http.Client, cfg Config, _ purl.Identity, spurl, _ string, records []VulnRecord, now time.Time) {
		f(ctx, cfg, spurl, records, now)
	}
}

// TestCollectAssemblesCPERStage: what stage 3 persists (CPEs + source=nvd
// records) ends up assembled in the Result as the canonical's 3rd source.
func TestCollectAssemblesCPERStage(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
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
	cfg.MaxAge = 24 * time.Hour

	cfg.CPER = fakeCPERStage(func(ctx context.Context, cfg Config, sp string, records []VulnRecord, now time.Time) {
		assert.NotEmpty(t, records, "stage: want the assembled records")
		_ = cfg.Store.PutCPEs(ctx, sp, []ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash", CVE: "CVE-2021-23337"}})
		_ = cfg.Store.PutVulns(ctx, SourceNVD, sp, []VulnRecord{{
			Source: SourceNVD, QueryKey: sp, OriginalID: "CVE-2021-23337",
			CanonicalID: "CVE-2021-23337", Score: 7.2, FetchedAt: now,
		}})
	})

	res, err := Collect(context.Background(), "pkg:npm/lodash@4.17.20", cfg)
	require.NoError(t, err)

	require.Len(t, res.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:lodash:lodash", res.CPEs[0].CPE)

	// The NVD record got assembled as a member of the CVE's group.
	var nvdMembers int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			if m.Record.Source == SourceNVD {
				nvdMembers++
			}
		}
	}
	assert.Equal(t, 1, nvdMembers, "want 1 nvd member in groups")
}
