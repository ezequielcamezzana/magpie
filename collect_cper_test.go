package magpie

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// registerCPERStage instala un stage 3 fake para la duración del test. La
// lógica real de CPER se testea en el package cper; acá solo el contrato de
// Collect: invoca el stage y ensambla lo que dejó en el store.
func registerCPERStage(t *testing.T, f func(ctx context.Context, cfg Config, spurl string, records []VulnRecord, now time.Time)) {
	t.Helper()
	RegisterCPER(func(ctx context.Context, _ *http.Client, cfg Config, _ purl.Identity, spurl, _ string, records []VulnRecord, now time.Time) {
		f(ctx, cfg, spurl, records, now)
	})
	t.Cleanup(func() { RegisterCPER(nil) })
}

// TestCollectAssemblesCPERStage: lo que el stage 3 persiste (CPEs + records
// source=nvd) queda ensamblado en el Result como 3ra fuente del canonical.
func TestCollectAssemblesCPERStage(t *testing.T) {
	st := newFakeStore()
	spurl := "pkg:npm/lodash"
	registerEco(t, &stubFetcher{
		comp: Component{SPURL: spurl, Name: "lodash"},
		vulns: []VulnRecord{{
			Source: SourceEcosystems, QueryKey: spurl, OriginalID: "GHSA-x",
			Aliases: []string{"CVE-2021-23337"}, AffectedRanges: []string{"[*, 4.17.21)"},
		}},
	})
	registerOSV(t, stubOSV{})

	registerCPERStage(t, func(ctx context.Context, cfg Config, sp string, records []VulnRecord, now time.Time) {
		if len(records) == 0 {
			t.Error("stage: want the assembled records, got none")
		}
		_ = cfg.Store.PutCPEs(ctx, sp, []ResolvedCPE{{CPE: "cpe:2.3:a:lodash:lodash", CVE: "CVE-2021-23337"}})
		_ = cfg.Store.PutVulns(ctx, SourceNVD, sp, []VulnRecord{{
			Source: SourceNVD, QueryKey: sp, OriginalID: "CVE-2021-23337",
			CanonicalID: "CVE-2021-23337", Score: 7.2, FetchedAt: now,
		}})
	})

	res, err := Collect(context.Background(), "pkg:npm/lodash@4.17.20",
		Config{Store: st, NVDAPIKey: "test", MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.CPEs) != 1 || res.CPEs[0].CPE != "cpe:2.3:a:lodash:lodash" {
		t.Fatalf("want the stage's CPE in result, got %+v", res.CPEs)
	}

	// El record NVD quedó ensamblado como member del grupo del CVE.
	var nvdMembers int
	for _, g := range res.Groups {
		for _, m := range g.Members {
			if m.Record.Source == SourceNVD {
				nvdMembers++
			}
		}
	}
	if nvdMembers != 1 {
		t.Errorf("want 1 nvd member in groups, got %d", nvdMembers)
	}
}
