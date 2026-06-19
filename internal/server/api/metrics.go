package api

import (
	"math"
	"net/http"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/health"
)

// metricsStaleAfter is the freshness cutoff for the dashboard's fresh rate:
// a package not re-collected within this window counts as stale.
const metricsStaleAfter = 24 * time.Hour

type metricsResponse struct {
	Components      int                            `json:"components"`
	Vulnerabilities int                            `json:"vulnerabilities"`
	CPEs            int                            `json:"cpes"`
	CPECollectRate  float64                        `json:"cpeCollectRate"` // % of CPE searches that resolved
	FreshRate       float64                        `json:"freshRate"`      // % of components refreshed within 24h
	Sources         map[string]health.SourceHealth `json:"sources"`        // live per-source upstream health
}

func handleMetrics(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := deps.Config.Store.Metrics(r.Context(), time.Now().UTC().Add(-metricsStaleAfter))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp := metricsResponse{
			Components:      m.Components,
			Vulnerabilities: m.Vulns,
			CPEs:            m.CPEs,
			CPECollectRate:  pct(m.ComponentsWithCPE, m.ComponentsWithCPE+m.MissedCPEs),
			FreshRate:       pct(m.Components-m.StaleComponents, m.Components),
		}
		if deps.Health != nil {
			resp.Sources = deps.Health.Snapshot()
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// pct returns num/den as a percentage rounded to one decimal, or 0 when den is 0.
func pct(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return math.Round(float64(num)/float64(den)*1000) / 10
}
