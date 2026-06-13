package api

import (
	"net/http"
	"strconv"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

type vulnsResponse struct {
	Records []collect.VulnRecord `json:"records"`
	Page    int                  `json:"page"`
	Limit   int                  `json:"limit"`
	Total   int                  `json:"total"`
}

func handleVulnerabilities(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		id := q.Get("id")

		page := 1
		if p, err := strconv.Atoi(q.Get("page")); err == nil && p >= 1 {
			page = p
		}

		limit := 25
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l >= 1 {
			limit = l
		}
		// WHY: 100 is the DD §8 maximum; we clamp so the client can't request
		// arbitrarily large pages.
		if limit > 100 {
			limit = 100
		}

		recs, total, err := deps.Config.Store.QueryVulns(r.Context(), collect.VulnQuery{
			ID: id, Page: page, Limit: limit,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// WHY: empty list, not null — the FE iterates over records without checking nil.
		if recs == nil {
			recs = []collect.VulnRecord{}
		}

		writeJSON(w, http.StatusOK, vulnsResponse{
			Records: recs,
			Page:    page,
			Limit:   limit,
			Total:   total,
		})
	}
}
