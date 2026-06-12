package httpapi

import (
	"net/http"
	"strconv"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

type cpesResponse struct {
	CPEs  []collect.ResolvedCPE `json:"cpes"`
	Page  int                   `json:"page"`
	Limit int                   `json:"limit"`
	Total int                   `json:"total"`
}

// handleCPEs es el índice global de CPEs resueltos, buscable por
// cpe/vendor/product/spurl. Espejo de handleComponents.
func handleCPEs(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		page := 1
		if p, err := strconv.Atoi(q.Get("page")); err == nil && p >= 1 {
			page = p
		}
		limit := 25
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l >= 1 {
			limit = l
		}
		if limit > 100 {
			limit = 100
		}

		cpes, total, err := deps.Config.Store.QueryCPEs(r.Context(), collect.CPEQuery{
			Search: q.Get("search"), Page: page, Limit: limit,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if cpes == nil {
			cpes = []collect.ResolvedCPE{}
		}

		writeJSON(w, http.StatusOK, cpesResponse{CPEs: cpes, Page: page, Limit: limit, Total: total})
	}
}
