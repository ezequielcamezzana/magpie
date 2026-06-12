package httpapi

import (
	"net/http"
	"strconv"

	"github.com/ezequielcamezzana/magpie"
)

type componentsResponse struct {
	Components []magpie.Component `json:"components"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	Total      int                `json:"total"`
}

func handleComponents(deps Deps) http.HandlerFunc {
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

		comps, total, err := deps.Config.Store.QueryComponents(r.Context(), magpie.ComponentQuery{
			Name: q.Get("name"), Ecosystem: q.Get("ecosystem"), Page: page, Limit: limit,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// WHY: lista vacía, no null — el FE itera sin chequear nil.
		if comps == nil {
			comps = []magpie.Component{}
		}

		writeJSON(w, http.StatusOK, componentsResponse{
			Components: comps,
			Page:       page,
			Limit:      limit,
			Total:      total,
		})
	}
}
