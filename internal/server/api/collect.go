package api

import (
	"encoding/json"
	"net/http"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

func handleCollect(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		coord := r.URL.Query().Get("purl")
		if coord == "" {
			coord = r.URL.Query().Get("spurl")
		}
		if coord == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing purl or spurl"})
			return
		}

		result, err := collect.Collect(r.Context(), coord, deps.Config)
		if err != nil {
			// WHY: the coord is user input; a parse error is a bad request.
			// TODO: distinguish 400 (invalid coord) from 500 (broken config).
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// WHY: a non-empty Result.Errors is a partial failure, not a total one —
		// the status stays 200 with the errors array populated.
		vpage, vorder, vfilter := parseVulnParams(r)
		page, meta := paginateGroups(result.Groups, vpage, vorder, vfilter)
		result.Groups = page
		writeBundle(w, result, meta)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
