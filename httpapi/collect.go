package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/ezequielcamezzana/magpie"
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

		result, err := magpie.Collect(r.Context(), coord, deps.Config)
		if err != nil {
			// WHY: el coord es input del usuario; un parse error es bad request.
			// TODO: distinguir 400 (coord inválida) de 500 (config rota).
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// WHY: Result.Errors no-vacío es partial failure, no fallo total — el
		// status sigue 200 con el array errors poblado.
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
