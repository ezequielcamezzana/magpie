package httpapi

import (
	"net/http"

	"github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/pkg/purl"
)

// handleComponent sirve el bundle de un paquete (datos + repo + vulns) SIN versión:
// devuelve todas las vulns que afectan al paquete (no a una versión puntual). Mismo
// layout/serializer que /collect, pero sin filtro affected.
func handleComponent(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		spurl := r.URL.Query().Get("spurl")
		if spurl == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing spurl"})
			return
		}

		// WHY: el detalle de componente es por paquete, no por versión. Strip
		// descarta cualquier versión que venga en el coord → match "todas afectan".
		p, err := purl.Parse(spurl)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		stripped := purl.Strip(p)

		// WHY: la página de componente lee SOLO de la DB (sin red); FromStore no
		// invoca fetchers, así que no hay errores de ecosyste.ms/OSV acá.
		result, err := magpie.FromStore(r.Context(), stripped, deps.Config.Store)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// WHY: la página de componente no tiene filtro affected (no hay versión);
		// siempre "all".
		vpage, vorder, _ := parseVulnParams(r)
		page, meta := paginateGroups(result.Groups, vpage, vorder, "all")
		result.Groups = page
		writeBundle(w, result, meta)
	}
}
