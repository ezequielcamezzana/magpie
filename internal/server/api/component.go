package api

import (
	"net/http"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// handleBundle re-serves a collected bundle from the store ONLY (no network),
// keeping the queried version so the affected filter still works. WHY: once
// /collect has run the pipeline and persisted everything, re-paginating,
// re-ordering or toggling the affected/all filter must NOT re-run the pipeline —
// it reads back exactly what /collect wrote and paginates differently.
func handleBundle(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		coord := r.URL.Query().Get("purl")
		if coord == "" {
			coord = r.URL.Query().Get("spurl")
		}
		if coord == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing purl or spurl"})
			return
		}

		result, err := collect.FromStore(r.Context(), coord, deps.Config.Store)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		vpage, vorder, vfilter := parseVulnParams(r)
		page, meta := paginateGroups(result.Groups, vpage, vorder, vfilter)
		result.Groups = page
		writeBundle(w, result, meta)
	}
}

// handleComponent serves a package bundle (data + repo + vulns) WITHOUT a version:
// it returns every vuln that affects the package (not a specific version). Same
// layout/serializer as /collect, but without the affected filter.
func handleComponent(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		spurl := r.URL.Query().Get("spurl")
		if spurl == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing spurl"})
			return
		}

		// WHY: the component detail is per package, not per version. Strip drops
		// any version present in the coord → "all affect" match.
		p, err := purl.Parse(spurl)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		stripped := purl.Strip(p)

		// WHY: the component page reads ONLY from the DB (no network); FromStore
		// doesn't invoke fetchers, so there are no ecosyste.ms/OSV errors here.
		result, err := collect.FromStore(r.Context(), stripped, deps.Config.Store)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// WHY: the component page has no affected filter (there's no version);
		// always "all".
		vpage, vorder, _ := parseVulnParams(r)
		page, meta := paginateGroups(result.Groups, vpage, vorder, "all")
		result.Groups = page
		writeBundle(w, result, meta)
	}
}
