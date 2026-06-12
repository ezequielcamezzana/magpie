package httpapi

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/ezequielcamezzana/magpie"
)

// vulnPageSize es la cantidad de grupos de vuln por página (el BE pagina tras
// agrupar y ordenar).
const vulnPageSize = 10

// vulnPage es el meta de paginación de vulns que acompaña al bundle. All y
// Affected son conteos globales (para las tabs); Total/Pages son del set ya
// filtrado por Filter.
type vulnPage struct {
	Page     int    `json:"Page"`
	Pages    int    `json:"Pages"`
	Total    int    `json:"Total"`
	All      int    `json:"All"`
	Affected int    `json:"Affected"`
	Order    string `json:"Order"`
	Filter   string `json:"Filter"`
}

// parseVulnParams lee vpage/vorder/vfilter (defaults: page 1, severity, all).
func parseVulnParams(r *http.Request) (vpage int, vorder, vfilter string) {
	vpage = 1
	if p, err := strconv.Atoi(r.URL.Query().Get("vpage")); err == nil && p >= 1 {
		vpage = p
	}
	vorder = r.URL.Query().Get("vorder")
	if vorder != "recent" {
		vorder = "severity"
	}
	vfilter = r.URL.Query().Get("vfilter")
	if vfilter != "affected" {
		vfilter = "all"
	}
	return vpage, vorder, vfilter
}

// paginateGroups ordena (vorder), filtra (vfilter) y pagina los grupos ya
// ensamblados. El filtro se aplica ANTES de paginar (por eso la página nunca
// queda vacía cuando hay matches). El meta trae los conteos globales.
func paginateGroups(groups []magpie.VulnGroup, vpage int, vorder, vfilter string) ([]magpie.VulnGroup, vulnPage) {
	all := len(groups)
	affected := 0
	for _, g := range groups {
		if g.Affected {
			affected++
		}
	}

	// WHY: severity ya viene aplicado por Collect.orderGroups; solo reordenamos
	// para "recent" (Updated desc, desempate por MaxScore desc).
	if vorder == "recent" {
		sort.SliceStable(groups, func(i, j int) bool {
			if !groups[i].Updated.Equal(groups[j].Updated) {
				return groups[i].Updated.After(groups[j].Updated)
			}
			return groups[i].MaxScore > groups[j].MaxScore
		})
	}

	work := groups
	if vfilter == "affected" {
		work = make([]magpie.VulnGroup, 0, affected)
		for _, g := range groups {
			if g.Affected {
				work = append(work, g)
			}
		}
	}

	total := len(work)
	pages := (total + vulnPageSize - 1) / vulnPageSize
	if pages < 1 {
		pages = 1
	}
	if vpage > pages {
		vpage = pages
	}

	off := (vpage - 1) * vulnPageSize
	end := off + vulnPageSize
	if off > total {
		off = total
	}
	if end > total {
		end = total
	}

	return work[off:end], vulnPage{
		Page: vpage, Pages: pages, Total: total, All: all, Affected: affected,
		Order: vorder, Filter: vfilter,
	}
}

// writeBundle serializa el Result (con Groups ya recortado a la página) más el
// meta de paginación de vulns. Serializer compartido por /collect y /component.
func writeBundle(w http.ResponseWriter, res *magpie.Result, meta vulnPage) {
	writeJSON(w, http.StatusOK, struct {
		*magpie.Result
		Vuln vulnPage `json:"Vuln"`
	}{res, meta})
}
