package api

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

// vulnPageSize is the number of vuln groups per page (the BE paginates after
// grouping and ordering).
const vulnPageSize = 10

// vulnPage is the vuln pagination meta that accompanies the bundle. All and
// Affected are global counts (for the tabs); Total/Pages are for the set
// already filtered by Filter.
type vulnPage struct {
	Page     int    `json:"Page"`
	Pages    int    `json:"Pages"`
	Total    int    `json:"Total"`
	All      int    `json:"All"`
	Affected int    `json:"Affected"`
	Order    string `json:"Order"`
	Filter   string `json:"Filter"`
}

// parseVulnParams reads vpage/vorder/vfilter (defaults: page 1, severity, all).
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

// paginateGroups orders (vorder), filters (vfilter) and paginates the
// already-assembled groups. The filter is applied BEFORE paginating (so the
// page is never empty when there are matches). The meta carries the global
// counts.
func paginateGroups(groups []collect.VulnGroup, vpage int, vorder, vfilter string) ([]collect.VulnGroup, vulnPage) {
	all := len(groups)
	affected := 0
	for _, g := range groups {
		if g.Affected {
			affected++
		}
	}

	// WHY: severity is already applied by Collect.orderGroups; we only reorder
	// for "recent" (Updated desc, tie-break by MaxScore desc).
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
		work = make([]collect.VulnGroup, 0, affected)
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

// writeBundle serializes the Result (with Groups already trimmed to the page)
// plus the vuln pagination meta. Shared serializer for /collect and /component.
func writeBundle(w http.ResponseWriter, res *collect.Result, meta vulnPage) {
	writeJSON(w, http.StatusOK, struct {
		*collect.Result
		Vuln vulnPage `json:"Vuln"`
	}{res, meta})
}
