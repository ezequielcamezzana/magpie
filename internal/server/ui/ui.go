// Package ui serves magpie's SPA: index.html and the static assets,
// all embedded in the binary via go:embed.
package ui

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
)

//go:embed index.html static
var assets embed.FS

// Handler serves the SPA under the /app prefix: /app/static/* maps to the
// embedded FS and any other /app/... path returns index.html (GET).
// version is injected into the HTML footer, replacing __MAGPIE_VERSION__.
func Handler(version string) http.Handler {
	static := http.StripPrefix("/app", http.FileServer(http.FS(assets)))

	index, _ := assets.ReadFile("index.html")
	index = bytes.Replace(index, []byte("__MAGPIE_VERSION__"), []byte(version), 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// WHY: catch-all SPA — anything other than /app/static/ returns the index.
		if strings.HasPrefix(r.URL.Path, "/app/static/") {
			static.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})
	return mux
}
