// Package web sirve la SPA de magpie: index.html y los assets estáticos,
// todo embebido en el binario vía go:embed.
package web

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
)

//go:embed index.html static
var assets embed.FS

// Handler sirve /static/* desde el FS embebido e index.html para el resto (GET).
// version se inyecta en el footer del HTML reemplazando __MAGPIE_VERSION__.
func Handler(version string) http.Handler {
	static := http.FileServer(http.FS(assets))

	index, _ := assets.ReadFile("index.html")
	index = bytes.Replace(index, []byte("__MAGPIE_VERSION__"), []byte(version), 1)

	mux := http.NewServeMux()
	mux.Handle("/static/", static)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// WHY: catch-all SPA — cualquier path no-/static/ devuelve el index.
		if strings.HasPrefix(r.URL.Path, "/static/") {
			static.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})
	return mux
}
