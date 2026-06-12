# Task 026: mover web/ → internal/server/ui y montar la SPA en /app

## Descripción
La SPA embebida pasa a `internal/server/ui` (modelo meerkat) y se sirve
bajo `/app` en vez del catch-all `/*` actual. Los endpoints de API quedan
donde están.

## Pasos
1. `git mv web internal/server/ui`, renombrar `package web` → `package ui`
   y `web.go` → `ui.go`. Los assets (`index.html`, `static/`) viajan con el
   embed.
2. En `api.Mount` (ex `httpapi/api.go:42`): reemplazar
   `r.Handle("/*", web.Handler(...))` por `r.Mount("/app", ui.Handler(...))`
   y un redirect `GET /` → `/app`.
3. Ajustar `ui.Handler` para servir bajo el prefijo `/app`: el catch-all
   SPA y `/static/` tienen que resolver con el prefijo strippeado
   (`http.StripPrefix`), y las URLs de assets en `index.html` pasar a
   relativas o con prefijo `/app/static/`.
4. Actualizar el target `ui-sync` del Makefile: destino
   `internal/server/ui/static/ui/`.
5. Traducir comentarios a inglés.

## Archivos afectados
- `internal/server/ui/ui.go` — movido y renombrado
- `internal/server/ui/{index.html,static/}` — movidos; paths de assets revisados
- `internal/server/api/api.go` — mount en /app + redirect
- `Makefile` — ui-sync apunta al path nuevo

## Definition of done
- `GET /app` devuelve la SPA (200, HTML con `__MAGPIE_VERSION__` reemplazado).
- `GET /app/static/app.css` devuelve 200.
- `GET /` redirige a `/app` (302 o 307).
- Rutas internas de la SPA (`/app/loquesea`) devuelven el index (catch-all).
- `make ui-sync` copia tokens.css/base.css al path nuevo.
- `go test ./...` verde.

## Depende de
- 025
