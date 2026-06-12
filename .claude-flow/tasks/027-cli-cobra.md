# Task 027: CLI con cobra — magpie server / magpie version

## Descripción
Magpie pasa a tener CLI estilo meerkat: root command cobra con subcomandos
`server` y `version`. Todo lo que hoy hace `main.go` se muda al comando
`server`. Versionado completo por ldflags (Version/Commit/Date).

## Pasos
1. Agregar `github.com/spf13/cobra` al go.mod.
2. Crear `cmd/magpie/commands/server.go`: el cuerpo actual de main
   (config.Load, logger, db.Open, wiring de fetchers, chi router,
   api.Mount, graceful shutdown) pasa acá como `RunE`.
3. Crear `cmd/magpie/commands/version.go` con variables package-level
   `Version`, `Commit`, `Date` (modelo meerkat
   `cmd/meerkat/commands/version.go`).
4. `cmd/magpie/main.go` queda fino: root command + registro de subcomandos
   (modelo `cmd/meerkat/main.go`, ~40 líneas).
5. Actualizar Makefile: LDFLAGS al estilo meerkat
   (`-X .../cmd/magpie/commands.Version=...` + Commit + Date), mantener el
   formato documentado con `##` y el output en `bin/`, comentarios del
   Makefile en inglés.
6. Pasar `Version` (que hoy llega por `main.version`) a `api.Deps` desde el
   comando server.

## Archivos afectados
- `cmd/magpie/commands/server.go` — nuevo
- `cmd/magpie/commands/version.go` — nuevo
- `cmd/magpie/main.go` — reescrito fino
- `Makefile` — LDFLAGS nuevos, comentarios en inglés
- `go.mod`, `go.sum` — cobra

## Definition of done
- `make build && ./bin/magpie server` levanta el server.
- `./bin/magpie version` imprime version/commit/date inyectados por make.
- `./bin/magpie` sin args muestra el help de cobra.
- `go test ./...` verde.

## Depende de
- 024, 025, 026
