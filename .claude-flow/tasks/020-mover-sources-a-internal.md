# Task 020: mover source/* → internal/server/source/*

## Descripción
Mover los tres sources (ecosystems, osv, nvd) bajo `internal/server/source/`,
con sus testdata per-package (decisión: las fixtures quedan al lado del
package). Traducir comentarios y migrar tests a testify.

## Pasos
1. `git mv source/ecosystems internal/server/source/ecosystems` (incluye
   `testdata/`), ídem `source/osv` y `source/nvd`. Borrar `source/` vacío.
2. Reescribir imports en todo el repo:
   `magpie/source/<x>` → `magpie/internal/server/source/<x>`.
3. Traducir comentarios a inglés en los tres packages.
4. Migrar a testify: `ecosystems/{client_test.go,registry_test.go}`,
   `osv/client_test.go`, `nvd/parse_test.go`.

## Archivos afectados
- `internal/server/source/ecosystems/` — movido (5 archivos + testdata)
- `internal/server/source/osv/` — movido (3 archivos + testdata)
- `internal/server/source/nvd/` — movido (3 archivos)
- `cmd/magpie/main.go` — blank imports actualizados
- archivos que importen los sources — imports actualizados

## Definition of done
- `source/` no existe en la raíz.
- `grep -r "magpie/source/" --include="*.go" .` no devuelve nada.
- `go test ./internal/server/source/...` verde (las fixtures se cargan del
  path nuevo).
- `go build ./...` verde.

## Depende de
- 019
