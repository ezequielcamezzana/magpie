# Task 021: mover cper/ → internal/server/cper

## Descripción
Mover el stage CPER bajo `internal/server/`, traducir comentarios y migrar
su test a testify.

## Pasos
1. `git mv cper internal/server/cper`.
2. Reescribir imports: `magpie/cper` → `magpie/internal/server/cper`
   (incluye el blank import de `cmd/magpie/main.go`).
3. Traducir comentarios a inglés.
4. Migrar `cper_test.go` a testify.

## Archivos afectados
- `internal/server/cper/{cper.go,cper_test.go}` — movidos, inglés, testify
- `cmd/magpie/main.go` — blank import actualizado

## Definition of done
- `cper/` no existe en la raíz.
- `go test ./internal/server/cper/` verde.
- `go build ./...` verde.

## Depende de
- 019
