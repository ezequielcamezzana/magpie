# Task 025: mover httpapi → internal/server/api

## Descripción
El package HTTP pasa a `internal/server/api` como package `api` (modelo
meerkat). Traducir comentarios y migrar tests a testify.

## Pasos
1. `git mv httpapi internal/server/api` y renombrar `package httpapi` →
   `package api`.
2. Reescribir imports y referencias (`httpapi.Mount` → `api.Mount`,
   `httpapi.Deps` → `api.Deps`).
3. Traducir comentarios a inglés en los 11 archivos.
4. Migrar a testify: `api_test.go`, `vulnerabilities_test.go`, `e2e_test.go`.

## Archivos afectados
- `internal/server/api/*.go` — movidos (11 archivos), package renombrado,
  inglés, testify en tests
- `cmd/magpie/main.go` — import actualizado

## Definition of done
- `httpapi/` no existe en la raíz.
- `go test ./internal/server/api/` verde (incluido el e2e).
- `go build ./...` verde.

## Notas
Es la task más grande en cantidad de archivos pero es 100% mecánica
(mv + rename + traducción + asserts). Si el e2e usa paths relativos a
testdata de otros packages, ajustarlos.

## Depende de
- 022, 023
