# Task 018: mover pkg/match → internal/server/match

## Descripción
Igual que 017 pero para `match`: mover bajo `internal/server/`, traducir
comentarios a inglés y migrar tests a testify.

## Pasos
1. `git mv pkg/match internal/server/match`.
2. Reescribir imports en todo el repo:
   `github.com/ezequielcamezzana/magpie/pkg/match` →
   `github.com/ezequielcamezzana/magpie/internal/server/match`.
3. Borrar `pkg/` (queda vacío).
4. Traducir comentarios a inglés (el package doc de `match.go` ya está en
   inglés; revisar el resto, p.ej. los inline de `Evidence`).
5. Migrar a testify: `dpkg_test.go`, `go_test.go`, `semver_test.go`,
   `for_test.go`.

## Archivos afectados
- `internal/server/match/*.go` — movidos (10 archivos), comentarios en inglés
- tests del package — testify
- todo archivo que importe `pkg/match` — import actualizado

## Definition of done
- `pkg/` no existe.
- `grep -r "magpie/pkg/" --include="*.go" .` no devuelve nada.
- `go test ./internal/server/match/` verde.
- `go build ./...` verde.

## Depende de
- 017
