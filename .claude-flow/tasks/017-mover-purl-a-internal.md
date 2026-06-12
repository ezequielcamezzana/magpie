# Task 017: mover pkg/purl → internal/server/purl

## Descripción
Magpie deja de ser library: nada queda en `pkg/`. Mover `purl` bajo
`internal/server/` (layout meerkat), traducir comentarios a inglés y migrar
sus tests a testify.

## Pasos
1. `git mv pkg/purl internal/server/purl`.
2. Reescribir imports en todo el repo:
   `github.com/ezequielcamezzana/magpie/pkg/purl` →
   `github.com/ezequielcamezzana/magpie/internal/server/purl`.
3. Traducir a inglés todos los comentarios del package (doc del package,
   docs de funciones, inline). Mantener los markers (`WHY:`, etc.).
4. Agregar `github.com/stretchr/testify` al `go.mod` y migrar
   `purl_test.go` e `identity_test.go` a `assert`/`require`.

## Archivos afectados
- `internal/server/purl/{purl.go,identity.go,osvquery.go}` — movidos, comentarios en inglés
- `internal/server/purl/{purl_test.go,identity_test.go}` — movidos, testify
- todo archivo que importe `pkg/purl` — import actualizado
- `go.mod`, `go.sum` — testify agregado

## Definition of done
- `pkg/purl/` no existe.
- `grep -r "magpie/pkg/purl" --include="*.go" .` no devuelve nada.
- `go test ./internal/server/purl/` verde.
- `go build ./...` verde.
- Sin comentarios en español en el package (revisión manual del diff).

## Depende de
- 016
