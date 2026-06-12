# Task 019: mover package raíz magpie → internal/server/collect

## Descripción
El corazón del refactor: el package `magpie` de la raíz (pipeline de
recolección y tipos core) pasa a `internal/server/collect` como package
`collect`. El registration pattern (`Register*` + blank imports) se mantiene
intacto en esta task para no romper nada; se elimina en la 022.

## Pasos
1. `git mv` de `collect.go`, `config.go`, `group.go`, `result.go`, `store.go`
   y sus tests (`collect_test.go`, `collect_cper_test.go`, `group_test.go`)
   a `internal/server/collect/`.
2. Renombrar `package magpie` → `package collect` en los archivos movidos.
3. Reescribir en todo el repo el import
   `github.com/ezequielcamezzana/magpie` →
   `github.com/ezequielcamezzana/magpie/internal/server/collect`
   y las referencias `magpie.X` → `collect.X` (Config, Result, VulnRecord,
   Store, Collect, Register*, errores exportados, etc.).
4. Traducir comentarios a inglés (collect.go tiene varios `WHY:` en español).
5. Migrar los tres tests del package a testify.

## Archivos afectados
- `internal/server/collect/{collect.go,config.go,group.go,result.go,store.go}` — movidos, package renombrado, inglés
- `internal/server/collect/{collect_test.go,collect_cper_test.go,group_test.go}` — movidos, testify
- `cmd/magpie/main.go`, `httpapi/*.go`, `source/*/*.go`, `cper/*.go`,
  `store/sqlite/*.go` — imports y referencias actualizadas

## Definition of done
- La raíz del repo no tiene archivos `.go`.
- `grep -rn "package magpie$" --include="*.go" .` no devuelve nada.
- `go build ./...` y `go test ./...` verdes.
- El server sigue levantando: `go run ./cmd/magpie` responde en `:8080`.

## Notas
- `collect.Collect` suena repetido pero es el mismo trade-off que
  `ingest.Ingest` en meerkat; no renombrar la función en esta task.
- No tocar el mecanismo de `Register*`/blank-imports acá — es scope de 022.

## Depende de
- 017, 018
