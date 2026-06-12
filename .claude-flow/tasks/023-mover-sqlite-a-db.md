# Task 023: mover store/sqlite → internal/server/db

## Descripción
El store SQLite pasa a `internal/server/db` (nombre del modelo meerkat).
Traducir comentarios y migrar el test a testify.

## Pasos
1. `git mv store/sqlite internal/server/db` y borrar `store/` vacío.
2. Renombrar `package sqlite` → `package db`; el embed de `schema.sql`
   queda igual (viaja con el package).
3. Reescribir imports y referencias en el repo: `sqlite.Open` → `db.Open`,
   etc.
4. Traducir comentarios a inglés (el package doc está en español).
5. Migrar `sqlite_test.go` → `db_test.go` con testify.

## Archivos afectados
- `internal/server/db/{db.go,db_test.go,schema.sql}` — movidos/renombrados
- `cmd/magpie/main.go` — import y llamada actualizados
- `internal/server/collect/store.go` — referencia en docs si la hay

## Definition of done
- `store/` no existe en la raíz.
- `go test ./internal/server/db/` verde.
- `go build ./...` verde y el server abre la DB en el path configurado.

## Depende de
- 019
