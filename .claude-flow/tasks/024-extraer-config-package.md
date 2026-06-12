# Task 024: extraer config de main.go → internal/server/config

## Descripción
Hoy el parsing de env vars vive inline en `cmd/magpie/main.go`. Extraerlo a
un package `config` con `Load()` y `validate()`, calcado del modelo de
meerkat (`internal/server/config/config.go`).

## Pasos
1. Crear `internal/server/config/config.go` con un struct `Config` que
   cubra lo que hoy lee main: `Listen` (MAGPIE_ADDR), `DBPath`
   (MAGPIE_DB_PATH), `LogFormat` (MAGPIE_LOG), `NVDAPIKey` (NVD_API_KEY),
   `MaxAge` (MAGPIE_MAX_AGE), `RequestTimeout` (MAGPIE_REQUEST_TIMEOUT).
2. Copiar de meerkat los helpers `envOr`/`envInt`/`envDuration` y el patrón
   `Load()` + `validate()`. Defaults idénticos a los actuales.
3. Mantener el warning por duración inválida (hoy main loguea y usa el
   default; conservar esa semántica o devolver error en validate —
   documentar la elección con un `WHY:`).
4. `main.go` queda: cargar config, armar logger, abrir DB, wiring, serve.
5. Comentarios en inglés desde el inicio.

## Archivos afectados
- `internal/server/config/config.go` — nuevo
- `cmd/magpie/main.go` — adelgazado, usa config.Load()

## Definition of done
- `go run ./cmd/magpie` con `MAGPIE_ADDR=:9999` escucha en 9999.
- `MAGPIE_MAX_AGE=banana` no crashea (warning + default, o error claro,
  según lo decidido en el paso 3).
- `go test ./...` verde.

## Depende de
- 022
