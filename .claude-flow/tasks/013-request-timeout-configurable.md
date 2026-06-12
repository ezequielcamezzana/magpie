# Task 013: request timeout configurable (MAGPIE_REQUEST_TIMEOUT)

## Descripción
El timeout de request está hardcodeado en 15s (`httpapi/api.go:25`,
`middleware.Timeout(15*time.Second)`). Para repos con muchísimas vulns la query
OSV-GIT tarda más (curl/curl: 24s, 335 vulns) → `context deadline exceeded`.
Hacerlo configurable por env con default subido a 30s. Detectado probando la
task 012.

## Pasos
1. Agregar `RequestTimeout time.Duration` a `httpapi.Deps`.
2. En `Mount`, usar `deps.RequestTimeout`; si es 0, fallback a un default (30s)
   para no romper otros callers/tests que no lo seteen.
3. En `cmd/magpie/main.go`, parsear `MAGPIE_REQUEST_TIMEOUT` con el mismo patrón
   que `MAGPIE_MAX_AGE` (`time.ParseDuration`, warn + default si inválido),
   default `30 * time.Second`, y pasarlo en `httpapi.Deps`.
4. Test del fallback en `Mount` (deps sin timeout → no panic, usa el default) o
   smoke; lo principal es que compile y el override ande.

## Archivos afectados
- `httpapi/api.go` — `Deps.RequestTimeout` + `Mount` lo usa con fallback
- `cmd/magpie/main.go` — parse de `MAGPIE_REQUEST_TIMEOUT` (default 30s)

## Definition of done
- Sin env: el timeout efectivo es 30s.
- `MAGPIE_REQUEST_TIMEOUT=45s` → el server usa 45s; valor inválido → warn +
  default.
- Smoke manual: `MAGPIE_REQUEST_TIMEOUT=40s ... GET /collect?purl=pkg:github/curl/curl`
  devuelve `Groups` no vacío (no más `context deadline exceeded`).
- `go build ./...` y `go test ./httpapi/` verdes.

## Depende de
- ninguna

## Notas
Caveat aceptado: subir el límite hace que una fuente colgada tarde más en
fallar. Es el trade-off elegido (configurable + default 30s) sobre el esquema
por-fuente, más complejo. El cliente HTTP saliente no tiene timeout propio; el
único bound sigue siendo este request timeout.
