# Task 007: source/osv — store key linux release-scopeado (opcional)

## Descripción
Evitar colisión de cache `noble`/`jammy` cuando el release es desconocido. Con
release, el sufijo del ecosystem ya scopea la key; sin release, `noble` y
`jammy` comparten key. Plan P6 (TODO task 022 del build original).

## Pasos
1. En `pkg/purl/osvquery.go` `StoreKey()`, branch `KindLinux`: incluir el
   `ReleaseToken` (o el `Ecosystem` ya sufijado) explícitamente para que la key
   sea release-aware aun cuando el ecosystem quede pelado.
2. Verificar que `collect.go` y el cliente OSV usen la misma key (no driftear).
3. Tests en `pkg/purl` para `StoreKey` de dos releases del mismo paquete.

## Archivos afectados
- `pkg/purl/osvquery.go` — `StoreKey` linux release-scopeada
- `pkg/purl/osvquery_test.go` — keys distintas por release

## Definition of done
- `StoreKey` de `ubuntu/curl@noble` ≠ `StoreKey` de `ubuntu/curl@jammy`.
- `go test ./pkg/purl/` verde y `go build ./...` ok.

## Depende de
- 002

## Notas
Opcional / baja prioridad: solo afecta el caso de release desconocido. Si el
sufijo del ecosystem ya alcanza en la práctica, se puede cerrar como no-op
documentado.
