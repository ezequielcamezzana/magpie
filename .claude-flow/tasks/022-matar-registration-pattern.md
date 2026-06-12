# Task 022: reemplazar registration pattern por inyección explícita

## Descripción
El patrón `Register*` + blank-imports existía para evitar ciclos de import
cuando `magpie` era el package raíz importable. Con todo bajo `internal/`
ya no se justifica: el wiring pasa a ser explícito en el entrypoint.

## Pasos
1. En `internal/server/collect`: borrar `RegisterEcosystemsFetcher`,
   `RegisterOSVFetcher`, `RegisterCPER` y las variables globales asociadas.
2. Agregar a `collect.Config` (o a la firma de `Collect`, lo que quede más
   limpio) las dependencias: `EcosystemsFetcher`, `OSVFetcher` y el stage
   CPER como función opcional.
3. En los sources y en `cper`: borrar los `init()` que registraban; exponer
   constructores normales (`ecosystems.New(httpc, logger)`, etc.) si no
   existen ya.
4. En `cmd/magpie/main.go`: borrar los blank imports, construir los fetchers
   y pasarlos en el `Config`.
5. Actualizar los tests de `collect` que stubeaban vía registration para que
   inyecten los stubs por `Config`.

## Archivos afectados
- `internal/server/collect/collect.go` — Register* fuera, deps en Config
- `internal/server/collect/{collect_test.go,collect_cper_test.go}` — stubs por Config
- `internal/server/source/{ecosystems,osv}/client.go` — sin init() de registro
- `internal/server/cper/cper.go` — sin init() de registro
- `cmd/magpie/main.go` — wiring explícito, sin blank imports

## Definition of done
- `grep -rn "Register" internal/server/collect/` no devuelve nada.
- `grep -n '_ "github.com/ezequielcamezzana/magpie' cmd/magpie/main.go` no
  devuelve nada.
- `go test ./...` verde.
- Smoke test manual: `GET /collect?...` con un purl conocido devuelve
  resultado con stages de ecosystems y osv poblados.

## Notas
El error `ErrSourceNotApplicable` y el comportamiento de "fetcher no
configurado" deben mantener la semántica actual: si falta una dependencia
en Config es error de programación (panic o error claro), no un skip
silencioso.

## Depende de
- 020, 021
