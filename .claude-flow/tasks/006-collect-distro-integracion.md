# Task 006: collect — distro cubierto enriquece, no-cubierto skipea limpio

## Descripción
Cerrar el comportamiento de stage 1 para distros: un distro con registry
resolvable enriquece vía ecosyste.ms; uno sin registry skipea sin `SourceError`
(no ruido). Plan P5. El branch `ErrSourceNotApplicable` en `collectStage1` ya
existe; esta task lo confirma y lo cubre con tests.

## Pasos
1. Revisar el branch `errors.Is(err, ErrSourceNotApplicable)` en
   `collectStage1` (collect.go): confirmar que retorna sin agregar `SourceError`.
2. Test en `collect_test.go` con `stubFetcher`:
   - distro cubierto (registry resolvable) → la respuesta trae Component/vulns y
     `Result.Errors` no contiene error de ecosyste.ms.
   - distro no cubierto (stub devuelve `ErrSourceNotApplicable`) → `Result.Errors`
     sin error de ecosyste.ms; el pipeline sigue a OSV.
3. Si hace falta, ajustar el wording/clasificación del branch.

## Archivos afectados
- `collect.go` — revisar/ajustar branch `ErrSourceNotApplicable`
- `collect_test.go` — dos casos distro

## Definition of done
- Collect de un distro no cubierto no produce `SourceError` de `ecosyste.ms`.
- Collect de un distro cubierto incluye los datos del stub y cero error de stage 1.
- `go test .` verde.

## Depende de
- 005

## Notas
La task 005 hace que el cliente devuelva `ErrSourceNotApplicable` solo cuando
`registryName==""`; acá se valida el efecto end-to-end en el pipeline.
