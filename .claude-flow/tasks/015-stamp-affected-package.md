# Task 015: estampar affected_package con el spurl cuando OSV no lo trae

## Descripción
Las entradas OSV-GIT (github/curl/curl) vienen con `package:{}` vacío → `mapVuln`
deja `AffectedPackage == ""` → en `package_vuln` la columna `affected_package`
queda NULL/vacía: la vuln no queda asociada al paquete por ese campo. Fix:
estampar `affected_package` con el `spurl` del paquete consultado cuando OSV no
reporta un purl. Bug detectado por el usuario en github/curl/curl.

NOTA de causa: NO es por el orden de creación del synthetic package (la página
de componente ya asocia por `query_key` al leer, y funciona). Es que OSV-GIT no
trae `package.purl`. La 014 ya persiste el Component solo si hay vulns.

## Pasos
1. `runOSV` (collect.go) recibe un nuevo parámetro `spurl string`.
2. En el loop de stamping previo a `PutVulns`, agregar:
   `if records[i].AffectedPackage == "" { records[i].AffectedPackage = spurl }`.
3. `Collect` pasa `spurl` a `runOSV`.
4. (Opcional, confirmar) mismo criterio para stage1/ecosystems si quedara vacío
   — por ahora el bug es OSV, scope mínimo ahí.

## Archivos afectados
- `collect.go` — `runOSV(..., spurl, ...)` + stamp de `AffectedPackage` vacío
- `collect_test.go` — caso: vuln OSV sin package purl → `AffectedPackage == spurl`

## Definition of done
- Tras `Collect("pkg:github/curl/curl")`, todas las filas `package_vuln` de ese
  paquete tienen `affected_package == "pkg:github/curl/curl"` (cero NULL/vacías).
- Una vuln OSV que SÍ trae purl (p.ej. `pkg:generic/curl`) conserva el suyo (solo
  se estampan las vacías).
- `go test .` verde (salvo el rojo pre-existente `TestAcceptCPE_SoleSingleCPE`).

## Depende de
- 012 (github trae vulns OSV-GIT con package vacío)

## Notas
Solo se estampan las vacías (preserva el purl real que OSV sí reporta). Si más
adelante se quiere que TODAS las vulns de un paquete sintético usen su spurl
(override del `pkg:generic/...`), es otra decisión — por ahora fill-nulls.
`runOSV` ya tiene el loop de stamping (CanonicalID/FetchedAt), se agrega ahí.
