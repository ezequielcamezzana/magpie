# Task 009: pkg/purl — Strip embebe el release canónico (round-trip a stage 1)

## Descripción
El release derivado de la versión (`+deb12`→bookworm) llega a OSV pero NO a
ecosyste.ms: `collect.go` le pasa `purl.Strip(p)` al stage 1, y `Strip` descarta
la versión, conservando solo qualifiers `?distro`/`?arch`. Sin `?distro=`
explícito, el cliente re-decompone un purl sin release → sin registry → sin
Component. Plan P4/item-3 (+ cierra P6: store key release-scopeada). Bug
detectado probando en la UI.

## Pasos
1. En `pkg/purl/purl.go` `Strip`, para tipos linux: decomponer (`Decompose(p)`)
   y, cuando `id.Distro != "" && id.Release != ""`, emitir el qualifier canónico
   `distro=<id.Distro>-<id.Release>` (en vez de copiar el `distro` crudo). Seguir
   conservando `arch` si está. Si no hay release derivable, comportamiento actual
   (sin distro).
2. Confirmar el round-trip: `Decompose(Parse(Strip(p)))` recupera el mismo
   `Release` (extractRelease parsea `distro=<distro>-<release>` → release, y
   canonicalRelease lo normaliza).
3. Verificar que la store key resultante sea release-aware (noble ≠ jammy) — esto
   hace innecesaria la task 007 (cerrarla como cubierta).
4. Tests en `pkg/purl/purl_test.go` (Strip linux con release de versión y de
   qualifier) + un round-trip test.

## Archivos afectados
- `pkg/purl/purl.go` — `Strip` embebe el release canónico para linux
- `pkg/purl/purl_test.go` — Strip linux + round-trip
- (revisar) tests existentes de `Strip` que asserten el formato viejo

## Definition of done
- `Strip(Parse("pkg:deb/debian/curl@7.88.1-10+deb12u5"))` contiene
  `?distro=debian-bookworm` (o forma equivalente que round-trippee a bookworm).
- `Decompose(Parse(Strip(p))).Release == Decompose(p).Release` para deb/ubuntu/
  alpine con release (de versión o qualifier).
- Smoke manual: `GET /collect?purl=pkg:deb/debian/curl@7.88.1-10+deb12u5` (SIN
  `?distro=`) devuelve `Component` no nulo (name/repo).
- `go test ./pkg/purl/` y `go build ./...` verdes.

## Depende de
- 001, 002, 005

## Notas
`Strip` y `Decompose` viven en el mismo package (sin ciclo). El spurl es la
store key de Component/Repository/NVD/CPE (todos via `Strip(p)` en collect.go),
así que embeber el release los hace release-aware de forma consistente. OSV usa
su propia key (`OSVQuery.StoreKey`), no se toca acá. Revisar que la UI
(`web/index.html`, usa `URLSearchParams`) siga andando — no requiere cambios.
