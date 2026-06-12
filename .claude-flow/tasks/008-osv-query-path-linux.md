# Task 008: source/osv — implementar el path KindLinux en Query

## Descripción
El cliente OSV nunca consulta para distros: `Query` tiene
`case purl.KindLinux: return nil, nil` (TODO task 022). Es el bloqueante real
de "0 affected packages" en Linux. La query es la misma que lenguaje (POST
`{package:{ecosystem,name}}`); solo hay que rutearla. Hueco detectado al probar,
no estaba en el plan original.

## Pasos
1. En `source/osv/client.go`, generalizar `queryLanguage` a una query compartida
   (renombrar a `query` o equivalente; no cambia su lógica HTTP/parseo).
2. En `Query`, `case purl.KindLinux:` → llamar a esa query compartida (igual que
   `KindLanguage`). El ecosystem ya viene release-suffixed (`"Debian:12"`) desde
   `OSVQuery()`, y `mapVuln`→`pickAffected` ya filtra por release (task 003).
3. `queryKey` linux ya queda `"debian:12:curl"` (release-scopeado por el sufijo).
4. Tests en `source/osv/client_test.go`: query linux con `httptest` que devuelve
   una vuln `Debian:12` → produce un `VulnRecord` con `AffectedRanges`.

## Archivos afectados
- `source/osv/client.go` — rutear `KindLinux` a la query compartida
- `source/osv/client_test.go` — caso linux end-to-end (stub HTTP)

## Definition of done
- `Query(ctx, OSVQuery{Kind:KindLinux, Ecosystem:"Debian:12", BaseEcosystem:"Debian",
  ReleaseToken:"12", Name:"curl"})` contra un stub que devuelve una vuln Debian:12
  retorna ≥1 `VulnRecord` con `AffectedRanges` no vacío.
- `go test ./source/osv/` verde.
- Smoke manual: `GET /collect?purl=pkg:deb/debian/curl@7.88.1-10+deb12u5` devuelve
  `Groups` no vacío (≥1 affected).

## Depende de
- 002, 003

## Notas
Sin esto, las tasks 001-003 son correctas pero inalcanzables para distros.
GitHub (`KindGitHub`) sigue como TODO aparte (task 023 del build original) —
fuera de scope acá.
