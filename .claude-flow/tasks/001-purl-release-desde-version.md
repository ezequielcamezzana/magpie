# Task 001: pkg/purl — extraer release desde la versión

## Descripción
Portar `releaseFromVersion` de Holmes: cuando el PURL linux no trae qualifier
de release, derivarlo de la versión (`+debNN`, `~bpoN`, `.elN`, `.fcNN`).
Plan P1.

## Pasos
1. En `pkg/purl/identity.go`, agregar `releaseFromVersion(version string) string`
   que reconozca los patrones inequívocos: `+debNN`/`~bpoN` → `debN`,
   `.elN` → `elN`, `.fcNN` → `fcN`. Sufijos ambiguos (p.ej. `-2ubuntu10.9`) → `""`.
2. En `extractRelease`, cuando los qualifiers no dan release, caer a
   `releaseFromVersion(p.Version)`.
3. Verificar que `canonicalRelease` normalice los tokens nuevos (`deb12`→codename,
   `el8` se mantiene).
4. Tests en `pkg/purl/identity_test.go`.

## Archivos afectados
- `pkg/purl/identity.go` — nueva `releaseFromVersion`, `extractRelease` extendida
- `pkg/purl/identity_test.go` — casos de release desde versión

## Definition of done
- `Decompose(Parse("pkg:deb/debian/curl@7.88.1-10+deb12u5"))` → `Release == "bookworm"`.
- `Decompose(Parse("pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.4"))` (sufijo ambiguo,
  sin qualifier) → `Release == ""`.
- `go test ./pkg/purl/` verde.

## Depende de
- ninguna

## Notas
Holmes marca `-NubuntuM` como ambiguo a propósito (no hay mapeo 1:1 a release).
No inventar heurísticas nuevas; portar solo los patrones de Holmes
(`identity.go:342-379`).
