# Task 002: pkg/purl — exponer ReleaseToken y BaseEcosystem en OSVQuery

## Descripción
Exponer el token de release (numérico) para que source/ecosystems arme el
nombre de registry, y agregar el ecosystem "pelado" a `OSVQuery` para el filtro
tolerante de OSV. Plan P1.

## Pasos
1. En `pkg/purl/osvquery.go`, agregar método `func (id Identity) ReleaseToken()
   string` que envuelva la `releaseToken(id.Distro, id.Release)` existente.
2. Agregar campo `BaseEcosystem string` al struct `OSVQuery`.
3. En `OSVQuery()`, branch `KindLinux`: setear `BaseEcosystem: id.Ecosystem`
   (el pelado, antes del sufijo de release). Para los otros kinds, `BaseEcosystem`
   puede quedar igual a `Ecosystem`.
4. Tests en `pkg/purl` cubriendo `ReleaseToken()` y el `BaseEcosystem` de la query.

## Archivos afectados
- `pkg/purl/osvquery.go` — método `ReleaseToken`, campo y seteo de `BaseEcosystem`
- `pkg/purl/identity_test.go` o `osvquery_test.go` — tests

## Definition of done
- `Decompose(Parse("pkg:deb/ubuntu/curl?distro=ubuntu-24.04")).ReleaseToken()`
  → `"24.04"`.
- `Identity{...ubuntu, noble}.OSVQuery()` → `Ecosystem=="Ubuntu:24.04"`,
  `BaseEcosystem=="Ubuntu"`, `ReleaseToken=="24.04"`.
- `go test ./pkg/purl/` verde.

## Depende de
- ninguna

## Notas
`releaseToken` y el campo `ReleaseToken` de `OSVQuery` ya existen; esto solo
expone el helper a nivel Identity y agrega el ecosystem pelado.
