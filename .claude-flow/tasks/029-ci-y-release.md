# Task 029: CI y release (GitHub Actions + goreleaser)

## Descripción
Copiar y adaptar la infra de meerkat: workflow de CI (build + test + vet)
y release con goreleaser para que magpie se distribuya igual que meerkat.

## Pasos
1. `.github/workflows/ci.yml` basado en el de meerkat: go build, go vet,
   go test en push/PR. Ajustar versión de Go (magpie usa 1.26.x).
2. `.github/workflows/release.yml` basado en el de meerkat (tag → goreleaser).
3. `.goreleaser.yaml` adaptado: binario `magpie`, main `./cmd/magpie`,
   ldflags de `cmd/magpie/commands` (Version/Commit/Date), mismas
   plataformas que meerkat.
4. Si meerkat tiene `install.sh`, evaluar copiarlo adaptado (decisión
   menor: incluirlo si el README lo referencia).

## Archivos afectados
- `.github/workflows/ci.yml` — nuevo
- `.github/workflows/release.yml` — nuevo
- `.goreleaser.yaml` — nuevo

## Definition of done
- `goreleaser build --snapshot --clean` local genera binarios y
  `dist/.../magpie version` muestra la versión del snapshot.
- El workflow de CI pasa el lint de actions (`act` opcional o revisión
  manual de sintaxis).
- Push del repo a GitHub + primer run de CI verde (requiere crear el
  remote; si no existe todavía, dejarlo listo y marcarlo en el PR/commit).

## Depende de
- 027
