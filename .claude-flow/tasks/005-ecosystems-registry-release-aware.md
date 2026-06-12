# Task 005: source/ecosystems — registry release-aware para distros

## Descripción
ecosyste.ms tiene registries de distro scopeados por release (`ubuntu-24.04`,
`debian-12`, `alpine-v3.19`). Resolver el nombre desde la Identity en vez de
`registryByType[id.Type]`. Plan P4.

## Pasos
1. Nuevo `source/ecosystems/registry.go` con `registryName(id purl.Identity)
   string`:
   - `KindLanguage` → `registryByType[id.Type]`.
   - `KindLinux` con `id.ReleaseToken() != ""`: `ubuntu` → `"ubuntu-"+token`,
     `debian` → `"debian-"+token`, `alpine` → `"alpine-v"+token`. Resto → `""`.
   - Otro / sin token → `""`.
2. En `source/ecosystems/client.go` `Fetch`, reemplazar el lookup
   `registryByType[id.Type]` por `registry := registryName(id)`; si `== ""`
   devolver `magpie.ErrSourceNotApplicable`.
3. Confirmar que el endpoint usa `id.Name` (ya es el nombre OSV-normalizado vía
   `osvNameFor` en `Decompose`).
4. Tests en `source/ecosystems/` para `registryName` (ubuntu/debian/alpine y
   casos que dan `""`).

## Archivos afectados
- `source/ecosystems/registry.go` — nuevo, `registryName`
- `source/ecosystems/client.go` — `Fetch` usa `registryName`
- `source/ecosystems/registry_test.go` — nuevo, tabla de casos

## Definition of done
- `registryName(Identity{ubuntu, noble})` → `"ubuntu-24.04"`;
  `{debian, bookworm}` → `"debian-12"`; `{alpine, v3.19}` → `"alpine-v3.19"`.
- `{rpm, fedora}` y `{ubuntu, ""}` → `""`.
- `Fetch` de un distro sin registry resolvable devuelve `ErrSourceNotApplicable`.
- `go test ./source/ecosystems/` verde.

## Depende de
- 002

## Notas
El naming es ecosyste.ms-específico, por eso vive en source/ecosystems (no en
pkg/purl) reutilizando `Identity.ReleaseToken()`. Verificar forma exacta de
alpine (`alpine-v3.19` vs `alpine-3.19`) contra la API — decisión abierta del
plan. Holmes solo da registry a ubuntu/debian/alpine.
