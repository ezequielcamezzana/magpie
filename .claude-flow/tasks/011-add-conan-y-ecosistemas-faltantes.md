# Task 011: agregar conan y ecosistemas faltantes (ecosyste.ms + OSV)

## Descripción
Magpie mapea solo 8 ecosistemas de lenguaje; ecosyste.ms (y OSV) soportan más.
Un `pkg:conan/...` cae a `KindOther` → no se enriquece ni se queréa. Confirmado
contra la API: ecosyste.ms tiene registry `conan.io`. Agregar conan (prioridad)
y el resto de ecosistemas que faltan, en los dos mapas. Detectado por el usuario.

## Pasos
1. En `pkg/purl/identity.go` `languageEcosystems` (purl type → OSV ecosystem
   name), agregar:
   - `conan` → `ConanCenter` (verificado: OSV usa "ConanCenter")
   - y, verificando el nombre OSV de cada uno antes: `hex`→`Hex`, `pub`→`Pub`,
     `cran`→`CRAN`, `hackage`→`Hackage`, `bioconductor`→`Bioconductor`,
     `swift`→`SwiftURL`, `pub-dev`/`cocoapods`/`clojars`/`julia`/`elm`/`vcpkg`
     según cobertura OSV real.
2. En `source/ecosystems/client.go` `registryByType` (purl type → ecosyste.ms
   registry), agregar (confirmados contra la API):
   - `conan`→`conan.io`, `hex`→`hex.pm`, `pub`→`pub.dev`,
     `cran`→`cran.r-project.org`, `hackage`→`hackage.haskell.org`,
     `bioconductor`→`bioconductor.org`, `swift`→`swiftpackageindex.com`,
     `cocoapods`→`cocoapods.org`, `clojars`→`clojars.org`, `julia`→`juliahub.com`,
     `elm`→`package.elm-lang.org`, `vcpkg`→`vcpkg.io`.
3. Si algún ecosistema enriquece (ecosyste.ms) pero no tiene ecosystem OSV
   válido, agregarlo solo a `registryByType` (enrich-only) y no a
   `languageEcosystems` (evita queries OSV inválidas).
4. Tests: tabla en `pkg/purl` (conan → KindLanguage + Ecosystem ConanCenter) y
   en `source/ecosystems` (registryName de conan → conan.io).

## Archivos afectados
- `pkg/purl/identity.go` — `languageEcosystems` extendido
- `source/ecosystems/client.go` — `registryByType` extendido
- `pkg/purl/identity_test.go` + `source/ecosystems/registry_test.go` — casos

## Definition of done
- `Decompose(Parse("pkg:conan/zlib@1.3"))` → `Kind==KindLanguage`,
  `Ecosystem=="ConanCenter"`.
- `registryName(Identity{conan...})` → `"conan.io"`.
- Smoke manual: `GET /collect?purl=pkg:conan/<paquete-conocido>` devuelve
  Component no nulo.
- `go test ./pkg/purl/ ./source/ecosystems/` verde.

## Depende de
- 005 (registryName ya existe y mapea KindLanguage vía registryByType)

## Notas
Tres vocabularios distintos: purl type (`conan`), registry ecosyste.ms
(`conan.io`), ecosystem OSV (`ConanCenter`). No confundirlos. Los nombres OSV de
los ecosistemas menos comunes conviene verificarlos contra api.osv.dev antes de
agregarlos (cobertura parcial); enrich-only es un fallback válido.
