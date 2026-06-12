# Distro packages (deb / rpm / apk): qué hace Holmes y qué le falta a Magpie

Doc de observación, no de diseño cerrado. Captura cómo Holmes resuelve
ecosyste.ms + OSV + matching para paquetes de distro Linux, y dónde Magpie se
queda corto. Sirve de referencia para portar el comportamiento.

## El síntoma

```
pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.4
  → ecosyste.ms (other): no registry for purl type
  → sin vuln matching
```

En Holmes el mismo paquete: ecosyste.ms lo encuentra y el vuln matching corre.

## Por qué — la pieza que falta

ecosyste.ms **sí** tiene registries de distro, pero **scopeados por release**:
`ubuntu-24.04`, `debian-12`, `alpine-v3.19`. El nombre del registry embebe el
release. Holmes lo arma; Magpie no.

| Paso | Holmes | Magpie hoy |
| --- | --- | --- |
| Registry name | `EcosystemsRegistry(id)` → `ubuntu-<ver>` / `debian-<ver>` / `alpine-<rel>` | `registryByType[id.Type]` — solo 8 lenguajes; `deb`/`rpm`/`apk` no están → `ErrNoRegistry` |
| Endpoint name | `OSVName(id)` (npm scoped, go module path, maven `g:a`) | `id.Name` crudo |
| Release | extraído de qualifiers/versión, canonicalizado a codename, embebido en el SPURL (`pkg:deb/ubuntu/curl/noble`) | `Identity.Release` existe y se canonicaliza, pero **no** se usa para registry ni para el store key |

## Cómo lo hace Holmes (end-to-end)

Fuente: `holmes/pkg/domain/identity.go`, `holmes/pkg/agents/ecosystems.go`,
`holmes/pkg/agents/osv.go`.

### 1. Identity normalizada (`identity.go`)

- **SPURL extendido con release** como segmento extra:
  `pkg:deb/ubuntu/curl/noble`. No es un PURL válido — es convención de storage
  para que `noble` vs `jammy` no colisionen en cache. `QueryPURL()` lo recorta
  antes de salir a APIs externas. (`Identity` líneas 18-36, `composeSPURL`,
  `IdentifyFromSPURL`, `QueryPURL`.)
- **Release** sale de, en orden: qualifiers (`distro`, `distro_version`,
  `release`, `os_distro`, `os_release`), si no de la versión cuando el patrón es
  inequívoco (`+debNN`, `~bpoN`, `.elN`, `.fcNN`). Sufijos ambiguos como
  `-2ubuntu10.9` → `""`. (`extractRelease`, `releaseFromVersion`.)
- **Canonicalización** a codename: `deb12`/`12`/`bookworm` → `bookworm`,
  `24.04.1` → `noble`, alpine fuerza `v`-prefix. (`canonicalizeRelease`,
  `numericToCodename`.)
- **Clasificación** por `(type, namespace)`: `{deb,ubuntu}`→`Ubuntu`,
  `{deb,debian}`→`Debian`, `{apk,alpine}`→`Alpine`, `{rpm,fedora}`→`Fedora`, …
  También parsea `pkg:deb/ubuntu-noble/curl` (namespace `<distro>-<release>`).
  (`linuxEcosystems`, `splitNamespaceDistro`.)

### 2. ecosyste.ms (`ecosystems.go` + `EcosystemsRegistry`)

```go
registry := domain.EcosystemsRegistry(id)   // "ubuntu-24.04", "" si no mapea
if registry == "" { return ErrNotFound }
url := base + registry + "/packages/" + OSVName(id)
```

`EcosystemsRegistry` (`identity.go:133`):
- Language → `languageRegistries[type]`.
- Linux **con release conocido** → `ubuntu-<ver>` / `debian-<ver>` /
  `alpine-<rel>`. **Sin release → `""`** (no se puede armar el nombre, se
  skipea ecosyste.ms y se confía en OSV).

### 3. OSV (`osv.go:78`)

- Query: `{"ecosystem": OSVQueryString(id), "name": OSVName(id)}`.
  `OSVQueryString` → `"Ubuntu:24.04"`, `"Debian:12"`, `"Alpine:v3.19"`, o el
  ecosystem pelado cuando el distro no se scopea por release (SUSE, Fedora).
- Filtrado de la respuesta: OSV devuelve formas más específicas que la query
  (`"Ubuntu:24.04:LTS"`, `"Red Hat:enterprise_linux:8::baseos"`). Se filtra por
  `HasPrefix(ecosystem, id.Ecosystem)` + `Contains(ecosystem, OSVReleaseToken(id))`.
  (`OSVReleaseToken`, `identity.go:530`.)

### 4. Matching

Versiones de distro se comparan con el algoritmo **dpkg** (no semver).

## Estado de Magpie (file:line)

- `source/ecosystems/client.go:75` — `registryByType[id.Type]`: sin entradas de
  distro, y key por `type` en vez del registry release-aware. **Gap principal.**
- `source/ecosystems/client.go:35` — `registryByType` solo lenguajes.
- No existe equivalente a `EcosystemsRegistry(Identity)`.
- `pkg/purl/identity.go` — `Identity` ya tiene `Kind/Distro/Release` y los
  canonicaliza. ✅ La materia prima está.
- `pkg/purl/purl.go` `Strip` — conserva `?distro=&arch=` para linux, pero el
  SPURL **no** se extiende con el release; el store key OSV linux **no** es
  release-scoped (`osvquery.go` `StoreKey`, TODO task 022) → `noble`/`jammy`
  colisionan en cache.
- `pkg/purl/osvquery.go` — el *descriptor* de query OSV por release **ya está**
  portado (`OSVQuery`, `releaseToken`, `osvSuffix`, `codenameToNumeric`). ✅
- `source/osv/client.go:55` — **PERO el cliente nunca ejecuta la query Linux**:
  `case purl.KindLinux: return nil, nil` (TODO task 022). OSV no consulta nada
  para distros → 0 vulns. El path `KindLanguage` (`queryLanguage`) ya hace el
  POST correcto; `KindLinux` solo necesita rutear a la misma query (la response
  ya la filtra `pickAffected` release-aware). **Bloqueante real para distros.**
- `pkg/match/match.go:49` — `For` ya selecciona `dpkgMatcher` para deb/ubuntu/rpm. ✅
- `collect.go` (este branch) — agregué `ErrSourceNotApplicable`: silencia el
  error pero **es lo contrario del objetivo** para distros con release. Para
  esos queremos pegarle a ecosyste.ms, no skipear. Sirve solo como fallback de
  types genuinamente no cubiertos (o sin release).

## OSV no encuentra vulns en Linux — 2 trucos de Holmes

Aparte del registry de ecosyste.ms, el matching de OSV para distros falla por
dos cosas que Holmes hace y Magpie no.

### Truco 1 — filtrado de `affected[]` tolerante al release

OSV `/v1/query` con `ecosystem:"Ubuntu:24.04"` devuelve vulns cuyo array
`affected[]` mezcla **varios releases/distros** (Ubuntu 22.04, 24.04, Debian, el
upstream, …). Hay que elegir la entrada del release correcto.

- **Holmes** (`osv.go:100-118`): para Linux NO usa igualdad exacta de ecosystem.
  Filtra con `HasPrefix(aff.Ecosystem, id.Ecosystem)` (ecosystem pelado, p.ej.
  `"Ubuntu"`) + `Contains(aff.Ecosystem, OSVReleaseToken(id))` (substring del
  release, p.ej. `"24.04"`). Esto tolera que la respuesta sea más específica que
  la query (`"Ubuntu:24.04:LTS"`, `"Red Hat:enterprise_linux:8::baseos"`).
- **Magpie** (`source/osv/client.go:171`): `pickAffected` exige
  `p.Name == q.Name && EqualFold(p.Ecosystem, q.Ecosystem)`. Query
  `"Ubuntu:24.04"` vs respuesta `"Ubuntu:24.04:LTS"` → no matchea → cae a
  `affected[0]` (línea 175), que puede ser **otro release/distro** → rangos
  equivocados → dpkg no matchea. Encima `q.ReleaseToken` ya se calcula en
  `OSVQuery` pero el cliente **nunca lo usa**. **Este es el bug principal de
  "OSV no encuentra vulns".**

### Truco 2 — merge de `upstream` en aliases

Entradas tipo `DEBIAN-CVE-*` (y varias de Ubuntu) dejan `aliases` vacío y ponen
el CVE canónico en el campo OSV `upstream`.

- **Holmes** (`osv.go:283-286`): `Aliases = mergeUniqueIDs(v.Aliases, v.Upstream)`.
  Sin esto el vuln de distro no tiene alias CVE → el CPE learner no puede caminar
  a NVD y el alias-grouping no puede deduplicar con la entrada canónica.
- **Magpie** (`source/osv/types.go`, `client.go:136`): no parsea `upstream`,
  `Aliases: v.Aliases` a secas. Falta el campo y el merge.

(Bonus ya presente en ambos: skip de ranges `GIT` —SHAs de commit, no versiones—
en el mapeo; `source/osv/client.go:153`. ✅)

## Qué falta portar

1. `EcosystemsRegistry(purl.Identity) string` en `pkg/purl` (o en el cliente):
   linux con release → `ubuntu-<ver>` / `debian-<ver>` / `alpine-<rel>`.
2. `source/ecosystems` usa la `Identity` completa (Kind/Distro/Release) y
   `EcosystemsRegistry`, no `registryByType[id.Type]`. Endpoint con `OSVName(id)`.
3. Pasar la `Identity` (o un SPURL release-extendido) hasta stage 1 — hoy el
   cliente recibe el `Strip` y re-decompone; verificar que el release sobreviva.
4. Release-scopear el store key linux (TODO task 022) para que cache no colisione.
5. Revisar `ErrSourceNotApplicable`: dejarlo solo para "sin release / type no
   cubierto", no para todo distro.
6. **`pickAffected` release-tolerante para Linux** (bug principal de OSV):
   en vez de `EqualFold(ecosystem)`, usar `HasPrefix(aff.Ecosystem, id.Ecosystem)`
   + `Contains(aff.Ecosystem, q.ReleaseToken)`. Usar el `ReleaseToken` que
   `OSVQuery` ya calcula. Sin match real → `nil`, no `affected[0]`.
7. **Parsear + mergear `upstream`**: agregar `Upstream []string` a los OSV types
   y `Aliases = mergeUnique(v.Aliases, v.Upstream)` en `mapVuln`.

## Taxonomía Kind → fuente de match (CPE vs PURL)

Insight de diseño (smoke de curl): **CPE identifica el código upstream; un PURL
puede apuntar a una *distribución* de ese código.** De ahí qué fuente de
vulnerabilidades es correcta por `Kind`:

| Kind | Qué es | Fuente correcta |
| --- | --- | --- |
| Language (npm/pypi/conan/…) | paquete de un ecosistema | OSV(ecosystem) **+ CPE/NVD** (mismo esquema de versión) |
| Linux (deb/rpm/apk) | una *distribución* del código | **OSV(distro)**. CPE NO: la distro backportea fixes → aplicar rangos upstream de NVD da **falsos positivos** |
| GitHub | el repo upstream | OSV(GIT) |
| generic | el código upstream "pelado" | CPE/NVD *sería* la correcta, pero **no la podemos bootstrapear** |

### Por qué CPE es incorrecto para distros (no solo difícil)

Smoke CVE-2023-38545 / curl:
- NVD `haxx:libcurl` rango **upstream** `[7.69.0, 8.4.0]`, fixed upstream `8.4.0`.
- OSV `Debian:12 curl` rango **Debian** `[*, 7.88.1-10+deb12u4)` (`introduced:0`
  → unbounded-below), fixed = backport `7.88.1-10+deb12u4`.
- La lógica de range es fingerprint-equivalencia (mismo intervalo), no solape.
  Esquemas distintos + fix backporteado ≠ fix upstream → `subset=false`,
  `shareConcrete=false` (verificado). Y `vendor=haxx` no es candidato derivable.
- Conclusión: aplicar CPE/NVD a un paquete distro marcaría como vulnerable algo
  ya fixeado por backport. Por eso CPER se **gatea** para `KindLinux` (task 010).
  Holmes tiene la misma limitación (su learner es `name+vendor OR range`).

### generic: fuera de scope (decisión)

`pkg:generic/...` es código upstream → CPE *sería* la fuente ideal (lo opuesto a
distro). Pero la arquitectura no llega:
- CPER necesita una **CVE semilla** de OSV para caminar a NVD. Generic no tiene
  OSV-by-ecosystem ni OSV-by-distro → sin semilla.
- La alternativa (name→CPE, cpe-guesser) la **descartó el DD** ("CPER es el único
  path de CPE").

Decisión: **generic queda fuera de scope por ahora.** Caminos futuros si se
retoma: (a) generic con `?vcs_url=`/repo → OSV-GIT; (b) reintroducir un
cpe-guesser acotado para KindOther (requiere `/design`, contradice el DD actual).
