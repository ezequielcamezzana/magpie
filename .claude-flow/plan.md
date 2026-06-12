# Plan: Soporte de paquetes Linux (deb/rpm/apk)

Design de referencia: `docs/distro-packages.md`.

## Stack
Go (codebase existente). Sin deps nuevas — todo se porta de Holmes
respetando la estructura actual de Magpie (`pkg/purl`, `source/*`,
register-pattern).

## Arquitectura

```
Collect ──┬─ stage1 source/ecosystems ── registryName(Identity) ─→ ecosyste.ms
          │     (P4: registry release-aware + OSVName)
          ├─ stage2 source/osv ── pickAffected tolerante (P2) + upstream merge (P3)
          │
          └─ pkg/purl (P1: Identity.Release/ReleaseToken, base ecosystem)  ← fundación
                 │
            match.For → dpkgMatcher (ya existe) → Group/CPER
```

La materia prima ya está: `Identity` tiene `Kind/Distro/Release`, el scoping
OSV por release está portado, y `match.For` ya elige `dpkgMatcher`. Este plan
cierra los huecos que hacen que distros no enriquezcan (ecosyste.ms) ni
matcheen vulns (OSV).

## Piezas

### P1 — pkg/purl (fundación)
- **Responsabilidad**: dar release normalizado + tokens a las demás piezas.
- **Inputs**: `PURL` / `Identity` (distro, release, version).
- **Outputs**: `Identity.Release` más robusto; `OSVQuery{Ecosystem,
  BaseEcosystem, ReleaseToken, Name}`.
- **Interfaces**: `Identity.ReleaseToken() string`; `extractRelease` cae a la
  versión cuando no hay qualifier (`+debNN/~bpoN/.elN/.fcNN`); `OSVQuery` lleva
  el ecosystem pelado (`BaseEcosystem`, p.ej. "Ubuntu").
- **Dependencias**: ninguna.

### P2 — source/osv: filtrado tolerante (Truco 1, bug principal)
- **Responsabilidad**: elegir la entrada `affected[]` del release correcto.
- **Inputs**: `[]rawAffected`, `purl.OSVQuery`.
- **Outputs**: el `*rawAffected` correcto, o `nil` (no fallback a `affected[0]`
  para linux).
- **Interfaces**: `pickAffected`. Linux → `HasPrefix(aff.Eco, BaseEcosystem) &&
  (ReleaseToken=="" || Contains(aff.Eco, ReleaseToken))`; lenguaje → igualdad
  exacta como hoy.
- **Dependencias**: P1 (BaseEcosystem en la query).

### P3 — source/osv: merge de upstream (Truco 2)
- **Responsabilidad**: que los vulns de distro tengan alias CVE (para CPER +
  grouping).
- **Inputs**: `rawVuln` (`aliases`, `upstream`).
- **Outputs**: `VulnRecord.Aliases` con el CVE canónico incluido.
- **Interfaces**: `+Upstream []string` en los OSV types; `Aliases =
  mergeUnique(Aliases, Upstream)` en `mapVuln`.
- **Dependencias**: ninguna (independiente).

### P4 — source/ecosystems: registry release-aware
- **Responsabilidad**: resolver el nombre de registry de distro y pegarle a
  ecosyste.ms.
- **Inputs**: `purl.Identity` completa (Kind/Distro/Release).
- **Outputs**: respuesta de ecosyste.ms para el paquete de distro, o
  `ErrSourceNotApplicable` cuando no hay registry resolvable.
- **Interfaces**: `registryName(purl.Identity) string` (ubuntu/debian numérico,
  alpine v-prefix) usando `Identity.ReleaseToken()`; `Fetch` usa la Identity
  completa + `OSVName` para el endpoint, no `registryByType[id.Type]`.
- **Dependencias**: P1.

### P5 — collect.go: refinar ErrSourceNotApplicable
- **Responsabilidad**: skip silencioso solo cuando no hay registry resolvable
  (sin release / type no cubierto), no para todo distro.
- **Inputs**: error de stage 1.
- **Outputs**: skip limpio vs `SourceError`.
- **Interfaces**: el branch en `collectStage1`.
- **Dependencias**: P4.

### P6 — store key release-scope (menor / opcional)
- **Responsabilidad**: evitar colisión de cache `noble`/`jammy` cuando el
  release es desconocido (con release ya queda scopeado por el sufijo del
  ecosystem).
- **Inputs**: `OSVQuery`.
- **Outputs**: store key linux release-scopeado.
- **Interfaces**: `OSVQuery.StoreKey()` (TODO task 022).
- **Dependencias**: P1.

## Flujos clave

1. **deb con `?distro=`**: `Parse` → `Decompose` (Identity+Release) → stage1
   `registryName → ubuntu-24.04` → fetch ecosyste.ms → stage2 OSV query
   `Ubuntu:24.04` → `pickAffected` tolerante → ranges → `dpkgMatcher` → `Group`
   (alias CVE del upstream merge) → CPER camina a NVD por el CVE.
2. **deb sin release**: ecosyste.ms `ErrSourceNotApplicable` (skip limpio) →
   OSV con ecosystem pelado → match.

## Datos
- `Identity`: +`ReleaseToken()`, `Release` también desde la versión.
- `OSVQuery`: +`BaseEcosystem`.
- OSV raw / `VulnRecord`: +`Upstream`, `Aliases` mergeados.

## Orden de implementación
1. **P1** — fundación (release tokens, base ecosystem, releaseFromVersion).
2. **P2** — `pickAffected` tolerante (bug principal "OSV no encuentra vulns").
3. **P3** — upstream merge (desbloquea CPER de distro).
4. **P4** — registry ecosyste.ms.
5. **P5** — refinar `ErrSourceNotApplicable`.
6. **P6** — store key (opcional).

## Decisiones abiertas
- Forma exacta del registry alpine en ecosyste.ms (`alpine-v3.19` vs
  `alpine-3.19`) — verificar contra la API.
- `OSVName` deb/rpm: binary name (Holmes) vs source package — dejamos binary,
  observamos fallos.
- `releaseFromVersion`: qué sufijos aceptar sin falsos positivos (Holmes marca
  `-2ubuntu10.9` como ambiguo).
- redhat/suse/fedora sin scoping OSV por release: el filtro tolerante puede
  traer múltiples releases. Aceptable por ahora.
