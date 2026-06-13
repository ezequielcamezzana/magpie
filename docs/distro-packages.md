# Distro packages (deb / rpm / apk): what Holmes does and what Magpie is missing

An observation doc, not a closed design. It captures how Holmes resolves
ecosyste.ms + OSV + matching for Linux distro packages, and where Magpie falls
short. Use it as a reference for porting the behavior.

## The symptom

```
pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.4
  → ecosyste.ms (other): no registry for purl type
  → no vuln matching
```

In Holmes the same package: ecosyste.ms finds it and vuln matching runs.

## Why — the missing piece

ecosyste.ms **does** have distro registries, but they are **scoped per release**:
`ubuntu-24.04`, `debian-12`, `alpine-v3.19`. The registry name embeds the
release. Holmes builds it; Magpie does not.

| Step | Holmes | Magpie today |
| --- | --- | --- |
| Registry name | `EcosystemsRegistry(id)` → `ubuntu-<ver>` / `debian-<ver>` / `alpine-<rel>` | `registryByType[id.Type]` — only 8 languages; `deb`/`rpm`/`apk` are absent → `ErrNoRegistry` |
| Endpoint name | `OSVName(id)` (npm scoped, go module path, maven `g:a`) | raw `id.Name` |
| Release | extracted from qualifiers/version, canonicalized to codename, embedded in the SPURL (`pkg:deb/ubuntu/curl/noble`) | `Identity.Release` exists and is canonicalized, but is **not** used for the registry or the store key |

## How Holmes does it (end-to-end)

Source: `holmes/pkg/domain/identity.go`, `holmes/pkg/agents/ecosystems.go`,
`holmes/pkg/agents/osv.go`.

### 1. Normalized identity (`identity.go`)

- **SPURL extended with the release** as an extra segment:
  `pkg:deb/ubuntu/curl/noble`. It is not a valid PURL — it's a storage
  convention so that `noble` vs `jammy` don't collide in the cache. `QueryPURL()`
  trims it before calling external APIs. (`Identity` lines 18-36, `composeSPURL`,
  `IdentifyFromSPURL`, `QueryPURL`.)
- **Release** comes from, in order: qualifiers (`distro`, `distro_version`,
  `release`, `os_distro`, `os_release`), otherwise from the version when the
  pattern is unambiguous (`+debNN`, `~bpoN`, `.elN`, `.fcNN`). Ambiguous suffixes
  like `-2ubuntu10.9` → `""`. (`extractRelease`, `releaseFromVersion`.)
- **Canonicalization** to codename: `deb12`/`12`/`bookworm` → `bookworm`,
  `24.04.1` → `noble`, alpine forces a `v`-prefix. (`canonicalizeRelease`,
  `numericToCodename`.)
- **Classification** by `(type, namespace)`: `{deb,ubuntu}`→`Ubuntu`,
  `{deb,debian}`→`Debian`, `{apk,alpine}`→`Alpine`, `{rpm,fedora}`→`Fedora`, …
  It also parses `pkg:deb/ubuntu-noble/curl` (namespace `<distro>-<release>`).
  (`linuxEcosystems`, `splitNamespaceDistro`.)

### 2. ecosyste.ms (`ecosystems.go` + `EcosystemsRegistry`)

```go
registry := domain.EcosystemsRegistry(id)   // "ubuntu-24.04", "" if it doesn't map
if registry == "" { return ErrNotFound }
url := base + registry + "/packages/" + OSVName(id)
```

`EcosystemsRegistry` (`identity.go:133`):
- Language → `languageRegistries[type]`.
- Linux **with a known release** → `ubuntu-<ver>` / `debian-<ver>` /
  `alpine-<rel>`. **Without a release → `""`** (the name can't be built, so
  ecosyste.ms is skipped and we rely on OSV).

### 3. OSV (`osv.go:78`)

- Query: `{"ecosystem": OSVQueryString(id), "name": OSVName(id)}`.
  `OSVQueryString` → `"Ubuntu:24.04"`, `"Debian:12"`, `"Alpine:v3.19"`, or the
  bare ecosystem when the distro isn't release-scoped (SUSE, Fedora).
- Filtering the response: OSV returns more specific forms than the query
  (`"Ubuntu:24.04:LTS"`, `"Red Hat:enterprise_linux:8::baseos"`). It filters by
  `HasPrefix(ecosystem, id.Ecosystem)` + `Contains(ecosystem, OSVReleaseToken(id))`.
  (`OSVReleaseToken`, `identity.go:530`.)

### 4. Matching

Distro versions are compared with the **dpkg** algorithm (not semver).

## Magpie's status (file:line)

- `source/ecosystems/client.go:75` — `registryByType[id.Type]`: no distro
  entries, and keyed by `type` instead of the release-aware registry. **Main gap.**
- `source/ecosystems/client.go:35` — `registryByType` languages only.
- No equivalent of `EcosystemsRegistry(Identity)` exists.
- `pkg/purl/identity.go` — `Identity` already has `Kind/Distro/Release` and
  canonicalizes them. ✅ The raw material is there.
- `pkg/purl/purl.go` `Strip` — preserves `?distro=&arch=` for linux, but the
  SPURL is **not** extended with the release; the OSV linux store key is **not**
  release-scoped (`osvquery.go` `StoreKey`, TODO task 022) → `noble`/`jammy`
  collide in the cache.
- `pkg/purl/osvquery.go` — the OSV query *descriptor* per release is **already**
  ported (`OSVQuery`, `releaseToken`, `osvSuffix`, `codenameToNumeric`). ✅
- `source/osv/client.go:55` — **but the client never runs the Linux query**:
  `case purl.KindLinux: return nil, nil` (TODO task 022). OSV queries nothing for
  distros → 0 vulns. The `KindLanguage` path (`queryLanguage`) already does the
  right POST; `KindLinux` only needs to route to the same query (the response is
  already filtered release-aware by `pickAffected`). **Real blocker for distros.**
- `pkg/match/match.go:49` — `For` already selects `dpkgMatcher` for deb/ubuntu/rpm. ✅
- `collect.go` (this branch) — I added `ErrSourceNotApplicable`: it silences the
  error but **is the opposite of the goal** for distros with a release. For those
  we want to hit ecosyste.ms, not skip. It only works as a fallback for types
  genuinely not covered (or without a release).

## OSV finds no vulns for Linux — 2 Holmes tricks

Beyond the ecosyste.ms registry, OSV matching for distros fails for two reasons
that Holmes handles and Magpie doesn't.

### Trick 1 — release-tolerant `affected[]` filtering

OSV `/v1/query` with `ecosystem:"Ubuntu:24.04"` returns vulns whose `affected[]`
array mixes **several releases/distros** (Ubuntu 22.04, 24.04, Debian, upstream,
…). You have to pick the entry for the correct release.

- **Holmes** (`osv.go:100-118`): for Linux it does NOT use exact ecosystem
  equality. It filters with `HasPrefix(aff.Ecosystem, id.Ecosystem)` (bare
  ecosystem, e.g. `"Ubuntu"`) + `Contains(aff.Ecosystem, OSVReleaseToken(id))`
  (release substring, e.g. `"24.04"`). This tolerates a response more specific
  than the query (`"Ubuntu:24.04:LTS"`, `"Red Hat:enterprise_linux:8::baseos"`).
- **Magpie** (`source/osv/client.go:171`): `pickAffected` requires
  `p.Name == q.Name && EqualFold(p.Ecosystem, q.Ecosystem)`. Query
  `"Ubuntu:24.04"` vs response `"Ubuntu:24.04:LTS"` → no match → falls back to
  `affected[0]` (line 175), which may be **another release/distro** → wrong
  ranges → dpkg doesn't match. On top of that `q.ReleaseToken` is already
  computed in `OSVQuery` but the client **never uses it**. **This is the main
  "OSV finds no vulns" bug.**

### Trick 2 — merging `upstream` into aliases

`DEBIAN-CVE-*` entries (and several Ubuntu ones) leave `aliases` empty and put
the canonical CVE in OSV's `upstream` field.

- **Holmes** (`osv.go:283-286`): `Aliases = mergeUniqueIDs(v.Aliases, v.Upstream)`.
  Without this the distro vuln has no CVE alias → the CPE learner can't walk to
  NVD and alias-grouping can't dedupe against the canonical entry.
- **Magpie** (`source/osv/types.go`, `client.go:136`): doesn't parse `upstream`,
  just `Aliases: v.Aliases`. The field and the merge are missing.

(Bonus already present in both: skipping `GIT` ranges —commit SHAs, not
versions— in the mapping; `source/osv/client.go:153`. ✅)

## What's left to port

1. `EcosystemsRegistry(purl.Identity) string` in `pkg/purl` (or in the client):
   linux with a release → `ubuntu-<ver>` / `debian-<ver>` / `alpine-<rel>`.
2. `source/ecosystems` uses the full `Identity` (Kind/Distro/Release) and
   `EcosystemsRegistry`, not `registryByType[id.Type]`. Endpoint with `OSVName(id)`.
3. Pass the `Identity` (or a release-extended SPURL) down to stage 1 — today the
   client receives the `Strip` and re-decomposes; verify the release survives.
4. Release-scope the linux store key (TODO task 022) so the cache doesn't collide.
5. Revisit `ErrSourceNotApplicable`: keep it only for "no release / uncovered
   type", not for every distro.
6. **Release-tolerant `pickAffected` for Linux** (the main OSV bug):
   instead of `EqualFold(ecosystem)`, use `HasPrefix(aff.Ecosystem, id.Ecosystem)`
   + `Contains(aff.Ecosystem, q.ReleaseToken)`. Use the `ReleaseToken` that
   `OSVQuery` already computes. No real match → `nil`, not `affected[0]`.
7. **Parse + merge `upstream`**: add `Upstream []string` to the OSV types and
   `Aliases = mergeUnique(v.Aliases, v.Upstream)` in `mapVuln`.

## Taxonomy Kind → match source (CPE vs PURL)

Design insight (curl smoke test): **CPE identifies the upstream code; a PURL can
point to a *distribution* of that code.** Hence which vulnerability source is
correct per `Kind`:

| Kind | What it is | Correct source |
| --- | --- | --- |
| Language (npm/pypi/conan/…) | a package from an ecosystem | OSV(ecosystem) **+ CPE/NVD** (same version scheme) |
| Linux (deb/rpm/apk) | a *distribution* of the code | **OSV(distro)**. NOT CPE: the distro backports fixes → applying upstream NVD ranges gives **false positives** |
| GitHub | the upstream repo | OSV(GIT) |
| generic | the bare upstream code | CPE/NVD *would be* correct, but **we can't bootstrap it** |

### Why CPE is wrong for distros (not just hard)

Smoke test CVE-2023-38545 / curl:
- NVD `haxx:libcurl` **upstream** range `[7.69.0, 8.4.0]`, fixed upstream `8.4.0`.
- OSV `Debian:12 curl` **Debian** range `[*, 7.88.1-10+deb12u4)` (`introduced:0`
  → unbounded-below), fixed = backport `7.88.1-10+deb12u4`.
- The range logic is fingerprint-equivalence (same interval), not overlap.
  Different schemes + a backported fix ≠ the upstream fix → `subset=false`,
  `shareConcrete=false` (verified). And `vendor=haxx` is not a derivable
  candidate.
- Conclusion: applying CPE/NVD to a distro package would flag as vulnerable
  something already fixed by a backport. That's why CPER is **gated** for
  `KindLinux` (task 010). Holmes has the same limitation (its learner is
  `name+vendor OR range`).

### generic: out of scope (decision)

`pkg:generic/...` is upstream code → CPE *would be* the ideal source (the opposite
of distro). But the architecture doesn't get there:
- CPER needs a **seed CVE** from OSV to walk to NVD. Generic has neither
  OSV-by-ecosystem nor OSV-by-distro → no seed.
- The alternative (name→CPE, cpe-guesser) was **rejected by the DD** ("CPER is the
  only CPE path").

Decision: **generic is out of scope for now.** Future paths if revisited:
(a) generic with `?vcs_url=`/repo → OSV-GIT; (b) reintroduce a scoped cpe-guesser
for KindOther (requires `/design`, contradicts the current DD).
