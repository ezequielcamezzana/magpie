# Magpie — Design Document

> **Status:** Locked for implementation. New project at `~/Proyectos/magpie`.
> Holmes stays as-is; Magpie is a fresh module. Where useful, code is lifted
> from Holmes and rewritten for clarity. Anything still genuinely undecided is
> tagged **OPEN** at the bottom (§11).

Magpie is a Software Composition Analysis (SCA) library and small server. You hand
it a package coordinate; it scavenges everything it can find about that package —
metadata, repository, CPEs, vulnerabilities — from public sources, caches the raw
data, and returns an assembled result. The name follows the bird: a magpie collects
shiny things.

---

## 1. Guiding principles

- **Library first.** The core entry point is `magpie.Collect(...)`. The HTTP server
  is a thin wrapper over the library; anything the server can do, a Go consumer can
  do by calling the library directly.
- **No "investigation" concept.** No named runs, no save-the-whole-run flow, no
  investigation tables. Collect operates on a single coordinate at a time and writes
  raw enrichment into the cache.
- **Cache stores data, never calculations.** Raw per-source records are persisted.
  Match verdicts and canonical groupings are **always recomputed** on demand.
- **Best-effort, never fatal.** A source failing does not abort Collect. Failures
  are accumulated as structured, per-source errors and returned alongside partial
  results. Top-level `error` only on hard failures (nil pointer, programmer error,
  config invalid).
- **Simple and explained.** Where logic is intricate (version matching, CPE
  resolution), prefer the clearest possible code with comments explaining *why*,
  not the cleverest.
- **No confidence.** The Holmes 1–10 confidence scale and NVD penalty are gone.
  Match is binary.

---

## 2. Input model: PURL and SPURL

Magpie accepts two coordinate shapes:

- **PURL** — a full package URL **with** a version, e.g. `pkg:npm/chalk@1.0.0`.
- **SPURL** — a "stripped PURL", the PURL **without** a version, e.g. `pkg:npm/chalk`.

The version is what the match step compares against. When a SPURL is supplied
(no version), matching still runs but trivially matches every vulnerability (§6).

**Parsing.** Use `github.com/package-url/packageurl-go` (already used in Holmes).
A thin `pkg/purl` wrapper exposes `Parse`, `Strip` (purl → spurl), and
`Decompose` (spurl → name+ecosystem).

**Decomposition for OSV.** OSV is queried by `(name, ecosystem)`:

| purl type   | OSV ecosystem | Name rule                                              |
| ----------- | ------------- | ------------------------------------------------------ |
| `npm`       | `npm`         | `@<namespace>/<name>` if namespace present, else name  |
| `pypi`      | `PyPI`        | name                                                   |
| `golang`    | `Go`          | `<namespace>/<name>` (full module path, no scheme)     |
| `cargo`     | `crates.io`   | name                                                   |
| `gem`       | `RubyGems`    | name                                                   |
| `maven`     | `Maven`       | `<namespace>:<name>`                                   |
| `nuget`     | `NuGet`       | name                                                   |
| `composer`  | `Packagist`   | `<namespace>/<name>`                                   |
| `deb`       | `Debian:<v>`  | name (distro suffix only when present in qualifiers)   |
| `rpm`       | `<distro>`    | name; ecosystem from `distro` qualifier                |
| `apk`       | `Alpine:<v>`  | name; version suffix from `distro` qualifier           |

Lift the relevant chunks of Holmes' `pkg/domain/identity.go` (`IdentifyFromSPURL`)
into Magpie's `pkg/purl` and adapt — it already handles most of these cases.

---

## 3. The Collect flow

`Collect` runs a fixed, ordered pipeline for one coordinate. Each stage is
best-effort.

```
spurl/purl
   │
   ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. ecosyste.ms   → package + repository + advisory records  │  key: spurl / repo_url
├─────────────────────────────────────────────────────────────┤
│ 2. OSV           → vuln records by (name, ecosystem)        │  key: (name, ecosystem)
├─────────────────────────────────────────────────────────────┤
│ 3. CPER          → resolve CPE(s) from OSV's CVE aliases    │  key: spurl
│    (CPE Resolver) → walk each CVE's NVD config, accept CPEs │
├─────────────────────────────────────────────────────────────┤
│ 4. NVD           → vuln records by CPE                      │  key: CPE
└─────────────────────────────────────────────────────────────┘
   │
   ▼
 assemble raw records  →  group by canonical id (§5)  →  match per record (§6)
   │
   ▼
 Result { components, repository, cpes, grouped vulns + verdicts, errors[] }
```

### Stage detail

1. **ecosyste.ms** — single fetch yields **package metadata** (name, description,
   licenses, latest version, repo URL, icon), **repository data** (stars, forks,
   language, last push/release — folded into the same fetch, stored as its own
   row), and **advisory/vulnerability records**.
2. **OSV** — vuln records by `(name, ecosystem)`. OSV's CVE aliases feed CPER.
3. **CPER (CPE Resolver)** — the **only** CPE resolution path in Magpie (no
   cpe-guesser). For each `CVE-*` alias OSV surfaced, fetch NVD's CPE configuration
   and evaluate four signals (§3a) to accept a `(vendor, product)` CPE. Persists
   accepted CPEs with provenance: which CVE, which signals fired, NVD's declared
   vendor/product/target_sw, the package-side candidates compared against.
   Requires an NVD API key; without one the resolver is disabled and stage 4 is
   skipped.
4. **NVD** — vuln records, queried **only** by CPE. No CPE → no NVD query, and
   that is acceptable.

### 3a. CPER acceptance rule (locked)

Lifted from Holmes' `pkg/agents/cpe_nvd_learner.go`. Four signals collected
per candidate CPE, acceptance is the OR of three combinations.

**Signals**

| Signal      | Definition                                                                                                  |
| ----------- | ----------------------------------------------------------------------------------------------------------- |
| `name`      | NVD CPE's `product` ∈ package's name candidates (lowercased)                                                |
| `vendor`    | NVD CPE's `vendor` ∈ package's vendor candidates (lowercased)                                               |
| `ecosystem` | NVD CPE's `target_sw` non-wildcard AND equals the expected target_sw for the purl ecosystem (table below)   |
| `range`     | OSV affected ranges intersect NVD affected ranges (stratified — see below)                                  |

**`target_sw` per ecosystem** (rest fall back to other signals):

```
npm → node.js | pypi → python | gem → ruby | cargo → rust | composer → php | nuget → .net
```

**Range comparison is stratified by the product fingerprint:**

- If `name` fires (product matches a candidate) → accept any **shared concrete
  range** between OSV and NVD intervals.
- If `name` does not fire → require the stricter **OSV ⊆ NVD** subset (every
  OSV interval is contained in some NVD interval) to avoid attributing the CPE
  of an unrelated chain-CVE neighbor.

For Go ecosystem, normalize pseudo-versions on both interval sets before
comparing (Holmes' `match.NormalizeGoIntervals`).

**Acceptance** — accept the CPE iff any one of:

```
(name AND vendor)             // full lexical match
OR (name AND ecosystem)       // product + target_sw pinning
OR range                      // stratified per above
```

**Per-CVE & per-call bounds:**

- `learnerMaxLookups = 5` — cap on NVD CVE fetches per Collect call.
- Stop scanning subsequent CVEs as soon as at least one CPE is accepted for the
  current CVE (per-CVE early stop). Continue across CVEs only when the current
  CVE yielded nothing.
- A failed NVD lookup for one CVE never aborts the loop.

**Provenance recorded per accepted CPE:**

```go
type ResolvedCPE struct {
    CPE         string   // "cpe:2.3:a:vendor:product:..."
    CVE         string   // originating CVE
    MatchedBy   []string // subset of {"name","vendor","ecosystem","range"}
    NVDVendor   string
    NVDProduct  string
    NVDTargetSw string   // when ecosystem signal fired
    NVDRanges   []string // when range signal fired
    OSVRanges   []string // when range signal fired
    Ecosystem   string
    Names       []string // package-side name candidates
    Vendors     []string // package-side vendor candidates
}
```

> **OPEN — future.** What to do when a package has an affected-versions list but
> no ranges. Deferred. Documented here so we don't forget it (§11).

### Name & vendor candidates (input to CPER)

Lifted from Holmes' `pkg/detectives/candidates.go`, unchanged in spirit:

- vendor: purl `type`, namespace first segment, repo owner, every name candidate
  (covers self-named upstreams like `lodash/lodash`).
- name: purl `name`, namespace last segment, repo name.

Repo data (when ecosyste.ms returned it) wins; the repo URL path is the fallback.
All values lowercased & deduped.

### Ordering & concurrency

- Strict order: **ecosyste.ms → OSV → CPER → NVD** (NVD needs a CPE; CPER needs
  OSV's CVE aliases).
- **Single coordinate per Collect** for now. ecosyste.ms and OSV *could* run in
  parallel (OSV doesn't consume ecosyste.ms output) — defer until a real benchmark
  asks for it. CPER is the forced convergence point.

### Signature & config

```go
package magpie

type Config struct {
    NVDAPIKey  string         // CPER + NVD stages skipped when empty
    Store      Store          // §7
    HTTPClient *http.Client   // default: http.DefaultClient with sane timeouts
    MaxAge     time.Duration  // freshness threshold; 0 = always refetch

    // Per-source toggles. Default zero value = enabled. Disabling a source
    // skips its fetch and emits a structured "disabled" SourceError so the
    // caller can tell "skipped on purpose" from "broke".
    Disable struct {
        Ecosystems bool
        OSV        bool
        CPER       bool
        NVD        bool
    }

    // Per-source timeouts. Zero = use a sensible default (5s).
    Timeouts struct {
        Ecosystems time.Duration
        OSV        time.Duration
        NVD        time.Duration
    }
}

func Collect(ctx context.Context, coord string, cfg Config) (*Result, error)
```

**Freshness is caller-controlled.** Collect passes `cfg.MaxAge` to every store
read; stores compare the row's `fetched_at` against `now - MaxAge`. Stores never
embed a hardcoded TTL. Default in the server wrapper: 24h.

### Errors

Failures are **structured and per-source**, not panicked. Partial results coexist
with a non-empty `Result.Errors`:

```go
type SourceError struct {
    Source string    // "ecosyste.ms" | "osv" | "cper" | "nvd"
    Kind   string    // "disabled" | "timeout" | "http" | "parse" | "auth" | "other"
    Err    error
}

// Result.Errors []SourceError
```

The top-level `error` return is `nil` for the normal partial-failure case
(everything went to `Errors`). It is non-nil only for **hard failures**: invalid
config, invalid coordinate (parse error), nil store, or anything that would
otherwise be a panic.

---

## 4. Sources summary

| Source       | Queried with        | Contributes                                | Cache key            |
| ------------ | ------------------- | ------------------------------------------ | -------------------- |
| ecosyste.ms  | `spurl`             | package + repo + advisories                | `spurl` / `repo_url` |
| OSV          | `(name, ecosystem)` | vuln records; CVE aliases feed CPER        | `(name, ecosystem)`  |
| CPER → NVD   | `spurl` → `CPE`     | resolved CPE(s) with provenance; NVD vulns | `spurl` / `CPE`      |

### ecosyste.ms canonical identifier

The ecosyste.ms advisories endpoint returns records with an `identifier` field
(typically `GHSA-...`, `CVE-...`, or `PYSEC-...`) plus an `aliases` array. The
canonical-ID derivation (§5) prefers any `CVE-...` value found in
`{identifier} ∪ aliases`; otherwise the record keeps its own identifier.

---

## 5. Canonical grouping

Every vulnerability belongs to a **canonical group**. Grouping is a **pure
function over a set of raw records** with no I/O:

```go
func Group(records []VulnRecord) []CanonicalGroup
```

Called the same way by Collect and by read paths needing grouping (§8) — **one**
grouping implementation, never two.

### Canonical ID derivation

- Canonical ID is a **CVE** (`CVE-YYYY-NNNN`) when one exists in the record's
  IDs/aliases:
  - **OSV** — search `id`, `aliases`, `upstream`.
  - **NVD** — `id` is already a CVE.
  - **ecosyste.ms** — search `identifier`, `aliases`.
- **No CVE present** → canonical ID is the record's **own original ID**
  (e.g. `GHSA-...`, `PYSEC-...`).
- **Multiple CVE candidates on one record** → pick **one deterministically:
  newest CVE wins** (compare by year, then number; `CVE-2023-0001` beats
  `CVE-2009-9999`). Acknowledged as imperfect; acceptable.

### Group shape

```go
type CanonicalGroup struct {
    CanonicalID string        // chosen canonical ID
    MaxScore    float64       // max CVSS score across all records (ties don't matter)
    Records     []VulnRecord  // every member, full per-source payload retained
}
```

Non-matching records are retained for granularity; they just aren't decisive
in the verdict (§6 level 2).

---

## 6. Matching

Matching answers: *is the requested version affected by this vulnerability?* It
always runs (never bypassed), and is **recomputed fresh every Collect** — match
results are never cached.

### Two levels

- **Level 1 — per-record.** Each raw record carries its own affected-version data
  (lists + ranges). Match the requested version against **each record
  independently**, producing `matched: bool`, `reason`, `range`, `next_fix`,
  `warnings`. No score.
- **Level 2 — canonical roll-up.** A canonical group is affected if **any**
  member record matched (OR logic). Verdict is **binary**.

### No version (SPURL) case

When no version is supplied, matching still runs and trivially matches everything:
each entry is `matched: true, reason: no_version_specified`. SPURL results count
as affected, consistently.

### Reason codes

| Reason                       | Matched | Meaning                                                       |
| ---------------------------- | ------- | ------------------------------------------------------------- |
| `no_version_specified`       | ✓       | No version provided — matches all versions                    |
| `unsupported_version_scheme` | ✗       | Unknown ecosystem and not valid semver — cannot evaluate      |
| `in_unaffected_list`         | ✗       | Explicitly unaffected                                         |
| `in_fixed_list`              | ✗       | Explicitly fixed                                              |
| `in_affected_list`           | ✓       | Exactly listed as affected                                    |
| `not_in_affected_list`       | ✗       | Version list exists, version not in it, no ranges to check    |
| `in_affected_range`          | ✓       | Within an affected semver interval                            |
| `not_in_affected_range`      | ✗       | Ranges exist, version outside all of them                     |
| `no_evidence`                | ✗       | Record carries no range or list data                          |

### Evaluation order (per record)

Checks run in order; **return immediately only on a positive finding** (match or
definitive clear). Negative intermediates never short-circuit — both the
affected-versions list and the affected-ranges list are always checked:

1. version in `unaffected_versions` → clear (`in_unaffected_list`)
2. version in `fixed_versions` → clear (`in_fixed_list`)
3. version in `affected_versions` → **matched** (`in_affected_list`)
4. version in any `affected_ranges` entry → **matched** (`in_affected_range`)
5. otherwise → not matched (`not_in_affected_range` if ranges existed,
   `not_in_affected_list` if only a list existed, else `no_evidence`)

A vuln carrying both a list and ranges is evaluated against **both** — a version
absent from the list can still match via a range.

### Ecosystem matchers (`pkg/match`)

Lifted from Holmes, rewritten simply. Comparison is delegated to a matcher chosen
by `match.For(source, ecosystem)`:

| Ecosystem / Source | Matcher         | Notes                                                                       |
| ------------------ | --------------- | --------------------------------------------------------------------------- |
| `go`               | `goMatcher`     | `golang.org/x/mod/semver`; Masterminds fallback for non-standard bounds     |
| `npm`              | `npmMatcher`    | Masterminds semver                                                          |
| `pypi`             | `pypiMatcher`   | Masterminds semver                                                          |
| `deb` / `rpm`      | `dpkgMatcher`   | Lift Holmes' dpkg comparator                                                |
| everything else    | `semverMatcher` | Masterminds semver                                                          |
| `nvd` (any eco)    | `semverMatcher` | NVD always uses semver regardless of the ecosystem field                    |

Invariants: strip build metadata before comparison; **never assume-affected** on
an unparseable version or bound — return `unsupported_version_scheme` or leave
the range unmatched rather than silently treating the package as vulnerable.

---

## 7. Storage & cache

Everything Magpie collects is stored in a database and reused as a cache.

- **Freshness is caller-controlled** via `Config.MaxAge` (§3).
- **Per-type freshness.** A Collect checks each type's age independently and
  refetches only the stale types. (A 3h-old component with 30h-old vulns →
  reuse component, refetch vulns, assuming `MaxAge=24h`.)
- **Cache stores raw data only** — never grouped output, never match verdicts.

### Tables (keys)

| Table          | Key                          | Notes                                                                          |
| -------------- | ---------------------------- | ------------------------------------------------------------------------------ |
| `components`   | `spurl`                      | package metadata                                                               |
| `repositories` | `repo_url`                   | separate rows (two packages can share a repo)                                  |
| `cpes`         | `spurl`                      | resolved CPE(s) + CPER provenance                                              |
| `vulns`        | `(source, query_key)`        | raw per-source records; `canonical_id` is an **indexed column**, *not* the key |

The vuln cache is keyed by **what query produced the record**, because a single
canonical group is assembled from records fetched by *different* queries:

- OSV record → found by `(name, ecosystem)`
- NVD record → found by `CPE`
- ecosyste.ms record → found by `spurl`

`canonical_id` is indexed for `/vulnerabilities` search and grouping at read
time, but grouping is never persisted.

### Store interface

```go
package store

type Result[T any] struct {
    Value T
    FetchedAt time.Time
    Found     bool
}

type Store interface {
    // Components / repositories / cpes — one row per key.
    GetComponent(ctx context.Context, spurl string) (Result[Component], error)
    PutComponent(ctx context.Context, c Component) error

    GetRepository(ctx context.Context, repoURL string) (Result[Repository], error)
    PutRepository(ctx context.Context, r Repository) error

    GetCPEs(ctx context.Context, spurl string) (Result[[]ResolvedCPE], error)
    PutCPEs(ctx context.Context, spurl string, cpes []ResolvedCPE) error

    // Vulns — query keyed by (source, queryKey); replaces the whole set per key
    // on Put so stale records don't linger.
    GetVulns(ctx context.Context, source, queryKey string) (Result[[]VulnRecord], error)
    PutVulns(ctx context.Context, source, queryKey string, vs []VulnRecord) error

    // Read-side query for the /vulnerabilities endpoint.
    QueryVulns(ctx context.Context, q VulnQuery) ([]VulnRecord, int, error)

    Close() error
}

type VulnQuery struct {
    // OR'd across record's own ID and canonical_id columns.
    ID    string
    Page  int
    Limit int
}
```

**Freshness lives at the caller**, not in the Store. The Store returns
`FetchedAt`; Collect compares to `MaxAge`. This keeps the Store dumb and
testable, and lets the caller override TTL per call.

**Default implementation: SQLite** (`modernc.org/sqlite`, already used by
Holmes — no CGO).

---

## 8. HTTP API

Thin wrappers over the library. Basic `page`/`limit` pagination on list
endpoints. JSON throughout.

### `GET /collect?purl=…` (or `?spurl=…`)

Runs the library `Collect`. Cache-first and idempotent, hence GET. Returns the
assembled `Result` — components, repository, cpes, **grouped** vulns with match
verdicts, and the `errors[]` array.

### `GET /vulnerabilities`

Returns **flat raw vuln records** (NOT grouped). Paginated.

| Param   | Default | Description                                              |
| ------- | ------- | -------------------------------------------------------- |
| `id`    | —       | match record ID **or** canonical ID (OR'd across both)   |
| `page`  | `1`     | page number                                              |
| `limit` | `25`    | results per page (max 100)                               |

One filter param (`id`) matches both columns — searching `GHSA-xxxx` finds
records whose canonical is a CVE; searching `CVE-2024-1234` finds it whether
that's the canonical or just an alias on a member record.

### `GET /components`

Returns the **full bundle** per component — component + repository + cpes +
**grouped** vulns. Paginated. Filter by `spurl`.

> The component bundle and the Collect result share a serializer / response
> type.

> **Note — grouped-vuln pagination.** Grouping happens *after* reading raw rows,
> so paging grouped vulns is not a plain `LIMIT/OFFSET`. The component bundle's
> nested vulns are bounded per-component, so this is fine. If a top-level
> grouped+paginated list is ever needed, paginate over
> `SELECT DISTINCT canonical_id` then hydrate each page — do **not** page raw
> rows and group, as a group could straddle a page boundary. `/vulnerabilities`
> avoids this entirely by returning flat records.

### `GET /cpes?spurl=…`

Returns the resolved CPE(s) for a package **with CPER provenance** (`MatchedBy`
signals, originating CVE, NVD-declared vendor+product+target_sw, package-side
candidates, OSV/NVD ranges when range signal fired).

### Server-only knobs

The server wrapper applies sane defaults on top of the library Config:

- `MaxAge` default = 24h, overridable via env (`MAGPIE_MAX_AGE`).
- `NVDAPIKey` from `NVD_API_KEY` env.
- `HTTPClient` with 5s per-source timeouts, 15s overall ceiling per Collect.

---

## 9. Frontend

A small single-file **Alpine.js** SPA, **no build step**, served by the same
binary. Chart.js via CDN only where it actually helps (the FE is a **research
bucket**, not a monitoring dashboard — favor search and drill-down over summary
widgets).

Four pages:

1. **Main / Collect** — input box; paste a purl or spurl, run collect, display
   the assembled result inline (components, repo, cpes, grouped vulns with
   verdicts).
2. **Components** — browse the component cache; each component shows repo +
   cpes + its **grouped** vulns (drill-down).
3. **Vulnerabilities** — browse/search the flat vuln records; filter by
   ID/canonical ID.
4. **CPEs** — browse CPEs with their CPER provenance.

Assets embedded via `//go:embed` so the binary is self-contained.

---

## 10. Package layout

```
magpie/
  go.mod                  // module github.com/ezequielcamezzana/magpie
  cmd/magpie/main.go      // server entry point (no CLI subcommands)

  collect.go              // Collect(ctx, coord, cfg) — orchestrates the pipeline
  config.go               // Config struct
  result.go               // Result, CanonicalGroup, VulnRecord, SourceError, ...
  group.go                // Group(records) []CanonicalGroup — pure, shared

  pkg/
    purl/                 // Parse / Strip / Decompose (wraps packageurl-go)
    match/                // ecosystem matchers + match.For(source, ecosystem)

  source/
    ecosystems/           // ecosyste.ms client
    osv/                  // OSV client
    nvd/                  // NVD client
    cper/                 // CPE Resolver (NVD-config walking, §3a)

  store/
    store.go              // Store interface + types
    sqlite/               // default implementation (modernc.org/sqlite)

  httpapi/                // GET /collect, /vulnerabilities, /components, /cpes
  web/                    // single-file Alpine.js SPA + embedded assets
```

### Code reuse from Holmes (explicit map)

| Holmes path                            | Magpie path             | Disposition                                                        |
| -------------------------------------- | ----------------------- | ------------------------------------------------------------------ |
| `pkg/parser/purl.go`                   | `pkg/purl/`             | Lift, expand with `Strip` + `Decompose`                            |
| `pkg/domain/identity.go`               | `pkg/purl/identity.go`  | Lift; trim to ecosystem mapping (no Clue/Detective types)          |
| `pkg/domain/types.go`                  | `result.go` + sources   | Lift the data shapes (CPE, Vuln, Component); drop confidence       |
| `pkg/match/*`                          | `pkg/match/`            | Lift, simplify, **drop confidence-bearing branches**               |
| `pkg/detectives/candidates.go`         | `source/cper/`          | Lift unchanged in spirit; reshape into CPER inputs                 |
| `pkg/agents/cpe_nvd_learner.go`        | `source/cper/`          | Lift the 4-signal acceptance rule + Go pseudoversion normalization |
| `pkg/agents/osv.go`                    | `source/osv/`           | Rewrite (smaller surface, no agent interfaces)                     |
| `pkg/agents/nvd.go`                    | `source/nvd/`           | Rewrite                                                            |
| `pkg/archivist/*`                      | `store/sqlite/`         | **Replace** — new schema, new Store interface                      |
| `pkg/detectives/*` (orchestration)     | `collect.go`            | **Replace** — pipeline becomes plain stages                        |
| `pkg/assembly/*`, `pkg/bureau/*`       | —                       | **Delete** — no archiver/detective concept in Magpie               |
| `internal/server/*`                    | `httpapi/`              | Rewrite around new endpoints                                       |
| `ui/*`                                 | `web/`                  | Rebuild as 4-page Alpine SPA (no build step)                       |

---

## 11. Open items (deferred — not blockers)

1. **Affected-versions list with no ranges.** What CPER should do when a package
   has an affected-versions list but no ranges. Punted to a follow-up.
2. **ecosyste.ms response shape verification.** §4 documents the expected
   `identifier`/`aliases` fields based on Holmes' usage; verify against a live
   response before locking the canonical-ID derivation.
3. **Parallelism inside Collect.** Running ecosyste.ms and OSV concurrently is
   possible (OSV doesn't consume ecosyste.ms output). Defer until a benchmark
   asks for it; current sequential ordering is the baseline.
4. **Pagination over grouped vulns at top level.** Only needed if a
   `/vulnerabilities?grouped=true` endpoint is ever added. Strategy sketched
   in §8.
5. **Postgres store.** The `Store` interface is small enough that a Postgres
   backend is thinkable; SQLite is the only implementation shipped now.
