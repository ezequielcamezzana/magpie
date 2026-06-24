# How magpie works

magpie is a single HTTP server. You hand it a [purl](https://github.com/package-url/purl-spec) (package URL) and it runs the **collect pipeline**, persists the result in SQLite, and serves it back over the API and embedded UI.

## The collect pipeline

`internal/server/collect.Collect` runs four stages for a given purl:

1. **Collect** — query upstream sources for the component and its known vulnerabilities:
   - [ecosyste.ms](https://ecosyste.ms) — package/repo metadata and ecosystem advisories.
   - [OSV](https://osv.dev) — open-source vulnerability records.
   - [NVD](https://nvd.nist.gov) — NVD vulnerability data (by CPE).
   - [VulnCheck](https://vulncheck.com) — NVD2 index used to resolve CPE configurations by CVE.
2. **Match** — resolve affected version ranges and CPEs against the requested version (`internal/server/match`). Semver, dpkg, and Go pseudo-version comparisons are handled per ecosystem.
3. **Group** — deduplicate and group vulnerabilities by their canonical CVE.
4. **Persist** — store components, CPEs, and vulnerabilities in SQLite (`internal/server/db`).

## Caching & freshness

Each source result is cached in the DB with a per-type max age (`MAGPIE_MAX_AGE_*`). A request re-fetches a source only when its cached data is older than that age. A per-source live-fetch budget (`MAGPIE_SOURCE_BUDGET`) bounds how long any one source can block a `/collect` call — if it's exceeded, the stage falls back to cached data (even if stale) with a non-fatal warning.

An opt-in background **updater** (`MAGPIE_UPDATER_ENABLED`) periodically re-collects the oldest stale packages without the cache, keeping stored data fresh.

## Package layout

```
cmd/magpie/             # CLI (cobra): magpie server / magpie version
internal/server/api/    # HTTP handlers (chi) for collect, components, vulnerabilities, cpes
internal/server/collect/# the collect → match → group → persist pipeline
internal/server/match/  # version-range and CPE matching per ecosystem
internal/server/source/ # upstream clients: ecosystems, osv, nvd, vulncheck
internal/server/purl/   # purl parsing and identity
internal/server/db/     # SQLite store + schema.sql
internal/server/ui/     # embedded landing site (/) and SPA (/app)
internal/server/config/ # environment-variable configuration
internal/server/updater/# background passive refresh
```

## Configuration

All configuration is read from environment variables — see [`.env.example`](../.env.example) and the table in the [README](../README.md#configuration).
