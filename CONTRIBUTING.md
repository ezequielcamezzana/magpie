# Contributing to magpie

Thanks for your interest! magpie is alpha, so things move — issues and PRs are welcome.

## Prerequisites

- **Go 1.26+** (see `go.mod`)
- git

No CGO is required — the SQLite driver (`modernc.org/sqlite`) is pure Go, so everything cross-compiles cleanly.

## Build & test

```sh
make build       # build the binary into ./bin/magpie
make test        # run the full suite
make vet         # static analysis (go vet ./...)
make fmt         # format the code (go fmt ./...)
make tidy        # tidy go.mod / go.sum
```

CI runs build + vet + test on every push and PR — keep them green.

## Run it locally

```sh
make run                         # run the server from source on :8080
./bin/magpie server              # or run the built binary

# trigger a collection
curl 'http://localhost:8080/collect?purl=pkg:npm/lodash@4.17.20'
```

The landing site is at `/`, the SPA at `http://localhost:8080/app`.

Some features need API keys (set them in `.env`, see [`.env.example`](.env.example)):

- `VULNCHECK_API_KEY` — required for CPE resolution (by-CVE NVD2 lookups).
- `NVD_API_KEY` — optional; raises NVD rate limits.

## Project layout

```
cmd/magpie/             # CLI entry point + command definitions (cobra)
internal/server/api/    # HTTP handlers (chi)
internal/server/collect/# the collect → match → group → persist pipeline
internal/server/match/  # version-range and CPE matching
internal/server/source/ # upstream clients: ecosyste.ms, OSV, NVD, VulnCheck
internal/server/purl/   # purl parsing and identity
internal/server/db/     # SQLite store + schema
internal/server/ui/     # embedded landing site + SPA
docs/                   # documentation
```

## Conventions

- **Match the surrounding style.** Run `gofmt`; keep changes small and focused.
- **Tests** for new packages and behavior. Server packages use an in-memory SQLite DB.
- **Commit messages**: short and descriptive. Prefixes like `docs:`, `test:`, `chore:` are filtered out of the release changelog, so use them for non-feature work.
- The frontend follows a flat black/white/grays design system (pills, no brand colors).

## Pull requests

1. Branch off `main`.
2. Make the change + tests; ensure `make build/vet/test` and `gofmt` pass.
3. Open a PR describing what and why. CI must pass before merge.

For security issues, **do not** open a public issue — see [SECURITY.md](SECURITY.md).
