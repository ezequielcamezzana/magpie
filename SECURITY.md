# Security Policy

> [!NOTE]
> magpie is **alpha** and built for research purposes. Treat it accordingly: it has not had a formal security audit, and the model below describes the *current* state, not a hardened product.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue.

Email **ezequielcamezzana@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected version / commit.

You'll get a best-effort acknowledgement. Given the alpha status, fixes are handled on a best-effort basis with no formal SLA. Please allow reasonable time for a fix before any public disclosure.

## Supported versions

Only the **latest release** is supported. Fixes land on `main` and ship in the next tag.

## Security model & operator responsibilities

magpie is a server that fetches from upstream sources and exposes an HTTP API with no built-in authentication. Operators are responsible for the surrounding controls:

- **No built-in auth or TLS.** Anyone who can reach the server can drive the API. Run it on a trusted/internal network and terminate TLS at a reverse proxy (nginx/Caddy). Don't expose it over plaintext HTTP on untrusted networks.
- **API keys are secrets.** `VULNCHECK_API_KEY` and `NVD_API_KEY` live in environment variables / `.env`, which is git-ignored. Never commit `.env`, API keys, or the database.
- **Outbound requests.** magpie queries third-party services (ecosyste.ms, OSV, NVD, VulnCheck) with the purls you submit. Be aware of what you send if those queries are sensitive.
- **The database is local state.** `magpie.db` holds the components and vulnerabilities you've collected; protect it like any other local data store.

## What magpie does *not* do

- It never runs package managers, never scans filesystems, and never executes external scanners.
- It does not (yet) cover everything you'd expect from a production-grade security tool — see the scope notes in the [README](README.md).
