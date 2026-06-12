# UI kit — `advisories` (research tool)

A high-fidelity, interactive recreation of a **vulnerability / advisory tracker**
built entirely on the "Ollama, smaller" design system. This is the canonical
application of the system — the severity palette and CVSS buckets in the tokens
exist for exactly this kind of tool.

It is a **cosmetic recreation**, not production code: data is static
(`data.js`), the "scan" is faked, and sign-in just flips a flag. The point is
pixel-faithful, reusable components.

## Run
Open `index.html`. Loads `tokens.css` → `base.css` → `ring.css` → `app.css`,
then React + Babel and the component scripts.

## Interactions
- **Filter bar** — search, severity filter, sort (severity / newest); pager sits
  above the list and is wired to real pagination.
- **Advisory card → detail** — click any card to open the detail view (key/value
  grid, summary, collapsible remediation with a code block). "‹ All advisories"
  returns.
- **New scan** — opens a modal (dark scrim = the one "look here" elevation). Run
  scan with a package name that matches the data (e.g. `openssl`) to jump to its
  advisory.
- **Sign in** — flips the nav action to a "signed in" badge.

## Components
| File | What it is |
|---|---|
| `Topbar.jsx` | Logo + wordmark + plain-text nav (active underlined) + actions. |
| `Summary.jsx` | Severity donut (`renderRing`) + totals on a hairline card. |
| `AdvisoryList.jsx` | Filter bar + above-data pager + advisory card list. |
| `AdvisoryDetail.jsx` | Single advisory: kv grid, summary, collapsible remediation. |
| `NewScanModal.jsx` | Modal with pill inputs + ink primary action. |
| `VulnCard.jsx` | Single advisory card — `OriginalID (CanonicalID)` + CVSS & source pills, GitHub/OSV links, published & updated dates (no description). |
| `ComponentCard.jsx` | Dependency/component square grid tile — icon + GitHub link (top), name, version, ecosystem pill. GitHub link only when `RepoUrl` exists. |
| `GroupedVulnCard.jsx` | Canonical advisory (root) with collapsible per-source children. |
| `Footer.jsx` | Meta left, Lucide link glyphs right. |
| `data.js` | Static sample advisories (illustrative). |
| `grouped-vulns-data.js` | Grouped-advisory dataset (axios scan, from real scan output). |

## Vulnerability page (`vulnerability-page.html`)
The `vuln/{CVE-id}` route — reads the id from `?id=` or `#/vuln/<id>` (breadcrumb
+ header shows the CVE), then lists the source advisories tied to it as
**extended vuln cards** stacked vertically. Each card: `OriginalID (CanonicalID)`
title + `CVSS · score · bucket` pill + ecosystem pill; a **GitHub advisory** link
always plus an **OSV** link only when `Source === "osv"`; description; published /
created dates as `DD/MM/YYYY (rel)`; and a **collapsible per affected package**
with purl + four version fields — **Affected**, **Affected ranges**,
**Unaffected**, **Fixed** — all arrays rendered as mono chips. The Affected list
can be long, so it caps at 12 chips with a `+N more` / `show less` toggle.
Components: `ExtendedVulnCard.jsx` + `extended-vulns-data.js`, styles in
`vulncard.css`.

## Grouped vulnerability card (`grouped-vulns.html`)
A canonical advisory aggregated from multiple sources. **Root** shows the
canonical ID and two score pills — `ExS · {exposure} · {bucket} ⓘ` and
`CVSS · {max} · {bucket}` — plus a child-count caret. **Expanded**, each child
source record shows: `OriginalID (source)` pill + a `CVSS · {score} · {bucket}`
pill, the description, a match-reason strip (`{version} · {reason} · {range} →
fixed in {next}`), and published / updated dates. Not-affected groups render
grey-tinted with a `not affected` tag and no score pills. Open `grouped-vulns.html`
for the demo (`vulncard.css` + `GroupedVulnCard.jsx`).

## Notes / substitutions
- **App icon** is the placeholder (`ui/app-icon.svg`) — the system's one spot of
  color. Replace per app.
- **Footer glyphs** use **Lucide** from CDN (`github`, `book-open`, `download`) —
  a flagged substitution; the source pins no icon set.
- Stays pure monochrome: the only color is the severity chips/ring and the icon.
