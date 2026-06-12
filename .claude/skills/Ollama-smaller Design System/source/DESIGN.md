# Design System — "Ollama, smaller"

A documentation-first, aggressively minimal system. Paper-white canvas, pill
geometry, system fonts, no ornament. Tuned denser than Ollama's marketing site
because these are research/data tools, not landing pages. Pure monochrome — the
only color is the app's own icon and the severity palette.

## Principles
1. **Monochrome base.** Black ink on white canvas, gray (`--color-body`) prose.
   If you're reaching for a color, stop — the answer is ink, mute, or a hairline.
2. **No brand color.** There is no `--brand`. Wordmark, active tab, focus ring,
   buttons — all ink, white, or grey. The app's identity lives in ONE place: its
   icon/logo image (`.nav-logo`). Rings and accents use neutral grey tones.
3. **Color only on severity + the icon.** The `--color-severity-*` palette (on
   `.sev-*` badges and ring segments) and the app icon image are the only color
   in the system. Nothing else.
4. **No depth tricks.** No `box-shadow`, no gradients. Elevation is a 1px
   `--color-hairline` border, or — once per view, for "look here" — the dark
   surface (`--color-surface-dark`).
5. **Pills + cards.** Everything interactive is `--radius-full` (9999px). Cards
   are `--radius-lg` (12px). Nothing in between.
6. **Compact.** 14px body, 24px hero, 16px card padding, tight section rhythm.
   Density over air — these are tools.

## Type
- `--font-display` (SF Pro Rounded → system-ui): headings ≥18px only.
- `--font-body` (ui-sans-serif): everything else.
- `--font-mono` (ui-monospace): code, IDs, ranges, badges.

## Severity palette (the one exception)
CVSS-bucketed, `.sev-*` badges only. Soft tint background + matching dark ink
(not solid). bg / ink:
- critical `#fee2e2` / `#991b1b` (9.0–10) · high `#ffedd5` / `#9a3412` (7.0–8.9)
- medium `#fef9c3` / `#854d0e` (4.0–6.9) · low `#fafafa` / `#525252` (0.1–3.9)
- none `#fafafa` / `#a3a3a3` (no score).

## Topbar
Sticky, borderless, 56px. Left group, glued together: `.nav-logo` (the app icon —
its one spot of color) + `.nav-brand` wordmark (ink) + `.nav-links`. Nav links are
plain text (Ollama-style): quiet charcoal, ink on hover, and the active item is
underlined ink — no pill background. Right group: `.nav-actions` (buttons). No
external icon links (GitHub/Docs/Install — those live in the `.footer`) and no
"last refreshed" timestamp. Keep the topbar to identity, navigation, and actions.

## Per-app identity
The only thing that changes between apps is the icon image in `.nav-logo` (and
the favicon). There is no color token to set.

## Ring, select, pager, collapsible
- **Ring** (`ring.css` + `ring.js`): segmented donut via `renderRing(segments)`.
  Segments colored by severity, or grey when neutral. Never a custom color ramp.
- **Select** (`.select-pill`): pill with a grey caret, native appearance stripped.
- **Filter bar** (`.filter-bar`): one line above a list. Left (`.filter-left`):
  a `.search-input` (capped at 320px, never full-width) + any `.select-pill`s
  (filter/sort). Right: the `.pager` with the result count. This is the standard
  layout for search + sorting + pagination everywhere.
- **Pager** (`.pager` + `.page-btn`): sits ABOVE the data, never below. Holds the
  result count (`N results`) then `‹ p / total ›`.
- **Collapsible** (`.collapse` / `.collapse-chevron` / `.collapse-body`): toggle
  `.open` on `.collapse`; the `▶` chevron rotates 90°.
- **Footer** (`.footer`): meta on the left (`.footer-meta` — brand · version ·
  year), external links on the right (`.footer-links` with `.icon-link`s). The
  only home for GitHub/Docs/Install; mute icons that go ink on hover.

## Do / Don't
- **Do** keep the page a single narrow reading column with hairline-bordered cards.
- **Do** signal severity with the colored badge; signal "affected/clear" with
  ink-vs-mute typographic weight, not color.
- **Don't** add gradients, shadows, or any color beyond severity + the app icon.
- **Don't** put GitHub/Docs/Install icon links or a refresh timestamp in the nav.
- **Don't** edit `tokens.css`/`base.css` per app — only the app icon and your own
  app-specific classes change between apps.
