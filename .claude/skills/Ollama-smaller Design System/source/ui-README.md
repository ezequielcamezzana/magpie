# ui — shared design system ("Ollama, smaller")

A tiny, framework-agnostic CSS design system shared across my apps so they all
look the same. Pure monochrome black/white base, pill geometry, compact density.
The only color is the app's own icon and the severity palette.

## Files
- `tokens.css` — design tokens (neutrals, severity palette, radii, spacing,
  fonts). **Copy verbatim. Never edit per app.**
- `base.css` — generic components (topbar, buttons, inputs, selects, cards,
  badges, tabs, severity chips, code blocks, pager, collapsible, footer).
  **Copy verbatim.**
- `ring.css` + `ring.js` — segmented donut chart (`renderRing(segments)`).
- `DESIGN.md` — the spec (rules, do's/don'ts).

## Adopt in an app
1. Copy `tokens.css` + `base.css` into the app (e.g. `web/static/ui/`); add
   `ring.css` + `ring.js` if you need the donut. A `make ui-sync` target that
   copies from this folder keeps them in sync.
2. Add app-specific classes in the app's own `app.css`. There is no color token
   to set — the app's identity is its icon image (`.nav-logo`) and favicon.
3. Load order in HTML: `tokens.css` → `base.css` → app `app.css`
   (`ring.css` + `ring.js` alongside as needed).

## Rules (see DESIGN.md)
- **Pure monochrome.** Black ink, white canvas, gray body text. No `--brand`.
- **Color only on severity** (`.sev-*`, ring segments) **and the app icon.**
- **No shadows, no gradients.** Elevation = 1px hairline or a dark surface.
- **Pills** (`--radius-full`) for interactive; `--radius-lg` (12px) for cards.
- **Topbar:** sticky; left = logo + wordmark + nav links (plain text, active
  underlined); right = actions. No GitHub/Docs icon links, no refresh timestamp.
- **Footer:** meta left (brand · version · year), links right. **Pager goes above
  the data, never below.**
