# "Ollama, smaller" — Design System

A tiny, framework-agnostic design system shared across a family of small
research/data tools so they all look the same. **Pure monochrome black on white,
pill geometry, compact density.** The only color anywhere is (1) each app's own
icon image and (2) a CVSS-bucketed severity palette. No brand color, no shadows,
no gradients.

The name is the brief: *"Ollama, smaller."* It borrows Ollama's documentation-site
restraint — paper-white canvas, plain text, quiet ink — and tunes it **denser**,
because these are tools for reading data, not marketing pages.

---

## What this system is for

This is **not** a marketing brand kit. It's the shared visual layer for a set of
internal research / security / data tools. The strongest signal of intent is the
**severity palette and CVSS buckets** baked into the tokens — the canonical use
case is a **vulnerability / advisory / CVE tracker** and similar data dashboards.
Each app is identical except for its icon. There is deliberately no `--brand`
color to set.

Core component vocabulary (all in `base.css`): sticky topbar, pill buttons
(ink primary / outline secondary), pill inputs & selects, hairline cards, badges,
`.sev-*` severity chips, code blocks, a filter bar, an above-the-data pager, a
collapsible row, and a footer. Plus an optional segmented **donut ring** chart
(`ring.css` + `ring.js`).

---

## Sources

This system was built entirely from an attached read-only codebase — a pure-CSS
design system, no application/product code:

- **Codebase:** `ui/` (mounted locally) containing:
  - `tokens.css` — design tokens (copy verbatim, never edit per app)
  - `base.css` — generic components (copy verbatim)
  - `ring.css` + `ring.js` — segmented donut chart, `renderRing(segments)`
  - `DESIGN.md` — the full spec (rules, do's/don'ts)
  - `README.md` — adoption guide

Verbatim copies of all of the above live in [`source/`](source/) for reference.

There were **no font files** (the system uses OS system fonts) and **no logo /
icon assets** in the codebase (each app supplies its own icon — see ICONOGRAPHY).

---

## CONTENT FUNDAMENTALS

The voice is **documentation-first: terse, lowercase-leaning, factual, engineer-to-
engineer.** It reads like a README or a man page, not marketing copy.

- **Tone.** Plain and declarative. States rules, not benefits. *"Pager goes above
  the data, never below."* / *"If you're reaching for a color, stop — the answer
  is ink, mute, or a hairline."*
- **Person.** Mostly impersonal/imperative ("Copy this file verbatim", "Keep the
  topbar to identity, navigation, and actions"). First person appears only as the
  author's aside ("shared across my apps"). Rarely addresses "you".
- **Casing.** Sentence case everywhere. Headings are sentence case. UI labels are
  short and sentence-cased (`N results`, `Install`, `Docs`). The wordmark is the
  app name; no ALL-CAPS, no Title Case Marketing Phrases.
- **Density of language.** Maximally compact. Abbreviations welcome (CVSS, IDs,
  ranges). Numbers and identifiers render in mono.
- **Emoji.** None. Never. Not in copy, not in UI.
- **Punctuation flavor.** Middot separators in meta (`brand · version · year`),
  arrows for navigation (`‹ p / total ›`), chevrons for collapse (`▶`).
- **Vibe.** Quiet, confident, anti-ornament. The interface should feel like a
  well-kept terminal: nothing decorative, everything legible.

Example copy from the system itself: *"A documentation-first, aggressively minimal
system. Paper-white canvas, pill geometry, system fonts, no ornament."*

---

## VISUAL FOUNDATIONS

**Overall vibe:** paper-white research tool. Maximum restraint. If something looks
designed, it's probably too much.

- **Color.** Pure monochrome. Canvas `#ffffff`, ink `#000000`, body prose grey
  `#737373`, with a charcoal/mute/hairline ramp (`#525252 → #a3a3a3 → #d4d4d4 →
  #e5e5e5`). **There is no brand color.** The *only* color permitted is the
  `.sev-*` severity palette (soft tint bg + matching dark ink + a colored
  border, the brighter Meerkat ramp), the saturated **status dots** / pastel
  **timeline squares**, and each app's icon image. Focus rings, active states,
  CTAs, the wordmark — all ink/white/grey.
- **Type.** Three families, all effectively system fonts: `--font-display`
  (SF Pro Rounded → `system-ui`) for headings ≥18px only; `--font-body`
  (`ui-sans-serif`) for everything else; `--font-mono` (`ui-monospace`) for code,
  IDs, ranges, and badges. Compact scale: 14px body, 24px hero, 18px card title,
  13px controls, 11px badges/captions. Display weight 500–600.
- **Spacing.** Tight, tool-grade rhythm on a 4px base: 4 / 8 / 12 / 16 / 24 / 32 /
  48. 16px card padding. Single narrow reading column, `max-width: 860px`, centered.
- **Backgrounds.** Flat white. **No** images, no full-bleed photography, no
  illustrations, no repeating patterns/textures, no gradients. The one permitted
  non-white surface is `--color-surface-soft` (`#fafafa`, for code blocks/badges)
  and the single dark "look here" surface `--color-surface-dark` (`#171717`).
- **Elevation.** **No box-shadow, ever. No gradients, ever.** Elevation is
  expressed two ways only: a 1px hairline border, or — used once per view max —
  the dark surface. That's the entire depth system.
- **Borders / hairlines.** Cards and dividers use the 1px `--color-hairline`
  (`#e5e5e5`); inputs and secondary buttons use the stronger `#d4d4d4`. Borders go
  ink on hover/focus.
- **Corner radii.** Binary by intent: **pills** (`--radius-full`, 9999px) for
  *everything interactive* (buttons, inputs, selects, badges, chips, pager);
  **12px** (`--radius-lg`) for cards; 6px only for the ring tooltip. Nothing in
  between.
- **Cards.** White background, 1px hairline border, 12px radius, 16px padding.
  **No shadow.** A `.card-strong` variant just uses the stronger hairline. That's
  it — cards are containers, not floating objects.
- **Buttons.** Primary = solid ink, white text, pill, 32px tall; `:active` deepens
  to `#090909`; disabled goes to the soft surface. Secondary = white with a
  hairline-strong border that goes ink on hover. Heights: 32px buttons, 36px
  inputs/selects.
- **Animation.** Almost none. The only transitions in the system are a 0.15s
  opacity fade on the ring tooltip and a 0.15s rotate on the collapse chevron.
  No bounces, no easing showpieces, no entrance animations. Motion is functional
  or absent.
- **Hover states.** Quiet-text elements go from charcoal/mute → ink. Bordered
  elements go hairline → ink. Pager buttons get a soft-grey fill. No color shifts,
  no lifts.
- **Press states.** Primary button deepens its black (`#000 → #090909`). No shrink
  transforms, no shadow changes.
- **Transparency / blur.** None. No glassmorphism, no backdrop blur, no translucent
  overlays. Surfaces are opaque.
- **Layout rules.** Sticky borderless 56px topbar (left = logo + wordmark + plain-
  text nav, active item *underlined* not pilled; right = action buttons). Footer
  carries meta left + external links right and is the *only* home for
  GitHub/Docs/Install. The pager always sits **above** the data. Search inputs cap
  at 320px, never full width.
- **Imagery color.** N/A — the system has no imagery. The only raster is each app's
  icon (its lone spot of color).

---

## ICONOGRAPHY

The system is **almost icon-free by design.** It treats iconography the way it
treats color: a luxury to be spent sparingly.

- **No built-in icon font, no sprite, no bundled SVG icon set** ships in the
  codebase. There is nothing to copy out.
- **The one mandated image per app is its icon/logo** (`.nav-logo`, 45×45,
  `object-fit: contain`). This is the app's single spot of color and its entire
  identity — the only thing that changes between apps. The codebase does not
  contain these (they're per-app); a neutral placeholder mark is provided in
  [`assets/`](assets/) for previews — **replace it with the real app icon.**
- **Inline SVG appears in exactly two utility spots:** the select-pill caret (a
  10×6 grey chevron, embedded as a data-URI) and the footer's `.icon-link` slots
  (20×20, mute → ink on hover) for GitHub/Docs/Install. The codebase ships the
  caret only; the footer link glyphs are left to the app.
- **Unicode characters are used as "icons" where a glyph will do:** the collapse
  chevron is a literal `▶` that rotates 90° via CSS; pager arrows are `‹` `›`;
  meta separators are `·`. This is intentional — text over assets.
- **No emoji, anywhere.**
- **Recommended substitution for the footer link glyphs:** since the set is tiny
  (GitHub, Docs/book, download) and CDN-available, use **Lucide** (`github`,
  `book-open`, `download`) at 20×20, 1.5–2px stroke, `currentColor` — it matches
  the system's thin, neutral, monochrome line style. This is a **flagged
  substitution** (the codebase doesn't pin an icon set); swap for the app's
  preferred set if one exists. The UI kit links Lucide from CDN for these slots.

---

## VISUAL ELEMENTS (UI kits)

- **[`ui_kits/research-tool/`](ui_kits/research-tool/)** — a representative
  vulnerability / advisory tracker built entirely from `base.css`: topbar, hero +
  search, severity ring summary, filter bar + pager, advisory cards with severity
  chips, a collapsible detail row, code block, and footer. This is the canonical
  application of the system. See its README for component coverage.

---

## Index / manifest

Root files:

| File | What it is |
|---|---|
| `README.md` | This file — context, content + visual foundations, iconography, index. |
| `colors_and_type.css` | Color tokens + type scale + semantic type helpers (`.ds-*`). |
| `SKILL.md` | Agent-Skill front-matter wrapper for downloading into Claude Code. |
| `source/` | Verbatim copies of the original codebase (`tokens.css`, `base.css`, `ring.css`, `ring.js`, `DESIGN.md`, `ui-README.md`). |
| `assets/` | App-icon placeholder + any copied visual assets. |
| `preview/` | Small HTML specimen cards that populate the Design System tab. |
| `ui_kits/research-tool/` | High-fidelity interactive recreation of a tool built on the system. |

**Adoption (from the source README):** load order is `tokens.css` → `base.css` →
your app's own `app.css`, with `ring.css` + `ring.js` alongside if you need the
donut. Copy `tokens.css` / `base.css` **verbatim**; never edit them per app. The
only per-app change is the icon image.

---

## CAVEATS / substitutions

- **Fonts are system fonts** — `SF Pro Rounded` (Apple-only; falls back to
  `system-ui`), `ui-sans-serif`, `ui-monospace`. Nothing to bundle, but rendering
  differs across OSes by design. No web-font files were provided or needed.
- **No app icon was provided.** A neutral placeholder sits in `assets/`; the real
  identity comes from dropping in the actual app icon.
- **Footer link icons** use Lucide from CDN as a flagged substitution (no icon set
  is pinned in the source).
