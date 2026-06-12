---
name: ollama-smaller-design
description: Use this skill to generate well-branded interfaces and assets for the "Ollama, smaller" design system — a pure-monochrome, pill-geometry, compact research/data tool aesthetic — either for production or throwaway prototypes/mocks/etc. Contains essential design guidelines, colors, type, fonts, assets, and UI kit components for prototyping.
user-invocable: true
---

Read the `README.md` file within this skill, and explore the other available files.

If creating visual artifacts (slides, mocks, throwaway prototypes, etc), copy
assets out and create static HTML files for the user to view. If working on
production code, you can copy assets and read the rules here to become an expert
in designing with this brand.

If the user invokes this skill without any other guidance, ask them what they
want to build or design, ask some questions, and act as an expert designer who
outputs HTML artifacts _or_ production code, depending on the need.

## The one rule that matters most
**Pure monochrome.** Black ink on a white canvas, grey body prose. There is NO
brand color. The ONLY color permitted anywhere is (1) the app's own icon image
and (2) the `.sev-*` CVSS severity palette. If you reach for a color, stop — the
answer is ink, mute, or a hairline. No shadows. No gradients. No emoji.

## Key files
- `README.md` — full context: content + visual foundations, iconography, index.
- `colors_and_type.css` — color tokens + type scale + semantic helpers.
- `source/tokens.css` + `source/base.css` — copy these **verbatim** into any app
  (load order: tokens → base → your app.css). Never edit per app.
- `source/ring.css` + `source/ring.js` — segmented severity donut (`renderRing`).
- `source/DESIGN.md` — the authoritative spec (rules, do's/don'ts).
- `ui_kits/research-tool/` — interactive recreation; reusable JSX components.
- `assets/` — app-icon placeholder (replace with the real per-app icon).

## Shape & density at a glance
Pills (9999px) for everything interactive; 12px radius for cards; 16px card
padding; 14px body / 24px hero; system fonts (display = SF Pro Rounded →
system-ui). Single narrow reading column (max 860px). Pager goes above the data.
