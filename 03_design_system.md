# Design System — PS 26160 Dashboard
### "Must not look AI-generated" is a hard requirement, not a style preference

---

## 1. The problem to avoid
Judges see dozens of hackathon dashboards that converge on the same look because they came from the same default AI-scaffolded component patterns: purple/blue gradient hero backgrounds, glassmorphism-by-default, generic rounded-everything cards with soft drop shadows, stock "AI orb" hero graphics, emoji-as-icons, centered-hero-with-gradient-text landing sections. The way to stand out is a considered, restrained, motion-literate interface — not more visual noise.

## 2. Direction
**Minimal, editorial, high-contrast, motion as a functional layer (not decoration).** This is a security-analyst tool, not a marketing site — dense information display, a small number of very deliberate animated moments.

## 3. Required libraries (named directly — required building blocks, not optional inspiration)

- **Lenis** — smooth-scroll. Apply to the dashboard/report-scroll and any overview page for a controlled, weighted scroll feel. Cheap, high-perceived-quality integration.
- **GSAP** — the actual animation work: dashboard state transitions, number/score count-ups for risk score and confidence score, staggered reveal of threat-matrix rows, timeline scrubbing for a live-capture view. Prefer over ad hoc CSS transitions for anything that needs to feel sequenced and intentional. GSAP is a precise tool, not a taste-generator — real design decisions (easing, duration, what animates vs. stays still) still need to be made deliberately.
- **Vanta** — background effects (subtle animated network/net/globe backdrop). Use sparingly, one place only (e.g. a single hero/landing background) — a strong visual signature overused reads as templated.
- **React Bits** — animated React component reference (typography reveal, hover states, small interactive details). Use as a starting point and customize color/spacing/timing — used verbatim, any component library reads as "default."
- **animos.app** — reference for animation *craft and restraint* (what moves, what doesn't, how subtle the easing is), not an asset to lift wholesale.

## 4. Guardrails on top of the libraries

- **No default AI-tool gradients** (purple-to-pink, blue-to-cyan hero backgrounds). Pick a deliberate, narrow palette: near-black/near-white base with a single accent color tied to risk-severity states — this does real functional work in a security dashboard, since red/amber/green severity coding needs to read clearly against the base.
- **Typography carries hierarchy.** A considered type pairing — technical monospace for protocol/packet data, clean sans for prose/report copy — does more for the "human-designed" feeling than any animation.
- **Motion is functional first.** Animate to reveal state changes (new scan result, updated score, expanded threat detail), never for decoration on static content. Test: if a judge could screenshot two states and the animation added nothing to understanding the transition, cut it.
- **Data density is a feature, not something to hide behind whitespace.** This is a security-analyst tool — favor dense, well-organized layout (tables, sparklines, compact severity badges) over sparse single-column marketing-site layout.
- **Dark mode is the default** given the security-tool context; light mode is secondary, not the reverse.

## 5. Concrete component notes
- Risk score and AI confidence score: GSAP count-up animation on load/update, not a static number.
- Threat matrix: staggered row reveal via GSAP on filter/sort change, not on every re-render.
- Severity badges: compact, color-coded against the single accent-color system, never full-width colored cards.
- Report download (Executive/Technical PDF/HTML): rendered from the same shared data model the dashboard reads — never let the two diverge visually or numerically.
- Live-capture view (bonus/demo-mode overlay): timeline scrubbing via GSAP, clearly marked as a secondary/demo path, not the primary judged flow.
