# Aegis — Final Landing Page Generation Prompt

> Paste everything under **PROMPT** into v0, Claude, Cursor, Bolt or Framer AI.
> Anything in `[BRACKETS]` is a placeholder you must replace with real facts. Don't ship made-up
> customer logos, testimonials, user counts or compliance certifications.

---

## PROMPT

Build a single-page, dark-mode, production-quality landing page for **Aegis — the Zero-Trust
Responsible AI Gateway**. Aegis is an open-source reverse-proxy API gateway that sits between a
company's apps and upstream LLM providers (OpenAI, Anthropic, Groq, Together, GLM, local Ollama).
Every prompt passes through Aegis guardrails before it reaches a model: it redacts PII and secrets,
blocks prompt injection, serves repeated questions from a semantic cache, sends each request to the
cheapest model that can handle it, checks answers for hallucinations, fails over when a provider
goes down, and writes an audit trail you can export as an EU AI Act report.

Positioning: **"Ship AI your security team will actually approve."** The audience is enterprise
engineering leads, CISOs and compliance officers. The tone is confident, precise and technical, with
no hype words like "revolutionary".

---

### 1. Tech stack

- **Next.js (App Router) + React + TypeScript (strict, no `any`)**
- **Tailwind CSS v4.** Put design tokens in `globals.css` using `@theme`.
- **Framer Motion** for animation and **lucide-react** for icons.
- Brand logos for integrations come from **simple-icons** (or an SVG, or a text fallback).
- Split the page into section components under `components/landing/` (`Navbar.tsx`, `Hero.tsx`,
  `RevealText.tsx`, `FeatureCards.tsx`, and so on) and assemble them in `app/page.tsx`.
- Keep the content in a typed `content.ts` file so the copy can be edited without touching layout.
- No images for the glow effects. Use pure CSS gradients with blur so they stay sharp at any size.
- Draw the product mockup in HTML/CSS, not as a screenshot (see Hero).

### 2. Design language

**Colors (define these as CSS variables):**
| Token | Value |
|---|---|
| `--bg` | `#000000` (every section) |
| `--text` | `#FFFFFF` |
| `--text-2` | `rgba(255,255,255,0.6)` (body text) |
| `--text-3` | `rgba(255,255,255,0.4)` (labels, meta text) |
| `--border` | `rgba(255,255,255,0.1)` |
| `--orange` | `#FF8A00` |
| `--blue` | `#0175FF` |
| `--violet` | `#7B3FF2` (midpoint) |
| `--accent-gradient` | `linear-gradient(90deg, #FF8A00, #7B3FF2, #0175FF)` |
| `--pass` / `--flag` / `--block` | `#22C55E` / `#F59E0B` / `#EF4444`. Use these **only** inside the product mockup. |

**Type:**
- **Inter** for body text, **Inter Display** (or Inter at 700–800 with tight tracking) for headings.
- Hero headline 64–80px on desktop, 40px on mobile. Section titles 44–56px.
- Monospace (JetBrains Mono) for code, request IDs, placeholders like `[PERSON_1]` and millisecond timers.

**Spacing and borders:**
- Very generous whitespace: 120–200px of vertical padding between sections.
- Content max-width 1200px.
- 1px `--border` dividers only. Card radius 20–24px. Pill radius 999px.

**Section eyebrow.** Every section title has a label above it:
- Small uppercase text with wide tracking (`0.2em`) in a muted gray-blue.
- A small lucide icon before the text.
- A thin horizontal rule next to it.
- Examples: `◆ GUARDRAILS ————`, `◆ HOW IT WORKS ————`.

**Background, used across the whole page:**
- **Aurora:** 3–4 large, absolutely positioned blobs (orange, blue, violet) anchored at the top centre
  behind the hero. Use `filter: blur(80–120px)` at 35–55% opacity. Each blob drifts very slowly
  (30–40s `translate`/`scale` loop). Stop the drift under `prefers-reduced-motion`.
- **Starfield:** faint white dots with random opacity (0.1–0.6) over the full page height. Render them
  with one canvas or a repeated radial-gradient layer, not thousands of DOM nodes.
- **Grain:** a subtle noise overlay (SVG `feTurbulence` at about 4% opacity) so the gradients don't look flat.
- Reuse the same aurora as small glowing orbs behind icons and inside cards.
- All glows sit at `z-index: 0`. Content sits at `z-index: 10`.

**Buttons:**
- **Primary "glow ring":** black pill with white text and a 1px animated conic-gradient border
  (orange → violet → blue → orange) rotating over 6s. A soft outer glow appears on hover.
  Build it with a `::before` pseudo-element and `mask`, or with a wrapper and padding.
- **Secondary:** transparent pill, 1px `--border`, white text. On hover the border brightens to 0.25.

---

### 3. Sections, in order, with Aegis copy

#### 3.1 Navbar
- Floating, centered, glass pill (not full width). `backdrop-blur(16px)`, 1px border, fixed about 20px from the top.
- **Left:** a shield icon plus the wordmark **AEGIS** (bold, tracked-out small caps).
- **Centre links:** Features · How it works · Security · Pricing · Docs.
- **Right:** a "Get Started" glow-ring button.
- **Mobile:** hamburger opening a full-screen black overlay menu.

#### 3.2 Hero
- **Badge pill:** `● Open-source · v0.1 [launch date]` (muted text, thin border).
- **Headline** (two lines, centered, gradient on the second line):
  > **The Zero-Trust Gateway**
  > **for Responsible AI**
- **Subheadline** (max-width 620px, `--text-2`):
  > Aegis sits between your apps and every LLM. It redacts PII and secrets, blocks prompt injection,
  > caches and routes to cut spend, catches hallucinations, and exports an audit trail for the EU AI Act.
- **CTAs:** `Get Started` (glow ring) and `View on GitHub` (secondary, with the GitHub icon).
- **Trust line under the CTAs** (small, `--text-3`):
  "OpenAI-compatible API · Drop-in: change one base URL · Self-hosted"
- **Product mockup:**
  - A large rounded card (1px border, dark glass) floating over the aurora, cropped by the bottom of the viewport.
  - It shows the **Aegis Live Inspector** as three columns: *Prompt* | *Pipeline* | *Response*.
  - **Prompt column:** `Email John Smith at john@acme.com with key AKIA••••`
  - **Pipeline column:** stage rows with icon, status chip and millisecond timer:
    - 🛡 PII & Secret Scanner: `Scrubbed 2 · 14ms`
    - 🧱 Injection Defense: `Pass · 3ms`
    - ⚡ Semantic Cache: `Miss · 9ms`
    - 🚦 Smart Router: `llama-3-8b · $0.0003`
    - 🔍 Hallucination Check: `94% faithful · 41ms`
  - **Response column:** text containing `[PERSON_1]` and `[EMAIL_1]` placeholders, plus badges for latency, cost and tokens.
  - A small header strip on the card reads: `$ saved · injections blocked · CO₂ offset`.
  - Rows light up one after another on load (stagger 150ms).
  - The mockup tilts slightly (`perspective`, `rotateX(8deg)`) and flattens as you scroll.

#### 3.3 Scroll-reveal statement
Large paragraph (36–44px, centered, max-width 1000px). It animates **word by word**: each word starts at
opacity 0.2 and turns fully white as the section scrolls through the viewport. Use Framer Motion
`useScroll` on the section plus a per-word `useTransform`.
> Every prompt your company sends to an AI model is a potential data leak, a compliance risk and a line
> item on next month's bill. Aegis puts a zero-trust checkpoint in front of every model call, so teams
> can adopt AI quickly without handing customer data, credentials or accountability to a third party.

#### 3.4 Guardrails — "What sets Aegis apart"
Eyebrow `GUARDRAILS`. Title: **Six guardrails. One gateway.**

Show a 3×2 grid on desktop, 2 columns on tablet, 1 on mobile. Each card has:
- A visual area on top, with the starfield and aurora clipped inside the card.
- A lower panel with a top border, a title and a one-sentence description.
- On hover: `translateY(-4px)`, border brightens, the glow gets 10% stronger.

| # | Title | Description | Visual |
|---|---|---|---|
| 1 | **PII & Secret Redaction** | Names, emails, SSNs, cards, AWS keys, JWTs and connection strings become reversible placeholders before any model sees them. | A text line where `john@acme.com` morphs into `[EMAIL_1]` on a loop |
| 2 | **Prompt Injection Defense** | Jailbreaks, "ignore previous instructions" and delimiter attacks are stopped with an instant 403. | A red `403` shield pulsing over a blurred prompt |
| 3 | **Semantic Cache** | Similar questions return from cache in milliseconds for $0, cutting cost and carbon. | A glowing orange/blue orb with a `HIT · 0.95` chip |
| 4 | **Smart Model Routing** | Simple tasks go to fast, cheap models; complex reasoning goes to frontier models. | Three animated vertical bars (low/medium/high) with model names |
| 5 | **Hallucination Firewall** | Answers are scored against your source documents; unsupported claims are replaced with a safe fallback. | A radial gauge reading `94% faithful` |
| 6 | **Zero-Downtime Failover** | Circuit breakers detect 5xx, 429 and timeouts and switch to a backup provider without the user noticing. | Two provider nodes, the path jumping from a red node to a green one |

#### 3.5 CTA strip
- Thin bordered pill-shaped band: "Ready to put guardrails on your AI?" with a `Get Started` button.
- A small aurora glow behind it.

#### 3.6 How it works (tabbed panel)
Eyebrow `ARCHITECTURE`. Title: **One base URL. Every model. Fully governed.**

**Left column:** vertical tabs with icons and a bottom border. The active tab has white text and a
2px gradient left border.

- **Drop-in**
  - Shows a code block with a copy button that switches the client to Aegis:
    ```ts
    const client = new OpenAI({
      baseURL: "https://aegis.yourcompany.com/api/v1",
      apiKey: process.env.AEGIS_KEY,
    });
    ```
  - Caption: "Works with any OpenAI-compatible SDK. No code rewrite."
- **Pipeline**
  - An animated horizontal flow diagram:
    `App → Scan (PII/Secrets/Injection) → Cache → Router → Provider (with failover) → Verify → Audit log → App`
  - A light pulse travels along the path.
- **Providers**
  - Chips: OpenAI, Anthropic, Groq, Together AI, GLM, Ollama (local).
  - Plus a config snippet showing a `failover_chain`.

The content cross-fades when you switch tabs (opacity and 12px `translateX`, 0.3s).

**Integrations row below the tabs:**
- A row of rounded-square icon tiles: OpenAI, Anthropic, Groq, Ollama, Redis, PostgreSQL, Next.js, Python, Docker.
- Each tile has a soft blue or orange radial glow behind it.
- The row is masked with a left/right gradient fade so it looks endless.

#### 3.7 Logo marquee
- Label: "Built for teams shipping AI in regulated industries".
- An infinite CSS marquee (`animation: marquee 30s linear infinite`, content duplicated for a seamless loop).
- Logos are placeholder wordmarks (`[LOGO]`) at 40% opacity, 80% on hover. Pause on hover.

#### 3.8 Use cases ("Built for every AI workload")
Eyebrow `USE CASES`. Four bordered cards, each with an icon, a title and a sentence:
- **Healthcare:** keep patient identifiers out of third-party models (HIPAA-minded redaction).
- **Financial services:** block card numbers and account data; keep a full audit trail.
- **Customer support:** answers grounded in your knowledge base, with hallucinations stopped.
- **Engineering:** let developers use AI without pasting API keys and connection strings into prompts.

#### 3.9 Three steps
Eyebrow `GET STARTED`. Title: **Live in three steps.**

One large rounded bordered container holding three stacked full-width panels separated by 1px dividers.
Each panel has a big step number (`01`), a headline and description on the left, and a checklist of three
pill rows with circular check icons on the right.

1. **Deploy Aegis**: "Run it with Docker Compose next to your stack."
   - Self-hosted
   - Redis + Postgres included
   - Open source
2. **Connect your providers**: "Add keys as environment variables and set a failover chain."
   - OpenAI-compatible
   - Local Ollama supported
   - Keys never in config
3. **Point your apps at Aegis**: "Change one base URL. Every request is now governed."
   - Live inspector
   - Policy controls
   - Audit export

#### 3.10 Security
Eyebrow `SECURITY`. Title: **Fail-closed by design.**

A large card with the hero aurora inside it and three glass callouts on top (icon, label, one line):
- **Fail-closed gate:** if the security engine is unreachable, the request is rejected, never forwarded unscanned.
- **SSRF-guarded egress:** provider calls are restricted to an allowlist and private IP ranges are blocked.
- **No raw data at rest:** logs and audit entries store counts, categories and IDs, never prompt text.

#### 3.11 Compliance and audit ("1-Click EU AI Act report")
Split layout:
- **Left:** a headline, a short description, and a `Download sample report` secondary button.
- **Right:** a mock PDF page card with fake tables and a "Transparency · Risk management · Record-keeping"
  checklist, tilted slightly, with an aurora glow behind it.

#### 3.12 Testimonials
- A full-width divider of blurred vertical aurora bands (orange, blue, violet).
- Below it, three quote cards with a circular avatar, quote, name and role.
- **Use clearly marked placeholders**: `"[Customer quote]"` — `[Name], [Title], [Company]`.

#### 3.13 Pricing
Eyebrow `PRICING`. Monthly/Yearly toggle, with a `Save 20%` badge on Yearly.

| Plan | Price | Features | CTA |
|---|---|---|---|
| **Community** | Free (self-hosted, open source) | All 6 guardrails, OpenAI-compatible API, Docker deploy, community support | View on GitHub |
| **Team** | `$[X]`/mo | Hosted gateway, live inspector dashboard, audit PDF export, policy controls, email support | Start free trial |
| **Enterprise** (featured) | Contact us | SSO, dedicated deployment, custom detectors, SLA, compliance onboarding | Talk to sales |

- The featured card is slightly larger, has a gradient border and an aurora glow inside, and shows no price.
- Under each plan, a small line: `[social proof placeholder]`.

#### 3.14 FAQ
An accordion with 8 items:
- Smooth height and opacity animation.
- The `+` icon rotates 45° into `×`.
- Only one item is open at a time.
- Built with `button` elements, `aria-expanded` and `aria-controls`.

1. Does Aegis see or store my prompts? *(Prompts are scanned in-flight; logs store only metadata such as IDs, counts, categories and latency.)*
2. Which LLM providers are supported? *(Any OpenAI-compatible API, plus local models through Ollama.)*
3. How much latency does Aegis add? *(A few milliseconds of scanning; cache hits are faster than calling the model at all.)*
4. What happens if the security engine is down? *(Fail-closed: the request is rejected, never sent unscanned.)*
5. How does redaction keep answers readable? *(Reversible placeholders such as `[PERSON_1]` are mapped back on the way out.)*
6. Can I customize what gets blocked? *(Yes, per-policy toggles, strict or sanitize mode, and a faithfulness threshold.)*
7. Does it help with the EU AI Act? *(It provides logging, transparency and risk-control evidence as an exportable report. It supports compliance but is not legal advice.)*
8. Is Aegis open source? *(Yes, the core gateway is self-hostable. `[license]`)*

#### 3.15 Final CTA
- Large centered heading: **Step into Aegis — the future of responsible AI.**
- The heading text is partly masked by a soft radial glow.
- One glow-ring `Get Started` button. Mostly empty space and glow.

#### 3.16 Footer
Four columns:
- **Brand:** logo plus the tagline "Zero-trust guardrails for every LLM call."
- **Product:** Features, How it works, Security, Pricing.
- **Resources:** Docs, GitHub, Changelog, Blog, Privacy, Terms.
- **Social:** X, LinkedIn, GitHub, Discord.

Bottom bar above a 1px top border: `© 2026 Aegis. All rights reserved.` on the left and `Built by [your name/team]` on the right.

**Floating element:** a small fixed pill in the bottom-right corner, `★ Star on GitHub`, with a dark
semi-transparent background and a thin border. It appears after scrolling past the hero.

---

### 4. Motion summary
1. Word-by-word scroll-linked text reveal (3.3).
2. Fade-up entrance for eyebrows, titles and cards (`opacity 0→1`, `y 20→0`, stagger 0.08s, `whileInView`, `once: true`, amount 0.2).
3. Infinite logo marquee (pure CSS) and integration row fade masks.
4. Rotating conic-gradient glow-ring buttons.
5. Card hover lift (`-4px`, 0.25s ease) with the border brightening.
6. Tab cross-fade (0.3s).
7. Accordion height animation with a 45° icon rotation.
8. Slow aurora drift (30–40s) and a staggered light-up of the hero mockup's pipeline rows.
9. **Every animation must be disabled or reduced under `prefers-reduced-motion`.**

### 5. Quality bar
- **Responsive** at 375 / 768 / 1280 / 1536px. No horizontal scroll. 16px side gutters on mobile.
- **Accessibility:**
  - Semantic landmarks (`header`, `nav`, `main`, `section` with `aria-labelledby`, `footer`).
  - Visible focus rings.
  - WCAG AA contrast for all body text.
  - Glow and decoration elements marked `aria-hidden`.
- **Performance:**
  - Lighthouse 90+ on mobile.
  - Blurred layers use `will-change: transform` sparingly.
  - Starfield drawn once to canvas.
  - Fonts via `next/font`.
  - Below-the-fold sections lazy-mounted.
- **SEO:** a `metadata` export (title "Aegis — Zero-Trust Responsible AI Gateway", description, Open Graph image), plus `favicon`.
- **Anchors:** every nav link scrolls smoothly to its section id.
- **Placeholders:** no lorem ipsum. Unknown facts stay as visible `[placeholders]`.

---
---

# PART 2 — Aegis Dashboard App (same theme)

> Paste this **after** Part 1 in the same session, or on its own. If you use it on its own, include
> Part 1's §1 (Tech stack) and §2 (Design language) too, because this part reuses those tokens.

## PROMPT

Build the **Aegis Dashboard**: the product app behind the landing page. It is where operators watch
every LLM request pass through the Aegis guardrails in real time, track savings and blocked threats,
review the audit trail and tune policies. Use **exactly the same design language as the landing page**:
black background, orange/violet/blue aurora, starfield, grain, glass cards, Inter fonts, 1px
`rgba(255,255,255,0.1)` borders and glow-ring primary buttons. Tune it for **readability of data**, not marketing.

Stack: Next.js App Router, TypeScript strict, Tailwind v4, Framer Motion, lucide-react, **Recharts**, zod.

---

### 1. Background and surfaces in the app

- **Background:** the same `#000` + starfield + grain as the landing page, but the aurora is **dimmer and smaller**.
  - One orange/violet blob in the top-left corner and one blue blob in the bottom-right.
  - Opacity 15–25%, `blur(140px)`, drifting very slowly.
  - Fixed to the viewport (`position: fixed`), so it doesn't scroll with the data.
  - Charts and tables must never sit directly on a bright glow.
- **Glass card** (`<Panel>`):
  - `background: rgba(255,255,255,0.03)`, `backdrop-filter: blur(20px)`, 1px border, radius 20px.
  - Optional header row with an eyebrow label and actions.
- **Highlighted card:** gradient 1px border (orange → blue) plus a faint inner glow. Use it for the live
  pipeline and for anything currently running.
- **Status colors** (only for data, never decoration):
  - pass `#22C55E`
  - flagged/warn `#F59E0B`
  - blocked `#EF4444`
  - skipped `rgba(255,255,255,0.3)`
  - info `#0175FF`

  Always pair a color with an icon and a text label.
- **Numbers:** tabular numerals (`font-variant-numeric: tabular-nums`). Monospace for IDs, ms timers and placeholders.

### 2. App shell (shared by all pages)

- **Left sidebar**, 240px wide, collapsible to a 72px icon rail, glass surface with a right border:
  - Top: shield logo + **AEGIS** wordmark.
  - Nav items with icons:
    - Overview (`LayoutDashboard`)
    - Playground (`FlaskConical`)
    - Audit Log (`ScrollText`)
    - Policies (`SlidersHorizontal`)
    - Providers (`Server`)
    - Settings (`Settings`)
  - The active item gets a white label, a 2px gradient left bar and a faint glow.
  - Bottom: an **engine status pill** (`● Engine OK · mock`, green/amber/red dot) and the version.
- **Top bar**, sticky, glass, bottom border:
  - Page title + breadcrumb.
  - Time-range selector pill (`15m · 1h · 24h · 7d`).
  - A live indicator (`● Live`, pulsing dot) and an **Export Audit PDF** glow-ring button.
- **Mobile (<768px):** the sidebar becomes a bottom tab bar (5 icons) and the top bar compacts.
- Page content max-width 1440px, 24–32px padding. Every card fades up on mount (stagger 0.05s).

### 3. Pages

#### 3.1 `/dashboard` — Overview
1. **KPI row**: 4–6 glass tiles. Each tile has an icon in a small glowing orb, a label, a big count-up value,
   the change vs. the previous period (▲/▼ colored), and a Recharts sparkline (gradient stroke, no axes).
   - **Dollars saved**: `$1,284.20`
   - **Avg latency reduction**: `-184 ms`
   - **Injections blocked**: `37`
   - **Data leaks prevented** (credentials + PII blocks): `112`
   - **Entities scrubbed**: `4,902`
   - **Carbon offset**: `3.4 kg CO₂`
2. **Requests over time**, a large area chart.
   - Stacked series: allowed (blue), sanitized (violet), warned (amber), blocked (red).
   - Gradient fills fading to transparent, dotted grid lines at 0.06 opacity, glass tooltip, legend toggles.
3. **Two-column row:**
   - **Blocks by category**: horizontal bar chart (PROMPT_INJECTION, SECRET_AWS_ACCESS_KEY, PII_EMAIL,
     PII_CREDIT_CARD, SECRET_JWT…), sorted, with value labels.
   - **Cache performance**: a donut chart of hit/miss rate, with `Hit rate 41%`, `Avg similarity 0.94`
     and `$ avoided` in the centre and underneath.
4. **Two-column row:**
   - **Model routing mix**: donut or stacked bar of requests per model (low/medium/high complexity →
     model name), plus estimated cost per model.
   - **Provider health**: a list of providers (glm-free, groq, openai, ollama-local). Each row shows:
     - circuit breaker state chip (`CLOSED` green / `HALF_OPEN` amber / `OPEN` red)
     - p50/p95 latency
     - error rate
     - a failover count badge
5. **Live activity feed** (full width):
   - Newest requests stream in at the top with a slide-down animation.
   - Row columns: time · `request_id` (mono, truncated, copy button) · action chip · rule triggers
     (category chips) · model · latency · cost · cache hit icon · failover icon.
   - Clicking a row opens the **Request Detail drawer** (§3.6).

#### 3.2 `/playground` — Live Inspector (the demo screen)
A 3-column layout filling the viewport height below the top bar. Each column is a glass panel that scrolls on its own.

- **Column 1: Client Input**
  - Chat history bubbles. User bubbles are glass; assistant bubbles are plain.
  - Composer textarea with a send button (glow ring) and a stop button. `Cmd/Ctrl+Enter` sends, `Esc` stops.
  - Controls:
    - **Confidential Mode** toggle (lock icon, gradient track when on)
    - **Mode** segmented control: `Sanitize | Strict`
    - **No cache** checkbox
    - **Reference document** upload (drag & drop `.txt`/`.md`, max 200KB, shows filename chip)
  - **Demo presets** dropdown:
    - Clean question
    - Repeat (cache hit)
    - PII
    - AWS secret
    - Prompt injection
    - Complex reasoning
    - Hallucination
- **Column 2: Aegis Live Inspection Pipeline** (highlighted card with a gradient border)
  - A vertical timeline with a connecting line that fills with the gradient as stages complete. Stage cards:
    1. 🛡 **PII & Credential Scanner**: Clean / `Scrubbed 2`. Expands to show detected **categories and
       placeholders only** (`PII_EMAIL → [EMAIL_1]`). The raw matched text is never shown.
    2. 🧱 **Prompt Injection Defense**: Pass / Blocked
    3. ⚡ **Semantic Cache**: Hit (similarity) / Miss / Skipped (reason)
    4. 🚦 **Smart Router**: complexity chip + selected model + estimated cost
    5. 🔁 **Provider / Failover**: provider used. If failover happened, show the attempts trace
       (`glm-free ✕ 503 → groq ✓`).
    6. 🔍 **Hallucination Check**: faithfulness % radial gauge / Blocked + fallback text / Skipped
  - Each card has a status icon, a status chip and a **ms timer** that ticks live while running and then locks
    to the server value.
  - States:
    - `idle`: dim
    - `running`: shimmer + pulsing dot
    - `pass` / `flagged` / `blocked` / `skipped`: blocked also shakes once with a red glow
  - Stages after a block are greyed out as `skipped`.
- **Column 3: Egress / Final Output**
  - Streamed response text with a blinking caret. Placeholders like `[PERSON_1]` render as mono chips
    with a tooltip.
  - A badge row: `⏱ 412 ms` · `$0.0003` · `≈186 tokens` · `model` · `⚡ cache hit` · `🔁 failover`.
  - **Blocked card** (replaces the response): red-tinted glass, big icon, title, error code in mono,
    one-line explanation and `request_id` with a copy button.
    - 400 `CREDENTIAL_LEAK_PREVENTED`: "Credential leak prevented"
    - 403 `PROMPT_INJECTION_BLOCKED`: "Prompt injection blocked"
    - 403 `AEGIS_POLICY_BLOCKED`: "Blocked by policy"
    - 503 `AEGIS_ENGINE_UNAVAILABLE` (amber): "Security engine unavailable — request was not sent (fail-closed)"
  - A stream cut off mid-response keeps the partial text and shows a "Stream interrupted" banner with a Retry button.
- **Mini KPI strip** along the top of the playground: session totals (requests, saved $, blocked, CO₂) that count up after each run.
- **Mobile:** tabs `Input / Pipeline / Output`. The Pipeline tab shows a pulsing dot while a run is in progress.

#### 3.3 `/audit` — Audit Log
- **Filter bar:** date range picker, action multi-select (allow/warn/sanitize/block), rule trigger
  multi-select, model select, search by `request_id`, and a "Clear filters" link.
- **Summary chips:** total entries, blocked %, entities scrubbed.
- **Data table** (glass, sticky header, zebra rows at 0.02 opacity, hover highlight):
  - Columns: Timestamp · Request ID · Action · Error code · Rule triggers · Model · Tokens · Latency · Scrubbed.
  - Sortable columns, pagination (25/50/100), empty state illustration (dim shield + glow), loading skeleton rows.
- A row click opens the Request Detail drawer.
- **Export Audit PDF** button (glow ring):
  - Opens a modal with the date range, include-sections checkboxes (Executive summary, EU AI Act mapping,
    Incidents, Policy snapshot, Methodology) and a Generate button.
  - While generating: progress state. When done: download and a toast.
- **Note under the table** (`--text-3`): "Audit entries contain metadata only — no prompt or response text is stored."

#### 3.4 `/policies` — Guardrail Policies
- A grid of glass cards, one per guardrail, each with an icon orb, title, description and a large toggle:
  - PII detection
  - Secret detection
  - Prompt injection detection
  - Hallucination check
  - Block on PII (instead of sanitizing)
- **Faithfulness threshold** slider (0–1, gradient track, live value bubble, helper text: "Answers below this score are replaced with a safe fallback").
- **Default scan mode:** `Sanitize | Strict` segmented control.
- A sticky save bar slides up from the bottom when there are unsaved changes: `Discard` (secondary) and
  `Save changes` (glow ring).
- **Last updated** timestamp.
- **Read-only lock** state: a banner reading "Policies are locked in demo mode" with the controls disabled.

#### 3.5 `/providers` — Providers & Failover
- **Provider cards:**
  - Name, kind (`openai_compatible` / `ollama`), base URL host, and the API key env var name. Show the env
    var **name only**, never a value.
  - Circuit breaker state chip, last error, latency sparkline, and a "Test connection" button.
- **Failover chain visual:** a horizontal node chain (`glm-free → groq`) with animated connectors. The
  active primary glows. An OPEN breaker shows the node in red with a skip arrow around it.
- **Breaker settings shown read-only:** failure threshold, open duration, connect/total timeouts.

#### 3.6 Request Detail drawer (shared)
A right-side glass drawer, 520px wide, sliding in. Contents:
- `request_id`, timestamp, session (truncated), action chip, error code.
- A pipeline timeline, as in the playground, with the recorded stage durations.
- Detections table: category · placeholder · confidence · message index. **No raw values.**
- Routing: complexity → model, estimated cost / energy / carbon.
- Provider: used, primary, failover attempts list.
- Cache: hit/miss, similarity, cost avoided.
- A "Copy as JSON" button.

#### 3.7 `/settings`
- **Theme:** dark (default) / light (a light variant of the tokens).
- **Reduce motion** toggle.
- **Background effects** toggle (turns off aurora and starfield for low-end machines or screen sharing).
- Metrics refresh interval.
- Engine URL shown read-only.

---

### 4. Data contracts (use mock data first, typed)
Create `lib/dashboard/types.ts` and `lib/dashboard/mock.ts` with realistic seeded mock data. Fetch through
same-origin API routes only:

```ts
// GET /api/metrics?range=1h
interface MetricsResponse {
  window: { from: string; to: string };
  total_requests: number;
  dollars_saved_usd: number;
  avg_latency_reduction_ms: number;
  injections_blocked: number;
  data_leaks_blocked: number;
  entities_scrubbed: number;
  carbon_offset_kg: number;
  cache: { hit_rate: number; avg_similarity: number; cost_avoided_usd: number };
  actions_series: { t: string; allow: number; sanitize: number; warn: number; block: number }[];
  blocks_by_category: { category: string; count: number }[];
  models: { model: string; complexity: "low" | "medium" | "high"; requests: number; cost_usd: number }[];
}

// GET /api/health
interface HealthView {
  engine: { status: "ok" | "degraded" | "down"; kind: "mock" | "python"; version: string; uptime_s: number };
  providers: { name: string; kind: string; breaker: "CLOSED" | "OPEN" | "HALF_OPEN";
               p50_ms: number; p95_ms: number; error_rate: number; failovers: number }[];
  failover_chain: string[];
}

// GET /api/audit?from&to&limit&action&rule  → { entries: AuditLogEntry[]; total: number }
interface AuditLogEntry {
  id: string; request_id: string; timestamp: string; model_used: string | null;
  tokens_consumed: number | null; latency_ms: number | null; scrubbed_entity_count: number;
  rule_triggers: string[]; action: "allow" | "warn" | "sanitize" | "block"; error_code: string | null;
}

// GET/PUT /api/policies
interface AegisPolicy {
  pii_detection_enabled: boolean; secret_detection_enabled: boolean;
  prompt_injection_detection_enabled: boolean; hallucination_check_enabled: boolean;
  faithfulness_threshold: number; block_on_pii: boolean;
}

// Playground: POST /api/v1/chat/completions  { model, messages, stream: true }
// headers: x-aegis-mode: sanitize|strict, x-aegis-confidential: true, x-aegis-no-cache: true
// SSE: `data: {chat.completion.chunk}` … `event: aegis.stages` (pipeline stages)
//      … `event: aegis.telemetry` (provider, failover, cost, tokens, cache) … `data: [DONE]`
// Errors: JSON { error: { code, message, request_id }, aegis?: { stages, detection_categories } }
```

- Write one `parseSseStream()` helper and a `usePlaygroundRun()` reducer hook (idle → scanning →
  streaming → done | blocked | error) with an `AbortController` for Stop.
- Poll `/api/metrics` and `/api/health` every 5s, and pause polling when the tab is hidden.
- Validate every response with zod. If validation fails, show an inline error card, not a crash.

### 5. Charts (Recharts styling)
- Transparent chart backgrounds sitting on glass panels. Axis text 12px at `rgba(255,255,255,0.4)`,
  no axis lines, grid lines dashed at 0.06 opacity.
- Series colors: blue `#0175FF`, violet `#7B3FF2`, orange `#FF8A00`, amber `#F59E0B`, red `#EF4444`.
  Gradient area fills go from 40% to 0%.
- Glass tooltip: blurred dark card, 1px border, mono numbers, colored dot per series.
- Animate on first render only (600ms). No re-animation on every poll.

### 6. States and quality bar
- Every data component has **loading** (shimmer skeletons shaped like the content), **empty**
  (dim icon orb + one line + action) and **error** (amber glass card + Retry) states.
- Toasts appear bottom-right as glass cards with a colored left bar.
- Keyboard: `g o` Overview, `g p` Playground, `g a` Audit, `/` focuses search, `Esc` closes the drawer or modal.
- Accessibility:
  - `aria-live="polite"` on the pipeline, output and activity feed.
  - Focus rings; drawers and modals trap focus.
  - Charts have a visually hidden data table fallback.
  - AA contrast.
- **Security in the UI:**
  - Never display raw detection matches, API key values or the engine URL to the browser.
  - Render model output as text (no `dangerouslySetInnerHTML`).
  - Don't store prompts or responses in `localStorage`. UI prefs (theme, sidebar collapsed, reduce motion) are fine.
- `prefers-reduced-motion` and the Settings toggle disable: aurora drift, count-ups, shimmer, the stage shake and the drawer slide (use a fade instead).
- Responsive at 375 / 768 / 1280 / 1536px with no horizontal page scroll. Wide tables scroll inside their own card.
- **Routing:** landing page at `/`, dashboard under `/dashboard`, `/playground`, `/audit`, `/policies`,
  `/providers`, `/settings`. "Get Started" on the landing page links to `/dashboard`.
