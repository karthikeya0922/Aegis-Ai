# Aegis Guard — browser extension

Scans what you type into **ChatGPT, Claude and Gemini** through your own
Aegis Inspector *before* the site receives it.

- **E1 — Threat detection & sanitisation on send.** Enter or the send button
  is intercepted, the text goes to `POST /internal/scan`, and the verdict is
  applied with the Gateway's own semantics: `allow` → sent; `sanitize` →
  the composer now holds `[EMAIL_1]`-style placeholders and you press send
  again (or Undo); `warn` → sent with a notice; `block` → nothing is sent,
  the card names the category, never the value.
- **E2 — Prompt-injection screen on paste.** A paste longer than 200
  characters (configurable) is scanned on its own. If it carries
  instructions aimed at the model, the paste is held with the matched rule
  id and a *Paste anyway / Discard* choice. Credentials in a paste are held
  the same way; personal data pastes go in with a note that they will be
  masked on send.
- **Popup.** *This page*: scans, masked, blocked, pastes held, and the last
  pipeline with measured stage timings. *Deployment*: your Gateway's
  traffic, security counts, cache hit rate, cost/energy **with their basis
  strings**, providers and failover, fairness recall per group. *Reviews*:
  pending appeals.

## Install (unpacked, no build step)

1. Start the Inspector (`backend/`, port 8000).
2. `chrome://extensions` → Developer mode → **Load unpacked** → this folder.
3. Open chatgpt.com / claude.ai / gemini.google.com. Type
   `my key is AKIA…` and press Enter: blocked. Type an email: masked.

Options (extension menu → Options): Inspector URL, `sanitize` / `strict`
mode, fail-open, paste threshold, per-site toggles.

## How it talks to the Inspector

All requests are made by the **service worker** from the extension origin
(`host_permissions` covers `localhost:8000`), so the Inspector needs no
CORS entry for the chat sites and the page never learns its address. The
worker strips raw matched values before anything reaches the content
script: it forwards categories, placeholders, offsets and, for injection,
the rule id. Per-tab counters live in `chrome.storage.session` and vanish
when the browser closes. Prompt text is never stored.

## Fail closed

If the Inspector does not answer within 3 s, the send is **held** and the
card offers *Send anyway*. Fail-open is a visible option, off by default.

## What it cannot do — stated plainly

- It cannot see the chat site's own network call to its model. Cache hit
  rate, routing and cost in the popup are **your Gateway's** numbers for
  traffic that went through Aegis, not OpenAI's or Anthropic's.
- Detection is heuristic (patterns, entropy, NER, injection rules). It
  misses what matches no rule and flags fixtures that look real. Every card
  says so.
- The site adapters in `adapters.js` depend on each site's markup, which
  changes without notice. When a site stops being intercepted, that file is
  the only place to look; a generic fallback catches the focused composer.
- `sanitize` is a two-step send on purpose (mask, then you press send). An
  automatic re-send would remove your chance to Undo.

## Files

```
manifest.json   MV3; content scripts on the three sites; service worker
background.js   settings, /internal/scan, /internal/health, metrics, per-tab counters
adapters.js     site selectors (the only DOM knowledge)
content.js      send interception (E1), paste screen (E2), cards
popup.*         this page / deployment / reviews
options.*       settings
```
