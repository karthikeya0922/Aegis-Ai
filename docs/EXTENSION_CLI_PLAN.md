# Aegis beyond the gateway: browser extension + CLI

Two features ship as a **browser extension**, two as a **CLI tool**. Both are thin
front doors onto the Inspector and Gateway that already exist and are already
tested; neither reimplements detection, policy or routing. If a feature needs
new detection logic, it is in the wrong place.

## Allocation and why

| # | Feature | Form | What makes this the right home |
|---|---|---|---|
| E1 | **Threat Detection & Sanitisation** on third-party AI sites | Extension | The only way to protect a user typing into chat.openai.com / claude.ai / gemini.google.com is to sit in the browser. The extension intercepts the send, calls the local Inspector, and replaces the text with the sanitised version (or blocks) before the site ever sees it. |
| E2 | **Heuristic Prompt-Injection Defense** on pasted content | Extension | Same interception point, opposite direction: text a user *pastes* (a web page, an email, a "helpful" snippet) is scanned for injection before it goes into the model. Unique to the browser: the CLI never sees a paste. |
| C1 | **Threat Detection & Sanitisation** as a pre-commit / CI scanner | CLI | `aegis scan` + a git hook is the developer-side twin of E1: same scanner, different moment. Stops a leaked AWS key before it is *committed*, not just before it is *prompted*. Recognised tool category (`gitleaks`, `detect-secrets`) so judges know what they are looking at. |
| C2 | **Smart Routing & Semantic Cache**, shown as a live terminal Inspector | CLI | The CLI places the LLM call *through the Gateway*, so routing, failover and cache hit/miss are real events it can report -- the two features an extension structurally cannot execute. Rendered as the pipeline readout (Feature 5 in terminal form). |

Both form factors also carry a read-only **information panel** (extension popup /
`aegis status`) that reads `/api/metrics*`, `/api/audit/events` and
`/api/reviews`. That is the same dashboard data in a smaller container, costs
almost nothing, and is what makes the extension feel like part of one product
rather than a bookmarklet.

Ownership: **Person 1 builds the CLI** (Python, reuses `backend/app/security`
directly and the Gateway over HTTP). **Person 2 builds the extension**
(TypeScript, Manifest V3, reuses `lib/types/aegis.ts`). Interfaces between them
are the HTTP contracts already in `backend/openapi.json`; nothing new to agree.

---

## Part A -- Browser extension (Person 2)

Directory: `extension/`. Manifest V3, TypeScript, Vite build, no framework in
the content script (it must be tiny and fast). Popup may use React if Person 2
prefers; it shares `@aegis/types`.

### A0. Skeleton and connectivity (half day)

- [ ] `manifest.json`: `permissions: ["storage", "activeTab"]`,
      `host_permissions` for the supported chat sites and `http://localhost:8000/*`.
- [ ] Options page: Inspector URL (default `http://localhost:8000`), mode
      (`sanitize` | `strict`), per-site enable toggles, "show what was masked".
- [ ] Inspector CORS: `AEGIS_CORS_ORIGINS` must include `chrome-extension://<id>`.
      Add a note to `backend/.env.example`; during dev use the unpacked extension id.
- [ ] Health badge: popup shows green/amber/grey from `GET /internal/health`
      (`degraded` list rendered honestly, e.g. "hardening: tokens not set").

**Done when:** popup opens, shows Inspector version and health; a `fetch` to
`/internal/scan` from the extension origin succeeds (no CORS error).

### A1. E1 -- intercept, scan, sanitise (1.5 days)

- [ ] Site adapters, one file each, each exporting `{ match, findComposer, findSendControls, readText, writeText }`:
      `chatgpt.ts`, `claude.ts`, `gemini.ts`. Keep the DOM knowledge here and
      nowhere else -- these sites change their markup without notice.
- [ ] Interception: capture-phase listeners on the send button click and on
      `Enter` (without Shift) inside the composer. `preventDefault` +
      `stopImmediatePropagation`, then decide.
- [ ] Call `POST /internal/scan` with `{ request_id, session_id, messages:[{role:"user",content}], mode }`.
      Timeout 3 s. **Fail closed by default**: if the Inspector is unreachable,
      show "Aegis unavailable -- send anyway?" rather than silently sending.
      (Configurable to fail open in options; default stays closed.)
- [ ] Verdict handling, mirroring the Gateway's `scan-gate.ts` exactly:
      `allow` -> re-dispatch the original send; `sanitize` -> write
      `sanitized_messages[0].content` into the composer, flash the placeholders,
      re-dispatch; `warn` -> send original, toast; `block` -> do not send, inline
      card with `error_code` and the detection categories (never the values).
- [ ] Inline card: "2 items masked: EMAIL, PERSON. [Show] [Undo]". Show reveals
      the original values *locally* (they never left the page); Undo restores the
      original text and lets the user send it deliberately.
- [ ] Never log or store prompt text. `chrome.storage` holds settings only.

**Done when:** on chat.openai.com, typing `my key is AKIA...` and pressing Enter
produces the block card and nothing is sent; typing an email produces a
composer with `[EMAIL_1]` and the send goes through with the placeholder.

### A2. E2 -- injection defence on paste (1 day)

- [ ] `paste` listener on the composer: read `clipboardData`, if length > N (say 200
      chars, configurable) call `/internal/scan` on the pasted text alone.
- [ ] If `PROMPT_INJECTION` is among the detections: do not insert the paste;
      show "This pasted text contains instructions aimed at the model
      (rule: `<matched_rule>`). [Paste anyway] [Discard]". The rule id comes
      from `detections[].match` for the injection category (the adapter sets it
      to the rule id, never the text).
- [ ] Score below the block threshold but non-zero -> insert the paste, mark the
      composer border amber, tooltip with the score. Heuristic, and says so.
- [ ] Benign-paste regression list in the extension's tests (the same corpus
      as `backend/tests/test_injection.py`'s benign block): code snippets,
      recipes, a support email. None may trigger the block card.

**Done when:** pasting the demo injection text ("Ignore previous instructions
and ...") into claude.ai shows the card; pasting a README does not.

### A3. Information popup (half day)

- [ ] Popup tabs: **This page** (counts intercepted this session, last verdict,
      last pipeline stages with `duration_ms`), **Deployment** (reads
      `/api/metrics`, `/api/metrics/security`, `/api/metrics/sustainability`,
      `/api/metrics/providers`), **Reviews** (pending count from `/api/reviews`,
      link to the dashboard).
- [ ] Every number that has a `basis` in the API is shown with it. Cost and CO2
      are labelled "estimate".
- [ ] Refresh every 15 s while the popup is open; nothing runs in the background.

### A4. Tests, packaging, README (half day)

- [ ] Vitest: adapter selectors against saved HTML fixtures of each site's
      composer; verdict handling with a mocked `fetch`.
- [ ] `npm run build` -> `extension/dist`; load-unpacked instructions; a zip for
      the demo machine.
- [ ] `extension/README.md`: what it does, what it cannot do (it does not see
      the site's own network call, so no cache/routing on third-party sites --
      that information comes from your own Gateway deployment in the popup),
      and the fail-closed default.

**Extension total: ~4 days.** Cut order if time is short: A2 first (keep E2 as
"warn only"), then A3's Deployment tab.

---

## Part B -- CLI (Person 1)

Directory: `cli/`, package `aegis-cli`, Python 3.11, `typer` + `rich` + `httpx`.
Installed with `pip install -e ./cli`, entry point `aegis`. Two backends:

- **local**: imports `backend/app/security` directly (scanner, injection,
  policy engine). No server needed. Used by `scan` and the git hook so a commit
  never waits on a network call.
- **remote**: HTTP to the Gateway (`AEGIS_GATEWAY_URL`, default
  `http://localhost:3000`) and Inspector (`AEGIS_ENGINE_URL`). Used by `chat`
  and `status`.

### B0. Skeleton (half day)

- [ ] `cli/pyproject.toml`, `aegis --version`, `aegis config` (show resolved
      URLs, profile, mode), `~/.aegis/config.toml` + env overrides.
- [ ] Output modes on every command: human (rich), `--json`, `--quiet`.
      Exit codes are the contract for CI: `0` clean, `1` findings, `2` error.

### B1. C1 -- `aegis scan` and the pre-commit hook (1.5 days)

- [ ] `aegis scan <path>...`: walks files (respects `.gitignore`, skips
      binaries and files > 1 MB, configurable), runs the secret scanner,
      entropy and PII scanner per file, applies the policy profile, prints a
      table: file:line, type, confidence, action, placeholder. **Never prints
      the matched value** -- a masked preview (`AKIA****MPLE`) at most.
- [ ] `aegis scan --staged`: only the git index (what is about to be committed),
      reading blob contents from the index, not the working tree.
- [ ] `aegis scan --diff <ref>`: only added lines since `<ref>`, for CI on PRs.
- [ ] `aegis install-hook`: writes `.git/hooks/pre-commit` (or a
      `pre-commit` framework entry if `.pre-commit-config.yaml` exists) that
      runs `aegis scan --staged --quiet` and blocks the commit on exit 1 with a
      one-screen explanation and the override instruction.
- [ ] Override: `AEGIS_ALLOW=1 git commit` or `# aegis:allow` on the line, both
      recorded in the scan output as "allowed by annotation". No silent bypass.
- [ ] Baseline: `aegis scan --baseline .aegis-baseline.json` /
      `--update-baseline` so a legacy repo can adopt it without a 400-finding
      first run (same idea as `detect-secrets`).
- [ ] `--profile strict|default|permissive` maps to the policy profiles;
      `--fail-on secret|pii|any` (default `secret`; PII in code is usually a
      fixture, so it warns unless asked).
- [ ] SARIF output (`--format sarif`) so GitHub code scanning can ingest it.
      Small, and it is what makes "CI integration" true rather than claimed.

**Done when:** in a scratch repo, `git add` a file with an AWS key and `git
commit` is refused with the finding shown masked; with `# aegis:allow` it goes
through and the allow is printed.

### B2. C2 -- `aegis chat`: routing, cache and the terminal Inspector (1.5 days)

- [ ] `aegis chat "<prompt>"` and `aegis chat` (REPL). Sends to the Gateway's
      `/api/v1/chat/completions` (so routing, failover, cache and audit all
      happen for real) with `stream: true`, and renders:
      1. the `aegis.scan` SSE frame as the live pipeline checklist -- one line
         per stage with measured `duration_ms` and detail;
      2. the sanitised prompt if the verdict was `sanitize` (placeholders
         highlighted);
      3. the streamed answer;
      4. the `aegis.telemetry` frame as the footer: provider used, failover
         used, cache hit, latency, and the estimate line with its basis.
- [ ] `--mode strict`, `--no-cache` (`x-aegis-no-cache` header), `--ref <file>`
      attaches reference docs so the grounding stage and its verdict show up.
- [ ] `--explain`: after the answer, fetch `/api/requests/<request_id>` and print
      the full audit row (rules fired, policy version, estimate basis).
- [ ] Blocked verdicts render the same card the extension shows, with the
      appeal instruction: `aegis appeal <request_id> "<why>"` -> `POST /api/reviews`.
- [ ] `aegis appeal`, `aegis reviews` (pending list; decisions need
      `X-Reviewer-Token`, read from config) -- human oversight from the terminal.
- [ ] Session id persisted in `~/.aegis/session` so the Gateway's per-session
      behaviour (cache keyed by tenant, telemetry) is exercised across calls.

**Done when:** `aegis chat "Contact john@example.com about the merger"` shows
the PII stage flagged, the sanitised prompt, a real answer with the name
rehydrated, and a footer naming the provider; running the same prompt twice
shows `cache: HIT` the second time (needs Redis Stack up).

### B3. `aegis status` -- the information view (half day)

- [ ] One screen: Inspector health (components, degraded reasons), Gateway
      reachability, `/api/metrics` totals for the last 24 h, security counts,
      cache hit rate and estimated savings *with basis*, provider table,
      pending reviews, last fairness run (per-group recall, including the gap
      that is not closed -- printed, not hidden).
- [ ] `--watch` redraws every 5 s. `--json` for scripts.

### B4. Tests, packaging, README (half day)

- [ ] `cli/tests/`: scan on fixture files (assembled at runtime, same
      `_joined()` trick as the backend so GitHub push protection stays quiet),
      hook installation in a temp git repo, exit codes, SARIF validity,
      `chat` against a recorded SSE stream (no network in tests).
- [ ] `pipx install ./cli` works; `aegis --help` is the README's first block.
- [ ] `cli/README.md`: the four commands, exit codes, hook, baseline, what it
      does not do (it is not a replacement for provider-side safety, the
      detection is heuristic and says so on every finding).

**CLI total: ~4.5 days.** Cut order if short: SARIF, then the REPL (keep
one-shot `chat`), then `status --watch`.

---

## Shared work (both, one hour)

- [ ] Root `README.md`: add "Extension" and "CLI" rows to the parts table with
      one-line install instructions.
- [ ] `docker-compose.yml`: nothing -- both talk to the existing services.
- [ ] Pitch deck: one slide each. Demo moments, in order of impact:
      1. CLI: `git commit` refused with the masked AWS key. (15 s)
      2. Extension: paste a key into ChatGPT, watch it get blocked; type an
         email, watch it become `[EMAIL_1]` before send. (30 s)
      3. CLI: `aegis chat` twice, second run `cache: HIT`, footer shows the
         provider and the estimate basis. (30 s)
      4. Extension popup: the deployment's live numbers, fairness gap included. (15 s)

## Honesty rules carried over (spec section 11)

- Every finding says "heuristic"; no "100%", no "guaranteed".
- Matched values are never printed, logged, or stored by either tool.
- Cost / CO2 lines carry their basis string from the API, always.
- The extension's README states plainly that it cannot see a third-party
  site's own network call; cache/routing information in the popup is from
  *your* Gateway, not from OpenAI's servers.
- Fail closed by default when the Inspector is unreachable; the user can
  choose to fail open, and the choice is visible in the UI.
