# Person 1 — Build Plan

**Role:** Security & AI Engineer ("The Inspector")
**Deliverable:** a stateless FastAPI microservice that is the absolute authority on whether a prompt is safe, plus the database that records the platform's history.

17 phases. Each phase is independently testable and leaves the service in a working state. Phase 0 unblocks Person 2 and must land first.

---

## Dependency graph

```text
P0 Foundation & Contract  ──┬──> P1 Secrets ──┐
   (unblocks Person 2)      │                 │
                            ├──> P2 PII ──> P3 India Recognizers ──┐
                            │                                      │
                            ├──> P4 Injection ─────────────────────┤
                            │                                      │
                            └──> P5 Redactor ──> P6 Policy Engine ─┴──> P7 Real /inspect
                                                                            │
P8 Database ────────────────────────────────────────────────────────────────┤
P9 Embeddings ──────────────────────────────────────────────────────────────┤
P10 Grounding ──> P11 Egress Screen ────────────────────────────────────────┤
                                                                            ▼
                          P12 Metrics APIs ──> P13 Fairness ──> P14 Reviews ──> P15 Policies API
                                                                            │
                                                                            ▼
                                                                    P16 Hardening & Ship
```

**Critical path for the demo:** P0 → P1 → P2 → P5 → P6 → P7. Everything after that adds requirement coverage.

---

## Phase 0 — Foundation & Contract

*Goal: Person 2 can build against a real HTTP surface within the hour.*

- [x] `backend/` scaffold per the directory structure
- [x] `requirements.txt` split into base and ML extras so the service boots before models download
- [x] `app/config.py` — pydantic-settings, every threshold from `.env`, no magic numbers in code
- [x] `app/contracts/` — Pydantic models for **every** request and response in spec §4
- [x] `app/main.py` — FastAPI app, CORS, request-ID middleware, exception handlers
- [x] All 16 endpoints stubbed, returning contract-valid fixed JSON
- [x] `app/utils/ids.py` (request IDs), `timing.py` (stage stopwatch), `logging.py` (**redacting formatter**)
- [x] `GET /api/health` reporting model-load and DB status
- [x] `scripts/export_openapi.py` → `openapi.json` for Person 2
- [x] `Dockerfile` + `.dockerignore`
- [x] `.env.example`
- [x] `tests/test_contract.py` — every stub validates against its Pydantic model

**Exit:** `uvicorn app.main:app` serves all endpoints; `openapi.json` handed to Person 2. **DONE.**

---

## Phase 1 — Secret Scanner + Entropy

*No ML dependency. Fastest path to a real demo moment.*

- [x] `config/secret_patterns.yaml` — patterns are data, never hardcoded
- [x] AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, Slack, Stripe
- [x] JWT three-segment structural match + `Bearer eyJ`
- [x] PEM private keys (RSA / OPENSSH / generic / EC)
- [x] DB URIs with embedded credentials: postgres, mysql, mongodb, redis, mssql
- [x] `app/security/entropy.py` — Shannon entropy over candidate literals
- [x] Entropy is a **confidence modifier only**, never an independent finding that blocks
- [x] Per-match confidence scoring (prefix match + charset + length + entropy)
- [x] `tests/test_secrets.py`, `tests/test_entropy.py` incl. false-positive corpus (UUIDs, git SHAs, base64 images)

**Exit:** demo scenario 1 (credential leak) detects correctly. **DONE** -- 25 patterns, overlap resolution, JWT + placeholder validators, scanner warm-up at startup, 84 tests.

---

## Phase 2 — PII Scanner

- [x] Presidio `AnalyzerEngine` + spaCy `en_core_web_lg`, **lazy-loaded singleton**
- [x] Entities: PERSON, EMAIL, PHONE, IP, LOCATION, CREDIT_CARD, US_SSN, DATE_TIME, MEDICAL_LICENSE, NRP
- [x] **Graceful degradation** — if models are absent, fall back to regex-only and report `degraded: true` in `/api/health`
- [x] Confidence threshold configurable per entity type
- [x] Overlapping-span resolution (longest match wins, higher confidence breaks ties)
- [x] `tests/test_pii.py` — email, phone, name, IP, card, plus negative cases

**Exit:** demo scenario 2 (PII sanitize) detects 3 entities. **DONE** -- Presidio + spaCy with regex fallback, Luhn-validated cards, 47 tests, inference warm-up (first request 110ms -> 12ms).

**Measured baseline for Phase 3 / Requirement 5.** Identical sentence template, `en_core_web_sm`:

| Prompt | PERSON detected |
|---|---|
| `Contact John Smith at john@example.com ...` | yes, 0.85 |
| `Contact Priya Ramaswamy at priya@example.in ...` | **no** |

The detector protects the Anglo name and misses the Indian one. This is the gap Phase 3 closes and Phase 13 measures across a full corpus. Recorded here so the before/after is honest.

---

## Phase 3 — India-Specific Recognizers

*Requirement 5 groundwork. This is the differentiator.*

- [x] `app/security/india_recognizers.py`
- [x] **Aadhaar** — 12 digits + **Verhoeff checksum** validation (rejects random 12-digit numbers)
- [x] **PAN** — `[A-Z]{5}[0-9]{4}[A-Z]` with 4th-char entity-type validation
- [x] **IFSC** — `[A-Z]{4}0[A-Z0-9]{6}`
- [x] **UPI VPA** — `handle@bank` against a known-PSP list
- [x] **Indian mobile** — `+91` / `0` prefixed, leading digit 6-9
- [x] **Indian name gazetteer** to lift spaCy NER recall on Indian names
- [x] ~~Register all as Presidio custom recognizers~~ Implemented as an **always-on engine** instead -- a strict superset. Presidio-only recognisers would vanish in degraded mode, which is exactly when a fallback matters most
- [x] `tests/test_india_pii.py` — valid, invalid-checksum, and near-miss cases

**Exit:** demo scenario 3 detects `Priya Ramaswamy` and an Aadhaar number. **DONE** -- 61 tests, 298-name gazetteer, Verhoeff-validated Aadhaar, PAN holder-type check, IFSC bank list, UPI PSP list.

**The anecdote is fixed; Phase 13 then measured the whole corpus and found the systematic gap is elsewhere (see Phase 13).** With `en_core_web_lg` now installed:

| Prompt | spaCy lg | Gazetteer | Result |
|---|---|---|---|
| `Contact John Smith at ...` | caught, 0.85 | -- | PERSON |
| `Contact Priya Ramaswamy at ...` | **still missed** | caught, 0.88 | PERSON |

Even the large model misses the Indian name in this template. The gazetteer catches it, and works with no model loaded. Over the full corpus, though, the large model's Indian recall is 0.942 and the gazetteer lifts it to 0.950 -- the template above was a worst case, not the norm. See Phase 13.

---

## Phase 4 — Injection Defense

- [x] `config/injection_rules.yaml` — rule ID, pattern, weight, category
- [x] Categories: instruction override, system-prompt extraction, role confusion, delimiter injection, jailbreak persona (DAN etc.), encoding evasion hints
- [x] Weighted scoring → single `score` in `[0,1]`, threshold configurable
- [x] Returns `matched_rules` by ID so the UI can show *why*
- [x] Normalisation pass (unicode fold, whitespace collapse, leetspeak) before matching
- [x] `tests/test_injection.py` — positives, benign security questions (false-positive guard), obfuscated variants documented as **known misses**

**Exit:** demo scenario 4 blocks with rule IDs shown. **DONE** -- 27 rules across 6 OWASP LLM01 categories, per-category-max + noisy-OR scoring, five de-obfuscation passes (leet, spaced letters, homoglyphs, zero-width, base64 decode-and-rescan), compact whitespace-free signatures, system/assistant turns exempt, 77 tests.

**Two honest lists live in the tests.** Known misses: non-English attacks, keyword-free paraphrases, indirect extraction, chunked base64. Known false positives: `how do I enable developer mode?` blocks at 0.78 without a device context -- ambiguous, and appealable for exactly that reason.

---

## Phase 5 — Redactor & Vault Mapping

- [x] Deterministic placeholder naming: `[EMAIL_1]`, `[PERSON_2]`, `[AWS_KEY_1]`
- [x] Stable numbering within a request; identical values reuse the same placeholder
- [x] Offset-safe replacement (apply right-to-left, handle overlaps)
- [x] Returns `vault` map separately — **raw values never enter `detections[]`**
- [x] `vault_policy` marks PII rehydratable, secrets never
- [x] `tests/test_redactor.py` — overlapping spans, repeated values, unicode offsets

---

**DONE** -- 30 tests. Also fixed two latent bugs found on the way: scanners now run per message (so `message_index` and offsets are real, not into a joined string that does not exist), and multi-message requests are sanitised in place (the old code stuffed the joined text into the last message). Placeholder numbering is global per request: the same value in two turns shares one placeholder, different values never collide. Values are sliced from the source at resolved offsets; the scanners' per-call vault maps are no longer consulted.

## Phase 6 — Policy Engine

- [x] `config/policies.yaml` with `default` and `strict` profiles
- [x] Actions: `allow` | `sanitize` | `warn` | `block`
- [x] Precedence: `block` > `sanitize` > `warn` > `allow`
- [x] `appealable` flag per rule (credentials false, injection true)
- [x] Hot reload on file change
- [x] **Zero detection logic in this module** — it only maps findings to actions
- [x] Emits a decision event per evaluation
- [x] `tests/test_policy.py` — full matrix of detection combinations × profiles

---

**DONE** -- 47 engine tests + integration. Three profiles (`default`, `strict`, `permissive`) with inheritance; most-specific-key resolution; block > sanitize > warn > allow; highest-priority blocking rule supplies the reason; hot reload with bad-reload resilience. Override lifts only appealable rules -- the first draft lifted everything and the matrix caught it. Redaction is now action-aware: pipeline is scan -> resolve -> policy -> redact, so a warn-only profile flags without redacting. `GET /api/policies` serves the real file; `PUT` validates (persists in Phase 15).

## Phase 7 — Real `/inspect`

*Replace the Phase 0 stub with the orchestrated pipeline.*

- [x] Stage runner with **measured** per-stage `duration_ms`
- [x] Order: PII → secrets → entropy → injection → policy → redact
- [x] `routing_hint` complexity classifier (length, reasoning markers, code presence, question type)
- [x] `cache.semantic_guards` extraction — negation tokens, numbers, named entities
- [x] `cache.cacheable` false when secrets present
- [x] Plain-language `explanation` generator (Requirement 4)
- [x] `override_token` verification path (accepts an approved review)
- [x] `tests/test_inspect.py` — end-to-end for all six demo scenarios

**Exit:** Person 2 swaps the stub for the real thing with no contract change. **DONE** -- `security/pipeline.py` on the Phase 0 `StageRecorder`; ten measured stages in a fixed order; 26 end-to-end tests over the demo scenarios. `stub_inspect`, `STUB_MODE` and `stub_policy` deleted. Four ledger rows struck. One added: the permissive override verifier, replaced in Phase 14.

---

## Phase 8 — Database Layer

- [x] `app/audit/models.py` — `request_audit`, `review_request`, `policy_version`, `fairness_eval`
- [x] `app/audit/database.py` — engine, session factory, SQLite→Postgres via `DATABASE_URL`
- [x] Alembic migrations
- [x] `app/audit/service.py` — write path, with a **field allowlist** so nothing unexpected is persisted
- [x] Salted-hash helper for `user_ref_hash`
- [x] `POST /audit/events` real implementation, idempotent on `request_id`
- [x] Retention purge job + per-subject delete endpoint
- [x] `tests/test_audit.py` — asserts no raw prompt, key or identifier reaches the DB

---

**DONE** -- 4 tables, Alembic initial migration verified with `alembic check`, two-phase write (Inspector at `/inspect`, Gateway at `POST /audit/events`), idempotent upsert, per-subject erasure, retention purge, `GET /api/requests/{id}`. Privacy enforced by schema (no column can hold a prompt, credential or raw identity -- tested against every table) and by an AST-checked field allowlist. 23 tests plus API round-trips.

## Phase 9 — Embeddings

- [ ] `sentence-transformers` `all-MiniLM-L6-v2`, lazy singleton, warmed at startup
- [ ] `POST /embed` batch support
- [ ] Normalised vectors so Person 2's cosine search is correct
- [ ] Model name + dim returned so the gateway can assert index compatibility
- [ ] `tests/test_embed.py` — determinism, batch equality, dim check

---

## Phase 10 — Grounded Response Verification

- [ ] Sentence-level claim splitting
- [ ] Evidence retrieval — embed reference chunks, top-k per claim
- [ ] **NLI cross-encoder** entailment (not BERTScore)
- [ ] Per-claim `SUPPORTED` / `UNSUPPORTED` / `CONTRADICTED`
- [ ] Aggregate score + `status` via configurable thresholds
- [ ] Returns `unsupported_claims` for display
- [ ] `tests/test_grounding.py` — supported, unsupported, contradicted, no-reference (skips)

---

## Phase 11 — Egress Screening

- [ ] `POST /inspect/egress` full implementation
- [ ] Harm screen — categories with scores
- [ ] Bias screen — stereotype and demeaning-language signals (Requirement 5, output side)
- [ ] Composes with grounding into a single `action`: `PASS` | `ANNOTATE` | `REPLACE`
- [ ] Fallback replacement text configurable
- [ ] `tests/test_egress.py`

---

## Phase 12 — Metrics & Audit Read APIs

- [x] `app/audit/metrics.py` aggregation queries
- [x] `GET /api/metrics` — volume, latency p50/p95, tokens, cost
- [x] `GET /api/metrics/security` — counts, top rules fired
- [x] `GET /api/metrics/sustainability` — cache hit rate, Wh, gCO2e
- [x] `GET /api/metrics/providers`
- [x] `GET /api/audit/events` — pagination + filters
- [x] `GET /api/audit/report`
- [x] `config/pricing.yaml`, `config/sustainability.yaml` — every estimate carries a `basis` string
- [x] `tests/test_metrics.py`

---

**DONE** -- `app/audit/metrics.py` + `estimates.py`, 20 tests. Nearest-rank percentiles in Python (capped window). Estimates filled on the audit write from `pricing.yaml` / `sustainability.yaml`; every response carries the basis and names the counterfactual model. Report has one section per HLEG requirement. Two bugs caught by tests: percentile used round not ceil; prefix match took first not longest. Live: inspector overhead p50 6.2ms / p95 7.8ms over simulated traffic.

## Phase 13 — Fairness Evaluation Harness

*Requirement 5. Do not cut this.*

- [x] `eval/name_corpus.yaml` — ~60 names × 5 origin groups (Indian, Anglo, Arabic, East Asian, African) in identical templates
- [x] `eval/run_fairness.py` — recall / precision / F1 per group
- [x] Persist to `fairness_eval`; record the **baseline before** India recognizers
- [x] Re-run after Phase 3 and record the **after**
- [x] `GET /api/fairness/report` returns both runs plus the measured gap
- [x] `tests/test_fairness.py` — harness correctness, not a target score

**Exit:** a real, honest before/after table for the dashboard. **DONE** -- 1,800 samples per configuration, both persisted, 20 harness-correctness tests, `POST /api/fairness/run`, CLI runner.

**Result (en_core_web_lg):** Indian 0.942 -> 0.950 (gazetteer-covered 0.980 -> 1.000, held-out 0.914 unchanged); Anglo 0.972; Arabic 0.986; **East Asian 0.811; African 0.833**. Gap 0.175 -> 0.175, `gap_closed = 0.0`. Precision 1.00 everywhere.

**The measurement corrected the assumption.** The Phase 2 anecdote was true for its template and is fixed, but the systematic gap is East Asian (hyphenated given names, short names colliding with English words) and African (Southern African and Igbo names under-represented in training data). The India-focused gazetteer does nothing for them. Published as measured; no corpus names were added to any gazetteer. Next fix is in the ledger.

---

## Phase 14 — Human Review / Oversight API

*Requirement 1. Do not cut this.*

- [x] `POST /api/reviews` — user appeals a block with a justification
- [x] `GET /api/reviews` — queue with filters
- [x] `POST /api/reviews/{id}/decision` — approve/deny with a reviewer note
- [x] Approval mints a short-TTL, single-use `override_token` scoped to one `request_id`
- [x] Token verification wired back into `/inspect`
- [x] Non-appealable rules (credentials) reject appeals with a clear reason
- [x] `tests/test_reviews.py` — full lifecycle, token replay rejection, scope violation

---

**DONE** -- `app/reviews/service.py`, 24 tests plus the API lifecycle. Appeals persist to `review_request` and link back to the audit row. Approval mints a token once and stores only its hash. `ReviewOverrideVerifier` is the pipeline default: approved, scoped to one request_id, unexpired, single-use, consumed only when it actually lifted a block. A valid injection-override token still cannot lift a credential block in the same request. Verified live: block -> appeal -> approve -> replay lifts -> replay again refused ("token already used").

## Phase 15 — Policies API & Versioning

- [ ] `GET /api/policies` — current YAML + version
- [ ] `PUT /api/policies` — validate, then write a new immutable `policy_version` row
- [ ] Diff summary between versions
- [ ] Rollback endpoint
- [ ] `tests/test_policies_api.py`

---

## Phase 16 — Hardening & Ship

- [ ] Input size limits, request timeouts, per-tenant rate limiting
- [ ] Security headers, safe error envelopes (no stack traces)
- [ ] **Assert the redacting logger** — a test that greps captured logs for known secrets
- [ ] Startup model warm-up so demo-day cold start is not a risk
- [ ] Retention purge scheduler
- [ ] `README.md` — setup, curl examples, architecture, **limitations section**
- [ ] Docker image with models baked in
- [ ] `docker-compose` integration verified with Person 2
- [ ] Full `pytest` green; coverage on every scanner

---

## Debt ledger -- hardcoded things that must not survive Phase 16

Living list. Most items die in a scheduled phase; the rest are the final
sweep's checklist. Add to it whenever something is hardcoded to keep moving.

| Item | Where | Should be | Removed in |
|---|---|---|---|
| ~~Decision if/else chain (secrets->BLOCK, pii->SANITIZE)~~ | `stubs.py` | `config/policies.yaml` | **done, Phase 6** |
| ~~`NON_APPEALABLE_RULES` set~~ | `api/governance.py` | derived from `policies.yaml` `appealable` flags | **done, Phase 6** |
| ~~Routing complexity thresholds (20 / 120 words)~~ | `stubs.py` | `config/routing.yaml` | **done, Phase 7** |
| ~~Negation / number regex for `semantic_guards`~~ | `stubs.py` | `config/routing.yaml` | **done, Phase 7** |
| ~~`STUB_MODE = True` flag, misleading now~~ | `stubs.py` | gone | **done, Phase 7** |
| ~~Whole-request `stubs.py` orchestration~~ | `stubs.py` | `security/pipeline.py` with `StageRecorder` | **done, Phase 7** |
| `_KNOWN_BANK_CODES`, `_UPI_PSPS` | `india_recognizers.py` | YAML, per "patterns are data" | sweep |
| Honorific list | `pii_scanner.py` regex | YAML | sweep |
| `_LEADING_STOP` overlaps `contact_cues` | `india_recognizers.py` / `india_names.yaml` | one list | sweep |
| Health component list maintained by hand | `api/health.py` | derived from a scanner registry | Phase 16 |
| Reviewer identity is a free-text `reviewer_ref`, unauthenticated | `api/governance.py` | reviewer role + auth; RBAC is Person 2's gateway concern, the Inspector should at least require a shared secret | Phase 16 |
| `BUILD_PHASE` string bumped by hand | `api/health.py` | derived from git tag or version | Phase 16 |
| ~~Scanners run on joined text; `message_index` always 0~~ | `stubs.py` | per-message scan, real offsets | **done, Phase 5** |
| ~~In-memory review records~~ | `api/governance.py` | `review_request` table | **done, Phase 14** |
| ~~`PermissiveOverrideVerifier` accepts any `ovr_` token~~ | `security/pipeline.py` | `ReviewOverrideVerifier` is the default; permissive kept for tests only | **done, Phase 14** |
| Deterministic hash "embeddings" | `api/embed.py` | sentence-transformers | Phase 9 |
| Fixed 8/10 grounding result | `stubs.py` | NLI cross-encoder | Phase 10 |
| Egress always PASS | `stubs.py` | harm/bias screen | Phase 11 |
| ~~Metrics return zeros~~ | `stubs.py` | aggregation over `request_audit` | **done, Phase 12** |
| ~~Fairness report nulls~~ | `stubs.py` | measured harness output | **done, Phase 13** |
| PERSON recall gap for East Asian (0.81) and African (0.83) names | detector | gazetteers for those groups sourced independently of the eval corpus; hyphen-aware name matching | post-16 / roadmap |
| Policy PUT not persisted | `api/governance.py` | `policy_version` table | Phase 15 |

---

## Testing standard

Every phase ships tests in the same commit. Minimum per scanner: true positives, true negatives, boundary cases, and a documented **known-misses** list. The known-misses list is an ethics deliverable, not an admission of failure — it feeds the UI limitations panel.

---

## Non-negotiables carried from the spec

1. Scanners report; the policy engine decides.
2. Raw values never appear in `detections[]`, logs, or the database.
3. Entropy never blocks on its own.
4. Secrets never rehydrate.
5. Every `duration_ms` is measured, never estimated.
6. Every cost and carbon figure carries its `basis`.
7. The service stays stateless — session state belongs to Person 2's Redis.
