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

- [ ] `backend/` scaffold per the directory structure
- [ ] `requirements.txt` split into base and ML extras so the service boots before models download
- [ ] `app/config.py` — pydantic-settings, every threshold from `.env`, no magic numbers in code
- [ ] `app/contracts/` — Pydantic models for **every** request and response in spec §4
- [ ] `app/main.py` — FastAPI app, CORS, request-ID middleware, exception handlers
- [ ] All 16 endpoints stubbed, returning contract-valid fixed JSON
- [ ] `app/utils/ids.py` (request IDs), `timing.py` (stage stopwatch), `logging.py` (**redacting formatter**)
- [ ] `GET /api/health` reporting model-load and DB status
- [ ] `scripts/export_openapi.py` → `openapi.json` for Person 2
- [ ] `Dockerfile` + `.dockerignore`
- [ ] `.env.example`
- [ ] `tests/test_contract.py` — every stub validates against its Pydantic model

**Exit:** `uvicorn app.main:app` serves all endpoints; `openapi.json` handed to Person 2.

---

## Phase 1 — Secret Scanner + Entropy

*No ML dependency. Fastest path to a real demo moment.*

- [ ] `config/secret_patterns.yaml` — patterns are data, never hardcoded
- [ ] AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, Slack, Stripe
- [ ] JWT three-segment structural match + `Bearer eyJ`
- [ ] PEM private keys (RSA / OPENSSH / generic / EC)
- [ ] DB URIs with embedded credentials: postgres, mysql, mongodb, redis, mssql
- [ ] `app/security/entropy.py` — Shannon entropy over candidate literals
- [ ] Entropy is a **confidence modifier only**, never an independent finding that blocks
- [ ] Per-match confidence scoring (prefix match + charset + length + entropy)
- [ ] `tests/test_secrets.py`, `tests/test_entropy.py` incl. false-positive corpus (UUIDs, git SHAs, base64 images)

**Exit:** demo scenario 1 (credential leak) detects correctly.

---

## Phase 2 — PII Scanner

- [ ] Presidio `AnalyzerEngine` + spaCy `en_core_web_lg`, **lazy-loaded singleton**
- [ ] Entities: PERSON, EMAIL, PHONE, IP, LOCATION, CREDIT_CARD, US_SSN, DATE_TIME, MEDICAL_LICENSE, NRP
- [ ] **Graceful degradation** — if models are absent, fall back to regex-only and report `degraded: true` in `/api/health`
- [ ] Confidence threshold configurable per entity type
- [ ] Overlapping-span resolution (longest match wins, higher confidence breaks ties)
- [ ] `tests/test_pii.py` — email, phone, name, IP, card, plus negative cases

**Exit:** demo scenario 2 (PII sanitize) detects 3 entities.

---

## Phase 3 — India-Specific Recognizers

*Requirement 5 groundwork. This is the differentiator.*

- [ ] `app/security/india_recognizers.py`
- [ ] **Aadhaar** — 12 digits + **Verhoeff checksum** validation (rejects random 12-digit numbers)
- [ ] **PAN** — `[A-Z]{5}[0-9]{4}[A-Z]` with 4th-char entity-type validation
- [ ] **IFSC** — `[A-Z]{4}0[A-Z0-9]{6}`
- [ ] **UPI VPA** — `handle@bank` against a known-PSP list
- [ ] **Indian mobile** — `+91` / `0` prefixed, leading digit 6-9
- [ ] **Indian name gazetteer** to lift spaCy NER recall on Indian names
- [ ] Register all as Presidio custom recognizers
- [ ] `tests/test_india_pii.py` — valid, invalid-checksum, and near-miss cases

**Exit:** demo scenario 3 detects `Priya Ramaswamy` and an Aadhaar number.

---

## Phase 4 — Injection Defense

- [ ] `config/injection_rules.yaml` — rule ID, pattern, weight, category
- [ ] Categories: instruction override, system-prompt extraction, role confusion, delimiter injection, jailbreak persona (DAN etc.), encoding evasion hints
- [ ] Weighted scoring → single `score` in `[0,1]`, threshold configurable
- [ ] Returns `matched_rules` by ID so the UI can show *why*
- [ ] Normalisation pass (unicode fold, whitespace collapse, leetspeak) before matching
- [ ] `tests/test_injection.py` — positives, benign security questions (false-positive guard), obfuscated variants documented as **known misses**

**Exit:** demo scenario 4 blocks with rule IDs shown.

---

## Phase 5 — Redactor & Vault Mapping

- [ ] Deterministic placeholder naming: `[EMAIL_1]`, `[PERSON_2]`, `[AWS_KEY_1]`
- [ ] Stable numbering within a request; identical values reuse the same placeholder
- [ ] Offset-safe replacement (apply right-to-left, handle overlaps)
- [ ] Returns `vault` map separately — **raw values never enter `detections[]`**
- [ ] `vault_policy` marks PII rehydratable, secrets never
- [ ] `tests/test_redactor.py` — overlapping spans, repeated values, unicode offsets

---

## Phase 6 — Policy Engine

- [ ] `config/policies.yaml` with `default` and `strict` profiles
- [ ] Actions: `allow` | `sanitize` | `warn` | `block`
- [ ] Precedence: `block` > `sanitize` > `warn` > `allow`
- [ ] `appealable` flag per rule (credentials false, injection true)
- [ ] Hot reload on file change
- [ ] **Zero detection logic in this module** — it only maps findings to actions
- [ ] Emits a decision event per evaluation
- [ ] `tests/test_policy.py` — full matrix of detection combinations × profiles

---

## Phase 7 — Real `/inspect`

*Replace the Phase 0 stub with the orchestrated pipeline.*

- [ ] Stage runner with **measured** per-stage `duration_ms`
- [ ] Order: PII → secrets → entropy → injection → policy → redact
- [ ] `routing_hint` complexity classifier (length, reasoning markers, code presence, question type)
- [ ] `cache.semantic_guards` extraction — negation tokens, numbers, named entities
- [ ] `cache.cacheable` false when secrets present
- [ ] Plain-language `explanation` generator (Requirement 4)
- [ ] `override_token` verification path (accepts an approved review)
- [ ] `tests/test_inspect.py` — end-to-end for all six demo scenarios

**Exit:** Person 2 swaps the stub for the real thing with no contract change.

---

## Phase 8 — Database Layer

- [ ] `app/audit/models.py` — `request_audit`, `review_request`, `policy_version`, `fairness_eval`
- [ ] `app/audit/database.py` — engine, session factory, SQLite→Postgres via `DATABASE_URL`
- [ ] Alembic migrations
- [ ] `app/audit/service.py` — write path, with a **field allowlist** so nothing unexpected is persisted
- [ ] Salted-hash helper for `user_ref_hash`
- [ ] `POST /audit/events` real implementation, idempotent on `request_id`
- [ ] Retention purge job + per-subject delete endpoint
- [ ] `tests/test_audit.py` — asserts no raw prompt, key or identifier reaches the DB

---

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

- [ ] `app/audit/metrics.py` aggregation queries
- [ ] `GET /api/metrics` — volume, latency p50/p95, tokens, cost
- [ ] `GET /api/metrics/security` — counts, top rules fired
- [ ] `GET /api/metrics/sustainability` — cache hit rate, Wh, gCO2e
- [ ] `GET /api/metrics/providers`
- [ ] `GET /api/audit/events` — pagination + filters
- [ ] `GET /api/audit/report`
- [ ] `config/pricing.yaml`, `config/sustainability.yaml` — every estimate carries a `basis` string
- [ ] `tests/test_metrics.py`

---

## Phase 13 — Fairness Evaluation Harness

*Requirement 5. Do not cut this.*

- [ ] `eval/name_corpus.yaml` — ~60 names × 5 origin groups (Indian, Anglo, Arabic, East Asian, African) in identical templates
- [ ] `eval/run_fairness.py` — recall / precision / F1 per group
- [ ] Persist to `fairness_eval`; record the **baseline before** India recognizers
- [ ] Re-run after Phase 3 and record the **after**
- [ ] `GET /api/fairness/report` returns both runs plus the measured gap
- [ ] `tests/test_fairness.py` — harness correctness, not a target score

**Exit:** a real, honest before/after table for the dashboard.

---

## Phase 14 — Human Review / Oversight API

*Requirement 1. Do not cut this.*

- [ ] `POST /api/reviews` — user appeals a block with a justification
- [ ] `GET /api/reviews` — queue with filters
- [ ] `POST /api/reviews/{id}/decision` — approve/deny with a reviewer note
- [ ] Approval mints a short-TTL, single-use `override_token` scoped to one `request_id`
- [ ] Token verification wired back into `/inspect`
- [ ] Non-appealable rules (credentials) reject appeals with a clear reason
- [ ] `tests/test_reviews.py` — full lifecycle, token replay rejection, scope violation

---

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
