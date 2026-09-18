# Aegis Mock Engine

Standalone mock of Person 1's Python security engine. Implements the full
`/internal/*` contract from [`../../lib/types/aegis.ts`](../../lib/types/aegis.ts)
with realistic fake data, so frontend work never blocks on the real engine.

## Run

```bash
npm install
npm run dev     # tsx watch — restarts on change
# or
npm start       # one-shot
```

Listens on `http://localhost:8001` (override with `PORT`).

## Endpoints

| Method | Path                | Feature                              |
|--------|---------------------|---------------------------------------|
| POST   | `/internal/scan`    | PII / secret / prompt-injection scan |
| POST   | `/internal/verify`  | RAG faithfulness / hallucination     |
| POST   | `/internal/audit`   | Write an audit log entry             |
| GET    | `/internal/audit`   | Query audit log entries              |
| GET    | `/internal/policies`| Read guardrail policy                |
| PUT    | `/internal/policies`| Update guardrail policy              |
| GET    | `/internal/health`  | Liveness / version                   |

## Mock behavior

- Prompt contains an AWS key (`AKIA...`) or `postgres://` connection string →
  `action: "block"`, `error_code: "CREDENTIAL_LEAK_PREVENTED"`.
- Prompt contains "ignore previous instructions" →
  `action: "block"`, `error_code: "PROMPT_INJECTION_BLOCKED"`.
- Prompt contains an email address or a capitalized "Full Name" →
  `action: "sanitize"`, with `[EMAIL_1]` / `[PERSON_1]` placeholders.
- Otherwise → `action: "allow"`.
- Every response includes a realistic `stages[]` pipeline with jittered
  `duration_ms` values for the live inspector UI.

Point the frontend at this by setting `AEGIS_ENGINE_URL=http://localhost:8001`
(see `frontend/.env.example`). Swap it for the real engine's URL later — the
contract doesn't change.
