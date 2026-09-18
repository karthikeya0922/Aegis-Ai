# Aegis -- Zero-Trust Responsible AI Gateway

Team Future Bytes. An inspection and governance layer that sits between an
organisation and the LLM providers it uses, built against the seven EU HLEG
requirements for Trustworthy AI. The design and the division of work are in
[`docs/AEGIS_PROBLEM_STATEMENT.md`](docs/AEGIS_PROBLEM_STATEMENT.md).

| Part | Owner | Where |
|---|---|---|
| **Inspector** -- FastAPI service: secret / PII / injection detection, redaction, policy engine, audit database, human review, fairness harness, embeddings, grounded response verification, egress screens | Person 1 | [`backend/`](backend/README.md) |
| **Gateway + dashboard** -- Next.js: provider routing, semantic cache, token vault, streaming, UI | Person 2 | `gateway/` (separate repository until merge) |
| Build plan and debt ledger | Person 1 | [`docs/PERSON1_BUILD_PLAN.md`](docs/PERSON1_BUILD_PLAN.md) |
| Pitch deck | -- | [`presentation/`](presentation/) |

## Run it

```bash
cp backend/.env.example .env      # set AEGIS_USER_HASH_SALT, AEGIS_ADMIN_TOKEN, AEGIS_REVIEWER_TOKEN
docker compose up --build         # inspector on :8000, postgres, redis
```

or, without Docker, follow the quick start in [`backend/README.md`](backend/README.md).
Interactive API docs at <http://localhost:8000/docs>; the contract is
[`backend/openapi.json`](backend/openapi.json).

## What it claims and what it does not

Detection is heuristic and says so in every response. Cost and carbon
figures are estimates and carry their basis. Grounded Response Verification
is a support score, not a truth oracle. The fairness harness reports what it
measures, including the gap it has not closed (PERSON recall for East Asian
and African names is lower than for other groups). The audit trail is
transaction evidence, not a conformity assessment. The full list is under
*Limitations* in the backend README.
