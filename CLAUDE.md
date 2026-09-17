# Aegis — Agent Rules

## RULE 1 (MANDATORY): Log every action in `docs/PROJECT.md`
Whatever the model/agent does in this repo — creating, editing or deleting files, installing
dependencies, changing config, making design decisions — it MUST append an entry to the
**Change Log** section of [docs/PROJECT.md](docs/PROJECT.md) in the same turn, before finishing.
No change is complete until the log is updated.

Entry format:
```
### YYYY-MM-DD — <short title>
- What changed (files / folders / deps)
- Why
- Next step / open questions
```

## RULE 2: Do not build features until the user says so
The user is driving phase by phase. Only scaffold/setup work is allowed until the user
explicitly says to start a phase (see the roadmap in docs/PROJECT.md).

## Environment
- Backend: `backend/` — Python 3.11 venv at `backend/.venv` (`source backend/.venv/bin/activate`)
- Frontend: `frontend/` — Next.js (App Router, TypeScript, Tailwind). See `frontend/AGENTS.md`.
