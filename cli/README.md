# aegis-cli

Aegis from the terminal. Two jobs:

1. **`aegis scan`** -- stop a credential before it is *committed*. Runs the
   Inspector's secret, entropy and (optionally) PII scanners in-process, so a
   commit never waits on a network call. Ships as a git pre-commit hook and a
   CI step (SARIF).
2. **`aegis chat`** -- a guarded chat that goes through the Aegis Gateway, so
   routing, failover, semantic cache and audit all happen for real, rendered
   as the live pipeline readout. Plus `appeal` / `reviews` for human
   oversight and `status` for the deployment's numbers.

```
pip install -e ./cli          # from the repository root; needs backend/ alongside
aegis --help
```

## `aegis scan`

```
aegis scan                        # current directory, respects .gitignore
aegis scan src/ config/           # paths
aegis scan --staged               # the git index -- what is about to be committed
aegis scan --diff origin/main     # only lines added since a ref (CI on PRs)
aegis scan --pii --fail-on pii    # also run the PII scanner (loads the NER model)
aegis scan --format sarif -o aegis.sarif      # GitHub code scanning
aegis scan --format json
```

| Exit | Meaning |
|---|---|
| 0 | clean, or only findings below `--fail-on` |
| 1 | findings at or above `--fail-on` (`secret` by default; `pii`, `any`) |
| 2 | error: bad arguments, backend not found, git failure |

**Matched values are never printed, logged or stored.** A masked preview
(`AKIA************MPLE`) is shown at most; JSON and SARIF carry the same
preview and a fingerprint, never the value.

### Pre-commit hook

```
aegis install-hook              # writes .git/hooks/pre-commit
aegis install-hook --uninstall
```

A commit with a staged credential is refused with the finding shown masked.
Two overrides, both visible:

- once: `AEGIS_ALLOW=1 git commit ...` (the hook prints that it was skipped)
- per line: append `# aegis:allow` -- the finding is still listed, marked
  "allowed by annotation", and does not fail the scan

If the repo uses the [pre-commit framework](https://pre-commit.com),
`install-hook` prints the `repos:` snippet to add instead.

### Baseline for an existing repo

```
aegis scan --baseline .aegis-baseline.json --update-baseline   # once
aegis scan --baseline .aegis-baseline.json                     # from then on
```

The baseline holds fingerprints (a hash of path, type and value), never the
values. A changed value at the same place is a new finding.

### Policy

`--profile default|strict|permissive` selects the same profile the Gateway
uses (`backend/config/policies.yaml`). Under `default`, secrets are BLOCK and
PII is SANITIZE, which is why `--fail-on` defaults to `secret`: PII in source
is usually a test fixture and should warn, not break the build, unless you ask.

## `aegis chat`

```
aegis chat "Contact john@example.com about the merger"   # one shot
aegis chat                                              # REPL, keeps history
aegis chat "..." --mode strict                          # strict profile (x-aegis-mode)
aegis chat "..." --no-cache                             # bypass the semantic cache
aegis chat "..." --confidential                         # strict + no cache
aegis chat "..." --ref policy.md --ref faq.md           # grounding against reference docs
aegis chat "..." --explain                              # then print the Inspector's audit row
aegis chat "..." --json                                 # machine-readable outcome
```

The readout, in the order the Gateway streams it:

```
pipeline
ok   secret_scanner              0.1 ms
!!   pii_scanner                19.1 ms  1 finding(s)
ok   policy_engine               0.6 ms  profile=default v1 decision=SANITIZE rules=pii
ok   cache_hint                  0.0 ms  not cacheable: personal_data_present
+- sent to the provider (sanitised) ----------------------------+
| Contact [EMAIL_1] about the merger.                           |
+---------------------------------------------------------------+
answer
Please review the merger proposal promptly.
provider groq  cache MISS  grounding pass (1)  rehydrated  req_...
```

Streamed tokens cannot be retracted. When the trailing `aegis.grounding`
frame carries a different final text -- placeholders rehydrated, or the
Gateway's fallback after a grounding block -- it is shown in a "final
answer" panel under the streamed text, so what the model actually said and
what the client should show are both visible.

Exit codes: `0` answered (a grounding fallback is still 0), `1` blocked by
policy, `2` gateway/provider error.

### Human oversight from the terminal

```
aegis appeal <request_id> "why this should be allowed"     # opens a review
aegis reviews list [--status PENDING|APPROVED|DENIED|all]
aegis reviews decide <review_id> --approve|--deny [--note ..] [--reviewer ..]
```

`decide` sends `X-Reviewer-Token` from `AEGIS_REVIEWER_TOKEN` when set; an
approval prints the single-use, request-scoped override token.

## `aegis status`

```
aegis status              # services, traffic, security, cache/sustainability, providers, reviews, fairness
aegis status --watch      # redraw every 5 s
aegis status --json
```

Every estimate is printed with the basis string the API returns. The
fairness section prints per-group recall and the worst-best gap as measured
-- including when the gap is not closed.

## Configuration

`~/.aegis/config.toml`, overridden by environment. `aegis config` shows the
resolved values and their source.

| key | env | default |
|---|---|---|
| `engine_url` | `AEGIS_ENGINE_URL` | `http://localhost:8000` |
| `gateway_url` | `AEGIS_GATEWAY_URL` | `http://localhost:3000` |
| `profile` | `AEGIS_POLICY_PROFILE` | `default` |
| `backend_path` | `AEGIS_BACKEND_PATH` | auto-detected `../backend` |
| `reviewer_token` | `AEGIS_REVIEWER_TOKEN` | -- |

## What it does not do

- Detection is heuristic: patterns, entropy, and NER with `--pii`. It misses
  secrets that match no pattern and it flags fixtures that look real. Every
  scan prints this.
- It is not a replacement for provider-side safety or for rotating a key that
  was already pushed. If the hook refused a commit, the key is still on disk.
- `scan` runs locally and never talks to the Inspector service; `chat` and
  `status` do.
