# aegis-cli

Aegis from the terminal. Two jobs:

1. **`aegis scan`** -- stop a credential before it is *committed*. Runs the
   Inspector's secret, entropy and (optionally) PII scanners in-process, so a
   commit never waits on a network call. Ships as a git pre-commit hook and a
   CI step (SARIF).
2. **`aegis chat`** -- a guarded chat that goes through the Aegis Gateway, so
   routing, failover, semantic cache and audit all happen for real, rendered
   as the live pipeline readout. *(next checkpoint)*

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
