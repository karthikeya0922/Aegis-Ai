"""Local backend: the Inspector's scanners imported in-process.

`aegis scan` and the git hook must never wait on a network call, so they
import `backend/app/security` directly. Detection logic is not duplicated
here; this module only locates the backend, runs the scanners on a file, and
turns the result into line-numbered findings with masked previews.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from aegis_cli.config import CLIConfig


class BackendNotFound(RuntimeError):
    pass


def _candidates(cfg: CLIConfig) -> list[Path]:
    out: list[Path] = []
    if cfg.backend_path:
        out.append(Path(cfg.backend_path))
    here = Path(__file__).resolve()
    out.append(here.parents[2] / "backend")  # repo checkout: <root>/cli/aegis_cli/local.py
    out.append(Path.cwd() / "backend")
    return out


def bootstrap(cfg: CLIConfig | None = None) -> Path:
    """Put the backend on sys.path once. Returns the backend directory."""
    cfg = cfg or CLIConfig.load()
    for cand in _candidates(cfg):
        if (cand / "app" / "security" / "secret_scanner.py").exists():
            p = str(cand)
            if p not in sys.path:
                sys.path.insert(0, p)
            # The Inspector's settings read .env relative to the backend dir.
            os.environ.setdefault("AEGIS_CLI", "1")
            return cand
    raise BackendNotFound(
        "Could not find the Aegis backend (looked for backend/app/security). "
        "Run from the repository, or set AEGIS_BACKEND_PATH."
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    path: str
    line: int
    column: int
    type: str            # e.g. AWS_ACCESS_KEY, EMAIL_ADDRESS, HIGH_ENTROPY_STRING
    category: str        # SECRET | PII | ENTROPY
    confidence: float
    action: str          # block | sanitize | warn | allow  (from the policy profile)
    preview: str         # masked, never the value
    fingerprint: str     # stable id for baselines; hash of (path, type, value)
    allowed_inline: bool = False
    rule_id: str | None = None


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    if len(v) <= 12:
        return v[:2] + "*" * (len(v) - 4) + v[-2:]
    return v[:4] + "*" * min(len(v) - 8, 12) + v[-4:]


def fingerprint(path: str, ftype: str, value: str) -> str:
    return hashlib.sha256(f"{path}\0{ftype}\0{value}".encode("utf-8")).hexdigest()[:16]


def _line_col(text: str, offset: int, line_starts: list[int]) -> tuple[int, int]:
    import bisect

    i = bisect.bisect_right(line_starts, offset) - 1
    return i + 1, offset - line_starts[i] + 1


@lru_cache
def _engines(profile: str, pii: bool):
    bootstrap()
    from app.contracts.common import InjectionFinding  # noqa: WPS433
    from app.security import entropy as entropy_mod
    from app.security.policy_engine import get_policy_engine
    from app.security.secret_scanner import get_scanner

    pii_scanner = None
    if pii:
        from app.security.pii_scanner import get_pii_scanner

        pii_scanner = get_pii_scanner()
    return get_scanner(), entropy_mod, pii_scanner, get_policy_engine(), InjectionFinding


ALLOW_MARKER = "aegis:allow"


def scan_text(path: str, text: str, *, profile: str = "default", pii: bool = False) -> list[Finding]:
    """Run the Inspector's scanners on one file's text."""
    secrets, entropy_mod, pii_scanner, policy, InjectionFinding = _engines(profile, pii)

    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    lines = text.split("\n")

    detections, vault = secrets.scan(text)
    ent = entropy_mod.scan(text)
    # Drop entropy findings that overlap a recognised secret: the secret is the
    # better explanation and the policy already acts on it.
    spans = [(d.start, d.end) for d in detections]
    ent = [e for e in ent if not any(s <= e.start < t or s < e.end <= t for s, t in spans)]
    if pii_scanner is not None:
        pdet, pvault = pii_scanner.scan(text)
        detections += pdet
        vault.update(pvault)

    decision = policy.evaluate(detections, ent, InjectionFinding(), profile=profile)

    out: list[Finding] = []
    for d in decision.detections:
        value = vault.get(d.placeholder or "", "")
        line, col = _line_col(text, d.start, line_starts)
        src = lines[line - 1] if line - 1 < len(lines) else ""
        out.append(Finding(
            path=path, line=line, column=col, type=d.type, category=d.category.value,
            confidence=round(d.confidence, 3), action=d.action.value,
            preview=mask(value) if value else (d.placeholder or "-"),
            fingerprint=fingerprint(path, d.type, value or f"{d.start}:{d.end}"),
            allowed_inline=ALLOW_MARKER in src, rule_id=d.pattern or d.recognizer,
        ))
    for e in ent:
        line, col = _line_col(text, e.start, line_starts)
        src = lines[line - 1] if line - 1 < len(lines) else ""
        raw = text[e.start:e.end]
        out.append(Finding(
            path=path, line=line, column=col, type=e.type, category="ENTROPY",
            confidence=round(e.confidence, 3), action="warn",
            preview=mask(raw), fingerprint=fingerprint(path, e.type, raw),
            allowed_inline=ALLOW_MARKER in src, rule_id=f"entropy>={e.entropy:.2f}",
        ))
    out.sort(key=lambda f: (f.path, f.line, f.column))
    return out
