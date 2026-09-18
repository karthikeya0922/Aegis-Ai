"""`aegis scan`: files, the git index, or a diff -- with baselines and SARIF."""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from aegis_cli.local import Finding, scan_text

MAX_BYTES_DEFAULT = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl", ".pyc", ".so", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".db", ".sqlite", ".safetensors", ".bin", ".pptx", ".docx", ".xlsx"}

SEVERITY_RANK = {"block": 3, "sanitize": 2, "warn": 1, "allow": 0}
FAIL_ON_RANK = {"secret": ("SECRET",), "pii": ("SECRET", "PII"), "any": ("SECRET", "PII", "ENTROPY")}


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def _is_binary(data: bytes) -> bool:
    return b"\0" in data[:8000]


def _gitignored(root: Path, paths: list[Path]) -> set[Path]:
    """Ask git which of these paths are ignored. Empty set outside a repo."""
    if not paths:
        return set()
    try:
        rel = [str(p.relative_to(root)) for p in paths]
        r = subprocess.run(["git", "check-ignore", "--stdin"], input="\n".join(rel), capture_output=True,
                           text=True, cwd=root)
        return {root / line.strip() for line in r.stdout.splitlines() if line.strip()}
    except (OSError, ValueError):
        return set()


def iter_files(targets: list[Path], *, max_bytes: int = MAX_BYTES_DEFAULT, include: list[str] | None = None,
               exclude: list[str] | None = None) -> list[tuple[str, str]]:
    """(display_path, text) for every scannable file under the targets."""
    files: list[Path] = []
    for t in targets:
        t = t.resolve()
        if t.is_file():
            files.append(t)
            continue
        for p in t.rglob("*"):
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.is_file():
                files.append(p)
    root = _git_root(Path.cwd()) or Path.cwd()
    ignored = _gitignored(root, [f for f in files if _under(f, root)])
    out: list[tuple[str, str]] = []
    for f in files:
        if f in ignored:
            continue
        rel = _display(f, root)
        if include and not any(fnmatch.fnmatch(rel, g) for g in include):
            continue
        if exclude and any(fnmatch.fnmatch(rel, g) for g in exclude):
            continue
        if f.suffix.lower() in BINARY_EXT:
            continue
        try:
            if f.stat().st_size > max_bytes:
                continue
            data = f.read_bytes()
        except OSError:
            continue
        if _is_binary(data):
            continue
        out.append((rel, data.decode("utf-8", errors="replace")))
    return out


def _under(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _display(p: Path, root: Path) -> str:
    return str(p.relative_to(root)).replace("\\", "/") if _under(p, root) else str(p)


def _git_root(cwd: Path) -> Path | None:
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, cwd=cwd)
        return Path(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else None
    except OSError:
        return None


def staged_files(cwd: Path | None = None) -> list[tuple[str, str]]:
    """What is about to be committed: blob contents from the index, not the
    working tree, so an unstaged edit cannot hide a staged secret."""
    cwd = cwd or Path.cwd()
    r = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
                       capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "not a git repository")
    out = []
    for name in filter(None, r.stdout.split("\0")):
        if Path(name).suffix.lower() in BINARY_EXT:
            continue
        blob = subprocess.run(["git", "show", f":{name}"], capture_output=True, cwd=cwd)
        if blob.returncode != 0 or _is_binary(blob.stdout) or len(blob.stdout) > MAX_BYTES_DEFAULT:
            continue
        out.append((name, blob.stdout.decode("utf-8", errors="replace")))
    return out


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def diff_added_lines(ref: str, cwd: Path | None = None) -> dict[str, set[int]]:
    """path -> line numbers added since `ref` (working tree vs ref)."""
    cwd = cwd or Path.cwd()
    r = subprocess.run(["git", "diff", ref, "--unified=0", "--no-color", "--diff-filter=ACMR"],
                       capture_output=True, text=True, cwd=cwd, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"git diff {ref} failed")
    added: dict[str, set[int]] = {}
    current: str | None = None
    for line in r.stdout.splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            current = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            continue
        m = _HUNK.match(line)
        if m and current:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            added.setdefault(current, set()).update(range(start, start + count))
    return added


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {e["fingerprint"] for e in raw.get("findings", [])}


def write_baseline(path: Path, findings: list[Finding]) -> None:
    body = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Fingerprints only (hash of path, type and value). No secret values are stored here.",
        "findings": [{"fingerprint": f.fingerprint, "path": f.path, "line": f.line, "type": f.type} for f in findings],
    }
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    suppressed_baseline: int
    suppressed_inline: int
    fail_on: str
    profile: str

    @property
    def failing(self) -> list[Finding]:
        cats = FAIL_ON_RANK[self.fail_on]
        return [f for f in self.findings if f.category in cats and not f.allowed_inline
                and SEVERITY_RANK.get(f.action, 0) >= 1]

    @property
    def exit_code(self) -> int:
        return 1 if self.failing else 0

    def to_json(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "profile": self.profile,
            "fail_on": self.fail_on,
            "suppressed": {"baseline": self.suppressed_baseline, "inline": self.suppressed_inline},
            "findings": [asdict(f) for f in self.findings],
            "failing": len(self.failing),
            "exit_code": self.exit_code,
            "disclaimer": "Heuristic detection: pattern, entropy and (optionally) NER based. It can miss secrets and can flag test fixtures.",
        }


def run_scan(sources: list[tuple[str, str]], *, profile: str, pii: bool, fail_on: str,
             baseline: set[str] | None = None, only_lines: dict[str, set[int]] | None = None) -> ScanResult:
    findings: list[Finding] = []
    suppressed_b = suppressed_i = 0
    for path, text in sources:
        for f in scan_text(path, text, profile=profile, pii=pii):
            if only_lines is not None and f.line not in only_lines.get(path, set()):
                continue
            if baseline and f.fingerprint in baseline:
                suppressed_b += 1
                continue
            if f.allowed_inline:
                suppressed_i += 1
            findings.append(f)
    return ScanResult(findings, len(sources), suppressed_b, suppressed_i, fail_on, profile)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def to_sarif(res: ScanResult, version: str) -> dict:
    level = {"block": "error", "sanitize": "warning", "warn": "note", "allow": "none"}
    rules: dict[str, dict] = {}
    results = []
    for f in res.findings:
        rid = f"aegis/{f.category.lower()}/{f.type}"
        rules.setdefault(rid, {
            "id": rid, "name": f.type,
            "shortDescription": {"text": f"{f.category.title()} detection: {f.type}"},
            "properties": {"category": f.category},
        })
        results.append({
            "ruleId": rid,
            "level": "none" if f.allowed_inline else level.get(f.action, "warning"),
            "message": {"text": f"{f.type} ({f.category.lower()}, confidence {f.confidence}) -> policy {f.action}"
                                f"{' [allowed by annotation]' if f.allowed_inline else ''}; preview {f.preview}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {"startLine": f.line, "startColumn": f.column},
            }}],
            "partialFingerprints": {"aegis/v1": f.fingerprint},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "aegis-cli", "version": version,
                "informationUri": "https://github.com/karthikeya0922/Aegis-Ai",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"disclaimer": res.to_json()["disclaimer"]},
        }],
    }
