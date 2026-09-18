"""`aegis install-hook`: a pre-commit hook that runs `aegis scan --staged`."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

HOOK_MARKER = "# aegis-cli pre-commit hook"

HOOK_BODY = f"""#!/bin/sh
{HOOK_MARKER}
# Refuses a commit whose staged content contains a credential.
# Override once:   AEGIS_ALLOW=1 git commit ...
# Override a line: add  # aegis:allow  on that line (recorded in the scan output).
if [ "$AEGIS_ALLOW" = "1" ]; then
  echo "aegis: AEGIS_ALLOW=1 set, skipping staged scan for this commit" >&2
  exit 0
fi
if command -v aegis >/dev/null 2>&1; then
  exec aegis scan --staged --hook
fi
if command -v python >/dev/null 2>&1; then
  exec python -m aegis_cli scan --staged --hook
fi
echo "aegis: CLI not found on PATH; install with 'pip install -e ./cli' (commit allowed)" >&2
exit 0
"""

PRE_COMMIT_FRAMEWORK_SNIPPET = """  - repo: local
    hooks:
      - id: aegis-scan
        name: aegis scan (staged)
        entry: aegis scan --staged --hook
        language: system
        pass_filenames: false
"""


def git_dir(cwd: Path) -> Path:
    r = subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        raise RuntimeError("not a git repository")
    p = Path(r.stdout.strip())
    return p if p.is_absolute() else (cwd / p)


def install(cwd: Path | None = None, *, force: bool = False) -> tuple[Path, str]:
    """Returns (hook_path, status) where status is installed | replaced | kept."""
    cwd = cwd or Path.cwd()
    hooks = git_dir(cwd) / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    target = hooks / "pre-commit"
    status = "installed"
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER in existing:
            status = "replaced"
        elif not force:
            raise FileExistsError(
                f"{target} already exists and is not an aegis hook. "
                "Re-run with --force to replace it, or add the pre-commit framework snippet instead."
            )
        else:
            status = "replaced"
    target.write_text(HOOK_BODY, encoding="utf-8", newline="\n")
    if os.name != "nt":
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target, status


def uninstall(cwd: Path | None = None) -> bool:
    cwd = cwd or Path.cwd()
    target = git_dir(cwd) / "hooks" / "pre-commit"
    if target.exists() and HOOK_MARKER in target.read_text(encoding="utf-8", errors="replace"):
        target.unlink()
        return True
    return False
