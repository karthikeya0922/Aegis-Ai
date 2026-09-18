"""Policy versioning (Requirement 7 -- accountability).

Every change to the policy file is an immutable row in policy_version, so
any past decision can be replayed against the rules that were in force:
the audit row records `policy_version`, and this table says what that
version contained.

Flow for an update:

    validate the document through the same loader the engine uses
      -> assign version = max(existing) + 1 and stamp it into the YAML
      -> write the row (immutable; never updated)
      -> write config/policies.yaml so the running engine picks it up
      -> force the engine to reload now, not on next mtime check

Rollback does not delete or rewrite history. It creates a NEW version whose
body is the old body, noted as a rollback. The history stays linear and
complete.

On startup, if the table is empty, the current file is recorded as
version 1 so the baseline is on file too.
"""

from __future__ import annotations

import difflib
import re
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

import yaml
from sqlalchemy import func, select

from app.audit.database import session_scope
from app.audit.models import PolicyVersion
from app.contracts.governance import PolicyResponse, PolicyVersionSummary
from app.security.policy_engine import get_policy_engine, load_policies
from app.utils.ids import hash_user_ref
from app.utils.logging import get_logger

log = get_logger(__name__)

_VERSION_LINE = re.compile(r"^version:\s*\d+\s*$", re.MULTILINE)


class PolicyInvalid(ValueError):
    pass


class PolicyVersionNotFound(LookupError):
    pass


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Validation and diffing
# ---------------------------------------------------------------------------


def validate(yaml_body: str) -> None:
    """Run the document through the engine's own loader. Raises PolicyInvalid."""
    with NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(yaml_body)
        path = Path(tmp.name)
    try:
        load_policies(path)
    except Exception as exc:  # noqa: BLE001 - surface the loader's message
        raise PolicyInvalid(str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)


def _rules_flat(body: str) -> dict[str, dict]:
    """profile.key -> rule dict, for a readable diff of what actually changed."""
    try:
        raw = yaml.safe_load(body) or {}
    except yaml.YAMLError:
        return {}
    out: dict[str, dict] = {}
    for prof, spec in (raw.get("profiles") or {}).items():
        for key, rule in ((spec or {}).get("rules") or {}).items():
            out[f"{prof}.{key}"] = rule or {}
    return out


def diff_summary(old_body: str, new_body: str) -> str:
    """One line a reviewer can read: added / removed / changed rules, plus
    line-level counts from a unified diff."""
    old_r, new_r = _rules_flat(old_body), _rules_flat(new_body)
    added = sorted(set(new_r) - set(old_r))
    removed = sorted(set(old_r) - set(new_r))
    changed = []
    for k in sorted(set(old_r) & set(new_r)):
        if old_r[k] != new_r[k]:
            oa, na = old_r[k].get("action"), new_r[k].get("action")
            changed.append(f"{k}: {oa}->{na}" if oa != na else k)

    udiff = list(difflib.unified_diff(old_body.splitlines(), new_body.splitlines(), lineterm="", n=0))
    plus = sum(1 for l in udiff if l.startswith("+") and not l.startswith("+++"))
    minus = sum(1 for l in udiff if l.startswith("-") and not l.startswith("---"))

    parts = [f"+{len(added)} rules", f"-{len(removed)} rules", f"~{len(changed)} changed"]
    detail = []
    if changed:
        detail.append("changed: " + ", ".join(changed[:6]) + (" ..." if len(changed) > 6 else ""))
    if added:
        detail.append("added: " + ", ".join(added[:6]) + (" ..." if len(added) > 6 else ""))
    if removed:
        detail.append("removed: " + ", ".join(removed[:6]) + (" ..." if len(removed) > 6 else ""))
    return f"{', '.join(parts)} ({plus}+/{minus}- lines)" + ("; " + "; ".join(detail) if detail else "")


def _stamp_version(body: str, version: int) -> str:
    if _VERSION_LINE.search(body):
        return _VERSION_LINE.sub(f"version: {version}", body, count=1)
    return f"version: {version}\n" + body


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def _latest_row(s) -> PolicyVersion | None:
    return s.execute(select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(1)).scalar_one_or_none()


def current() -> PolicyResponse:
    engine = get_policy_engine()
    ps = engine.policies
    with session_scope() as s:
        latest = _latest_row(s)
        updated = _aware(latest.created_at) if latest else datetime.fromtimestamp(ps.source_mtime, tz=timezone.utc)
    return PolicyResponse(
        version=ps.version,
        profile=engine.profile(None).name,
        available_profiles=sorted(ps.profiles),
        yaml_body=engine.path.read_text(encoding="utf-8"),
        updated_at=updated,
    )


def history(limit: int = 50) -> list[PolicyVersionSummary]:
    with session_scope() as s:
        rows = s.execute(
            select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(limit)
        ).scalars().all()
        return [
            PolicyVersionSummary(
                version=r.version, created_at=_aware(r.created_at),
                diff_summary=r.diff_summary, note=r.note,
            )
            for r in rows
        ]


def get_version_body(version: int) -> str:
    with session_scope() as s:
        row = s.execute(select(PolicyVersion).where(PolicyVersion.version == version)).scalar_one_or_none()
        if row is None:
            raise PolicyVersionNotFound(version)
        return row.yaml_body


def version_count() -> int:
    with session_scope() as s:
        return int(s.execute(select(func.count()).select_from(PolicyVersion)).scalar_one())


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def bootstrap() -> bool:
    """Record the current file as version 1 if history is empty. Idempotent."""
    engine = get_policy_engine()
    with session_scope() as s:
        if _latest_row(s) is not None:
            return False
        body = engine.path.read_text(encoding="utf-8")
        v = engine.policies.version or 1
        s.add(PolicyVersion(version=v, yaml_body=body, author_ref_hash=None,
                            diff_summary="initial", note="baseline recorded at startup"))
    log.info("policies: recorded baseline as version %d", v)
    return True


def update(yaml_body: str, *, author_ref: str | None, note: str | None) -> PolicyResponse:
    validate(yaml_body)
    engine = get_policy_engine()

    # The baseline must be on file before anything replaces it, or the first
    # change on a fresh deployment would have nothing to roll back to.
    bootstrap()

    with session_scope() as s:
        latest = _latest_row(s)
        old_body = latest.yaml_body if latest else engine.path.read_text(encoding="utf-8")
        new_version = (latest.version if latest else engine.policies.version) + 1
        body = _stamp_version(yaml_body, new_version)
        summary = diff_summary(old_body, body)
        s.add(PolicyVersion(
            version=new_version, yaml_body=body,
            author_ref_hash=hash_user_ref(author_ref),
            diff_summary=summary, note=note,
        ))

    # The row is committed; now make it live. Write the file the engine
    # watches and reload immediately rather than waiting for an mtime tick.
    engine.path.write_text(body, encoding="utf-8")
    engine.force_reload()
    log.info("policies: version %d in force (%s)", new_version, summary)
    return current()


def rollback(version: int, *, author_ref: str | None, note: str | None) -> PolicyResponse:
    body = get_version_body(version)
    return update(body, author_ref=author_ref, note=f"rollback to v{version}" + (f": {note}" if note else ""))
