"""CLI configuration: ~/.aegis/config.toml, overridden by environment.

Nothing here is a detection threshold -- those live in the Inspector's
config. This is only where the CLI finds the services and which profile it
asks for.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("AEGIS_HOME", Path.home() / ".aegis"))
CONFIG_FILE = CONFIG_DIR / "config.toml"
SESSION_FILE = CONFIG_DIR / "session"

_ENV = {
    "engine_url": "AEGIS_ENGINE_URL",
    "gateway_url": "AEGIS_GATEWAY_URL",
    "profile": "AEGIS_POLICY_PROFILE",
    "mode": "AEGIS_MODE",
    "reviewer_token": "AEGIS_REVIEWER_TOKEN",
    "admin_token": "AEGIS_ADMIN_TOKEN",
    "backend_path": "AEGIS_BACKEND_PATH",
    "tenant_id": "AEGIS_TENANT_ID",
}


@dataclass
class CLIConfig:
    engine_url: str = "http://localhost:8000"
    gateway_url: str = "http://localhost:3000"
    profile: str = "default"
    mode: str = "sanitize"
    reviewer_token: str | None = None
    admin_token: str | None = None
    backend_path: str | None = None
    tenant_id: str = "default"
    sources: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "CLIConfig":
        cfg = cls()
        if CONFIG_FILE.exists():
            raw = tomllib.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            for k in _ENV:
                if k in raw and raw[k] not in (None, ""):
                    setattr(cfg, k, raw[k])
                    cfg.sources[k] = str(CONFIG_FILE)
        for k, env in _ENV.items():
            v = os.environ.get(env)
            if v:
                setattr(cfg, k, v)
                cfg.sources[k] = f"${env}"
        for k in _ENV:
            cfg.sources.setdefault(k, "default")
        return cfg

    def as_rows(self) -> list[tuple[str, str, str]]:
        rows = []
        for k in _ENV:
            v = getattr(self, k)
            shown = "(set)" if k.endswith("_token") and v else (str(v) if v is not None else "-")
            rows.append((k, shown, self.sources.get(k, "default")))
        return rows


def load_session_id() -> str:
    """A stable per-user session id so the Gateway's per-session behaviour
    (cache keyed by tenant, telemetry) is exercised across CLI calls."""
    import secrets

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if SESSION_FILE.exists():
        sid = SESSION_FILE.read_text(encoding="utf-8").strip()
        if sid:
            return sid
    sid = "sess_cli_" + secrets.token_urlsafe(12)
    SESSION_FILE.write_text(sid, encoding="utf-8")
    return sid
