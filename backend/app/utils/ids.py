"""Identifier generation and privacy-preserving hashing."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from app.config import settings

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _token(length: int = 12) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def request_id() -> str:
    return f"req_{_token(12)}"


def review_id() -> str:
    return f"rev_{_token(12)}"


def run_id() -> str:
    return f"run_{_token(10)}"


def override_token() -> str:
    """Opaque, single-use, scoped to one request_id. Never guessable."""
    return f"ovr_{secrets.token_urlsafe(32)}"


def hash_user_ref(user_ref: str | None) -> str | None:
    """Salted HMAC of a user identifier.

    The audit database stores this, never the raw value. Aegis inspects every
    prompt in an organisation, which makes its own log a surveillance
    capability -- so the log is pseudonymous by construction.
    """
    if not user_ref:
        return None
    return hmac.new(
        settings.user_hash_salt.encode("utf-8"),
        user_ref.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


def fingerprint(value: str) -> str:
    """Short non-reversible fingerprint, used to correlate a repeated secret
    across requests without ever storing the secret itself."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
