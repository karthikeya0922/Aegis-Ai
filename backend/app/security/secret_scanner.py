"""Credential and secret detection.

Loads patterns from config/secret_patterns.yaml -- patterns are data, so a new
provider is a config change, not a code change.

Two things this scanner deliberately does not do:

  * It does not decide what happens next. It reports findings with a type, a
    confidence and a category; the policy engine (phase 6) maps category to
    action. A scanner that returns "block" is a bug.
  * It does not claim certainty. Every finding carries a confidence score,
    because "this string matches the shape of an AWS key" is not the same
    statement as "this is a live AWS key".

Raw matched values are returned separately in a vault map, never inside the
Detection objects that get logged and audited.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

import yaml

from app.config import settings
from app.contracts.common import Detection, DetectionCategory, PolicyAction
from app.security.entropy import entropy_confidence_modifier, shannon_entropy
from app.security.spans import resolve_overlaps

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

ValidatorFn = Callable[[str, "SecretScanner"], bool]


def _validate_jwt_structure(value: str, scanner: "SecretScanner") -> bool:
    """A JWT's header must base64url-decode to JSON containing `alg`.

    Rejects arbitrary dot-separated base64 that merely looks like a token.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = parts[0]
    padding = "=" * (-len(header) % 4)
    try:
        decoded = base64.urlsafe_b64decode(header + padding)
        parsed = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    return isinstance(parsed, dict) and "alg" in parsed


def _validate_not_placeholder(value: str, scanner: "SecretScanner") -> bool:
    """Reject documentation placeholders like `your_api_key_here`."""
    normalized = value.strip().strip("\"'").lower()
    if normalized in scanner.placeholder_values:
        return False
    # Repeated-character masks: xxxxxxxx, ********, --------
    if len(set(normalized)) <= 2 and len(normalized) >= 4:
        return False
    if re.fullmatch(r"[<{\[].*[>}\]]", normalized):  # <your-key>, {{TOKEN}}
        return False
    for marker in ("your_", "your-", "_here", "-here", "replace", "insert_", "example_"):
        if marker in normalized:
            return False
    return True


VALIDATORS: dict[str, ValidatorFn] = {
    "jwt_structure": _validate_jwt_structure,
    "not_placeholder_password": _validate_not_placeholder,
}


# ---------------------------------------------------------------------------
# Pattern model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    id: str
    type: str
    category: str
    regex: re.Pattern[str]
    base_confidence: float
    placeholder: str
    entropy_weight: float = 0.0
    min_entropy: float | None = None
    validator: str | None = None
    description: str = ""


@dataclass
class SecretMatch:
    """Internal carrier. `value` is the raw secret and never leaves the
    scanner except through the vault map."""

    pattern: SecretPattern
    value: str
    start: int
    end: int
    confidence: float
    message_index: int = 0
    entropy: float = 0.0
    rejected_by: str | None = field(default=None)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SecretScanner:
    def __init__(self, patterns_path: Path | None = None) -> None:
        path = patterns_path or settings.secret_patterns_path
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.version: int = raw.get("version", 1)
        self.placeholder_values: set[str] = {
            str(v).lower() for v in raw.get("placeholder_values", [])
        }
        self.patterns: list[SecretPattern] = [
            SecretPattern(
                id=p["id"],
                type=p["type"],
                category=p["category"],
                regex=re.compile(p["regex"]),
                base_confidence=float(p["base_confidence"]),
                placeholder=p["placeholder"],
                entropy_weight=float(p.get("entropy_weight", 0.0)),
                min_entropy=(
                    float(p["min_entropy"]) if p.get("min_entropy") is not None else None
                ),
                validator=p.get("validator"),
                description=p.get("description", "") or "",
            )
            for p in raw.get("patterns", [])
        ]

    # -- internals ---------------------------------------------------------

    def _secret_span(self, match: re.Match[str]) -> tuple[str, int, int]:
        """The credential itself, which may be narrower than the full match."""
        if "secret" in (match.groupdict() or {}) and match.group("secret") is not None:
            return match.group("secret"), match.start("secret"), match.end("secret")
        return match.group(0), match.start(), match.end()

    def _score(self, pattern: SecretPattern, secret: str) -> tuple[float, float]:
        """Confidence for one match, and the entropy that informed it."""
        h = shannon_entropy(secret)
        confidence = pattern.base_confidence
        if pattern.entropy_weight > 0:
            confidence += entropy_confidence_modifier(secret) * pattern.entropy_weight
        return round(max(0.0, min(confidence, 0.99)), 3), round(h, 3)

    def _raw_matches(self, text: str, message_index: int) -> list[SecretMatch]:
        found: list[SecretMatch] = []
        for pattern in self.patterns:
            for m in pattern.regex.finditer(text):
                secret, s_start, s_end = self._secret_span(m)
                if not secret:
                    continue

                if pattern.validator:
                    validator = VALIDATORS.get(pattern.validator)
                    if validator and not validator(secret, self):
                        continue

                confidence, h = self._score(pattern, secret)

                if pattern.min_entropy is not None and h < pattern.min_entropy:
                    continue

                # Redaction covers the whole match (a DB URI discloses the host
                # and database name, not only the password), but confidence is
                # scored on the credential portion.
                found.append(
                    SecretMatch(
                        pattern=pattern,
                        value=m.group(0),
                        start=m.start(),
                        end=m.end(),
                        confidence=confidence,
                        message_index=message_index,
                        entropy=h,
                    )
                )
        return found

    @staticmethod
    def _resolve_overlaps(matches: list[SecretMatch]) -> list[SecretMatch]:
        """One finding per overlapping span -- see app.security.spans."""
        return resolve_overlaps(
            matches,
            span=lambda m: (m.message_index, m.start, m.end),
            score=lambda m: m.confidence,
        )

    # -- public API --------------------------------------------------------

    def find(self, text: str, message_index: int = 0) -> list[SecretMatch]:
        """Raw matches, overlap-resolved. Carries secret values -- internal use."""
        return self._resolve_overlaps(self._raw_matches(text, message_index))

    def scan(
        self, text: str, message_index: int = 0, placeholder_offset: int = 0
    ) -> tuple[list[Detection], dict[str, str]]:
        """Detections plus the vault map.

        Returns:
            detections: safe to log and audit -- no raw values.
            vault:      placeholder -> original. Secret-grade; the Gateway
                        stores it in Redis with a short TTL and never
                        rehydrates it into a response.
        """
        matches = self.find(text, message_index)
        detections: list[Detection] = []
        vault: dict[str, str] = {}
        counters: dict[str, int] = {}
        seen: dict[str, str] = {}  # identical value -> same placeholder

        for match in matches:
            value = match.value
            if value in seen:
                placeholder = seen[value]
            else:
                prefix = match.pattern.placeholder
                counters[prefix] = counters.get(prefix, 0) + 1 + placeholder_offset
                placeholder = f"[{prefix}_{counters[prefix]}]"
                seen[value] = placeholder
                vault[placeholder] = value

            detections.append(
                Detection(
                    type=match.pattern.type,
                    category=DetectionCategory.SECRET,
                    placeholder=placeholder,
                    confidence=match.confidence,
                    start=match.start,
                    end=match.end,
                    message_index=match.message_index,
                    recognizer=f"secret_scanner/{match.pattern.id}",
                    pattern=match.pattern.id,
                    # The policy engine decides the real action in phase 6.
                    # Until then every secret is reported, none is actioned here.
                    action=PolicyAction.ALLOW,
                )
            )

        return detections, vault

    def categories_found(self, detections: list[Detection]) -> set[str]:
        """Policy-engine keys for the detections produced by this scanner."""
        by_id = {p.id: p.category for p in self.patterns}
        return {by_id[d.pattern] for d in detections if d.pattern in by_id}


@lru_cache
def get_scanner() -> SecretScanner:
    return SecretScanner()
