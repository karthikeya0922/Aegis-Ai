"""Redaction: turn detections into sanitised messages and a vault map.

The scanners find spans. This module is the single place that decides what
the sanitised text looks like, and it owns three guarantees the scanners
cannot give on their own:

  1. **One placeholder per distinct value per request.** Each scanner numbers
     its own findings from 1 on every call, so two messages each containing
     a different email would both yield `[EMAIL_1]`. The redactor renumbers
     globally in document order: identical (prefix, value) pairs share a
     placeholder; distinct values get distinct numbers.

  2. **Offset-safe splicing.** Spans are replaced right-to-left within each
     message so earlier offsets stay valid. `str.replace` -- what the Phase 0
     stub did -- would also rewrite matching text *inside* other tokens and
     drift on repeated values.

  3. **Cross-scanner precedence.** A finding that lies inside another
     scanner's span yields to it. The email-shaped `user:pass@host` fragment
     of a database URI is not an email; the URI finding owns that text.

Raw values are sliced from the original message text at the resolved
offsets. They are placed in the vault map and nowhere else; the Detection
objects that leave here still carry no raw value.

`vault_policy` states which categories the Gateway may rehydrate on egress.
PII placeholders may be mapped back for the end user. Secret placeholders
never are: a credential that entered the pipeline stays replaced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.config import settings
from app.contracts.common import Detection, DetectionCategory, Message
from app.contracts.inspect import VaultPolicy
from app.security.spans import resolve_overlaps, subtract_covered
from app.utils.logging import get_logger

log = get_logger(__name__)

_PLACEHOLDER = re.compile(r"^\[([A-Z][A-Z0-9_]*?)_\d+\]$")

# Which categories take precedence when spans collide. Earlier wins.
# Secrets first: a credential inside a URI outranks the URI's email-shaped
# fragment, and the whole URI must be replaced, not just the password.
_PRECEDENCE: tuple[DetectionCategory, ...] = (
    DetectionCategory.SECRET,
    DetectionCategory.PII,
)


@dataclass
class RedactionResult:
    messages: list[Message]
    detections: list[Detection]
    vault: dict[str, str]
    vault_policy: VaultPolicy
    replacements: int = 0
    dropped_overlaps: int = 0
    skipped_invalid: int = 0
    per_message: dict[int, int] = field(default_factory=dict)


def placeholder_prefix(placeholder: str | None, fallback: str = "REDACTED") -> str:
    """`[EMAIL_3]` -> `EMAIL`. Scanners choose the prefix; the redactor numbers it."""
    if not placeholder:
        return fallback
    m = _PLACEHOLDER.match(placeholder)
    return m.group(1) if m else fallback


class Redactor:
    def __init__(self, vault_ttl_seconds: int | None = None) -> None:
        self.vault_ttl_seconds = vault_ttl_seconds or settings.vault_ttl_seconds

    # -- resolution -----------------------------------------------------------

    @staticmethod
    def _span(d: Detection) -> tuple[int, int, int]:
        return (d.message_index, d.start, d.end)

    def resolve(self, detections: list[Detection]) -> tuple[list[Detection], int]:
        """Cross-scanner overlap resolution. Returns (kept, dropped_count)."""
        redactable = [d for d in detections if d.placeholder]
        by_cat: dict[DetectionCategory, list[Detection]] = {}
        for d in redactable:
            by_cat.setdefault(d.category, []).append(d)

        kept: list[Detection] = []
        for cat in _PRECEDENCE:
            group = by_cat.get(cat, [])
            if not group:
                continue
            # Lower-precedence findings inside a higher-precedence span are noise.
            group = subtract_covered(
                group, kept, span_candidate=self._span, span_covering=self._span
            )
            kept.extend(group)

        # Anything in a category not listed in _PRECEDENCE is appended last.
        for cat, group in by_cat.items():
            if cat not in _PRECEDENCE:
                kept.extend(
                    subtract_covered(group, kept, span_candidate=self._span, span_covering=self._span)
                )

        resolved = resolve_overlaps(kept, span=self._span, score=lambda d: d.confidence)
        return resolved, len(redactable) - len(resolved)

    # -- numbering ------------------------------------------------------------

    def assign_placeholders(
        self, messages: list[Message], detections: list[Detection]
    ) -> tuple[list[Detection], dict[str, str], int]:
        """Global, deterministic placeholder numbering in document order.

        Returns (detections with final placeholders, vault, skipped_invalid).
        Values are sliced from the original text -- the scanners' own vault
        maps are not consulted, which is what makes cross-message collisions
        impossible.
        """
        ordered = sorted(detections, key=self._span)
        counters: dict[str, int] = {}
        seen: dict[tuple[str, str], str] = {}
        vault: dict[str, str] = {}
        out: list[Detection] = []
        skipped = 0

        for d in ordered:
            if d.message_index >= len(messages):
                skipped += 1
                continue
            content = messages[d.message_index].content
            if not (0 <= d.start < d.end <= len(content)):
                skipped += 1
                log.warning(
                    "redactor: dropping detection %s with out-of-range span %d:%d (len %d)",
                    d.type, d.start, d.end, len(content),
                )
                continue
            value = content[d.start : d.end]
            prefix = placeholder_prefix(d.placeholder, fallback=d.type)
            key = (prefix, value)
            if key in seen:
                placeholder = seen[key]
            else:
                counters[prefix] = counters.get(prefix, 0) + 1
                placeholder = f"[{prefix}_{counters[prefix]}]"
                seen[key] = placeholder
                vault[placeholder] = value
            out.append(d.model_copy(update={"placeholder": placeholder}))

        return out, vault, skipped

    # -- splicing -------------------------------------------------------------

    @staticmethod
    def splice(messages: list[Message], detections: list[Detection]) -> tuple[list[Message], dict[int, int]]:
        """Replace spans right-to-left so earlier offsets stay valid."""
        by_msg: dict[int, list[Detection]] = {}
        for d in detections:
            by_msg.setdefault(d.message_index, []).append(d)

        out: list[Message] = []
        counts: dict[int, int] = {}
        for i, m in enumerate(messages):
            spans = sorted(by_msg.get(i, []), key=lambda d: d.start, reverse=True)
            if not spans:
                out.append(m)
                continue
            content = m.content
            for d in spans:
                content = content[: d.start] + (d.placeholder or "") + content[d.end :]
            counts[i] = len(spans)
            out.append(m.model_copy(update={"content": content}))
        return out, counts

    # -- public API -----------------------------------------------------------

    def vault_policy(self) -> VaultPolicy:
        return VaultPolicy(
            rehydrate=["PII"] if settings.pii_rehydration else [],
            never_rehydrate=["SECRET"],  # not configurable -- see spec s3
            ttl_seconds=self.vault_ttl_seconds,
        )

    def redact(self, messages: list[Message], detections: list[Detection]) -> RedactionResult:
        resolved, dropped = self.resolve(detections)
        numbered, vault, skipped = self.assign_placeholders(messages, resolved)
        sanitised, per_msg = self.splice(messages, numbered)

        # Findings that were never redactable (no placeholder -- e.g. entropy
        # warnings are not Detections and never reach here; but a Detection
        # with placeholder=None is legal) are passed through untouched.
        passthrough = [d for d in detections if not d.placeholder]

        return RedactionResult(
            messages=sanitised,
            detections=sorted(numbered + passthrough, key=self._span),
            vault=vault,
            vault_policy=self.vault_policy(),
            replacements=len(numbered),
            dropped_overlaps=dropped,
            skipped_invalid=skipped,
            per_message=per_msg,
        )

    @staticmethod
    def rehydratable(detection: Detection) -> bool:
        """Whether the Gateway may map this placeholder back on egress."""
        if detection.category is DetectionCategory.SECRET:
            return False
        return detection.category is DetectionCategory.PII and settings.pii_rehydration


_redactor: Redactor | None = None


def get_redactor() -> Redactor:
    global _redactor
    if _redactor is None:
        _redactor = Redactor()
    return _redactor
