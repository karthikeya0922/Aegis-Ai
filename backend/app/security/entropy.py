"""Shannon entropy analysis.

    H(X) = -sum over x of  p(x) * log2 p(x)

Entropy tells us a string *looks* randomly generated. It does not tell us the
string is a credential -- a UUID, a git SHA and a base64 thumbnail all score
high. So entropy is used here in exactly two ways:

  1. As a **confidence modifier** on a pattern match that already fired.
  2. As a standalone **warn-level** finding for unrecognised high-entropy
     strings, so a reviewer can look.

Entropy never blocks on its own. That is a hard rule from the spec (s11), and
`scan` enforces it by emitting findings whose action is fixed at WARN.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from app.config import settings
from app.contracts.common import EntropyFinding, PolicyAction

# Tokens that are high-entropy by nature and carry no secret. Checked before
# a finding is raised so the reviewer queue is not flooded with noise.
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHORT_SHA = re.compile(r"^[0-9a-f]{7,12}$")
_HEX_COLOR = re.compile(r"^#?[0-9a-fA-F]{6}$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}.*)?$")
_NUMERIC = re.compile(r"^[\d.,_+-]+$")
_PATH_LIKE = re.compile(r"^[./~]|[/]{2,}|^[A-Za-z]:[/\\]")
_DATA_URI = re.compile(r"^data:[\w/+.-]+;base64,")

# Candidate splitting: whitespace plus the punctuation that typically wraps a
# literal in source or config.
_SPLIT = re.compile(r"[\s\"'`,;<>(){}\[\]]+")

_VOWELS = set("aeiouAEIOU")


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    # `+ 0.0` normalises the -0.0 that falls out of negating a zero sum.
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) + 0.0


def charset_size(text: str) -> int:
    """Size of the alphabet actually used -- distinct characters present."""
    return len(set(text))


def normalized_entropy(text: str) -> float:
    """Entropy scaled to [0, 1] against the maximum for this string's length.

    A short string cannot reach high absolute entropy, so raw entropy alone
    penalises short secrets. This gives a length-fair signal.
    """
    if len(text) < 2:
        return 0.0
    max_possible = math.log2(min(len(text), charset_size(text) or 1))
    if max_possible <= 0:
        return 0.0
    return min(shannon_entropy(text) / max_possible, 1.0)


def character_classes(text: str) -> int:
    """How many of lower / upper / digit / symbol appear."""
    return sum(
        [
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
            any(not c.isalnum() for c in text),
        ]
    )


def looks_like_natural_language(text: str) -> bool:
    """Cheap heuristic: prose has vowels in roughly predictable proportion."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 6:
        return False
    vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
    return 0.25 <= vowel_ratio <= 0.60 and not any(c.isdigit() for c in text)


def is_known_benign(token: str) -> str | None:
    """Return the reason this high-entropy token is not interesting, or None."""
    if _UUID.match(token):
        return "uuid"
    if _GIT_SHA.match(token):
        return "git_sha"
    if _SHORT_SHA.match(token):
        return "short_hash"
    if _HEX_COLOR.match(token):
        return "hex_color"
    if _ISO_DATE.match(token):
        return "timestamp"
    if _NUMERIC.match(token):
        return "numeric"
    if _PATH_LIKE.search(token):
        return "path"
    if _DATA_URI.match(token):
        return "data_uri"
    if looks_like_natural_language(token):
        return "natural_language"
    return None


def entropy_confidence_modifier(text: str) -> float:
    """Adjustment applied to a pattern match's base confidence.

    Bounded to +/-0.10 so entropy can nudge a verdict but never drive it.
    A prefixed AWS key is a credential whether or not its body scores well.
    """
    h = shannon_entropy(text)
    if h >= 4.5:
        return 0.10
    if h >= 3.5:
        return 0.05
    if h >= 2.5:
        return 0.0
    if h >= 1.5:
        return -0.05
    return -0.10


def _confidence(token: str, entropy: float) -> float:
    """Confidence that an unrecognised token is *some* kind of secret.

    Capped at 0.75: without a recognisable prefix or structure we are
    guessing, and the scanner should say so rather than assert.
    """
    score = 0.35
    if entropy >= settings.entropy_threshold:
        score += 0.15
    if entropy >= 5.0:
        score += 0.10
    if character_classes(token) >= 3:
        score += 0.10
    if len(token) >= 32:
        score += 0.05
    return round(min(score, 0.75), 3)


def extract_candidates(
    text: str, min_length: int | None = None
) -> list[tuple[str, int, int]]:
    """Yield (token, start, end) for substrings worth scoring."""
    min_len = min_length if min_length is not None else settings.entropy_min_length
    out: list[tuple[str, int, int]] = []
    cursor = 0
    for token in _SPLIT.split(text):
        if not token:
            continue
        start = text.find(token, cursor)
        if start == -1:
            continue
        cursor = start + len(token)
        if len(token) < min_len:
            continue
        out.append((token, start, start + len(token)))
    return out


def scan(
    text: str,
    message_index: int = 0,
    min_length: int | None = None,
    threshold: float | None = None,
) -> list[EntropyFinding]:
    """Findings for unrecognised high-entropy strings.

    Every finding is WARN. Entropy is a reason to look, never a reason to
    block -- see the module docstring.
    """
    limit = threshold if threshold is not None else settings.entropy_threshold
    findings: list[EntropyFinding] = []

    for token, start, end in extract_candidates(text, min_length):
        if is_known_benign(token):
            continue
        h = shannon_entropy(token)
        if h < limit:
            continue
        findings.append(
            EntropyFinding(
                entropy=round(h, 3),
                length=len(token),
                confidence=_confidence(token, h),
                start=start,
                end=end,
                message_index=message_index,
                action=PolicyAction.WARN,  # never BLOCK, by design
            )
        )
    return findings
