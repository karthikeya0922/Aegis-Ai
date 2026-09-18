"""Personal data detection.

Two engines, one interface:

  * **regex** -- always available, no model download. Covers the structured
    identifiers (email, phone, IP, card, SSN) where a pattern plus a checksum
    beats a statistical model anyway.
  * **presidio** -- Microsoft Presidio over a spaCy NER model. Adds the
    unstructured entities (PERSON, LOCATION, NRP, ...) that no regex can find.

If Presidio or the spaCy model is unavailable the scanner runs regex-only and
says so: `degraded` is True, `degraded_reason` explains why, and /api/health
reports it. It never silently pretends PERSON detection is happening.

Like the secret scanner, this module reports and never decides. Every
Detection leaves here with action=ALLOW; the policy engine (phase 6) maps
entity types to actions. Raw matched values go only into the vault map.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import CONFIG_DIR, settings
from app.contracts.common import Detection, DetectionCategory, PolicyAction
from app.security.spans import resolve_overlaps
from app.utils.logging import get_logger

log = get_logger(__name__)

PII_CONFIG_PATH = CONFIG_DIR / "pii_entities.yaml"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntityConfig:
    type: str
    placeholder: str
    threshold: float
    enabled: bool
    engine: str  # regex | presidio | both
    sensitivity: str


def _load_config(path: Path) -> tuple[dict[str, EntityConfig], list[str], int]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    entities = {
        name: EntityConfig(
            type=name,
            placeholder=str(cfg["placeholder"]),
            threshold=float(cfg.get("threshold", 0.5)),
            enabled=bool(cfg.get("enabled", True)),
            engine=str(cfg.get("engine", "both")),
            sensitivity=str(cfg.get("sensitivity", "medium")),
        )
        for name, cfg in (raw.get("entities") or {}).items()
    }
    disabled = list(raw.get("presidio_disabled_recognizers") or [])
    return entities, disabled, int(raw.get("version", 1))


# ---------------------------------------------------------------------------
# Internal match carrier -- holds the raw value, never leaves the scanner
# except through the vault map
# ---------------------------------------------------------------------------


@dataclass
class PIIMatch:
    type: str
    value: str
    start: int
    end: int
    confidence: float
    recognizer: str
    message_index: int = 0


# ---------------------------------------------------------------------------
# Regex engine
# ---------------------------------------------------------------------------

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Phone: requires either a leading + / country code, or grouping separators.
# A bare run of digits is NOT a phone -- that is what made the phase 0 stub
# flag the middle of a UUID. Total digit count is bounded to 8-15 (E.164).
_PHONE = re.compile(
    r"(?<![\w.\-])"
    r"(?:\+\d{1,3}[\s.\-]?)?"          # optional country code
    r"(?:\(\d{2,5}\)[\s.\-]?)?"        # optional bracketed area code
    r"\d{2,5}(?:[\s.\-]\d{2,5}){1,3}"   # 2-4 digit groups, separated
    r"(?![\w\-])"
)
# 12 digits in 4-4-4 groups is the Aadhaar layout. Whether or not the
# checksum passes, it is not a phone number.
_AADHAAR_SHAPED = re.compile(r"\d{4}[ \-]\d{4}[ \-]\d{4}")

# Separator-joined digit groups that are dates, not phones.
_DATE_LIKE = re.compile(
    r"^(?:\d{4}[-./]\d{1,2}[-./]\d{1,2}|\d{1,2}[-./]\d{1,2}[-./]\d{2,4})$"
)

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}){0,1}\b"
)

# Card: 13-19 digits, optional space/dash groups, Luhn-validated below.
_CARD = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")

# US SSN: AAA-GG-SSSS with the area/group/serial constraints SSA publishes.
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Honorific + capitalised name. Narrow on purpose -- only used in degraded
# mode, and only because "Dr. Priya Ramaswamy" is unambiguous enough to be
# worth a low-confidence flag when no NER model is loaded. The title list is
# data (pii_entities.yaml: honorifics).
def _honorific_pattern(titles: list[str]) -> re.Pattern[str]:
    alt = "|".join(re.escape(t) for t in titles) or "Dr"
    return re.compile(r"\b(?:" + alt + r")\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b")


_HONORIFIC_NAME = _honorific_pattern(
    [str(t) for t in (yaml.safe_load(PII_CONFIG_PATH.read_text(encoding="utf-8")).get("honorifics") or [])]
)

# Runs of digits that are known non-PII structures. Consulted before the
# phone/card rules to keep UUIDs, hashes and timestamps out of the findings.
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def luhn_valid(digits: str) -> bool:
    """Luhn checksum. Rejects most random digit strings that merely look like a card."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _inside_uuid(text: str, start: int, end: int) -> bool:
    return any(m.start() <= start and end <= m.end() for m in _UUID.finditer(text))


_NUMERIC_RUN_CHARS = set("0123456789 .-()+")


def _digits_in_surrounding_run(text: str, start: int, end: int) -> int:
    """Count digits in the whole numeric run the span sits in.

    A phone regex can match a 12-digit *slice* of a 19-digit card number or a
    long numeric ID. Expanding to the full run and counting digits catches
    that: a real phone never lives inside a longer digit group.
    """
    lo = start
    while lo > 0 and text[lo - 1] in _NUMERIC_RUN_CHARS:
        lo -= 1
    hi = end
    while hi < len(text) and text[hi] in _NUMERIC_RUN_CHARS:
        hi += 1
    return sum(ch.isdigit() for ch in text[lo:hi])


class RegexEngine:
    name = "regex"

    def find(self, text: str, message_index: int) -> list[PIIMatch]:
        out: list[PIIMatch] = []

        for m in _EMAIL.finditer(text):
            out.append(PIIMatch("EMAIL_ADDRESS", m.group(0), m.start(), m.end(), 0.95,
                                "regex.email", message_index))

        for m in _IPV4.finditer(text):
            out.append(PIIMatch("IP_ADDRESS", m.group(0), m.start(), m.end(), 0.90,
                                "regex.ipv4", message_index))
        for m in _IPV6.finditer(text):
            if ":" in m.group(0) and len(m.group(0)) >= 8:
                out.append(PIIMatch("IP_ADDRESS", m.group(0), m.start(), m.end(), 0.80,
                                    "regex.ipv6", message_index))

        for m in _SSN.finditer(text):
            out.append(PIIMatch("US_SSN", m.group(0), m.start(), m.end(), 0.85,
                                "regex.ssn", message_index))

        for m in _CARD.finditer(text):
            digits = re.sub(r"[ \-]", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                if not _inside_uuid(text, m.start(), m.end()):
                    out.append(PIIMatch("CREDIT_CARD", m.group(0), m.start(), m.end(), 0.92,
                                        "regex.card_luhn", message_index))

        for m in _PHONE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if not (8 <= len(digits) <= 15):
                continue
            if _inside_uuid(text, m.start(), m.end()):
                continue
            if _digits_in_surrounding_run(text, m.start(), m.end()) > 15:
                continue  # a slice of a card number or long numeric ID
            if _DATE_LIKE.match(raw.strip()):
                continue  # 2024-03-15 is a date
            if _AADHAAR_SHAPED.fullmatch(raw.strip()):
                continue  # 4-4-4 grouping is Aadhaar-shaped; the Aadhaar rule owns it
            # Something with a + or parentheses is a phone with high confidence;
            # a plain "555-123-4567" is likely but not certain.
            conf = 0.85 if ("+" in raw or "(" in raw) else 0.70
            out.append(PIIMatch("PHONE_NUMBER", raw, m.start(), m.end(), conf,
                                "regex.phone", message_index))

        for m in _HONORIFIC_NAME.finditer(text):
            out.append(PIIMatch("PERSON", m.group(1), m.start(1), m.end(1), 0.60,
                                "regex.honorific_name", message_index))

        return out


# ---------------------------------------------------------------------------
# Presidio engine (optional)
# ---------------------------------------------------------------------------


class PresidioEngine:
    name = "presidio"

    def __init__(self, model_name: str, disabled_recognizers: list[str]) -> None:
        from presidio_analyzer import AnalyzerEngine  # noqa: WPS433 - optional dep
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model_name}],
            }
        )
        nlp_engine = provider.create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        for name in disabled_recognizers:
            try:
                self.analyzer.registry.remove_recognizer(name)
            except Exception:  # noqa: BLE001 - absent recognizer is fine
                pass
        self.model_name = model_name

    def find(self, text: str, message_index: int, entities: list[str]) -> list[PIIMatch]:
        results = self.analyzer.analyze(
            text=text, language="en", entities=entities, score_threshold=0.0
        )
        out: list[PIIMatch] = []
        for r in results:
            meta = getattr(r, "recognition_metadata", None) or {}
            rec = meta.get("recognizer_name", "presidio")
            out.append(
                PIIMatch(
                    type=r.entity_type,
                    value=text[r.start : r.end],
                    start=r.start,
                    end=r.end,
                    confidence=float(r.score),
                    recognizer=f"presidio.{rec}",
                    message_index=message_index,
                )
            )
        return out


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class PIIScanner:
    def __init__(
        self,
        config_path: Path | None = None,
        *,
        gazetteer_enabled: bool = True,
        share_presidio_with: "PIIScanner | None" = None,
    ) -> None:
        self.entities, self._disabled_recognizers, self.version = _load_config(
            config_path or PII_CONFIG_PATH
        )
        self._regex = RegexEngine()
        from app.security.india_recognizers import IndiaEngine  # noqa: WPS433 - circular

        self._india = IndiaEngine(gazetteer_enabled=gazetteer_enabled)
        self._presidio: PresidioEngine | None = None
        self._presidio_attempted = False
        self._lock = threading.Lock()
        self.degraded_reason: str | None = None
        self.gazetteer_enabled = gazetteer_enabled

        # A second scanner (the fairness baseline) reuses an already-loaded
        # spaCy model rather than paying another multi-second load and a
        # second copy in memory.
        if share_presidio_with is not None:
            share_presidio_with._try_load_presidio()
            self._presidio = share_presidio_with._presidio
            self._presidio_attempted = True
            self.degraded_reason = share_presidio_with.degraded_reason

    # -- engine management --------------------------------------------------

    def _try_load_presidio(self) -> None:
        """Load once, on first use. Failure is recorded, not raised."""
        if self._presidio_attempted:
            return
        with self._lock:
            if self._presidio_attempted:
                return
            self._presidio_attempted = True
            candidates = [settings.spacy_model, "en_core_web_md", "en_core_web_sm"]
            last_error: str | None = None
            for model in candidates:
                try:
                    # Presidio's spaCy engine will *download* a missing model
                    # rather than fail. That is a 400MB network fetch in the
                    # request path, and a hang when offline. Check locally
                    # first so degradation is immediate and never touches
                    # the network.
                    import spacy.util  # noqa: WPS433

                    if not spacy.util.is_package(model):
                        last_error = f"spaCy model {model} not installed"
                        continue
                    self._presidio = PresidioEngine(model, self._disabled_recognizers)
                    if model != settings.spacy_model:
                        log.warning(
                            "pii: configured spaCy model %s unavailable, using %s",
                            settings.spacy_model, model,
                        )
                    log.info("pii: presidio engine ready (spaCy model %s)", model)
                    return
                except ImportError as exc:
                    last_error = f"presidio not installed ({exc.name})"
                    break
                except Exception as exc:  # noqa: BLE001 - model missing / load error
                    last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
                    continue
            self.degraded_reason = (
                f"regex-only: {last_error or 'no spaCy model found'}; "
                "PERSON/LOCATION/NRP detection unavailable"
            )
            log.warning("pii: %s", self.degraded_reason)

    def warm(self) -> None:
        """Load the engine and run one inference.

        Loading spaCy is only half the cold-start cost; the first `analyze`
        call pays another ~100ms of pipeline initialisation. Doing it here
        keeps that off the first real request.
        """
        self._try_load_presidio()
        if self._presidio is not None:
            # Every recogniser lazy-initialises on its first hit (the phone
            # recogniser loads `phonenumbers` region metadata, for one), so
            # the warm-up text must contain something for each of them.
            probe = (
                "Contact Alex Example at alex@example.com or +1-555-000-0000, "
                "IP 10.0.0.1, card 4111 1111 1111 1111, SSN 123-45-6789, "
                "IBAN GB82WEST12345698765432."
            )
            self.scan(probe)

    @property
    def engine(self) -> str:
        self._try_load_presidio()
        return "presidio+regex" if self._presidio else "regex"

    @property
    def degraded(self) -> bool:
        self._try_load_presidio()
        return self._presidio is None

    @property
    def has_ner(self) -> bool:
        return not self.degraded

    @property
    def spacy_model(self) -> str | None:
        return self._presidio.model_name if self._presidio else None

    # -- detection ------------------------------------------------------------

    def _presidio_entities(self) -> list[str]:
        """Entity types Presidio is asked for. India-engine and regex-only
        types are produced locally and never requested from Presidio."""
        return [
            name
            for name, cfg in self.entities.items()
            if cfg.enabled and cfg.engine in ("presidio", "both")
        ]

    def find(self, text: str, message_index: int = 0) -> list[PIIMatch]:
        """Raw matches from every available engine, filtered and overlap-resolved."""
        self._try_load_presidio()
        raw: list[PIIMatch] = self._regex.find(text, message_index)
        raw.extend(self._india.find(text, message_index))
        if self._presidio is not None:
            raw.extend(self._presidio.find(text, message_index, self._presidio_entities()))

        kept: list[PIIMatch] = []
        for m in raw:
            cfg = self.entities.get(m.type)
            if cfg is None or not cfg.enabled:
                continue
            if m.recognizer == "regex.honorific_name" and self._presidio is not None:
                # NER is loaded; the honorific heuristic is a degraded-mode
                # fallback only. The gazetteer is NOT dropped -- it exists
                # precisely because NER under-serves Indian names.
                continue
            if m.confidence < cfg.threshold:
                continue
            kept.append(m)

        return resolve_overlaps(
            kept,
            span=lambda x: (x.message_index, x.start, x.end),
            score=lambda x: x.confidence,
        )

    def scan(
        self, text: str, message_index: int = 0
    ) -> tuple[list[Detection], dict[str, str]]:
        """Detections plus the vault map. Same contract as SecretScanner.scan."""
        matches = self.find(text, message_index)
        detections: list[Detection] = []
        vault: dict[str, str] = {}
        counters: dict[str, int] = {}
        seen: dict[tuple[str, str], str] = {}

        for m in matches:
            cfg = self.entities[m.type]
            key = (cfg.placeholder, m.value)
            if key in seen:
                placeholder = seen[key]
            else:
                counters[cfg.placeholder] = counters.get(cfg.placeholder, 0) + 1
                placeholder = f"[{cfg.placeholder}_{counters[cfg.placeholder]}]"
                seen[key] = placeholder
                vault[placeholder] = m.value

            detections.append(
                Detection(
                    type=m.type,
                    category=DetectionCategory.PII,
                    placeholder=placeholder,
                    confidence=round(min(m.confidence, 0.99), 3),
                    start=m.start,
                    end=m.end,
                    message_index=m.message_index,
                    recognizer=m.recognizer,
                    pattern=cfg.sensitivity,  # surfaced to the UI as the sensitivity tag
                    action=PolicyAction.ALLOW,  # policy engine decides (phase 6)
                )
            )
        return detections, vault

    def health(self) -> dict[str, Any]:
        self._try_load_presidio()
        return {
            "engine": self.engine,
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason,
            "spacy_model": self.spacy_model,
            "entities_enabled": sorted(n for n, c in self.entities.items() if c.enabled),
            "config_version": self.version,
            "india_gazetteer_names": len(self._india.gazetteer.all_names),
        }


@lru_cache
def get_pii_scanner() -> PIIScanner:
    return PIIScanner()
