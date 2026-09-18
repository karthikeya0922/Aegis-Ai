"""Grounded Response Verification (Requirement 2 -- accuracy and reliability).

Named that way on purpose. It is a support score, not a hallucination
detector: it asks, claim by claim, whether the supplied reference text
entails what the model said. It cannot know whether the reference itself
is true, and it cannot judge claims the reference does not cover.

Pipeline for one response:

    answer -> sentence-level claim split
           -> for each claim, retrieve the top-k reference sentences by
              embedding cosine (Phase 9's model)
           -> NLI cross-encoder on (evidence, claim) pairs
           -> per-claim verdict: SUPPORTED | UNSUPPORTED | CONTRADICTED
           -> score = supported / claims

The NLI model is cross-encoder/nli-deberta-v3-small. Its label order is
read from the model config at load time, never assumed. BERTScore is NOT
used: it measures similarity, not entailment, and "took effect in 2019"
scores near-identical to "took effect in 2021" on similarity.

If the model is unavailable the verifier reports SKIPPED with a reason and
enabled=False. It does not fall back to a lexical heuristic that would
produce a plausible-looking but meaningless score.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache

from app.cache.embeddings import get_embedding_service
from app.config import settings
from app.contracts.common import GroundingStatus
from app.contracts.egress import ClaimVerdict, GroundingResult
from app.utils.logging import get_logger

log = get_logger(__name__)

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

# Sentence boundaries: end punctuation followed by whitespace and a capital,
# digit, quote or bracket. Abbreviations are imperfectly handled; the
# limitation is documented in the tests.
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")
_MIN_CLAIM_WORDS = 4
_MAX_CLAIMS = 40
_MAX_EVIDENCE = 3

SUPPORT_THRESHOLD = 0.50
CONTRADICT_THRESHOLD = 0.50


def split_claims(text: str) -> list[str]:
    """Assertive sentences of at least a few words. Questions and fragments
    are not claims and are dropped."""
    out: list[str] = []
    for s in _SENT_SPLIT.split(text.strip()):
        s = s.strip()
        if not s or s.endswith("?"):
            continue
        if len(s.split()) < _MIN_CLAIM_WORDS:
            continue
        out.append(s)
        if len(out) >= _MAX_CLAIMS:
            break
    return out


def split_reference(text: str) -> list[str]:
    return [s.strip() for s in _SENT_SPLIT.split(text.strip()) if s.strip()]


@dataclass
class ClaimScore:
    claim: str
    evidence: str | None
    entailment: float
    contradiction: float
    neutral: float
    verdict: str


@dataclass
class VerificationOutcome:
    result: GroundingResult
    claim_scores: list[ClaimScore] = field(default_factory=list)
    duration_ms: float = 0.0
    engine: str = "nli-cross-encoder"


class GroundingVerifier:
    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or settings.nli_model
        self._model = None
        self._labels: dict[str, int] = {}
        self._attempted = False
        self._lock = threading.Lock()
        self.degraded_reason: str | None = None

    # -- loading ----------------------------------------------------------------

    def _try_load(self) -> None:
        if self._attempted:
            return
        with self._lock:
            if self._attempted:
                return
            self._attempted = True
            t0 = time.perf_counter()
            try:
                from sentence_transformers import CrossEncoder  # noqa: WPS433 - optional

                self._model = CrossEncoder(self.model_name, device="cpu")
                id2label = {int(k): str(v).lower() for k, v in self._model.model.config.id2label.items()}
                self._labels = {v: k for k, v in id2label.items()}
                missing = {"entailment", "contradiction", "neutral"} - set(self._labels)
                if missing:
                    raise RuntimeError(f"NLI model labels missing {sorted(missing)}: {id2label}")
                log.info("grounding: %s ready (labels %s) in %.1fs",
                         self.model_name, id2label, time.perf_counter() - t0)
            except ImportError as exc:
                self._model = None
                self.degraded_reason = f"sentence-transformers not installed ({exc.name})"
            except Exception as exc:  # noqa: BLE001
                self._model = None
                self.degraded_reason = f"{type(exc).__name__}: {str(exc)[:120]}"
            if self.degraded_reason:
                log.warning("grounding DEGRADED (verification skipped): %s", self.degraded_reason)

    def warm(self) -> None:
        self._try_load()
        if self._model is not None:
            self._model.predict([("warm-up reference.", "warm-up claim.")], apply_softmax=True)

    @property
    def degraded(self) -> bool:
        self._try_load()
        return self._model is None

    # -- verification -------------------------------------------------------------

    def verify(self, answer: str, reference: str) -> VerificationOutcome:
        t0 = time.perf_counter()
        self._try_load()

        claims = split_claims(answer)
        ref_sents = split_reference(reference)

        if self._model is None:
            return VerificationOutcome(
                result=GroundingResult(enabled=False, status=GroundingStatus.SKIPPED),
                duration_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                engine=f"unavailable: {self.degraded_reason}",
            )
        if not claims or not ref_sents:
            return VerificationOutcome(
                result=GroundingResult(enabled=True, claims=len(claims), status=GroundingStatus.SKIPPED),
                duration_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                engine="no assertive claims" if not claims else "empty reference",
            )

        # Evidence retrieval: top-k reference sentences per claim by cosine.
        emb = get_embedding_service()
        vecs = emb.embed(claims + ref_sents).vectors
        c_vecs, r_vecs = vecs[: len(claims)], vecs[len(claims):]

        def cos(a: list[float], b: list[float]) -> float:
            return sum(x * y for x, y in zip(a, b))

        pairs: list[tuple[str, str]] = []
        pair_index: list[tuple[int, int]] = []
        for ci, cv in enumerate(c_vecs):
            ranked = sorted(range(len(ref_sents)), key=lambda ri: cos(cv, r_vecs[ri]), reverse=True)
            for ri in ranked[:_MAX_EVIDENCE]:
                pairs.append((ref_sents[ri], claims[ci]))
                pair_index.append((ci, ri))

        probs = self._model.predict(pairs, apply_softmax=True, show_progress_bar=False)
        ent_i, con_i, neu_i = self._labels["entailment"], self._labels["contradiction"], self._labels["neutral"]

        # Per claim: the evidence sentence with the strongest entailment.
        best: dict[int, tuple[float, float, float, int]] = {}
        for (ci, ri), row in zip(pair_index, probs):
            e, c, n = float(row[ent_i]), float(row[con_i]), float(row[neu_i])
            cur = best.get(ci)
            if cur is None or e > cur[0] or (e == cur[0] and c > cur[1]):
                best[ci] = (e, c, n, ri)

        scores: list[ClaimScore] = []
        for ci, claim in enumerate(claims):
            e, c, n, ri = best[ci]
            if e >= SUPPORT_THRESHOLD and e >= c:
                verdict = "SUPPORTED"
            elif c >= CONTRADICT_THRESHOLD and c > e:
                verdict = "CONTRADICTED"
            else:
                verdict = "UNSUPPORTED"
            scores.append(ClaimScore(claim, ref_sents[ri], round(e, 4), round(c, 4), round(n, 4), verdict))

        supported = sum(1 for s in scores if s.verdict == "SUPPORTED")
        contradicted = sum(1 for s in scores if s.verdict == "CONTRADICTED")
        unsupported = len(scores) - supported - contradicted
        score = round(supported / len(scores), 4)

        # Status bands are the engine's fallback; the policy engine applies
        # the profile's own review_below / replace_below on top.
        if score < settings.grounding_replace_below:
            status = GroundingStatus.UNGROUNDED
        elif score < settings.grounding_review_below:
            status = GroundingStatus.REVIEW
        else:
            status = GroundingStatus.GROUNDED

        result = GroundingResult(
            enabled=True,
            claims=len(scores),
            supported=supported,
            unsupported=unsupported,
            contradicted=contradicted,
            score=score,
            status=status,
            unsupported_claims=[s.claim for s in scores if s.verdict != "SUPPORTED"][:10],
            claim_detail=[
                ClaimVerdict(claim=s.claim, verdict=s.verdict,  # type: ignore[arg-type]
                             score=s.entailment if s.verdict == "SUPPORTED" else
                             (s.contradiction if s.verdict == "CONTRADICTED" else s.entailment),
                             evidence=s.evidence)
                for s in scores
            ],
        )
        return VerificationOutcome(
            result=result, claim_scores=scores,
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def health(self) -> dict:
        self._try_load()
        return {
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason,
            "model": self.model_name,
            "labels": dict(self._labels),
        }


@lru_cache
def get_verifier() -> GroundingVerifier:
    return GroundingVerifier()
