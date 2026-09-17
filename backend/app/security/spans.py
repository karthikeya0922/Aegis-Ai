"""Span arithmetic shared by every scanner.

Several recognisers legitimately fire on the same text: a JWT inside a Bearer
header, an email-shaped fragment inside a database URI, a phone number that
also looks like a card fragment. Reporting all of them inflates counts and
produces nested placeholders, so each scanner resolves its own overlaps, and
the redactor (phase 5) resolves overlaps *between* scanners.

Rule: longest match wins; confidence breaks a tie. This is deliberately
simple and deterministic -- a reviewer should be able to predict the outcome.
"""

from __future__ import annotations

from typing import Callable, Iterable, TypeVar

T = TypeVar("T")

SpanKey = Callable[[T], tuple[int, int, int]]
"""Returns (message_index, start, end) for an item."""

Score = Callable[[T], float]


def resolve_overlaps(
    items: Iterable[T],
    span: SpanKey[T],
    score: Score[T],
) -> list[T]:
    """Keep the strongest item per overlapping region.

    Two items overlap when they share a message_index and their [start, end)
    ranges intersect. Among overlapping items the longest wins; if lengths tie,
    the higher score wins; if that ties too, the earlier one is kept.
    """
    ordered = sorted(
        items,
        key=lambda it: (
            span(it)[0],
            span(it)[1],
            -(span(it)[2] - span(it)[1]),
            -score(it),
        ),
    )
    kept: list[T] = []
    for candidate in ordered:
        c_msg, c_start, c_end = span(candidate)
        clash_index = next(
            (
                i
                for i, k in enumerate(kept)
                if span(k)[0] == c_msg and c_start < span(k)[2] and span(k)[1] < c_end
            ),
            None,
        )
        if clash_index is None:
            kept.append(candidate)
            continue
        incumbent = kept[clash_index]
        _, i_start, i_end = span(incumbent)
        if ((c_end - c_start), score(candidate)) > ((i_end - i_start), score(incumbent)):
            kept[clash_index] = candidate
    return sorted(kept, key=lambda it: (span(it)[0], span(it)[1]))


def subtract_covered(
    candidates: Iterable[T],
    covering: Iterable[T],
    span_candidate: SpanKey[T],
    span_covering: SpanKey,
) -> list[T]:
    """Drop any candidate whose span lies inside a covering span.

    Used when one scanner's finding should take precedence over another's on
    the same text. A database URI detected by the secret scanner covers the
    email-shaped `user:pass@host` fragment inside it; the PII scanner's
    EMAIL finding on that fragment is noise and is removed here.
    """
    cover = [span_covering(c) for c in covering]
    out: list[T] = []
    for cand in candidates:
        c_msg, c_start, c_end = span_candidate(cand)
        inside = any(
            m == c_msg and s <= c_start and c_end <= e for (m, s, e) in cover
        )
        if not inside:
            out.append(cand)
    return out
