"""Stage timing.

Every duration reported to the Gateway is measured here with a monotonic
clock. Nothing in Aegis is allowed to report an estimated or hardcoded
duration -- the live pipeline view in the dashboard is only meaningful if the
numbers are real (spec s11 rule 6).
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from app.contracts.common import PipelineStage, StageStatus


class StageRecorder:
    """Collects measured PipelineStage entries for one request."""

    def __init__(self) -> None:
        self._stages: list[PipelineStage] = []
        self._started = time.perf_counter()

    @contextmanager
    def stage(self, name: str) -> Iterator["StageHandle"]:
        handle = StageHandle(name)
        start = time.perf_counter()
        try:
            yield handle
        except Exception as exc:  # noqa: BLE001 - recorded then re-raised
            elapsed = (time.perf_counter() - start) * 1000.0
            self._stages.append(
                PipelineStage(
                    stage=name,
                    status=StageStatus.ERROR,
                    duration_ms=round(elapsed, 3),
                    detail=type(exc).__name__,
                )
            )
            raise
        else:
            elapsed = (time.perf_counter() - start) * 1000.0
            self._stages.append(
                PipelineStage(
                    stage=name,
                    status=handle.status,
                    duration_ms=round(elapsed, 3),
                    detail=handle.detail,
                )
            )

    def skip(self, name: str, detail: str | None = None) -> None:
        """Record a stage that did not run. Never silently omit a stage --
        the dashboard must be able to show that it was skipped and why."""
        self._stages.append(
            PipelineStage(
                stage=name, status=StageStatus.SKIPPED, duration_ms=0.0, detail=detail
            )
        )

    @property
    def stages(self) -> list[PipelineStage]:
        return list(self._stages)

    @property
    def total_ms(self) -> float:
        return round((time.perf_counter() - self._started) * 1000.0, 3)


class StageHandle:
    """Mutable handle a stage body uses to report its own outcome."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.status: StageStatus = StageStatus.SUCCESS
        self.detail: str | None = None

    def warn(self, detail: str | None = None) -> None:
        self.status = StageStatus.WARNING
        self.detail = detail

    def block(self, detail: str | None = None) -> None:
        self.status = StageStatus.BLOCKED
        self.detail = detail

    def hit(self, detail: str | None = None) -> None:
        self.status = StageStatus.HIT
        self.detail = detail

    def miss(self, detail: str | None = None) -> None:
        self.status = StageStatus.MISS
        self.detail = detail

    def note(self, detail: str) -> None:
        self.detail = detail
