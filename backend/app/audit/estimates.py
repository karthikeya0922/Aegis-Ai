"""Cost, energy and carbon ESTIMATES.

Every function here returns a number the Inspector did not measure. That is
fine as long as the number is labelled and its basis travels with it -- so
each loader exposes a `basis` string, and every metrics response carries it.

Used in two places: upsert_event fills in estimated_* fields the Gateway
did not supply, and metrics.py reports the basis alongside the sums.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import CONFIG_DIR

PRICING_PATH = CONFIG_DIR / "pricing.yaml"
SUSTAINABILITY_PATH = CONFIG_DIR / "sustainability.yaml"


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pricing:
    version: int
    as_of: str
    basis: str
    models: dict[str, tuple[float, float]]  # model -> (input, output) USD per 1M
    default: tuple[float, float]
    savings_counterfactual_model: str

    def rates(self, model: str | None) -> tuple[float, float]:
        if model and model in self.models:
            return self.models[model]
        # tolerate provider-prefixed or versioned names: "openai/gpt-4o-2024-08"
        if model:
            key = model.split("/")[-1].lower()
            # Longest prefix wins: "gpt-4o-mini-2025" must match gpt-4o-mini, not gpt-4o.
            for name in sorted(self.models, key=len, reverse=True):
                if key.startswith(name):
                    return self.models[name]
        return self.default

    def cost_usd(self, model: str | None, input_tokens: int | None, output_tokens: int | None) -> float:
        i, o = self.rates(model)
        return round(((input_tokens or 0) * i + (output_tokens or 0) * o) / 1_000_000, 6)


@lru_cache
def get_pricing(path: Path | None = None) -> Pricing:
    raw = yaml.safe_load((path or PRICING_PATH).read_text(encoding="utf-8"))
    models = {
        str(k): (float(v.get("input", 0.0)), float(v.get("output", 0.0)))
        for k, v in (raw.get("models") or {}).items()
    }
    d = raw.get("default") or {}
    return Pricing(
        version=int(raw.get("version", 1)),
        as_of=str(raw.get("as_of", "")),
        basis=" ".join(str(raw.get("basis", "")).split()),
        models=models,
        default=(float(d.get("input", 1.0)), float(d.get("output", 4.0))),
        savings_counterfactual_model=str(raw.get("savings_counterfactual_model", "gpt-4o-mini")),
    )


# ---------------------------------------------------------------------------
# Sustainability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Sustainability:
    version: int
    basis: str
    wh_per_1k: dict[str, float]  # class -> Wh per 1k tokens
    model_class: dict[str, str]
    grid: dict[str, float]  # region -> gCO2 per kWh
    region: str
    avoided_counterfactual_model: str

    def klass(self, model: str | None) -> str:
        if not model:
            return "unknown"
        if model in self.model_class:
            return self.model_class[model]
        key = model.split("/")[-1].lower()
        for name in sorted(self.model_class, key=len, reverse=True):
            if key.startswith(name):
                return self.model_class[name]
        return "unknown"

    def energy_wh(self, model: str | None, total_tokens: int | None) -> float:
        per_1k = self.wh_per_1k.get(self.klass(model), self.wh_per_1k.get("unknown", 1.5))
        return round((total_tokens or 0) / 1000.0 * per_1k, 6)

    @property
    def gco2_per_kwh(self) -> float:
        return self.grid.get(self.region, self.grid.get("global", 480.0))

    def co2_g(self, energy_wh: float) -> float:
        return round(energy_wh / 1000.0 * self.gco2_per_kwh, 6)


@lru_cache
def get_sustainability(path: Path | None = None) -> Sustainability:
    raw = yaml.safe_load((path or SUSTAINABILITY_PATH).read_text(encoding="utf-8"))
    region = os.environ.get("AEGIS_GRID_REGION", str(raw.get("default_region", "global"))).lower()
    grid = {str(k).lower(): float(v) for k, v in (raw.get("grid_gco2_per_kwh") or {}).items()}
    if region not in grid:
        region = str(raw.get("default_region", "global")).lower()
    return Sustainability(
        version=int(raw.get("version", 1)),
        basis=" ".join(str(raw.get("basis", "")).split()) + f" Grid region: {region} ({grid.get(region)} gCO2/kWh).",
        wh_per_1k={str(k): float(v) for k, v in (raw.get("energy_wh_per_1k_tokens") or {}).items()},
        model_class={str(k): str(v) for k, v in (raw.get("model_class") or {}).items()},
        grid=grid,
        region=region,
        avoided_counterfactual_model=str(raw.get("avoided_counterfactual_model", "gpt-4o-mini")),
    )
