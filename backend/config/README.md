# Configuration

Detection patterns, policy rules and estimation assumptions live here as
**data, not code**. Nothing in `app/` is allowed to hardcode a tunable value.

| File | Phase | Purpose |
|---|---|---|
| `secret_patterns.yaml` | 1 | Credential regexes, weights, confidence scoring |
| `injection_rules.yaml` | 4 | OWASP LLM01 heuristics, rule IDs, weights |
| `policies.yaml` | 6 | Detection to action mapping, profiles, appealability |
| `pii_entities.yaml` | 2 | Per-entity thresholds, placeholders, engines |
| `india_names.yaml` | 3 | Name gazetteer that closes the measured PERSON recall gap |
| `routing.yaml` | 7 | Complexity classifier bands and markers; semantic-guard config |
| `pricing.yaml` | 12 | Per-model list prices, savings counterfactual, and the `basis` string shown in the UI |
| `sustainability.yaml` | 12 | Wh per 1k tokens by model class, grid gCO2/kWh by region, avoided counterfactual |

Every file that drives an estimate must carry a `basis` field. A number
without a stated assumption is fabricated telemetry.
