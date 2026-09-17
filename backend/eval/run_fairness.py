"""Run the fairness harness from the command line.

    python eval/run_fairness.py              # full corpus, both configurations, persisted
    python eval/run_fairness.py --quick      # 2 templates x 10 names per group, not persisted
    python eval/run_fairness.py --no-persist

Prints a per-group table for the baseline (NER only) and current (full
scanner) runs, plus the Indian gazetteer-covered / held-out split. The same
numbers are what GET /api/fairness/report serves.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit.database import init_db  # noqa: E402
from app.fairness.harness import format_table, load_corpus, run_both  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="2 templates x 10 names per group; implies --no-persist")
    ap.add_argument("--no-persist", action="store_true", help="do not write fairness_eval rows")
    ap.add_argument("--templates", type=int, default=None, help="limit templates")
    ap.add_argument("--names", type=int, default=None, help="limit names per group")
    args = ap.parse_args()

    if args.quick:
        args.templates, args.names, args.no_persist = 2, 10, True

    init_db()
    corpus = load_corpus()
    print(
        f"corpus v{corpus.version}: {len(corpus.templates)} templates, "
        + ", ".join(f"{k}={len(v)}" for k, v in corpus.groups.items())
    )
    baseline, current = run_both(
        corpus=corpus, max_templates=args.templates, max_names=args.names, persist=not args.no_persist
    )
    print()
    print(format_table(baseline, corpus))
    print()
    print(format_table(current, corpus))
    print()
    b = {g: t.recall for g, t in baseline.tallies.items()}
    c = {g: t.recall for g, t in current.tallies.items()}
    print("per-group delta (current - baseline):")
    for g in b:
        print(f"  {corpus.labels.get(g, g):12} {c[g] - b[g]:+.3f}")
    print("persisted" if not args.no_persist else "not persisted (--no-persist)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
