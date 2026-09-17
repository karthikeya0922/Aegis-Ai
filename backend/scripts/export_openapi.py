"""Export openapi.json for Person 2.

Run after any contract change:

    python scripts/export_openapi.py

Person 2 generates a typed client from the output:

    npx openapi-typescript backend/openapi.json -o gateway/src/lib/inspector.d.ts
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "openapi.json"


def main() -> int:
    spec = app.openapi()
    OUT.write_text(json.dumps(spec, indent=2), encoding="utf-8")

    paths = spec.get("paths", {})
    operations = sum(
        1
        for methods in paths.values()
        for m in methods
        if m in {"get", "post", "put", "delete", "patch"}
    )
    print(f"wrote {OUT}")
    print(f"  {len(paths)} paths, {operations} operations, "
          f"{len(spec.get('components', {}).get('schemas', {}))} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
