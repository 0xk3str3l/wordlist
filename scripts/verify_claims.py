#!/usr/bin/env python3
"""Verify that the numbers we publish actually match the corpus.

Every headline number in the README is a *claim*. This script re-derives each
claim from the corpus and fails if the README (or the committed claim file)
has drifted — the same discipline an upstream red-team harness uses when it
re-derives its README numbers from committed result artifacts.

    python3 scripts/verify_claims.py            # verify (CI)
    python3 scripts/verify_claims.py --update   # re-derive bench/claims.json

Nothing here is a benchmark result; it is a *consistency* check. A corpus that
silently drifts away from the badge on the front page is a corpus nobody can
trust.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import promptwl  # noqa: E402

CLAIMS_PATH = ROOT / "bench" / "claims.json"
README = ROOT / "README.md"
SCHEMA = "promptwl.claims/1"


def derive() -> dict:
    """Re-derive every published claim from the corpus itself."""
    stats = promptwl.stats()
    total = stats.pop("total")
    multilingual = [p for p in promptwl.files() if p.startswith("wordlists/multilingual/")]
    return {
        "total_phrases": total,
        "unique_phrases": len(promptwl.unique_phrases()),
        "categories": len(promptwl.categories()),
        "files": len(promptwl.files()),
        "translated_languages": len(multilingual),
        "languages_incl_english": len(multilingual) + 1,
        "per_category": dict(sorted(stats.items())),
    }


def readme_badges(text: str) -> dict:
    """Pull the shields.io badge values out of the README.

    A shields.io badge URL is ``/<label>-<value>-<color>``; we keep the value.
    """
    from urllib.parse import unquote

    badges = {}
    for alt, raw in re.findall(r'alt="([^"]+)"\s+src="https://img\.shields\.io/badge/([^"]+)"', text):
        body = raw
        prefix = f"{alt}-"
        if body.startswith(prefix):
            body = body[len(prefix):]
        badges[alt] = unquote(body.rsplit("-", 1)[0])
    return badges


def main() -> int:
    update = "--update" in sys.argv
    derived = derive()

    if update:
        payload = {"schema": SCHEMA, "claims": derived}
        CLAIMS_PATH.parent.mkdir(parents=True, exist_ok=True)
        CLAIMS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {CLAIMS_PATH.relative_to(ROOT)}")
        for k, v in derived.items():
            print(f"  {k:<22} {v}")
        return 0

    errors = []

    if not CLAIMS_PATH.exists():
        errors.append(f"missing {CLAIMS_PATH.relative_to(ROOT)} — run with --update")
    else:
        committed = json.loads(CLAIMS_PATH.read_text(encoding="utf-8"))
        if committed.get("schema") != SCHEMA:
            errors.append(f"claims schema is {committed.get('schema')!r}, expected {SCHEMA!r}")
        for key, value in committed.get("claims", {}).items():
            actual = derived.get(key)
            if actual != value:
                errors.append(f"claim {key!r}: committed {value!r} != derived {actual!r}")

    # The README badges are claims too — a stale badge is a broken promise.
    badges = readme_badges(README.read_text(encoding="utf-8"))
    expected_badges = {
        "phrases": str(derived["total_phrases"]),
        "languages": str(derived["languages_incl_english"]),
    }
    for alt, expected in expected_badges.items():
        value = badges.get(alt)
        if value is None:
            errors.append(f"README has no '{alt}' badge")
            continue
        if value != expected:
            errors.append(f"README badge {alt}: shows {value!r}, corpus says {expected!r}")

    if errors:
        print("CLAIM VERIFICATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        print("\nRe-derive with: python3 scripts/verify_claims.py --update")
        return 1

    print("claims OK — every published number re-derives from the corpus")
    for k, v in derived.items():
        print(f"  {k:<22} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
