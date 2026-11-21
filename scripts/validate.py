#!/usr/bin/env python3
"""Validate that manifest.json and the wordlist corpus are consistent.

Exits non-zero (failing CI) if any manifest file is missing, empty, or if the
loader raises. Also reports — and optionally fails on — corpus hygiene
problems: orphaned files, duplicate phrases, missing file headers, and
metadata sidecars that don't line up with their corpus.

    python3 scripts/validate.py            # errors fail, warnings are printed
    python3 scripts/validate.py --strict   # warnings fail too
"""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import promptwl  # noqa: E402

REQUIRED_HEADER_KEYS = ("category:", "purpose:", "use:", "source-level:")


def header_block(path: Path) -> str:
    """Return the file's leading comment block (the documentation header)."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            if out:
                break  # a blank line ends the header
            continue
        if not stripped.startswith("#"):
            break
        out.append(stripped.lower())
    return "\n".join(out)


def main() -> int:
    strict = "--strict" in sys.argv
    errors = []
    warnings = []
    m = promptwl.manifest()

    # Version single-source guard: the raw on-disk manifest.json must match
    # promptwl.__version__ (the one source of truth). manifest() overrides the
    # field at load time, so this reads the file directly to catch static drift.
    raw = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    if raw.get("version") != promptwl.__version__:
        errors.append(
            f"manifest.json version {raw.get('version')!r} != "
            f"promptwl.__version__ {promptwl.__version__!r} "
            f"(update manifest.json to match)"
        )

    # Manifest paths must be unique — a repeated path double-counts a file.
    manifest_paths = [f["path"] for c in m["categories"] for f in c["files"]]
    for path, n in Counter(manifest_paths).items():
        if n > 1:
            errors.append(f"path listed {n} times in manifest.json: {path}")

    entries_by_file = {}
    for cat in m["categories"]:
        for f in cat["files"]:
            path = ROOT / f["path"]
            if not path.exists():
                errors.append(f"missing file: {f['path']}")
                continue
            entries = [e for e in promptwl.load(cat["id"]) if e.file == f["path"]]
            if not entries:
                errors.append(f"no phrases loaded from: {f['path']}")
            entries_by_file[f["path"]] = entries

            # Header hygiene: the header is the documentation for the file.
            header = header_block(path)
            for key in REQUIRED_HEADER_KEYS:
                if key not in header:
                    warnings.append(f"{f['path']}: header is missing '# {key}'")

    # Orphaned corpus files: present on disk, absent from the manifest. They
    # would never load, so nothing would ever test them.
    on_disk = {
        str(p.relative_to(ROOT)).replace("\\", "/")
        for p in (ROOT / "wordlists").rglob("*.txt")
    }
    for orphan in sorted(on_disk - set(manifest_paths)):
        errors.append(f"file not registered in manifest.json: {orphan}")

    # Metadata sidecars must exist for files that declare per-phrase metadata,
    # and their keys must match phrases that are actually in the corpus.
    for path in sorted(ROOT.glob("wordlists/**/*.meta.json")):
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        corpus_path = path.with_name(path.name[: -len(".meta.json")] + ".txt")
        if not corpus_path.exists():
            errors.append(f"metadata sidecar without a corpus file: {rel}")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON ({exc})")
            continue
        if data.get("schema") != promptwl.META_SCHEMA:
            warnings.append(f"{rel}: schema is {data.get('schema')!r}, expected {promptwl.META_SCHEMA!r}")
        phrases = set()
        for line in corpus_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("\\"):
                phrases.add(promptwl.unescape(s).strip())
            elif not s.startswith("#"):
                phrases.add(s)
        for key in data.get("entries", {}):
            if key not in phrases:
                errors.append(f"{rel}: metadata key not found in corpus: {key!r}")

    # Duplicate phrases: inside one file that is a copy-paste bug; across files
    # it inflates recall numbers (the same phrase counted twice).
    all_entries = list(promptwl.load())
    per_file = Counter(e.text for e in all_entries)
    dupes = {t: n for t, n in per_file.items() if n > 1}
    for text, n in sorted(dupes.items()):
        files = sorted({e.file for e in all_entries if e.text == text})
        same_file = any(
            sum(1 for e in all_entries if e.text == text and e.file == f) > 1 for f in files
        )
        msg = f"duplicate phrase ({n}x): {text!r} in {', '.join(files)}"
        if same_file:
            errors.append(msg + " — same file twice")
        else:
            warnings.append(msg)

    if errors or (strict and warnings):
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        for w in warnings:
            print(f"  ! {w}" + ("  [strict]" if strict else ""))
        return 1

    stats = promptwl.stats()
    total = stats.pop("total")
    unique = len(promptwl.unique_phrases())
    print("promptwl corpus OK")
    for cat, n in stats.items():
        print(f"  {cat:<12} {n:>4}")
    print(f"  {'total':<12} {total:>4}   ({unique} unique phrases)")
    if warnings:
        print("\nwarnings:")
        for w in warnings:
            print(f"  ! {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
