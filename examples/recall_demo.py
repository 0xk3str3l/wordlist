#!/usr/bin/env python3
"""Score the naive guardrail against the promptwl corpus.

Run it:

    python3 examples/recall_demo.py

Recall = fraction of known-attack phrases the guardrail flags as "block".

Three numbers matter, and they answer three different questions:

  * **per class** — which *shape* of attack a keyword filter can even see.
  * **English vs translated** — the same phrasings, two languages: the gap a
    monolingual filter hides from itself.
  * **structural classes** — control markers, output payloads and tokenizer
    artifacts, where a phrase filter is the wrong tool entirely and 0% is not
    a bug but the point.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import promptwl  # noqa: E402
from examples.naive_guardrail import guardrail  # noqa: E402


def _bar(pct: float, width: int = 24) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "·" * (width - filled)


def _recall(entries) -> float:
    if not entries:
        return 0.0
    caught = sum(1 for e in entries if guardrail(e.text) == "block")
    return 100 * caught / len(entries)


def main() -> int:
    entries = list(promptwl.load())

    print("\npromptwl · naive-guardrail recall demo 🦜")
    print("=" * 52)
    print("A caricature English keyword filter, scored against the corpus.\n")

    # --- per category ---
    print(f"{'category':<14}{'recall':>8}   coverage")
    print("-" * 52)
    for cat in promptwl.categories():
        cat_entries = [e for e in entries if e.category == cat]
        r = _recall(cat_entries)
        print(f"{cat:<14}{r:>6.0f}%   {_bar(r)}")

    # --- the headline: SAME phrasing, English vs translated ---
    # The multilingual set is a translation of the English prose patterns, so
    # compare prose against prose — apples to apples.
    core = {"injection", "jailbreak", "extraction"}
    english = [e for e in entries if e.category in core and e.klass == "prose"]
    multi = [e for e in entries if e.category == "multilingual"]
    r_en, r_ml = _recall(english), _recall(multi)

    print("\n" + "=" * 52)
    print("HEADLINE — same phrasing, English vs translated")
    print("-" * 52)
    print(f"{'English (prose)':<26}{r_en:>6.0f}%   {_bar(r_en)}")
    print(f"{'The same, translated':<26}{r_ml:>6.0f}%   {_bar(r_ml)}")
    gap = r_en - r_ml
    print(f"\n  → the filter catches ~{r_en:.0f}% of these attacks in English")
    print(f"    and ~{r_ml:.0f}% the moment the attacker switches language.\n")

    # --- per language, to show it's not one outlier ---
    langs = {}
    for e in multi:
        code = Path(e.file).stem  # es, fr, de, ...
        langs.setdefault(code, []).append(e)
    print("multilingual breakdown")
    print("-" * 52)
    for code in sorted(langs):
        r = _recall(langs[code])
        print(f"  {code:<6}{r:>6.0f}%   {_bar(r, 18)}")

    # --- structural classes: a phrase filter is the wrong tool here ---
    structural = [e for e in entries if e.klass == "structural"]
    r_st = _recall(structural)
    print("\n" + "=" * 52)
    print("STRUCTURAL CLASSES — where a phrase filter cannot help")
    print("-" * 52)
    print(f"{'structural patterns':<26}{r_st:>6.0f}%   {_bar(r_st)}")
    print("  (chat-template markers, output payloads, tokenizer artifacts)")
    print("  → 0% here is not a bug: these are literal markers and payloads.")
    print("    They need literal matching, output escaping and tokenizer")
    print("    hygiene — a keyword list was never going to see them.\n")

    # --- false-positive rate on benign traffic ---
    benign_path = ROOT / "examples" / "benign.txt"
    benign = [
        line.strip()
        for line in benign_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    fp = sum(1 for t in benign if guardrail(t) == "block")
    fpr = 100 * fp / len(benign) if benign else 0.0

    print("=" * 52)
    print(f"overall recall : {_recall(entries):.0f}%  ({len(entries)} attack phrases)")
    print(f"false positives: {fpr:.0f}%  ({fp}/{len(benign)} benign requests blocked)")
    print("\nMoral: keyword filters catch the English phrasings they were written")
    print("for — and go blind on other languages, encodings, indirect injection,")
    print("and glitch tokens (all 0% above). Wire promptwl into CI and watch the")
    print("number instead of guessing. 🦜\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
