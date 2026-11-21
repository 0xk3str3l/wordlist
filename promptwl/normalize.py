"""Canonicalization for matching — the F-005 / F-006 / F-007 stack, in-library.

The demos in ``examples/`` proved, one row at a time, that a keyword guardrail
only sees the surface form it was written for:

  * F-005 — encodings (leet, Base64, ROT13, reversal, chains) hide the payload;
  * F-006 — invisible codepoints (zero-width, Unicode Tags, bidi) carry it as
    *structure* rather than as text;
  * F-007 — cross-script confusables (Cyrillic ``а`` for Latin ``a``) render
    as ASCII to a human while being different codepoints to the matcher.

Everything needed to close those three channels lives here, so a defender can
canonicalize once and match against the corpus instead of re-implementing the
stack in every project::

    import promptwl
    hits = promptwl.scan(user_text)          # matched through all three channels
    clean, n = promptwl.strip_invisible(user_text)

Rules of the road (these are F-007's caveats, kept honest):

* Canonicalize a **copy**. Match on the canonical form; never rewrite the
  user-visible text — folding a real non-Latin language breaks it.
* This is a **recall-oriented baseline**, not a complete guardrail. It is a
  corpus of patterns, not a classifier. Pair it with your own benign corpus
  and measure the false-positive rate before shipping it.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

__all__ = [
    "INVISIBLE",
    "BIDI",
    "TAGS_LO",
    "TAGS_HI",
    "strip_invisible",
    "reveal_tags",
    "reveal_bidi",
    "confusable_fold",
    "normalize",
    "variants",
]


# --- invisible vehicles (F-006) --------------------------------------------

#: Zero-width / invisible-format vehicles and their names.
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
}

#: Bidirectional formatting / override controls (Trojan Source class, F-009).
BIDI = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x061C: "ARABIC LETTER MARK",
}

#: Unicode Tags block — the invisible ASCII mirror.
TAGS_LO, TAGS_HI = 0xE0000, 0xE007F


def _is_invisible(cp: int) -> bool:
    if cp in INVISIBLE or cp in BIDI:
        return True
    if TAGS_LO <= cp <= TAGS_HI:
        return True
    ch = chr(cp)
    if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\t\n\r":
        return True
    return False


def strip_invisible(text: str) -> Tuple[str, int]:
    """Strip invisible/format codepoints. Returns ``(clean_text, n_removed)``."""
    kept = [ch for ch in text if not _is_invisible(ord(ch))]
    return "".join(kept), len(text) - len(kept)


def reveal_tags(text: str) -> str:
    """Decode the Unicode Tags mirror back to visible ASCII."""
    return "".join(
        chr(ord(ch) - TAGS_LO)
        for ch in text
        if TAGS_LO + 0x20 <= ord(ch) <= TAGS_LO + 0x7E
    )


def reveal_bidi(text: str) -> Tuple[List[str], str]:
    """Report bidi controls present and the logical (stored) order.

    Bidi overrides reorder how a string *renders*; stripping them shows the
    true byte order a compiler/model sees.
    """
    controls = [BIDI[ord(c)] for c in text if ord(c) in BIDI]
    logical = "".join(c for c in text if ord(c) not in BIDI)
    return controls, logical


# --- confusables (F-007) ---------------------------------------------------

#: Curated cross-script confusable -> ASCII map (a practical subset of the
#: Unicode UTS-39 "confusables" set). NFKC does NOT fold these — Cyrillic and
#: Greek look-alikes live in separate scripts — so we handle them explicitly.
#:
#: Production deployments should load the full UTS-39 table; this subset
#: covers the letters that appear in the corpus and in real traffic.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "к": "k", "н": "h", "в": "b", "м": "m",
    "т": "t", "ѐ": "e", "ԁ": "d", "ց": "g", "ո": "n", "һ": "h", "ӏ": "l",
    "ᴧ": "a", "в": "b",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "τ": "t", "ν": "v", "υ": "u",
    "κ": "k", "ι": "i", "χ": "x", "β": "b", "γ": "y", "ϲ": "c", "ϳ": "j",
    # Latin look-alikes / mathematical alphanumerics
    "ɡ": "g", "ɑ": "a", "ɩ": "i", "ɪ": "i", "ʟ": "l", "ᴏ": "o",
    "ⅽ": "c", "ⅾ": "d", "ⅿ": "m", "ⲟ": "o", "ⲣ": "r", "ⲡ": "p",
    # Fullwidth forms are folded by NFKC, listed here for completeness.
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
}


def confusable_fold(text: str) -> str:
    """Map cross-script confusable letters back to their ASCII skeleton."""
    return "".join(CONFUSABLES.get(c, c) for c in text)


# --- the canonical form ----------------------------------------------------

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)


def normalize(text: str) -> str:
    """Canonicalize text for matching.

    Order matters, and it is the order the journal landed on:

    1. **NFKC** — folds compatibility forms (fullwidth, ligatures, superscripts).
    2. **strip invisible** — removes zero-width / bidi / Tags codepoints (F-006).
    3. **confusable-fold** — collapses cross-script look-alikes (F-007).
    4. **casefold** — case-insensitive matching.
    5. **collapse whitespace** — so line wrapping can't hide a phrase.
    """
    text = unicodedata.normalize("NFKC", text)
    text, _ = strip_invisible(text)
    text = confusable_fold(text)
    text = text.casefold()
    return _WS.sub(" ", text).strip()


def depunctuate(text: str) -> str:
    """Remove punctuation (each mark becomes a space) and collapse whitespace."""
    return _WS.sub(" ", _PUNCT.sub(" ", text)).strip()


def variants(text: str) -> List[str]:
    """Return the canonical forms worth matching against.

    The second form drops punctuation, so a phrase still matches when the
    attacker sprinkles it with dots or brackets ("ignore.all.previous.instructions").
    The third drops spaces entirely, which catches space-separated obfuscation.
    """
    base = normalize(text)
    out = [base]
    depunct = depunctuate(base)
    if depunct and depunct != base:
        out.append(depunct)
    tight = base.replace(" ", "")
    if len(tight) >= 6 and tight != base:
        out.append(tight)
    # de-duplicate, keep order
    seen = set()
    uniq = []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq
