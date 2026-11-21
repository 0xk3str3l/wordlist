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
from dataclasses import dataclass
from typing import List, Tuple

__all__ = [
    "INVISIBLE",
    "BIDI",
    "TAGS_LO",
    "TAGS_HI",
    "CARRIER_CHANNELS",
    "Carrier",
    "carriers",
    "strip_invisible",
    "reveal_tags",
    "reveal_bidi",
    "confusable_fold",
    "normalize",
    "depunctuate",
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
    0x034F: "COMBINING GRAPHEME JOINER",
    0x3164: "HANGUL FILLER",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0xFE0E: "VARIATION SELECTOR-15 (TEXT PRESENTATION)",
    0xFE0F: "VARIATION SELECTOR-16 (EMOJI PRESENTATION)",
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


# --- steganographic carriers (F-006 extended) --------------------------------

def _cps(*parts) -> frozenset:
    """Build a frozenset of codepoints from ints and (lo, hi) pairs."""
    out = set()
    for part in parts:
        if isinstance(part, tuple):
            out.update(range(part[0], part[1] + 1))
        else:
            out.add(part)
    return frozenset(out)


#: Carrier channels — the *places* a payload can hide that render as ordinary
#: text. ``high`` channels render as nothing at all; ``soft`` channels render
#: as visible but unusual characters (dots, wide spaces, skin tones) and are
#: therefore reported only in ``strict`` mode.
CARRIER_CHANNELS = {
    "zero-width": (True, _cps((0x200B, 0x200D), (0x2060, 0x2060), (0xFEFF, 0xFEFF), (0x00AD, 0x00AD))),
    "bidi-override": (True, _cps((0x202A, 0x202E), (0x2066, 0x2069), (0x200E, 0x200F), (0x061C, 0x061C))),
    "unicode-tags": (True, _cps((TAGS_LO, TAGS_HI))),
    "variation-selector": (True, _cps((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))),
    "hangul-filler": (True, _cps((0x3164, 0x3164), (0x115F, 0x1160))),
    "invisible-ink": (True, _cps((0x2061, 0x2064), (0x034F, 0x034F), (0x180E, 0x180E))),
    "braille-pattern": (False, _cps((0x2800, 0x28FF))),
    "confusable-space": (False, _cps((0x1680, 0x1680), (0x2000, 0x200A), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000))),
    "emoji-modifier": (False, _cps((0x1F3FB, 0x1F3FF))),
}


@dataclass(frozen=True)
class Carrier:
    """One steganographic carrier found in a string."""

    channel: str
    index: int
    codepoint: int
    name: str

    def __str__(self) -> str:
        return f"  [{self.index}] {self.channel} — U+{self.codepoint:04X} {self.name}"


def carriers(text: str, strict: bool = False) -> List[Carrier]:
    """Report the steganographic carrier channels present in ``text``.

    A carrier is a *place* a payload hides, not a payload: zero-width
    joiners, bidi overrides, Unicode Tags, variation selectors, Hangul
    fillers, invisible-ink controls, and — in ``strict`` mode — the visible
    but unusual ones (Braille dot patterns, look-alike spaces, emoji skin-tone
    modifiers).

    ``strict=False`` reports only the channels that render as nothing. Those
    are the ones that are unambiguously worth stopping: legitimate text
    contains Braille and emoji modifiers, so flagging those by default would
    drown the signal.

    Detection is cheap; the decision of what to do about a hit is yours.
    """
    out: List[Carrier] = []
    for index, ch in enumerate(text):
        cp = ord(ch)
        for channel, (high, codepoints) in CARRIER_CHANNELS.items():
            if not high and not strict:
                continue
            if cp in codepoints:
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    name = f"CARRIER U+{cp:04X}"
                out.append(Carrier(channel=channel, index=index, codepoint=cp, name=name))
                break
    return out


def _is_invisible(cp: int) -> bool:
    if cp in INVISIBLE or cp in BIDI:
        return True
    if TAGS_LO <= cp <= TAGS_HI:
        return True
    # High-signal carrier channels render as nothing (F-006 extended).
    for channel, (high, codepoints) in CARRIER_CHANNELS.items():
        if high and cp in codepoints:
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
