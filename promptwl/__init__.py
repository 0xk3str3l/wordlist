"""promptwl — a red-team and guardrail wordlist for LLMs. Kept by Parrot. 🦜

If Parrot can repeat it, so can your model. This is the zero-dependency loader
over the ``wordlists/`` corpus and ``manifest.json``.

Typical use — wire the corpus into a guardrail eval::

    import promptwl

    for entry in promptwl.load():                 # every phrase, with metadata
        verdict = my_guardrail(entry.text)         # your classifier under test
        assert verdict == "block", f"missed: {entry.text!r} ({entry.category})"

    # or pull a single category
    injections = promptwl.phrases(category="injection")

    # or scan live traffic for known attack patterns (normalizes first)
    hits = promptwl.scan(user_message)
    if hits:
        log.warning("promptwl matched: %s", hits[0].entry.text)

Lines that are blank or start with ``#`` are treated as comments and skipped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .normalize import (  # noqa: F401  (re-exported for convenience)
    BIDI,
    CONFUSABLES,
    INVISIBLE,
    TAGS_HI,
    TAGS_LO,
    confusable_fold,
    depunctuate,
    normalize,
    reveal_bidi,
    reveal_tags,
    strip_invisible,
    variants,
)

__version__ = "0.4.0"

_PKG_DIR = Path(__file__).resolve().parent
# pip-installed: wordlists/ is bundled next to __init__.py (force-include in pyproject.toml)
# git clone:     wordlists/ lives at the repo root (parent of the package dir)
_ROOT = _PKG_DIR if (_PKG_DIR / "wordlists").exists() else _PKG_DIR.parent
_MANIFEST = _ROOT / "manifest.json"

#: Metadata sidecar schema identifier.
META_SCHEMA = "promptwl.meta/1"


@dataclass(frozen=True)
class Entry:
    """A single wordlist phrase plus where it came from."""

    text: str
    category: str
    file: str
    title: str
    tags: Tuple[str, ...] = ()
    owasp: Optional[str] = None
    refs: Tuple[str, ...] = ()
    scannable: bool = True
    klass: str = "prose"


@dataclass(frozen=True)
class Match:
    """One corpus phrase found in a scanned string."""

    entry: Entry
    span: Tuple[int, int]
    needle: str

    def __str__(self) -> str:
        return f"{self.entry.category}/{self.entry.title}: {self.entry.text!r}"


def manifest() -> dict:
    """Return the parsed ``manifest.json``.

    The ``version`` field is always set from :data:`__version__` (the single
    source of truth), so the API never reports a stale on-disk value.
    """
    m = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    m["version"] = __version__
    return m


_ESCAPE_RE = re.compile(r"\\([#\\])")


def unescape(line: str) -> str:
    """Decode the escape convention used by corpus files.

    ``\\#`` becomes ``#`` and ``\\\\`` becomes ``\\``. Only used on lines that
    start with a backslash (i.e. escaped phrases).
    """
    return _ESCAPE_RE.sub(r"\1", line)


def _read_lines(path: Path) -> List[str]:
    """Read one phrase per line.

    Blank lines and ``#`` lines are comments. A line that starts with a
    backslash is an *escaped* phrase whose leading ``#`` is part of the text
    (chat-template markers like ``### Instruction:`` would otherwise be
    swallowed as a comment). So ``\\#\\#\\# Instruction:`` reads as
    ``### Instruction:``.
    """
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("\\"):
            out.append(unescape(line).strip())
            continue
        if line.startswith("#"):
            continue
        out.append(line)
    return out


def _meta_path(path: Path) -> Path:
    """Sidecar metadata path for a wordlist file: ``<name>.meta.json``.

    ``wordlists/injection/chat-template-markers.txt`` pairs with
    ``wordlists/injection/chat-template-markers.meta.json``.
    """
    return path.with_suffix(".meta.json")


def _load_meta(path: Path) -> Dict[str, dict]:
    """Load the optional metadata sidecar for ``path``.

    The sidecar keeps the corpus greppable (plain text, one phrase per line)
    while still carrying structured annotations per phrase::

        {
          "schema": "promptwl.meta/1",
          "entries": {
            "<|start_header_id|>": {"tags": ["llama3", "role-marker"], "owasp": "LLM01"}
          }
        }

    A missing sidecar is not an error — most files carry no per-phrase data.
    """
    meta_path = _meta_path(path)
    if not meta_path.exists():
        return {}
    raw = json.loads(meta_path.read_text(encoding="utf-8"))
    entries = raw.get("entries", {})
    if not isinstance(entries, dict):
        raise ValueError(f"{meta_path}: 'entries' must be an object")
    return entries


def _as_tuple(value) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def load(
    category: Optional[str] = None,
    tag: Optional[str] = None,
    owasp: Optional[str] = None,
    file: Optional[str] = None,
    klass: Optional[str] = None,
) -> Iterator[Entry]:
    """Yield every :class:`Entry`, optionally filtered.

    Filters combine with AND. ``tag`` matches if the entry carries that tag;
    ``owasp`` matches the OWASP LLM Top-10 id (file-level override first,
    then the category's); ``klass`` matches the file's attack shape:

    * ``prose``     — natural-language phrases; a keyword or semantic filter
      can target these.
    * ``structural`` — literal control markers, template tokens and output
      payloads; these need literal matching, output escaping or tokenizer
      hygiene, not a phrase filter.
    * ``notation``  — catalogs of codepoints and probe vocabulary; test
      inputs, not attack strings.
    """
    for cat in manifest()["categories"]:
        if category is not None and cat["id"] != category:
            continue
        cat_owasp = cat.get("owasp")
        for f in cat["files"]:
            if file is not None and f["path"] != file:
                continue
            if klass is not None and f.get("class", "prose") != klass:
                continue
            path = _ROOT / f["path"]
            meta = _load_meta(path)
            file_owasp = f.get("owasp", cat_owasp)
            for text in _read_lines(path):
                m = meta.get(text, {})
                entry_tags = _as_tuple(m.get("tags"))
                if tag is not None and tag not in entry_tags:
                    continue
                entry_owasp = m.get("owasp", file_owasp)
                if owasp is not None and entry_owasp != owasp:
                    continue
                yield Entry(
                    text=text,
                    category=cat["id"],
                    file=f["path"],
                    title=f["title"],
                    tags=entry_tags,
                    owasp=entry_owasp,
                    refs=_as_tuple(m.get("refs")),
                    scannable=bool(f.get("scan", True)),
                    klass=f.get("class", "prose"),
                )


def phrases(
    category: Optional[str] = None,
    tag: Optional[str] = None,
    owasp: Optional[str] = None,
    klass: Optional[str] = None,
) -> List[str]:
    """Return just the phrase strings, optionally filtered."""
    return [e.text for e in load(category, tag=tag, owasp=owasp, klass=klass)]


def categories() -> List[str]:
    """Return the list of category ids."""
    return [c["id"] for c in manifest()["categories"]]


def files() -> List[str]:
    """Return the list of corpus file paths, in manifest order."""
    return [f["path"] for c in manifest()["categories"] for f in c["files"]]


def tags() -> List[str]:
    """Return every tag used anywhere in the corpus, sorted."""
    out = set()
    for e in load():
        out.update(e.tags)
    return sorted(out)


def classes() -> List[str]:
    """Return the attack shapes present in the corpus.

    ``prose`` (phrases), ``structural`` (literal markers / payloads) and
    ``notation`` (codepoint catalogs). A keyword filter and a structural
    defense are two different jobs — the split keeps them honest.
    """
    out = set()
    for c in manifest()["categories"]:
        for f in c["files"]:
            out.add(f.get("class", "prose"))
    return sorted(out)


def stats() -> dict:
    """Return ``{category_id: phrase_count}`` plus a ``total``."""
    counts = {}
    for e in load():
        counts[e.category] = counts.get(e.category, 0) + 1
    counts["total"] = sum(counts.values())
    return counts


def unique_phrases() -> List[str]:
    """Return the corpus phrases with duplicates removed (order preserved)."""
    seen = set()
    out = []
    for e in load():
        if e.text in seen:
            continue
        seen.add(e.text)
        out.append(e.text)
    return out


# --- scanning ---------------------------------------------------------------

#: Phrases shorter than this are ignored by :func:`scan` — a two-character
#: "pattern" matches almost any text and turns a scan into noise.
DEFAULT_MIN_MATCH = 4


def _needle_forms(text: str) -> List[str]:
    """Canonical forms of a corpus phrase worth matching against.

    Unlike the input side, a *leading* punctuation marker is kept: dropping
    it would turn "### Instruction:" into "instruction" and match every
    English sentence that contains the word. Interior punctuation
    ("ignore.all.previous.instructions") is still folded away.
    """
    base = normalize(text)
    forms = [base]
    stripped = base.strip()
    if stripped and stripped[0].isalnum():
        depunct = depunctuate(base)
        if depunct and depunct != base:
            forms.append(depunct)
    tight = base.replace(" ", "")
    if len(tight) >= 6 and tight != base:
        forms.append(tight)
    seen = set()
    return [f for f in forms if f and not (f in seen or seen.add(f))]


def scan(
    text: str,
    categories: Optional[Sequence[str]] = None,
    tags: Optional[Sequence[str]] = None,
    min_length: int = DEFAULT_MIN_MATCH,
    include_unscannable: bool = False,
) -> List[Match]:
    """Scan ``text`` for known promptwl patterns.

    The text is canonicalized first (NFKC → strip invisible → confusable-fold
    → casefold → collapse whitespace), so an attack hidden behind Cyrillic
    look-alikes, zero-width joiners or fullwidth forms still matches. Punctuation
    and spacing variants are tried too.

    A phrase that appears in more than one file is reported once (the first
    file in manifest order). Files marked ``"scan": false`` in the manifest —
    seed word lists and probe fixtures that are not attack phrases — are
    skipped unless ``include_unscannable=True``.

    Returns a list of :class:`Match` objects, one per matched corpus phrase.
    An empty list means "no known pattern matched" — **not** "the input is
    safe". This is a recall-oriented baseline over a pattern corpus; it cannot
    see novel attacks, semantic framing, or anything your own classifier would
    catch better.
    """
    if not text:
        return []

    haystacks = variants(text)
    if not haystacks:
        return []

    wanted_cats = set(categories) if categories else None
    wanted_tags = set(tags) if tags else None

    matches: List[Match] = []
    seen_texts = set()
    for entry in load():
        if not entry.scannable and not include_unscannable:
            continue
        if wanted_cats is not None and entry.category not in wanted_cats:
            continue
        if wanted_tags is not None and not (wanted_tags & set(entry.tags)):
            continue
        if entry.text in seen_texts:
            continue
        for needle in _needle_forms(entry.text):
            if len(needle) < min_length:
                continue
            for hay in haystacks:
                idx = hay.find(needle)
                if idx != -1:
                    matches.append(Match(entry=entry, span=(idx, idx + len(needle)), needle=needle))
                    seen_texts.add(entry.text)
                    break
            else:
                continue
            break
    return matches


def detect(text: str, **kwargs) -> bool:
    """``True`` when :func:`scan` finds at least one known pattern."""
    return bool(scan(text, **kwargs))


# --- export -----------------------------------------------------------------

_EXPORT_FORMATS = ("jsonl", "json", "csv", "txt", "garak")


def export(
    fmt: str = "jsonl",
    path: Optional[Path] = None,
    category: Optional[str] = None,
    tag: Optional[str] = None,
    owasp: Optional[str] = None,
) -> str:
    """Export the corpus in a format other tools can consume.

    * ``jsonl`` — one JSON object per phrase (the default; what most
      red-team harnesses ingest).
    * ``json``  — a single JSON array.
    * ``csv``   — ``text,category,file,title,tags,owasp,refs``.
    * ``txt``   — one phrase per line, same shape as the corpus files.
    * ``garak`` — one prompt per line, ``<|endoftext|>`` separated, which is
      the shape garak's ``prompt`` resources expect.

    When ``path`` is given the output is also written there (UTF-8, LF).
    """
    if fmt not in _EXPORT_FORMATS:
        raise ValueError(f"unknown export format {fmt!r}; pick one of {_EXPORT_FORMATS}")
    entries = list(load(category, tag=tag, owasp=owasp))

    if fmt == "jsonl":
        out = "\n".join(
            json.dumps(
                {
                    "text": e.text,
                    "category": e.category,
                    "file": e.file,
                    "title": e.title,
                    "tags": list(e.tags),
                    "owasp": e.owasp,
                    "refs": list(e.refs),
                },
                ensure_ascii=False,
            )
            for e in entries
        )
    elif fmt == "json":
        out = json.dumps(
            [
                {
                    "text": e.text,
                    "category": e.category,
                    "file": e.file,
                    "title": e.title,
                    "tags": list(e.tags),
                    "owasp": e.owasp,
                    "refs": list(e.refs),
                }
                for e in entries
            ],
            ensure_ascii=False,
            indent=2,
        )
    elif fmt == "csv":
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["text", "category", "file", "title", "tags", "owasp", "refs"])
        for e in entries:
            writer.writerow(
                [e.text, e.category, e.file, e.title, ";".join(e.tags), e.owasp or "", ";".join(e.refs)]
            )
        out = buf.getvalue().rstrip("\n")
    elif fmt == "txt":
        out = "\n".join(e.text for e in entries)
    else:  # garak
        out = "\n".join(f"{e.text}<|endoftext|>" for e in entries)

    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(out + "\n", encoding="utf-8")
    return out
