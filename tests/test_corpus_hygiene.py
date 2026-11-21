"""Corpus hygiene tests — the rules CONTRIBUTING.md asks contributors to follow.

These are the checks that keep the corpus trustworthy: every file registered,
every file documented, and no accidental invisible codepoints hiding in a
phrase file (F-006).
"""

import sys
import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import promptwl  # noqa: E402

#: Files that legitimately store codepoints or notation rather than plain prose.
NOTATION_OK = {
    "wordlists/evasion/invisible-characters.txt",
    "wordlists/tokens/control-and-artifact.txt",
    "wordlists/tokens/boundary/separators.txt",
    "wordlists/tokens/fragmentation/base-words.txt",
}


def _is_invisible(ch: str) -> bool:
    if ch in "\t\n\r":
        return False
    if unicodedata.category(ch) in ("Cf", "Cc"):
        return True
    return 0xE0000 <= ord(ch) <= 0xE007F


class TestCorpusHygiene(unittest.TestCase):
    def test_every_manifest_file_exists(self):
        for path in promptwl.files():
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), f"{path} is registered but missing")

    def test_no_orphaned_corpus_files(self):
        registered = set(promptwl.files())
        on_disk = {
            str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / "wordlists").rglob("*.txt")
        }
        self.assertEqual(on_disk - registered, set(), "corpus files not registered in manifest.json")

    def test_files_have_a_documented_header(self):
        for path in promptwl.files():
            with self.subTest(path=path):
                header = []
                for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
                    s = line.strip()
                    if not s:
                        if header:
                            break
                        continue
                    if not s.startswith("#"):
                        break
                    header.append(s.lower())
                block = "\n".join(header)
                for key in ("category:", "purpose:", "use:", "source-level:"):
                    self.assertIn(key, block, f"{path} header is missing '# {key}'")

    def test_no_literal_invisible_characters_in_phrase_files(self):
        for path in promptwl.files():
            if path in NOTATION_OK:
                continue
            with self.subTest(path=path):
                text = (ROOT / path).read_text(encoding="utf-8")
                bad = {ch for ch in text if _is_invisible(ch)}
                self.assertFalse(
                    bad,
                    f"{path} contains literal invisible codepoints "
                    f"{[hex(ord(c)) for c in bad]} — use 'U+NNNN NAME' notation",
                )

    def test_no_duplicate_phrases_within_a_file(self):
        for path in promptwl.files():
            with self.subTest(path=path):
                texts = [e.text for e in promptwl.load(file=path)]
                self.assertEqual(len(texts), len(set(texts)), f"{path} repeats a phrase")

    def test_manifest_paths_are_unique(self):
        paths = promptwl.files()
        self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
