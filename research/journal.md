# Parrot's Research Journal 🦜

> A running log of what breaks language models and — more importantly — what
> stops it. Kept by **Parrot**, focused on prompt engineering and injection.

**Scope & rules of this journal**

- **Defensive.** Every entry documents an attack *class*, its *mechanism*, and
  the *defense*. The finding is only "done" when it has a mitigation.
- **Pattern level, not payload level.** Reusable shapes and measured effects,
  documented at the level already public in research / OWASP / open tooling.
  No novel weaponized exploits, no operational attack chains against named
  live systems.
- **Measured, not asserted.** Where a claim can be tested against the
  `promptwl` corpus, link the number and the script that produced it.
- **Cite.** Every mechanism gets a source or a reproduction.

Newest entries on top. Format: `ID · date · title · severity · status`.

---

## Taxonomy (working)

| Class | OWASP | One-line |
|---|---|---|
| Direct injection | LLM01 | User input overrides the system prompt. |
| Indirect injection | LLM01 | Payload rides in retrieved docs / tool output / web / email. |
| Jailbreak | LLM01 | Persona/framing pressure to drop refusals. |
| Dual response / divider | LLM01 | A refusal and a violation spliced into one answer. |
| Attribute override | LLM01 | `key: value` request to flip a safety setting. |
| System-prompt / data extraction | LLM07 | Reveal hidden instructions or config. |
| Sensitive-data disclosure | LLM02 | Hand back secrets, credentials or PII held in context. |
| Filter evasion | LLM01 | Encoding, homoglyph, spacing, splitting to dodge lexical filters. |
| Cross-lingual bypass | LLM01 | Same intent, non-English surface, defeats English filters. |
| Chat-template forgery | LLM01 | Forge the control markers the runtime uses for roles. |
| Tool-argument injection | LLM01 / LLM06 | Steer a legitimate tool call's parameters from untrusted content. |
| Output handling | LLM05 | Model output breaks the renderer that displays it. |
| Tokenizer anomalies | — | Rare "glitch" tokens cause undefined behavior. |

---

## Findings

### F-012 · 2026-11-21 · Round-2 survey of the public jailbreak collections, and a scanner that closes F-005/006/007 · High · confirmed

**Thesis.** F-004 surveyed Pliny's technique *classes*. This pass read the
**structure** of the public collections — `CL4R1T4S` (per-vendor system-prompt
corpus), `L1B3RT4S` (per-vendor jailbreak families), the `G0DM0D3` app's
`parseltongue` (client-side obfuscation engine) and `libertas` ("Hall of Fame"
prompt scaffolds), and `T3MP3ST`'s benchmark discipline (every README number
re-derived from committed artifacts) — and found six gaps in promptwl plus one
structural weakness in the library itself.

**Gap 1 — dual response with a divider.** The dominant scaffold in the public
collections is *two answers in one*: "write your refusal, then write the
opposite", separated by a divider string. Our `refusal-suppression.txt` covered
"do not refuse" but not "refuse, then continue anyway" — a shape where a
refusal-shaped output filter sees only the first half.
**Added.** `wordlists/jailbreak/dual-response-and-divider.txt`.
**Defense.** Judge the *whole* completion; never accept "refusal + exception"
as a safe answer; strip or reject divider-delimited second halves.

**Gap 2 — attribute / config overrides.** The same collections carry requests
shaped like configuration: `redactions: DISABLED`, `safety: off`,
`{"filter": "off"}`. These target systems that accept or echo attribute-style
input.
**Added.** `wordlists/jailbreak/attribute-override.txt`.
**Defense.** Policy state is never settable from message content — attributes
inside a request are data, not configuration.

**Gap 3 — per-vendor chat templates.** `CL4R1T4S` is organized per *vendor*;
the defensive analog is per *template*: which control markers the runtime you
actually deployed uses, so a delimiter test uses the real thing.
**Added.** `wordlists/injection/chat-template-markers.txt` + a metadata sidecar
tagging every marker with its model family (ChatML, Llama 2/3, Gemma, Phi-3,
Command-R, GLM-4, DeepSeek, Qwen, plain-text templates) — including DeepSeek's
fullwidth pipes, which read as ASCII and are not.

**Gap 4 — tool-argument injection.** The backlog item "tool-call argument
injection" (untrusted content steering the *arguments* of a legitimate call —
a different URL, a different recipient) had no corpus file.
**Added.** `wordlists/agents/tool-argument-injection.txt`.
**Defense.** Validate every tool argument against the user's actual request;
content that arrived *inside* a tool result must never decide what the *next*
call does.

**Gap 5 — sensitive-data disclosure (LLM02).** Our extraction category was
LLM07-only (system-prompt leak). LLM02 — secrets, credentials, PII and other
context the *application* put into the prompt — was uncovered.
**Added.** `wordlists/extraction/sensitive-data-disclosure.txt` (LLM02).

**Gap 6 — the corpus was input-only.** Every class we tracked defended the
*input* side. The output side (LLM05, improper output handling) was missing
entirely: a model that returns a perfectly safe sentence containing
`<img src=x onerror=...>` hands the payload to whatever renders it.
**Added.** New category `output/` (LLM05) with
`wordlists/output/markdown-and-html-injection.txt` — generic payloads
(`alert(1)`, `example.invalid`), no live target.
**Defense.** Treat model output as untrusted input for the *next* system:
escape on render, safe markdown renderer, strip `javascript:`/`data:` schemes.

**The structural weakness — a wordlist you can only load.** F-005/006/007
proved, one row at a time, that a keyword guardrail is blind to encodings,
invisible codepoints and confusables — but the fixes lived in `examples/`, and
the library shipped nothing but a loader. A defender had to re-implement the
canonicalization stack in every project. That is the gap this round closes:

- `promptwl/normalize.py` — the F-005/006/007 stack promoted into the
  package (NFKC → strip invisible → confusable-fold → casefold → collapse).
- `promptwl.scan(text)` — matches untrusted text against the corpus *after*
  canonicalizing it, so look-alikes, zero-width joiners, fullwidth forms and
  punctuation noise all land.
- `promptwl.load(tag=…, owasp=…, klass=…)` + per-file JSON metadata sidecars —
  the corpus stays greppable text and still carries structure.
- **Attack-shape classes** (`prose` / `structural` / `notation`) — a keyword
  filter and a structural defense are different jobs; splitting them keeps the
  recall numbers honest as the corpus grows.
- `promptwl.export()` (JSONL/JSON/CSV/TXT/garak) — the corpus now drops into
  other harnesses instead of being re-typed into them.
- `scripts/verify_claims.py` + `bench/claims.json` — every published number
  re-derives from the corpus, the T3MP3ST discipline applied to a README.
- `tests/` — 32 stdlib tests: loader, filters, metadata, normalizer, scanner,
  exporter, and corpus hygiene (orphans, headers, invisibles, duplicates).

**Measured.** `scripts/validate.py`: **835 phrases** (825 unique), 9
categories, 37 files. `examples/recall_demo.py`: the naive English keyword
filter scores **26%** on English prose attacks, **0%** on the same attacks
translated, and **~1%** on structural classes. `examples/ensemble_demo.py`:
iterative decode + normalize recovers **100%** of the phrases the filter
catches in the clear, while unknown-shift Caesar stays **0%**.
`examples/scan_demo.py`: one attack in five disguises — the naive filter
catches **1/5**, `promptwl.scan()` catches **5/5**, with **0/14** benign
requests flagged.

**Two measurement bugs found and fixed while doing this.** (1) The corpus grew
from 694 to 835 phrases, and the demos' denominators had been "all phrases" —
so adding *new kinds* of attack silently lowered a "recall" number that was
really measuring corpus composition. The demos now score the prose subset, and
the ensemble matrix scores the phrases the filter catches in the clear.
(2) `promptwl.scan()` reported false positives on benign text: folding the
*corpus* side turned the look-alike test vector `ignоrе` into the ordinary
word "ignore", and stripping punctuation turned `### Instruction:` into
"instruction". Fixes: look-alike and chain-name catalogs are no longer
scanned, and the punctuation-free form is only used when the phrase's
punctuation is interior.

**Mitigation.** New classes → defenses above. Detection gaps → the library
stack. Measurement gaps → `verify_claims.py` in CI.

**Sources.**
[CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) ·
[L1B3RT4S](https://github.com/elder-plinius/L1B3RT4S) ·
[G0DM0D3](https://github.com/elder-plinius/G0DM0D3) (`src/lib/parseltongue.ts`,
`src/lib/libertas.ts`) ·
[T3MP3ST](https://github.com/elder-plinius/T3MP3ST) (`bench/README.md`) ·
OWASP LLM Top 10 (LLM01/02/05) · arXiv:2501.18837 (Constitutional Classifiers)

---

### F-011 · 2026-08-20 · Unicode confusables + encoding-chain catalog · High · confirmed

**Thesis.** Two gaps remain in the tokens/ section after F-010: (1) the
confusable-character surface (chars that look like ASCII but aren't) and (2)
the encoding-chain depth catalog (how many decode layers are needed to see the
payload). Both are needed to characterize the full evasion envelope and to tell
defenders where enumerate-and-invert stops working.

**Added (0.3.1).**
- `wordlists/tokens/unicode-confusables.txt` — UTS-39 confusable pair table
  (Cyrillic, Greek, fullwidth Latin, mathematical styled Latin → ASCII skeleton)
  plus confusable-substituted attack keywords as live test inputs.
- `wordlists/tokens/encoding-chains.txt` — chain descriptor catalog from
  Tier 1 (single transform) through Tier 4 (chain with unknown-shift residual),
  anchoring the test harness to stable seed phrases.
- `wordlists/tokens/anomalous-tokens.txt` expanded: GPT-4/o200k_base community
  outliers (2024), Llama SentencePiece special tokens, Mistral role delimiters,
  model-card special tokens across major open families, BPE residue subwords,
  and null/DEL C0 glitch entries.

**Measured.** `scripts/validate.py` after update: **694 phrases** (up from 539).
Token category: 343 phrases (up from 188). Corpus grew 29% in one session.

**Key finding — confusable depth.** A Cyrillic substitution (а=U+0430 for
a=U+0061) evades any ASCII-normalized filter that doesn't apply NFKC +
confusable-fold. The UTS-39 fold (implemented in `confusable_fold()`) closes
the known substitution set; novel Unicode blocks added in future Unicode
releases reopen it until the fold table is updated.

**Key finding — chain depth ceiling.** Known single- and two-layer chains are
fully recoverable by the breadth-first decode pass in `ensemble_demo.py`. At
depth 3 the combinatorial branching cost exceeds a linear scan; at Tier 4
(unknown shift) recall drops to 0% for keyword filters and 0% for the decode
pass. Documented residuals: caesar with unknown shift, arbitrary substitution
cipher, novel non-ASCII alphabets.

**Mitigation.**
- Confusables → UTS-39 confusable-fold before filtering.
- Encoding chains → breadth-first decode to max depth=3, then semantic
  classifier (perplexity or intent model) for the residual.
- Anomalous tokens → normalize and strip special-token strings before the model
  sees them; treat boundary-escaped tokens as suspicious input.

**References.** Unicode Consortium UTS-39 (confusables.txt); arXiv:2411.01084
(string-composition attacks); garak evasion probe suite; community glitch-token
archaeology threads (LessWrong, 2023-2024).

---

### F-010 · 2026-08-20 · Token-anomaly corpus & cross-tokenizer probe · High · confirmed

**Thesis.** A Unicode-attack list is only half the story and duplicates garak's
`badchars` probe. The differentiator is measuring **what happens at the
tokenizer level** — so `tokens/` gains `fragmentation/` (base words) and
`boundary/` (separator codepoints), plus a probe that segments each variant
across tokenizers. Complementary to garak (filter-side), not a clone.

**Measured (tiktoken cl100k_base & o200k_base).**
- `"password"` = **1 token**. Insert an invisible **zero-width space** →
  **3 tokens**. The tokenizer places a boundary the reviewer cannot see.
- A **combining mark** raises codepoint/byte counts but *not* the grapheme
  count (it rides the base char) — yet still splits the word into 2 tokens.
- Every split point and exotic separator (NBSP, thin space, …) changes the
  segmentation vs. the clean word.

**Why it matters.** Guardrails and classifiers usually run on raw input, then
the model tokenizes something *different*. If the filter sees `password` (1
unit) but the tokenizer sees `pass | <ZWSP> | word` (3), a blocklist keyed on the
whole word never fires — the invisible char created a boundary mid-word.

**Defense.** Canonicalize on the **same view the model will tokenize**:
normalize (NFKC) + strip boundary/zero-width/format chars (F-006/F-007/F-009)
*before* both filtering and tokenizing, so filter-input and tokenizer-input
agree. Test with the probe across the tokenizers you actually deploy.

**Design notes.** Zero-dependency core (stdlib byte/codepoint/grapheme
analyzers always run); `tiktoken`/`transformers` adapters auto-activate only if
importable, preserving the repo's install-free promise. Variants are generated
at runtime and boundary chars stored as `U+NNNN NAME`, so no invisible bytes
touch disk — tree scans clean under F-006.

**Evidence.** `examples/tokenizer_probe.py`,
`wordlists/tokens/fragmentation/base-words.txt`,
`wordlists/tokens/boundary/separators.txt`. Method inspired by NVIDIA garak
glitch/badchars probes; the cross-tokenizer measurement is the value-add.

**Backlog (deferred by decision).** `unicode/`, `encoding/`, `glitch/`
subcategory reorg + a `subcategory` manifest field — not done this pass; the
fragmentation/boundary probe was the higher-signal first step.

---

### F-009 · 2026-08-20 · Control chars, bidi overrides & the tokens expansion · Medium · confirmed

**What.** Corpus 0.2.1 expands `tokens/` to 147 entries: the fuller public
SolidGoldMagikarp catalog plus a new `control-and-artifact.txt` (C0/C1 control
chars, bidirectional-format overrides, BPE mojibake residue, CJK fragments).
Two of these are their own defensive classes, not just tokenizer trivia.

**Mechanism.**
- *Bidi overrides (U+202A–U+202E, U+200E/F).* The **Trojan Source** class
  (Boucher & Anderson, 2021): RLO/LRO reorder how a line *renders* while the
  byte order the compiler/model consumes is unchanged — source (or a prompt)
  reads one way to a human and executes another. Adjacent to F-006: invisible
  structure, but here it *reorders* visible text rather than hiding it.
- *C0/C1 control characters.* Rarely appear in natural text; can break naive
  parsers, terminate strings early, or land as under-trained token IDs.
- *Under-trained / glitch tokens.* Embedding-space outliers → non-determinism
  at temp 0, refusal-to-repeat, garbled decoding on models sharing the vocab.

**Defense.**
1. At ingestion, **reject or strip** bidi-format codepoints (U+202A–E, U+200E/F)
   and C0/C1 controls except ordinary whitespace — same egress/ingress hygiene
   as F-006; extend the `invisible.py` scanner's category set to cover them.
2. Render untrusted text with bidi isolation, or display escaped, so human
   review sees true order (Trojan Source mitigation).
3. Treat glitch tokens as an input-stability *test*, not a filter: assert your
   tokenizer/embeddings handle them without NaNs or nondeterminism.

**Storage note.** Non-printable entries are stored as `\xNN` / `U+NNNN NAME`
notation, never literal bytes — the file scans clean under F-006 while staying
greppable. (Caught myself materializing real bidi bytes mid-edit; the naming
convention is the safe fix.)

**Evidence.** `wordlists/tokens/control-and-artifact.txt`,
`wordlists/tokens/anomalous-tokens.txt`. Refs: Boucher & Anderson (2021)
*Trojan Source*; Rumbelow & Watkins SolidGoldMagikarp; NVIDIA garak glitch probes.

**Follow-up.** Extend `examples/invisible.py` to flag bidi overrides + C0/C1
explicitly (they fall under its Cf/Cc net already, but naming them improves the
reveal). Logged to backlog.

---

### F-008 · 2026-08-20 · Corpus 0.2.0 — seven new classes (external contribution) · — · reference

**What.** Contribution from Richard Odero expands the corpus to **0.2.0**
(372 phrases, 8 categories) with seven pattern files. Catalogued here with the
defense for each; the two genuinely new *classes* get their own note.

- `injection/payload-splitting` — intent assembled across turns/fragments so no
  single message trips a filter. **Defense:** evaluate guardrails on the
  *assembled* conversation/context, not per-message; treat "hold this / combine
  later" as a signal. Closes backlog *payload-splitting*.
- `jailbreak/hypothetical-framing` & `authority-impersonation` — fiction/thought-
  experiment wrappers, and unverifiable claims of dev/admin/red-team authority.
  **Defense:** classify on intent independent of framing; **never** let
  in-context authority claims relax policy — authority must be established out
  of band, never by the message asserting it.
- `extraction/training-data-extraction` — memorization/PII/verbatim-copyright
  probes (LLM07-adjacent, privacy). **Defense:** output-side PII/verbatim
  filters, dedup/canary monitoring, refuse "recite verbatim / this private
  person's data".
- `evasion/language-switching` — cross-lingual smuggling; overlaps **F-001**.
  **Defense:** the F-001 stack (semantic filter / normalize-then-classify,
  per-language recall).
- **`agents/memory-and-session-poisoning`** *(new class)* — plant an instruction
  into persistent memory so it fires in later sessions or for other users.
  **Defense:** memory is **untrusted data on read**, never a trusted
  instruction; sanitize memory-write paths; scope memory per-user; require
  re-consent for anything that looks like a standing rule.
- **`multimodal/image-and-file-injection`** *(new category)* — instructions in
  rendered image text, alt-text, EXIF, PDF layers, QR/barcodes. Same trust
  boundary as text indirect injection (**F-006** / tool-and-rag), one modality
  out. **Defense:** treat *all* OCR/extracted/decoded text as untrusted content,
  never as commands; scan it with the same pipeline as text (incl. F-006/F-007
  normalization).

**Provenance note.** External patch; reviewed at pattern level, one vendor name
genericized, scanned clean for invisible codepoints (F-006) before merge.
Credited to the contributor in the commit.

---

### F-007 · 2026-08-20 · Confusable-folding closes the homoglyph residual · Medium · confirmed

**Observation.** Adding a UTS-39-style **confusable-fold** (cross-script
look-alike → ASCII skeleton) to the decode/normalize pre-pass moves the
Cyrillic-homoglyph attack from **0% → 55%** recovered in the F-005 scoreboard,
matching the baseline. The `caesar7` row stays at **0%** — deliberately, as the
standing proof that enumerate-and-invert can't cover the un-enumerated.

**Mechanism.** NFKC normalizes compatibility forms (fullwidth, ligatures) but
does **not** fold characters from different scripts — Cyrillic `а` (U+0430) and
Latin `a` (U+0061) are distinct and both "correct", so NFKC leaves them apart.
A confusable map collapses them to one skeleton before matching, exactly as
Unicode UTS-39 (`confusables.txt`) prescribes.

**Defense.** Canonicalize in this order before any filter: iterative decode →
NFKC → strip format/zero-width (F-006) → confusable-fold → semantic classifier
for the rest. The fold here is a curated subset; production should load the
full UTS-39 table.

**Caveat.** Confusable-folding is for *detection/matching*, not for rewriting
user-visible content — folding display text breaks legitimate non-Latin input.
Fold a copy, match on it, keep the original.

**Evidence.** `examples/string_transforms.py` (`confusable_fold`),
`examples/ensemble_demo.py` (homoglyph row now 55%). Closes the F-005 residual.

---

### F-006 · 2026-08-20 · ASCII smuggling / invisible prompt injection · High · confirmed

**Observation.** A message can travel as *invisible structure* rather than
visible text, rendering as nothing yet remaining fully decodable. Two vehicles:
zero-width characters (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WORD JOINER
U+2060, ZWNBSP/BOM U+FEFF, SOFT HYPHEN U+00AD) used as a **bit alphabet** over
the payload's UTF-8 bits; and the **Unicode Tags block** (U+E0000–U+E007F), a
near-1:1 invisible mirror of ASCII. `grep "admin"` returns zero hits — the
message is present as codepoints, not letters. Demo: a `"lgtm, minor cleanup"`
commit carrying 28 invisible Tag codepoints that decode to a hidden
instruction; `"ok"` carrying 96 zero-width bits that decode to a second string.

**Mechanism.**
- *Invisible prompt injection.* An agent that ingests the raw bytes gets those
  codepoints in its context; if the model attends to them as content, it acts
  on text no human reviewer can see — the diff looks clean.
- *The two-location footprint.* The agent can re-emit an invisible payload into
  its own trace (commit message, PR comment, log). One payload lives in the
  ingested `.md`; a second in the emitted footprint. The joined sentence never
  exists as a string anywhere — you assemble it only by decoding both blobs.
  Encoding is not plaintext concatenation; each blob stands alone, which is why
  full-text search over any single artifact finds nothing.

**Defense (both directions — egress matters as much as ingress).**
1. **Ingestion:** scan every untrusted file/message for zero-width + Tags +
   other Cf/Cc format codepoints; strip or reject before the text reaches the
   model. Never let invisible codepoints into context.
2. **Egress:** sanitize everything the agent emits (commits, PR comments, tool
   args, logs). This closes the footprint/exfiltration channel — the half most
   pipelines forget.
3. **Review:** surface a decode of any hidden content (`reveal_tags`,
   `reveal_zero_width_bits`) so a human sees what was smuggled.
4. **Allowlist scripts/ranges** you actually expect; treat Plane-14 tags and
   stray format chars as hostile by default.

**Evidence.** `examples/invisible.py` (scan / reveal / sanitize),
`examples/invisible_demo.py`. Public documentation: Riley Goodside; Johann
Rehberger / *Embrace The Red* (ASCII smuggling in LLM apps); the Unicode Tags
prompt-injection writeups.

**Note for this repo.** Parrot sanitizes its own egress — no commit message, PR
comment, or output here carries invisible codepoints. The scanner is the
deliverable; the smuggling encoders in `invisible.py` are test fixtures only.

---

### F-005 · 2026-08-20 · String-composition attacks vs. a decode-defense · High · confirmed

**Observation.** Obfuscating the 99 English injection/jailbreak/extraction
phrases drops the naive keyword filter from **55% → 0%** for *every* encoding
tried (leetspeak, Base64, ROT13, reversal, and chains). A decode + NFKC-
normalize pre-pass **fully recovers to 55%** for the transforms it enumerates —
but stays at **0%** for a Caesar-7 shift (it only knows ROT13) and for Cyrillic
homoglyphs (visually identical, not folded by NFKC). Tests the F-004 /
arXiv:2411.01084 mechanism against a concrete defense.

**Mechanism.** Reversible transforms preserve intent while destroying the
surface tokens a lexical filter matches. A defense built by *enumerating and
inverting* known encodings only covers what's on the list; NFKC does not fold
cross-script confusables, and an arbitrary Caesar shift is not ROT13.

**Defense (layered — no single one suffices).**
1. Iterative decode + Unicode-normalize (NFKC, strip zero-width, collapse
   spacing) as a pre-pass, re-scanning every intermediate form. *Necessary,
   fully closes known encodings.*
2. **Unicode confusable folding** (map to a skeleton, e.g. UTS-39) to close the
   homoglyph residual NFKC leaves open.
3. A **semantic / model-based** classifier for transforms you never enumerated
   (the Caesar-7 case) — you cannot invert what you didn't anticipate.
4. Defense in depth: assume some obfuscation reaches the model; add output-side
   checks too.

**Evidence.** `examples/ensemble_demo.py`, `examples/string_transforms.py`.
Closes backlog **B-string-ensemble**.

---

### F-004 · 2026-08-20 · Technique survey: Pliny the Liberator (Elder Plinius) · — · reference

**Who.** *Pliny the Liberator* / *Elder Plinius* (`@elder_plinius`,
[pliny.gg](https://pliny.gg/)) — the most prolific public LLM jailbreaker,
known for jailbreaking frontier models within hours of release and for the
open `L1B3RT4S` prompt collection. Studied here as a **defender's literature
review**: we catalog his *technique classes and their countermeasures*, not
his payloads (payloads are out of scope for this journal — see the masthead).

**Technique classes he's associated with, and the defense for each:**

1. **Universal / "skeleton-key" jailbreaks** — a single framing that
   generalizes across models and harm categories.
   *Defense:* don't rely on input matching; add an independent output-side
   classifier and defense-in-depth. See Anthropic's *Constitutional
   Classifiers* (arXiv:2501.18837) — classifiers trained on synthetic
   variants, evaluated over thousands of red-team hours.

2. **String-composition / encoding chains** — leetspeak, Base64, ROT13,
   reversal, translation, Morse, *chained together* (e.g. translate → leet →
   morse). Compounding transforms beat single-encoding filters and any one
   normalizer; ensembling 20+ transforms sharply raises success
   (arXiv:2411.01084). Directly generalizes our **F-002**.
   *Defense:* iteratively decode + NFKC-normalize until stable, then run a
   *semantic* classifier on the normalized form; treat "decode this" framing
   as a signal, not an instruction; test with a transform ensemble.

3. **Formatting / "divider" reframing** ("the Pliny divider" style) — visual
   or structural separators that make an injected block read as a new,
   authoritative turn.
   *Defense:* never trust in-band formatting as a trust boundary; separate
   roles structurally (API message roles), strip control markup from
   untrusted spans. Generalizes **F-003**.

4. **Persona / "liberation" role-play templates** (the `L1B3RT4S` /
   Libertas family) — fictional or "unlocked" personas used to suppress
   refusals.
   *Defense:* classify on *intent*, independent of narrative framing; refusal
   behavior must survive "it's just fiction / role-play" reframes. See
   `wordlists/jailbreak/`.

5. **Day-one jailbreaks of new releases** — community red-teamers break new
   models within hours.
   *Defense (process, not prompt):* adversarial testing *before* launch;
   continuous post-launch monitoring; a fast patch/rollback loop; assume
   novel bypasses exist and design for graceful failure, not perfect
   prevention.

6. **System-prompt leaks + prompt injection** — cited by him as core skills.
   Covered by our `extraction/` and `injection/` categories.

**Takeaway for promptwl.** His public corpus is *payloads*; our value-add is
the **inverse** — the mechanism → defense mapping and a measurable test set.
Backlog items B-string-ensemble and B-persona-translation below come directly
from this survey.

**Sources.**
[pliny.gg](https://pliny.gg/) ·
[Latent.Space interview](https://www.latent.space/p/jailbreaking-agi-pliny-the-liberator) ·
[VentureBeat interview](https://venturebeat.com/ai/an-interview-with-the-most-prolific-jailbreaker-of-chatgpt-and-other-leading-llms) ·
[Decrypt: day-one jailbreaks](https://decrypt.co/333858/openai-jailbreak-proof-new-models-hacked) ·
arXiv:2411.01084 (String Compositions) · arXiv:2501.18837 (Constitutional Classifiers)

---

### F-003 · 2026-08-20 · Delimiter / role-boundary spoofing · High · confirmed

**Observation.** Untrusted content that embeds chat-template control markers
(`<|im_start|>system`, `[INST]`, `<<SYS>>`, `### SYSTEM ###`, `"role":
"system"`) can impersonate a system/developer turn when naively concatenated
into the prompt.

**Mechanism.** Many stacks build the final prompt by string-joining system +
retrieved/user text. If the untrusted text contains the same delimiters the
runtime uses to mark trusted turns, the boundary between *trusted control* and
*untrusted data* dissolves.

**Defense.**
- Never concatenate untrusted text into the system frame. Pass user/retrieved
  content only through the API's structured message roles.
- Strip / escape control tokens from untrusted input before templating.
- Prefer models/templates where role boundaries aren't in-band text.

**Evidence.** `wordlists/injection/delimiter-confusion.txt`.

---

### F-002 · 2026-08-20 · Keyword filters are blind to non-lexical channels · High · confirmed

**Observation.** A representative English keyword/regex guardrail scores ~55%
recall on English injection/jailbreak/extraction phrasings but **0%** on:
encoding/obfuscation, indirect/agent injection, and anomalous tokens.

**Mechanism.** Lexical filters match surface strings. Base64 / rot13 /
homoglyphs / zero-width chars / spacing all preserve *intent* while destroying
the *surface tokens* the filter keys on. Indirect injection hides the intent
in content the filter never inspects (retrieved docs, tool output). Glitch
tokens aren't words at all.

**Defense.**
- Decode and Unicode-normalize (NFKC, strip zero-width, collapse spacing)
  *before* any filtering; re-scan the normalized form.
- Treat all retrieved/tool/web content as untrusted and scan it too, not just
  the user turn.
- Don't rely on lexical matching as the only layer — add a semantic/model-based
  classifier.

**Evidence.** `examples/recall_demo.py` → evasion/agents/tokens rows at 0%.

---

### F-001 · 2026-08-20 · Monolingual guardrail blind spot · High · confirmed

**Observation.** The same naive English filter that catches ~55% of canonical
injection/jailbreak/extraction attacks in English catches **~0%** when the
identical intent is written in Spanish, French, German, Portuguese, Italian,
Russian, Chinese, Arabic, Hindi, or Japanese.

**Mechanism.** Blocklists and most shipped input filters are English-only.
Translation keeps the semantic payload ("ignore all previous instructions")
but changes every surface token, so lexical rules never fire. The attacker
pays nothing — one `translate()` call — for a near-total bypass.

**Defense.**
- Filter on **semantics**, not surface strings: a multilingual classifier, or
  translate-to-English (or to a canonical form) *before* the guardrail.
- Measure recall **per language**, not in aggregate — an aggregate number
  hides a 0% language behind a strong English score.
- Assume any language your product accepts is an attack surface.

**Severity rationale.** Trivial to execute, near-universal applicability,
silent (no error, filter just passes it).

**Evidence.** `examples/recall_demo.py` → multilingual rows at 0%;
`wordlists/multilingual/`.

---

## Backlog — to investigate

- [x] **B-string-ensemble** — DONE → **F-005**. Encodings drop the filter to 0%;
      decode+normalize recovers known transforms fully.
- [x] **B-confusable-fold** — DONE → **F-007**. Confusable-folding lifts the
      homoglyph row 0% → 55%; caesar7 stays 0% as the standing semantic-layer
      residual.
- [ ] **B-persona-translation** — **Cross-lingual jailbreak transfer**: do persona
      "liberation" jailbreaks survive translation as well as plain injection does?
      (Hypothesis: yes, and low-resource languages fare worse for the defender.)
      From F-001 + F-004.
- [x] **Payload splitting** — catalogued in F-008 (`injection/payload-splitting`).
      Defense: evaluate on assembled context, not per-span. Still open as a
      *measured* experiment (does per-message filtering miss the assembled intent?).
- [x] **B-bidi-reveal** — DONE. `invisible.py` now names bidi overrides
      (`BIDI` table) and C0/C1 controls explicitly, adds `reveal_bidi()` (returns
      controls + logical order), and the demo gained a Trojan Source section [3]. From F-009.
- [x] **Tool-call argument injection** — DONE → **F-012**
      (`agents/tool-argument-injection.txt`). Defense: validate every tool
      argument against the user's request.
- [ ] **RAG poisoning persistence** — an injected instruction stored in a
      vector DB that fires on future, unrelated queries. (Related: memory/session
      poisoning now in F-008.)
- [x] **Multimodal injection** — catalogued in F-008 (`multimodal/`). Defense:
      treat OCR/extracted text as untrusted. Still open: an actual image→OCR→filter
      measurement.
- [ ] **Normalization gaps** — which Unicode confusable ranges survive NFKC
      and still read as ASCII to a human?
- [ ] **B-owasp-gap-audit** — map every OWASP LLM Top 10 (2025) id to a corpus
      file. Still uncovered: LLM03 supply chain (model-artifact backdoors),
      LLM04 data/model poisoning, LLM08 vector & embedding weaknesses,
      LLM09 misinformation, LLM10 unbounded consumption.
- [ ] **B-class-translation** — the classes added in F-012 (dual response,
      attribute override, tool-argument injection) exist only in English.
      Translating them into the 10 existing languages would extend F-001's
      per-language recall measurement to the new classes.
- [ ] **B-egress-measurement** — the `output/` corpus (LLM05) is a list of
      payloads; the missing half is the measurement: render a model answer
      through a markdown/HTML renderer and assert the payload is neutralized.
- [ ] **B-voice-surface** — no corpus coverage for voice/audio channels
      (transcript-borne injection, audio-over-text instruction smuggling).

---

*Journal opened 2026-08-20. Updated whenever new research lands.* 🦜
