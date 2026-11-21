# Roadmap — what to take from the public jailbreak collections 🦜

This is the survey behind **0.4.0**, written up so the next contributor doesn't
have to re-read the public collections to know what we already took, what we
chose *not* to take, and what is still open.

The reference points are the public repositories of **Pliny the Liberator**
(`@elder_plinius`) — `CL4R1T4S` (per-vendor system-prompt corpus), `L1B3RT4S`
(per-vendor jailbreak families), `G0DM0D3` (the chat app, including its
client-side `parseltongue` obfuscation engine and `libertas` prompt scaffolds),
`T3MP3ST` (the autonomous red-team harness, and its benchmark discipline),
`ST3GG` (the steganography suite — the text-side carrier channels),
`P4RS3LT0NGV3` (the text-mutation engine — anti-classifier and token-level
substitution), `V3R1T4S` (the "known unknowns" benchmark) and `AutoRedTeam`
(the automated defense tester).

**The rule this repo applies**: take *structure and technique classes*, never
payloads. The public collections are payloads; our value is the inverse — the
mechanism → defense mapping plus a corpus you can measure against. Everything
below is framed that way, and every new file says so in its header.

---

## 1. Taken in 0.4.0 (implemented)

| # | Inspired by | What we did | Where |
|---|---|---|---|
| 1 | `L1B3RT4S` / `G0DM0D3` "hall of fame" scaffolds | New class: **dual response with a divider** — a refusal and a violation spliced into one answer, so a refusal-shaped output filter only sees the first half. | `wordlists/jailbreak/dual-response-and-divider.txt` |
| 2 | `G0DM0D3` prompt scaffolds (`redactions: DISABLED`, `tone: rebel`) | New class: **attribute / config overrides** — requests shaped like configuration. | `wordlists/jailbreak/attribute-override.txt` |
| 3 | `CL4R1T4S` per-vendor organization | New file: **real chat-template control markers** (ChatML, Llama 2/3, Gemma, Phi-3, Command-R, GLM-4, DeepSeek, Qwen, plain-text templates), each tagged with its model family — so a delimiter test uses the template you actually deployed. | `wordlists/injection/chat-template-markers.txt` + `.meta.json` sidecar |
| 4 | `G0DM0D3` `parseltongue` (obfuscation applied client-side) | The canonicalization stack moved **into the library** (`promptwl/normalize.py`) and `promptwl.scan()` now matches untrusted text *after* canonicalizing it. The demos' fixes were never reusable; now they are. | `promptwl/normalize.py`, `promptwl.scan()` |
| 5 | `T3MP3ST` `bench/` discipline (every README number re-derived from committed artifacts) | `scripts/verify_claims.py` + `bench/claims.json`: every published number re-derives from the corpus and fails CI when it drifts. | `scripts/verify_claims.py` |
| 6 | `T3MP3ST` ground-truth samples | `tests/` — 32 stdlib tests over loader, filters, metadata, normalizer, scanner, exporter and corpus hygiene. | `tests/` |
| 7 | The corpus's own gap list (OWASP LLM02 / LLM05) | New class: **sensitive-data disclosure** (LLM02) and a whole new category: **output handling** (LLM05) — the corpus had been input-only. | `wordlists/extraction/sensitive-data-disclosure.txt`, `wordlists/output/` |
| 8 | The agent-tooling gap in our own backlog | New class: **tool-argument injection** — untrusted content steering the *arguments* of a legitimate tool call. | `wordlists/agents/tool-argument-injection.txt` |

## 1b. Taken in 0.5.0 (the adjacent tools, not the jailbreak collections)

The jailbreak collections were the obvious source. The *adjacent* tools were
the richer one — same author, different problem, same techniques.

| # | Inspired by | What we did | Where |
|---|---|---|---|
| 9 | `ST3GG` text-carrier examples | New class: **steganographic channels** — variation selectors, Hangul fillers, combining marks, Braille dot patterns, emoji modifiers, IDN/punycode domains. Plus a **detector**: `promptwl.carriers(text)`. | `wordlists/evasion/steganographic-channels.txt`, `promptwl.carriers()` |
| 10 | `P4RS3LT0NGV3` anti-classifier tool | New class: **classifier-evasion paraphrase** — keep the meaning, change the surface so the automated filter misses it. | `wordlists/evasion/classifier-evasion-paraphrase.txt` |
| 11 | `P4RS3LT0NGV3` gibberish / mutation / emoji / spelling-alphabet tools | New class: **token-level substitution** — phonetic respelling, invented words, emoji letters, affix padding. | `wordlists/evasion/token-level-substitution.txt` |
| 12 | `V3R1T4S` "known unknowns" | New category: **misinformation** (LLM09) — questions with no determinate answer, where the failure mode is confident fabrication. | `wordlists/misinformation/unknowable-probes.txt` |
| 13 | `ST3GG` / domain layer | **Punycode/IDN homograph** entries for the tool-argument class — a URL that renders as one domain and resolves to another. | `wordlists/agents/tool-argument-injection.txt` |
| 14 | `P4RS3LT0NGV3` transform catalog | Wider transform taxonomy for the encoding-chain catalog (base32/58/85, punycode, pig-latin, zalgo, braille, respell, affix padding, …). | `wordlists/tokens/encoding-chains.txt` |

Two measurement bugs were found and fixed while doing this, and they are worth
more than the files:

* The demos' denominators were "all phrases", so growing the corpus silently
  lowered a "recall" number that was really measuring corpus composition. The
  demos now score the **prose** subset, and the ensemble matrix scores the
  phrases the filter catches *in the clear*.
* `promptwl.scan()` reported false positives on benign text: folding the corpus
  side turned the look-alike vector `ignоrе` into the ordinary word "ignore",
  and stripping punctuation turned `### Instruction:` into "instruction". Fixed
  by not scanning test-vector catalogs and by only stripping *interior*
  punctuation.

---

## 2. Proposed — not implemented yet

Each of these is a real gap with a concrete landing spot. None of them are
urgent enough to displace 0.4.0's scope.

### 2.1 Corpus

1. **Per-model-failure file** (`wordlists/targets/`). `CL4R1T4S` is organized
   per *vendor*; a red team usually wants per *model* ("what breaks Grok 4?").
   Our chat-template file is the seed: a second dimension, "which models this
   class was observed on", as metadata rather than as more files.
   *Cost:* a tag vocabulary plus back-fill. *Value:* turns the corpus into a
   per-model regression plan.
2. **Translate the new classes** (dual response, attribute override, tool-argument
   injection) into the 10 existing languages. F-001 showed English-only filters
   fail; the new classes are English-only right now.
   *Cost:* ~30 lines × 10 languages. *Value:* keeps the per-language recall
   measurement honest for the new classes.
3. **Voice / audio surface.** No coverage for transcripts, TTS-rendered
   instructions, or audio-over-text smuggling. Not in the OWASP list, but it is
   the next surface after text and multimodal.
4. **Agent-to-agent / protocol surfaces** — instructions aimed at an MCP server
   or a tool description rather than at a human's chat window.
5. **Supply-chain and model-artifact triggers** (LLM03): the "backdoor trigger"
   literature is public, and it is a token-corpus question rather than a
   prompt-corpus one.
6. **Abstention eval** — the `misinformation/` corpus is a list of probes;
   the missing half is the measurement: does the deployment actually abstain,
   and at what rate? Same shape as the LLM05 egress measurement below.

### 2.2 Library

7. **`promptwl.bench()`** — a two-sided benchmark helper: recall over the
   corpus, false-positive rate over a user-supplied benign set, broken down by
   category, class and language. Every number the README quotes is currently
   produced by a demo script; this makes it a call.
8. **Multi-turn and assembled-context evaluation.** `payload-splitting.txt`
   exists, but nothing measures whether a guardrail misses intent that is
   assembled across turns. That is the last open measurement from F-008.
9. **Encoder registry** — `promptwl.encode(phrase, chain)` / `decode(text)`
   for the transform catalog, so a defender can generate their own evasion
   matrix instead of writing one per project.
10. **`promptwl.guardrail()`** — a ready-made, deliberately conservative
    guardrail built on `scan()`: canonicalize → match → severity policy. Today
    the library hands you a corpus and a scanner; this would hand you a
    baseline you can put in front of a model *today*, with the honest caveat
    that it is a floor, not a ceiling.
11. **Carrier decoders.** `carriers()` tells you *which* channel is in use;
    the next step is `decode_carrier(text)` — turn Braille dot patterns, case
    patterns, whitespace patterns and emoji-modifier sequences back into the
    ASCII they carry. Detection without decoding still leaves the payload
    unreviewed.
12. **IDN / punycode helper** — `promptwl.homograph_host(url)` that decodes
    the punycode label and compares the ASCII skeleton against the rendered
    form, so a tool-argument defense can compare *resolved* names, not
    rendered ones.

### 2.3 Process

13. **Weekly diff against the public collections.** A scheduled job that diffs
    our class list against the shapes appearing in newly published prompt
    collections, and opens an issue when a class is missing. This is the
    "keep pace with how attacks evolve" promise in `CONTRIBUTING.md` turned
    into something automatic.
14. **Adversarial review of our own corpus.** We ship 929 patterns; someone
    should try to write filters that beat them, and the surviving filter
    becomes a new corpus file. (The `caesar7` row in `ensemble_demo.py` is the
    same idea in miniature.)
15. **Paraphrase-robustness eval.** The new `classifier-evasion-paraphrase`
    class makes the question measurable: take the English corpus, generate
    meaning-preserving paraphrases, and measure how much recall a filter
    loses. A filter that only survives exact strings has no coverage at all.

---

## 3. Deliberately not taken

| Idea | Why not |
|---|---|
| Shipping payloads from the public collections | The repo's contract: pattern level, defensively framed, no weaponized chains. The collections are already public; copying them adds no defensive value and a lot of liability. |
| Persona / "liberation" role-play templates verbatim | We catalog the *class* (`persona-override.txt`) so a defender can test refusal robustness. Reproducing the best-performing character sheets is payload work, and it optimizes for bypass rather than for defense. |
| "Semantic inversion" / refusal-then-opposite as a *product* feature | The dual-response class is in the corpus as a *test input*. Making it work is the attacker's job; documenting it as a pattern is ours. |
| Vendor-specific jailbreak prompt sets keyed to a named model | `L1B3RT4S` is organized this way. For defenders it optimizes for a moving target — models change weekly. Per-family *markers* (stable) are useful; per-model *payload sets* are not. |
| File-format steganography (LSB in images/audio, PDF layers, archive nesting, network timing) | A forensics discipline, not a prompt-injection class: it needs a different detector, a different defender, and a different reader. We took the *text* carriers and stopped there. |
| The mutation / obfuscation *tools* themselves | We catalog what they make attackers ask for. Shipping an obfuscation engine is the attacker's job, and it would make this repo a weapon with a corpus stapled on. |
| The "known unknowns" benchmark content | It is a research harness, not an attack corpus. We took only its *question shape* — unanswerable questions that expose confident fabrication. |
| Anything that needs a live target | No real hosts, no real credentials, no working chains against named services. `example.invalid` and `alert(1)` only. |

---

*Survey written 2026-11-21 while shipping 0.4.0. The journal entry for the
same round is **F-012** in `research/journal.md`.* 🦜
