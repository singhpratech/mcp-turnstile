# mcp-turnstile — measure what your MCP server costs and hides

A dependency-free harness that gives any MCP server a **report card**: how many
context tokens its tool definitions cost, and whether its tool metadata carries
the trust problems the protocol leaves unaddressed. Plus a reproducible
benchmark you can cite.

> Named for the `tools/list` boundary it watches — the turnstile every tool
> definition passes through on its way into the model's context. (Working name;
> swappable.)

Two structural gaps in the Model Context Protocol, measured at one place:

- **Token tax** (optimization) — tool definitions consume a large, growing share
  of the context window before the model reasons at all.
- **Metadata trust** (security) — tool descriptions are untrusted input the host
  feeds to the model as if trusted, with no protocol-level mechanism to
  normalize, verify, or pin them.

Both sit at the tool-catalog boundary (`tools/list`), so **one mediator there
closes both** — the security checks ride in on the token savings everyone
already wants. The headline result: **~97% of per-task tool-definition tokens
are avoidable overhead**, and the same interception point catches three classes
of metadata attack. Full write-up with numbers: **[`report/BENCHMARK.md`](report/BENCHMARK.md)**.

Nothing here touches any system you don't control. Every "server" is a local
Python subprocess speaking real MCP JSON-RPC over stdio. The attack payloads are
inert text embedded in local servers' own metadata; they exist to be detected.

## Use it on your own server (the product)

`turnstile` scans **any** MCP server — one you run locally over stdio, or a
remote streamable-HTTP endpoint — and prints a report card: token cost, the
worst-offending tools, progressive-disclosure savings, and any concealment /
poisoning / rug-pull signals. It returns a CI exit code and can remember tool
digests across runs to catch silent redefinition.

Four ways to run it — pick one:

```bash
# 1. single file, zero install, zero dependencies (build once, ship anywhere)
python3 build.py                     # -> dist/mcpturn.pyz  (~27 KB, one file)
python3 dist/mcpturn.pyz scan --stdio -- npx -y @modelcontextprotocol/server-github

# 2. install the command (also zero runtime dependencies)
pip install .                        # gives you `mcpturn` (aliases: turnstile, mcp-turnstile)
# once published:  pip install mcp-turnstile   ·   pipx install mcp-turnstile
mcpturn scan --stdio -- npx -y @modelcontextprotocol/server-github

# 3. no install at all, straight from a checkout
python3 -m mcpturn scan --stdio -- python3 -m servers.benign_server 6

# 4. docker (node/npx included, so npx-based servers and remote --http both work)
docker build -t mcp-turnstile .
docker run --rm mcp-turnstile scan --http https://example.com/mcp --fail-on high
```

More examples (`mcpturn`, `turnstile`, `mcp-turnstile`, and `python3 dist/mcpturn.pyz` are interchangeable):

```bash

# scan a remote HTTP server, with auth, and fail CI on any high finding
turnstile scan --http https://example.com/mcp \
  --header "Authorization: Bearer $TOKEN" --fail-on high

# JSON output, and remember digests to catch rug-pulls next time
mcpturn scan --json --pin .mcpturn-pins.json --stdio -- ./my-server
```

Flags: `--window N` (context size), `--top N` (heaviest tools), `--task STR`
(disclosure estimate), `--fail-on {none,high,any}` (CI gate), `--pin FILE`
(cross-run rug-pull detection), `--json`. Exit code is `2` when findings trip
`--fail-on`.

Example (a poisoned local server): `safety F · 4 high findings` — concealed
Unicode TAG-block payload, `do not tell the user`, and an `id_rsa` exfil signal,
all **flagged** at the boundary. turnstile *reports and grades*; it does not block
or intercept — the findings are signals for review and CI, not a security
boundary. `--fail-on` is a CI gate, not enforcement.

## Prove it / develop it

```bash
./run.sh                          # full report card
python3 -m bench.token_tax        # token tax only
python3 -m bench.security_proof   # metadata-trust checks + defenses
python3 -m bench.concealment_lab  # 5 concealment techniques vs i18n corpus
python3 -m bench.progressive_demo # both fixes at one chokepoint
```

Requires only Python 3.10+. If `tiktoken` is installed, token counts are exact;
otherwise a conservative heuristic is used (it *under*-counts, so the reported
tax is a floor). Character and byte counts are always exact.

## What each run reports

**Token tax** (`bench/token_tax.py`) — launches a realistic github-like server at
12/24/48/72 tools, pulls `tools/list`, and measures the catalog as it enters
context: **~468 tokens/tool, a ~6.6× redundancy over a minimal schema, ~17% of a
200k window at 72 tools** — before any user input.

**Metadata-trust checks** (`bench/security_proof.py`) — three attacks against
local servers, each shown landing on a naïve host then caught at the boundary:
visible `<IMPORTANT>` poisoning; invisible Unicode TAG-block concealment (the
**approval-view fidelity gap** — the human approves text they cannot see); and a
rug-pull (benign at approval, silently redefined) caught by byte-pinning.

**Unicode forensics lab** (`bench/concealment_lab.py`) — an enhanced PoC that
runs **five** distinct concealment techniques against a benign description and
shows human-view vs. model-view, the hidden byte-capacity, and the detector's
verdict for each: TAG-block mirror, zero-width binary, bidi Trojan-Source,
variation-selector smuggling, and homoglyph spoof. It then runs a legitimate
**i18n corpus** of 35 strings across dozens of scripts and mechanisms (Persian
ZWNJ, Arabic/Hebrew bidi embeddings, Indic conjuncts, emoji ZWJ sequences and
professions, subdivision-flag emoji, keycap / ©®™ / arrow / media-button
presentation selectors, CJK ideographic variation sequences, Thai/Lao/Khmer/CJK
zero-width word-breaks, Mongolian FVS, Greek math letters glued to Latin) and
confirms **0 false positives** — the whole point being that every attack channel
abuses a mechanism that is *also* legitimate somewhere, so only context-aware
detection works. Result: **5/5 caught, 0 i18n false positives**. The detector
was hardened against an adversarial battery of 139 fresh strings (98 legit across
~40 scripts + 41 evasions); see Limitations for the residuals that remain by
design.

**Progressive disclosure** (`bench/progressive_demo.py`) — the same
`mediate_catalog()` call that flags metadata also feeds a `tool_search` /
`tool_load` index. Per-task cost drops **~97%** vs. loading the full catalog.

## Prior art & what's novel

Be clear-eyed — this is a crowded space:

- Rug-pull **byte-pinning** is already shipped by **Invariant Labs' MCP-Scan**
  (Snyk).
- **Hidden-Unicode detection** in tool metadata already ships in **Microsoft's
  Agent Governance Toolkit** for .NET.
- The **crypto** for signed tool definitions is already in the literature
  ("The Trustworthy MCP Registry"), and **SEP-1766** already occupies the
  digest/versioning slot in the spec pipeline.

**mcp-turnstile's contribution is not new crypto, and not any single check.**
Every leg exists elsewhere: token-costing (mcp-checkup), deterministic
hidden-Unicode detection (Microsoft's Agent Governance Toolkit, Cisco's YARA
rules), and false-positive tuning (Cisco). The defensible, verified contribution
is the *compound*:

1. **Measurement** — a reproducible token-tax + metadata-trust benchmark against
   the brand-new `2026-07-28` spec.
2. **Static `tools/list` catalog pricing *and* metadata concealment audit in one
   offline, dependency-free pass** — no tool found does both at this boundary.
3. **Context-aware, i18n-honest concealment detection** — deterministic (no LLM,
   no network), verified at **0 false positives** on a 35-string corpus and on all
   98 legitimate strings of a 139-string adversarial battery spanning ~40 scripts
   and mechanisms, while catching 5/5 core techniques. The deterministic prior art
   trades coverage for false positives: some tools strip codepoints (flagging real
   Persian/Thai/Indic/emoji) or set blunt count thresholds; others add an
   LLM/neural arbitrator (slow, non-deterministic, network-bound). This uses
   grapheme/script context instead — catching single-codepoint smuggling *and*
   leaving real languages alone, offline.

It **reports and grades** — it is not a blocking security boundary. The full
write-up and prior-art map are in **[`report/BENCHMARK.md`](report/BENCHMARK.md)**.

## Limitations

- **Token counts are a floor** when `tiktoken` is absent (heuristic under-counts).
- **Byte-pinning is Trust-On-First-Use** — it detects post-approval mutation, not
  first-contact poisoning, and covers received bytes only, not JSON Schema `$ref`
  referents.
- **Unicode handling respects i18n** — detection keys off *context*, not
  codepoint identity: a single variation selector after a *visible* base is
  legitimate (a run, or singles orphaned onto invisible bases, is a byte chain);
  zero-width is a payload only as a run of ≥3 or a ≥16 cluster, never as isolated
  word-breaks; bidi is flagged on
  RLO/LRO *overrides* (embeddings and isolates are treated as legitimate);
  homoglyphs are flagged only via the Latin-targeting subset of UTS #39 plus the
  canonical Latin-look-alike scripts. This is verified at 0 false positives on a
  35-string corpus and on all 98 legitimate strings of a 139-string adversarial
  battery, on both the Python and TypeScript engines. Hygiene is display-layer,
  never a hash input.
- **The injection/exfil signals are report-card hints, not a security boundary.**
  These regexes are deliberately noisy (a benign "read a file" tool can match)
  and are separate from the i18n-honest Unicode detector above; they are hints
  for review, and a motivated attacker rephrases around them.
- **Concealment detection has documented residuals** (by design, not oversight):
  a *wholly* non-Latin homoglyph word — all-Cyrillic `ѕсоре`, a Cherokee or Lisu
  word spelling a Latin one — is not caught per-string (needs the full UTS #39
  fold table + cross-catalog skeleton collision; a naive fold would false-positive
  on real Cyrillic/Cherokee) — and a Latin word carrying *Armenian* confusables is
  likewise left alone, since Armenian agglutinates case suffixes onto Latin brand
  words; Latin-block or *visibly distinct* look-alikes
  (script-`ɡ` U+0261, Turkish dotless-ı, fullwidth `ｇｅｔ`, small-caps,
  math-alphanumerics) are out of the invisible "approval-view gap" threat model
  because a human reviewer can see them; **bidi embeddings and isolates**
  (LRE/RLE, LRI/RLI/FSI, and the RLM/LRM marks) are not high-flagged — they are
  legitimate in RTL text and in W3C/ICU interpolation, so only the RLO/LRO
  overrides that the classic Trojan-Source PoCs use are flagged; a zero-width
  payload spread as *strictly isolated* singletons AND padded below 30% density
  evades the count floor, but that bloats the text to several times the payload
  length; and the bidi renderer is a simplified approximation of the Unicode BiDi
  algorithm.

## Layout

```
harness/mcpkit.py           shared MCP stdio server + client + token estimator
servers/catalog.py          realistic, verbose github-like tool schemas (benign)
servers/benign_server.py    clean baseline server (factor = catalog size)
servers/malicious_server.py LOCAL poisoned/concealed server (defensive research)
attacks/payloads.py         TAG-block codec + poisoning templates (inert)
attacks/concealment.py      5 concealment techniques (encode/decode, inert)
attacks/i18n_corpus.py      legitimate international text (false-positive test set)
defenses/mediator.py        flag + byte-pin + provenance (security half, i18n-honest)
defenses/unicode_forensics.py  context-aware detector for all 5 techniques
defenses/progressive.py     search/load meta-tools (optimization half)
bench/                      the four measurement / demo entrypoints
report/BENCHMARK.md         the citeable write-up (headline numbers)
report/GAP_ANALYSIS.md      spec-mapped gap analysis with sources
mcpturn/                    the Python CLI product (scan any MCP server)
ts/                         the TypeScript/Node CLI (same tool, npm-installable)
docs/index.html             the project site (GitHub Pages)
docs/about.html             the story + roadmap + live demos (GitHub Pages)
```

## Scope / ethics

Defensive security research. Attacks run only against subprocesses this repo
launches. No scanning, targeting, or transmission to third parties. The payloads
demonstrate *detection*, not offense.
