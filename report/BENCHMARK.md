# Your MCP tools cost 97% more context than they need to — and the 2026-07-28 spec doesn't fix it

*A reproducible benchmark from [mcp-turnstile](../README.md). Published 2026-07-25,
against the MCP `2026-07-28` release candidate. Every number below comes from a
harness you can run yourself in under a minute with no dependencies.*

## The headline

Connect an agent to a realistic set of MCP servers and **~97% of the tokens you
spend on tool definitions are pure overhead** — paid on every session, before
the model reads a single word from the user. On a 72-tool surface that is
**~33,700 tokens (17% of a 200k context window) sitting idle**, versus **~800
tokens** for the one tool a given task actually uses.

The MCP `2026-07-28` revision — the largest change to the protocol since
authorization, shipping stateless transport, OAuth hardening, JSON Schema
2020-12, and deprecating Roots/Sampling/Logging — **does not address this.** The
token tax is not on the roadmap as core work. So it is worth measuring precisely.

## What the numbers actually are

Run against a genuine local MCP server (real JSON-RPC over stdio, github-style
tools written in the verbose style production servers actually ship):

| tools | tool-def tokens | tokens/tool | minimal floor | redundancy | % of 200k ctx |
|------:|----------------:|------------:|--------------:|-----------:|--------------:|
| 12 | 5,589 | 466 | 815 | 6.9× | 2.8% |
| 24 | 11,213 | 467 | 1,667 | 6.7× | 5.6% |
| 48 | 22,461 | 468 | 3,371 | 6.7× | 11.2% |
| 72 | 33,709 | 468 | 5,075 | **6.6×** | **16.9%** |

"Minimal floor" is the smallest serialization that still names each tool, its
one-line purpose, and its parameters as `name:type` — i.e. what the model
actually needs to choose and call a tool. The gap between the two columns is the
**6.6× redundancy the current protocol forces** by injecting full JSON Schema
for every tool, up front, whether or not the task will touch it.

### The fix, measured at the same boundary

Put a mediator at `tools/list` that indexes the catalog and exposes two
meta-tools — `tool_search(query)` and `tool_load(name)` — instead of the raw
catalog. Per-task cost collapses:

| task | tool loaded | tokens paid | reduction vs. 72-tool baseline |
|------|-------------|------------:|------------------------------:|
| "open a new issue about a crash" | `create_issue` | 883 | **97.4%** |
| "merge a pull request" | `merge_pull_request` | 814 | **97.6%** |
| "read a file from the repo" | `get_file_contents` | 750 | **97.8%** |

The always-paid index is **209 tokens**. This is the progressive-disclosure
pattern (Anthropic's Tool Search, agentgateway, and others report the same order
of magnitude); the contribution here is that it is *measured against the brand-new
spec* and produced by the *same interception point* that does the security
checks below.

## The second gap at the same boundary: metadata trust

The spec says tool descriptions "should be considered untrusted" and then gives
no mechanism to act on it. mcp-turnstile demonstrates three metadata-trust
issues against local servers it controls, and shows each caught at the
`tools/list` boundary:

1. **Visible tool poisoning** — an `<IMPORTANT>` instruction block appended to a
   description. Flagged (injection + exfil signals).
2. **Invisible Unicode TAG-block concealment** — the same payload encoded in the
   invisible TAG range (U+E0000–E007F), so the description renders as clean text
   in an approval UI while the model receives the hidden instruction. This is the
   **approval-view fidelity gap**: the human approves text they cannot see. The
   harness prints the human-view vs. model-view divergence explicitly, then
   flags and neutralizes it — while *preserving* legitimate uses of the same
   codepoints (subdivision-flag emoji, Persian ZWNJ, emoji ZWJ).
3. **Rug-pull** — a tool that is benign when approved, then silently redefined;
   caught by byte-pinning (Trust-On-First-Use).

## The thesis

Both gaps live at exactly one place: **the moment tool metadata crosses from a
server into the model's context.** The optimization view asks *why is all of
this in context?*; the security view asks *why is all of this trusted?* — and
one mediator at `tools/list` answers both. The security checks are near-free once
you are already mediating that boundary for tokens, which is the point: the
integrity work rides in on the token savings everyone already wants.

## How to reproduce

```bash
git clone <your-fork>/mcp-turnstile && cd mcp-turnstile
./run.sh
```

Requires only **Python 3.10+**. No pip, no dependencies — every "server" is a
local subprocess speaking real MCP. `bench/token_tax.py`, `bench/security_proof.py`,
and `bench/progressive_demo.py` each run standalone.

## Limitations — what this is and is not

- **Token counts are a floor.** When `tiktoken` is not installed the harness
  uses a documented heuristic that *under*-counts, so the real tax is higher than
  reported. Install `tiktoken` for exact `cl100k_base` counts; the 6.6× ratio and
  the % figures hold either way.
- **Not novel crypto, not any single check, and not a hardened boundary.**
  Rug-pull byte-pinning ships in Invariant Labs' MCP-Scan (Snyk); deterministic
  hidden-Unicode detection ships in Microsoft's Agent Governance Toolkit and
  Cisco's YARA rules; token-costing ships in mcp-checkup. The defensible,
  verified contribution is the *compound*: reproducible **measurement**, plus
  **static `tools/list` catalog token-pricing and metadata concealment audit in
  one offline, dependency-free pass** (no tool found does both at this boundary).
  It reports and grades; it is not a new security primitive.
- **i18n-honest concealment, deterministically.** The Unicode detector decides
  attack-vs-legitimate by *context* (runs, counts, adjacency, base visibility,
  the UTS #39 Latin-confusable subset), not codepoint identity — no LLM, no
  network, and verdict-identical across the Python and TypeScript builds on the
  corpus and adversarial battery (a pinned Unicode version would extend that to
  every code point; today the two runtimes' category tables can differ only for
  code points newer than the host Python's UCD). Verified at **0 false
  positives** on a 35-string corpus and on all 98 legitimate strings of a
  139-string adversarial battery across ~40 scripts and mechanisms, catching 5/5
  core techniques (and 27/41 of the battery's evasion *variants*). Residuals (by
  design): wholly-non-Latin homoglyph words (need the full UTS #39 fold table) and
  Latin words carrying Armenian confusables (Armenian agglutinates onto Latin brand
  words, so flagging would false-positive on real text);
  Latin-block / visibly-distinct look-alikes (script-ɡ, dotless-ı, fullwidth,
  small-caps, math-alphanumerics — a human can see them); bidi embeddings and
  isolates (only the RLO/LRO overrides of the classic PoCs are flagged); and a
  zero-width payload spread as strictly isolated singletons padded below 30%
  density (which bloats the text conspicuously).
- **Byte-pinning is TOFU.** It detects post-approval mutation, not first-contact
  poisoning, and it covers received bytes only — not the referents of a JSON
  Schema `$ref`.
- **The injection/exfil signals are report-card hints, not a boundary**, and are
  separate from the i18n-honest Unicode detector — deliberately noisy (a benign
  "read a file" tool can match). A motivated attacker rephrases around regexes;
  real defense is defense-in-depth.

## Sources

- MCP spec (2025-11-25): <https://modelcontextprotocol.io/specification/latest>
- 2026-07-28 release candidate: <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>
- 2026 roadmap: <https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/>
- Token overhead issue #2808: <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2808>
- SEP-1576 (token bloat, dormant): <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1576>
- Context-bloat fixes compared: <https://mcp.directory/blog/mcp-context-bloat-fix-2026-tool-search-code-mode-progressive-disclosure>
- MCPTox (tool poisoning benchmark): <https://arxiv.org/abs/2508.14925>
- Unicode TAG-block concealment: <https://arxiv.org/pdf/2607.05744>
- Invariant Labs MCP-Scan: <https://invariantlabs-ai.github.io/docs/mcp-scan/>
