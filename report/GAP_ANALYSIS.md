# The two gaps in MCP: optimization and security

*Companion analysis to the `mcp-turnstile` harness. Written 2026-07-25. Spec
baseline: `2025-11-25`; release candidate `2026-07-28` (finalizes 2026-07-28).*

## TL;DR

MCP has two structural gaps that the specification does not close:

1. **The token tax** (optimization) — tool metadata consumes a large, growing
   share of the context window before the model reasons. The `2026-07-28`
   release candidate does **not** address this; the roadmap files it under "on
   the horizon," core maintainers not leading. `SEP-1576` (the schema-dedup
   proposal) is **closed as dormant**; `#2808` is **open with no maintainer
   response**.
2. **Metadata trust** (security) — the spec says tool descriptions "should be
   considered untrusted" but provides **no mechanism** to act on that. Every
   defense today is bolted on outside the protocol.

Both gaps live at one place: the `tools/list` boundary. That is the design
insight the harness demonstrates — a mediator there closes both at once.

---

## Timing: the ground is moving (finalizes 2026-07-28)

The `2026-07-28` revision is the largest change "since adding authorization,"
and is **not backward compatible**. Before treating anything as a gap, subtract
what this release already fixes:

| Previously a gap | `2026-07-28` status |
| --- | --- |
| Stateful sessions fight load balancers | **Fixed** — protocol is stateless; `initialize` handshake removed, capabilities ride in `_meta` per request |
| No discovery caching | **Fixed** — `ttlMs` + `cacheScope` on list/resource responses |
| No observability | **Fixed** — W3C Trace Context in `_meta` |
| OAuth mix-up attacks | **Hardened** — `iss` validation (RFC 9207), OIDC `application_type`, issuer-bound credentials |
| Rigid schemas (no `$ref`) | **Fixed** — JSON Schema 2020-12, so `$ref`/`oneOf`/`allOf` are now legal |

Deprecated (12-month lifecycle): **Roots, Sampling, Logging**. Analyses that
lean on sampling attacks are aiming at a primitive being removed.

The release also **adds** attack surface — see §2.4.

---

## 1. The optimization gap: the token tax

### 1.1 Magnitude (independently reported)

- **7 servers = 67,300 tokens** before user input — 33.7% of a 200k window;
  GitHub MCP alone ≈ **18k tokens / 27 tools**.
- Tool definitions run **5–15× larger** than a minimal schema for the same tool
  (`#2808`, measuring 11 production tools at ~100–1,000 tokens each).
- Cloudflare's 2,500-endpoint API as tools ≈ **1.17M tokens** — larger than any
  context window.
- It is not only cost: deferring tool loading moved Claude Opus from **49% → 74%**
  on MCP evals — the bloat degrades accuracy ("lost in the middle").

### 1.2 What this harness measures

`bench/token_tax.py` reproduces the effect end-to-end against a real (local)
MCP server: **~468 tokens/tool, ~6.6× over minimal, ~17% of a 200k window at 72
tools.** (Conservative — the fallback tokenizer under-counts.) The magnitude and
the ratio both land inside the independently reported ranges.

### 1.3 Why the spec doesn't fix it

- **No native progressive disclosure.** `tools/list` is all-or-nothing.
- The three real fixes — Anthropic Tool Search (85%), Cloudflare Code Mode
  (99.9%), code-execution-with-MCP (98.7%) — are all **client/vendor-side**, not
  protocol features.
- `SEP-1576` (schema dedup via `$ref` + embedding tool-filtering): **closed,
  dormant**. Ironically, `2026-07-28` just made `$ref` legal, then shipped no
  mechanism that uses it for dedup.
- Roadmap places "deeper" token/tool work as community-led, not core-led.

### 1.4 Open seams (optimization)

1. **Medium scale (30–100 tools)** — explicitly called out as unsolved: Tool
   Search adds a latency turn; Code Mode needs sandbox infra most teams lack.
2. **Chaining penalty** — intermediate results round-trip through the model;
   only code-execution avoids it, and only with a sandbox.
3. **Idle-session cache misses** — sessions idle past the cache TTL reload the
   full catalog. `ttlMs`/`cacheScope` help discovery, not this.
4. **No protocol-native tiered schema** — discovery-tier vs. invocation-tier
   (`#2808`'s proposal) has no home in the spec.

---

## 2. The security gap: metadata trust

### 2.1 The core flaw

The spec states descriptions/annotations "should be considered untrusted,
unless obtained from a trusted server," then provides **no primitive** to
normalize, verify, sign, or pin them. It is a MUST-shaped hole filled with a
SHOULD. The host feeds untrusted metadata to the model as instruction.

### 2.2 Severity (independently measured)

- **MCPTox** (AAAI 2026; 45 live servers, 353 real tools, 20 agents): tool
  poisoning succeeds up to **72.8%** (GPT-o1-mini); **best refusal rate < 3%**
  (Claude-3.7-Sonnet). More capable models are *more* vulnerable — the attack
  rides good instruction-following. Generic prompt-injection payloads score
  ~0% here, confirming tool poisoning is a **distinct** vector.
- **Unicode TAG-block concealment** (arXiv:2607.05744): payloads in the
  invisible TAG range (U+E0000–U+E007F) create an **approval-view fidelity
  gap** — clean text in the approval UI, hidden instruction to the model.
  Tested against 3 independent server implementations; all affected.
- **Self-asserted, unverified capabilities** and **no cross-server provenance**
  (arXiv:2601.17549) — a preprint reports +41.6% cross-server amplification and
  78.3% success with 1-of-5 servers compromised (self-reported; treat magnitude
  as directional).

### 2.3 What this harness demonstrates

`bench/security_proof.py` reproduces, against local servers, all three classes
and shows each caught at the `tools/list` boundary:
- visible `<IMPORTANT>` poisoning → flagged (injection + exfil signals);
- TAG-block concealment → the **approval-view gap is shown explicitly** (human
  view ≠ model view), then flagged and normalized so they match again;
- rug-pull → caught by SHA-256 hash-pinning of the canonical definition.

### 2.4 New surface introduced by `2026-07-28`

Statelessness and the extension framework are not free:
- **Predictable stateless IDs / `requestState`** → workflow hijacking,
  cross-agent and cross-tenant access.
- **`Mcp-Method` / `Mcp-Name` headers** → protocol-desync past intermediaries;
  secrets leaked into headers if inputs are mis-mapped.
- **MCP Apps (sandboxed iframes)** → classic web risks (stored XSS).
- **Tasks** → cheap-to-request / expensive-to-serve **DoS**.

### 2.5 Open seams (security)

1. **No metadata-integrity primitive** — no signing, hash-pinning, or
   attestation in the protocol.
2. **No provenance / taint tracking** across servers.
3. **No enforcement of declared capabilities** — declarations are self-asserted.
4. **Stateless-era threat model is days old** — opaque `requestState`,
   header-based routing, task DoS are largely unwritten.

---

## 3. The unifying insight

The optimization view asks *why is all of this in context?* The security view
asks *why is all of this trusted?* **Same answer: mediate `tools/list`.** A
component that intercepts the catalog can, in one pass:

- index it and serve only relevant tools on demand (closes §1), **and**
- normalize invisible Unicode, scan for injection/exfil, hash-pin against
  rug-pulls, and tag provenance (closes §2).

The security work is near-zero marginal cost once you are already mediating the
boundary for tokens — which is why "attach both" is the right instinct.
`defenses/mediator.py` + `defenses/progressive.py` implement this; the same
`mediate_catalog()` call produces both the cleaned catalog and the disclosure
index (`bench/progressive_demo.py`), collapsing per-task cost ~97%.

The protocol *cannot* enforce this itself (it says so). Clients won't all agree.
**A mediator is where enforcement can actually live** — until, ideally, a future
SEP gives §2.5.1 (integrity) and §1.4.4 (tiered schema) a home in the spec.

---

## Sources

Spec & official:
- MCP specification (2025-11-25): https://modelcontextprotocol.io/specification/latest
- 2026-07-28 release candidate: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- 2026 MCP roadmap: https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/
- SEP-1576 (token bloat, dormant): https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1576
- Issue #2808 (schema overhead, open): https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2808

Optimization:
- Three context-bloat fixes compared: https://mcp.directory/blog/mcp-context-bloat-fix-2026-tool-search-code-mode-progressive-disclosure
- StackOne token optimization: https://www.stackone.com/blog/mcp-token-optimization/

Security:
- MCPTox (AAAI 2026): https://arxiv.org/abs/2508.14925
- Unicode TAG-block concealment: https://arxiv.org/pdf/2607.05744
- MCP spec security analysis: https://arxiv.org/html/2601.17549v1
- NSA MCP security CSI: https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF
- New spec, new security challenges: https://www.securityweek.com/new-enterprise-ready-mcp-specification-brings-new-security-challenges/
- MCP breaks with stateful past: https://www.theregister.com/devops/2026/07/23/model-context-protocol-prepares-to-break-with-its-stateful-past/5276722
