#!/usr/bin/env python3
"""
token_tax.py — measure the MCP "token tax": how many tokens tool definitions
consume before the model does any reasoning, and how that scales.

Method
------
1. Launch the benign server as a real subprocess at several catalog sizes.
2. Perform the MCP handshake and call tools/list, exactly as a host would.
3. Serialize the returned tool definitions the way they enter the model's
   context (compact JSON) and measure chars/bytes/tokens.
4. Compute a "minimal-schema floor": the smallest serialization that still
   names each tool, its one-line purpose, and its parameter names+types. The
   ratio full/minimal is the redundancy the protocol forces today.
5. Express the full cost as a fraction of a 200k-token context window.

All measurements on tool metadata are reproducible and deterministic. Token
counts are exact if tiktoken is installed, otherwise a documented (conservative)
estimate — the ratio holds either way.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.mcpkit import StdioClient, measure, tokenizer_name  # noqa: E402

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTEXT_WINDOW = 200_000


def full_serialization(tools: list[dict]) -> str:
    """How tool defs actually enter context: full JSON schemas, compact."""
    return json.dumps(tools, separators=(",", ":"), ensure_ascii=False)


def minimal_serialization(tools: list[dict]) -> str:
    """The floor: name, first sentence of description, param name:type pairs."""
    lines = []
    for t in tools:
        desc = (t.get("description") or "").split(". ")[0].strip()
        props = (t.get("inputSchema") or {}).get("properties") or {}
        params = ",".join(f"{k}:{v.get('type','any')}" for k, v in props.items())
        lines.append(f"{t['name']}({params}) - {desc}")
    return "\n".join(lines)


def measure_server(factor: int) -> dict:
    client = StdioClient([PY, "-m", "servers.benign_server", str(factor)])
    try:
        client.initialize()
        tools = client.list_tools()
    finally:
        client.close()

    full = full_serialization(tools)
    minimal = minimal_serialization(tools)
    fm = measure(full)
    mm = measure(minimal)
    ratio = fm["tokens"] / mm["tokens"] if mm["tokens"] else 0.0
    return {
        "n_tools": len(tools),
        "full": fm,
        "minimal": mm,
        "ratio": ratio,
        "pct_context": 100.0 * fm["tokens"] / CONTEXT_WINDOW,
        "tokens_per_tool": fm["tokens"] / len(tools) if tools else 0,
    }


def main() -> None:
    os.chdir(ROOT)
    print("=" * 74)
    print("  MCP TOKEN-TAX BENCHMARK")
    print(f"  tokenizer: {tokenizer_name()}")
    print(f"  context window assumed: {CONTEXT_WINDOW:,} tokens")
    print("=" * 74)

    header = f"{'tools':>6} | {'full tokens':>12} | {'tok/tool':>9} | {'minimal':>8} | {'ratio':>6} | {'% of ctx':>9}"
    print(header)
    print("-" * len(header))

    rows = []
    for factor in (1, 2, 4, 6):
        r = measure_server(factor)
        rows.append(r)
        print(
            f"{r['n_tools']:>6} | {r['full']['tokens']:>12,} | "
            f"{r['tokens_per_tool']:>9.0f} | {r['minimal']['tokens']:>8,} | "
            f"{r['ratio']:>5.1f}x | {r['pct_context']:>8.1f}%"
        )

    print("-" * len(header))
    worst = rows[-1]
    print(
        f"\nFINDING: at {worst['n_tools']} tools the catalog costs "
        f"~{worst['full']['tokens']:,} tokens "
        f"({worst['pct_context']:.1f}% of a {CONTEXT_WINDOW//1000}k window) "
        f"before the model reads a single user message."
    )
    print(
        f"         The same tools expressed minimally need ~{worst['minimal']['tokens']:,} "
        f"tokens — a {worst['ratio']:.1f}x redundancy the protocol forces today."
    )
    print(
        "         Native progressive disclosure would load only the ~1-3 tools a "
        "task needs, collapsing this to a near-constant cost."
    )

    # Emit machine-readable results for the report.
    out_dir = os.path.join(ROOT, "report")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "token_tax.json"), "w") as f:
        json.dump({"tokenizer": tokenizer_name(), "context_window": CONTEXT_WINDOW, "rows": rows}, f, indent=2)
    print(f"\n(results written to report/token_tax.json)")


if __name__ == "__main__":
    main()
