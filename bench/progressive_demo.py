#!/usr/bin/env python3
"""
progressive_demo.py — measure the optimization fix at the same boundary that
does the security scanning.

Baseline: full catalog injected up front (equals the bench.token_tax number;
the internal `_provenance` bookkeeping tag is excluded so the two agree).
Mediated: two meta-tools + on-demand search/load for one representative task.

Prints the token reduction, and confirms the catalog it operates on is the
SECURITY-cleaned one (same mediate_catalog() call) — proving one chokepoint
serves both fixes.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from defenses.mediator import mediate_catalog  # noqa: E402
from defenses.progressive import ProgressiveCatalog  # noqa: E402
from harness.mcpkit import StdioClient, count_tokens  # noqa: E402

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    os.chdir(ROOT)
    # Large surface (factor 6 -> 72 tools), the realistic multi-server case.
    client = StdioClient([PY, "-m", "servers.benign_server", "6"])
    try:
        client.initialize()
        tools = client.list_tools()
    finally:
        client.close()

    # ONE interception point: security-clean + provenance, then hand to
    # progressive disclosure. Same call, both fixes.
    med = mediate_catalog(tools, provenance="benign-github-like")
    # Exclude internal underscore-prefixed bookkeeping (e.g. _provenance) so the
    # baseline equals the bench.token_tax number rather than being inflated by it.
    clean = [{k: v for k, v in t.items() if not k.startswith("_")} for t in med.cleaned_tools]
    baseline = count_tokens(json.dumps(clean, separators=(",", ":")))

    pc = ProgressiveCatalog(clean)

    print("=" * 74)
    print("  PROGRESSIVE DISCLOSURE AT THE MEDIATION BOUNDARY")
    print("=" * 74)
    print(f"  catalog size            : {len(tools)} tools")
    print(f"  security findings        : {len(med.findings)} (clean baseline)")
    print(f"  baseline (all schemas)   : {baseline:,} tokens paid up front")
    print(f"  meta-tool index          : {pc.index_tokens():,} tokens (always paid)")
    print("-" * 74)

    tasks = [
        "open a new issue about a crash",
        "merge a pull request",
        "read a file from the repo",
    ]
    for q in tasks:
        c = pc.cost_for_task(q)
        reduction = 100.0 * (1 - c["tokens_paid"] / baseline)
        print(f"  task: {q!r}")
        print(f"     -> loaded '{c['loaded']}'  |  paid {c['tokens_paid']:,} tokens  "
              f"|  {reduction:.1f}% reduction vs baseline")

    print("-" * 74)
    print("  Same mediate_catalog() call produced BOTH the security-cleaned")
    print("  catalog and the index this disclosure runs on: one chokepoint,")
    print("  both gaps closed.")


if __name__ == "__main__":
    main()
