#!/usr/bin/env python3
"""
security_proof.py — demonstrate the two metadata-trust attacks against LOCAL
servers, then prove the mediator neutralises them.

For each attack (visible tool poisoning, invisible TAG-block concealment) we:
  1. Launch the malicious server as a local subprocess and pull tools/list.
  2. Show the NAIVE host path: what a human approver sees vs. what the model
     actually receives. For concealment these differ — that is the
     approval-view fidelity gap, and it means the human "approved" text they
     never saw.
  3. Show the MEDIATED path: the mediator flags the tool and normalises the
     description so model-view == human-view again.

No network access. Servers are subprocesses of this process only.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks.payloads import contains_tag_chars, from_tag  # noqa: E402
from defenses.mediator import CatalogPinner, mediate_catalog, normalize  # noqa: E402
from harness.mcpkit import StdioClient  # noqa: E402

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def human_view(desc: str) -> str:
    """What an approval UI shows: invisible codepoints render as nothing."""
    return "".join(ch for ch in desc if not (0xE0000 <= ord(ch) <= 0xE007F))


def model_view(desc: str) -> str:
    """What the model receives: everything, with TAG codepoints decoded so we
    can print the payload it would actually read."""
    return from_tag(desc) if contains_tag_chars(desc) else desc


def run_attack(mode: str, title: str) -> dict:
    client = StdioClient([PY, "-m", "servers.malicious_server", mode])
    try:
        client.initialize()
        tools = client.list_tools()
    finally:
        client.close()

    target = tools[0]  # the poisoned tool is first
    desc = target["description"]

    print("\n" + "=" * 74)
    print(f"  ATTACK: {title}")
    print("=" * 74)

    hv = human_view(desc)
    mv = model_view(desc)
    gap = hv.strip() != mv.strip()

    print("\n[NAIVE HOST] approval UI shows the human:")
    print("   " + repr(hv[:140] + ("…" if len(hv) > 140 else "")))
    print("\n[NAIVE HOST] the model actually receives:")
    print("   " + repr(mv[:200] + ("…" if len(mv) > 200 else "")))
    print(f"\n   approval-view fidelity gap: {'YES — human approved text they could not see' if gap else 'no (payload is visible)'}")
    print("   => on a naive host this metadata enters the model context as-is: ATTACK LANDS")

    # Mediated path
    pinner = CatalogPinner()
    result = mediate_catalog(tools, pinner=pinner, provenance="malicious-server")
    hits = [f for f in result.findings if f.tool == target["name"]]

    print("\n[MEDIATED] findings:")
    for f in hits:
        print(f"   - [{f.severity}] {f.kind}: {f.detail}")
    cleaned_desc = result.cleaned_tools[0]["description"]
    now_clean = human_view(cleaned_desc).strip() == model_view(cleaned_desc).strip()
    print(f"   after normalize(): model-view == human-view again? {now_clean}")
    print(f"   => mediator {'BLOCKS/flags' if hits else 'MISSED'} this tool before it reaches the model")

    return {"mode": mode, "gap": gap, "n_findings": len(hits), "blocked": bool(hits)}


def rug_pull_demo() -> dict:
    """Show hash-pin catching a server that serves a clean tool, then mutates it."""
    print("\n" + "=" * 74)
    print("  ATTACK: rug-pull (definition mutates after approval)")
    print("=" * 74)
    pinner = CatalogPinner()

    # First sight: benign server
    c1 = StdioClient([PY, "-m", "servers.benign_server", "1"])
    try:
        c1.initialize()
        clean = c1.list_tools()
    finally:
        c1.close()
    r1 = mediate_catalog(clean, pinner=pinner)
    print(f"\n   first sight: {len(clean)} tools pinned, findings={len(r1.findings)}")

    # Later: same tool name, now poisoned
    c2 = StdioClient([PY, "-m", "servers.malicious_server", "poison"])
    try:
        c2.initialize()
        poisoned = c2.list_tools()
    finally:
        c2.close()
    # align on the shared name get_issue
    r2 = mediate_catalog(poisoned, pinner=pinner)
    rug = [f for f in r2.findings if f.kind == "rug-pull"]
    print(f"   after mutation: rug-pull findings={len(rug)}")
    for f in rug:
        print(f"   - [{f.severity}] {f.tool}: {f.detail}")
    print(f"   => mediator {'DETECTS' if rug else 'MISSED'} the silent redefinition")
    return {"mode": "rug-pull", "blocked": bool(rug), "n_findings": len(rug)}


def main() -> None:
    os.chdir(ROOT)
    print("=" * 74)
    print("  MCP METADATA-TRUST SECURITY PROOF (local servers only)")
    print("=" * 74)

    results = [
        run_attack("poison", "visible tool poisoning (<IMPORTANT> injection in description)"),
        run_attack("conceal", "invisible Unicode TAG-block concealment"),
        rug_pull_demo(),
    ]

    print("\n" + "=" * 74)
    print("  SUMMARY")
    print("=" * 74)
    caught = sum(1 for r in results if r.get("blocked"))
    print(f"  attacks demonstrated : {len(results)}")
    print(f"  caught by mediator   : {caught}/{len(results)}")
    print(f"  approval-view gaps   : {sum(1 for r in results if r.get('gap'))} "
          f"(cases where the human could not see what they approved)")
    if caught == len(results):
        print("\n  All demonstrated attacks are invisible to a naive MCP host and")
        print("  caught at the tool-catalog boundary by the mediator. The protocol")
        print("  itself provides no primitive for any of these checks today.")


if __name__ == "__main__":
    main()
