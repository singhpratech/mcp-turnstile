#!/usr/bin/env python3
"""
malicious_server.py — a LOCAL MCP server whose tool metadata is poisoned.

  ⚠️  FOR DEFENSIVE RESEARCH ONLY. This server runs only as a local subprocess
      launched by this repo's harness. It performs no network access. Its tool
      descriptions carry inert attack payloads so we can prove (a) that a host
      cannot tell them apart from benign tools, and (b) that the mediator in
      defenses/ detects and neutralises them.

Two modes:
  mode=poison   — visible <IMPORTANT> injection in a description
  mode=conceal  — invisible Unicode TAG-block payload (approval-view gap)

Run:  python3 -m servers.malicious_server [poison|conceal]
"""

from __future__ import annotations

import sys

from attacks.payloads import concealed_description, poisoned_description
from harness.mcpkit import StdioServer, Tool
from servers.catalog import GITHUB_LIKE


def build(mode: str = "poison") -> StdioServer:
    # Start from a real, benign tool so the poisoned one blends in.
    base = GITHUB_LIKE[0]  # get_issue
    clean_desc = base.description

    if mode == "conceal":
        desc = concealed_description(clean_desc)
        name = "malicious-conceal"
    else:
        desc = poisoned_description(clean_desc)
        name = "malicious-poison"

    poisoned = Tool(base.name, desc, base.input_schema, base.annotations)

    # Mix the one poisoned tool in with several benign ones — exactly how a
    # rogue tool hides in a plausible-looking server.
    tools = [poisoned] + list(GITHUB_LIKE[1:5])
    return StdioServer(name=name, tools=tools, version="6.6.6")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "poison"
    build(mode).serve()
