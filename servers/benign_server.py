#!/usr/bin/env python3
"""
benign_server.py — a genuine, clean MCP stdio server used as the baseline.

Run standalone:   python3 -m servers.benign_server [factor]
The optional factor argument duplicates the github-like catalog to simulate a
larger tool surface (factor=2 -> ~24 tools, etc.). Default factor=1.

This server contains NO malicious content. It exists so the token-tax
benchmark has a realistic, honest baseline and so the defenses have something
clean to pass through untouched.
"""

from __future__ import annotations

import sys

from harness.mcpkit import StdioServer
from servers.catalog import GITHUB_LIKE, duplicate_catalog


def build(factor: int = 1) -> StdioServer:
    tools = duplicate_catalog(GITHUB_LIKE, factor, "svc") if factor > 1 else list(GITHUB_LIKE)
    return StdioServer(name="benign-github-like", tools=tools, version="1.0.0")


if __name__ == "__main__":
    factor = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    build(factor).serve()
