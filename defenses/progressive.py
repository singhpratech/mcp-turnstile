"""
progressive.py — the optimization half of the mediator, at the same boundary.

Instead of injecting every tool's full schema into context, the mediator
indexes the (already-cleaned, already-scanned) catalog locally and exposes just
two meta-tools to the model:

    tool_search(query)  -> ranked list of {name, one-line summary}
    tool_load(name)     -> the full schema for one tool, on demand

This is the progressive-disclosure pattern (Anthropic Tool Search, agentgateway,
et al.), but reached through the SAME mediate_catalog() interception point that
does the security scanning — which is the project's thesis: one chokepoint pays
for both fixes.

The ranking here is a dependency-free lexical scorer (token overlap + name
match). A production build would swap in embeddings; the token-accounting
result is unaffected.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from harness.mcpkit import count_tokens

_WORD = re.compile(r"[a-z0-9]+")


def _terms(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


@dataclass
class ProgressiveCatalog:
    tools: list[dict]  # cleaned tools from mediate_catalog()

    def _summary(self, tool: dict) -> str:
        desc = (tool.get("description") or "").split(". ")[0].strip()
        return f"{tool['name']}: {desc}"

    def index_tokens(self) -> int:
        """Tokens the model always pays: the two meta-tool schemas + nothing else."""
        meta = [
            {"name": "tool_search", "description": "Search available tools by intent; "
             "returns ranked tool names and one-line summaries.",
             "inputSchema": {"type": "object", "properties": {
                 "query": {"type": "string", "description": "What you want to do."}},
                 "required": ["query"]}},
            {"name": "tool_load", "description": "Load the full schema for one tool by name.",
             "inputSchema": {"type": "object", "properties": {
                 "name": {"type": "string", "description": "Exact tool name."}},
                 "required": ["name"]}},
        ]
        return count_tokens(json.dumps(meta, separators=(",", ":")))

    def search(self, query: str, k: int = 3) -> list[dict]:
        q = _terms(query)
        scored = []
        for t in self.tools:
            hay = _terms(t.get("name", "")) | _terms(t.get("description", ""))
            name_bonus = 3 if q & _terms(t.get("name", "")) else 0
            score = len(q & hay) + name_bonus
            scored.append((score, t))
        scored.sort(key=lambda x: (-x[0], x[1]["name"]))
        return [t for s, t in scored[:k] if s > 0] or [scored[0][1]]

    def load(self, name: str) -> dict | None:
        for t in self.tools:
            if t["name"] == name:
                return t
        return None

    def cost_for_task(self, query: str, k: int = 3) -> dict:
        """Tokens actually paid for a task: index + search results + 1 loaded tool."""
        hits = self.search(query, k)
        search_result = [{"name": t["name"], "summary": self._summary(t)} for t in hits]
        loaded = self.load(hits[0]["name"])
        total = (
            self.index_tokens()
            + count_tokens(json.dumps(search_result, separators=(",", ":")))
            + count_tokens(json.dumps(loaded, separators=(",", ":")))
        )
        return {"index": self.index_tokens(), "n_hits": len(hits),
                "loaded": hits[0]["name"], "tokens_paid": total}
