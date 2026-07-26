"""
scan.py — the scan engine: connect, pull tools/list, and build a report card.

Reuses the project's measurement + defense libraries so the CLI reports exactly
what the benchmark proves:
  - token tax (full vs. minimal-schema floor, per-tool, worst offenders)
  - metadata-safety findings (poisoning / concealment / rug-pull) via the
    i18n-honest mediator + unicode forensics
  - progressive-disclosure potential at the same boundary
  - optional cross-run digest pinning for real rug-pull detection over time
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from defenses.mediator import CatalogPinner, mediate_catalog
from defenses.progressive import ProgressiveCatalog
from harness.mcpkit import count_tokens, measure, tokenizer_name


def _full(tools: list[dict]) -> str:
    return json.dumps(tools, separators=(",", ":"), ensure_ascii=False)


def _minimal(tools: list[dict]) -> str:
    lines = []
    for t in tools:
        desc = (t.get("description") or "").split(". ")[0].strip()
        props = (t.get("inputSchema") or {}).get("properties") or {}
        params = ",".join(f"{k}:{v.get('type','any')}" for k, v in props.items() if isinstance(v, dict))
        lines.append(f"{t.get('name','?')}({params}) - {desc}")
    return "\n".join(lines)


@dataclass
class ScanReport:
    server: str = ""
    transport: str = ""
    tokenizer: str = ""
    window: int = 200_000
    n_tools: int = 0
    full_tokens: int = 0
    minimal_tokens: int = 0
    ratio: float = 0.0
    pct_context: float = 0.0
    per_tool: list[dict] = field(default_factory=list)      # [{name,tokens}]
    findings: list[dict] = field(default_factory=list)      # [{tool,severity,kind,detail}]
    progressive: dict = field(default_factory=dict)
    grades: dict = field(default_factory=dict)

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "high")

    @property
    def rug_pulls(self) -> int:
        return sum(1 for f in self.findings if f["kind"] == "rug-pull")

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in (
            "server", "transport", "tokenizer", "window", "n_tools",
            "full_tokens", "minimal_tokens", "ratio", "pct_context",
            "per_tool", "findings", "progressive", "grades")}
        d["high_findings"] = self.high
        return d


def _grade(pct: float, high: int) -> dict:
    if pct < 5:
        eff = "A"
    elif pct < 12:
        eff = "B"
    elif pct < 20:
        eff = "C"
    else:
        eff = "D"
    sec = "A" if high == 0 else ("C" if high <= 2 else "F")
    return {"efficiency": eff, "safety": sec}


def scan(client, window: int = 200_000, pin_path: str | None = None,
         example_task: str = "create a new item") -> ScanReport:
    info = client.initialize()
    tools = client.list_tools()
    server = (info.get("serverInfo") or {}).get("name", "<unknown>") if isinstance(info, dict) else "<unknown>"

    rep = ScanReport(server=server, transport=getattr(client, "transport", "?"),
                     tokenizer=tokenizer_name(), window=window, n_tools=len(tools))

    # ---- token tax ----
    fm = measure(_full(tools)) if tools else {"tokens": 0}
    mm = measure(_minimal(tools)) if tools else {"tokens": 0}
    rep.full_tokens = fm["tokens"]
    rep.minimal_tokens = mm["tokens"]
    rep.ratio = round(fm["tokens"] / mm["tokens"], 2) if mm["tokens"] else 0.0
    rep.pct_context = round(100.0 * fm["tokens"] / window, 1) if window else 0.0
    rep.per_tool = sorted(
        ({"name": t.get("name", "?"), "tokens": measure(json.dumps(t, separators=(",", ":"), ensure_ascii=False))["tokens"]}
         for t in tools), key=lambda x: -x["tokens"])

    # ---- metadata safety (with optional cross-run pinning) ----
    pinner = CatalogPinner()
    if pin_path and os.path.exists(pin_path):
        try:
            with open(pin_path) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):  # ignore a hand-edited file of the wrong shape
                pinner._pins = loaded
        except Exception:
            pass
    result = mediate_catalog(tools, pinner=pinner, provenance=server)
    rep.findings = [{"tool": f.tool, "severity": f.severity, "kind": f.kind, "detail": f.detail}
                    for f in result.findings]
    if pin_path:
        try:
            with open(pin_path, "w") as f:
                json.dump(pinner._pins, f)
        except Exception:
            pass

    # ---- progressive-disclosure potential ----
    if tools:
        clean = [{k: v for k, v in t.items() if not k.startswith("_")} for t in result.cleaned_tools]
        pc = ProgressiveCatalog(clean)
        baseline = count_tokens(_full(clean))
        cost = pc.cost_for_task(example_task)
        rep.progressive = {
            "index_tokens": pc.index_tokens(),
            "baseline_tokens": baseline,
            "task_tokens": cost["tokens_paid"],
            "reduction_pct": round(100.0 * (1 - cost["tokens_paid"] / baseline), 1) if baseline else 0.0,
            "example_task": example_task,
            "loaded": cost["loaded"],
        }

    rep.grades = _grade(rep.pct_context, rep.high)
    return rep
