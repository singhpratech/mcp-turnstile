"""render.py — turn a ScanReport into a colored terminal report or JSON."""

from __future__ import annotations

import json
import os
import sys

from .scan import ScanReport

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


AMBER = lambda s: _c("33", s)
DANGER = lambda s: _c("91", s)
SAFE = lambda s: _c("92", s)
DIM = lambda s: _c("90", s)
BOLD = lambda s: _c("1", s)


def _bar(pct: float, width: int = 32) -> str:
    fill = max(0, min(width, round(pct / 100 * width)))
    return "█" * fill + "░" * (width - fill)


def render_terminal(rep: ScanReport, top: int = 5) -> str:
    L = []
    L.append(BOLD("mcp-turnstile") + DIM(f"  ·  {rep.server}  ·  {rep.transport}  ·  {rep.n_tools} tools"))
    L.append(DIM(f"tokenizer: {rep.tokenizer}"))
    L.append("")

    # token tax
    L.append(BOLD("TOKEN TAX"))
    L.append(f"  {AMBER(_bar(rep.pct_context))} {AMBER(str(rep.pct_context) + '%')} of a {rep.window // 1000}k window")
    L.append(f"  {rep.full_tokens:,} tokens for tool definitions  ·  "
             f"{rep.ratio}x over a minimal schema  ·  "
             f"{rep.full_tokens // rep.n_tools if rep.n_tools else 0} avg/tool")
    if rep.per_tool:
        L.append(DIM("  heaviest tools:"))
        for t in rep.per_tool[:top]:
            L.append(DIM(f"    {t['tokens']:>6,}  {t['name']}"))
    L.append("")

    # progressive potential
    if rep.progressive:
        p = rep.progressive
        L.append(BOLD("IF YOU DISCLOSE PROGRESSIVELY"))
        L.append(f"  index costs {p['index_tokens']:,} tokens; task '{p['example_task']}' loads "
                 f"{AMBER(p['loaded'])} for {p['task_tokens']:,} tokens")
        if p["reduction_pct"] > 0:
            L.append(f"  {SAFE(str(p['reduction_pct']) + '% fewer tokens')} per task vs. loading everything")
        else:
            L.append(DIM("  too few tools to save — progressive disclosure would cost more here"))
        L.append("")

    # safety
    L.append(BOLD("METADATA SAFETY"))
    if not rep.findings:
        L.append("  " + SAFE("✓ no concealment, poisoning, or rug-pull signals"))
    else:
        highs = [f for f in rep.findings if f["severity"] == "high"]
        lows = [f for f in rep.findings if f["severity"] != "high"]
        for f in highs:
            L.append("  " + DANGER(f"🚩 [{f['kind']}] ") + f"{f['tool']}: " + DIM(f["detail"]))
        for f in lows[:8]:
            L.append("  " + DIM(f"·  [{f['kind']}] {f['tool']}: {f['detail']}"))
        if len(lows) > 8:
            L.append(DIM(f"  … +{len(lows) - 8} more informational"))
    L.append("")

    # grades
    g = rep.grades
    seccol = SAFE if g.get("safety") == "A" else DANGER
    L.append(BOLD("GRADE") + f"   efficiency {AMBER(g.get('efficiency','?'))}   ·   safety {seccol(g.get('safety','?'))}"
             + (DANGER(f"   ({rep.high} high finding{'s' if rep.high != 1 else ''})") if rep.high else ""))
    if rep.rug_pulls:
        L.append(DANGER(f"  ⚠ {rep.rug_pulls} tool(s) changed since last scan (rug-pull)"))
    return "\n".join(L)


def render_json(rep: ScanReport) -> str:
    return json.dumps(rep.to_dict(), indent=2, ensure_ascii=False)
