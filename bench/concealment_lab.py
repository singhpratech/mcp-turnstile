#!/usr/bin/env python3
"""
concealment_lab.py — the enhanced Unicode-concealment proof-of-concept.

Three parts:
  A. ATTACKS   — run all 5 concealment techniques against a benign visible
                 description, showing human-view vs model-view, hidden capacity,
                 and whether the forensics detector catches each.
  B. LEGIT     — run the whole legitimate-i18n corpus through the same detector
                 and confirm ZERO false positives (no high-severity flags).
  C. MATRIX    — a summary table: invisible? capacity? detected? false-pos-free?

All strings are local and inert. No network, no execution.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import concealment as C  # noqa: E402
from attacks.i18n_corpus import CORPUS  # noqa: E402
from defenses import unicode_forensics as F  # noqa: E402

VISIBLE = "Gets the contents of a single issue."


def _glyphs(s: str) -> str:
    """Approx what a human sees: drop invisibles, apply bidi, collapse."""
    return F._human_render(s)


def part_a() -> list[dict]:
    print("=" * 78)
    print("  PART A — 5 concealment techniques vs. a benign description")
    print("=" * 78)
    rows = []
    for t in C.TECHNIQUES:
        hidden = None if t.key == "homoglyph" else C.PAYLOAD
        if t.key == "homoglyph":
            # spoof a trusted tool NAME instead of hiding a payload in a description
            malicious = t.encode("get_issue")
            subject = "tool name 'get_issue'"
        else:
            malicious = t.encode(VISIBLE, hidden)
            subject = "description"

        rep = F.analyze(malicious)
        human = _glyphs(malicious)
        caught = bool(rep.high)

        print(f"\n[{t.key}] {t.title}")
        print(f"   mechanism : {t.mechanism}")
        print(f"   collides w: {t.legit_collision}")
        print(f"   subject   : {subject}")
        print(f"   human sees: {human!r}")
        if t.key == "homoglyph":
            print(f"   skeleton  : {C.homoglyph_decode(malicious)!r}  (<- the impersonation)")
        else:
            print(f"   model gets: {(rep.decoded_payload or '(none recovered)')!r}")
        vis_delta = abs(len(human) - len(_glyphs(VISIBLE if t.key != 'homoglyph' else 'get_issue')))
        print(f"   visible-glyph delta vs clean: {vis_delta}")
        print(f"   hidden capacity: {rep.capacity} bytes")
        for f in rep.findings:
            mark = "🚩" if f.severity == "high" else "·"
            print(f"     {mark} [{f.severity}] {f.technique}: {f.evidence}")
        print(f"   DETECTOR VERDICT: {'CAUGHT' if caught else 'MISSED'}")
        rows.append({
            "key": t.key, "title": t.title,
            # homoglyph is visually IDENTICAL, not invisible; bidi reorders (delta>0)
            "invisible": vis_delta == 0 and t.key != "homoglyph",
            "capacity": rep.capacity, "caught": caught,
        })
    return rows


def part_b() -> dict:
    print("\n" + "=" * 78)
    print("  PART B — legitimate i18n corpus (must produce ZERO high-severity flags)")
    print("=" * 78)
    false_positives = []
    for key, text, desc in CORPUS:
        rep = F.analyze(text)
        highs = rep.high
        note = ", ".join(f"{f.technique}[{f.severity}]" for f in rep.findings) or "clean"
        status = "OK" if not highs else "FALSE POSITIVE"
        if highs:
            false_positives.append(key)
        print(f"   {status:15s} {key:16s} {desc:34s} -> {note}")
    ok = not false_positives
    print(f"\n   false positives: {len(false_positives)} "
          f"({'PASS — detector is i18n-safe' if ok else 'FAIL: ' + ', '.join(false_positives)})")
    return {"false_positive_free": ok, "count": len(false_positives)}


def part_c(rows: list[dict], legit: dict) -> None:
    print("\n" + "=" * 78)
    print("  PART C — summary matrix")
    print("=" * 78)
    hdr = f"  {'technique':28s} | {'invisible':>9} | {'hidden bytes':>12} | {'detected':>8}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        print(f"  {r['title']:28s} | {('yes' if r['invisible'] else 'no'):>9} | "
              f"{r['capacity']:>12} | {('yes' if r['caught'] else 'NO'):>8}")
    caught = sum(1 for r in rows if r["caught"])
    print("  " + "-" * (len(hdr) - 2))
    print(f"\n  techniques caught          : {caught}/{len(rows)}")
    print(f"  legitimate i18n false-pos  : {legit['count']} "
          f"({'i18n-safe' if legit['false_positive_free'] else 'UNSAFE'})")
    invis = [r for r in rows if r["invisible"] and r["capacity"]]
    total_hidden = sum(r["capacity"] for r in invis)
    print(f"  total payload smuggled     : {total_hidden} bytes across "
          f"{len(invis)} fully-invisible channels")
    print("\n  Takeaway: every channel abuses a mechanism that is ALSO legitimate")
    print("  somewhere. Banning the codepoints breaks the Part B corpus; only")
    print("  context-aware detection catches Part A while leaving Part B intact.")


def main() -> None:
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("=" * 78)
    print("  mcp-turnstile — UNICODE CONCEALMENT FORENSICS LAB (local, inert)")
    print("=" * 78)
    rows = part_a()
    legit = part_b()
    part_c(rows, legit)


if __name__ == "__main__":
    main()
