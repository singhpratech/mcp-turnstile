"""
unicode_forensics.py — context-aware detection of text-concealment techniques.

Given a string (e.g. a tool description), analyze() returns a report with:
  - findings: one per detected technique, with severity + human-readable evidence
  - views:    human (rendered), model (logical codepoints), decoded (recovered payload)
  - capacity: hidden bytes recoverable with ~zero visible-glyph change
  - sanitized: a defensively cleaned string safe to show a model

The guiding rule (see attacks/i18n_corpus.py): NEVER high-flag a codepoint that
is legitimately needed for a language or emoji. We distinguish attack from i18n
by CONTEXT — runs, balance, adjacency, script mixing — not by the codepoint alone.

Stdlib only. Approximations (e.g. "emoji" = a coarse pictographic range) are
documented inline; a production build would use the full UTS #39 / UTS #51 data.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Greek letters that are commonly legitimate as math symbols / units (μs, θ, Ω).
GREEK_MATH = set("μθΩπλσΔαβγδεφψωτΦΣΠ")

# --- codepoint sets --------------------------------------------------------
TAG_LO, TAG_HI = 0xE0000, 0xE007F
WAVING_FLAG = 0x1F3F4
ZWJ, ZWNJ = 0x200D, 0x200C
ZW_STEG = {0x200B, 0x2060, 0xFEFF}                 # abused for zero-width binary
BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}  # LRE RLE PDF LRO RLO
BIDI_ISOLATE = {0x2066, 0x2067, 0x2068, 0x2069}    # LRI RLI FSI PDI
VS_LO1, VS_HI1 = 0xFE00, 0xFE0F                    # variation selectors
VS_LO2, VS_HI2 = 0xE0100, 0xE01EF                  # variation selectors supplement
_RLO, _LRO, _PDF = chr(0x202E), chr(0x202D), chr(0x202C)  # named, not literal, controls


def _is_pictographic(cp: int) -> bool:
    """Coarse Extended_Pictographic approximation."""
    return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or cp in (0x203C, 0x2049, 0x2764)


def _script(ch: str) -> str:
    o = ord(ch)
    if 0x0400 <= o <= 0x04FF:
        return "Cyrillic"
    if 0x0370 <= o <= 0x03FF:
        return "Greek"
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or 0x00C0 <= o <= 0x024F:
        return "Latin"
    return "other"


@dataclass
class Finding:
    technique: str
    severity: str            # "high" | "low"
    evidence: str
    hidden_bytes: int = 0


@dataclass
class Report:
    text: str
    findings: list[Finding] = field(default_factory=list)
    human_view: str = ""
    model_view: str = ""
    decoded_payload: str = ""
    sanitized: str = ""

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def capacity(self) -> int:
        return sum(f.hidden_bytes for f in self.findings)


# --- per-technique detectors ----------------------------------------------
def _detect_tag(text: str) -> Finding | None:
    # single forward pass (O(n)): track whether the char before the current TAG
    # run was a base flag emoji, so a whole run is classified once.
    run, legit = 0, 0
    prev_was_flag = False
    in_tag = False
    for ch in text:
        o = ord(ch)
        if TAG_LO <= o <= TAG_HI:
            if not in_tag:
                in_tag = True  # start of a run; prev_was_flag already set below
            if prev_was_flag:
                legit += 1
            else:
                run += 1
        else:
            in_tag = False
            prev_was_flag = (o == WAVING_FLAG)
    if run:
        return Finding("TAG-block mirror", "high",
                       f"{run} standalone TAG codepoints (not part of a flag emoji)",
                       hidden_bytes=run)
    if legit:
        return Finding("TAG-block (flag emoji)", "low",
                       f"{legit} TAG codepoints inside a valid flag sequence")
    return None


def _detect_zwbin(text: str) -> Finding | None:
    # TOTAL steg zero-width codepoints is the signal (>=8 ~= 1 smuggled byte).
    # We track the total, not just the longest run, so an attacker can't evade by
    # chunking the payload with a normal char every few bits.
    best = cur = total = 0
    for ch in text:
        if ord(ch) in ZW_STEG:
            cur += 1
            total += 1
            best = max(best, cur)
        else:
            cur = 0
    if total >= 8:
        return Finding("Zero-width binary", "high",
                       f"{total} zero-width steg codepoints (longest run {best}; ~{total // 8} bytes)",
                       hidden_bytes=total // 8)
    if total:
        return Finding("Zero-width", "low", f"{total} isolated zero-width codepoint(s)")
    return None


def _detect_bidi(text: str) -> Finding | None:
    overrides = sum(1 for ch in text if ord(ch) in BIDI_OVERRIDE)
    # overrides (RLO/LRO/RLE/LRE) inside otherwise-LTR text are the Trojan-Source
    # signal; balanced isolates around real RTL script are legitimate (low).
    if overrides:
        # count how much text is *reordered* by the override
        hidden = 0
        i = 0
        while i < len(text):
            if ord(text[i]) in (0x202E, 0x202D):  # RLO / LRO
                j = text.find(_PDF, i + 1)
                hidden += (j - i - 1) if j != -1 else (len(text) - i - 1)
                i = j + 1 if j != -1 else len(text)
            else:
                i += 1
        # bidi hides NOTHING — it reorders display. hidden_bytes stays 0 so the
        # lab's capacity totals stay honest.
        return Finding("Bidi Trojan-Source", "high",
                       f"{overrides} bidi override control(s); ~{hidden} chars display-reordered",
                       hidden_bytes=0)
    isolates = sum(1 for ch in text if ord(ch) in BIDI_ISOLATE)
    if isolates:
        return Finding("Bidi isolate (i18n)", "low", f"{isolates} balanced isolate control(s)")
    return None


def _detect_vs(text: str) -> Finding | None:
    chain = legit = 0
    prev_pict = False
    for ch in text:
        o = ord(ch)
        is_vs = (VS_LO1 <= o <= VS_HI1) or (VS_LO2 <= o <= VS_HI2)
        if is_vs:
            # one VS right after a pictographic/CJK base is legitimate presentation;
            # a CHAIN, or VS after a plain letter, is smuggling.
            if prev_pict and chain == 0:
                legit += 1
            else:
                chain += 1
        else:
            prev_pict = _is_pictographic(o) or (0x3000 <= o <= 0x9FFF)
            continue
        prev_pict = False
    if chain:
        return Finding("Variation-selector smuggling", "high",
                       f"chain of {chain} variation selectors (~{chain} bytes)",
                       hidden_bytes=chain)
    if legit:
        return Finding("Variation selector (presentation)", "low",
                       f"{legit} presentation variation selector(s)")
    return None


def _detect_homoglyph(text: str) -> Finding | None:
    # Signal = a SINGLE word-piece mixing Latin with Cyrillic/Greek (the classic
    # confusable spoof, e.g. "gеt_issue" with a Cyrillic 'е'). We split on
    # separators so a legitimately bilingual token like "GitHub-репозиторий"
    # (each side single-script) is NOT flagged, and we exempt Greek used as a
    # math symbol / unit (e.g. "10μs", "θx"). NOTE (documented limitation): a
    # WHOLLY non-Latin spoof like all-Cyrillic "ѕсоре" is not detected here,
    # because a skeleton-to-ASCII heuristic would false-positive on real Cyrillic
    # words — cross-catalog skeleton collision is the right place to catch that.
    for raw in re.split(r"\s+", text):
        for token in re.split(r"[-_/.]", raw):
            if not token:
                continue
            has_digit = any(c.isdigit() for c in token)
            scripts = set()
            for ch in token:
                s = _script(ch)
                if s == "Greek" and (has_digit or ch in GREEK_MATH):
                    continue  # math/unit Greek — legitimate
                if s in ("Latin", "Cyrillic", "Greek"):
                    scripts.add(s)
            if len(scripts) >= 2:
                return Finding("Homoglyph spoof", "high",
                               f"token mixes scripts within one word: {token!r}")
    return None


# --- rendering / sanitization ----------------------------------------------
def _human_render(text: str) -> str:
    """Simplified renderer: apply bidi overrides (reverse), drop invisible/steg."""
    out, i = [], 0
    while i < len(text):
        o = ord(text[i])
        if o == 0x202E or o == 0x202D:  # RLO / LRO -> reverse to PDF
            j = text.find(_PDF, i + 1)
            j = len(text) if j == -1 else j
            out.append(text[i + 1 : j][::-1])
            i = j + 1
            continue
        if (TAG_LO <= o <= TAG_HI) or o in ZW_STEG or o == 0x202C \
                or (VS_LO2 <= o <= VS_HI2):
            i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _sanitize(text: str) -> str:
    """Remove context-suspicious concealment while preserving legitimate i18n.
    Single forward pass (O(n)): a TAG run is kept only if the char before it was
    a base flag emoji."""
    out = []
    prev_was_flag = False
    for ch in text:
        o = ord(ch)
        if TAG_LO <= o <= TAG_HI:
            if prev_was_flag:      # part of a legitimate flag sequence
                out.append(ch)
            # else: standalone TAG -> drop
            continue               # prev_was_flag unchanged across the TAG run
        prev_was_flag = (o == WAVING_FLAG)
        # drop steg zero-width and bidi overrides; keep isolates/marks + ZWNJ/ZWJ
        if o in ZW_STEG or o in BIDI_OVERRIDE:
            continue
        # drop VS-supplement chains (keep single FE00-FE0F presentation selectors)
        if VS_LO2 <= o <= VS_HI2:
            continue
        out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


# --- public API ------------------------------------------------------------
_DETECTORS = (_detect_tag, _detect_zwbin, _detect_bidi, _detect_vs, _detect_homoglyph)


def analyze(text: str) -> Report:
    rep = Report(text=text)
    for det in _DETECTORS:
        f = det(text)
        if f is not None:
            rep.findings.append(f)
    rep.human_view = _human_render(text)
    rep.model_view = "".join(
        ch for ch in text
        if not (0x202A <= ord(ch) <= 0x202E)  # model sees logical order, sans controls
    )
    rep.sanitized = _sanitize(text)

    # best-effort payload recovery, for the demo's "what the model really got".
    # Optional: defenses must not hard-depend on the attack library, so this is
    # guarded — if attacks/ is absent (e.g. defenses/ shipped alone), we simply
    # skip payload recovery. Detection above does not need it.
    try:
        from attacks import concealment as C
        for dec in (C.tag_decode, C.zwbin_decode, C.vs_decode, C.bidi_decode, C.homoglyph_decode):
            got = dec(text)
            if got and got.strip() and got != text:
                rep.decoded_payload = got.strip()
                break
    except ImportError:
        pass
    return rep
