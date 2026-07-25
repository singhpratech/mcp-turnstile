"""
mediator.py — the tool-catalog boundary mediator.

Thesis: the optimization gap and the security gap live at the SAME chokepoint —
the moment tool metadata crosses from a server into the model's context. A
component that mediates tools/list can address both at once.

This module does the SECURITY half. IMPORTANT, HONEST SCOPE:

  - What this reliably does:
      * flag standalone invisible/concealed payloads (Unicode TAG-block runs,
        stray zero-width joiners/spaces) that create an approval-view gap;
      * byte-pin tool definitions on first sight (TOFU) and detect silent
        redefinition ("rug-pull") of the *received bytes*;
      * surface injection/exfil signals as report-card findings.

  - What this deliberately does NOT claim:
      * It is NOT prompt-injection detection. The regex signals are report-card
        hints, not a security boundary; a motivated attacker rephrases around
        them. Real defense is defense-in-depth, not this file.
      * Byte-pinning is Trust-On-First-Use. It does NOT defend against
        first-contact poisoning (a tool that is malicious the first time it is
        seen), only against later mutation.
      * A pin covers the tool-definition bytes AS RECEIVED. It does NOT cover
        the referents of any JSON Schema `$ref`: an attacker who changes what an
        external `$ref` points to is invisible to the pin. (This is why the
        parked SEP draft's schema-integrity claim was withdrawn.)

  - i18n honesty: invisible codepoints are NOT blanket-stripped. Many are
    legitimate: U+200C ZWNJ is mandatory in Persian; U+200D ZWJ builds emoji
    sequences; the TAG block encodes subdivision-flag emoji (e.g. the Scottish
    flag = U+1F3F4 + TAG letters); bidi controls are needed for Arabic/Hebrew.
    We flag context-suspicious runs (high severity) and merely note legitimate
    ones (low severity). A production tool should use a full UTS #39 / UTS #51
    aware profile; hygiene is a display-layer concern and is decoupled from any
    hashing here.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# --- invisible / format-control Unicode ------------------------------------
TAG_LO, TAG_HI = 0xE0000, 0xE007F
WAVING_BLACK_FLAG = 0x1F3F4  # base for subdivision-flag emoji sequences
ZWJ = 0x200D                 # legitimate inside emoji sequences
ZWNJ = 0x200C                # legitimate in Persian/Indic scripts
ZERO_WIDTH_SUSPICIOUS = {0x200B, 0x2060, 0xFEFF}
BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def _is_emoji(cp: int) -> bool:
    """Approximate 'Extended_Pictographic'. Documented approximation: real code
    should consult the Unicode property table; this covers the common ranges."""
    return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or cp in (0x203C, 0x2049)


def _tag_is_flag(text: str, i: int) -> bool:
    """A TAG codepoint at i is legitimate iff it belongs to a flag sequence:
    a run of TAG chars immediately preceded by U+1F3F4."""
    j = i - 1
    while j >= 0 and TAG_LO <= ord(text[j]) <= TAG_HI:
        j -= 1
    return j >= 0 and ord(text[j]) == WAVING_BLACK_FLAG


def _zwj_in_emoji(text: str, i: int) -> bool:
    """A ZWJ at i is legitimate iff it joins two 'joinable' codepoints: two
    pictographs (emoji sequence) OR two letters (e.g. a Devanagari/Indic conjunct
    like क्‍ष). Only a ZWJ NOT between joinables (stray/among a run) is suspect."""
    if i == 0 or i + 1 >= len(text):
        return False

    def joinable(ch: str) -> bool:
        # letters (L*) and combining marks (M*, e.g. the Devanagari virama U+094D
        # that precedes a ZWJ in a legitimate conjunct) both count as joinable.
        return _is_emoji(ord(ch)) or unicodedata.category(ch)[0] in ("L", "M")

    return joinable(text[i - 1]) and joinable(text[i + 1])


# --- tool-poisoning heuristics (report-card hints, NOT a boundary) ----------
_INJECTION_MARKERS = [
    re.compile(r"</?\s*IMPORTANT\s*>", re.I),
    re.compile(r"</?\s*SYSTEM\s*>", re.I),
    re.compile(r"\bignore (the |all )?(previous|prior|above)\b", re.I),
    re.compile(r"\bdo not (tell|mention|inform|reveal).{0,30}\buser\b", re.I),
    re.compile(r"\bbefore (using|calling|invoking) this tool\b", re.I),
]
_EXFIL_MARKERS = [
    re.compile(r"~?/?\.ssh/|id_rsa|id_ed25519", re.I),
    re.compile(r"\b(credentials|api[_ ]?key|secret|token|password)\b", re.I),
    re.compile(r"\b(read|exfiltrate|send|upload|include).{0,40}\b(file|contents|env)\b", re.I),
]


@dataclass
class Finding:
    tool: str
    kind: str          # "concealed-unicode" | "invisible-unicode-info" | "injection" | "exfil" | "rug-pull"
    severity: str      # "high" | "low"
    detail: str


def classify_invisible(text: str) -> list[tuple[str, str, str]]:
    """Return (category, severity, detail) for each class of invisible codepoint
    present, distinguishing context-suspicious runs from legitimate i18n."""
    seen: dict[str, tuple[str, str, str]] = {}
    for i, ch in enumerate(text):
        o = ord(ch)
        if TAG_LO <= o <= TAG_HI:
            if _tag_is_flag(text, i):
                key = ("unicode-tag-flag", "low", "TAG chars in a subdivision-flag emoji (legitimate)")
            else:
                key = ("unicode-tag-block", "high", "standalone Unicode TAG-block run (concealed payload)")
        elif o == ZWJ:
            if _zwj_in_emoji(text, i):
                key = ("zwj-emoji", "low", "zero-width joiner inside an emoji sequence (legitimate)")
            else:
                key = ("zero-width-joiner", "high", "zero-width joiner outside any emoji sequence")
        elif o == ZWNJ:
            key = ("zwnj-i18n", "low", "zero-width non-joiner (legitimate in Persian/Indic)")
        elif o in ZERO_WIDTH_SUSPICIOUS:
            key = ("zero-width", "high", f"suspicious zero-width codepoint U+{o:04X}")
        elif o in BIDI_CONTROLS:
            key = ("bidi-control-i18n", "low", "bidi format control (legitimate in Arabic/Hebrew)")
        else:
            continue
        seen[key[0]] = key
    return list(seen.values())


def has_invisible(text: str) -> list[str]:
    """Back-compat helper: category names of invisible codepoints present."""
    return [c for c, _s, _d in classify_invisible(text)]


def normalize(text: str) -> str:
    """Return text with context-SUSPICIOUS invisible codepoints removed, so that
    a display/approval view and the model view become byte-identical for the
    concealment case. Legitimate i18n codepoints (ZWNJ, bidi marks, emoji ZWJ,
    flag TAG sequences) are PRESERVED.

    NOTE: this is a DISPLAY-layer transform for approval-view parity. It is NOT
    used to compute the integrity digest (see CatalogPinner), because mixing
    normalization into a canonical hash is unsound (RFC 8785 forbids altering
    strings). Keep hygiene and hashing separate.
    """
    out = []
    for i, ch in enumerate(text):
        o = ord(ch)
        if TAG_LO <= o <= TAG_HI and not _tag_is_flag(text, i):
            continue
        if o == ZWJ and not _zwj_in_emoji(text, i):
            continue
        if o in ZERO_WIDTH_SUSPICIOUS:
            continue
        out.append(ch)
    # NFC is applied for DISPLAY parity only; never feed this into a digest.
    return unicodedata.normalize("NFC", "".join(out))


def _strip_to_ascii(text: str) -> str:
    """Map TAG codepoints back to ASCII so hidden payloads become scannable."""
    out = []
    for ch in text:
        o = ord(ch)
        if TAG_LO + 0x20 <= o <= TAG_LO + 0x7E:
            out.append(chr(o - TAG_LO))
        else:
            out.append(ch)
    return "".join(out)


def scan_tool(tool: dict[str, Any]) -> list[Finding]:
    name = tool.get("name", "<unknown>")
    findings: list[Finding] = []
    # scan the tool NAME too — homoglyph name-spoofing is a real vector.
    blobs = [tool.get("description", ""), tool.get("name", "")]
    schema = tool.get("inputSchema") or {}
    for prop in (schema.get("properties") or {}).values():
        if isinstance(prop, dict) and "description" in prop:
            blobs.append(prop["description"])
    annotations = tool.get("annotations")
    if annotations:
        # ensure_ascii=False so concealed codepoints in annotations stay scannable
        # (ensure_ascii would escape them to \uXXXX text and hide the attack).
        blobs.append(json.dumps(annotations, ensure_ascii=False))
    # DoS guard: bound per-blob scan length against a hostile server sending a
    # multi-megabyte description at the tools/list boundary.
    blobs = [b[:20000] if isinstance(b, str) else b for b in blobs]

    for blob in blobs:
        if not isinstance(blob, str):
            continue
        for cat, sev, detail in classify_invisible(blob):
            kind = "concealed-unicode" if sev == "high" else "invisible-unicode-info"
            findings.append(Finding(name, kind, sev, f"{cat}: {detail}"))
        # richer, technique-aware concealment detection (TAG / zero-width binary /
        # bidi Trojan-Source / variation-selector smuggling / homoglyph spoof),
        # i18n-safe. See defenses/unicode_forensics.py.
        from defenses import unicode_forensics as _forensics
        for ff in _forensics.analyze(blob).high:
            findings.append(Finding(name, "concealed-unicode", "high",
                                    f"{ff.technique}: {ff.evidence}"))
        decoded = _strip_to_ascii(blob)
        for probe in (blob, decoded):
            for rx in _INJECTION_MARKERS:
                if rx.search(probe):
                    findings.append(Finding(name, "injection", "high",
                                            f"injection marker: /{rx.pattern}/"))
                    break
            for rx in _EXFIL_MARKERS:
                if rx.search(probe):
                    findings.append(Finding(name, "exfil", "high",
                                            f"exfiltration signal: /{rx.pattern}/"))
                    break
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        uniq[(f.kind, f.detail)] = f
    return list(uniq.values())


class CatalogPinner:
    """Byte-pin tool definitions (TOFU); flag silent mutation (rug-pull).

    LIMITATION (honest): the digest is over the tool-definition bytes AS
    RECEIVED. It does NOT cover the referents of any JSON Schema `$ref`. An
    attacker who leaves the tool definition byte-identical but changes what an
    external `$ref` points to is NOT detected here. Do not represent this as
    schema integrity — it is definition-byte pinning only.
    """

    def __init__(self) -> None:
        self._pins: dict[str, str] = {}

    @staticmethod
    def _digest(tool: dict[str, Any]) -> str:
        # Sorted-key compact JSON over the received bytes. NOT RFC 8785, and
        # deliberately NOT normalized — see normalize() note.
        canon = json.dumps(
            {"name": tool.get("name"), "description": tool.get("description"),
             "inputSchema": tool.get("inputSchema")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        return hashlib.sha256(canon.encode()).hexdigest()

    def check(self, tool: dict[str, Any]) -> Finding | None:
        name = tool.get("name", "<unknown>")
        d = self._digest(tool)
        prev = self._pins.get(name)
        self._pins[name] = d
        if prev is not None and prev != d:
            return Finding(name, "rug-pull", "high",
                           f"definition changed since first seen ({prev[:12]}… → {d[:12]}…)")
        return None


@dataclass
class MediationResult:
    cleaned_tools: list[dict[str, Any]]
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> list[str]:
        return sorted({f.tool for f in self.findings if f.severity == "high"})


def mediate_catalog(tools: list[dict[str, Any]], pinner: CatalogPinner | None = None,
                    provenance: str | None = None) -> MediationResult:
    """Run a tools/list result through hygiene flagging + pinning + provenance."""
    findings: list[Finding] = []
    cleaned: list[dict[str, Any]] = []
    for tool in tools:
        findings.extend(scan_tool(tool))
        if pinner is not None:
            rp = pinner.check(tool)
            if rp:
                findings.append(rp)
        c = dict(tool)
        if isinstance(c.get("description"), str):
            c["description"] = normalize(c["description"])
        if provenance:
            c["_provenance"] = provenance
        cleaned.append(c)
    return MediationResult(cleaned_tools=cleaned, findings=findings)
