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

Stdlib only. Detection keys off structural context, not codepoint identity: a
single variation selector after a VISIBLE base is legitimate (a run, or singles
orphaned onto invisible bases, is a byte chain); zero-width is a payload only as a
run or a dense/repeating cluster, never as isolated word-breaks; bidi is flagged
only on RLO/LRO overrides, not embeddings/isolates; homoglyph uses the
Latin-targeting subset of UTS #39 plus the canonical Latin-look-alike scripts. A
production build would consult the full UTS #39 / UTS #51 data tables (and would
pin a Unicode version so two runtimes' category tables cannot differ); the curated
sets here are documented inline and exercised by attacks/i18n_corpus.py.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Cyrillic/Greek codepoints that impersonate a Latin letter (the Latin-targeting
# subset of the UTS #39 confusables). We flag a homoglyph spoof only when one of
# THESE appears inside a Latin word — so genuine Greek math letters (η, ξ, β, μ,
# λ, Ω, …) glued to Latin (e.g. "ηmax", "10μs") are NOT false-flagged, because
# they do not look like Latin letters and so are absent from this set.
LATIN_CONFUSABLES = {
    # Cyrillic lowercase → Latin
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, 0x0455, 0x0456,
    0x0458, 0x0501, 0x0475, 0x04BB, 0x051B, 0x051D, 0x04CF,   # …һ ԛ ԝ ӏ
    # Cyrillic uppercase → Latin
    0x0410, 0x0412, 0x0415, 0x0417, 0x041A, 0x041C, 0x041D, 0x041E, 0x0420,
    0x0421, 0x0422, 0x0423, 0x0425, 0x0405, 0x0406, 0x0408,
    # Greek uppercase that look Latin, plus lowercase omicron/rho/lunate-sigma
    0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C, 0x039D,
    0x039F, 0x03A1, 0x03A4, 0x03A5, 0x03A7, 0x03BF, 0x03F2,
}

# Whole scripts whose letters are canonical Latin look-alikes (Cherokee, Lisu,
# Canadian Aboriginal Syllabics, Coptic, Vai, Deseret, Osage). Unlike Greek
# (legit as math glued to Latin) and Armenian (agglutinates onto Latin brand
# words), these have NO legitimate mixed-with-Latin use inside a single token, so
# ANY such letter in a Latin word is a spoof.
def _is_confusable_script(o: int) -> bool:
    # NB: Armenian is deliberately excluded — it agglutinates case suffixes
    # directly onto Latin brand/loan words (e.g. "Googleում"), so treating its
    # letters as spoofs would false-positive on legitimate Armenian text.
    return (0x13A0 <= o <= 0x13FF or 0xAB70 <= o <= 0xABBF        # Cherokee
            or 0xA4D0 <= o <= 0xA4FF                              # Lisu
            or 0x1400 <= o <= 0x167F or 0x18B0 <= o <= 0x18FF     # Canadian syllabics
            or 0x2C80 <= o <= 0x2CFF                              # Coptic
            or 0xA500 <= o <= 0xA63F                              # Vai
            or 0x10400 <= o <= 0x1044F or 0x104B0 <= o <= 0x104FF)  # Deseret, Osage


# --- codepoint sets --------------------------------------------------------
TAG_LO, TAG_HI = 0xE0000, 0xE007F
TAG_TERM = 0xE007F                                 # CANCEL TAG — terminates a flag
WAVING_FLAG = 0x1F3F4
ZWJ, ZWNJ = 0x200D, 0x200C
# zero-advance / invisible-format codepoints abused for zero-width binary. Beyond
# the classic trio we include Hangul fillers, invisible math operators, and the
# Mongolian vowel separator so an attacker cannot switch to an off-list alphabet.
ZW_STEG = ({0x200B, 0x2060, 0xFEFF, 0x115F, 0x1160, 0x3164, 0xFFA0,
            0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0x00AD}
           | set(range(0x1D173, 0x1D17B)))   # + soft-hyphen and musical-beam format controls
BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E}  # LRE RLE PDF LRO RLO (all dropped on sanitize)
BIDI_STRONG_OVERRIDE = {0x202D, 0x202E}            # LRO / RLO — reorder even in RTL context
BIDI_EMBED = {0x202A, 0x202B}                      # LRE / RLE — legit only amid real RTL text
BIDI_ISOLATE = {0x2066, 0x2067, 0x2068, 0x2069}    # LRI RLI FSI PDI
VS_LO1, VS_HI1 = 0xFE00, 0xFE0F                    # variation selectors
VS_LO2, VS_HI2 = 0xE0100, 0xE01EF                  # variation selectors supplement
FVS_LO, FVS_HI = 0x180B, 0x180D                    # Mongolian free variation selectors
_RLO, _LRO, _PDF = chr(0x202E), chr(0x202D), chr(0x202C)  # named, not literal, controls


def _valid_flag_tagchar(o: int) -> bool:
    """Tag chars legitimately used in an emoji subdivision-flag region code:
    tag digits (U+E0030–E0039) and tag lowercase letters (U+E0061–E007A)."""
    return 0xE0030 <= o <= 0xE0039 or 0xE0061 <= o <= 0xE007A


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
    # A legitimate subdivision-flag emoji is EXACTLY: base U+1F3F4, then 1..6
    # region tag chars (tag digits / lowercase), then the U+E007F terminator.
    # We validate that shape, so a payload appended after a flag emoji — extra
    # tag chars, non-region chars, or anything past the terminator — is counted
    # as a standalone concealed run, not waved through as "part of a flag".
    standalone, legit = 0, 0
    i, n = 0, len(text)
    while i < n:
        o = ord(text[i])
        if o == WAVING_FLAG:
            j, k = i + 1, 0
            while j < n and _valid_flag_tagchar(ord(text[j])) and k < 6:
                j += 1
                k += 1
            if k >= 1 and j < n and ord(text[j]) == TAG_TERM:
                legit += k          # well-formed flag: base + region + terminator
                i = j + 1
                continue
            i += 1                  # lone/malformed flag base — following TAGs are standalone
        elif TAG_LO <= o <= TAG_HI:
            standalone += 1
            i += 1
        else:
            i += 1
    if standalone:
        return Finding("TAG-block mirror", "high",
                       f"{standalone} standalone TAG codepoints (not a valid flag sequence)",
                       hidden_bytes=standalone)
    if legit:
        return Finding("TAG-block (flag emoji)", "low",
                       f"{legit} TAG codepoints inside a valid flag sequence")
    return None


def zero_width_is_stego(text: str) -> bool:
    """True when zero-width (ZWSP / WORD-JOINER / BOM) usage looks like a binary
    payload rather than legitimate word-breaking or no-break joining.

    The distinguisher is CONTEXT, not the codepoint:
      * a consecutive RUN of >=3 zero-width controls — no legitimate tool
        metadata stacks even three (the densest legit case, Hangul isolated-jamo
        display, uses at most two adjacent fillers), so a run of 3+ is a packed
        bit-string; OR
      * >=16 total that ALSO show run structure (a run of >=2) — a payload
        chunked into pairs/triples to dodge the run test still repeats; OR
      * >=16 total at high density among the visible-printable text — a payload
        interleaved with other invisibles to break runs still reads dense, because
        the density denominator counts only printable (non-C/M) characters.
    Legitimate word/line-break use in no-space scripts (Thai, Lao, Khmer, Burmese,
    Tibetan, short-token CJK) is ISOLATED singletons between real words — max run
    1, low density — so no branch fires. (Documented residual: a payload spread as
    strictly isolated singletons AND diluted below 30% density evades — but that
    requires padding the text to several times the payload length, which is
    conspicuous by sheer length.)
    """
    total = max_run = run = printable = 0
    for ch in text:
        o = ord(ch)
        if o in ZW_STEG:
            run += 1
            total += 1
            if run > max_run:
                max_run = run
        else:
            run = 0
            # count only printable text toward density; other format/control/
            # combining codepoints must not act as payload-diluting "filler".
            if unicodedata.category(ch)[0] not in ("C", "M"):
                printable += 1
    if max_run >= 3:
        return True
    return total >= 16 and (max_run >= 2 or total / (total + printable) >= 0.30)


def _detect_zwbin(text: str) -> Finding | None:
    total = max_run = run = 0
    for ch in text:
        if ord(ch) in ZW_STEG:
            run += 1
            total += 1
            if run > max_run:
                max_run = run
        else:
            run = 0
    if total == 0:
        return None
    if zero_width_is_stego(text):
        return Finding("Zero-width binary", "high",
                       f"{total} zero-width steg codepoints (longest run {max_run}; ~{total // 8} bytes)",
                       hidden_bytes=max(1, total // 8))
    return Finding("Zero-width", "low",
                   f"{total} isolated zero-width codepoint(s) (word-break / joiner)")


def _detect_bidi(text: str) -> Finding | None:
    # Only RLO (U+202E) / LRO (U+202D) force CHARACTER-level reordering — the
    # unambiguous Trojan-Source signal, flagged high in any context. LRE/RLE
    # embeddings, the PDF terminator, and the isolate controls (LRI/RLI/FSI/PDI)
    # are legitimate in mixed RTL/LTR text AND are the W3C/ICU-recommended way to
    # wrap interpolated values in LTR strings, so they are reported low, not high.
    # (Documented residual: an embedding/isolate-only reordering that carries no
    # RLO/LRO is not high-flagged — the classic Trojan-Source PoCs use RLO/LRO.)
    strong = sum(1 for ch in text if ord(ch) in BIDI_STRONG_OVERRIDE)
    if strong:
        hidden = 0
        i = 0
        while i < len(text):
            if ord(text[i]) in BIDI_STRONG_OVERRIDE:
                j = text.find(_PDF, i + 1)
                hidden += (j - i - 1) if j != -1 else (len(text) - i - 1)
                i = j + 1 if j != -1 else len(text)
            else:
                i += 1
        # bidi hides NOTHING — it reorders display. hidden_bytes stays 0 so the
        # lab's capacity totals stay honest.
        return Finding("Bidi Trojan-Source", "high",
                       f"{strong} directional-override control(s) (RLO/LRO); ~{hidden} chars display-reordered",
                       hidden_bytes=0)
    soft = sum(1 for ch in text if ord(ch) in BIDI_EMBED or ord(ch) in BIDI_ISOLATE)
    if soft:
        return Finding("Bidi embedding/isolate (i18n)", "low",
                       f"{soft} bidi embedding/isolate control(s)")
    return None


def _is_vs(o: int) -> bool:
    # emoji/text presentation selectors, VS supplement (CJK IVS), and Mongolian
    # free variation selectors — all "one-per-base" by design.
    return (VS_LO1 <= o <= VS_HI1) or (VS_LO2 <= o <= VS_HI2) or (FVS_LO <= o <= FVS_HI)


def _detect_vs(text: str) -> Finding | None:
    # A base glyph takes at MOST one variation selector. So a single selector
    # after a VISIBLE base is legitimate presentation regardless of what the base
    # is — clearing keycaps (1️⃣), ©️/®️/™️, arrows, media symbols, CJK IVS, and a
    # long list of legitimate emoji. Smuggling shows up two ways: a RUN of >=2
    # consecutive selectors (a byte chain), or selectors spread one-per-base where
    # the "base" is an invisible/control/space char or nothing (an ORPHAN selector
    # — no glyph to modify). Legit text never orphans a selector.
    chain_total = legit = orphan = run = 0
    base: str | None = None  # last non-VS codepoint before the current run

    def _close(run: int, base: str | None) -> None:
        nonlocal chain_total, legit, orphan
        if run == 1:
            if base is None or unicodedata.category(base)[0] in ("C", "Z") or _is_vs(ord(base)):
                orphan += 1
            else:
                legit += 1
        elif run >= 2:
            chain_total += run

    for ch in text:
        if _is_vs(ord(ch)):
            run += 1
        else:
            _close(run, base)
            run = 0
            base = ch
    _close(run, base)

    if chain_total or orphan >= 4:
        total = chain_total + orphan
        return Finding("Variation-selector smuggling", "high",
                       f"{total} smuggling variation selectors (chains {chain_total}, orphan singles {orphan}; ~{total} bytes)",
                       hidden_bytes=max(1, total))
    if legit:
        return Finding("Variation selector (presentation)", "low",
                       f"{legit} single presentation/IVS selector(s)")
    return None


# whitespace class shared with the TS port (explicit, NOT \s, whose members
# differ across languages): ASCII WS + the Unicode space separators.
_WS_SPLIT = "[ \t\n\r\f\v\u00a0]+"


def _detect_homoglyph(text: str) -> Finding | None:
    # Signal = a Latin word that hides a Cyrillic/Greek character which IMPERSONATES
    # a Latin letter (the classic confusable spoof, e.g. "gеt_issue" with a
    # Cyrillic 'е'). We key off LATIN_CONFUSABLES — the Latin-look-alike subset of
    # UTS #39 — instead of "any script mixing", so:
    #   * "ηmax", "ξmin", "βcarotene", "10μs", "10kΩ" are clean (η/ξ/β/μ/Ω do not
    #     look like Latin letters and so are not confusables);
    #   * "GitHub-репозиторий" is clean (each side is single-script; the Cyrillic
    #     token has no Latin letter to impersonate within it);
    #   * a pure-Greek word like "Ελληνικά" is clean (no Latin letter in the token).
    # NOTE (documented limitation): a WHOLLY non-Latin spoof like all-Cyrillic
    # "ѕсоре" is out of scope here — cross-catalog skeleton collision is the right
    # place to catch that without false-positiving on real Cyrillic words.
    # explicit whitespace class (NOT \s) so Python and the TS port tokenise
    # identically — their \s disagree on U+FEFF, U+0085, and U+001C–U+001F.
    for raw in re.split(_WS_SPLIT, text):
        for token in re.split(r"[-_/.]", raw):
            if not token:
                continue
            has_latin = any(_script(ch) == "Latin" for ch in token)
            confusables = [ch for ch in token
                           if ord(ch) in LATIN_CONFUSABLES or _is_confusable_script(ord(ch))]
            if has_latin and confusables:
                return Finding("Homoglyph spoof", "high",
                               f"Latin word contains a Latin-confusable character "
                               f"U+{ord(confusables[0]):04X}: {token!r}")
    return None


def _joinable(ch: str) -> bool:
    # letters, marks, AND numbers count: a ZWNJ between a digit and a suffix is a
    # legitimate Persian/Urdu half-space (e.g. "۲‌نفره" = "2-person"), not steg.
    o = ord(ch)
    return (o >= 0x1F000 or 0x2600 <= o <= 0x27BF or o in (0x203C, 0x2049, 0x2764)
            or unicodedata.category(ch)[0] in ("L", "M", "N"))


def _detect_zwj_bin(text: str) -> Finding | None:
    # ZWJ (U+200D) / ZWNJ (U+200C) are legitimate BETWEEN joinables — emoji
    # sequences, Persian/Indic conjuncts — even at a truncated boundary. Used as a
    # 0/1 bit alphabet they sit beside each other or non-joinables, i.e. "stray".
    # Legit text has ~0 stray; a payload needs many, so we threshold the count.
    stray = 0
    n = len(text)
    for i, ch in enumerate(text):
        if ord(ch) in (ZWJ, ZWNJ):
            left = _joinable(text[i - 1]) if i > 0 else None
            right = _joinable(text[i + 1]) if i + 1 < n else None
            present = [v for v in (left, right) if v is not None]
            if not (present and all(present)):
                stray += 1
    if stray >= 4:
        return Finding("Zero-width binary", "high",
                       f"{stray} stray zero-width joiners used as a bit alphabet (~{stray // 8} bytes)",
                       hidden_bytes=max(1, stray // 8))
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
_DETECTORS = (_detect_tag, _detect_zwbin, _detect_zwj_bin, _detect_bidi, _detect_vs, _detect_homoglyph)


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
