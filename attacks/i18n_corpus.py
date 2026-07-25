"""
i18n_corpus.py — legitimate international text that uses the SAME Unicode
mechanisms the attacks abuse. The forensics detector MUST NOT high-flag any of
these, or it is useless in the real world (it would corrupt Persian, Arabic,
emoji, and flags). This corpus is the false-positive test set.

Each entry pairs a real string with the mechanism it exercises. The invisible
control characters are built from explicit codepoints (not literals) so they are
unambiguous in source; visible non-Latin text (Persian/Arabic/Hindi) is literal
by necessity.
"""

from __future__ import annotations

# --- builders (invisible controls via explicit codepoints, no mojibake) ----
ZWNJ = chr(0x200C)   # zero-width non-joiner  — mandatory in Persian
ZWJ = chr(0x200D)    # zero-width joiner       — builds emoji sequences / conjuncts
RLM = chr(0x200F)    # right-to-left mark
LRM = chr(0x200E)    # left-to-right mark
FSI, PDI = chr(0x2068), chr(0x2069)  # first-strong isolate / pop

# Persian "mikhaham" (I want) — needs a ZWNJ between the prefix and the stem.
PERSIAN = "می" + ZWNJ + "خواهم"

# Arabic + an English product name, isolated for correct rendering.
ARABIC_MIXED = "الأداة " + FSI + "GitHub" + PDI

# Hindi (Devanagari) using ZWJ/ZWNJ for correct conjunct/half-form rendering.
HINDI = "क्" + ZWJ + "ष"  # k-virama-ZWJ-ssa (conjunct form)

# Emoji ZWJ sequence: man + ZWJ + woman + ZWJ + girl = family.
FAMILY = "\U0001f468" + ZWJ + "\U0001f469" + ZWJ + "\U0001f467"

# Subdivision-flag emoji: Scotland = waving-black-flag + TAG letters "gbsct" + term.
SCOTLAND = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbsct") + "\U000e007f"

# Emoji with a legitimate single variation selector (emoji presentation).
HEART_EMOJI = "❤️"  # red heart, VS-16

# Skin-tone modifier (also a legitimate "combining"-style sequence).
WAVE = "\U0001f44b\U0001f3fd"  # waving hand + medium skin tone


CORPUS: list[tuple[str, str, str]] = [
    ("persian-zwnj", PERSIAN, "Persian word requiring ZWNJ"),
    ("arabic-isolate", ARABIC_MIXED, "Arabic + English with bidi isolates"),
    ("hindi-zwj", HINDI, "Devanagari conjunct via ZWJ"),
    ("family-emoji", "reacts with " + FAMILY, "ZWJ emoji sequence"),
    ("scotland-flag", "region: " + SCOTLAND, "subdivision-flag emoji (TAG block)"),
    ("heart-vs16", "status " + HEART_EMOJI, "emoji presentation variation selector"),
    ("skin-tone", "waves " + WAVE, "emoji skin-tone modifier"),
    ("greek-unit", "timeout after 10μs then retry", "Greek letter as a unit (μs)"),
    ("ru-latin-hyphen", "Получить GitHub-репозиторий", "Cyrillic word + Latin name, hyphen-joined"),
    ("plain-ascii", "Gets the contents of a single issue.", "control: plain English"),
]
