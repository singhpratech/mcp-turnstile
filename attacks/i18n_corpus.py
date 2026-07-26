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

# --- broad-coverage builders (all invisibles via explicit codepoints) -------
# These turn the former false-positive air gaps into a permanent regression set:
# every mechanism the detector was hardened against is represented here, and the
# whole set MUST stay at zero high-severity flags.
ZWSP = chr(0x200B)   # word/line break in no-space scripts (Thai/Lao/Khmer/CJK)
WJ = chr(0x2060)     # WORD JOINER (no-break glue)
VS16, VS15 = chr(0xFE0F), chr(0xFE0E)   # emoji / text presentation selectors
KEYCAP = chr(0x20E3)
LRE, PDF = chr(0x202A), chr(0x202C)      # bidi embedding + terminator (legit)
FVS1 = chr(0x180B)                        # Mongolian free variation selector
ETA, BETA, XI, OMEGA, MU = chr(0x3B7), chr(0x3B2), chr(0x3BE), chr(0x3A9), chr(0x3BC)

KEYCAP_1 = "1" + VS16 + KEYCAP                              # 1️⃣
COPYRIGHT = chr(0x00A9) + VS16                             # ©️ (needs VS-16 to be emoji)
PLAY = chr(0x25B6) + VS16                                  # ▶️
ARROW_LR = chr(0x2194) + VS16                             # ↔️
WARNING = chr(0x26A0) + VS16                              # ⚠️
HEALTH_WORKER = "\U0001f468" + ZWJ + chr(0x2695) + VS16   # man health worker
RAINBOW = "\U0001f3f3" + VS16 + ZWJ + "\U0001f308"        # rainbow flag
WALES = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbwls") + chr(0xE007F)
CJK_IVS = "葛" + chr(0xE0100)                          # 葛 + ideographic VS
MONGOLIAN_FVS = "ᠭ" + FVS1                            # ᠭ + FVS1
TAMIL_CONJ = chr(0x0B95) + chr(0x0BCD) + ZWJ + chr(0x0BB7)     # Tamil conjunct
BENGALI_CONJ = chr(0x0995) + chr(0x09CD) + ZWJ + chr(0x09B7)   # Bengali conjunct
DOUBLE_STRUCK = " ".join(chr(c) for c in (0x2115, 0x2124, 0x211A, 0x211D, 0x2102))  # ℕ ℤ ℚ ℝ ℂ


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
    # --- word-break / no-break zero-width (must not read as steg) ---
    ("thai-zwsp", ZWSP.join(["ผม", "ต้องการ", "ทดสอบ", "ระบบ"]), "Thai (no spaces): ZWSP word breaks"),
    ("word-joiner", WJ.join(["C++", "std::vector", "x86_64", "UTF-8", "N/A", "Q&A", "R&D", "T&C"]),
     "WORD JOINER between techy tokens"),
    # --- single variation selectors on non-pictographic bases (all legit) ---
    ("keycap-emoji", "press " + KEYCAP_1 + " to start", "keycap emoji (VS-16 after ASCII digit)"),
    ("copyright-emoji", "notice " + COPYRIGHT + " 2026", "© with emoji-presentation VS-16"),
    ("media-play-emoji", "hit " + PLAY + " to run", "▶ media button with VS-16"),
    ("arrow-emoji", "resize " + ARROW_LR + " handle", "↔ arrow with VS-16"),
    ("warning-emoji", "note " + WARNING + " first", "⚠ warning with VS-16"),
    ("vs15-text", "plain " + chr(0x2764) + VS15, "heart with TEXT-presentation VS-15"),
    ("cjk-ivs", "kanji " + CJK_IVS, "CJK ideographic variation sequence (single IVS)"),
    ("mongolian-fvs", "word " + MONGOLIAN_FVS, "Mongolian free variation selector (single)"),
    # --- bidi embeddings (legit; only RLO/LRO overrides are the attack) ---
    ("hebrew-lre-embed", "מחיר: " + LRE + "$1,250" + PDF + " בלבד", "Hebrew price embedding Latin via LRE…PDF"),
    # --- more emoji ZWJ sequences ---
    ("health-worker-emoji", "assign " + HEALTH_WORKER, "man health worker (ZWJ + ⚕ + VS-16)"),
    ("rainbow-flag", "pride " + RAINBOW, "rainbow flag (VS-16 + ZWJ)"),
    ("wales-flag", "region: " + WALES, "Wales subdivision-flag emoji (TAG block)"),
    # --- more Indic conjuncts (ZWJ after virama) ---
    ("tamil-conj", "desc " + TAMIL_CONJ, "Tamil conjunct via ZWJ after virama"),
    ("bengali-conj", "desc " + BENGALI_CONJ, "Bengali conjunct via ZWJ after virama"),
    # --- Greek letters glued to Latin: NOT Latin-confusables, must stay clean ---
    ("greek-eta-max", "efficiency " + ETA + "max measured", "ηmax — Greek η glued to Latin"),
    ("greek-beta-carotene", "the " + BETA + "carotene level", "βcarotene — Greek β glued to Latin"),
    ("greek-ohm", "resistance 10k" + OMEGA + " load", "10kΩ — ohm unit glued to Latin"),
    ("greek-xi-min", "value " + XI + "min bound", "ξmin — Greek ξ glued to Latin"),
    ("greek-mu-unit", "delay 10" + MU + "s typical", "10μs — micro unit glued to Latin"),
    # --- plain non-Latin + legit mixed-script tokens ---
    ("russian-plain", "Получить содержимое задачи", "plain Russian sentence"),
    ("greek-word", "Ελληνικά κείμενο δοκιμή", "plain Greek words"),
    ("cyr-brand", "Сбербанк Online банк", "Cyrillic + Latin brand, space-separated"),
    ("math-double-struck", "over " + DOUBLE_STRUCK, "double-struck (blackboard) capitals"),
]
