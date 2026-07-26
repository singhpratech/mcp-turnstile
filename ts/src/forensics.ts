/**
 * forensics.ts — context-aware detection of text-concealment techniques,
 * ported from defenses/unicode_forensics.py. i18n-honest: it flags standalone
 * hidden payloads (TAG blocks, zero-width steg, bidi overrides, VS chains,
 * homoglyph spoofs) while preserving legitimate ZWNJ, bidi marks, emoji ZWJ,
 * and subdivision-flag TAG sequences.
 *
 * The guiding rule: never high-flag a codepoint that a language or emoji
 * legitimately needs. Attack vs. i18n is decided by CONTEXT (runs, adjacency,
 * script mixing), not the codepoint alone.
 */

const TAG_LO = 0xe0000, TAG_HI = 0xe007f;
const TAG_TERM = 0xe007f; // CANCEL TAG — terminates a subdivision-flag sequence
const WAVING_FLAG = 0x1f3f4;
const ZWJ = 0x200d, ZWNJ = 0x200c;
// zero-advance / invisible-format codepoints abused for zero-width binary —
// classic trio plus Hangul fillers, invisible math ops, Mongolian vowel sep,
// soft-hyphen, and musical beam controls (so an off-list alphabet can't dodge).
const ZW_STEG = new Set<number>([
  0x200b, 0x2060, 0xfeff, 0x115f, 0x1160, 0x3164, 0xffa0,
  0x2061, 0x2062, 0x2063, 0x2064, 0x180e, 0x00ad,
]);
for (let c = 0x1d173; c <= 0x1d17a; c++) ZW_STEG.add(c);
const BIDI_OVERRIDE = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e]); // all dropped on sanitize
const BIDI_STRONG_OVERRIDE = new Set([0x202d, 0x202e]); // LRO / RLO — reorder even in RTL context
const BIDI_EMBED = new Set([0x202a, 0x202b]); // LRE / RLE — legit only amid real RTL text
const BIDI_ISOLATE = new Set([0x2066, 0x2067, 0x2068, 0x2069]);
const VS_LO1 = 0xfe00, VS_HI1 = 0xfe0f, VS_LO2 = 0xe0100, VS_HI2 = 0xe01ef;
const FVS_LO = 0x180b, FVS_HI = 0x180d; // Mongolian free variation selectors
// Cyrillic/Greek codepoints that impersonate a Latin letter (the Latin-targeting
// subset of UTS #39 confusables). We flag a homoglyph spoof only when one of
// these hides inside a Latin word, so genuine Greek math letters (η, ξ, β, μ, Ω)
// glued to Latin are not false-flagged. Mirrors defenses/unicode_forensics.py.
const LATIN_CONFUSABLES = new Set([
  0x0430, 0x0435, 0x043e, 0x0440, 0x0441, 0x0443, 0x0445, 0x0455, 0x0456,
  0x0458, 0x0501, 0x0475, 0x04bb, 0x051b, 0x051d, 0x04cf,
  0x0410, 0x0412, 0x0415, 0x0417, 0x041a, 0x041c, 0x041d, 0x041e, 0x0420,
  0x0421, 0x0422, 0x0423, 0x0425, 0x0405, 0x0406, 0x0408,
  0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039a, 0x039c, 0x039d,
  0x039f, 0x03a1, 0x03a4, 0x03a5, 0x03a7, 0x03bf, 0x03f2,
]);
// Whole scripts whose letters are canonical Latin look-alikes — any such letter
// inside a Latin word is a spoof (no legitimate mixed-with-Latin token use).
function isConfusableScript(o: number): boolean {
  return ((o >= 0x13a0 && o <= 0x13ff) || (o >= 0xab70 && o <= 0xabbf) || // Cherokee
    (o >= 0xa4d0 && o <= 0xa4ff) ||                                       // Lisu
    (o >= 0x1400 && o <= 0x167f) || (o >= 0x18b0 && o <= 0x18ff) ||       // Canadian syllabics
    // Armenian deliberately excluded — agglutinates onto Latin brand words
    (o >= 0x2c80 && o <= 0x2cff) ||                                       // Coptic
    (o >= 0xa500 && o <= 0xa63f) ||                                       // Vai
    (o >= 0x10400 && o <= 0x1044f) || (o >= 0x104b0 && o <= 0x104ff));    // Deseret, Osage
}
function validFlagTagchar(o: number): boolean {
  return (o >= 0xe0030 && o <= 0xe0039) || (o >= 0xe0061 && o <= 0xe007a);
}
// whitespace class shared with the Python side (explicit, NOT \s, whose members
// differ across languages on U+FEFF/U+0085/U+001C-1F): ASCII WS + Unicode spaces.
const WS_SPLIT = /[ \t\n\r\f\v\u00a0]+/;

export type Severity = "high" | "low";
export interface Finding {
  technique: string;
  severity: Severity;
  evidence: string;
  hiddenBytes: number;
}

function script(ch: string): string {
  const o = ch.codePointAt(0)!;
  if (o >= 0x0400 && o <= 0x04ff) return "Cyrillic";
  if (o >= 0x0370 && o <= 0x03ff) return "Greek";
  if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (o >= 0x00c0 && o <= 0x024f)) return "Latin";
  return "other";
}

function cps(text: string): number[] {
  return [...text].map((c) => c.codePointAt(0)!);
}

function detectTag(text: string): Finding | null {
  // A legit subdivision flag is EXACTLY base U+1F3F4 + 1..6 region tag chars +
  // U+E007F terminator; anything appended after a flag is a standalone payload.
  const arr = cps(text);
  const n = arr.length;
  let standalone = 0, legit = 0, i = 0;
  while (i < n) {
    const o = arr[i];
    if (o === WAVING_FLAG) {
      let j = i + 1, k = 0;
      while (j < n && validFlagTagchar(arr[j]) && k < 6) { j++; k++; }
      if (k >= 1 && j < n && arr[j] === TAG_TERM) { legit += k; i = j + 1; continue; }
      i++;
    } else if (o >= TAG_LO && o <= TAG_HI) { standalone++; i++; }
    else i++;
  }
  if (standalone) return { technique: "TAG-block mirror", severity: "high", evidence: `${standalone} standalone TAG codepoints (not a valid flag sequence)`, hiddenBytes: standalone };
  if (legit) return { technique: "TAG-block (flag emoji)", severity: "low", evidence: `${legit} TAG codepoints inside a valid flag sequence`, hiddenBytes: 0 };
  return null;
}

/** True when zero-width (ZWSP/WORD-JOINER/BOM) usage looks like a binary payload
 *  rather than legitimate word-breaking. Signal = a run of >=3 (nothing legit
 *  stacks three), OR >=16 total that also show run structure (>=2) or high
 *  density. Isolated singletons in no-space scripts (Thai/Lao/Khmer/Burmese/
 *  Tibetan/short CJK) — max run 1 — never fire. Mirrors the Python side. */
export function zeroWidthIsStego(text: string): boolean {
  let total = 0, maxRun = 0, run = 0, printable = 0;
  for (const ch of text) {
    const o = ch.codePointAt(0)!;
    if (ZW_STEG.has(o)) { run++; total++; if (run > maxRun) maxRun = run; }
    else {
      run = 0;
      // count only printable text toward density (exclude Other/Mark categories)
      // so invisible separators can't dilute a chunked payload.
      if (!/[\p{C}\p{M}]/u.test(ch)) printable++;
    }
  }
  if (maxRun >= 3) return true;
  return total >= 16 && (maxRun >= 2 || total / (total + printable) >= 0.3);
}

function detectZwbin(text: string): Finding | null {
  let total = 0, maxRun = 0, run = 0;
  for (const o of cps(text)) {
    if (ZW_STEG.has(o)) { run++; total++; if (run > maxRun) maxRun = run; }
    else run = 0;
  }
  if (total === 0) return null;
  if (zeroWidthIsStego(text)) return { technique: "Zero-width binary", severity: "high", evidence: `${total} zero-width steg codepoints (longest run ${maxRun}; ~${Math.floor(total / 8)} bytes)`, hiddenBytes: Math.max(1, Math.floor(total / 8)) };
  return { technique: "Zero-width", severity: "low", evidence: `${total} isolated zero-width codepoint(s) (word-break / joiner)`, hiddenBytes: 0 };
}

function detectBidi(text: string): Finding | null {
  // Only RLO/LRO overrides force character-level reordering (the unambiguous
  // Trojan-Source signal, flagged high in any context). LRE/RLE embeddings, PDF,
  // and isolates are legitimate in mixed RTL/LTR and in W3C/ICU-recommended
  // interpolation, so they are low. (Residual: embedding/isolate-only reordering
  // with no RLO/LRO is not high-flagged — the classic PoCs use RLO/LRO.)
  const arr = cps(text);
  const strong = arr.filter((o) => BIDI_STRONG_OVERRIDE.has(o)).length;
  if (strong) {
    let hidden = 0, i = 0;
    while (i < arr.length) {
      if (BIDI_STRONG_OVERRIDE.has(arr[i])) {
        let j = arr.indexOf(0x202c, i + 1);
        if (j === -1) j = arr.length;
        hidden += j - i - 1;
        i = j + 1;
      } else i++;
    }
    return { technique: "Bidi Trojan-Source", severity: "high", evidence: `${strong} directional-override control(s) (RLO/LRO); ~${hidden} chars display-reordered`, hiddenBytes: 0 };
  }
  const soft = arr.filter((o) => BIDI_EMBED.has(o) || BIDI_ISOLATE.has(o)).length;
  if (soft) return { technique: "Bidi embedding/isolate (i18n)", severity: "low", evidence: `${soft} bidi embedding/isolate control(s)`, hiddenBytes: 0 };
  return null;
}

function isVs(o: number): boolean {
  return (o >= VS_LO1 && o <= VS_HI1) || (o >= VS_LO2 && o <= VS_HI2) || (o >= FVS_LO && o <= FVS_HI);
}

function detectVs(text: string): Finding | null {
  // A single selector after a VISIBLE base is legit presentation (clears
  // keycaps, ©️/®️/™️, arrows, media symbols, CJK IVS, emoji). Smuggling shows as
  // a RUN of >=2 (a byte chain) or ORPHAN singles after an invisible/control/
  // space base or nothing — a selector with no glyph to modify.
  let chainTotal = 0, legit = 0, orphan = 0, run = 0;
  let base: string | null = null;
  const close = (r: number, b: string | null) => {
    if (r === 1) {
      if (b === null || /[\p{C}\p{Z}]/u.test(b) || isVs(b.codePointAt(0)!)) orphan++;
      else legit++;
    } else if (r >= 2) chainTotal += r;
  };
  for (const ch of text) {
    if (isVs(ch.codePointAt(0)!)) run++;
    else { close(run, base); run = 0; base = ch; }
  }
  close(run, base);
  if (chainTotal || orphan >= 4) {
    const total = chainTotal + orphan;
    return { technique: "Variation-selector smuggling", severity: "high", evidence: `${total} smuggling variation selectors (chains ${chainTotal}, orphan singles ${orphan}; ~${total} bytes)`, hiddenBytes: Math.max(1, total) };
  }
  if (legit) return { technique: "Variation selector (presentation)", severity: "low", evidence: `${legit} single presentation/IVS selector(s)`, hiddenBytes: 0 };
  return null;
}

function detectHomoglyph(text: string): Finding | null {
  // Flag a Latin word only when it hides a Cyrillic/Greek character that
  // IMPERSONATES a Latin letter (LATIN_CONFUSABLES), so "ηmax"/"10μs"/"10kΩ",
  // "GitHub-репозиторий", and pure-Greek words stay clean while "gеt" (Cyrillic
  // е) is caught. Mirrors defenses/unicode_forensics.py.
  for (const raw of text.split(WS_SPLIT)) {
    for (const token of raw.split(/[-_/.]/)) {
      if (!token) continue;
      let hasLatin = false;
      let confusable: string | null = null;
      for (const ch of token) {
        const o = ch.codePointAt(0)!;
        if (script(ch) === "Latin") hasLatin = true;
        if ((LATIN_CONFUSABLES.has(o) || isConfusableScript(o)) && confusable === null) confusable = ch;
      }
      if (hasLatin && confusable) return { technique: "Homoglyph spoof", severity: "high", evidence: `Latin word contains a Latin-confusable character U+${confusable.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}: ${JSON.stringify(token)}`, hiddenBytes: 0 };
    }
  }
  return null;
}

function joinable(ch: string): boolean {
  // letters, marks, AND numbers: a ZWNJ between a digit and a suffix is a legit
  // Persian/Urdu half-space (e.g. "۲‌نفره"), not steg.
  const o = ch.codePointAt(0)!;
  return o >= 0x1f000 || (o >= 0x2600 && o <= 0x27bf) || o === 0x203c || o === 0x2049 || o === 0x2764 ||
    /[\p{L}\p{M}\p{N}]/u.test(ch);
}

function detectZwjBin(text: string): Finding | null {
  // ZWJ/ZWNJ are legit BETWEEN joinables (emoji sequences, Persian/Indic
  // conjuncts), even at a truncated boundary. As a 0/1 bit alphabet they sit
  // beside each other / non-joinables (stray). Legit text has ~0 stray.
  const chars = [...text];
  let stray = 0;
  for (let i = 0; i < chars.length; i++) {
    const o = chars[i].codePointAt(0)!;
    if (o === ZWJ || o === ZWNJ) {
      const left = i > 0 ? joinable(chars[i - 1]) : null;
      const right = i + 1 < chars.length ? joinable(chars[i + 1]) : null;
      const present = [left, right].filter((v) => v !== null) as boolean[];
      if (!(present.length && present.every(Boolean))) stray++;
    }
  }
  if (stray >= 4) return { technique: "Zero-width binary", severity: "high", evidence: `${stray} stray zero-width joiners used as a bit alphabet (~${Math.floor(stray / 8)} bytes)`, hiddenBytes: Math.max(1, Math.floor(stray / 8)) };
  return null;
}

const DETECTORS = [detectTag, detectZwbin, detectZwjBin, detectBidi, detectVs, detectHomoglyph];

/** injection / exfil regex markers — report-card hints (not a security boundary),
 *  matching defenses/mediator.py so the TS and Python tools grade identically. */
const INJECTION_MARKERS: RegExp[] = [
  /<\/?\s*IMPORTANT\s*>/i,
  /<\/?\s*SYSTEM\s*>/i,
  /\bignore (the |all )?(previous|prior|above)\b/i,
  /\bdo not (tell|mention|inform|reveal)[\s\S]{0,30}\buser\b/i,
  /\bbefore (using|calling|invoking) this tool\b/i,
];
const EXFIL_MARKERS: RegExp[] = [
  /~?\/?\.ssh\/|id_rsa|id_ed25519/i,
  /\b(credentials|api[_ ]?key|secret|token|password)\b/i,
  /\b(read|exfiltrate|send|upload|include)[\s\S]{0,40}\b(file|contents|env)\b/i,
];

/** Map TAG codepoints (U+E0020..E007E) back to ASCII so a concealed payload is
 *  scannable by the regex markers, exactly like the Python side. */
function stripToAscii(text: string): string {
  let out = "";
  for (const ch of text) {
    const o = ch.codePointAt(0)!;
    if (o >= TAG_LO + 0x20 && o <= TAG_LO + 0x7e) out += String.fromCharCode(o - TAG_LO);
    else out += ch;
  }
  return out;
}

export function analyze(text: string): Finding[] {
  const out: Finding[] = [];
  for (const d of DETECTORS) {
    const f = d(text);
    if (f) out.push(f);
  }
  // scan both the raw text and its TAG-decoded form for injection/exfil markers
  for (const probe of [text, stripToAscii(text)]) {
    for (const rx of INJECTION_MARKERS) {
      if (rx.test(probe)) { out.push({ technique: "injection", severity: "high", evidence: `injection marker: /${rx.source}/`, hiddenBytes: 0 }); break; }
    }
    for (const rx of EXFIL_MARKERS) {
      if (rx.test(probe)) { out.push({ technique: "exfil", severity: "high", evidence: `exfiltration signal: /${rx.source}/`, hiddenBytes: 0 }); break; }
    }
  }
  return out;
}

export function highFindings(text: string): Finding[] {
  return analyze(text).filter((f) => f.severity === "high");
}
