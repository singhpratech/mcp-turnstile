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
const WAVING_FLAG = 0x1f3f4;
const ZWJ = 0x200d, ZWNJ = 0x200c;
const ZW_STEG = new Set([0x200b, 0x2060, 0xfeff]);
const BIDI_OVERRIDE = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e]);
const BIDI_ISOLATE = new Set([0x2066, 0x2067, 0x2068, 0x2069]);
const VS_LO1 = 0xfe00, VS_HI1 = 0xfe0f, VS_LO2 = 0xe0100, VS_HI2 = 0xe01ef;
const GREEK_MATH = new Set([..."μθΩπλσΔαβγδεφψωτΦΣΠ"]);

export type Severity = "high" | "low";
export interface Finding {
  technique: string;
  severity: Severity;
  evidence: string;
  hiddenBytes: number;
}

function isPictographic(cp: number): boolean {
  return cp >= 0x1f000 || (cp >= 0x2600 && cp <= 0x27bf) || cp === 0x2764;
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
  const arr = cps(text);
  let run = 0, legit = 0, prevWasFlag = false, inTag = false;
  for (const o of arr) {
    if (o >= TAG_LO && o <= TAG_HI) {
      if (!inTag) inTag = true;
      if (prevWasFlag) legit++; else run++;
    } else {
      inTag = false;
      prevWasFlag = o === WAVING_FLAG;
    }
  }
  if (run) return { technique: "TAG-block mirror", severity: "high", evidence: `${run} standalone TAG codepoints (not part of a flag emoji)`, hiddenBytes: run };
  if (legit) return { technique: "TAG-block (flag emoji)", severity: "low", evidence: `${legit} TAG codepoints inside a valid flag sequence`, hiddenBytes: 0 };
  return null;
}

function detectZwbin(text: string): Finding | null {
  let best = 0, cur = 0, total = 0;
  for (const o of cps(text)) {
    if (ZW_STEG.has(o)) { cur++; total++; best = Math.max(best, cur); }
    else cur = 0;
  }
  if (total >= 8) return { technique: "Zero-width binary", severity: "high", evidence: `${total} zero-width steg codepoints (longest run ${best}; ~${Math.floor(total / 8)} bytes)`, hiddenBytes: Math.floor(total / 8) };
  if (total) return { technique: "Zero-width", severity: "low", evidence: `${total} isolated zero-width codepoint(s)`, hiddenBytes: 0 };
  return null;
}

function detectBidi(text: string): Finding | null {
  const arr = cps(text);
  const overrides = arr.filter((o) => BIDI_OVERRIDE.has(o)).length;
  if (overrides) {
    let hidden = 0, i = 0;
    while (i < arr.length) {
      if (arr[i] === 0x202e || arr[i] === 0x202d) {
        let j = arr.indexOf(0x202c, i + 1);
        if (j === -1) j = arr.length;
        hidden += j - i - 1;
        i = j + 1;
      } else i++;
    }
    return { technique: "Bidi Trojan-Source", severity: "high", evidence: `${overrides} bidi override control(s); ~${hidden} chars display-reordered`, hiddenBytes: 0 };
  }
  const isolates = arr.filter((o) => BIDI_ISOLATE.has(o)).length;
  if (isolates) return { technique: "Bidi isolate (i18n)", severity: "low", evidence: `${isolates} balanced isolate control(s)`, hiddenBytes: 0 };
  return null;
}

function detectVs(text: string): Finding | null {
  let chain = 0, legit = 0, prevPict = false;
  for (const o of cps(text)) {
    const isVs = (o >= VS_LO1 && o <= VS_HI1) || (o >= VS_LO2 && o <= VS_HI2);
    if (isVs) {
      if (prevPict && chain === 0) legit++; else chain++;
      prevPict = false;
    } else {
      prevPict = isPictographic(o) || (o >= 0x3000 && o <= 0x9fff);
    }
  }
  if (chain) return { technique: "Variation-selector smuggling", severity: "high", evidence: `chain of ${chain} variation selectors (~${chain} bytes)`, hiddenBytes: chain };
  if (legit) return { technique: "Variation selector (presentation)", severity: "low", evidence: `${legit} presentation variation selector(s)`, hiddenBytes: 0 };
  return null;
}

function detectHomoglyph(text: string): Finding | null {
  for (const raw of text.split(/\s+/)) {
    for (const token of raw.split(/[-_/.]/)) {
      if (!token) continue;
      const hasDigit = /[0-9]/.test(token);
      const scripts = new Set<string>();
      for (const ch of token) {
        const s = script(ch);
        if (s === "Greek" && (hasDigit || GREEK_MATH.has(ch))) continue;
        if (s === "Latin" || s === "Cyrillic" || s === "Greek") scripts.add(s);
      }
      if (scripts.size >= 2) return { technique: "Homoglyph spoof", severity: "high", evidence: `token mixes scripts within one word: ${JSON.stringify(token)}`, hiddenBytes: 0 };
    }
  }
  return null;
}

const DETECTORS = [detectTag, detectZwbin, detectBidi, detectVs, detectHomoglyph];

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
