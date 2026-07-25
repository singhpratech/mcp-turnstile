/**
 * tokens.ts — dependency-free token estimator, matching the Python heuristic.
 *
 * Counts "pieces": word-ish runs (long words split ~ceil(len/4)) plus every
 * individual punctuation/symbol/digit. Tracks real BPE counts on JSON schema
 * text within ~10-15% and deliberately under-counts, so the reported token tax
 * is a floor, not an exaggeration. Char/byte counts are exact.
 */

const PIECE = /[A-Za-z]+|[0-9]|[^\sA-Za-z0-9]|\s+/g;

export function countTokens(text: string): number {
  let n = 0;
  for (const m of text.matchAll(PIECE)) {
    const piece = m[0];
    if (/^\s+$/.test(piece)) { n += (piece.match(/\n/g) ?? []).length; continue; } // count newlines, like Python
    if (/^[A-Za-z]+$/.test(piece) && piece.length > 5) {
      n += Math.ceil(piece.length / 4);
    } else {
      n += 1;
    }
  }
  return n;
}

export function tokenizerName(): string {
  return "heuristic (estimate, tends to undercount)";
}

export interface Measure {
  chars: number;
  bytes: number;
  tokens: number;
}

export function measure(text: string): Measure {
  return {
    chars: [...text].length,
    bytes: Buffer.byteLength(text, "utf8"),
    tokens: countTokens(text),
  };
}
