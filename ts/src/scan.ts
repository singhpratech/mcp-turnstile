/**
 * scan.ts — connect, pull tools/list, build a report card (token tax + safety +
 * progressive-disclosure estimate + cross-run rug-pull pinning).
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { McpClient, Tool } from "./client.js";
import { measure, countTokens, tokenizerName } from "./tokens.js";
import { highFindings, Finding } from "./forensics.js";

export interface ScanFinding { tool: string; severity: string; kind: string; detail: string; }
export interface ScanReport {
  server: string; transport: string; tokenizer: string; window: number;
  nTools: number; fullTokens: number; minimalTokens: number; ratio: number; pctContext: number;
  perTool: { name: string; tokens: number }[];
  findings: ScanFinding[];
  progressive: null | { indexTokens: number; baselineTokens: number; taskTokens: number; reductionPct: number };
  grades: { efficiency: string; safety: string };
  highFindings: number;
  rugPulls: number;
}

function fullSer(tools: Tool[]): string { return JSON.stringify(tools); }
function minimalSer(tools: Tool[]): string {
  return tools.map((t) => {
    const desc = (t.description ?? "").split(". ")[0].trim();
    const props = (t.inputSchema?.properties ?? {}) as Record<string, any>;
    const params = Object.entries(props).map(([k, v]) => `${k}:${v?.type ?? "any"}`).join(",");
    return `${t.name ?? "?"}(${params}) - ${desc}`;
  }).join("\n");
}

function digest(t: Tool): string {
  const canon = JSON.stringify({ name: t.name ?? null, description: t.description ?? null, inputSchema: t.inputSchema ?? null });
  return createHash("sha256").update(canon).digest("hex");
}

function grade(pct: number, high: number): { efficiency: string; safety: string } {
  const eff = pct < 5 ? "A" : pct < 12 ? "B" : pct < 20 ? "C" : "D";
  const safety = high === 0 ? "A" : high <= 2 ? "C" : "F";
  return { efficiency: eff, safety };
}

/** minimal progressive-disclosure model: index (2 meta-tools) + one loaded tool. */
function indexTokens(): number {
  const meta = [
    { name: "tool_search", description: "Search available tools by intent; returns ranked names and one-line summaries.", inputSchema: { type: "object", properties: { query: { type: "string", description: "What you want to do." } }, required: ["query"] } },
    { name: "tool_load", description: "Load the full schema for one tool by name.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Exact tool name." } }, required: ["name"] } },
  ];
  return countTokens(JSON.stringify(meta));
}

export async function scan(client: McpClient, opts: { window?: number; pinPath?: string } = {}): Promise<ScanReport> {
  const window = opts.window ?? 200_000;
  const info = await client.initialize();
  const tools = await client.listTools();
  const server = info?.serverInfo?.name ?? "<unknown>";

  const full = tools.length ? measure(fullSer(tools)).tokens : 0;
  const minimal = tools.length ? measure(minimalSer(tools)).tokens : 0;
  const perTool = tools
    .map((t) => ({ name: t.name ?? "?", tokens: measure(JSON.stringify(t)).tokens }))
    .sort((a, b) => b.tokens - a.tokens);

  // safety: forensics on description + schema descriptions + name; plus rug-pull pinning
  const findings: ScanFinding[] = [];
  let pins: Record<string, string> = {};
  if (opts.pinPath && existsSync(opts.pinPath)) {
    try { const p = JSON.parse(readFileSync(opts.pinPath, "utf8")); if (p && typeof p === "object" && !Array.isArray(p)) pins = p; } catch { /* */ }
  }
  let rugPulls = 0;
  for (const t of tools) {
    const name = t.name ?? "<unknown>";
    const blobs: string[] = [t.description ?? "", t.name ?? ""];
    for (const v of Object.values((t.inputSchema?.properties ?? {}) as Record<string, any>)) {
      if (v && typeof v.description === "string") blobs.push(v.description);
    }
    if (t.annotations) blobs.push(JSON.stringify(t.annotations));
    for (const blob of blobs.map((b) => b.slice(0, 20000))) {
      for (const f of highFindings(blob)) findings.push({ tool: name, severity: "high", kind: kindOf(f), detail: `${f.technique}: ${f.evidence}` });
    }
    const d = digest(t);
    if (pins[name] && pins[name] !== d) { findings.push({ tool: name, severity: "high", kind: "rug-pull", detail: `definition changed since first seen (${pins[name].slice(0, 12)}… → ${d.slice(0, 12)}…)` }); rugPulls++; }
    pins[name] = d;
  }
  if (opts.pinPath) { try { writeFileSync(opts.pinPath, JSON.stringify(pins)); } catch { /* */ } }

  // dedupe findings by tool+detail
  const seen = new Set<string>();
  const deduped = findings.filter((f) => { const k = f.tool + "|" + f.detail; if (seen.has(k)) return false; seen.add(k); return true; });
  const high = deduped.filter((f) => f.severity === "high").length;

  let progressive: ScanReport["progressive"] = null;
  if (tools.length) {
    const baseline = full;
    const heaviestTask = perTool[0]?.tokens ?? 0;
    const idx = indexTokens();
    const searchResult = countTokens(JSON.stringify(perTool.slice(0, 3).map((t) => ({ name: t.name, summary: t.name }))));
    const taskTokens = idx + searchResult + heaviestTask;
    progressive = { indexTokens: idx, baselineTokens: baseline, taskTokens, reductionPct: baseline ? Math.round((1 - taskTokens / baseline) * 1000) / 10 : 0 };
  }

  return {
    server, transport: client.transport, tokenizer: tokenizerName(), window,
    nTools: tools.length, fullTokens: full, minimalTokens: minimal,
    ratio: minimal ? Math.round((full / minimal) * 100) / 100 : 0,
    pctContext: window ? Math.round((full / window) * 1000) / 10 : 0,
    perTool, findings: deduped, progressive, grades: grade(window ? (full / window) * 100 : 0, high),
    highFindings: high, rugPulls,
  };
}

function kindOf(f: Finding): string {
  const t = f.technique.toLowerCase();
  if (t === "injection") return "injection";
  if (t === "exfil") return "exfil";
  if (t.includes("homoglyph")) return "homoglyph";
  return "concealed-unicode";
}
