/** render.ts — terminal + JSON rendering of a ScanReport. */
import { ScanReport } from "./scan.js";

const TTY = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (TTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const amber = (s: string) => c("33", s);
const danger = (s: string) => c("91", s);
const safe = (s: string) => c("92", s);
const dim = (s: string) => c("90", s);
const bold = (s: string) => c("1", s);

function bar(pct: number, width = 32): string {
  const fill = Math.max(0, Math.min(width, Math.round((pct / 100) * width)));
  return "█".repeat(fill) + "░".repeat(width - fill);
}

export function renderTerminal(r: ScanReport, top = 5): string {
  const L: string[] = [];
  L.push(bold("mcp-turnstile") + dim(`  ·  ${r.server}  ·  ${r.transport}  ·  ${r.nTools} tools`));
  L.push(dim(`tokenizer: ${r.tokenizer}`));
  L.push("");
  L.push(bold("TOKEN TAX"));
  L.push(`  ${amber(bar(r.pctContext))} ${amber(r.pctContext + "%")} of a ${Math.round(r.window / 1000)}k window`);
  L.push(`  ${r.fullTokens.toLocaleString()} tokens for tool definitions  ·  ${r.ratio}x over a minimal schema  ·  ${r.nTools ? Math.floor(r.fullTokens / r.nTools) : 0} avg/tool`);
  if (r.perTool.length) {
    L.push(dim("  heaviest tools:"));
    for (const t of r.perTool.slice(0, top)) L.push(dim(`    ${String(t.tokens).padStart(6)}  ${t.name}`));
  }
  L.push("");
  if (r.progressive) {
    const p = r.progressive;
    L.push(bold("IF YOU DISCLOSE PROGRESSIVELY"));
    L.push(`  index costs ${p.indexTokens.toLocaleString()} tokens; a task loads one tool for ~${p.taskTokens.toLocaleString()} tokens`);
    if (p.reductionPct > 0) L.push(`  ${safe(p.reductionPct + "% fewer tokens")} per task vs. loading everything`);
    else L.push(dim("  too few tools to save — progressive disclosure would cost more here"));
    L.push("");
  }
  L.push(bold("METADATA SAFETY"));
  if (!r.findings.length) L.push("  " + safe("✓ no concealment, poisoning, or rug-pull signals"));
  else {
    for (const f of r.findings.filter((x) => x.severity === "high")) L.push("  " + danger(`🚩 [${f.kind}] `) + `${f.tool}: ` + dim(f.detail));
    for (const f of r.findings.filter((x) => x.severity !== "high").slice(0, 8)) L.push("  " + dim(`·  [${f.kind}] ${f.tool}: ${f.detail}`));
  }
  L.push("");
  const seccol = r.grades.safety === "A" ? safe : danger;
  L.push(bold("GRADE") + `   efficiency ${amber(r.grades.efficiency)}   ·   safety ${seccol(r.grades.safety)}` + (r.highFindings ? danger(`   (${r.highFindings} high finding${r.highFindings !== 1 ? "s" : ""})`) : ""));
  if (r.rugPulls) L.push(danger(`  ⚠ ${r.rugPulls} tool(s) changed since last scan (rug-pull)`));
  return L.join("\n");
}

export function renderJson(r: ScanReport): string {
  return JSON.stringify(r, null, 2);
}
