#!/usr/bin/env node
/**
 * mcpturn (TypeScript/Node) — scan any MCP server for token cost and metadata safety.
 *
 *   mcpturn scan --stdio -- npx -y @modelcontextprotocol/server-github
 *   mcpturn scan --http https://example.com/mcp --header "Authorization: Bearer X" --fail-on high
 *   mcpturn scan --json --pin .mcpturn-pins.json --stdio -- ./my-server
 */

import { connectStdio, connectHttp, McpClient } from "./client.js";
import { scan } from "./scan.js";
import { renderTerminal, renderJson } from "./render.js";

const VERSION = "0.1.0";

interface Opts {
  http?: string; stdio?: boolean; headers: Record<string, string>;
  window: number; top: number; pin?: string; json: boolean;
  failOn: "none" | "high" | "any"; command: string[];
}

function usage(): string {
  return `mcpturn ${VERSION} — scan any MCP server for token cost and metadata safety

usage:
  mcpturn scan --stdio -- <server command>
  mcpturn scan --http <url> [--header "K: V"]... [options]

options:
  --stdio                launch a stdio server; put its command after \`--\`
  --http <url>           streamable-HTTP MCP endpoint
  --header "K: V"        extra HTTP header (repeatable)
  --window <n>           context window size (default 200000)
  --top <n>              heaviest tools to list (default 5)
  --pin <file>           store/compare tool digests across runs (rug-pull detection)
  --json                 emit JSON instead of a terminal report
  --fail-on none|high|any  exit nonzero when findings at/above this level exist
  --version, -h/--help`;
}

function parse(argv: string[]): Opts | { help: true; error?: boolean } | { version: true } {
  // Split off the stdio server command (everything after `--`) BEFORE inspecting
  // flags, so a server command containing --version/-h/--help can't be mistaken
  // for our own flags (which would silently skip the scan and pass a CI gate).
  const dd = argv.indexOf("--");
  const head = dd >= 0 ? argv.slice(0, dd) : argv;
  const command = dd >= 0 ? argv.slice(dd + 1) : [];
  if (head.includes("--version")) return { version: true };
  if (head.includes("-h") || head.includes("--help")) return { help: true };
  if (head[0] !== "scan") return { help: true, error: true };
  const rest = head.slice(1);
  const o: Opts = { headers: {}, window: 200_000, top: 5, json: false, failOn: "none", command };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--stdio") o.stdio = true;
    else if (a === "--http") o.http = rest[++i];
    else if (a === "--header") { const h = rest[++i] ?? ""; const idx = h.indexOf(":"); if (idx >= 0) o.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim(); else process.stderr.write(`mcpturn: ignoring --header ${JSON.stringify(h)} (no ':')\n`); }
    else if (a === "--window") o.window = parseInt(rest[++i], 10) || 200_000;
    else if (a === "--top") o.top = parseInt(rest[++i], 10) || 5;
    else if (a === "--pin") o.pin = rest[++i];
    else if (a === "--json") o.json = true;
    else if (a === "--fail-on") {
      const v = rest[++i];
      if (v !== "none" && v !== "high" && v !== "any") { process.stderr.write(`error: --fail-on must be none|high|any (got ${JSON.stringify(v)})\n`); return { help: true, error: true }; }
      o.failOn = v;
    }
  }
  return o;
}

async function main(argv: string[]): Promise<number> {
  const p = parse(argv);
  if ("version" in p) { console.log(`mcpturn ${VERSION}`); return 0; }
  if ("help" in p) { console.log(usage()); return p.error ? 2 : 0; }
  if (!p.http && !p.stdio) { process.stderr.write("error: one of --stdio or --http is required\n"); return 2; }

  let client: McpClient; let label: string;
  if (p.http) { client = connectHttp(p.http, p.headers); label = p.http; }
  else {
    if (!p.command.length) { process.stderr.write("error: --stdio needs a server command after `--`\n"); return 1; }
    client = connectStdio(p.command); label = p.command.join(" ");
  }

  try {
    const rep = await scan(client, { window: p.window, pinPath: p.pin });
    console.log(p.json ? renderJson(rep) : renderTerminal(rep, p.top));
    if (p.failOn === "high" && rep.highFindings > 0) return 2;
    if (p.failOn === "any" && rep.findings.length > 0) return 2;
    return 0;
  } catch (e: any) {
    process.stderr.write(`mcpturn: failed to scan ${label}: ${e?.message ?? e}\n`);
    return 1;
  } finally { try { client.close(); } catch { /* */ } }
}

main(process.argv.slice(2)).then((code) => process.exit(code));
