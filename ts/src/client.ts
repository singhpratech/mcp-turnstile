/**
 * client.ts — connect to a real MCP server over stdio or streamable HTTP.
 * Uniform surface: initialize(), listTools(), close(). Dependency-free.
 */

import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";

export const PROTOCOL_VERSION = "2025-11-25";
export const CLIENT_INFO = { name: "mcpturn", version: "0.1.0" };
const HTTP_DEADLINE_MS = 30_000;

export interface Tool {
  name?: string;
  description?: string;
  inputSchema?: any;
  annotations?: any;
  [k: string]: any;
}
export interface McpClient {
  transport: string;
  initialize(): Promise<any>;
  listTools(): Promise<Tool[]>;
  close(): void;
}

/* ------------------------- stdio ------------------------- */
export class StdioClient implements McpClient {
  transport = "stdio";
  private proc: ChildProcessWithoutNullStreams;
  private buf = "";
  private id = 0;
  private waiters = new Map<number, (v: any) => void>();

  constructor(argv: string[]) {
    this.proc = spawn(argv[0], argv.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    this.proc.stdout.setEncoding("utf8");
    this.proc.stdout.on("data", (chunk: string) => this.onData(chunk));
  }
  private onData(chunk: string) {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id != null && this.waiters.has(msg.id)) {
          this.waiters.get(msg.id)!(msg);
          this.waiters.delete(msg.id);
        }
      } catch { /* ignore non-JSON lines */ }
    }
  }
  private rpc(method: string, params?: any, notify = false): Promise<any> {
    const msg: any = { jsonrpc: "2.0", method };
    if (params !== undefined) msg.params = params;
    if (!notify) { this.id += 1; msg.id = this.id; }
    this.proc.stdin.write(JSON.stringify(msg) + "\n");
    if (notify) return Promise.resolve(null);
    const id = this.id;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.waiters.delete(id); reject(new Error("stdio server timed out")); }, HTTP_DEADLINE_MS);
      this.waiters.set(id, (m) => {
        clearTimeout(t);
        if (m.error) reject(new Error(`RPC error: ${JSON.stringify(m.error)}`));
        else resolve(m.result);
      });
    });
  }
  async initialize() {
    const r = await this.rpc("initialize", { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
    await this.rpc("notifications/initialized", {}, true);
    return r;
  }
  async listTools(): Promise<Tool[]> { return (await this.rpc("tools/list", {})).tools ?? []; }
  close() { try { this.proc.stdin.end(); this.proc.kill(); } catch { /* */ } }
}

/* ------------------------- http ------------------------- */
export class HttpClient implements McpClient {
  transport = "http";
  private session: string | null = null;
  private proto: string | null = null;
  private id = 0;
  constructor(private url: string, private headers: Record<string, string> = {}) {}

  private async post(method: string, params?: any, notify = false): Promise<any> {
    const body: any = { jsonrpc: "2.0", method };
    if (params !== undefined) body.params = params;
    if (!notify) { this.id += 1; body.id = this.id; }
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...this.headers,
    };
    if (this.session) h["Mcp-Session-Id"] = this.session;
    if (this.proto) h["MCP-Protocol-Version"] = this.proto;

    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), HTTP_DEADLINE_MS);
    let resp: Response;
    try {
      resp = await fetch(this.url, { method: "POST", headers: h, body: JSON.stringify(body), signal: ac.signal });
    } catch (e) {
      clearTimeout(timer);   // fetch itself failed (dead port etc.) — don't leak the timer
      throw e;
    }

    const sid = resp.headers.get("Mcp-Session-Id");
    if (sid) this.session = sid;
    if (!resp.ok) {
      clearTimeout(timer);
      let text = "";
      try { text = (await resp.text()).slice(0, 400); } catch { /* */ }
      throw new Error(`HTTP ${resp.status} from ${this.url}${text.trim() ? ": " + text.trim() : ""}`);
    }
    if (notify) { clearTimeout(timer); return null; }

    const ctype = resp.headers.get("Content-Type") ?? "";
    try {
      if (ctype.includes("text/event-stream") && resp.body) {
        return await this.readSse(resp.body, notify ? null : this.id);
      }
      const obj = JSON.parse(await resp.text());
      return obj && typeof obj === "object" && !Array.isArray(obj)
        ? (obj.error ? (() => { throw new Error(`RPC error: ${JSON.stringify(obj.error)}`); })() : obj.result)
        : null;
    } finally { clearTimeout(timer); }
  }

  /** Stream SSE line-by-line; return the moment the matching JSON-RPC event
   *  arrives, so a server that holds the stream open with pings does not hang. */
  private async readSse(stream: ReadableStream<Uint8Array>, reqId: number | null): Promise<any> {
    const reader = stream.getReader();
    const dec = new TextDecoder();
    let buf = "", dataLines: string[] = [];
    const tryEvent = (): any | undefined => {
      const raw = dataLines.join("\n").trim();
      dataLines = [];
      if (!raw) return undefined;
      let obj: any;
      try { obj = JSON.parse(raw); } catch { return undefined; }
      if (obj && typeof obj === "object" && !Array.isArray(obj) && ("result" in obj || "error" in obj)) {
        if (reqId == null || obj.id === reqId) return obj;
      }
      return undefined;
    };
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).replace(/\r$/, "");
          buf = buf.slice(nl + 1);
          if (line.startsWith(":")) continue;          // keepalive comment
          if (line.startsWith("data:")) { dataLines.push(line.slice(5).replace(/^ /, "")); continue; }
          if (line === "") {
            const ev = tryEvent();
            if (ev !== undefined) {
              reader.cancel().catch(() => {});
              if (ev.error) throw new Error(`RPC error: ${JSON.stringify(ev.error)}`);
              return ev.result;
            }
          }
        }
      }
      const ev = tryEvent();
      if (ev !== undefined) { if (ev.error) throw new Error(`RPC error: ${JSON.stringify(ev.error)}`); return ev.result; }
      return null;
    } finally { reader.releaseLock(); }
  }

  async initialize() {
    const r = await this.post("initialize", { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO });
    if (r && typeof r === "object") this.proto = r.protocolVersion ?? PROTOCOL_VERSION;
    try { await this.post("notifications/initialized", {}, true); } catch { /* */ }
    return r ?? {};
  }
  async listTools(): Promise<Tool[]> { return ((await this.post("tools/list", {})) ?? {}).tools ?? []; }
  close() { /* stateless */ }
}

export function connectStdio(argv: string[]): McpClient { return new StdioClient(argv); }
export function connectHttp(url: string, headers: Record<string, string>): McpClient { return new HttpClient(url, headers); }
