"""
client.py — connect to a real MCP server over stdio or streamable HTTP.

Both clients expose the same tiny surface: initialize() -> serverInfo dict,
list_tools() -> [tool dicts], close(). No third-party dependencies — HTTP uses
urllib and parses either application/json or text/event-stream responses, so it
works against both the 2025-11-25 and the stateless 2026-07-28 transports.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from harness.mcpkit import PROTOCOL_VERSION, StdioClient

HTTP_DEADLINE_S = 30.0  # overall wall-clock cap per request (survives SSE keepalives)

CLIENT_INFO = {"name": "mcpturn", "version": "0.1.0"}


def connect_stdio(argv: list[str]) -> "StdioAdapter":
    return StdioAdapter(argv)


def connect_http(url: str, headers: dict[str, str] | None = None) -> "HttpClient":
    return HttpClient(url, headers or {})


class StdioAdapter:
    """Thin adapter over harness.mcpkit.StdioClient with a uniform surface."""

    def __init__(self, argv: list[str]):
        self._c = StdioClient(argv)
        self.transport = "stdio"

    def initialize(self) -> dict[str, Any]:
        return self._c.initialize()

    def list_tools(self) -> list[dict[str, Any]]:
        return self._c.list_tools()

    def close(self) -> None:
        self._c.close()


class HttpClient:
    """Minimal streamable-HTTP MCP client (JSON-RPC over POST)."""

    def __init__(self, url: str, headers: dict[str, str]):
        self.url = url
        self.transport = "http"
        self._headers = headers
        self._session: str | None = None
        self._proto: str | None = None
        self._id = 0

    def _post(self, method: str, params: dict[str, Any] | None, notify: bool = False) -> Any:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            self._id += 1
            body["id"] = self._id
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._headers,
        }
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        if self._proto:
            # spec-compliant streamable-HTTP servers may 400 without this
            headers["MCP-Protocol-Version"] = self._proto
        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        req_id = None if notify else self._id
        try:
            resp = urllib.request.urlopen(req, timeout=HTTP_DEADLINE_S)
        except urllib.error.HTTPError as e:
            # surface the server's error body (often the real JSON-RPC message)
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            raise RuntimeError(f"HTTP {e.code} from {self.url}" + (f": {body.strip()}" if body.strip() else ""))
        try:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            ctype = resp.headers.get("Content-Type", "")
            if notify:
                return None
            payload = _read_payload(resp, ctype, req_id)
        finally:
            resp.close()
        if payload is None:
            return None
        if isinstance(payload, dict) and "error" in payload:
            raise RuntimeError(f"RPC error from {self.url}: {payload['error']}")
        return payload.get("result") if isinstance(payload, dict) else None

    def initialize(self) -> dict[str, Any]:
        result = self._post("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        if isinstance(result, dict):
            self._proto = result.get("protocolVersion") or PROTOCOL_VERSION
        try:
            self._post("notifications/initialized", {}, notify=True)
        except Exception:
            pass
        return result or {}

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._post("tools/list", {})
        return (result or {}).get("tools", [])

    def close(self) -> None:
        return None


def _read_payload(resp, ctype: str, req_id: int | None) -> dict[str, Any] | None:
    """Read a JSON-RPC message from a JSON body or an SSE stream.

    For SSE we read line-by-line and return the instant a `data:` event parses to
    a JSON-RPC object matching our request id (or carrying result/error), so a
    server that holds the stream open with keepalives does NOT hang us. An overall
    wall-clock deadline guards against a silent stall that resets the socket timer.
    """
    if "text/event-stream" in ctype:
        deadline = time.monotonic() + HTTP_DEADLINE_S
        data_lines: list[str] = []
        for bline in resp:
            if time.monotonic() > deadline:
                raise RuntimeError(f"timed out after {HTTP_DEADLINE_S:.0f}s waiting for an SSE response")
            line = bline.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith(":"):
                continue  # SSE comment / keepalive ping
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
                continue
            if line == "":  # end of one event: join its data lines and try to parse
                obj = _loads_dict("\n".join(data_lines))
                data_lines = []
                if obj is not None and _matches(obj, req_id):
                    return obj
        # stream ended: last-chance parse of any trailing event
        return _loads_dict("\n".join(data_lines)) if data_lines else None
    # plain JSON body
    return _loads_dict(resp.read().decode("utf-8", errors="replace"))


def _loads_dict(raw: str) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None  # ignore batches/scalars


def _matches(obj: dict[str, Any], req_id: int | None) -> bool:
    if "result" in obj or "error" in obj:
        return req_id is None or obj.get("id") == req_id
    return False


# kept for tests / external callers
def _parse_body(raw: str, ctype: str) -> dict[str, Any] | None:
    class _S:
        def __init__(self, t): self._t = t.encode("utf-8")
        def read(self): return self._t
        def __iter__(self): return iter(self._t.splitlines(keepends=True))
    return _read_payload(_S(raw), ctype, None)
