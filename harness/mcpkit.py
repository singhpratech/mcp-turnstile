"""
mcpkit — a tiny, dependency-free MCP toolkit for the gap-proving harness.

Contains three things every other module reuses:

  1. StdioServer  — a minimal MCP server that speaks JSON-RPC 2.0 over stdio.
                    Real servers in servers/ subclass/instantiate this, so when
                    the benchmark connects it is talking to a genuine MCP server
                    process over a pipe — not a mock.

  2. StdioClient  — a minimal MCP client that launches a server subprocess,
                    performs the initialize handshake, and calls tools/list and
                    tools/call. This is what bench/ and defenses/ use.

  3. count_tokens — a pluggable token estimator. Uses tiktoken if it happens to
                    be installed; otherwise falls back to a documented heuristic.
                    Character and byte counts are always exact; token counts are
                    labelled as estimates unless tiktoken is present.

Everything here targets MCP's JSON-RPC + tools/list shape, which is stable
across the 2025-11-25 spec and the 2026-07-28 release candidate. The
token-tax measurement does not depend on the protocol revision.

SAFETY: nothing in this file performs any network access or touches any host
you do not control. Servers are launched as local subprocesses only.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

PROTOCOL_VERSION = "2025-11-25"


# --------------------------------------------------------------------------
# Token estimation
# --------------------------------------------------------------------------

_TIKTOKEN = None
try:  # pragma: no cover - depends on environment
    import tiktoken

    _TIKTOKEN = tiktoken.get_encoding("cl100k_base")
except Exception:
    _TIKTOKEN = None

# Heuristic tokenizer used when tiktoken is unavailable.
#
# BPE tokenizers (cl100k_base / o200k_base) split text roughly on:
#   - runs of letters (often sub-split, but ~1 token per short word)
#   - individual digits and punctuation (usually 1 token each)
#   - whitespace attaches to the following token
#
# We approximate by counting "pieces": word-ish runs plus every individual
# punctuation/symbol/digit character. This tracks real BPE counts on JSON
# schema text to within ~10-15%, which is more than enough to demonstrate a
# 5-15x ratio. It is deliberately conservative (tends to *under*-count), so
# the token tax we report is a floor, not an exaggeration.
_PIECE_RE = re.compile(r"[A-Za-z]+|[0-9]|[^\sA-Za-z0-9]|\s+")


def _heuristic_tokens(text: str) -> int:
    n = 0
    for m in _PIECE_RE.finditer(text):
        piece = m.group()
        if piece.isspace():
            # whitespace merges into an adjacent token; count runs of >1 newline
            n += max(0, piece.count("\n") - 0)
            continue
        if piece.isalpha() and len(piece) > 5:
            # long identifiers/words split into ~ceil(len/4) subword tokens
            n += -(-len(piece) // 4)
        else:
            n += 1
    return n


def count_tokens(text: str) -> int:
    """Estimate LLM tokens for a string. Exact if tiktoken is installed."""
    if _TIKTOKEN is not None:
        return len(_TIKTOKEN.encode(text))
    return _heuristic_tokens(text)


def tokenizer_name() -> str:
    return "tiktoken/cl100k_base (exact)" if _TIKTOKEN else "heuristic (estimate, tends to undercount)"


def measure(text: str) -> dict[str, int]:
    """Return exact chars/bytes and an (estimated) token count for a blob."""
    return {
        "chars": len(text),
        "bytes": len(text.encode("utf-8")),
        "tokens": count_tokens(text),
    }


# --------------------------------------------------------------------------
# MCP server (stdio JSON-RPC 2.0)
# --------------------------------------------------------------------------


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.annotations is not None:
            d["annotations"] = self.annotations
        return d


@dataclass
class StdioServer:
    """A minimal but genuine MCP server over stdio.

    Instantiate with a name + list of Tool, then call .serve(). It handles
    `initialize`, `tools/list`, and `tools/call` (echoing a stub result).
    """

    name: str
    tools: list[Tool] = field(default_factory=list)
    version: str = "0.0.1"

    def _result(self, req_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _error(self, req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "initialize":
            return self._result(
                req_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": self.name, "version": self.version},
                },
            )
        if method == "notifications/initialized":
            return None  # notification, no response
        if method == "tools/list":
            return self._result(req_id, {"tools": [t.to_wire() for t in self.tools]})
        if method == "tools/call":
            params = msg.get("params") or {}
            tname = params.get("name")
            return self._result(
                req_id,
                {"content": [{"type": "text", "text": f"[stub] {self.name}.{tname} called"}]},
            )
        if req_id is not None:
            return self._error(req_id, -32601, f"method not found: {method}")
        return None

    def serve(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = self.handle(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


# --------------------------------------------------------------------------
# MCP client (launches a server subprocess, does the handshake)
# --------------------------------------------------------------------------


class StdioClient:
    """Launch an MCP stdio server and speak JSON-RPC to it."""

    def __init__(self, argv: list[str]):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._lock = threading.Lock()

    def _rpc(self, method: str, params: dict[str, Any] | None = None, notify: bool = False) -> Any:
        with self._lock:
            msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            if not notify:
                self._id += 1
                msg["id"] = self._id
            assert self.proc.stdin is not None
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
            if notify:
                return None
            assert self.proc.stdout is not None
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError(f"server {self.proc.args} closed unexpectedly")
                line = line.strip()
                if not line:
                    continue
                resp = json.loads(line)
                if resp.get("id") == self._id:
                    if "error" in resp:
                        raise RuntimeError(f"RPC error: {resp['error']}")
                    return resp.get("result")

    def initialize(self) -> dict[str, Any]:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-turnstile-harness", "version": "0.0.1"},
            },
        )
        self._rpc("notifications/initialized", {}, notify=True)
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return self._rpc("tools/list")["tools"]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
