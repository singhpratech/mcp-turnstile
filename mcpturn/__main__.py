"""
mcpturn — scan any MCP server for token cost and metadata safety.

(Invoke as `mcpturn`, `turnstile`, or `mcp-turnstile` — all the same tool; or
`python3 -m mcpturn …` with no install.)

Examples:
  # a stdio server (everything after `--` is the server command)
  mcpturn scan --stdio -- npx -y @modelcontextprotocol/server-github
  mcpturn scan --stdio -- python3 -m servers.benign_server 6

  # a streamable-HTTP server, with an auth header, failing CI on any high finding
  mcpturn scan --http https://example.com/mcp --header "Authorization: Bearer XYZ" --fail-on high

  # machine-readable, and remember tool digests to catch rug-pulls next time
  mcpturn scan --json --pin .mcpturn-pins.json --stdio -- ./my-server
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpturn import __version__
from mcpturn.client import connect_http, connect_stdio
from mcpturn.render import render_json, render_terminal
from mcpturn.scan import scan


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcpturn",
                                description="Scan any MCP server for token cost and metadata safety.")
    p.add_argument("--version", action="version", version=f"mcpturn {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a single MCP server")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--http", metavar="URL", help="streamable-HTTP MCP endpoint")
    g.add_argument("--stdio", action="store_true",
                   help="launch a stdio MCP server; put its command after `--`")
    s.add_argument("--header", action="append", default=[], metavar="K: V",
                   help="extra HTTP header (repeatable), e.g. 'Authorization: Bearer …'")
    s.add_argument("--window", type=int, default=200_000, help="context window size (default 200000)")
    s.add_argument("--top", type=int, default=5, help="how many heaviest tools to list")
    s.add_argument("--task", default="create a new item", help="example task for the disclosure estimate")
    s.add_argument("--pin", metavar="FILE", help="store/compare tool digests across runs (rug-pull detection)")
    s.add_argument("--json", action="store_true", help="emit JSON instead of a terminal report")
    s.add_argument("--fail-on", choices=["none", "high", "any"], default="none",
                   help="exit nonzero when findings at/above this level are present (for CI)")
    return p


def _exit_code(rep, fail_on: str) -> int:
    if fail_on == "high" and rep.high > 0:
        return 2
    if fail_on == "any" and rep.findings:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Everything after a standalone `--` is the stdio server command; flags live
    # before it. This is robust regardless of flag order.
    stdio_cmd: list[str] = []
    if "--" in raw:
        i = raw.index("--")
        stdio_cmd = raw[i + 1:]
        raw = raw[:i]
    args = _build_parser().parse_args(raw)
    if args.cmd != "scan":
        return 1
    args.command = stdio_cmd

    if args.http:
        headers = {}
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            else:
                print(f"mcpturn: ignoring --header {h!r} (no ':' — expected 'Name: value')", file=sys.stderr)
        client = connect_http(args.http, headers)
        label = args.http
    else:
        cmd = args.command
        if not cmd:
            print("error: --stdio needs a server command after `--`, e.g. "
                  "turnstile scan --stdio -- npx -y @modelcontextprotocol/server-github", file=sys.stderr)
            return 1
        client = connect_stdio(cmd)
        label = " ".join(cmd)

    try:
        rep = scan(client, window=args.window, pin_path=args.pin, example_task=args.task)
    except Exception as e:
        print(f"mcpturn: failed to scan {label}: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            client.close()
        except Exception:
            pass

    print(render_json(rep) if args.json else render_terminal(rep, top=args.top))
    return _exit_code(rep, args.fail_on)


def run() -> None:
    """Entry point that propagates the exit code (used by the zipapp shim and as
    a belt-and-suspenders console entry). setuptools console_scripts already use
    main()'s return value, but the zipapp shim calls its target with no sys.exit."""
    raise SystemExit(main())


if __name__ == "__main__":
    run()
