#!/usr/bin/env python3
"""
build.py — package mcp-turnstile into a single executable file.

Produces `dist/mcpturn.pyz`: one self-contained zipapp bundling the turnstile
CLI and the only libraries it needs at runtime (harness, defenses). Because the
whole project is pure standard library, the result runs anywhere Python 3.10+
exists — no pip, no install, no dependencies:

    python3 build.py                       # -> dist/mcpturn.pyz
    python3 dist/mcpturn.pyz scan --stdio -- python3 -m servers.benign_server 6
    ./dist/mcpturn.pyz --version           # it's marked executable

Ship that one file and anyone can run it with a single command.
"""

from __future__ import annotations

import os
import shutil
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build" / "_pyz"
DIST = ROOT / "dist"
OUT = DIST / "mcpturn.pyz"

# packages the CLI imports at runtime (attacks/ is optional and omitted on purpose)
RUNTIME_PKGS = ["mcpturn", "harness", "defenses"]


def _ignore(_dir, names):
    return [n for n in names if n in ("__pycache__",) or n.endswith(".pyc")]


def main() -> int:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)
    DIST.mkdir(exist_ok=True)

    for pkg in RUNTIME_PKGS:
        src = ROOT / pkg
        if not src.is_dir():
            raise SystemExit(f"missing package: {pkg}")
        shutil.copytree(src, BUILD / pkg, ignore=_ignore)

    # zipapp entry point: mcpturn.__main__:run
    zipapp.create_archive(
        BUILD, target=str(OUT),
        main="mcpturn.__main__:run",   # run() propagates the exit code; main() alone would not
        interpreter="/usr/bin/env python3",
        compressed=True,
    )
    os.chmod(OUT, 0o755)
    size = OUT.stat().st_size
    print(f"built {OUT.relative_to(ROOT)}  ({size/1024:.0f} KB)")
    print("run it:  python3 dist/mcpturn.pyz scan --stdio -- <server command>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
