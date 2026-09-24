#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copy CSQTT rust engine from csqtt-antinet-module into this dual repo.

Default source: sibling checkout ../csqtt-antinet-module (or CSQTT_ANTINET_MODULE).
Keeps rustDir path examples/modulecsqtt/native/csqtt-engine stable for build.py.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DST = HERE / "examples" / "modulecsqtt" / "native" / "csqtt-engine"
LICENSE_DST = HERE / "examples" / "modulecsqtt" / "LICENSE"


def default_src_root() -> Path:
    env = os.environ.get("CSQTT_ANTINET_MODULE", "").strip()
    if env:
        return Path(env)
    return HERE.parent / "csqtt-antinet-module"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--from",
        dest="src_root",
        type=Path,
        default=None,
        help="Path to csqtt-antinet-module checkout (default: sibling or $CSQTT_ANTINET_MODULE)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = (args.src_root or default_src_root()).resolve()
    src = root / "examples" / "modulecsqtt" / "native" / "csqtt-engine"
    lic = root / "examples" / "modulecsqtt" / "LICENSE"
    if not src.is_dir() or not (src / "Cargo.toml").is_file():
        print(f"error: engine not found at {src}", file=sys.stderr)
        return 1

    print(f"source: {src}")
    print(f"dest:   {DST}")
    if args.dry_run:
        return 0

    if DST.exists():
        shutil.rmtree(DST)
    ignore = shutil.ignore_patterns(
        "target",
        ".git",
        "__pycache__",
        "*.pyc",
        ".cargo-cache",
    )
    shutil.copytree(src, DST, ignore=ignore)
    if lic.is_file():
        LICENSE_DST.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lic, LICENSE_DST)
        print(f"license: {LICENSE_DST}")
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
