# -*- coding: utf-8 -*-
"""Transform vendored CSQTT/qWDTT trees into dual-antinet packages."""
from __future__ import annotations

import pathlib
import re

DUAL = pathlib.Path(r"D:\csqtt\csqtt-antinet-module\examples\moduledual\native\dual")
QW = DUAL / "internal" / "qwdtt"
CS = DUAL / "internal" / "csqtt"


def rewrite_package(path: pathlib.Path, pkg: str, run_name: str = "Run", call_name: str = "Call") -> None:
    text = path.read_text(encoding="utf-8")
    text = text.replace("package main", f"package {pkg}", 1)
    text = re.sub(r"^func realMain\(", f"func {run_name}(", text, count=1, flags=re.M)
    text = re.sub(r"^func moduleCall\(", f"func {call_name}(", text, count=1, flags=re.M)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    for p in QW.glob("*.go"):
        if p.name == "host_wire.go":
            continue
        rewrite_package(p, "qwdtt")

    (QW / "host_wire.go").write_text(
        """package qwdtt

// Host hooks — wired from package main after AntiNet canons are injected.

type HostHooks struct {
	EmitProgress       func(format string, args ...any)
	EmitLog            func(format string, args ...any)
	EmitStatus         func(kind, detail string)
	EmitEventAck       func(detail string)
	DieWithParent      func()
	ProtectFromOomKill func()
}

var hooks HostHooks

func WireHost(h HostHooks) { hooks = h }

func emitProgress(format string, args ...any) {
	if hooks.EmitProgress != nil {
		hooks.EmitProgress(format, args...)
		return
	}
	panic("qwdtt: EmitProgress not wired")
}

func emitLog(format string, args ...any) {
	if hooks.EmitLog != nil {
		hooks.EmitLog(format, args...)
		return
	}
	panic("qwdtt: EmitLog not wired")
}

func emitStatus(kind, detail string) {
	if hooks.EmitStatus != nil {
		hooks.EmitStatus(kind, detail)
		return
	}
	panic("qwdtt: EmitStatus not wired")
}

func emitEventAck(detail string) {
	if hooks.EmitEventAck != nil {
		hooks.EmitEventAck(detail)
	}
}

func dieWithParent() {
	if hooks.DieWithParent != nil {
		hooks.DieWithParent()
	}
}

func protectFromOomKill() {
	if hooks.ProtectFromOomKill != nil {
		hooks.ProtectFromOomKill()
	}
}
""",
        encoding="utf-8",
    )

    # CSQTT: package rename + import path for tunnel
    for p in CS.glob("*.go"):
        if p.name == "host_wire.go":
            continue
        text = p.read_text(encoding="utf-8")
        text = text.replace("package main", "package csqtt", 1)
        text = re.sub(r"^func realMain\(", "func Run(", text, count=1, flags=re.M)
        text = re.sub(r"^func moduleCall\(", "func Call(", text, count=1, flags=re.M)
        text = text.replace('"csqtt-antinet/tunnel"', '"dual-antinet/tunnel"')
        p.write_text(text, encoding="utf-8")

    (CS / "host_wire.go").write_text(
        """package csqtt

// Host hooks — wired from package main after AntiNet canons are injected.

type HostHooks struct {
	EmitProgress func(format string, args ...any)
	EmitLog      func(format string, args ...any)
	EmitStatus   func(kind, detail string)
	EmitEventAck func(detail string)
}

var hooks HostHooks

func WireHost(h HostHooks) { hooks = h }

func emitProgress(format string, args ...any) {
	if hooks.EmitProgress != nil {
		hooks.EmitProgress(format, args...)
		return
	}
	panic("csqtt: EmitProgress not wired")
}

func emitLog(format string, args ...any) {
	if hooks.EmitLog != nil {
		hooks.EmitLog(format, args...)
		return
	}
	panic("csqtt: EmitLog not wired")
}

func emitStatus(kind, detail string) {
	if hooks.EmitStatus != nil {
		hooks.EmitStatus(kind, detail)
		return
	}
	panic("csqtt: EmitStatus not wired")
}

func emitEventAck(detail string) {
	if hooks.EmitEventAck != nil {
		hooks.EmitEventAck(detail)
	}
}
""",
        encoding="utf-8",
    )

    # tunnel package stays dual-antinet/tunnel
    print("ok")


if __name__ == "__main__":
    main()
