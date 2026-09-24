package qwdtt

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
