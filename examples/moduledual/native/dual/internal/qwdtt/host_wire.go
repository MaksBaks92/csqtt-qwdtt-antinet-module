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

// AutoHashesFunc — создать wantHashes звонков VK (calls.start) для добора под число
// групп воркеров. cleanup завершает только созданные звонки (calls.forceFinish).
type AutoHashesFunc func(profileDir, protectPath, moduleState string, wantHashes int, hashMode string) (hashes []string, cleanup func(), err error)

var hooks HostHooks
var autoHashesFn AutoHashesFunc

func WireHost(h HostHooks) { hooks = h }

func WireAutoHashes(fn AutoHashesFunc) { autoHashesFn = fn }

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
