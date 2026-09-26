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

// AutoHashesFunc — создать wantHashes звонков VK (calls.start), только когда в ссылке
// нет хешей вовсе и нет валидного кеша. dnsPreset — SETTING_dnsPreset (DoH → UDP в ProtectDNSCsv).
// cleanup опционален (обычно nil): forceFinish только при замене протухшего кеша, не на каждый стоп.
type AutoHashesFunc func(profileDir, protectPath, moduleState, dnsPreset string, wantHashes int, hashMode string) (hashes []string, cleanup func(), err error)

var hooks HostHooks
var autoHashesFn AutoHashesFunc
var extraModuleStateFn func() map[string]any

func WireHost(h HostHooks) { hooks = h }

func WireAutoHashes(fn AutoHashesFunc) { autoHashesFn = fn }

// WireExtraModuleState — поля helper (vk_token, auto_hashes, …) для слияния в STATE_SAVE
// вместе с TURN-кредами, чтобы один блоб не затирал другой.
func WireExtraModuleState(fn func() map[string]any) { extraModuleStateFn = fn }

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
