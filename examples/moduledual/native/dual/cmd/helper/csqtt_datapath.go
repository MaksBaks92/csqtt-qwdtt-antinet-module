// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Zombie data path: helper process + TURN control plane stay up, but DialTCP through
// gVisor→engine hangs until dialTimeout (exactly 20s) and SOCKS still accepts with scraps.
// Host FIRE needs 3 SOCKS rejects / 60s and gets reset by those scraps — so the module must
// self-heal (qWDTT relayWatchdog pattern: detect → recycle transport → give up → exit).
//
// Doze / netlost: pause TURN workers + reject SOCKS (battery). Never recycle or fatal while
// offline — defer heal until netback (energy-efficient hold).
//
// Sleep / wake: on Android the monotonic clock stops in deep sleep, so after a wake the engine
// believes nothing happened while its TURN paths died. wake.go detects the suspend; onWake()
// (a) asks the engine to re-validate every path now (engine does it on its own too, wake.rs),
// (b) opens a grace window so dial-timeouts that started before the wake do not count towards a
// recycle while the workers are already reconnecting, (c) if we were paused (netlost without a
// netback yet) probes the network ourselves instead of waiting for the host forever.
// waitForPath() holds a SOCKS CONNECT for a few seconds while active TURN paths == 0 so the
// first requests after a wake succeed instead of burning the 20 s dial timeout.

const (
	dataPathDialFailThreshold = 3
	dataPathRecycleMinGap     = 45 * time.Second
	dataPathMaxRecycles       = 8
	dataPathEngineSettle      = 800 * time.Millisecond
	dataPathWakeGrace         = 30 * time.Second
	dataPathPathWaitMax       = 8 * time.Second
	dataPathPathWaitPoll      = 200 * time.Millisecond
	// One lucky dial after a flap must not wipe the recycle streak; only a quiet window does.
	dataPathRecycleStable = 60 * time.Second
	// Soft handover (engineRebind): dedupe window, settle before judging, fallback deadline.
	dataPathRebindMinGap = 3 * time.Second
	dataPathRebindSettle = 1 * time.Second
	dataPathRebindWait   = 15 * time.Second
	dataPathRebindPoll   = 500 * time.Millisecond
	// Soft RESUME after sleep/netback: if READY paths stay 0 past this, cold-recycle once.
	dataPathSoftResumeWatch = 25 * time.Second
)

// Offline self-probe schedule while paused (host may never deliver netback, e.g. after a
// cold relaunch or when the module was not alive to receive it): cheap, sparse, capped.
var dataPathPausedProbeDelays = []time.Duration{
	30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute,
}

type dataPathGuard struct {
	mu sync.Mutex

	cfgJSON     string
	readyWaitMs int
	tunIP       string

	addr atomic.Pointer[net.UDPAddr]

	dialFails             int
	recycles              int
	lastRecycle           time.Time
	recycling             bool
	paused                bool // netlost: do not burn dial budget / recycle
	pauseGen              uint64
	pendingRecycle        bool // heal requested while paused → apply on netback
	pendingReason         string
	graceUntil            time.Time // after wake: stale dial-timeouts are not evidence
	lastRebind            time.Time // soft handover dedupe (host event + own detector)
	rebindGen             uint64
	rebindInFlight        bool // watchdog has not yet judged this rebind
	pendingHandover       bool
	pendingHandoverSource string
	softResumeGen         uint64 // invalidates overlapping soft-resume watches
	exiting               bool

	stopFn       func()
	startFn      func(string) error
	waitFn       func(int) error
	portFn       func() int
	ipFn         func() string
	pauseFn      func(bool)  // engine PauseGate; optional in tests
	activeFn     func() int  // engine READY TURN paths (-1 = unknown); optional
	nudgeFn      func()      // engine re-validate paths now; optional
	rebindFn     func() bool // engine soft handover; false → not supported, recycle instead
	disconnectFn func()      // DISCONNECT on host stop; optional in tests
	probeFn      func() bool // "is the network usable?" while paused; optional
	rebuildTunFn func(newIP string) error // swap gVisor when engine TUN IP changes on recycle
	exitFn       func(code int)
	nowFn        func() time.Time
	sleepFn      func(time.Duration)
	logFn        func(format string, args ...any)
	statusFn     func(kind, detail string)
}

func newDataPathGuard(cfgJSON string, readyWait time.Duration, pktPort int, tunIP string) *dataPathGuard {
	g := &dataPathGuard{
		cfgJSON:     cfgJSON,
		readyWaitMs: int(readyWait / time.Millisecond),
		tunIP:       strings.TrimSpace(tunIP),
		stopFn:      engineStop,
		startFn:     engineStart,
		waitFn:      engineWaitReady,
		portFn:      enginePacketPort,
		ipFn:        engineTunIP,
		pauseFn:     engineSetPaused,
		activeFn:    engineActivePaths,
		nudgeFn:     engineNudge,
		rebindFn:     engineRebind,
		disconnectFn: engineDisconnect,
		exitFn:      os.Exit,
		nowFn:       time.Now,
		sleepFn:     time.Sleep,
		logFn:       emitLog,
		statusFn:    emitStatus,
	}
	g.setPacketPort(pktPort)
	return g
}

func (g *dataPathGuard) setPacketPort(port int) {
	if port <= 0 || port > 65535 {
		g.addr.Store(nil)
		return
	}
	g.addr.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func (g *dataPathGuard) packetAddr() *net.UDPAddr {
	return g.addr.Load()
}

func (g *dataPathGuard) rejecting() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Recycle/rebind: SOCKS CONNECT is held (waitForPath), not rejected — apps survive the
	// 1–2 s path rebuild. Instant reject stays for pause (offline) and fatal exit (FIRE).
	return g.paused || g.exiting
}

func (g *dataPathGuard) setPaused(v bool) {
	g.mu.Lock()
	g.paused = v
	g.mu.Unlock()
}

func (g *dataPathGuard) applyEnginePause(v bool) {
	if g.pauseFn != nil {
		g.pauseFn(v)
	}
}

func isDialTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "deadline exceeded") || strings.Contains(s, "i/o timeout")
}

// noteDialResult — успех сбрасывает streak dial-timeout; recycle-счётчик — только после
// тихого окна (иначе один удачный dial на флапе маскирует исчерпание).
func (g *dataPathGuard) noteDialResult(err error) {
	if g == nil {
		return
	}
	if err == nil {
		g.mu.Lock()
		g.dialFails = 0
		g.pendingRecycle = false
		g.pendingReason = ""
		if g.recycles > 0 && (g.lastRecycle.IsZero() || g.nowFn().Sub(g.lastRecycle) >= dataPathRecycleStable) {
			g.recycles = 0
		}
		g.mu.Unlock()
		return
	}
	if !isDialTimeout(err) {
		return
	}
	g.mu.Lock()
	if g.paused || g.exiting {
		// Offline: do not burn recycle/DNS budget — remember for netback.
		g.pendingRecycle = true
		if g.pendingReason == "" {
			g.pendingReason = "dial-timeouts"
		}
		g.dialFails = 0
		g.mu.Unlock()
		return
	}
	if !g.graceUntil.IsZero() && g.nowFn().Before(g.graceUntil) {
		// Just woke up: this dial started while the phone was asleep. Workers are already
		// re-validating / reconnecting — a recycle now would only race them.
		g.mu.Unlock()
		return
	}
	g.dialFails++
	n := g.dialFails
	g.mu.Unlock()
	if n >= dataPathDialFailThreshold {
		go g.heal("dial-timeouts")
	}
}

func (g *dataPathGuard) onHostEvent(event string) {
	if g == nil {
		return
	}
	switch event {
	case "netlost":
		g.mu.Lock()
		g.paused = true
		g.pauseGen++
		gen := g.pauseGen
		g.dialFails = 0
		g.mu.Unlock()
		g.applyEnginePause(true)
		g.logFn("CSQTT: сеть пропала — пауза TURN/SOCKS (энергосбережение)")
		go g.pausedWatchdog(gen)
	case "netback":
		g.resumeFromPause("netback")
	case "stall":
		// The host only probes connectivity when it has a network: if we are still paused
		// the netback was lost — resume first, then heal. Heal = soft rebind first (dead
		// sockets are the common cause), full recycle only if no path returns.
		g.onHandover("stall")
	case "handover":
		g.onHandover("handover")
	case "stop":
		// Host is about to kill the process. DISCONNECT drops server routes inside the
		// desktop ~1s window. Do not exit here — the host owns process lifetime.
		g.logFn("CSQTT: stop — отправляю DISCONNECT")
		if g.disconnectFn != nil {
			g.disconnectFn()
		}
	}
}

// heal — try a soft rebind before a full engine restart. Rebind closes the old TURN
// sockets and opens new protected ones, then GETCONF runs again. Full recycle stays
// for a rebind that already failed, and for a new path failure that arrives while the
// 3s dedupe window still blocks another rebind. An in-flight rebind whose paths are
// still down keeps its watchdog. SOCKS on 127.0.0.1 is not rebound.
func (g *dataPathGuard) heal(reason string) {
	if g == nil {
		return
	}
	if strings.HasSuffix(reason, "-rebind-timeout") || strings.HasSuffix(reason, "-rebind-gap") {
		g.requestRecycle(reason)
		return
	}
	g.mu.Lock()
	if g.exiting {
		g.mu.Unlock()
		return
	}
	if g.paused {
		g.mu.Unlock()
		g.requestRecycle(reason)
		return
	}
	rebind := g.rebindFn
	withinGap := !g.lastRebind.IsZero() && g.nowFn().Sub(g.lastRebind) < dataPathRebindMinGap
	inFlight := g.rebindInFlight
	g.mu.Unlock()
	if rebind == nil {
		g.requestRecycle(reason)
		return
	}
	if withinGap {
		paths := -1
		if g.activeFn != nil {
			paths = g.activeFn()
		}
		// Watchdog is still waiting and nothing is READY yet. It recycles on its own
		// deadline. A new failure after paths are already back must not disappear.
		if inFlight && paths <= 0 {
			return
		}
		g.requestRecycle(reason + "-rebind-gap")
		return
	}
	g.onHandover(reason)
}

// onHandover — the network under the TURN sockets changed (host event, own detector or a
// stall). Soft path: keep the engine, VK credentials and dispatcher flows; ask the engine to
// re-allocate every TURN path on the current network (engineRebind). A watchdog falls back to
// the full recycle if no path is READY within dataPathRebindWait. Deduped against the host
// event and the own detector firing for the same change.
func (g *dataPathGuard) onHandover(source string) {
	if g == nil {
		return
	}
	g.resumeFromPause(source)
	g.mu.Lock()
	if g.exiting {
		g.mu.Unlock()
		return
	}
	if g.recycling {
		// Recycle owns the sockets; remember the change and rebind as soon as the new
		// engine is up instead of leaving it on the old network.
		g.pendingHandover = true
		if g.pendingHandoverSource == "" {
			g.pendingHandoverSource = source
		}
		g.mu.Unlock()
		g.logFn("CSQTT: %s во время recycle — rebind сразу после перезапуска движка", source)
		return
	}
	now := g.nowFn()
	if !g.lastRebind.IsZero() && now.Sub(g.lastRebind) < dataPathRebindMinGap {
		g.mu.Unlock()
		return
	}
	g.lastRebind = now
	g.rebindGen++
	gen := g.rebindGen
	g.rebindInFlight = true
	g.dialFails = 0
	// Dial timeouts while the paths re-allocate are not evidence of a dead data path.
	g.graceUntil = now.Add(dataPathWakeGrace)
	rebind := g.rebindFn
	g.mu.Unlock()
	if rebind == nil || !rebind() {
		g.finishRebind(gen)
		g.logFn("CSQTT: %s — движок без rebind, перезапускаю data path", source)
		go g.requestRecycle(source)
		return
	}
	g.logFn("CSQTT: %s — пересоздаю TURN-пути на новой сети (движок и креды сохраняются)", source)
	go g.rebindWatchdog(gen, source)
}

// finishRebind — the watchdog for `gen` is done. A newer rebind owns the flag.
func (g *dataPathGuard) finishRebind(gen uint64) {
	g.mu.Lock()
	if g.rebindGen == gen {
		g.rebindInFlight = false
	}
	g.mu.Unlock()
}

// rebindWatchdog — after a soft rebind the READY path count drops to zero and must come back.
// If it does not within dataPathRebindWait (relay unreachable, credentials dead on the new
// network, ...) escalate to the full recycle, which also fetches fresh credentials.
func (g *dataPathGuard) rebindWatchdog(gen uint64, source string) {
	if g.activeFn == nil {
		g.finishRebind(gen)
		return
	}
	// Let the old sessions actually tear down before counting; otherwise a stale non-zero
	// count would look like success.
	g.sleepFn(dataPathRebindSettle)
	deadline := g.nowFn().Add(dataPathRebindWait)
	for g.nowFn().Before(deadline) {
		g.mu.Lock()
		stale := g.rebindGen != gen || g.exiting || g.paused || g.recycling
		g.mu.Unlock()
		if stale {
			g.finishRebind(gen)
			return
		}
		if g.activeFn() != 0 { // -1 (unknown) counts as "cannot judge" → trust the engine
			g.finishRebind(gen)
			return
		}
		g.sleepFn(dataPathRebindPoll)
	}
	g.mu.Lock()
	stale := g.rebindGen != gen || g.exiting || g.paused
	g.mu.Unlock()
	if stale {
		g.finishRebind(gen)
		return
	}
	g.finishRebind(gen)
	g.logFn("CSQTT: после %s пути не поднялись за %s — перезапускаю data path", source, dataPathRebindWait)
	g.requestRecycle(source + "-rebind-timeout")
}

// resumeFromPause — leave the netlost hold: RESUME workers, apply a deferred heal if one was
// requested while offline. No-op when not paused. `source` names who proved the network is back;
// for anything but "netback" the caller performs its own heal afterwards.
func (g *dataPathGuard) resumeFromPause(source string) {
	g.mu.Lock()
	if !g.paused {
		g.mu.Unlock()
		return
	}
	g.paused = false
	g.pauseGen++
	need := g.pendingRecycle
	reason := g.pendingReason
	if reason == "" {
		reason = source
	}
	g.pendingRecycle = false
	g.pendingReason = ""
	g.dialFails = 0
	g.graceUntil = g.nowFn().Add(dataPathWakeGrace)
	g.mu.Unlock()
	g.applyEnginePause(false)
	if source != "netback" {
		g.logFn("CSQTT: сеть есть (%s), хотя netback не приходил — снимаю паузу", source)
		return
	}
	if need {
		g.logFn("CSQTT: сеть вернулась — лечу data path (%s)", reason)
		go g.heal(reason)
		return
	}
	// Prefer soft resume: workers reconnect without VK re-auth storm.
	g.logFn("CSQTT: сеть вернулась — RESUME воркеров (без recycle)")
	g.afterSoftResume(source)
}

// afterSoftResume — nudge paths and arm a one-shot watch: if READY stays 0, cold recycle.
func (g *dataPathGuard) afterSoftResume(source string) {
	if g.nudgeFn != nil {
		g.nudgeFn()
	}
	go g.watchSoftResume(source)
}

// watchSoftResume — after soft RESUME/wake, paths should come back without a full engine
// restart. If they do not, one cold recycle beats "только полный рестарт VPN".
func (g *dataPathGuard) watchSoftResume(source string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.softResumeGen++
	gen := g.softResumeGen
	g.mu.Unlock()

	// Production always sets sleepFn. Nil = tests that want an immediate check.
	if g.sleepFn != nil {
		g.sleepFn(dataPathSoftResumeWatch)
	}

	g.mu.Lock()
	stale := g.exiting || g.paused || g.recycling || g.softResumeGen != gen
	g.mu.Unlock()
	if stale {
		return
	}
	if g.activeFn == nil {
		return
	}
	paths := g.activeFn()
	if paths != 0 {
		// -1 (unknown) and >0: trust the engine; dial-timeouts still catch true zombies.
		return
	}
	g.logFn("CSQTT: после soft RESUME (%s) READY=0 — cold recycle", source)
	go g.requestRecycle(source + "-soft-dead")
}

// pausedWatchdog — while paused, probe the network ourselves on a sparse backoff. The host is
// supposed to send netback, but the module must not depend on it. Exits as soon as the pause
// generation changes.
func (g *dataPathGuard) pausedWatchdog(gen uint64) {
	if g.probeFn == nil {
		return
	}
	for i := 0; ; i++ {
		delay := dataPathPausedProbeDelays[min(i, len(dataPathPausedProbeDelays)-1)]
		g.sleepFn(delay)
		g.mu.Lock()
		stale := !g.paused || g.pauseGen != gen || g.exiting
		g.mu.Unlock()
		if stale {
			return
		}
		if g.probeFn() {
			g.probeSucceeded(gen, "probe")
			return
		}
	}
}

// probeSucceeded — a self-probe proved the network is back while we are still paused:
// resume and heal (deferred recycle if one was requested offline, otherwise a soft nudge).
func (g *dataPathGuard) probeSucceeded(gen uint64, source string) {
	g.mu.Lock()
	if !g.paused || g.pauseGen != gen {
		g.mu.Unlock()
		return
	}
	need := g.pendingRecycle
	reason := g.pendingReason
	if reason == "" {
		reason = source
	}
	g.mu.Unlock()
	g.resumeFromPause(source)
	if need {
		go g.heal(reason)
	} else {
		g.afterSoftResume(source)
	}
}

// onWake — the process was suspended for `gap` (wake.go). Called from the monitor goroutine.
func (g *dataPathGuard) onWake(gap time.Duration) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.exiting {
		g.mu.Unlock()
		return
	}
	g.graceUntil = g.nowFn().Add(dataPathWakeGrace)
	g.dialFails = 0
	paused := g.paused
	gen := g.pauseGen
	g.mu.Unlock()
	if paused {
		g.logFn("CSQTT: пробуждение после %s сна (пауза netlost) — проверяю сеть", gap.Round(time.Second))
		if g.probeFn != nil && g.probeFn() {
			g.probeSucceeded(gen, "wake")
		}
		return
	}
	g.logFn("CSQTT: пробуждение после %s сна — проверяю TURN-пути", gap.Round(time.Second))
	g.afterSoftResume("wake")
}

// waitForPath — hold a CONNECT while the engine has zero READY TURN paths (reconnecting after
// sleep / handover). Returns as soon as a path exists, ctx ends, or the cap elapses; the dial
// itself is still bounded by ctx. Zero cost on the hot path: one atomic read via FFI.
func (g *dataPathGuard) waitForPath(ctx context.Context) {
	if g == nil {
		return
	}
	if g.rejecting() {
		return
	}
	if g.activeFn == nil || g.activeFn() != 0 {
		return
	}
	deadline := g.nowFn().Add(dataPathPathWaitMax)
	for g.nowFn().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if g.rejecting() {
			return
		}
		g.sleepFn(dataPathPathWaitPoll)
		if g.activeFn() != 0 {
			return
		}
	}
	// Cap elapsed with still-zero READY paths: do not wait for 3×dialTimeout — recycle now.
	if !g.rejecting() && g.activeFn != nil && g.activeFn() == 0 {
		go g.heal("zero-paths")
	}
}

func (g *dataPathGuard) requestRecycle(reason string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.exiting {
		g.mu.Unlock()
		return
	}
	if g.paused {
		// Never stop/start engine while offline — DNS/TURN fail → fatal storm.
		g.pendingRecycle = true
		g.pendingReason = reason
		g.mu.Unlock()
		g.logFn("CSQTT: recycle отложен до netback (%s)", reason)
		return
	}
	if g.recycling {
		g.mu.Unlock()
		return
	}
	now := g.nowFn()
	if !g.lastRecycle.IsZero() && now.Sub(g.lastRecycle) < dataPathRecycleMinGap {
		g.mu.Unlock()
		return
	}
	if g.recycles >= dataPathMaxRecycles {
		g.exiting = true
		g.mu.Unlock()
		g.logFn("CSQTT: data path не ожил после %d перезапусков (%s) — выхожу", dataPathMaxRecycles, reason)
		g.statusFn(statusFatal, "data path recycle exhausted")
		g.exitFn(42)
		return
	}
	g.recycling = true
	g.lastRecycle = now
	g.recycles++
	streak := g.recycles
	cfg := g.cfgJSON
	readyMs := g.readyWaitMs
	wantIP := g.tunIP
	g.mu.Unlock()

	g.logFn("CSQTT: data path мёртв (%s) — перезапуск движка #%d", reason, streak)

	g.stopFn()
	time.Sleep(dataPathEngineSettle)

	if err := g.startFn(cfg); err != nil {
		g.failRecycle(reason, err)
		return
	}
	if err := g.waitFn(readyMs); err != nil {
		g.failRecycle(reason, err)
		return
	}
	newIP := strings.TrimSpace(g.ipFn())
	if wantIP != "" && newIP != "" && newIP != wantIP {
		if g.rebuildTunFn == nil {
			g.logFn("CSQTT: после recycle TUN IP сменился (%s→%s) — полный рестарт процесса", wantIP, newIP)
			g.mu.Lock()
			g.exiting = true
			g.recycling = false
			g.mu.Unlock()
			g.statusFn(statusFatal, "tun ip changed on recycle")
			g.exitFn(42)
			return
		}
		g.logFn("CSQTT: после recycle TUN IP сменился (%s→%s) — пересобираю netstack", wantIP, newIP)
		if err := g.rebuildTunFn(newIP); err != nil {
			g.failRecycle(reason, err)
			return
		}
		g.mu.Lock()
		g.tunIP = newIP
		g.mu.Unlock()
	}
	port := g.portFn()
	// packet_bridge mode keeps port 0 (in-process FFI); UDP bridge mode needs a real port.
	if port < 0 || port > 65535 {
		g.failRecycle(reason, errors.New("bad packet port"))
		return
	}
	if port > 0 {
		g.setPacketPort(port)
	}

	g.mu.Lock()
	g.recycling = false
	g.dialFails = 0
	handover := g.pendingHandover
	handoverSource := g.pendingHandoverSource
	g.pendingHandover = false
	g.pendingHandoverSource = ""
	if handover {
		g.lastRebind = time.Time{}
	}
	g.mu.Unlock()
	if port > 0 {
		g.logFn("CSQTT: движок перезапущен · pkt=%d", port)
	} else {
		g.logFn("CSQTT: движок перезапущен · bridge=in-process")
	}
	if handover {
		g.onHandover(handoverSource)
	}
}

func (g *dataPathGuard) failRecycle(reason string, err error) {
	g.mu.Lock()
	offline := g.paused
	if offline {
		// Should be rare (recycle gated), but never fatal offline — wait for netback.
		g.recycling = false
		g.pendingRecycle = true
		g.pendingReason = reason
		g.mu.Unlock()
		g.logFn("CSQTT: recycle не удался офлайн (%s): %v — жду netback", reason, err)
		return
	}
	g.exiting = true
	g.recycling = false
	g.mu.Unlock()
	g.logFn("CSQTT: recycle движка не удался (%s): %v — выхожу", reason, err)
	g.statusFn(statusFatal, "engine recycle failed")
	g.exitFn(42)
}
