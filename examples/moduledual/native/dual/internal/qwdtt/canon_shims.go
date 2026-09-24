package qwdtt

import (
	"context"
	"net"
	"syscall"
	"time"
)

// dialControl — set from package main to the injected offtun/protect canon.
// Signature matches shared/offtun and shared/protect adapters.
var dialControl func(protectPath string, st *protectStat) func(network, address string, c syscall.RawConn) error

func WireDialControl(fn func(protectPath string, st *protectStat) func(network, address string, c syscall.RawConn) error) {
	dialControl = fn
}

// protectStat is optional metering; nil is fine for dialControl.
// Exported alias so package main can pass typed nil without importing unexported name.
type ProtectStat = protectStat

type protectStat struct{}

var (
	statusReady      = "ready"
	statusOK         = "ok"
	statusFatal      = "fatal"
	statusOffline    = "offline"
	statusConnecting = "connecting"
	statusWaiting    = "waiting"
	statusDegraded   = "degraded"
)

func WireStatusConsts(ready, ok, fatal string) {
	if ready != "" {
		statusReady = ready
	}
	if ok != "" {
		statusOK = ok
	}
	if fatal != "" {
		statusFatal = fatal
	}
}

var (
	openListener         func(port, listenFd int) (net.Listener, error)
	writeReady           func(profileDir string, port int) error
	awaitActionResultFn  func(ctx context.Context, profileDir, id string, timeout time.Duration) (string, bool)
	setHostEventHandler  func(fn func(string))
	startHostEventReader func()
)

func WireSocks(open func(port, listenFd int) (net.Listener, error), ready func(profileDir string, port int) error) {
	openListener = open
	writeReady = ready
}

func WireActions(await func(ctx context.Context, profileDir, id string, timeout time.Duration) (string, bool)) {
	awaitActionResultFn = await
}

func awaitActionResult(ctx context.Context, profileDir, id string, timeout time.Duration) (string, bool) {
	if awaitActionResultFn != nil {
		return awaitActionResultFn(ctx, profileDir, id, timeout)
	}
	return "", false
}

func WireHostEvents(set func(fn func(string)), start func()) {
	setHostEventHandler = set
	startHostEventReader = start
}
