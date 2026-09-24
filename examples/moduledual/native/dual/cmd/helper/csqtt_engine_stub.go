//go:build !windows && !cgo

package main

import "fmt"

func engineLoad(searchDirs ...string) error {
	_ = searchDirs
	return fmt.Errorf("CSQTT engine on this OS requires cgo (build with CGO_ENABLED=1)")
}

func engineSetProtect(fn func(int64) bool) { _ = fn }
func engineSetPacketOut(fn func([][]byte)) { _ = fn }
func engineInjectPacket(pkt []byte) error {
	return engineInjectPackets([][]byte{pkt})
}
func engineInjectPackets(pkts [][]byte) error {
	_ = pkts
	return fmt.Errorf("CSQTT engine on this OS requires cgo")
}
func engineDisconnect() {}
func engineStart(configJSON string) error {
	_ = configJSON
	return fmt.Errorf("CSQTT engine on this OS requires cgo")
}
func engineWaitReady(timeoutMs int) error { _ = timeoutMs; return fmt.Errorf("engine not ready") }
func enginePacketPort() int               { return 0 }
func engineTunIP() string                 { return "" }
func engineTunDNS() string                { return "" }
func engineStop()                         {}
func engineSetPaused(paused bool)         { _ = paused }
func engineActivePaths() int              { return -1 }
func engineNudge()                        {}
func engineRebind() bool                  { return false }
