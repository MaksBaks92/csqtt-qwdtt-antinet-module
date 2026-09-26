// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"context"
	"log"
	"net"
	"strings"
	"time"
)

// Own network-change detector (Wi-Fi ↔ cellular). Host sends handover/netback, but must not
// be the only path — CSQTT already learned netback is unreliable. Same trick as CSQTT:
// protected UDP connect() towards peer → LocalAddr = current underlay IP. Change → respawn.

const (
	qwNetChangePoll        = 5 * time.Second
	qwNetChangeDialTimeout = 500 * time.Millisecond
)

func sourceAddrTowardsPeer(target string) (string, bool) {
	if target == "" || protectControl == nil {
		return "", false
	}
	d := net.Dialer{Timeout: qwNetChangeDialTimeout, Control: protectControl}
	c, err := d.Dial("udp", target)
	if err != nil {
		return "", false
	}
	defer c.Close()
	a, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || a == nil || a.IP == nil || a.IP.IsUnspecified() {
		return "", false
	}
	return a.IP.String(), true
}

// startNetChangeMonitor — poll underlay source IP; onChange(from,to) when it flips.
// Desktop without protectControl: no-op (socket would route into TUN).
func startNetChangeMonitor(ctx context.Context, peer *net.UDPAddr, onChange func(from, to string)) {
	if peer == nil || onChange == nil || protectControl == nil {
		return
	}
	target := peer.String()
	if host, port, err := net.SplitHostPort(target); err == nil {
		if ip := net.ParseIP(host); ip == nil {
			// hostname — keep as-is; rare for qWDTT peer
			_ = port
		}
	}
	go func() {
		var last string
		ticker := time.NewTicker(qwNetChangePoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			addr, ok := sourceAddrTowardsPeer(target)
			if !ok || addr == "" {
				continue // no route — netlost owns pause; keep last
			}
			if last != "" && last != addr {
				from, to := last, addr
				last = addr
				log.Printf("[HELPER] underlay IP %s → %s", from, to)
				onChange(from, to)
				continue
			}
			last = addr
		}
	}()
}

func isDNSHostEvent(event string) bool {
	return strings.HasPrefix(strings.TrimSpace(event), "dns=")
}
