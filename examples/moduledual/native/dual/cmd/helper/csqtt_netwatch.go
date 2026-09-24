// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"net"
	"strings"
	"time"
)

// Own network-change detector. The host is supposed to send `handover`, but the module must
// not depend on it (netback already proved unreliable). Every netChangePoll we create a
// protected UDP socket and connect() it towards the peer: no packet leaves the device, the
// kernel just picks a route, and LocalAddr tells us which interface/IP the current underlying
// network gives us. protect() pins the socket to the network the VPN currently rides on, so
// this is exactly the address the TURN sockets would get. A change between two successful
// probes = the network under our TURN paths moved → onChange.
//
// "No route" is not a change (netlost handles it); the last address is kept so that coming
// back on a different network is still detected.

const (
	netChangePoll        = 5 * time.Second
	netChangeDialTimeout = 500 * time.Millisecond
)

// sourceAddrTowards — the local IP a protected socket uses towards target ("ip:port").
func sourceAddrTowards(protectPath, target string) (string, bool) {
	d := net.Dialer{Timeout: netChangeDialTimeout, Control: dialControl(protectPath, nil)}
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

// netChangeTarget — "ip:port" for the route lookup. Uses the peer so no third-party address is
// hardcoded; a hostname is resolved through the protected resolver.
func netChangeTarget(peerAddr string, resolver *protectedResolver) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(peerAddr))
	if err != nil {
		host, port = strings.TrimSpace(peerAddr), "443"
	}
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, port)
	}
	if resolver == nil {
		return ""
	}
	ips, err := resolver.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return net.JoinHostPort(ips[0], port)
}

// netChangeTracker — pure state: feed it the current source IP, get "changed" back.
type netChangeTracker struct {
	last string
}

func (t *netChangeTracker) observe(addr string, ok bool) (from, to string, changed bool) {
	if !ok || addr == "" {
		return "", "", false
	}
	if t.last != "" && t.last != addr {
		from, to = t.last, addr
		changed = true
	}
	t.last = addr
	return from, to, changed
}

func startNetChangeMonitor(ctx context.Context, protectPath, peerAddr string, resolver *protectedResolver, onChange func(from, to string)) {
	if protectPath == "" || onChange == nil {
		return // desktop / tests: no protect → the socket would route into the TUN itself
	}
	go func() {
		var tracker netChangeTracker
		target := ""
		ticker := time.NewTicker(netChangePoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if target == "" {
				target = netChangeTarget(peerAddr, resolver)
				if target == "" {
					continue
				}
			}
			addr, ok := sourceAddrTowards(protectPath, target)
			if from, to, changed := tracker.observe(addr, ok); changed {
				onChange(from, to)
			}
		}
	}()
}
