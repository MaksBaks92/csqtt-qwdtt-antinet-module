// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAsyncSocksResolverDoesNotBlock(t *testing.T) {
	inner := &stubResolver{delay: 200 * time.Millisecond, ips: []string{"192.0.2.1"}}
	r := newAsyncSocksResolver(inner)
	start := time.Now()
	if _, err := r.LookupHost("example.test"); !errors.Is(err, errSocksDNSPending) {
		t.Fatalf("cold miss must be pending: %v", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("LookupHost must not wait on cold miss")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ips, err := r.LookupHost("example.test")
		if err == nil && len(ips) == 1 && ips[0] == "192.0.2.1" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cached answer never arrived")
}

type stubResolver struct {
	delay time.Duration
	ips   []string
}

func (s *stubResolver) LookupHost(host string) ([]string, error) {
	_ = host
	time.Sleep(s.delay)
	return append([]string(nil), s.ips...), nil
}

func TestSweepIdleUDPTargets(t *testing.T) {
	keepA, keepB := net.Pipe()
	dropA, dropB := net.Pipe()
	t.Cleanup(func() {
		_ = keepA.Close()
		_ = keepB.Close()
		_ = dropA.Close()
		_ = dropB.Close()
	})
	now := time.Now()
	live, _ := netip.ParseAddrPort("192.0.2.1:443")
	stale, _ := netip.ParseAddrPort("192.0.2.2:443")
	targets := map[netip.AddrPort]*udpNatEntry{
		live:  {conn: keepA, last: now.Add(-socksUDPIdleTTL / 2)},
		stale: {conn: dropA, last: now.Add(-socksUDPIdleTTL - time.Second)},
	}
	sweepIdleUDPTargets(targets, now)
	if _, ok := targets[live]; !ok {
		t.Fatal("fresh mapping must stay")
	}
	if _, ok := targets[stale]; ok {
		t.Fatal("idle mapping past TTL must go")
	}
	if _, err := dropB.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed idle conn must fail reads")
	}
}
