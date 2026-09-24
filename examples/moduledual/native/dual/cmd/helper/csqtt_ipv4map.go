// SPDX-License-Identifier: MIT
//
// CSQTT TUN is IPv4-only. Android 16 / Chrome still send IPv6 literals through
// SOCKS (Happy Eyeballs). Map them to IPv4 instantly when the address encodes
// one (NAT64 / 6to4 / Cloudflare / Google Public DNS), otherwise PTR then A.
// Google 1e100 names use in-xHH (IPv6-only) — rewrite to in-fDD which has A.

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type ipv4MapEntry struct {
	v4  netip.Addr
	err error
	exp time.Time
}

var ipv4Mapped sync.Map // netip.Addr → ipv4MapEntry
var ipv4MapOps atomic.Uint64

func mapIPv6To4(ip netip.Addr, resolver *protectedResolver) (netip.Addr, error) {
	ip = ip.Unmap()
	if ip.Is4() {
		return ip, nil
	}
	if !ip.Is6() {
		return netip.Addr{}, fmt.Errorf("not an IP")
	}
	if v, ok := ipv4Mapped.Load(ip); ok {
		e := v.(ipv4MapEntry)
		if time.Now().Before(e.exp) {
			return e.v4, e.err
		}
		ipv4Mapped.Delete(ip)
	}
	v4, err := deriveIPv4(ip, resolver)
	ttl := 10 * time.Minute
	if err != nil {
		ttl = 30 * time.Second
	}
	ipv4Mapped.Store(ip, ipv4MapEntry{v4: v4, err: err, exp: time.Now().Add(ttl)})
	if ipv4MapOps.Add(1)%64 == 0 {
		pruneIPv4Mapped(time.Now())
	}
	if err != nil {
		return netip.Addr{}, err
	}
	log.Printf("[SOCKS] IPv6 %s → IPv4 %s", ip, v4)
	return v4, nil
}

func pruneIPv4Mapped(now time.Time) {
	ipv4Mapped.Range(func(key, value any) bool {
		e := value.(ipv4MapEntry)
		if now.After(e.exp) {
			ipv4Mapped.Delete(key)
		}
		return true
	})
}

func deriveIPv4(ip netip.Addr, resolver *protectedResolver) (netip.Addr, error) {
	if v4, ok := nat64Embedded(ip); ok {
		return v4, nil
	}
	if v4, ok := sixToFour(ip); ok {
		return v4, nil
	}
	if v4, ok := cloudflareEmbedded(ip); ok {
		return v4, nil
	}
	if v4, ok := googlePublicDNS(ip); ok {
		return v4, nil
	}
	if skipSlowPTR(ip) {
		return netip.Addr{}, fmt.Errorf("IPv6 target %v: tunnel is IPv4-only", ip)
	}
	name, err := lookupPTRName(resolver, ip)
	if err != nil || name == "" {
		return netip.Addr{}, fmt.Errorf("IPv6 target %v: tunnel is IPv4-only", ip)
	}
	if v4, aerr := ipv4FromHost(resolver, name); aerr == nil {
		return v4, nil
	}
	if alt := google1e100IPv4Name(name); alt != "" && !strings.EqualFold(alt, name) {
		if v4, aerr := ipv4FromHost(resolver, alt); aerr == nil {
			return v4, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPv6 target %v: PTR %s has no A record", ip, name)
}

func ipv4FromHost(resolver *protectedResolver, host string) (netip.Addr, error) {
	if resolver == nil {
		return netip.Addr{}, fmt.Errorf("no resolver")
	}
	ips, err := resolver.LookupHost(strings.TrimSuffix(host, "."))
	if err != nil {
		return netip.Addr{}, err
	}
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no A for %s", host)
}

// google1e100IPv4Name turns lcarnb-ag-in-x0e.1e100.net into lcarnb-ag-in-f14.1e100.net.
// The in-xHH form is IPv6-only; in-fDD is the matching IPv4 frontend.
func google1e100IPv4Name(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	if !strings.HasSuffix(lower, ".1e100.net") {
		return ""
	}
	const tag = "-in-x"
	i := strings.LastIndex(lower, tag)
	if i < 0 {
		return ""
	}
	rest := lower[i+len(tag):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return ""
	}
	n, err := strconv.ParseUint(rest[:dot], 16, 32)
	if err != nil {
		return ""
	}
	return lower[:i] + "-in-f" + strconv.FormatUint(n, 10) + rest[dot:]
}

func nat64Embedded(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
		b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
		b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

func sixToFour(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] == 0x20 && b[1] == 0x02 {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

func cloudflareEmbedded(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] == 0x26 && b[1] == 0x06 && b[2] == 0x47 && b[3] == 0x00 {
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if v4.IsGlobalUnicast() && !v4.IsPrivate() {
			return v4, true
		}
	}
	return netip.Addr{}, false
}

// Microsoft / Azure / Hetzner / Cloudflare / AWS / Meta IPv6 almost never have a useful A
// sibling. Skip PTR so Happy Eyeballs can fall back to IPv4 immediately instead of waiting ~1s.
func skipSlowPTR(ip netip.Addr) bool {
	b := ip.As16()
	if b[0] == 0x26 && b[1] == 0x20 && b[2] == 0x01 && b[3] == 0xec {
		return true // 2620:1ec::/32 Microsoft 365
	}
	if b[0] == 0x26 && b[1] == 0x03 {
		return true // 2603::/16 Azure
	}
	if b[0] == 0x2a && b[1] == 0x01 && b[2] == 0x4f && b[3] == 0xf8 {
		return true // 2a01:4f8::/32 Hetzner
	}
	if b[0] == 0x26 && b[1] == 0x06 && b[2] == 0x47 && b[3] == 0x00 {
		return true // 2606:4700::/32 Cloudflare
	}
	if b[0] == 0x24 && b[1] == 0x00 && b[2] == 0xcb && b[3] == 0x00 {
		return true // 2400:cb00::/32 Cloudflare
	}
	if b[0] == 0x26 && b[1] == 0x00 && b[2] == 0x1f {
		return true // 2600:1f00::/24 AWS
	}
	if b[0] == 0x2a && b[1] == 0x03 && b[2] == 0x28 && b[3] == 0x80 {
		return true // 2a03:2880::/32 Meta
	}
	if b[0] == 0x2a && b[1] == 0x05 && b[2] == 0xd0 {
		return true // 2a05:d000::/29 AWS eu
	}
	return false
}

func googlePublicDNS(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] != 0x20 || b[1] != 0x01 || b[2] != 0x48 || b[3] != 0x60 {
		return netip.Addr{}, false
	}
	dns8888 := netip.MustParseAddr("8.8.8.8")
	dns8844 := netip.MustParseAddr("8.8.4.4")
	if b[4] == 0x48 && b[5] == 0x60 {
		if b[14] == 0x88 && b[15] == 0x88 {
			return dns8888, true
		}
		if b[14] == 0x88 && b[15] == 0x44 {
			return dns8844, true
		}
	}
	if b[6] == 0x77 && b[7] == 0x00 {
		return dns8888, true
	}
	return netip.Addr{}, false
}

func lookupPTRName(resolver *protectedResolver, ip netip.Addr) (string, error) {
	if resolver == nil {
		return "", fmt.Errorf("no resolver")
	}
	servers := resolver.currentServers()
	if len(servers) == 0 {
		servers = hostDNSServers()
	}
	if len(servers) == 0 {
		return "", errNoDNSServers
	}
	qname := ptrName(ip)
	var last error
	for _, srv := range servers {
		name, err := queryPTR(srv, resolver.protectPath, qname)
		if err == nil && name != "" {
			return name, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("dns: no PTR for %s", ip)
	}
	return "", last
}

func ptrName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var s strings.Builder
	s.Grow(72)
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&s, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	s.WriteString("ip6.arpa.")
	return s.String()
}

func queryPTR(server, protectPath, fqdn string) (string, error) {
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return "", err
	}
	d := net.Dialer{Timeout: 800 * time.Millisecond, Control: dialControl(protectPath, nil)}
	conn, err := d.Dial("udp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(packed); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return "", err
	}
	if resp.Header.ID != id || resp.Header.RCode != dnsmessage.RCodeSuccess {
		return "", fmt.Errorf("ptr rcode=%v", resp.Header.RCode)
	}
	for _, a := range resp.Answers {
		if rr, ok := a.Body.(*dnsmessage.PTRResource); ok {
			return strings.TrimSuffix(rr.PTR.String(), "."), nil
		}
	}
	return "", fmt.Errorf("no PTR answer")
}

func onlyIPv4(ips []string) []string {
	var out []string
	for _, s := range ips {
		if a := net.ParseIP(s); a != nil && a.To4() != nil {
			out = append(out, a.To4().String())
		}
	}
	return out
}
