// SPDX-License-Identifier: MIT
//
// CSQTT is IPv4-only. System DNS (Yandex 77.88.8.8 / 8.8.8.8 through SOCKS)
// still returns AAAA, so Android 16 Happy Eyeballs sends IPv6 literals and
// sites like yandex.ru never load. Strip AAAA from DNS responses on UDP/53.

package main

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsAAAAFilterConn struct {
	net.Conn
}

func (c *dnsAAAAFilterConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil || n == 0 {
		return n, err
	}
	filtered, ok := stripDNSAAAA(p[:n])
	if !ok || len(filtered) == 0 || len(filtered) > len(p) {
		return n, nil
	}
	copy(p, filtered)
	return len(filtered), nil
}

func stripDNSAAAA(pkt []byte) ([]byte, bool) {
	var msg dnsmessage.Message
	if err := msg.Unpack(pkt); err != nil {
		return nil, false
	}
	if !msg.Response {
		return nil, false
	}
	msg.Answers = dropAAAA(msg.Answers)
	msg.Authorities = dropAAAA(msg.Authorities)
	msg.Additionals = dropAAAAKeepOPT(msg.Additionals)
	packed, err := msg.Pack()
	if err != nil {
		return nil, false
	}
	return packed, true
}

func dropAAAA(rrs []dnsmessage.Resource) []dnsmessage.Resource {
	out := rrs[:0]
	for _, rr := range rrs {
		if rr.Header.Type == dnsmessage.TypeAAAA {
			continue
		}
		if _, ok := rr.Body.(*dnsmessage.AAAAResource); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func dropAAAAKeepOPT(rrs []dnsmessage.Resource) []dnsmessage.Resource {
	out := rrs[:0]
	for _, rr := range rrs {
		if rr.Header.Type == dnsmessage.TypeAAAA {
			continue
		}
		if _, ok := rr.Body.(*dnsmessage.AAAAResource); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}
