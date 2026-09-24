// SPDX-License-Identifier: MIT
//
// Local CONNECT proxy: rust primp/reqwest has no protect() on TCP, so HTTPS to VK
// (api.vk.me, login.vk.ru) would enter AntiNet's TUN and die. The engine talks to
// 127.0.0.1 here; this process dials the origin with dialControl.

package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func startProtectHTTPProxy(protectPath string, resolver *protectedResolver) (string, func(), error) {
	// Empty list → LookupHost uses systemResolver under protect (no public-DNS hardcode).
	if resolver == nil {
		resolver = newProtectedResolver("", protectPath)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", func() {}, err
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleProtectProxy(w, r, protectPath, resolver) }),
		ReadHeaderTimeout: 12 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("CSQTT: protect HTTP proxy: %v", err)
		}
	}()
	stop := func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return "http://" + ln.Addr().String(), stop, nil
}

func handleProtectProxy(w http.ResponseWriter, r *http.Request, protectPath string, resolver *protectedResolver) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	hostport := r.Host
	if hostport == "" {
		http.Error(w, "empty host", http.StatusBadRequest)
		return
	}
	if !strings.Contains(hostport, ":") {
		hostport += ":443"
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	ip := host
	if net.ParseIP(host) == nil {
		ips, lerr := resolver.LookupHost(host)
		if lerr != nil || len(ips) == 0 {
			http.Error(w, "dns failed", http.StatusBadGateway)
			return
		}
		ip = pickIPv4(ips)
	}
	d := net.Dialer{
		Timeout: 12 * time.Second,
		Control: dialControl(protectPath, nil),
	}
	up, err := d.Dial("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	down, bufrw, err := hj.Hijack()
	if err != nil {
		up.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	if _, err := io.WriteString(bufrw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		up.Close()
		down.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		up.Close()
		down.Close()
		return
	}
	if bufrw.Reader.Buffered() > 0 {
		if _, err := io.CopyN(up, bufrw, int64(bufrw.Reader.Buffered())); err != nil {
			up.Close()
			down.Close()
			return
		}
	}
	go func() {
		_, _ = io.Copy(up, down)
		up.Close()
		down.Close()
	}()
	_, _ = io.Copy(down, up)
	up.Close()
	down.Close()
}

func pickIPv4(ips []string) string {
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil {
			return p.To4().String()
		}
	}
	return ips[0]
}
