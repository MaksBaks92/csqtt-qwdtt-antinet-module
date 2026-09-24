// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import "strings"

// workerErrorHint возвращает короткую подсказку для пользователя по тексту ошибки воркера.
func workerErrorHint(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "wrap_auth_timeout"):
		return "server did not respond to WRAP/DTLS - check the password, IP/port, and that wdtt-server is running"
	case strings.Contains(text, "context canceled"):
		return "connection aborted before handshake - usually server unreachable, UDP blocked by carrier, or network changed"
	case strings.Contains(text, "context deadline exceeded"):
		return "handshake timeout - server not responding, check the VPS, firewall, and WRAP password"
	case strings.Contains(text, "deadline exceeded") || strings.Contains(text, "timeout") || strings.Contains(text, "i/o timeout"):
		return "timeout - server not responding, check VPS availability and password"
	case strings.Contains(text, "connection refused"):
		return "server refused the connection - check the IP, DTLS port, and that wdtt-server is running"
	case strings.Contains(text, "connection reset"):
		return "server reset the connection - possibly a wrong WRAP password or a server restart"
	case strings.Contains(text, "no route") || strings.Contains(text, "network is unreachable"):
		return "no route to server - check your internet; disable other VPN/proxy clients"
	case strings.Contains(text, "lookup") || strings.Contains(text, "no such host"):
		return "DNS does not resolve the address - change DNS in Settings -> Network"
	case strings.Contains(text, "turn квота") || strings.Contains(text, "quota") || strings.Contains(text, "486"):
		return "VK exhausted TURN slots - reduce worker count or switch VK hash/account"
	case strings.Contains(text, "turn allocate"):
		return "TURN relay error - VK may be blocking UDP; try another hash or captcha mode"
	case strings.Contains(text, "rate limit") || strings.Contains(text, "flood") || strings.Contains(text, "error 29"):
		return "VK temporarily rate-limited requests - wait, or switch IP/hash"
	case strings.Contains(text, "rtp aead") || strings.Contains(text, "auth failed") || strings.Contains(text, "tag mismatch"):
		return "WRAP/RTP error - wrong password or an incompatible server version"
	case strings.Contains(text, "fatal_auth") || strings.Contains(text, "неверный пароль"):
		return "wrong connection password, or it has expired"
	case strings.Contains(text, "cannot create socket"):
		return "failed to open a UDP socket - firmware restriction or no network"
	default:
		return ""
	}
}
