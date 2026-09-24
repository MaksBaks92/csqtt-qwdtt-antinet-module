// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// RequestConfig запрашивает WireGuard конфиг через DTLS-соединение.
func RequestConfig(conn net.Conn, localPort, deviceID, password string) (string, error) {
	payload := fmt.Sprintf("GETCONF:%s|%s|%s", localPort, deviceID, password)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", fmt.Errorf("sending GETCONF: %w", err)
	}

	b := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(configRequestBudget)); err != nil {
		return "", fmt.Errorf("setting deadline: %w", err)
	}
	n, err := conn.Read(b)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", fmt.Errorf("reading config response: %w", err)
	}

	resp := string(b[:n])
	if resp == "NOCONF" {
		return "", nil
	}

	if strings.HasPrefix(resp, "DENIED:") {
		reason := strings.TrimPrefix(resp, "DENIED:")
		switch reason {
		case "wrong_password":
			return "", fmt.Errorf("FATAL_AUTH: wrong connection password")
		case "expired":
			return "", fmt.Errorf("FATAL_AUTH: password has expired")
		case "device_mismatch":
			return "", fmt.Errorf("FATAL_AUTH: password is bound to another device")
		default:
			return "", fmt.Errorf("FATAL_AUTH: access denied (%s)", reason)
		}
	}

	return resp, nil
}

// SendAuth отправляет команду авторизации, чтобы сервер мог связать соединение с устройством
func SendAuth(conn net.Conn, deviceID, password string) error {
	payload := fmt.Sprintf("AUTH:%s|%s", deviceID, password)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("sending AUTH: %w", err)
	}

	return nil
}

// RequestRawConfig запрашивает у сервера конфигурацию для raw-IP режима
// (без WireGuard) — сервер отвечает "RAWCONF:ip|dns|mtu" (см. server/raw.go
// handleConnRaw). ip пусто на первый вызов, если сервер ещё не назначил его.
func RequestRawConfig(conn net.Conn, deviceID, password string) (ip, dnsCSV string, mtu int, err error) {
	// AntiNet: тексты ошибок английские — как и во всей остальной части этого файла (dev-лог, см.
	// корневой CLAUDE.md). Функция пришла с бампом 1.4.3 и была единственной непереведённой.
	// Токены протокола (`FATAL_AUTH`, `DENIED:`, `NOCONF`) НЕ трогаем: по ним матчат group.go и
	// classifyProgress, это часть контракта, а не текст для человека.
	payload := fmt.Sprintf("GETCONF_RAW:%s|%s", deviceID, password)
	if _, err = conn.Write([]byte(payload)); err != nil {
		return "", "", 0, fmt.Errorf("sending GETCONF_RAW: %w", err)
	}

	b := make([]byte, 4096)
	if err = conn.SetReadDeadline(time.Now().Add(configRequestBudget)); err != nil {
		return "", "", 0, fmt.Errorf("setting deadline: %w", err)
	}
	n, readErr := conn.Read(b)
	_ = conn.SetReadDeadline(time.Time{})
	if readErr != nil {
		return "", "", 0, fmt.Errorf("reading RAWCONF response: %w", readErr)
	}

	resp := string(b[:n])
	if resp == "NOCONF" {
		return "", "", 0, nil
	}
	if strings.HasPrefix(resp, "DENIED:") {
		reason := strings.TrimPrefix(resp, "DENIED:")
		switch reason {
		case "wrong_password":
			return "", "", 0, fmt.Errorf("FATAL_AUTH: wrong connection password")
		case "expired":
			return "", "", 0, fmt.Errorf("FATAL_AUTH: password has expired")
		case "device_mismatch":
			return "", "", 0, fmt.Errorf("FATAL_AUTH: password is bound to another device")
		default:
			return "", "", 0, fmt.Errorf("FATAL_AUTH: access denied (%s)", reason)
		}
	}
	// rawConfPrefix, а не литерал: префикс — одно знание на producer'а и всех потребителей
	// (rawtun.go::formatRawConf/parseRawConfLine, main.go, run.go).
	if !strings.HasPrefix(resp, rawConfPrefix) {
		return "", "", 0, fmt.Errorf("unexpected RAWCONF response: %q", resp)
	}

	parts := strings.Split(strings.TrimPrefix(resp, rawConfPrefix), "|")
	if len(parts) != 3 {
		return "", "", 0, fmt.Errorf("malformed RAWCONF: %q", resp)
	}
	mtuVal, convErr := strconv.Atoi(strings.TrimSpace(parts[2]))
	if convErr != nil {
		return "", "", 0, fmt.Errorf("malformed MTU in RAWCONF: %q", parts[2])
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), mtuVal, nil
}
