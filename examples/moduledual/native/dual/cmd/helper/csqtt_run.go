// SPDX-License-Identifier: MIT
//
// CSQTT helper — протокол-модуль AntiNet. Каноны shared/* инжектит build.py.
// Data-plane: SOCKS5 → gVisor → in-process FFI → rust CSQTT engine (TURN/RTP).
// Движок — производный от https://github.com/amurcanov/csqtt (PolyForm-Noncommercial-1.0.0).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"dual-antinet/internal/qwdtt"
	"dual-antinet/internal/vk"
	"dual-antinet/tunnel"

	_ "golang.org/x/net/dns/dnsmessage" // канон shared/dns, инжектируется build.py
)

const (
	linkScheme      = "csqtt"
	linkHostConnect = "connect"
	defaultDialSec  = 20
	readyWaitBudget = 90 * time.Second
	maxVkHashes     = 4
	// Апстримный AUTH_TIMEOUT_MS = 300_000 (Constants.kt): столько же даём на вход с SMS/2FA.
	vkOAuthTimeout = 5 * time.Minute
	vkOAuthURLHop  = vkOAuthTimeout

	// Константы VK OAuth — дословно апстримные (`Constants.kt`: VK_OAUTH_AUTH_URL,
	// VK_OAUTH_REDIRECT_URI, VK_LOGIN_URL). Менять их здесь нельзя: `client_id`/`scope` привязаны к
	// приложению CSQTT, а домен — `vk.ru`, не `vk.com`.
	vkOAuthAuthURL = "https://oauth.vk.ru/authorize" +
		"?client_id=7793118" +
		"&scope=1073737727" +
		"&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html" +
		"&display=page" +
		"&response_type=token" +
		"&revoke=1" +
		"&v=5.199"
	vkLoginURL = "https://vk.ru/"
	// Хвост `VK_OAUTH_REDIRECT_URI`: на него VK уводит с `#access_token=…`, и именно его ловит
	// хост (§2.7, режим `navigation`).
	vkOAuthRedirectMark = "blank.html"
)

type csqttStrings struct {
	badLinkFmt           string
	missingHashes        string
	engineLoadFailedFmt  string
	engineStartFailedFmt string
	engineNotReadyFmt    string
	badTunIPFmt          string
	packetPortFailed     string
	bridgeListenFailed   string
	socksListenFailedFmt string
	writeReadyFailedFmt  string
	socksUpFmt           string
	openingEngine        string
	vkLoginProgress      string
	vkLoginFailedFmt     string
	vkAutoAPIProgress    string
	vkAutoAPIFailedFmt   string
	handoverLog          string
	hashFormTitle        string
	hashFormHint         string
	hashFormLabelFmt     string
	hashFormCancelled    string
	hashFormOk           string
	hashFormProgress     string
	deviceIDFmt          string
	deviceAuthOKFmt      string
}

var csqttStringsRU = csqttStrings{
	badLinkFmt:           "CSQTT: неверная ссылка: %v",
	missingHashes:        "CSQTT: в режиме «Ручной» заполните VK-хеш 1…4 в настройках модуля",
	engineLoadFailedFmt:  "CSQTT: не удалось загрузить движок: %v",
	engineStartFailedFmt: "CSQTT: движок не стартовал: %v",
	engineNotReadyFmt:    "CSQTT: туннель не поднялся за %s",
	badTunIPFmt:          "CSQTT: некорректный TUN IP %q",
	packetPortFailed:     "CSQTT: движок не открыл пакетный UDP-порт",
	bridgeListenFailed:   "CSQTT: не удалось открыть пакетный мост",
	socksListenFailedFmt: "CSQTT: не удалось взять SOCKS-листенер: %v",
	writeReadyFailedFmt:  "CSQTT: не удалось записать маркер готовности: %v",
	socksUpFmt:           "CSQTT: SOCKS5 поднят на 127.0.0.1:%d",
	openingEngine:        "CSQTT: поднимаю TURN-туннель",
	vkLoginProgress:      "CSQTT: войдите в VK и подтвердите доступ; окно закроется само",
	vkLoginFailedFmt:     "CSQTT: не удалось получить VK-токен: %v",
	vkAutoAPIProgress:    "CSQTT: создаю звонки VK через API",
	vkAutoAPIFailedFmt:   "CSQTT: не удалось создать звонки VK: %v",
	handoverLog:          "хендовер: сменилась сеть — перезапускаю data path",
	hashFormTitle:        "VK-хеши",
	hashFormHint:         "До 4 хешей. Можно вставить ссылку звонка. Только для режима «Ручной».",
	hashFormLabelFmt:     "VK-хеш %d",
	hashFormCancelled:    "CSQTT: ввод хешей отменён",
	hashFormOk:           "Подключить",
	hashFormProgress:     "CSQTT: укажите до 4 VK-хешей",
	deviceIDFmt:          "CSQTT: Device ID=%s (%s)",
	deviceAuthOKFmt:      "CSQTT: авторизовано · Device ID=%s",
}

var csqttStringsEN = csqttStrings{
	badLinkFmt:           "CSQTT: bad link: %v",
	missingHashes:        "CSQTT: in Manual mode fill VK hash 1…4 in module settings",
	engineLoadFailedFmt:  "CSQTT: failed to load engine: %v",
	engineStartFailedFmt: "CSQTT: engine failed to start: %v",
	engineNotReadyFmt:    "CSQTT: tunnel did not come up within %s",
	badTunIPFmt:          "CSQTT: bad TUN IP %q",
	packetPortFailed:     "CSQTT: engine did not open a packet UDP port",
	bridgeListenFailed:   "CSQTT: packet bridge listen failed",
	socksListenFailedFmt: "CSQTT: SOCKS listener failed: %v",
	writeReadyFailedFmt:  "CSQTT: failed to mark readiness: %v",
	socksUpFmt:           "CSQTT: SOCKS5 up on 127.0.0.1:%d",
	openingEngine:        "CSQTT: starting TURN tunnel",
	vkLoginProgress:      "CSQTT: sign in to VK and allow access; the window closes itself",
	vkLoginFailedFmt:     "CSQTT: failed to get VK token: %v",
	vkAutoAPIProgress:    "CSQTT: creating VK calls via API",
	vkAutoAPIFailedFmt:   "CSQTT: failed to create VK calls: %v",
	handoverLog:          "handover: network changed — recycling data path",
	hashFormTitle:        "VK hashes",
	hashFormHint:         "Up to 4 hashes. A call link is fine. Manual mode only.",
	hashFormLabelFmt:     "VK hash %d",
	hashFormCancelled:    "CSQTT: hash entry cancelled",
	hashFormOk:           "Connect",
	hashFormProgress:     "CSQTT: enter up to 4 VK hashes",
	deviceIDFmt:          "CSQTT: Device ID=%s (%s)",
	deviceAuthOKFmt:      "CSQTT: authorized · Device ID=%s",
}

func csqttStringsFor(lang string) csqttStrings {
	if strings.EqualFold(strings.TrimSpace(lang), "ru") {
		return csqttStringsRU
	}
	return csqttStringsEN
}

type csqttLink struct {
	Host     string
	Peer     string
	Password string
	Hashes   []string
	Name     string
}

func (l csqttLink) peerAddr() string {
	peer := strings.TrimSpace(l.Peer)
	host := strings.TrimSpace(l.Host)
	if strings.Contains(peer, ":") {
		return peer
	}
	if host == "" {
		return peer
	}
	if peer == "" {
		return host
	}
	return net.JoinHostPort(host, peer)
}

func (l csqttLink) server() string {
	if addr := l.peerAddr(); addr != "" {
		return addr
	}
	return "csqtt"
}

func (l csqttLink) displayName() string {
	if l.Name != "" {
		return l.Name
	}
	if host := strings.TrimSpace(l.Host); host != "" {
		return "CSQTT " + host
	}
	return "CSQTT"
}

func parseCsqttLink(raw string) (csqttLink, error) {
	var l csqttLink
	s := strings.TrimSpace(raw)
	if s == "" {
		return l, fmt.Errorf("empty link")
	}
	u, err := url.Parse(s)
	if err != nil {
		return l, fmt.Errorf("parse %q: %w", s, err)
	}
	if !strings.EqualFold(u.Scheme, linkScheme) {
		return l, fmt.Errorf("not a %s:// link", linkScheme)
	}
	l.Name = strings.TrimSpace(u.Fragment)
	host := strings.ToLower(strings.TrimSpace(u.Host))
	if host == linkHostConnect || u.Host == "" && strings.EqualFold(strings.Trim(u.Path, "/"), linkHostConnect) {
		q := u.Query()
		l.Host = strings.TrimSpace(q.Get("host"))
		l.Peer = strings.TrimSpace(q.Get("peer"))
		l.Password = strings.TrimSpace(q.Get("password"))
		l.Hashes = splitHashes(q.Get("hashes"))
		if l.Password == "" {
			return l, fmt.Errorf("connect: missing password=")
		}
		if l.Host == "" && l.Peer == "" {
			return l, fmt.Errorf("connect: missing host=/peer=")
		}
		return l, nil
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			l.Password = p
			if u.User.Username() != "" {
				l.Host = u.User.Username()
			}
		} else {
			l.Password = u.User.Username()
		}
	}
	if h := strings.TrimSpace(u.Host); h != "" {
		l.Peer = h
		if hostOnly, _, err := net.SplitHostPort(h); err == nil {
			l.Host = hostOnly
		} else {
			l.Host = h
		}
	}
	if extra := u.Query().Get("hashes"); extra != "" {
		l.Hashes = splitHashes(extra)
	}
	if l.Password == "" || l.peerAddr() == "" {
		return l, fmt.Errorf("legacy link needs password@host:port")
	}
	return l, nil
}

func splitHashes(raw string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '+' || r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		p = stripVkCallURL(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stripVkCallURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	prefixes := []string{
		"https://vk.com/call/join/",
		"http://vk.com/call/join/",
		"https://m.vk.com/call/join/",
		"http://m.vk.com/call/join/",
		"m.vk.com/call/join/",
		"vk.com/call/join/",
		"https://vk.ru/call/join/",
		"http://vk.ru/call/join/",
		"https://m.vk.ru/call/join/",
		"http://m.vk.ru/call/join/",
		"m.vk.ru/call/join/",
		"vk.ru/call/join/",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(strings.TrimSpace(s), "/")
}

// Manual hashes only. Auto API / Auto VK create their own and ignore these.
// Shared policy: dual-antinet/internal/vk (CSQTT hash collection).
func collectManualHashes(cfg map[string]string, linkHashes []string) []string {
	out := vk.CollectHashesFor(linkHashes, cfg, "csqtt")
	if len(out) > maxVkHashes {
		return out[:maxVkHashes]
	}
	return out
}

// settingPrefer — scheme-specific SETTING_ key, fallback to legacy shared key.
func settingPrefer(cfg map[string]string, primary, fallback string) string {
	if v := strings.TrimSpace(cfg[primary]); v != "" {
		return v
	}
	return strings.TrimSpace(cfg[fallback])
}

func normalizeCsqtt(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(strings.ToLower(s), linkScheme+"://") {
		return ""
	}
	if !strings.HasPrefix(s, "{") {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	str := func(k string) string {
		v, _ := m[k].(string)
		return strings.TrimSpace(v)
	}
	password := str("password")
	host := str("host")
	peer := str("peer")
	if password == "" || (host == "" && peer == "") {
		return ""
	}
	q := url.Values{}
	q.Set("v", "2")
	if host != "" {
		q.Set("host", host)
	}
	if peer != "" {
		q.Set("peer", peer)
	}
	q.Set("password", password)
	if h := str("hashes"); h != "" {
		q.Set("hashes", strings.Join(splitHashes(h), " "))
	}
	link := linkScheme + "://" + linkHostConnect + "?" + q.Encode()
	if n := str("name"); n != "" {
		link += "#" + url.PathEscape(n)
	}
	return link
}

func csqttCall(verb, arg string) string {
	switch verb {
	case "summarize":
		l, err := parseCsqttLink(arg)
		if err != nil {
			return "\n"
		}
		return l.displayName() + "\n" + l.server()
	case "normalize":
		return normalizeCsqtt(arg)
	case "canping":
		return canPingCSQTT(arg)
	}
	return ""
}

func canPingCSQTT(arg string) string {
	lines := strings.SplitN(arg, "\n", 3)
	link := ""
	blob := ""
	if len(lines) > 0 {
		link = strings.TrimSpace(lines[0])
	}
	if len(lines) > 2 {
		blob = lines[2]
	}
	if l, err := parseCsqttLink(link); err == nil && len(l.Hashes) > 0 {
		return "ok"
	}
	st := restoreSavedState(blob)
	if len(st.ManualHashes) > 0 || len(st.AutoHashes) > 0 || st.VKToken != "" {
		return "ok"
	}
	return "no"
}

func csqttRun(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath
	startHostEventReader()
	dieWithParent()
	protectFromOomKill()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := parseConfig(configContent)
	s := csqttStringsFor(cfg["APP_LANG"])
	persisted = restoreSavedState(cfg["MODULE_STATE"])
	qwdtt.HydrateTurnFromModuleState(cfg["MODULE_STATE"])
	deviceID, generation, sessionSalt := nextEngineIdentity(cfg, &persisted)
	persistState()
	emitLog(s.deviceIDFmt, deviceID, persistedDeviceSource(cfg, deviceID))
	port, _ := strconv.Atoi(cfg["LISTEN_PORT"])
	user := cfg["SOCKS_USER"]
	pass := cfg["SOCKS_PASS"]
	debug := cfg["SETTING_debugLog"] == "true"
	SetSocksUDPVerboseLog(debug)

	link, err := parseCsqttLink(cfg["LINK"])
	if err != nil {
		emitLog(s.badLinkFmt, err)
		emitStatus(statusFatal, "bad link")
		log.Fatalf("parse LINK: %v", err)
	}
	workers, _ := strconv.Atoi(settingPrefer(cfg, "SETTING_csqttWorkers", "SETTING_workers"))
	if workers <= 0 {
		workers = 18
	}

	dnsCSV := strings.TrimSpace(cfg["DNS_SERVERS"])
	if dnsCSV == "" {
		// Android: DNS_SERVERS часто пуст после OAuth (TUN снят) → hostDNS/preset UDP.
		dnsCSV = qwdtt.ProtectDNSCsv(cfg["SETTING_dnsPreset"], hostDNSServers())
	}
	resolver := newProtectedResolver(dnsCSV, protectPath)
	configureVkHTTP(protectPath, resolver)

	hashMode, authMode := normalizeVkModes(
		settingPrefer(cfg, "SETTING_csqttHashMode", "SETTING_hashMode"),
		settingPrefer(cfg, "SETTING_csqttAuthMode", "SETTING_vkAuthMode"),
	)
	if vk.NormalizeHashMode(settingPrefer(cfg, "SETTING_csqttHashMode", "SETTING_hashMode")) == "manual" &&
		vk.NormalizeAuthMode(settingPrefer(cfg, "SETTING_csqttAuthMode", "SETTING_vkAuthMode")) == "auto_js" {
		emitLog("CSQTT: Режим хешей=Ручной — «Авто ВК» в кредах отключён (движок требует Авто ВК и для хешей). Креды: Авто (vkcalls). Для аккаунтных TURN поставьте оба режима «Авто ВК».")
	}
	emitLog("CSQTT: режим хешей=%s · режим кредов=%s", hashMode, authModeLabel(authMode))
	vkToken := ""
	allowRedistrib := false
	var hashes []string
	seedHashes := uniqHashes(append(collectManualHashes(cfg, link.Hashes), persisted.ManualHashes...))
	needHashes := callCountForWorkers(workers)
	// Авто-хеши из MODULE_STATE — до OAuth, если уже хватает на workers.
	if hashMode == "auto_api" {
		if cached, ok := takeCachedAutoHashes(); ok {
			hashes = cached
			left := autoHashesTTL - time.Since(time.Unix(persisted.AutoHashesAt, 0))
			emitLog("CSQTT: auto hashes cache hit · %d · need=%d · TTL left %s", len(hashes), needHashes, left.Truncate(time.Second))
		}
	}
	// Token FIRST. OAuth не нужен, если auto_api-кеш уже покрывает needHashes и креды не auto_js.
	needOAuth := needsVkOAuth(hashMode, authMode) &&
		!(hashMode == "auto_api" && len(hashes) >= needHashes && authMode != "auto_js")
	if needOAuth {
		tok, terr := ensureVkToken(cfg["MODULE_STATE"], profileDir, s, resolver)
		if terr != nil {
			// Как в ≤1.2.5: при срыве OAuth/API не роняем сессию, если хеши уже есть.
			if len(seedHashes) > 0 {
				emitLog("CSQTT: вход в VK не удался (%v), беру хеши из ссылки/настроек/состояния", terr)
				hashMode = "manual"
				authMode = "vkcalls"
				hashes = seedHashes
			} else if cached, ok := takeCachedAutoHashes(); ok {
				emitLog("CSQTT: вход в VK не удался (%v), беру auto hashes из состояния", terr)
				hashMode = "manual"
				authMode = "vkcalls"
				hashes = cached
			} else {
				emitLog(s.vkLoginFailedFmt, terr)
				emitStatus(statusFatal, "vk login failed")
				log.Fatalf("vk token: %v", terr)
			}
		} else {
			vkToken = tok
		}
	}
	if len(hashes) == 0 {
		switch hashMode {
		case "auto_api":
			if len(persisted.AutoHashes) > 0 {
				emitLog("CSQTT: auto hashes cache expired — refresh via calls.start")
				expireAutoHashes(vkToken)
			}
			emitProgress("%s", s.vkAutoAPIProgress)
			started, aerr := startVkAutoCalls(vkToken, workers)
			if errors.Is(aerr, errVkTokenInvalid) {
				saveVkToken("")
				emitProgress("%s", s.vkLoginProgress)
				fresh, ferr := requestVkAccessToken(profileDir)
				if ferr != nil {
					if len(seedHashes) > 0 {
						emitLog("CSQTT: вход в VK не удался (%v), беру хеши из ссылки/настроек/состояния", ferr)
						hashMode = "manual"
						authMode = "vkcalls"
						hashes = seedHashes
					} else {
						emitLog(s.vkLoginFailedFmt, ferr)
						emitStatus(statusFatal, "vk login failed")
						log.Fatalf("vk token: %v", ferr)
					}
				} else {
					vkToken = fresh
					saveVkToken(vkToken)
					started, aerr = startVkAutoCalls(vkToken, workers)
				}
			}
			if hashMode == "auto_api" {
				if aerr != nil || len(started.Hashes) == 0 {
					if aerr == nil {
						aerr = fmt.Errorf("empty hash list")
					}
					if len(seedHashes) > 0 {
						emitLog("CSQTT: Авто API не удалось (%v), беру хеши из ссылки/настроек/состояния", aerr)
						hashMode = "manual"
						authMode = "vkcalls"
						hashes = seedHashes
					} else {
						emitLog(s.vkAutoAPIFailedFmt, aerr)
						emitStatus(statusFatal, "vk auto api failed")
						log.Fatalf("vk auto api: %v", aerr)
					}
				} else {
					hashes = started.Hashes
					storeAutoHashes(started)
					// Не forceFinish на стопе — хеши в MODULE_STATE до TTL.
				}
			}
		case "auto_js":
			// токен уже в vkToken — rust создаёт звонок сам
		default:
			hashes = seedHashes
			if len(hashes) == 0 {
				filled, herr := promptManualHashes(profileDir, hashes, s)
				if herr != nil {
					emitLog("%s", herr)
					emitStatus(statusFatal, "missing vk hashes")
					log.Fatalf("vk hashes: %v", herr)
				}
				hashes = filled
			}
			if len(hashes) == 0 {
				emitLog(s.missingHashes)
				emitStatus(statusFatal, "missing vk hashes")
				log.Fatalf("missing vk hashes")
			}
			persisted.ManualHashes = hashes
			persistState()
		}
	} else if hashMode == "manual" {
		persisted.ManualHashes = hashes
		persistState()
	}

	// CSQTT: 1 хеш ≈ 3×9 = 27 воркеров / ≈ один VK TURN-аллокатор (~2–3 Мбит на поток,
	// суммарно часто ~30–40 Мбит на звонок). Недобор хешей → шаринг → потолок скорости.
	// Добор calls.start только недостающих (не каждый connect, если need уже покрыт).
	emitLog("CSQTT: workers=%d · hashes=%d · need=%d", workers, len(hashes), needHashes)
	if hashMode == "auto_api" && len(hashes) > 0 && len(hashes) < needHashes {
		missing := needHashes - len(hashes)
		if room := maxVkHashes - len(hashes); room < missing {
			missing = room
		}
		if missing > 0 {
			emitLog("CSQTT: добор хешей %d→%d (нехватка %d) — иначе потолок VK Calls ~35 Мбит", len(hashes), needHashes, missing)
			if vkToken == "" {
				tok, terr := ensureVkToken(cfg["MODULE_STATE"], profileDir, s, resolver)
				if terr != nil {
					emitLog("CSQTT: добор хешей без токена (%v) — оставляю %d, allowRedistrib", terr, len(hashes))
				} else {
					vkToken = tok
				}
			}
			if vkToken != "" {
				emitProgress("%s", s.vkAutoAPIProgress)
				started, aerr := startVkAutoCallsCount(vkToken, missing)
				if errors.Is(aerr, errVkTokenInvalid) {
					saveVkToken("")
					fresh, ferr := requestVkAccessToken(profileDir)
					if ferr == nil {
						vkToken = fresh
						saveVkToken(vkToken)
						started, aerr = startVkAutoCallsCount(vkToken, missing)
					}
				}
				if aerr == nil && len(started.Hashes) > 0 {
					hashes = uniqHashes(append(hashes, started.Hashes...))
					if len(hashes) > maxVkHashes {
						hashes = hashes[:maxVkHashes]
					}
					appendAutoHashes(started)
					emitLog("CSQTT: хеши после добора=%d", len(hashes))
				} else if aerr != nil {
					emitLog("CSQTT: добор хешей не удался (%v)", aerr)
				}
			}
		}
	}
	if len(hashes) > 0 && len(hashes) < needHashes {
		allowRedistrib = true
		// Грубая оценка: ~2 Мбит/воркер на общем аллокаторе → видимый потолок.
		estMbps := len(hashes) * 35
		emitLog("CSQTT: soft-share %d hashes for %d workers (need=%d) — ожидаемый потолок ~%d Мбит; поднимите хеши (Авто API) или снизьте воркеры",
			len(hashes), workers, needHashes, estMbps)
	}

	// Engine off-TUN CONNECT proxy only AFTER token/hashes are ready.
	proxyURL, stopProxy, perr := startProtectHTTPProxy(protectPath, resolver)
	if perr != nil {
		emitLog("CSQTT: off-TUN HTTP proxy: %v", perr)
		stopProxy = func() {}
	} else {
		defer stopProxy()
	}

	dialTimeout := settingDuration(cfg, "SETTING_dialTimeoutSec", defaultDialSec)
	obfs := strings.TrimSpace(cfg["SETTING_obfs"])
	turnTransport := strings.ToLower(strings.TrimSpace(cfg["SETTING_turnTransport"]))
	switch turnTransport {
	case "tcp", "tcp_tls", "tcp-tls", "tcp/tls":
		turnTransport = "tcp_tls"
	default:
		turnTransport = "udp"
	}
	// Same-socket FEC (official default on). Off only on stable Wi‑Fi if user wants less uplink noise.
	fecDuplicate := cfg["SETTING_fecDuplicate"] != "false"
	// Idle scale-down (engine idle.rs): keepers held while uplink is quiet, rest parked.
	// Missing setting → engine default (2 / 180 s); explicit 0 workers → off.
	idleWorkers, idleAfterSec := idleSettings(cfg, workers)

	// Shared TURN seeds: prefetch via qWDTT GetCreds (same VK Calls path) into rust turn_seed.
	turnSeeds := prefetchSharedTurnSeeds(cfg, protectPath, hashes, authMode, s)

	search := []string{profileDir}
	if profileDir != "" {
		search = append(search, filepath.Dir(profileDir), filepath.Dir(filepath.Dir(profileDir)))
	}
	if err := engineLoad(search...); err != nil {
		emitLog(s.engineLoadFailedFmt, err)
		emitStatus(statusFatal, "engine load failed")
		log.Fatalf("engine load: %v", err)
	}

	protectFn := protectFdFunc(protectPath)
	engineSetProtect(func(fd int64) bool {
		if protectFn == nil {
			return true
		}
		return protectFn(int32(fd))
	})

	engineJSON := map[string]any{
		"peer":           link.peerAddr(),
		"password":       link.Password,
		"hashes":         strings.Join(hashes, ","),
		"workers":        workers,
		"device_id":      deviceID,
		"generation":     generation,
		"salt":           sessionSalt,
		"captcha_mode":   "auto",
		"vk_auth_mode":   authMode,
		"obfs":           obfs,
		"turn_transport": turnTransport,
		"fec_duplicate":  fecDuplicate,
		"fingerprint":    "firefox",
		"packet_bridge":  true,
	}
	if idleWorkers >= 0 {
		engineJSON["idle_workers"] = idleWorkers
	}
	if idleAfterSec > 0 {
		engineJSON["idle_after_secs"] = idleAfterSec
	}
	if proxyURL != "" {
		engineJSON["http_proxy"] = proxyURL
	}
	if hashMode == "auto_js" && vkToken != "" {
		engineJSON["vk_hash_mode"] = "auto_js"
		engineJSON["vk_js_token"] = vkToken
	}
	if allowRedistrib {
		engineJSON["allow_hash_redistribution"] = true
	}
	if len(turnSeeds) > 0 {
		engineJSON["turn_seed"] = turnSeeds
		emitLog("CSQTT: shared TURN seed count=%d (qWDTT GetCreds → rust)", len(turnSeeds))
	}
	engineCfg, _ := json.Marshal(engineJSON)

	emitProgress(s.openingEngine)
	// Downlink sink registered before start so early packets are not dropped.
	var inbound atomic.Pointer[func([][]byte)]
	engineSetPacketOut(func(pkts [][]byte) {
		if fn := inbound.Load(); fn != nil {
			(*fn)(pkts)
		}
	})
	if err := engineStart(string(engineCfg)); err != nil {
		emitLog(s.engineStartFailedFmt, err)
		emitStatus(statusFatal, "engine start failed")
		log.Fatalf("engine start: %v", err)
	}
	defer engineStop()

	if err := engineWaitReady(int(readyWaitBudget / time.Millisecond)); err != nil {
		emitLog(s.engineNotReadyFmt, readyWaitBudget)
		emitStatus(statusFatal, "engine not ready")
		log.Fatalf("engine wait: %v", err)
	}

	tunIP := net.ParseIP(strings.TrimSpace(engineTunIP()))
	if tunIP == nil || tunIP.To4() == nil {
		emitLog(s.badTunIPFmt, engineTunIP())
		emitStatus(statusFatal, "bad tun ip")
		log.Fatalf("bad TUN IP %q", engineTunIP())
	}

	// In-process bridge: gVisor ↔ rust without UDP 127.0.0.1.
	var liveTun atomic.Pointer[tunnel.IPTunnel]
	injectUp := func(pkts [][]byte) {
		if err := engineInjectPackets(pkts); err != nil && debug {
			log.Printf("[BRIDGE] inject: %v", err)
		}
	}
	tun, err := tunnel.NewIPTunnel(tunIP, injectUp)
	if err != nil {
		emitStatus(statusFatal, "netstack failed")
		log.Fatalf("netstack: %v", err)
	}
	liveTun.Store(tun)
	defer func() {
		if t := liveTun.Swap(nil); t != nil {
			t.Close()
		}
	}()
	deliver := func(pkts [][]byte) {
		if t := liveTun.Load(); t != nil {
			t.InjectInboundBatch(pkts)
		}
	}
	inbound.Store(&deliver)

	ln, err := openListener(port, listenFd)
	if err != nil {
		emitLog(s.socksListenFailedFmt, err)
		emitStatus(statusFatal, "socks listen failed")
		log.Fatalf("listen 127.0.0.1:%d: %v", port, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	if err := writeReady(profileDir, actualPort); err != nil {
		emitLog(s.writeReadyFailedFmt, err)
		emitStatus(statusFatal, "write ready marker failed")
		log.Fatalf("write ready marker: %v", err)
	}
	emitProgress(s.socksUpFmt, actualPort)
	emitLog(s.deviceAuthOKFmt, deviceID)
	emitStatus(statusOK, "")
	log.Printf("csqtt helper: SOCKS5 on 127.0.0.1:%d tun=%s dns=%s bridge=in-process", actualPort, tunIP, engineTunDNS())

	guard := newDataPathGuard(string(engineCfg), readyWaitBudget, 0, tunIP.String())
	guard.rebuildTunFn = func(newIP string) error {
		ip := net.ParseIP(strings.TrimSpace(newIP))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("bad tun ip %q", newIP)
		}
		nt, err := tunnel.NewIPTunnel(ip, injectUp)
		if err != nil {
			return err
		}
		old := liveTun.Swap(nt)
		d := func(pkts [][]byte) {
			if t := liveTun.Load(); t != nil {
				t.InjectInboundBatch(pkts)
			}
		}
		inbound.Store(&d)
		if old != nil {
			old.Close()
		}
		return nil
	}
	// Offline self-probe (paused watchdog / wake while paused): one protected DNS round trip
	// to a name we need anyway. Fails fast without a route, proves reachability with one.
	probeHost := networkProbeHost(link.peerAddr())
	guard.probeFn = func() bool { return probeNetwork(resolver, probeHost) }
	startWakeMonitor(context.Background(), guard.onWake)
	// Own Wi-Fi ↔ cellular detector (netwatch.go): does not depend on the host's `handover`.
	startNetChangeMonitor(context.Background(), protectPath, link.peerAddr(), resolver, func(from, to string) {
		emitLog("CSQTT: сменился адрес сети %s → %s", from, to)
		guard.onHandover("netchange")
	})

	setHostEventHandler(func(event string) {
		// dns=<…> забирает канон hostproto→rememberHostDNSServers (подписка newProtectedResolver).
		switch event {
		case "handover", "netlost", "netback", "stall", "stop":
			if event == "handover" {
				emitLog(s.handoverLog)
			}
			guard.onHostEvent(event)
		}
	})

	getTun := func() *tunnel.IPTunnel { return liveTun.Load() }
	udpT := csqttUDPTransport{getTun: getTun, resolver: resolver}
	// Soft cap: recycle/wake can hold many CONNECTs; do not spawn unbounded accept goroutines.
	socksSem := make(chan struct{}, 128)
	serveSocksListener(ln, func(c net.Conn) {
		select {
		case socksSem <- struct{}{}:
			defer func() { <-socksSem }()
			handleConn(c, user, pass, getTun, resolver, udpT, dialTimeout, guard)
		default:
			_ = c.Close()
		}
	})
	return 0
}

// networkProbeHost — a hostname whose resolution proves "network usable": the peer host from the
// link, or a VK API name (needed by the engine anyway) when the peer is an IP literal.
func networkProbeHost(peerAddr string) string {
	host := strings.TrimSpace(peerAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || net.ParseIP(host) != nil {
		return "api.vk.com"
	}
	return host
}

// probeNetwork — one UNCACHED protected DNS round trip. LookupHost's cache expiry is a
// monotonic deadline that does not advance while the phone sleeps, so a cached answer right
// after a wake proves nothing about the network; queryAll always goes to the wire.
func probeNetwork(r *protectedResolver, host string) bool {
	if r == nil {
		return false
	}
	if len(r.currentServers()) == 0 {
		// System-resolver path is uncached already.
		_, err := r.LookupHost(host)
		return err == nil
	}
	ips, err := r.queryAll(host)
	return err == nil && len(ips) > 0
}

type csqttUDPTransport struct {
	getTun   func() *tunnel.IPTunnel
	resolver *protectedResolver
}

func (t csqttUDPTransport) LookupHost(host string) ([]string, error) {
	ips, err := t.resolver.LookupHost(host)
	if err != nil {
		return nil, err
	}
	v4 := onlyIPv4(ips)
	if len(v4) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s (got %v)", host, ips)
	}
	return v4, nil
}

func (t csqttUDPTransport) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	ip := dst.Addr()
	if !ip.Is4() && !ip.Is4In6() {
		mapped, err := mapIPv6To4(ip, t.resolver)
		if err != nil {
			return nil, errSocksTargetUnreachable
		}
		dst = netip.AddrPortFrom(mapped, dst.Port())
	}
	tun := t.getTun()
	if tun == nil {
		return nil, errors.New("tunnel down")
	}
	c, err := tun.DialUDP(dst)
	if err != nil {
		return nil, err
	}
	if dst.Port() == 53 {
		return &dnsAAAAFilterConn{Conn: c}, nil
	}
	return c, nil
}

// idleSettings maps SETTING_idleWorkers / SETTING_idleAfterSec to engine values.
// workers = -1 means "not set, let the engine decide"; afterSec = 0 likewise.
// The keeper count is clamped to the configured worker total so a stale setting
// can never ask to keep more paths than exist.
func idleSettings(cfg map[string]string, workers int) (idleWorkers, afterSec int) {
	idleWorkers = -1
	if raw := strings.TrimSpace(cfg["SETTING_idleWorkers"]); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			idleWorkers = v
			if workers > 0 && idleWorkers > workers {
				idleWorkers = workers
			}
		}
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_idleAfterSec"])); err == nil && v > 0 {
		afterSec = v
	}
	return idleWorkers, afterSec
}

func settingDuration(cfg map[string]string, key string, defSec int) time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(cfg[key])); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defSec) * time.Second
}

func handleConn(c net.Conn, user, pass string, getTun func() *tunnel.IPTunnel, resolver *protectedResolver, udpT csqttUDPTransport, dialTimeout time.Duration, guard *dataPathGuard) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(45 * time.Second)
	}
	br := bufio.NewReader(c)
	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		if guard != nil && guard.rejecting() {
			_, _ = c.Write(socksRep(0x01))
			return
		}
		serveSocksUDPAssociate(c, br, udpT)
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))
	dialStart := time.Now()
	if guard != nil && guard.rejecting() {
		// Fast-fail while paused/exiting so host FIRE can accumulate rejects
		// instead of hanging on 20s dials and 146-byte scraps. Recycle/rebind
		// holds the CONNECT in waitForPath instead of rejecting.
		logSocksReject("[SOCKS] reject (data path recovering) target=%s", target)
		_, _ = c.Write(socksRep(0x01))
		return
	}

	// Overlap DNS with waitForPath: after wake/handover the workers reconnect while we resolve.
	type resolveOut struct {
		ip  string
		err error
	}
	resolved := make(chan resolveOut, 1)
	go func() {
		ip, err := resolveV4(req, resolver)
		resolved <- resolveOut{ip, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if guard != nil {
		guard.waitForPath(ctx)
	}
	res := <-resolved
	if res.err != nil {
		log.Printf("[SOCKS] resolve FAILED host=%s err=%v", host, res.err)
		_, _ = c.Write(socksRep(0x04))
		return
	}
	tun := getTun()
	if tun == nil {
		_, _ = c.Write(socksRep(0x01))
		return
	}
	up, err := tun.DialTCP(ctx, res.ip, req.Port)
	if guard != nil {
		guard.noteDialResult(err)
	}
	if err != nil {
		logSocksReject("[SOCKS] tunnel dial FAILED target=%s ip=%s elapsed=%v err=%v", target, res.ip, time.Since(dialStart), err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}
	relayBidi(c, br, up, target, dialStart)
}

var lastSocksRejectLog atomic.Int64

func logSocksReject(format string, args ...any) {
	now := time.Now().Unix()
	prev := lastSocksRejectLog.Load()
	if prev != 0 && now-prev < 2 {
		return
	}
	if lastSocksRejectLog.CompareAndSwap(prev, now) {
		log.Printf(format, args...)
	}
}

func resolveV4(req socksRequest, resolver *protectedResolver) (string, error) {
	if req.IsIP() {
		ip := req.IP.Unmap()
		if ip.Is4() {
			return ip.String(), nil
		}
		mapped, err := mapIPv6To4(ip, resolver)
		if err != nil {
			return "", err
		}
		return mapped.String(), nil
	}
	ips, err := resolver.LookupHost(req.Host)
	if err != nil {
		return "", err
	}
	v4 := onlyIPv4(ips)
	if len(v4) == 0 {
		return "", fmt.Errorf("no IPv4 address for %s (got %v)", req.Host, ips)
	}
	return v4[0], nil
}

type savedState struct {
	VKToken      string   `json:"vk_token"`
	DeviceID     string   `json:"device_id"`
	Generation   uint64   `json:"generation"`
	ManualHashes []string `json:"manual_hashes,omitempty"`
	// Авто API: хеши живут в MODULE_STATE до TTL — без calls.start/forceFinish на каждый connect.
	AutoHashes   []string `json:"auto_hashes,omitempty"`
	AutoCallIDs  []string `json:"auto_call_ids,omitempty"`
	AutoHashesAt int64    `json:"auto_hashes_at,omitempty"`
}

// autoHashesTTL — как у ручных hashes= в ссылке (дни). Пока не истёк — только reuse.
const autoHashesTTL = 72 * time.Hour

var persisted savedState

func restoreSavedState(blob string) savedState {
	var st savedState
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return st
	}
	raw := []byte(blob)
	if dec, err := base64.StdEncoding.DecodeString(blob); err == nil && len(dec) > 0 {
		raw = dec
	}
	_ = json.Unmarshal(raw, &st)
	st.VKToken = strings.TrimSpace(st.VKToken)
	st.DeviceID = strings.TrimSpace(st.DeviceID)
	st.ManualHashes = uniqHashes(st.ManualHashes)
	st.AutoHashes = uniqHashes(st.AutoHashes)
	if len(st.AutoCallIDs) > len(st.AutoHashes) {
		st.AutoCallIDs = st.AutoCallIDs[:len(st.AutoHashes)]
	}
	return st
}

func restoredVkToken(blob string) string {
	return restoreSavedState(blob).VKToken
}

func helperStateFields() map[string]any {
	m := map[string]any{
		"vk_token":   persisted.VKToken,
		"device_id":  persisted.DeviceID,
		"generation": persisted.Generation,
	}
	if len(persisted.ManualHashes) > 0 {
		m["manual_hashes"] = append([]string(nil), persisted.ManualHashes...)
	}
	if len(persisted.AutoHashes) > 0 {
		m["auto_hashes"] = append([]string(nil), persisted.AutoHashes...)
		m["auto_call_ids"] = append([]string(nil), persisted.AutoCallIDs...)
		m["auto_hashes_at"] = persisted.AutoHashesAt
	}
	return m
}

func autoHashesCacheValid() bool {
	if len(persisted.AutoHashes) == 0 || persisted.AutoHashesAt <= 0 {
		return false
	}
	age := time.Since(time.Unix(persisted.AutoHashesAt, 0))
	return age >= 0 && age < autoHashesTTL
}

func takeCachedAutoHashes() ([]string, bool) {
	if !autoHashesCacheValid() {
		return nil, false
	}
	out := append([]string(nil), persisted.AutoHashes...)
	return out, true
}

func storeAutoHashes(started vkAutoStart) {
	persisted.AutoHashes = uniqHashes(started.Hashes)
	ids := make([]string, 0, len(started.Calls))
	for _, c := range started.Calls {
		if id := strings.TrimSpace(c.CallID); id != "" {
			ids = append(ids, id)
		}
	}
	persisted.AutoCallIDs = ids
	persisted.AutoHashesAt = time.Now().Unix()
	persistState()
}

// appendAutoHashes — дописать новые авто-звонки к кешу (добор под workers), TTL не сбрасываем.
func appendAutoHashes(started vkAutoStart) {
	persisted.AutoHashes = uniqHashes(append(persisted.AutoHashes, started.Hashes...))
	for _, c := range started.Calls {
		if id := strings.TrimSpace(c.CallID); id != "" {
			persisted.AutoCallIDs = append(persisted.AutoCallIDs, id)
		}
	}
	if persisted.AutoHashesAt <= 0 {
		persisted.AutoHashesAt = time.Now().Unix()
	}
	persistState()
}

func expireAutoHashes(token string) {
	if len(persisted.AutoCallIDs) == 0 && len(persisted.AutoHashes) == 0 {
		return
	}
	calls := make([]vkActiveCall, 0, len(persisted.AutoCallIDs))
	for i, id := range persisted.AutoCallIDs {
		h := ""
		if i < len(persisted.AutoHashes) {
			h = persisted.AutoHashes[i]
		}
		calls = append(calls, vkActiveCall{CallID: id, Hash: h})
	}
	if tok := strings.TrimSpace(token); tok != "" && len(calls) > 0 {
		finishVkAutoCalls(tok, calls)
	}
	persisted.AutoHashes = nil
	persisted.AutoCallIDs = nil
	persisted.AutoHashesAt = 0
	persistState()
}

func persistState() {
	body, err := json.Marshal(persisted)
	if err != nil {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	// Не затирать TURN-поля из последнего SaveCredsToHost (единый MODULE_STATE).
	for k, v := range qwdtt.LastTurnStateFields() {
		m[k] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		return
	}
	fmt.Printf("STATE_SAVE|%s\n", base64.StdEncoding.EncodeToString(out))
	_ = os.Stdout.Sync()
}

func nextEngineIdentity(cfg map[string]string, st *savedState) (deviceID string, generation uint64, salt string) {
	deviceID = strings.TrimSpace(cfg["SETTING_deviceId"])
	if deviceID == "" {
		deviceID = strings.TrimSpace(cfg["DEVICE_ID"])
	}
	if deviceID == "" {
		deviceID = strings.TrimSpace(st.DeviceID)
	}
	if deviceID == "" {
		deviceID = randomHex(16)
	}
	if len(deviceID) > 128 {
		deviceID = deviceID[:128]
	}
	st.DeviceID = deviceID
	if st.Generation < ^uint64(0) {
		st.Generation++
	}
	if st.Generation == 0 {
		st.Generation = 1
	}
	return deviceID, st.Generation, randomHex(16)
}

func persistedDeviceSource(cfg map[string]string, deviceID string) string {
	if strings.TrimSpace(cfg["SETTING_deviceId"]) == deviceID {
		return "setting"
	}
	if strings.TrimSpace(cfg["DEVICE_ID"]) == deviceID {
		return "antinet"
	}
	return "saved"
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func normalizeHashMode(raw string) string {
	return vk.NormalizeHashMode(raw)
}

// normalizeVkAuthMode — как CsqttConstants.VkAuth в родном клиенте (+ qWDTT aliases).
func normalizeVkAuthMode(raw string) string {
	return vk.NormalizeAuthMode(raw)
}

// normalizeVkModes — связка «режим хешей» ↔ «режим кредов» (CSQTT VkModePolicy via internal/vk).
func normalizeVkModes(hashRaw, authRaw string) (hashMode, authMode string) {
	m := vk.NormalizeModes(hashRaw, authRaw)
	return m.Hash, m.Auth
}

func needsVkOAuth(hashMode, authMode string) bool {
	return vk.NeedsOAuth(vk.Mode{Hash: hashMode, Auth: authMode})
}

func authModeLabel(mode string) string {
	switch mode {
	case "legacy":
		return "Капча (legacy)"
	case "auto_js":
		return "Авто ВК (аккаунт)"
	default:
		return "Авто (vkcalls)"
	}
}

func ensureVkToken(stateBlob, profileDir string, s csqttStrings, resolver *protectedResolver) (string, error) {
	if tok := strings.TrimSpace(persisted.VKToken); tok != "" {
		return tok, nil
	}
	if tok := restoredVkToken(stateBlob); tok != "" {
		persisted.VKToken = tok
		return tok, nil
	}
	emitProgress("%s", s.vkLoginProgress)
	logVkDNSHint(resolver)
	tok, err := requestVkAccessToken(profileDir)
	if err != nil {
		return "", err
	}
	saveVkToken(tok)
	return tok, nil
}

func saveVkToken(token string) {
	persisted.VKToken = strings.TrimSpace(token)
	persistState()
}

func requestVkAccessToken(profileDir string) (string, error) {
	if profileDir == "" {
		return "", fmt.Errorf("profileDir not set")
	}
	// Апстрим (`VkAuthWebViewManager`): фаза LOGIN на vk.ru/ → remixsid/лента → фаза TOKEN
	// (authorize → blank.html#access_token). Один ACTION_REQUIRED: стартуем с VK_LOGIN_URL,
	// injectJs после входа сам уводит на authorize; хост ловит blank.html (§2.7 navigation).
	//
	// Стартовать сразу с authorize нельзя: без сессии пользователь логинится в id.vk.ru, окно
	// часто не доходит до blank.html (Back → CANCELLED), а повторный коннект уже с cookie
	// «магически» срабатывает — именно это видно в логе 1.2.43.
	id := fmt.Sprintf("vk-oauth-%d", time.Now().UnixNano())
	res, cancelled := runAction(profileDir, id, map[string]any{
		"type":          "webview",
		"mode":          "navigation",
		"url":           vkLoginURL,
		"urlPattern":    vkOAuthRedirectMark,
		"param":         "access_token",
		"urlTimeoutSec": int(vkOAuthURLHop / time.Second),
		"injectJs":      vkOAuthLoginThenTokenJS(vkOAuthAuthURL),
	})
	if cancelled {
		return "", fmt.Errorf("VK login cancelled (закройте окно только после входа и редиректа)")
	}
	if strings.TrimSpace(res) == "" {
		return "", fmt.Errorf("VK login empty (AntiNet не передал токен — обновите модуль ≥1.2.16)")
	}
	tok, err := parseVkAccessToken(res)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// vkOAuthLoginThenTokenJS — монитор как у апстрима: remixsid / /feed / «Лента» → authorize.
// Пока пользователь на id.vk.ru без cookie сессии — не трогаем (иначе сорвём SMS/2FA).
func vkOAuthLoginThenTokenJS(authURL string) string {
	authJSON, _ := json.Marshal(authURL)
	return `(function(){
if(window.__csqttVkOAuth)return;
window.__csqttVkOAuth=1;
var AUTH=` + string(authJSON) + `;
var switched=false;
function cookie(){try{return document.cookie||""}catch(e){return""}}
function remix(){var c=cookie();return c.indexOf("remixsid")>=0||c.indexOf("remixnsid")>=0}
function pathFeed(){var p=(location.pathname||"");return p.indexOf("/feed")===0}
function feedUI(){try{var t=(document.body&&document.body.innerText)||"";return t.indexOf("Лента")>=0||t.indexOf("Мессенджер")>=0||t.indexOf("News feed")>=0}catch(e){return false}}
function loggedIn(){return remix()||pathFeed()||feedUI()}
function onBlank(){return (location.href||"").indexOf("blank.html")>=0}
function onOAuth(){var h=(location.hostname||"");return h.indexOf("oauth.vk.")===0}
function goAuth(){
  if(switched||onBlank()||onOAuth())return;
  switched=true;
  try{location.replace(AUTH)}catch(e){location.href=AUTH}
}
function tick(){
  if(onBlank())return;
  if(onOAuth())return;
  if(loggedIn())goAuth();
}
setInterval(tick,500);
setTimeout(tick,200);
})();`
}

func parseVkAccessToken(res string) (string, error) {
	res = strings.TrimSpace(res)
	if res == "" || strings.EqualFold(res, "CANCELLED") {
		return "", fmt.Errorf("VK login cancelled")
	}
	// Ответ действия приходит КОНВЕРТОМ (`{"type":"webview","value":…}`) — разворачиваем ПЕРВЫМ
	// шагом, чтобы дальше разбор шёл над голым значением и был одинаков для обеих форм ответа.
	// Без этого токен доезжал и молча выбрасывался: подстроки `access_token=` в конверте нет,
	// ключа `access_token` тоже, а `looksLikeVkToken` отвергает JSON из-за кавычек — вход в VK
	// уходил на новый круг с «empty access_token» при полностью успешной авторизации.
	res = actionResultString(res, "value")
	if res == "" {
		return "", fmt.Errorf("empty access_token")
	}
	if strings.HasPrefix(strings.ToLower(res), "error:") {
		return "", fmt.Errorf("VK login failed: %s", res)
	}
	if tok := extractAccessToken(res); tok != "" {
		return tok, nil
	}
	var payload map[string]any
	if json.Unmarshal([]byte(res), &payload) == nil {
		if tok := extractAccessToken(fmt.Sprint(payload["access_token"])); tok != "" {
			return tok, nil
		}
		if t, ok := payload["access_token"].(string); ok {
			if tok := strings.TrimSpace(t); looksLikeVkToken(tok) {
				return tok, nil
			}
		}
	}
	if looksLikeVkToken(res) {
		return res, nil
	}
	if dec, err := base64.StdEncoding.DecodeString(res); err == nil {
		s := strings.TrimSpace(string(dec))
		if tok := extractAccessToken(s); tok != "" {
			return tok, nil
		}
		if looksLikeVkToken(s) {
			return s, nil
		}
	}
	return "", fmt.Errorf("empty access_token")
}

func extractAccessToken(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || s == "<nil>" {
		return ""
	}
	if i := strings.Index(s, "access_token="); i >= 0 {
		rest := s[i+len("access_token="):]
		if j := strings.IndexAny(rest, "&?#"); j >= 0 {
			rest = rest[:j]
		}
		if u, err := url.QueryUnescape(rest); err == nil && strings.TrimSpace(u) != "" {
			rest = u
		}
		rest = strings.TrimSpace(rest)
		if looksLikeVkToken(rest) {
			return rest
		}
	}
	return ""
}

func looksLikeVkToken(s string) bool {
	if len(s) < 20 || strings.ContainsAny(s, " \t\r\n<>\"'") {
		return false
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return false
	}
	return true
}

// prefetchSharedTurnSeeds fills rust turn_seed via qWDTT GetCreds (dual-shared VK TURN).
func prefetchSharedTurnSeeds(cfg map[string]string, protectPath string, hashes []string, authMode string, s csqttStrings) []map[string]any {
	_ = s
	mode := strings.ToLower(strings.TrimSpace(authMode))
	switch mode {
	case "auto_js", "legacy":
		var hits []map[string]any
		for _, h := range hashes {
			if seed, ok := vk.LookupTurn(h); ok {
				hits = append(hits, map[string]any{
					"hash": seed.Hash, "username": seed.Username, "password": seed.Password,
					"server_addrs": seed.ServerAddrs,
				})
			}
		}
		return hits
	}
	qwdtt.PrepareSharedAuth(
		protectPath,
		cfg["SETTING_dnsPreset"],
		cfg["SETTING_captchaMode"],
		authMode,
		cfg["SETTING_vkAnonPath"],
	)
	ctx, cancel := context.WithTimeout(context.Background(), qwdtt.PrefetchBudget)
	defer cancel()
	seeds := qwdtt.PrefetchTurnSeeds(ctx, hashes)
	if len(seeds) > 0 {
		emitLog("CSQTT: prefetched %d/%d TURN creds via shared GetCreds", len(seeds), len(hashes))
	}
	return seeds
}
