// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// wgconfig.go (AntiNet helper) — разбор WireGuard-конфига из GETCONF в аргументы netstack + UAPI.
import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
)

type wgParsed struct {
	addrs []netip.Addr // [Interface] Address (IP без /prefix) → CreateNetTUN
	dns   []netip.Addr // [Interface] DNS
	mtu   int          // ≥1280
	uapi  string       // для device.IpcSet
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	// Длина ключа — из апстрима (`go_client/socks_wg.go::b64KeyToHex`, 1.4.3). Curve25519-ключ WG
	// всегда ровно 32 байта, и без этой проверки усечённый ключ доезжает до `device.IpcSet` и
	// падает уже ТАМ — сообщением, из которого не видно, какой из трёх ключей плох. PSK хуже всех:
	// его ошибка по месту вызова игнорируется (`if h, err := b64ToHex(psk); err == nil`), так что
	// битый PSK просто молча не попадал в UAPI, и туннель не поднимался без единой жалобы.
	if len(b) != 32 {
		return "", fmt.Errorf("wireguard key must be 32 bytes, got %d", len(b))
	}
	return hex.EncodeToString(b), nil
}

// ensureTwoResolvers — antinet (task #12): в списке DNS туннеля обязаны быть ХОТЯ БЫ ДВА сервера.
// ЕДИНАЯ точка для обоих транспортных режимов — WG-конфиг (parseWGConfig ниже) и raw-конфиг от
// сервера (rawtun.go): список приходит из одного и того же места (сервер qWDTT), и вырожденность
// у него одна и та же, поэтому разводить две копии этой нормализации нельзя.
//
// Резолв домена целиком идёт ЧЕРЕЗ туннель: resolveHostCached зовёт tnet.LookupContextHost на ТОМ
// ЖЕ *netstack.Net, которым дозванивается tnet.DialContextTCPAddrPort (socks5.go) — netstack
// изолирован от реального сетевого стека устройства, источником пакета может быть ТОЛЬКО
// туннельный адрес, никакого прямого пути в обход туннеля структурно нет. Живой репро
// (helper.stdout.log): `cp.cloudflare.com` (tunnel-check checkURL) не резолвился НИ РАЗУ
// за dnsAttempts×dnsAttemptBudget=3.6с ("write udp 10.66.0.36:PORT: i/o timeout" на каждой
// попытке), хотя соседние домены через тот же relay в то же окно резолвились штатно — путь именно
// до ЕДИНСТВЕННОГО резолвера в списке (сервер прислал только `8.8.8.8`) был плох в этот момент.
// Вендоренный tryOneName (netstack/tun.go) уже перебирает НЕСКОЛЬКО серверов из tnet.dnsServers —
// списку из одного элемента перебирать нечего, и resolveHostCached уходит прямо в SOCKS5 0x04
// (host unreachable), не успев накопить serve-stale кэш для редко проверяемого домена. Резолв
// целиком в туннеле — РФ-блокировка публичных резолверов на пути юзера НЕ применяется, запрос
// уходит с IP ЗАРУБЕЖНОГО VPS. Yandex DNS здесь НЕ подходит (не как «запрещённый», а как
// ненадёжный): это резолвер, топологически заточенный под клиентов ИЗ России — с адреса
// иностранного VPS, резолвящего ГЛОБАЛЬНЫЕ домены (cp.cloudflare.com/www.gstatic.com, не
// Яндекс/VK), нет причин ждать от него ту же надёжность/anycast-близость, что у 1.1.1.1/8.8.8.8
// (для сравнения — control-plane Yandex-дефолт в creds.go/run.go резолвит ИМЕННО
// VK/Яндекс-домены, топикально иной случай). Оба значения — уже принятые в этом дереве, не новый
// хардкод: 1.1.1.1 — byte-в-byte апстримный дефолт пустого списка (`socks_wg.go:143-144`);
// 8.8.8.8 — второй globally-anycast резолвер, уже бывший выбором апстрима для control-plane
// (`goDNSServersForPreset("google")`, creds.go:785) — здесь он для ДРУГОЙ цели, но значение то же.
func ensureTwoResolvers(dns []netip.Addr) []netip.Addr {
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	if len(dns) < 2 {
		fallback := netip.MustParseAddr("1.1.1.1")
		if dns[0] == fallback {
			fallback = netip.MustParseAddr("8.8.8.8")
		}
		dns = append(dns, fallback)
	}
	return dns
}

// parseWGConfig: WG-INI → netstack-аргументы + UAPI. forceEndpoint перекрывает [Peer] Endpoint
// (= 127.0.0.1:localPort, где слушает qWDTT-транспорт). AllowedIPs форсятся 0.0.0.0/0 + ::/0 (как
// WireGuardHelper.kt оригинала). Ключи base64 → hex для UAPI.
func parseWGConfig(conf, forceEndpoint string) (*wgParsed, error) {
	iface := map[string]string{}
	peer := map[string]string{}
	cur := ""
	for _, ln := range strings.Split(conf, "\n") {
		ln = strings.TrimSpace(ln)
		// `;` — вторая форма комментария в INI, принята апстримом (`socks_wg.go::parseWgQuick`).
		// У нас такая строка не отбрасывалась, а шла в strings.Cut: `; DNS = 1.1.1.1` оседал ключом
		// `; dns` — безвредно ровно до тех пор, пока закомментированный ключ не совпадёт с живым.
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		switch strings.ToLower(ln) {
		case "[interface]":
			cur = "i"
			continue
		case "[peer]":
			cur = "p"
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if cur == "i" {
			iface[k] = v
		} else if cur == "p" {
			peer[k] = v
		}
	}

	out := &wgParsed{mtu: 1280}
	for _, a := range strings.Split(iface["address"], ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if i := strings.IndexByte(a, '/'); i >= 0 {
			a = a[:i]
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			out.addrs = append(out.addrs, addr)
		}
	}
	if len(out.addrs) == 0 {
		return nil, fmt.Errorf("WG config: empty [Interface] Address")
	}
	for _, d := range strings.Split(iface["dns"], ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if addr, err := netip.ParseAddr(d); err == nil {
			out.dns = append(out.dns, addr)
		}
	}
	out.dns = ensureTwoResolvers(out.dns)
	// MTU: нижняя граница ≥576, как у апстрима (socks_wg.go::parseWgQuick) — было `m > 1280`, из-за
	// чего конфиг с MTU МЕНЬШЕ 1280 молча игнорировался и мы поднимали туннель с 1280. Если сервер
	// просит меньший MTU, значит путь не тянет больший: игнорируя это, мы шлём заведомо крупные
	// пакеты во фрагментацию/дроп. Больший MTU по-прежнему принимаем как есть.
	if m, err := strconv.Atoi(iface["mtu"]); err == nil && m >= 576 {
		out.mtu = m
	}

	priv, err := b64ToHex(iface["privatekey"])
	if err != nil {
		return nil, fmt.Errorf("WG PrivateKey: %w", err)
	}
	pub, err := b64ToHex(peer["publickey"])
	if err != nil {
		return nil, fmt.Errorf("WG PublicKey: %w", err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", priv)
	fmt.Fprintf(&sb, "public_key=%s\n", pub)
	if psk := peer["presharedkey"]; psk != "" {
		if h, err := b64ToHex(psk); err == nil {
			fmt.Fprintf(&sb, "preshared_key=%s\n", h)
		}
	}
	ep := forceEndpoint
	if ep == "" {
		ep = peer["endpoint"]
	}
	fmt.Fprintf(&sb, "endpoint=%s\n", ep)
	// PersistentKeepalive: дефолт 25, как у апстрима (socks_wg.go::parseWgQuick — `keepalive: 25` и
	// безусловный вывод в ipcRequest). У нас поле выводилось ТОЛЬКО если сервер прислал его явно —
	// иначе keepalive не включался вовсе. Для этого транспорта это принципиально: WG живёт поверх
	// DTLS→TURN-релея, и без периодических keepalive'ов простой съедает NAT/relay-мэппинг, а первый
	// пакет после простоя теряется (ровно наблюдавшийся профиль: дозвон после паузы — медленный,
	// сразу следующий — быстрый). Явное значение из конфига по-прежнему главнее дефолта.
	ka := 25
	if v, err := strconv.Atoi(peer["persistentkeepalive"]); err == nil && v > 0 {
		ka = v
	}
	fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", ka)
	sb.WriteString("allowed_ip=0.0.0.0/0\n")
	sb.WriteString("allowed_ip=::/0\n")
	out.uapi = sb.String()
	// Диагностика эффективных параметров туннеля — постоянная (одна строка на запуск сессии, mirror
	// PERFSPLIT-дисциплины): именно молчаливое расхождение этих двух значений с апстримом стоило
	// расследования потерь пакетов, и проверять их надо фактом из лога, а не чтением кода.
	log.Printf("[SETTINGS] WG effective params: mtu=%d keepalive=%ds dns=%v addrs=%v",
		out.mtu, ka, out.dns, out.addrs)
	return out, nil
}
