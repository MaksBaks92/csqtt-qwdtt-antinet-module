// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// socks5.go (AntiNet helper) — ТРАНСПОРТ под канон `shared/socks5`: дозвон CONNECT-цели и
// UDP-таргета ЧЕРЕЗ поднятый туннель (netstack WireGuard → qWDTT-транспорт → VPS). Сам протокол
// SOCKS5 (рукопожатие, user/pass RFC 1929, реле, UDP ASSOCIATE RFC 1928 §7) модулю не принадлежит —
// он канонный, один на все модули.
//
// UDP ASSOCIATE обязателен, чтобы UDP-каскады (hysteria2/tuic/wireguard — QUIC/UDP) работали, когда
// qWDTT — PRIMARY каскада: sing-box на UDP-дозвоне через socks шлёт CMD=0x03, и ответ 0x07 (command
// not supported) даёт `socks5: request rejected, code=7` — каскад не поднимается.
import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ── antinet: in-tunnel DNS — кэш + single-flight + ограниченные попытки + serve-stale ──────────
//
// ЗАЧЕМ (живой замер на телефоне, 20 минут одной сессии): 56 резолвов, из них 12 стоили
// 5.1-5.4с и 2 провалились на 10.0с — юзер видит это как скачки «отклика» 250мс ↔ 5600мс. Разбивка
// PERFSPLIT показала однозначно: tcpDial через ТОТ ЖЕ туннель стабилен (86-200мс, 5 медленных из
// 127), проблема РОВНО в резолве.
//
// Корень — НАШ порт, не апстрим и не релей. У апстримного клиента (`/tmp/qwdtt-upstream/go_client`)
// SOCKS-прокси нет вообще: TUN там владеет сам Android, имена резолвит ОС со своим кэшем. SOCKS5
// поверх netstack — целиком наша надстройка, и она звала `tnet.LookupHost` на КАЖДОЕ соединение,
// без кэша. А вендоренный netstack-резолвер (`wireguard/tun/netstack/tun.go::tryOneName`) зашит
// намертво: `exchange(ctx, server, q, time.Second*5)` в цикле `for i := 0; i < 2; i++` — один
// потерянный UDP-пакет к DNS = ровно +5с, два = 10с и отказ. Своего таймаута он не принимает, но
// `exchange` строит дедлайн через `context.WithDeadline(ctx, ...)`, а тот берёт БОЛЕЕ РАННИЙ из
// двух — значит наш короткий ctx корректно перебивает зашитые 5с, без форка вендора.
//
// Три слоя, каждый бьёт свою часть наблюдаемого:
//  1. кэш (dnsFreshTTL) — 45 из 56 резолвов сессии были ОДНИМ И ТЕМ ЖЕ `www.gstatic.com` (проба
//     живости AntiNet раз в несколько секунд); повторный резолв не нужен вовсе;
//  2. single-flight — параллельные соединения к одному хосту (в логе видно по два одновременных
//     резолва gstatic) платили 5с КАЖДОЕ; теперь платит один, остальные ждут его результат;
//  3. ограниченные попытки + serve-stale (RFC 8767) — вместо 5с/10с получаем dnsAttemptBudget на
//     попытку, а на полном провале отдаём последний хороший ответ в пределах dnsStaleWindow.
//     Serve-stale — тот же приём и то же 30-минутное окно, что уже принято в AntiNet для
//     `LocalResolver` (root CLAUDE.md § DNS-death #2), не новая политика.
//  4. stale-while-revalidate — просроченный по dnsFreshTTL ответ отдаётся МГНОВЕННО, а обновление
//     уходит в фон. Без этого раз в минуту (ровно dnsFreshTTL) ПЕРВОЕ же соединение платило полный
//     in-tunnel резолв: живой замер на телефоне (helper.stdout.log)
//     дал по такому «просроченному» резолву 94мс / 123мс / 261мс / 2.5с, а с провалом и serve-stale —
//     3.6с. Это и есть наблюдавшиеся юзером ЕЖЕМИНУТНЫЕ провалы отклика: одно медленное измерение,
//     потом снова быстрые. Асинхронное обновление убирает синхронную цену целиком — платит только
//     САМЫЙ первый резолв хоста за сессию (записи нет вовсе).
const (
	dnsFreshTTL      = 60 * time.Second        // сколько ответ считается свежим
	dnsStaleWindow   = 30 * time.Minute        // сколько его ещё можно отдать как stale
	dnsAttemptBudget = 1200 * time.Millisecond // потолок ОДНОЙ попытки (перебивает зашитые 5с)
	dnsAttempts      = 3                       // столько попыток подряд, каждая со своим бюджетом
	// Минимум между фоновыми обновлениями одной записи. Без него на сломанном резолвере каждый
	// запрос кикал бы новое фоновое обновление (флаг refreshing защищает только от параллельных,
	// не от частых последовательных) — получился бы шторм в темпе трафика.
	dnsRefreshMinInterval = 15 * time.Second
)

type dnsCacheEntry struct {
	mu       sync.Mutex // защищает поля ниже; держится КОРОТКО, никогда на время резолва
	ips      []string
	gotAt    time.Time
	hasValue bool
	// single-flight: ровно один реальный резолв этого хоста одновременно. Отдельный от mu —
	// именно поэтому быстрый путь не блокируется на время чужого резолва (в этом и суть п.4).
	flight     sync.Mutex
	refreshing bool      // под mu: фоновое обновление уже в полёте
	lastTry    time.Time // под mu: когда в последний раз запускали фоновое обновление
}

var (
	dnsCacheMu sync.Mutex
	dnsCache   = map[string]*dnsCacheEntry{}
)

func dnsEntryFor(host string) *dnsCacheEntry {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	e := dnsCache[host]
	if e == nil {
		e = &dnsCacheEntry{}
		dnsCache[host] = e
	}
	return e
}

// resolveAndStore — реальный резолв с ограниченными попытками; на успехе обновляет запись.
// ВЫЗЫВАТЬ, УДЕРЖИВАЯ e.flight И НЕ УДЕРЖИВАЯ e.mu (mu берётся здесь коротко, только на запись).
func resolveAndStore(tnet *netstack.Net, host string, e *dnsCacheEntry) ([]string, error) {
	var lastErr error
	for i := 0; i < dnsAttempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), dnsAttemptBudget)
		ips, err := tnet.LookupContextHost(ctx, host)
		cancel()
		if err == nil && len(ips) > 0 {
			e.mu.Lock()
			e.ips = ips
			e.gotAt = time.Now()
			e.hasValue = true
			e.mu.Unlock()
			return ips, nil
		}
		if err == nil {
			err = fmt.Errorf("empty DNS response")
		}
		lastErr = err
	}
	return nil, lastErr
}

// kickDnsRefresh — фоновое обновление просроченной записи (stale-while-revalidate). Вызывающий уже
// получил ответ и НЕ ждёт эту горутину. Гейтов два: refreshing (нет параллельных) и lastTry
// (нет шторма последовательных на сломанном резолвере).
func kickDnsRefresh(tnet *netstack.Net, host string, e *dnsCacheEntry) {
	e.mu.Lock()
	if e.refreshing || (!e.lastTry.IsZero() && time.Since(e.lastTry) < dnsRefreshMinInterval) {
		e.mu.Unlock()
		return
	}
	e.refreshing = true
	e.lastTry = time.Now()
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			e.refreshing = false
			e.mu.Unlock()
		}()
		// Синхронный (холодный) резолв того же хоста уже идёт — обновлять нечего, он сам положит
		// свежее значение. TryLock, а не Lock: фоновой горутине незачем стоять в очереди.
		if !e.flight.TryLock() {
			return
		}
		defer e.flight.Unlock()
		if _, err := resolveAndStore(tnet, host, e); err != nil {
			log.Printf("PERFSPLIT lookup BG-REFRESH FAILED host=%s err=%v (continuing to serve stale)", host, err)
		}
	}()
}

// resolveHostCached — единственная точка резолва имени для SOCKS-CONNECT.
// Возвращает (ips, fromCache, err).
func resolveHostCached(tnet *netstack.Net, host string) ([]string, bool, error) {
	e := dnsEntryFor(host)

	// Быстрый путь: есть ЛЮБОЙ ответ в пределах stale-окна — отдаём МГНОВЕННО, не платя резолв.
	// Просроченный по dnsFreshTTL дополнительно кикает обновление В ФОН (stale-while-revalidate).
	e.mu.Lock()
	if e.hasValue && time.Since(e.gotAt) < dnsStaleWindow {
		ips := e.ips
		stale := time.Since(e.gotAt) >= dnsFreshTTL
		e.mu.Unlock()
		if stale {
			kickDnsRefresh(tnet, host, e)
		}
		return ips, true, nil
	}
	e.mu.Unlock()

	// Записи нет вовсе (или она старше stale-окна) — только здесь платим синхронно.
	// e.flight (а не e.mu) — single-flight, не блокирующий читателей быстрого пути.
	e.flight.Lock()
	defer e.flight.Unlock()
	// Пока ждали своей очереди, кто-то мог уже положить значение.
	e.mu.Lock()
	if e.hasValue && time.Since(e.gotAt) < dnsStaleWindow {
		ips := e.ips
		e.mu.Unlock()
		return ips, true, nil
	}
	e.mu.Unlock()

	ips, err := resolveAndStore(tnet, host, e)
	if err == nil {
		return ips, false, nil
	}

	// Все попытки провалились — отдаём последний хороший ответ, если он ещё в окне (RFC 8767).
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hasValue && time.Since(e.gotAt) < dnsStaleWindow {
		log.Printf("PERFSPLIT lookup SERVED-STALE host=%s ip=%s age=%v err=%v",
			host, e.ips[0], time.Since(e.gotAt).Truncate(time.Second), err)
		return e.ips, true, nil
	}
	return nil, false, err
}

// cachedResolver — адаптер под интерфейс `socksResolver` канона shared/socks5 (`LookupHost(string)`),
// чтобы UDP ASSOCIATE резолвил через ТОТ ЖЕ кэш, что и TCP CONNECT. Без него UDP-путь (второй и
// последний резолв-callsite модуля) продолжал бы ходить голым tnet.LookupHost — то есть платить
// зашитые в вендоренный netstack 5с×2 на каждую датаграмму с доменным адресатом. Сам канон при этом
// остаётся чистым wire-format'ом без знания о кэше.
type cachedResolver struct{ tnet *netstack.Net }

func (r cachedResolver) LookupHost(host string) ([]string, error) {
	ips, _, err := resolveHostCached(r.tnet, host)
	if err != nil {
		return nil, err
	}
	// Тот же выбор семьи, что и на TCP-пути. Без него parseSocksUDP берёт `ips[0]` вслепую
	// (shared/socks5udp/socks5udp.go:55), а netstack складывает ответы A и AAAA в порядке ПРИХОДА
	// (`tun.go::LookupContextHost`) — на dual-stack домене первым легко оказывается IPv6, которого
	// у WG-конфига qWDTT обычно нет вовсе (`Address = 10.66.x.x/32`). Общий socks5udp.go при этом
	// остаётся module-agnostic: что значит «резолв», задаёт переданный резолвер — у нашего это
	// «резолв + адрес, до которого отсюда реально есть путь».
	chosen, perr := pickDialableIP(ips)
	if perr != nil {
		return nil, perr
	}
	return []string{chosen.String()}, nil
}

// DialUDPTarget — вторая половина контракта [socksUDPTransport]: дозвон до цели UDP-датаграммы
// ЧЕРЕЗ туннель. Гейт по семье стоит ЗДЕСЬ, перед `tnet.Dial`, а не в каноне: канон не знает и не
// должен знать, какие семьи несёт транспорт конкретного модуля — он лишь различает наш отказ по
// `errSocksTargetUnreachable` и ведёт для него отдельный счётчик.
//
// Это ТРЕТЬЯ и последняя точка, где адресат становится известен (первые две — выбор среди ответов
// DNS в pickDialableIP и IP-литерал в SOCKS-CONNECT), и все три идут через один предикат
// tunnelSupportsAddr. Доменный адресат сюда приходит уже отфильтрованным — его отсеял LookupHost
// выше; здесь закрывается литерал (ATYP 0x01/0x04) прямо в датаграмме.
func (r cachedResolver) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	if !tunnelSupportsAddr(dst.Addr()) {
		return nil, fmt.Errorf("%w: dst=%v, tunnel has v4=%v v6=%v",
			errSocksTargetUnreachable, dst, tunHasV4, tunHasV6)
	}
	return r.tnet.Dial("udp", dst.String())
}

// ── Какие семьи адресов реально есть у туннеля ────────────────────────────────────────────────
// Ставится один раз в bringUpTunnelAndSocks из адресов WG-конфига. Нужно, чтобы не дозваниваться
// в семью, которой у нас нет: netstack примет такой dial и будет молча ждать до таймаута.
var (
	tunHasV4 bool
	tunHasV6 bool
)

func setTunnelAddressFamilies(addrs []netip.Addr) {
	for _, a := range addrs {
		if a.Is4() {
			tunHasV4 = true
		} else if a.Is6() {
			tunHasV6 = true
		}
	}
	// Оба флага пусты — конфиг без адресов (быть не должно): не сужаем, ведём себя как раньше.
	if !tunHasV4 && !tunHasV6 {
		tunHasV4, tunHasV6 = true, true
	}
	log.Printf("[TUN] tunnel address families: v4=%v v6=%v", tunHasV4, tunHasV6)
}

// tunnelSupportsAddr — несёт ли туннель семью этого адреса. ЕДИНСТВЕННЫЙ предикат «сюда можно
// дозваниваться»: через него идут ВСЕ три точки, где адресат становится известен — выбор среди
// ответов DNS (pickDialableIP), IP-литерал в SOCKS-CONNECT и таргет UDP-датаграммы. Семья решается
// в одном месте, а не в каждом из них по-своему.
func tunnelSupportsAddr(a netip.Addr) bool {
	if a.Is4() || a.Is4In6() {
		return tunHasV4
	}
	return tunHasV6
}

// pickDialableIP — первый адрес из ответа DNS, чью семью туннель реально несёт.
func pickDialableIP(ips []string) (netip.Addr, error) {
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if tunnelSupportsAddr(a) {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no address of a tunnel-supported family among %v", ips)
}

// ── Сколько соединений и дозвонов держим одновременно ─────────────────────────────────────────
// Диагностика постоянная: живой разбор показал окна, где дозвон через netstack вместо
// обычных 100-140мс занимал 3.1с / 7.1с и упирался в 10с-потолок, а в это же время падал и
// in-tunnel резолв (`write udp …: i/o timeout`). Без этих счётчиков нельзя отличить «встал релей»
// от «мы сами завалили трубу параллельными соединениями», а это принципиально разные причины.
var (
	activeConns int64
	activeDials int64
)

func serveSocks5(ln net.Listener, user, pass string) {
	serveSocksListener(ln, func(c net.Conn) { handleSocks(c, user, pass) })
}

// handleSocks — CONNECT-путь модуля. Протокол (приветствие, авторизация, разбор запроса, реле,
// UDP ASSOCIATE) целиком в каноне shared/socks5; здесь остаётся ровно то, что у qWDTT своё —
// резолв и дозвон ЧЕРЕЗ туннель (netstack) с их диагностикой.
//
// netstack берётся из [activeNet] НА КАЖДОЕ соединение, а не захватывается в замыкание при
// старте слушателя: в режиме `rawtun` сервер вправе переназначить адрес/DNS/MTU, и тогда
// netstack пересоздаётся под живым слушателем (ensureRawTunnel). Захваченный указатель означал
// бы, что новые соединения продолжают ходить через стек со СТАРЫМ адресом — то есть в никуда.
func handleSocks(c net.Conn, user, pass string) {
	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)
	defer c.Close()
	tnet := activeNet.Load()
	if tnet == nil {
		// Слушатель живёт дольше стека только в одном окне — между закрытием старого netstack и
		// публикацией нового. Соединение в этом окне честно отвергаем: молча закрыть значило бы
		// отдать sing-box'у обрыв без кода, который он прочитал бы как «сервер ответил и закончил».
		log.Printf("PERFSPLIT socks REJECTED (tunnel netstack is not published yet)")
		_, _ = c.Write(socksRep(0x01))
		return
	}
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// UDP-каскады (hysteria2/tuic/wireguard) — дозвон до цели идёт через туннель, см.
		// cachedResolver.DialUDPTarget.
		serveSocksUDPAssociate(c, br, cachedResolver{tnet})
		return
	}

	ipAddr, host, port := req.IP, req.Host, req.Port

	// CMD == CONNECT.
	// PERFSPLIT — миллисекундная разбивка дозвона в dev-лог. `dialStart` покрывает ВЕСЬ путь
	// «резолв + дозвон», а не только TCP-фазу: иначе строка лога называет одним словом два разных
	// отрезка времени, и сравнивать замеры между собой нельзя.
	dialStart := time.Now()
	if !req.IsIP() {
		// резолв домена ЧЕРЕЗ туннель (DNS из WG-конфига), но через кэш+single-flight+bounded
		// попытки — см. развёрнутое обоснование у resolveHostCached выше.
		lookupStart := time.Now()
		ips, fromCache, err := resolveHostCached(tnet, host)
		lookupElapsed := time.Since(lookupStart)
		if err != nil || len(ips) == 0 {
			log.Printf("PERFSPLIT lookup FAILED host=%s lookupElapsed=%v totalElapsed=%v err=%v", host, lookupElapsed, time.Since(dialStart), err)
			_, _ = c.Write(socksRep(0x04))
			return
		}
		// Берём первый адрес ТОЙ СЕМЬИ, которая реально есть у туннеля, а не просто ips[0].
		// `LookupHost` netstack'а спрашивает и A, и AAAA и складывает ответы в порядке их прихода
		// (`tun.go::LookupContextHost`) — то есть на dual-stack домене первым может оказаться IPv6,
		// а у WG-конфига qWDTT адрес обычно только IPv4 (`Address = 10.66.x.x/32`). Тогда дозвон
		// уходил в заведомо недоступную семью и гарантированно съедал весь socksDialTimeout, причём
		// НЕДЕТЕРМИНИРОВАННО — от того, какой ответ DNS вернулся первым. Это и есть класс «иногда
		// один и тот же хост открывается мгновенно, иногда висит».
		chosen, perr := pickDialableIP(ips)
		if perr != nil {
			log.Printf("PERFSPLIT lookup UNUSABLE host=%s ips=%v (no address of a tunnel-supported family)", host, ips)
			_, _ = c.Write(socksRep(0x04))
			return
		}
		log.Printf("PERFSPLIT lookup OK host=%s ip=%s lookupElapsed=%v cached=%v", host, chosen, lookupElapsed, fromCache)
		ipAddr = chosen
	} else {
		// IP-литерал от клиента: резолва нет, но проверка семьи ОБЯЗАТЕЛЬНА — ровно та же, что
		// применяется к ответу DNS в ветке выше. Без неё дозвон в семью, которой у туннеля нет,
		// уходил в netstack и стоил ВЕСЬ socksDialTimeout (10с) на КАЖДОЕ такое соединение: тот же
		// класс, что описан абзацем выше для dual-stack доменов, просто на этой ветке он не
		// закрывался ничем. Ветка боевая, а не теоретическая — sing-box со своим domain_resolver
		// присылает сюда именно литералы. Апстрим 1.4.3 закрывает это `ipv4OnlyRule`
		// (`go_client/socks5.go:38-49`) жёстким «только v4»; наш предикат знает РЕАЛЬНЫЕ семьи
		// туннеля, поэтому v6-туннель заодно не ломается.
		if !tunnelSupportsAddr(ipAddr) {
			log.Printf("PERFSPLIT literal UNREACHABLE ip=%s (tunnel has no address of this family, v4=%v v6=%v)", ipAddr, tunHasV4, tunHasV6)
			_, _ = c.Write(socksRep(0x03)) // network unreachable
			return
		}
		log.Printf("PERFSPLIT lookup SKIPPED ip=%s (already an IP literal)", ipAddr)
	}

	// ⏱ antinet: НЕ 15с хардкодом. Живой замер показывает цену такого потолка:
	// КАЖДЫЙ недостижимый адрес держит соединение все 15с, прежде чем модуль ответит отказом — на
	// заблокированном в РФ Telegram это десятки зависших соединений подряд, и приложение всё это
	// время ждёт. Сокращаем, но НЕ до echo'шных 5с: там прямой дозвон (успех 9-235мс), а здесь путь
	// идёт через WG-netstack поверх TURN/DTLS-релея с документированно высоким разбросом задержки —
	// слишком короткий потолок рубил бы живые, просто медленные соединения. 10с = вдвое дешевле
	// отказ при сохранённом запасе. Выносим в настройку (карточка «Модули»), а не зашиваем.
	ctx, cancel := context.WithTimeout(context.Background(), socksDialTimeout())
	defer cancel()
	tcpDialStart := time.Now()
	dialsNow := atomic.AddInt64(&activeDials, 1)
	up, err := tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ipAddr, port))
	atomic.AddInt64(&activeDials, -1)
	tcpDialElapsed := time.Since(tcpDialStart)
	// antinet: скользящее окно исходов — деградация транспорта видна одной строкой, см. workerhealth.go
	recordDialOutcome(float64(tcpDialElapsed.Microseconds())/1000.0, err != nil)
	if err != nil {
		log.Printf("PERFSPLIT tcpDial FAILED host=%s port=%d tcpDialElapsed=%v conns=%d dials=%d err=%v", host, port, tcpDialElapsed, atomic.LoadInt64(&activeConns), dialsNow, err)
		log.Printf("[PERF] connect FAILED host=%s port=%d dial=%v err=%v", host, port, time.Since(dialStart), err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	log.Printf("PERFSPLIT tcpDial OK host=%s port=%d tcpDialElapsed=%v totalElapsed=%v conns=%d dials=%d", host, port, tcpDialElapsed, time.Since(dialStart), atomic.LoadInt64(&activeConns), dialsNow)
	log.Printf("[PERF] connect OK host=%s port=%d dial=%v", host, port, time.Since(dialStart))
	defer up.Close()
	// TCP_NODELAY на SOCKS-клиентской стороне (sing-box → наш accept): Nagle копит мелкие
	// записи реле и режет upload. gonet.TCPConn SetNoDelay не экспортирует — только эта сторона.
	if nd, ok := c.(interface{ SetNoDelay(bool) error }); ok {
		_ = nd.SetNoDelay(true)
	}
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}

	// Реле и политика закрытия — канон shared/socks5 (`relayBidi`): обрыв туннеля обязан
	// выглядеть обрывом, а не «сервер ответил и закончил». Полное обоснование и цена прежнего
	// поведения (наша же проба отклика получала EOF и классифицировала обрыв как «виноват
	// адресат») — в доккомментарии самой функции.
	//
	// Почему бьёт именно каскад, а не основу: соединение до сервера каскада — это ещё одно
	// рукопожатие (vless/trojan/TLS) поверх нашего реле, несколько round-trip'ов и килобайты. Оно
	// на порядок дольше живёт «в полёте», чем одиночный HTTP-HEAD плеча основы, и потому в разы
	// чаще ловит момент обрыва СЕРЕДИНОЙ потока — там, где обрыв и превращался в фальшивый EOF.
	relayBidi(c, br, up, fmt.Sprintf("%s:%d", req.TargetLabel(), port), dialStart)
}

// relayCopy / relayTargetLabel — теперь канон shared/socks5 (`relayCopy`, `socksRequest.TargetLabel`).
// Обе жили здесь копиями, идентичными echo'шным: `relayCopy` — байт-в-байт.

// handleUDPAssociate / udpAssocSeq / parseSocksUDP / buildSocksUDPHeader / socksRep — теперь канон
// shared/socks5 (`serveSocksUDPAssociate` и соседи), инжектируемый build.py при `"socks5": true`.
// Реле-цикл был здесь копией echo'шного, отличаясь лишь тем, ЧЕМ дозваниваются до цели — а это
// ровно та граница, по которой канон и разрезан: он зовёт [socksUDPTransport], реализацию даёт
// модуль. Диагностика ассоциации (assocID, счётчики, `readyCh`, CLOSE-строка) жила только в этой
// копии и перенесена в канон целиком, а не отброшена.
//
// Гейт по семье адреса тоже уехал туда — но не как копия предиката, а как ошибка
// `errSocksTargetUnreachable` от [cachedResolver.DialUDPTarget]: канон различает «датаграмма
// битая» / «адресат вне достижимых семей» / «дозвон не удался» тремя счётчиками, как и было.

// activeNet — netstack, обслуживающий SOCKS ПРЯМО СЕЙЧАС. Отдельная ячейка, а не аргумент
// слушателя, ровно по одной причине: в режиме `rawtun` адрес/DNS/MTU назначает сервер, и он
// вправе назначить их заново на пере-спавне транспорта. Слушающий сокет при этом менять нельзя
// (он отдан хостом, порт опубликован в `socks.port`, sing-box держит на нём соединения), а стек
// под ним — нужно. Публикуется единственной точкой [applyNetstack].
var activeNet atomic.Pointer[netstack.Net]

// applyNetstack — ЕДИНАЯ точка «с этой секунды SOCKS ходит через ЭТОТ стек». Обе вещи здесь
// связаны и обязаны меняться вместе: семьи адресов (`tunHasV4/tunHasV6`, по ним фильтруется
// КАЖДЫЙ адресат) выводятся из адресов того же стека. Разнести их значило бы завести окно, в
// котором дозвоны фильтруются по семьям одного стека, а уходят в другой.
func applyNetstack(addrs []netip.Addr, tnet *netstack.Net) {
	setTunnelAddressFamilies(addrs)
	activeNet.Store(tnet)
}

// wgDevice — живое WG-устройство режима `vpn`. Держим указатель, а не счётчики: байты читаются
// штатным `IpcGet()` (публичный UAPI wireguard-go), то есть без единой правки ни в самом
// wireguard-go, ни в пристинном ядре автора.
//
// ⚠ Сигналом watchdog'а это БОЛЬШЕ НЕ является (2026-09-11). Второй сигнал relayWatchdog'а
// переехал на счётчики самого туннеля (`Stats.TotalBytesDown/Up`, dispatcher.go), потому что
// здешний источник существует только в режиме `vpn`: в `rawtun` WireGuard'а нет вовсе, `wgDevice`
// остаётся nil, и сигнал молчал по построению — модуль не мог заметить собственную смерть
// (живой инцидент 2026-09-11: `Σtx=3962 Σrx=190`, приём стоит час, ни одного срабатывания).
// Здесь остался WG-СРЕЗ для диагностической строки `[WRKDIAG]`: он показывает, сколько дошло до
// WG против того, сколько записали воркеры, — арифметика дропов диспетчера (см. workerhealth.go).
var wgDevice atomic.Pointer[device.Device]

// relayByteSnapshot — суммарные rx/tx WG-пиров прямо сейчас; `ok=false`, когда WG-устройства нет
// (режим `rawtun`) либо UAPI не ответил. Диагностика, не сигнал — см. доккоммент wgDevice.
func relayByteSnapshot() (rx, tx uint64, ok bool) {
	dev := wgDevice.Load()
	if dev == nil {
		return 0, 0, false
	}
	uapi, err := dev.IpcGet()
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(uapi, "\n") {
		v, parseErr := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "rx_bytes="), "tx_bytes=")), 10, 64)
		if parseErr != nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "rx_bytes="):
			rx += v
		case strings.HasPrefix(line, "tx_bytes="):
			tx += v
		}
	}
	return rx, tx, true
}

func bringUpTunnelAndSocks(wgConf, localPortStr, profileDir string, cfg helperConfig) error {
	wp, err := parseWGConfig(wgConf, "127.0.0.1:"+localPortStr)
	if err != nil {
		return err
	}
	tunDev, tnet, err := netstack.CreateNetTUN(wp.addrs, wp.dns, wp.mtu)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	// Кастомный логгер wireguard-go: хук Verbosef ловит «Handshake did not complete» (релей не
	// форвардит) / «Received handshake» (форвардит) → питает relayWatchdog (wgHandshakeFails). Это
	// WG-нативный сигнал живости релея; per-пакет wireguard-go даже на verbose НЕ логирует → объём низкий.
	wgLog := &device.Logger{
		Verbosef: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			switch {
			case strings.Contains(msg, "Handshake did not complete"):
				recordWgHandshakeFail()
			case strings.Contains(msg, "Received handshake"):
				recordWgHandshakeOK()
			}
		},
		Errorf: func(format string, args ...any) { log.Printf("qwdtt-wg ERR: "+format, args...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), wgLog)
	if err := dev.IpcSet(wp.uapi); err != nil {
		return fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("wg Up: %w", err)
	}
	wgDevice.Store(dev) // питает второй сигнал relayWatchdog (rx/tx), см. relayByteSnapshot

	return startSocksOverNetstack(wp.addrs, tnet, profileDir, cfg)
}

// startSocksOverNetstack — ЕДИНЫЙ хвост подъёма для ОБОИХ транспортных режимов: объявить семьи
// адресов туннеля, взять слушающий сокет у хоста, опубликовать маркер готовности и поднять SOCKS5
// поверх netstack. Что наполняет этот netstack пакетами — WireGuard (режим `vpn`, выше) или
// напрямую диспетчер (режим `rawtun`, rawtun.go) — здесь роли не играет.
//
// Вынесено ИМЕННО в общую функцию, а не скопировано в raw-ветку: любая правка этого хвоста (номер
// порта, содержимое маркера готовности, набор семей) обязана применяться к обоим режимам разом,
// иначе один из них тихо разойдётся с хостом — а внешне оба выглядят одинаково «модуль поднялся».
func startSocksOverNetstack(addrs []netip.Addr, tnet *netstack.Net, profileDir string, cfg helperConfig) error {
	applyNetstack(addrs, tnet)
	// Слушающий сокет отдаёт ХОСТ (§2.6 контракта, MODULE_API.md) — усыновляет его канон
	// `shared/hostproto::openListener`.
	ln, err := openListener(cfg.SocksPort, hostListenFd)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	actual := ln.Addr().(*net.TCPAddr).Port
	// Маркер готовности — канон shared/lifecycle (`writeReady`). Здесь он назывался
	// `writeSocksPort`, у echo — `writeReady`, тела были байт-в-байт равны; у masterdns тот же
	// маркер писался инлайном и уже разошёлся (без MkdirAll, права 0644, ошибки проглочены).
	if err := writeReady(profileDir, actual); err != nil {
		return err
	}
	go serveSocks5(ln, cfg.SocksUser, cfg.SocksPass)
	return nil
}

