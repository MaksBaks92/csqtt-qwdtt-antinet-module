// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// rawtun.go (AntiNet) — режим `rawtun` из бампа 1.4.3: сырые IP-пакеты поверх TURN, БЕЗ слоя
// WireGuard. Сервер (`-listen-raw`, handleConnRaw) сам назначает клиенту адрес/DNS/MTU и гоняет
// голый IP; obfs-AEAD остаётся, DTLS снимается (см. TurnParams.RawMode → NoDTLS в run.go).
//
// ─── Чем наша форма режима отличается от авторской и почему ────────────────────────────────────
//
// У автора go_client — ОТДЕЛЬНЫЙ ОС-процесс, поэтому его rawtun получает настоящий kernel-TUN,
// созданный Android'ом через VpnService.Builder().establish(), и дескриптор приезжает по unix-
// сокету через SCM_RIGHTS (`-tun-fd-sock`, его `tun_fd.go::recvTunFD`, парная Kotlin-сторона
// TunFdBridge.kt). Диспетчер там читает и пишет прямо в этот *os.File.
//
// У нас так не бывает и не может: модуль — это .so, загруженный в слот-процесс `:modN`, а TUN
// в AntiNet принадлежит sing-box'у, не модулю. Контракт модуля с хостом — SOCKS5-порт
// (MODULE_API §2.6), и он один и тот же во ВСЕХ режимах. Поэтому у нас пакеты, приходящие с
// провода, попадают не в kernel-TUN, а в пользовательский netstack, поверх которого работает
// тот же самый серверный SOCKS5 (socks5.go), что и в режиме `vpn`. Различие между режимами
// сжимается ровно до одного: КТО наполняет netstack пакетами — WireGuard (vpn) или диспетчер
// напрямую (rawtun). Всё, что после netstack, у обоих режимов общее — см.
// startSocksOverNetstack.
//
// Файлы автора `tun_fd.go` и `socks_wg.go` в порт при бампе НЕ взяты: первый — механизм передачи
// дескриптора между процессами, которого у нас нет по построению (и он linux-only без build-тега,
// то есть сломал бы сборку Desktop/Windows); второй — вторая реализация разбора wg-quick и
// подъёма netstack, дублирующая wgconfig.go+socks5.go (улучшения автора оттуда забраны внутрь
// наших: проверка длины ключа и `;`-комментарии в wgconfig.go). Подробности — в README §2-bis.

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netstackTunIO — адаптер между батчевым tun.Device (интерфейс wireguard-go) и обычным
// io.ReadWriter, которого ждёт Dispatcher.tunIO.
//
// Почему адаптер, а не «дать диспетчеру tun.Device»: у диспетчера УЖЕ есть источник-io
// (авторский *os.File), и второй тип источника означал бы второй набор веток в readLoop/writeLoop.
// Один io.ReadWriter оставляет пути обработки едиными, а различие изолирует здесь.
//
// netstack-устройство (`netstack.CreateNetTUN`) объявляет BatchSize()==1 и обрабатывает ровно
// один пакет за вызов (`tun/netstack/tun.go`: Read берёт одну view из incomingPacket, Write
// инжектит по пакету), поэтому слайсы держим длиной 1 — это не упрощение, а точное соответствие
// контракту устройства.
//
// ⚠ Буферы РАЗДЕЛЬНЫЕ на направление и переиспользуемые: Read зовёт ТОЛЬКО readLoop диспетчера,
// Write — ТОЛЬКО writeLoop, каждый в одной горутине. Общий буфер на оба направления был бы
// гонкой; аллокация на пакет — мусором в самом горячем месте туннеля.
type netstackTunIO struct {
	dev    tun.Device
	rbufs  [][]byte
	rsizes []int
	wbufs  [][]byte
}

func newNetstackTunIO(dev tun.Device, mtu int) *netstackTunIO {
	return &netstackTunIO{
		dev:    dev,
		rbufs:  [][]byte{make([]byte, mtu)},
		rsizes: make([]int, 1),
		wbufs:  make([][]byte, 1),
	}
}

func (t *netstackTunIO) Read(p []byte) (int, error) {
	// offset=0: смещение нужно драйверам с заголовком перед пакетом (virtio и т.п.); у
	// netstack-устройства его нет, оно пишет с начала буфера.
	if len(p) > len(t.rbufs[0]) {
		t.rbufs[0] = make([]byte, len(p))
	}
	n, err := t.dev.Read(t.rbufs[:1], t.rsizes[:1], 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	size := t.rsizes[0]
	if size > len(p) {
		// Пакет длиннее, чем готов принять вызывающий. Молча обрезать нельзя — получатель
		// собрал бы битый IP-пакет; отдаём ошибку, диспетчер её залогирует первым же
		// firstReadErr'ом.
		return 0, fmt.Errorf("rawtun: packet %d bytes exceeds read buffer %d", size, len(p))
	}
	return copy(p[:size], t.rbufs[0][:size]), nil
}

func (t *netstackTunIO) Write(p []byte) (int, error) {
	t.wbufs[0] = p
	if _, err := t.dev.Write(t.wbufs[:1], 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *netstackTunIO) Close() error { return t.dev.Close() }

// createRawNetstack — netstack на параметрах, назначенных сервером. ЕДИНАЯ точка создания для
// ОБОИХ случаев (первый подъём и пере-назначение сервером на пере-спавне): диагностика
// эффективных параметров обязана печататься в обоих, а расходиться этим двум веткам незачем.
//
// Строка `[SETTINGS] RAW effective params` — зеркало такой же строки WG-режима
// (`[WG] effective params`): именно молчаливое расхождение этих значений с ожиданиями сервера
// стоило расследования потерь пакетов в WG-режиме.
func createRawNetstack(addrs, dns []netip.Addr, mtu int) (*netstackTunIO, *netstack.Net, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("rawtun netstack: %w", err)
	}
	log.Printf("[SETTINGS] RAW effective params: mtu=%d dns=%v addrs=%v", mtu, dns, addrs)
	return newNetstackTunIO(tunDev, mtu), tnet, nil
}

// bringUpRawTunnelAndSocks — ПЕРВЫЙ подъём режима `rawtun`: netstack на выданном сервером адресе +
// тот же SOCKS5, что и в режиме `vpn`. Возвращает io.ReadWriter, который вызывающий (runTransport)
// отдаёт диспетчеру через AttachTUN — с этого момента сырые IP-пакеты начинают ходить.
func bringUpRawTunnelAndSocks(
	addrs, dns []netip.Addr, mtu int, profileDir string, cfg helperConfig,
) (*netstackTunIO, error) {
	tio, tnet, err := createRawNetstack(addrs, dns, mtu)
	if err != nil {
		return nil, err
	}
	if err := startSocksOverNetstack(addrs, tnet, profileDir, cfg); err != nil {
		tio.Close()
		return nil, err
	}
	return tio, nil
}

// rawTunnel — процессный держатель поднятого raw-туннеля вместе с параметрами, на которых он
// поднят.
//
// Ровно тот же инвариант, что уже задокументирован у супервизора для режима vpn: «WG-device/
// dispatcher/SOCKS на 127.0.0.1 НЕ трогаются — переживают» пере-спавн транспорта (хендовер или
// естественная смерть всех воркеров). В rawtun роль WG-девайса играет netstack, и он обязан
// пережить пере-спавн ровно так же: слушающий SOCKS-сокет уже отдан хосту и опубликован в
// `socks.port`/`ready`, sing-box держит на нём соединения — пересоздавать его на каждом
// пере-спавне значит рвать их без всякой причины. Новым при пере-спавне становится ТОЛЬКО
// диспетчер, и он просто получает тот же самый источник через AttachTUN.
//
// ⚠ «Переживает» относится к СОКЕТУ и к СЛУЧАЮ, когда сервер назначил то же самое. Сами
// addrs/dns/mtu — не наши, их назначает сервер в каждом RAWCONF, и на пере-спавне (тем более
// после перезапуска сервера) он вправе назначить ДРУГИЕ. Поэтому они хранятся здесь: без них
// сравнивать новый ответ не с чем, а без сравнения реюз тихо превращается в «шлём с адреса,
// который сервер уже забыл» — снаружи это неотличимо от мёртвого релея (tx растёт, rx ноль).
var rawTunnel struct {
	mu    sync.Mutex
	io    *netstackTunIO
	addrs []netip.Addr
	dns   []netip.Addr
	mtu   int
}

// sameRawConf — тот же ли туннель назначил сервер. Сравнение ПОЛНОЕ (адреса, резолверы, MTU): у
// netstack все три задаются при создании и после него не меняются, поэтому расхождение в любом
// из них означает, что живой стек уже не тот, который описал сервер.
func sameRawConf(addrs, dns []netip.Addr, mtu int) bool {
	if mtu != rawTunnel.mtu || len(addrs) != len(rawTunnel.addrs) || len(dns) != len(rawTunnel.dns) {
		return false
	}
	for i := range addrs {
		if addrs[i] != rawTunnel.addrs[i] {
			return false
		}
	}
	for i := range dns {
		if dns[i] != rawTunnel.dns[i] {
			return false
		}
	}
	return true
}

// ensureRawTunnel — идемпотентный подъём raw-туннеля: первый вызов создаёт netstack и SOCKS,
// последующие (пере-спавн) отдают уже поднятый, ЕСЛИ сервер назначил те же параметры; иначе
// пересоздают netstack под тем же слушателем. Мьютекс, а не sync.Once, потому что провал
// подъёма обязан быть ПОВТОРЯЕМЫМ: Once запомнил бы неудачу навсегда, и следующий пере-спавн
// (ради которого супервизор и существует) уже ничего бы не починил.
func ensureRawTunnel(
	addrs, dns []netip.Addr, mtu int, profileDir string, cfg helperConfig,
) (*netstackTunIO, error) {
	rawTunnel.mu.Lock()
	defer rawTunnel.mu.Unlock()
	if rawTunnel.io != nil {
		if sameRawConf(addrs, dns, mtu) {
			log.Printf("[RAW] Reusing the raw tunnel brought up earlier (transport re-spawn)")
			return rawTunnel.io, nil
		}
		log.Printf("[RAW] Server reassigned the tunnel: addrs %v -> %v, dns %v -> %v, mtu %d -> %d - rebuilding netstack",
			rawTunnel.addrs, addrs, rawTunnel.dns, dns, rawTunnel.mtu, mtu)
		tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
		if err != nil {
			return nil, fmt.Errorf("rawtun netstack (reassigned): %w", err)
		}
		log.Printf("[SETTINGS] RAW effective params: mtu=%d dns=%v addrs=%v", mtu, dns, addrs)
		old := rawTunnel.io
		rawTunnel.io, rawTunnel.addrs, rawTunnel.dns, rawTunnel.mtu = newNetstackTunIO(tunDev, mtu), addrs, dns, mtu
		// Публикуем НОВЫЙ стек ДО закрытия старого: SOCKS-слушатель живёт всё это время, и окно,
		// в котором activeNet пуст, должно быть нулевым. Тот же вызов, которым стек публикуется
		// при первом подъёме (startSocksOverNetstack) — второго пути публикации нет.
		applyNetstack(addrs, tnet)
		// Старый стек закрываем ПОСЛЕ: диспетчер, который в него писал, уже остановлен
		// (`runTransport`'s `defer disp.Shutdown()` отработал до нашего вызова — супервизор
		// пере-спавнивает последовательно), а висящие на нём SOCKS-соединения относятся к адресу,
		// который сервер уже не обслуживает: оставить их значило бы держать заведомо мёртвые.
		_ = old.Close()
		return rawTunnel.io, nil
	}
	tio, err := bringUpRawTunnelAndSocks(addrs, dns, mtu, profileDir, cfg)
	if err != nil {
		return nil, err
	}
	rawTunnel.io, rawTunnel.addrs, rawTunnel.dns, rawTunnel.mtu = tio, addrs, dns, mtu
	return tio, nil
}

// formatRawConf/parseRawConfLine — сериализация RAWCONF между RunSession (где приходит ответ
// сервера) и runTransport (где поднимается туннель). Формат задан автором
// (`fmt.Sprintf("RAWCONF:%s|%s|%d", ...)` по месту в его session.go); у нас сборка и разбор
// стоят ЗДЕСЬ, парой: разделитель, префикс и порядок полей — одно знание, и разъехаться между
// producer'ом и consumer'ом оно не должно.
const rawConfPrefix = "RAWCONF:"

func formatRawConf(ip, dnsCSV string, mtu int) string {
	return fmt.Sprintf("%s%s|%s|%d", rawConfPrefix, ip, dnsCSV, mtu)
}

// parseRawConfLine — строка с провода СРАЗУ в аргументы netstack. Промежуточной тройки
// (ip, dnsCSV, mtu) намеренно нет: она была бы чистой перекладкой между двумя парсерами и
// тащилась бы через три сигнатуры (ensureRawTunnel → bringUpRawTunnelAndSocks → второй парсер),
// ничего по дороге не выражая.
func parseRawConfLine(line string) (addrs, dns []netip.Addr, mtu int, ok bool) {
	if !strings.HasPrefix(line, rawConfPrefix) {
		return nil, nil, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(line, rawConfPrefix), "|")
	if len(parts) != 3 {
		return nil, nil, 0, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, nil, 0, false
	}
	for _, d := range strings.Split(parts[1], ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if a, e := netip.ParseAddr(d); e == nil {
			dns = append(dns, a)
		}
	}
	// Та же нормализация, что и у WG-конфига: список приходит из одного места (сервер qWDTT) и
	// вырожден одинаково — см. ensureTwoResolvers в wgconfig.go.
	dns = ensureTwoResolvers(dns)
	// Нижняя граница 576 — та же и по той же причине, что у WG-конфига: меньший MTU от сервера
	// законен (путь не тянет больший), но значение ниже минимума IPv4-датаграммы — мусор.
	if mtu, err = strconv.Atoi(strings.TrimSpace(parts[2])); err != nil || mtu < 576 {
		mtu = 1280
	}
	return []netip.Addr{addr}, dns, mtu, true
}
