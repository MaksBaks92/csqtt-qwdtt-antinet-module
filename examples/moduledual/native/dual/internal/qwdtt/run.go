// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// run.go — ТЕЛО модуля. Точки входа (C-ABI-экспорты на Android, argv-разбор на десктопе) и весь
// протокол разговора с хостом — каноны `shared/entry` и `shared/hostproto`: они зовут `realMain` и
// `moduleCall` ниже, больше от модуля ничего не требуется.
import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// Call — parse-only сабкоманды контракта (MODULE_API §2.2). ОДНА реализация на обе формы
// доставки: канон `shared/entry` зовёт её из argv на десктопе и из `antinet_module_call` в
// Android-слоте. dual module.json объявляет pingNeedsConsent → canping обязателен.
func Call(verb, arg string) string {
	switch verb {
	case "summarize":
		name, server := summarizeQwdtt(arg)
		return name + "\n" + server
	case "normalize":
		return normalizeQwdtt(arg)
	case "canping":
		return canPingQwdtt(arg)
	}
	return ""
}

// canPingQwdtt — «можно ли пинговать без UI?» (MODULE_API §2.2). ok, если в ссылке уже есть
// VK-хеши (или восстановленный MODULE_STATE намекает на сохранённые креды).
func canPingQwdtt(arg string) string {
	lines := strings.SplitN(arg, "\n", 3)
	link := ""
	if len(lines) > 0 {
		link = strings.TrimSpace(lines[0])
	}
	if link == "" {
		return "no"
	}
	low := strings.ToLower(link)
	if !strings.HasPrefix(low, "qwdtt://") && !strings.HasPrefix(low, "wdtt://") {
		return "no"
	}
	if i := strings.Index(link, "?"); i >= 0 {
		q := link[i+1:]
		for _, part := range strings.Split(q, "&") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			v := strings.TrimSpace(kv[1])
			if v == "" {
				continue
			}
			if k == "hashes" || k == "vkhashes" {
				return "ok"
			}
		}
	}
	if strings.HasPrefix(low, "wdtt://") {
		// legacy wdtt://ip:dtls:wg:local:pass:hash — hash is required field
		parts := strings.Split(link[len("wdtt://"):], ":")
		if len(parts) >= 6 && strings.TrimSpace(strings.Join(parts[5:], ":")) != "" {
			return "ok"
		}
	}
	if len(lines) > 2 && strings.TrimSpace(lines[2]) != "" {
		// Non-empty MODULE_STATE: may hold restored TURN creds (credstate).
		return "ok"
	}
	return "no"
}

// hostListenFd — слушающий SOCKS5-сокет, отданный хостом (MODULE_API §2.6). <=0 = хост его не
// передал (Windows — передать сокет нечем; либо старый хост) → биндим сами по LISTEN_PORT.
// Ставится ОДИН раз в realMain до любого использования — гонки нет. Читает socks5.go, у которого
// в области видимости аргументов realMain нет.
var hostListenFd int

// realMain — ОБЩЕЕ тело модуля для обеих форм доставки (desktop-процесс и Android-слот).
// configContent — СОДЕРЖИМОЕ конфига, не путь (§3: секреты мимо диска). Возврат — код выхода;
// на практике функция не возвращается, пока жив туннель (ждёт rootCtx.Done()).
func Run(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath // qWDTT не использует

	dieWithParent()      // android-subprocess: PR_SET_PDEATHSIG; слот/desktop: no-op
	protectFromOomKill() // android-subprocess: oom_score_adj=-1000; слот/desktop: no-op

	hostListenFd = listenFd
	moduleProfileDir = profileDir // для interactive-action капчи (§2.7)

	log.SetOutput(progressWriter{inner: os.Stderr})
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	raw := configContent
	// ЕДИНЫЙ формат коннект-конфига на ОБЕИХ платформах (MODULE_API §2.2): KEY=VALUE +
	// СЫРАЯ ссылка — LISTEN_PORT / SOCKS_USER / SOCKS_PASS / LINK, где LINK = qwdtt://-ссылка,
	// которую helper декодит САМ (Kotlin prepareConfig выпилен — единый источник декода в Go,
	// кроссплатформенно). И Android ModuleManager, и Desktop-хост пишут именно этот формат.
	// (JSON-импорт конфига юзером — отдельный путь через сабкоманду normalize, см. normalizeQwdtt.)
	cfg, derr := parseHelperConfig(strings.TrimSpace(raw))
	if derr != nil {
		log.Fatalf("[HELPER] parsing config: %v", derr)
	}
	// APP_LANG — резолвить СРАЗУ после парсинга, ДО любого emitProgress/emitLog ниже.
	qwS = qwdttStringsFor(cfg.AppLang)
	// antinet §4.2 — восстановить TURN-креды прошлой сессии, если хост их вернул и они ещё годны.
	// Строго ДО подъёма группы: GetCreds зовётся один раз на её старте, и подменять надо ДО, иначе
	// вся VK-цепочка (включая капчу) уже уйдёт в работу. Отказ на любой неоднозначности — внутри.
	// §4.2 — отпечаток ССЫЛКИ МОДУЛЯ для блоба состояния. Ставится ДО LoadRestoredCreds и до подъёма
	// группы: SaveCredsToHost зовётся из глубины creds.go, где ссылки модуля в области видимости нет
	// (там в обороте VK-хеш звонка). Развёрнутое обоснование — коммент к persistedCreds.
	SetStateLinkFP(cfg.Link)
	LoadRestoredCreds(cfg.ModuleState, cfg.Link, cfg.StartReason)
	setSocksDialTimeoutSec(cfg.DialTimeoutSec) // antinet: потолок дозвона до цели, см. socks5.go
	// relayWatchdog: окно детекта обрыва релея (сек) → порог handshake-fail'ов (÷ REKEY_TIMEOUT 5с).
	// RELAY_WINDOW_SEC из конфига (дефолт от модуля / юзер-оверрайд в карточке «Модули»); 0 → дефолт 15с.
	if cfg.RelayWindowSec > 0 {
		thr := int32(cfg.RelayWindowSec / 5)
		if thr < 2 {
			thr = 2
		}
		relayStuckThreshold = thr
		// Второй сигнал (rx/tx, см. relaySilentTicks) живёт на ТОМ ЖЕ окне, только делится на свой тик.
		sil := relaySilentTicksFor(cfg.RelayWindowSec)
		relaySilentTicks = sil
		// Из ТОГО ЖЕ окна — потолок ожидания ответа на запрос конфига: он обязан истечь раньше, чем
		// watchdog прибьёт транспорт, иначе причина неподъёма не попадёт наружу вовсе (обоснование
		// и живой случай — у configRequestBudget).
		configRequestBudget = configRequestBudgetFor(cfg.RelayWindowSec)
		log.Printf("[SETTINGS] relayWatchdog window %ds -> threshold %d handshake-fails / %d rx-silence ticks / config budget %s",
			cfg.RelayWindowSec, thr, sil, configRequestBudget)
	}

	// protect всех исходящих сокетов off-TUN — канон (`shared/protect` на android, `shared/offtun`
	// на десктопе). Замер (`*protectStat`) не собираем: у qWDTT своя разбивка PERFSPLIT на уровне
	// транспорта.
	protectControl = dialControl(protectPath, nil)
	// dnsPreset (SETTING_dnsPreset, карточка «Модули») — юзер-выбор DNS для ВСЕЙ VK-цепочки (VK API +
	// не-DoH DNS-дозвон); "" → "yandex" (прежний хардкод-дефолт 77.88.8.8/77.88.8.1, не связано с off-TUN).
	dnsPreset := strings.TrimSpace(cfg.DnsPreset)
	if dnsPreset == "" {
		dnsPreset = "yandex"
	}
	setupGlobalResolver(dnsPreset)
	// Режим решения капчи — из настройки SETTING_captchaMode (карточка «Модули»; auto/rjs/wv). Пусто → auto
	// (normalizeCaptchaMode). Это и есть юзер-выбор «авторешение капчи или ручной webview» (§ настройки модулей).
	log.Printf("[SETTINGS] captcha mode: %s", setCaptchaMode(cfg.CaptchaMode))
	// VK auth mode (SETTING_vkAuthMode) / anon path (SETTING_vkAnonPath) — см. vk_account.go. Пусто →
	// дефолты уже заданы init()'ом этого пакета (anonymous/vkcalls) — вызовы ниже no-op в этом случае.
	log.Printf("[SETTINGS] vk auth mode: %s / anon-path: %s", setVkAuthMode(cfg.VkAuthMode), setVkAnonPath(cfg.VkAnonPath))

	emitProgress("%s", "Starting qWDTT...")

	wrapKey, err := deriveWrapKey(cfg.Password)
	if err != nil {
		log.Fatalf("[HELPER] WRAP key: %v", err)
	}
	hashes := ParseHashes(cfg.Hashes)
	if len(hashes) == 0 {
		log.Fatal("[HELPER] no VK hashes")
	}
	// Адрес пира зависит от ТРАНСПОРТНОГО РЕЖИМА: у сервера под `rawtun` и под `noDtls` свои
	// слушатели на своих портах (peerForTransport, helper.go). Подмена стоит ЗДЕСЬ, до резолва,
	// потому что дальше `peer` расходится по всем воркерам и сессиям — подменять ниже значило бы
	// ловить каждого потребителя по отдельности. `cfg.Peer` при этом остаётся нетронутым: из него
	// считается deviceID, и его смена сломала бы уже выданные привязанные к устройству пароли.
	peerAddr := peerForTransport(cfg)
	if peerAddr != cfg.Peer {
		log.Printf("[SETTINGS] transport %q -> peer port overridden: %s (link had %s)", cfg.ConnMode, peerAddr, cfg.Peer)
	}
	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		log.Fatalf("[HELPER] peer address %q: %v", peerAddr, err)
	}

	// Число воркеров уходит в транспорт КАК ЕСТЬ: разбивку на группы (ceiling + клампинг последней)
	// делает `runTransport`, дословно как у автора. Своего округления здесь быть не должно — оно
	// стояло, роняло запрошенные 16 до 9 (floor к кратному 9) и молчало, то есть ссылка с
	// `workers=16` поднимала 9 TURN-релеев вместо 16.
	//
	// Верхний потолок оставлен: `cfg.Workers` приходит из ССЫЛКИ, а не из флага CLI, как у автора,
	// и ничем иным число relay-аллокаций не ограничено.
	numW := cfg.Workers
	if numW > maxWorkers {
		log.Printf("[SETTINGS] workers %d -> %d (upper cap)", cfg.Workers, maxWorkers)
		numW = maxWorkers
	}
	if numW <= 0 {
		numW = defaultWorkers
	}

	// Локальный UDP-порт — чисто внутрипроцессный IPC (wgconfig.go::forceEndpoint заставляет
	// wireguard-go этого же процесса дозваниваться на localConn ЧЕРЕЗ loopback; см. dispatcher.go).
	// Ни один внешний компонент не завязан на конкретное значение порта. Фиксированный дефолт
	// (defaultLocalPort=9000) на каждом релонче давал детерминированный "bind: address already in
	// use", если предыдущий инстанс модуля (прошлый reconnect/slot) ещё не успел освободить порт —
	// эфемерный bind устраняет класс гонки целиком вместо ретрая/ожидания. Явный `port=`/`listenPort=`
	// из ссылки (если оператор его задал) уважается как раньше.
	// Явный `port=` из ссылки уважается ПОПЫТКОЙ, а не требованием: если он занят — молча
	// уходим на эфемерный. Порт внутрипроцессный (см. абзац выше), снаружи на него не завязан
	// НИКТО, поэтому «не смог занять именно 9000» — не повод падать.
	//
	// Живой случай: вторая одновременная сессия схемы (пинг соседа при
	// активном коннекте) умирала за 33 мс с `[HELPER] local UDP 127.0.0.1:9000: listen udp …
	// address already in use` — первый экземпляр уже держал порт. С фоллбэком обе сессии
	// живут: коннектная на своём порту, пинговая на эфемерном.
	bindAddr := "127.0.0.1:0"
	if cfg.LocalPort > 0 {
		bindAddr = "127.0.0.1:" + strconv.Itoa(cfg.LocalPort)
	}
	localConn, err := net.ListenPacket("udp", bindAddr)
	if err != nil && bindAddr != "127.0.0.1:0" {
		log.Printf("[HELPER] local UDP %s is busy (%v) - falling back to an ephemeral port", bindAddr, err)
		bindAddr = "127.0.0.1:0"
		localConn, err = net.ListenPacket("udp", bindAddr)
	}
	if err != nil {
		log.Fatalf("[HELPER] local UDP %s: %v", bindAddr, err)
	}
	localPortStr := strconv.Itoa(localConn.LocalAddr().(*net.UDPAddr).Port)
	if uc, ok := localConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufSize)
		_ = uc.SetWriteBuffer(socketBufSize)
	}

	// Идентичность устройства для сервера qWDTT — СВОЯ, выводимая из пароля и адреса пира.
	// Хост с некоторых пор шлёт в конфиге generic-ключ `DEVICE_ID` (MODULE_API §2.3, единый hwid на
	// всё приложение), и этот модуль его НЕ читает намеренно: схема оставлена прежней.
	deviceID := deviceIDFor(cfg.Password, cfg.Peer)
	// v1.3.5: ObfsMode новое поле, "audio" = прежний неявный дефолт.
	// 1.4.3: три транспортных режима автора. RawMode ПОДРАЗУМЕВАЕТ NoDTLS — сервер на
	// `-listen-raw` DTLS не понимает вовсе (см. комментарий у TurnParams.RawMode), поэтому связка
	// выражается здесь, ОДИН раз, а не проверяется потом на каждом потребителе: иначе `rawtun` с
	// невыставленным `SETTING_noDtls` собирал бы DTLS-ветку и молча не соединялся.
	rawMode := cfg.ConnMode == "rawtun"
	tp := &TurnParams{
		Hashes:       hashes,
		WrapKey:      wrapKey,
		ObfsMode:     normalizeObfsMode("audio"),
		RawMode:      rawMode,
		NoDTLS:       cfg.NoDTLS || rawMode,
		TCPTransport: cfg.TurnTCP,
	}
	// Диагностика эффективных режимов — одна строка на запуск, тот же приём и та же причина, что у
	// соседних `[SETTINGS]`-строк выше: настройка, применяющаяся МОЛЧА, не проверяется юзером никак —
	// при жалобе «включил raw, не работает» по логу нельзя отличить «режим не доехал» от «режим
	// доехал и не сработал».
	// cfg.ConnMode как есть: нормализация уже сделана ЕДИНОЖДЫ при разборе настройки
	// (helper.go::parseHelperConfig). Повторный normalizeConnMode здесь означал бы недоверие к
	// собственному полю — и разошёлся бы со строкой выше, которая сравнивает его напрямую.
	log.Printf("[SETTINGS] transport: mode=%s noDtls=%v turnTcp=%v",
		cfg.ConnMode, tp.NoDTLS, tp.TCPTransport)
	// ...и ОДНА строка в ВИДИМЫЙ журнал (LOG|, §2.9): строка выше живёт в helper.stdout.log, куда
	// юзер без adb не заглянет, а прогресс-тост «прямой туннель (без DTLS)» одинаков у `rawtun` и у
	// `vpn+noDtls` — по нему режим неотличим. Здесь же он назван прямо, вместе с адресом, на который
	// реально идёт подключение: это единственное место, где видно и выбранный режим, и следствие
	// подмены порта.
	switch {
	case tp.RawMode:
		emitLog(qwS.transportRawFmt, peerAddr)
	case tp.NoDTLS:
		emitLog(qwS.transportDirectFmt, peerAddr)
	default:
		emitLog(qwS.transportDtlsFmt, peerAddr)
	}
	stats := NewStats()

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	// Хост перед остановкой шлёт событие `stop` (MODULE_API §2.8) и коротко ждёт. Нам это нужно,
	// чтобы каждая RAW-сессия успела отправить `DISCONNECT_RAW` (session.go): сервер вычищает
	// запись воркера иначе только по 90-секундному idleTimeout и всё это время продолжает лить в
	// неё downlink round-robin'ом — новая сессия того же устройства теряет половину обратного
	// трафика. Отмена корневого контекста — тот же путь, что и штатное завершение, своего не заводим.
	moduleStopHook = rootCancel

	wgConf, err := runTransportSupervised(rootCtx, tp, peer, localConn, localPortStr, numW, deviceID, cfg, stats, profileDir)
	if err != nil {
		return 1 // rootCtx уже отменён (родительский shutdown) — эмиты прогресса уже сделаны супервизором
	}
	// В режиме rawtun туннель уже поднят внутри runTransport (netstack там — источник пакетов
	// диспетчера). Сюда приезжает та же строка RAWCONF просто как признак
	// «конфиг получен»; повторный подъём означал бы второй netstack и второй SOCKS-листенер на
	// уже занятом порту.
	if strings.HasPrefix(wgConf, rawConfPrefix) {
		emitProgress("%s", "Tunnel ready")
		<-rootCtx.Done()
		return 0
	}

	emitProgress("%s", "WireGuard config received, bringing up the tunnel...")

	if err := bringUpTunnelAndSocks(wgConf, localPortStr, profileDir, cfg); err != nil {
		log.Fatalf("[HELPER] bringing up tunnel: %v", err)
	}
	emitProgress("%s", "Tunnel ready")
	<-rootCtx.Done()
	return 0
}
