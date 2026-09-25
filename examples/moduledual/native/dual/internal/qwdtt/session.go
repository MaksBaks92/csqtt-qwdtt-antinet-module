// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/turn/v5"
)

const (
	// Глубина SendCh на воркер. 128 при raw/SOCKS+gVisor не хватало на upload: TCP
	// внутри netstack успевал залить NIC быстрее, чем Writer успевал AEAD+TURN →
	// диспетчер упирался в полные каналы. Раньше дропал пакеты (обвал cwnd); теперь
	// backpressure, но глубокая очередь всё равно снижает частоту блокировок.
	workerSendBuf = 512
	sessionReadTimeout = 30 * time.Minute // Increased from 60s to 30min
	readBufSize        = 1600
	socketBufSize      = 625 * 1024
	keepaliveByte      = 0xFF // keepalive marker (DTLS-level или прямой obfs-кадр)
	// keepaliveInterval: 1с (как у референсного клиента) — агрессивнее держит
	// TURN permission/NAT-маппинг "тёплым" на каждом из 18-108 relay-сокетов
	// сессии, чем прежние 15с/5с.
	keepaliveInterval = 10 * time.Second
	// keepaliveMinSize/keepaliveMaxSize: keepalive-пакет теперь не
	// фиксированного размера (было 1 байт постоянно) — случайная длина
	// 25-44 байта имитирует "тишину" OPUS в реальном звонке; постоянный
	// размер через равные интервалы — легко узнаваемый паттерн для DPI.
	keepaliveMinSize = 25
	keepaliveMaxSize = 20 // диапазон добавки к keepaliveMinSize (rand.Intn(20))
)

// obfsDirectConn — net.Conn поверх TURN relay БЕЗ DTLS.
//
// RTP-obfs (ChaCha20-Poly1305/AES-GCM AEAD, obfs.go) уже даёт полноценное
// шифрование+аутентификацию каждого пакета. DTLS поверх него был чистым
// оверхедом: self-signed сертификат с InsecureSkipVerify не добавлял
// реальной защиты, зато удваивал AEAD-обработку на пакет и требовал
// отдельного хендшейка (см. handshakeSem) на каждую из 9 воркер-сессий.
// Используется только когда tp.NoDTLS=true И useWrap=true (иначе тут вообще
// нет шифрования — тогда обязателен DTLS, см. ветку ниже).
type obfsDirectConn struct {
	relay      net.PacketConn
	peer       net.Addr
	wrapKey    []byte
	cfg        *ObfsConfig
	writeState *ObfsState
	replay     replayWindow
	// sessionID — antinet: только для лог-строки первого пакета; сам транспорт им не пользуется.
	sessionID int
	// rbuf — antinet: переиспользуемый буфер приёма, см. Read.
	rbuf []byte
}

func (c *obfsDirectConn) Read(b []byte) (int, error) {
	// antinet: буфер переиспользуется между вызовами. У автора он аллоцируется ВНУТРИ Read, то есть
	// на КАЖДЫЙ принятый пакет — это самый горячий путь туннеля (Reader-горутина крутит Read в цикле
	// с b=2000 байт), и такая аллокация превращается в постоянное давление на GC, то есть в
	// процессорное время и расход батареи на устройстве. Держать буфер в структуре безопасно:
	// Read вызывает РОВНО один потребитель за раз — до старта Reader'а это последовательные
	// RequestRawConfig/RequestConfig/SendAuth, после — только сама Reader-горутина; keepalive
	// с бампа 1.4.3 ничего не читает (уходит через slot.PrioCh в единственный Writer).
	// Тот же приём и то же обоснование, что у netstackTunIO (rawtun.go).
	need := len(b) + 80 // RTP-заголовок(12) + AEAD tag + padding
	if cap(c.rbuf) < need {
		c.rbuf = make([]byte, need)
	}
	wire := c.rbuf[:need]
	for {
		n, _, err := c.relay.ReadFrom(wire)
		if err != nil {
			return 0, err
		}
		if !obfsIsRTPPacket(wire[:n]) {
			continue
		}
		m, unwrapErr := obfsUnwrapPacket(c.wrapKey, wire[:n], b)
		if unwrapErr != nil {
			continue
		}
		if !c.replay.accept(wire[:n]) {
			continue
		}
		// antinet: точка-эквивалент «DTLS установлен» для прямого режима — см. развёрнутое
		// обоснование у парного вызова в DTLS-ветке RunSession. Пакет расшифрован и прошёл
		// replay-окно, то есть релей реально ответил ИМЕННО нам и ИМЕННО нашим ключом; ничего
		// более раннего в этом режиме доказательством не является. Флаг once-ever на процесс,
		// поэтому в горячем пути стоит дешёвый Load, а не безусловный Swap на каждый пакет.
		if !transportEverEstablished.Load() {
			log.Printf("[WORKER #%d] [DIRECT] First packet decrypted from relay (%d bytes)", c.sessionID, m)
			noteTransportEstablished()
		}
		return m, nil
	}
}

func (c *obfsDirectConn) Write(b []byte) (int, error) {
	wrapped, err := obfsWrapPacket(c.wrapKey, b, c.cfg, c.writeState)
	if err != nil {
		return 0, err
	}
	if _, err := c.relay.WriteTo(wrapped, c.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *obfsDirectConn) Close() error                       { return nil }
func (c *obfsDirectConn) LocalAddr() net.Addr                { return c.relay.LocalAddr() }
func (c *obfsDirectConn) RemoteAddr() net.Addr               { return c.peer }
func (c *obfsDirectConn) SetDeadline(t time.Time) error      { return c.relay.SetDeadline(t) }
func (c *obfsDirectConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *obfsDirectConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }

// Handshake semaphore: limit to 3 concurrent DTLS handshakes
var handshakeSem = make(chan struct{}, 3)

// NullLoggerFactory подавляет логи pion
type NullLoggerFactory struct{}

func (n *NullLoggerFactory) NewLogger(_ string) logging.LeveledLogger { return &NullLogger{} }

type NullLogger struct{}

func (n *NullLogger) Trace(_ string)                    {}
func (n *NullLogger) Tracef(_ string, _ ...interface{}) {}
func (n *NullLogger) Debug(_ string)                    {}
func (n *NullLogger) Debugf(_ string, _ ...interface{}) {}
func (n *NullLogger) Info(_ string)                     {}
func (n *NullLogger) Infof(_ string, _ ...interface{})  {}
func (n *NullLogger) Warn(_ string)                     {}
func (n *NullLogger) Warnf(_ string, _ ...interface{})  {}
func (n *NullLogger) Error(_ string)                    {}
func (n *NullLogger) Errorf(_ string, _ ...interface{}) {}

// dialTURNConn открывает сокет до TURN-сервера и оборачивает его в
// net.PacketConn, которого ждёт turn.ClientConfig.Conn. По умолчанию — UDP
// (как раньше). Если tcp=true, поднимает обычное TCP-соединение и
// оборачивает его через turn.NewSTUNConn — это штатная, задокументированная
// pion/turn возможность (см. examples/turn-client/tcp), а не самописный
// протокол: NewSTUNConn сам разбирает STUN/ChannelData framing поверх
// потокового TCP. Нужен на сетях (замечено на Ростелекоме), где UDP до
// TURN-relay душится/дропается, а TCP до того же relay проходит — сравни
// github.com/anton48/vk-turn-proxy-ios, который к той же VK/OK TURN-инфре
// (calls.okcdn.ru) по умолчанию ходит именно через TCP.
func dialTURNConn(turnAddr string, tcp bool) (net.PacketConn, io.Closer, error) {
	if !tcp {
		resolved, err := net.ResolveUDPAddr("udp", turnAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN resolve: %w", err)
		}
		// AntiNet: protect off-TUN + UNCONNECTED сокет (у автора — net.DialUDP + connectedUDPConn).
		// Оба отличия обязательные, не стилистические: без protect'а TURN-трафик под Husi-pattern
		// (наш UID ВНУТРИ TUN) утекает в наш же туннель вместо физического интерфейса, а connected
		// UDP-сокет отдаёт ErrWriteToConnected на ПЕРВОМ же WriteTo, потому что pion/turn зовёт
		// WriteTo сам и для нескольких пиров на одном сокете. Полное обоснование обоих и история
		// живого провала — dial.go::protectedDialUDP.
		c, err := protectedDialUDP(resolved)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN UDP connect: %w", err)
		}
		_ = c.SetReadBuffer(socketBufSize)
		_ = c.SetWriteBuffer(socketBufSize)
		return c, c, nil
	}

	// AntiNet: TCP-плечо идёт через ТОТ ЖЕ protect, что и UDP — через уже существующий примитив
	// этого дерева (`dialWithTimeout` поверх `dialContext`, dial.go), а не через голый
	// net.Dialer автора. Иначе ровно тот транспорт, который вводится РАДИ обхода
	// UDP-душения, сам уходил бы в наш TUN — то есть в туннель, который он и поднимает.
	c, err := dialWithTimeout(context.Background(), "tcp", turnAddr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("TURN TCP connect: %w", err)
	}
	return turn.NewSTUNConn(c), c, nil
}

func RunSession(
	ctx context.Context,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	getConfig bool,
	configCh chan<- string,
	sessionID int,
	creds *Credentials,
	deviceID, password string,
	stats *Stats,
	allocateGate <-chan time.Time,
) (bool, error) {
	configDelivered := false
	var firstWrapUp uint32
	var firstWrapDown uint32
	var firstWireWrite uint32
	var firstWireRead uint32

	if len(creds.TurnURLs) == 0 {
		return false, fmt.Errorf("no TURN URL in credentials")
	}
	selectedURL := creds.TurnURLs[sessionID%len(creds.TurnURLs)]

	urlhost, urlport, err := net.SplitHostPort(selectedURL)
	if err != nil {
		return false, fmt.Errorf("parsing TURN URL %q: %w", selectedURL, err)
	}
	if tp.Host != "" {
		urlhost = tp.Host
	}
	if tp.Port != "" {
		urlport = tp.Port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)

	turnConn, turnConnCloser, err := dialTURNConn(turnAddr, tp.TCPTransport)
	if err != nil {
		return false, err
	}
	defer turnConnCloser.Close()

	if tp.TCPTransport {
		log.Printf("[SESSION #%d] TURN TCP (%s)", sessionID, turnAddr)
	} else {
		log.Printf("[SESSION #%d] TURN UDP (%s)", sessionID, turnAddr)
	}

	// RequestedAddressFamily
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	// Pion's default stdnet.NewNet enumerates network interfaces through
	// NETLINK_ROUTE. Some Huawei/Honor ROMs deny that operation to apps.
	// The zero-value stdnet.Net provides everything this UDP client uses
	// without performing the unnecessary interface enumeration.
	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Net:                    new(stdnet.Net),
		Username:               creds.User,
		Password:               creds.Pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          &NullLoggerFactory{},
	})
	if err != nil {
		return false, fmt.Errorf("TURN client: %w", err)
	}
	defer tc.Close()

	if err = tc.Listen(); err != nil {
		return false, fmt.Errorf("TURN Listen: %w", err)
	}

	// Глобальный rate-limit на сам момент TURN Allocate (не только на старт
	// горутины воркера, см. workerDelay в group.go) — не более одной новой
	// TURN-аллокации за тик по всей группе, независимо от того, сколько
	// воркеров сейчас готовы её сделать. Без этого стаггеринг старта не
	// спасает: на нестабильной сети (ретраи/задержки Allocate) несколько
	// воркеров всё равно накладываются друг на друга и вместе выжигают
	// VK-квоту (error 486) быстрее, чем должны. Тот же приём использует
	// free-turn-proxy (internal/proxy/udprelay/loop.go, общий 200ms-тикер).
	if allocateGate != nil {
		select {
		case <-allocateGate:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}

	relay, err := tc.Allocate()
	if err != nil {
		if isAuthError(err) {
			handleAuthError(creds.CacheStreamID)
		}
		errStr := err.Error()
		if strings.Contains(errStr, "Quota") || strings.Contains(errStr, "486") {
			return false, fmt.Errorf("TURN quota: %w", err)
		}
		return false, fmt.Errorf("TURN Allocate: %w", err)
	}
	defer relay.Close()

	// Reset error count on successful allocation
	getStreamCache(creds.CacheStreamID).errorCount.Store(0)

	log.Printf("[SESSION #%d] Relay: %s", sessionID, relay.LocalAddr())
	// Аллокация удалась — значит креды в обороте рабочие и слот у звонка есть. Это ЕДИНСТВЕННОЕ
	// доказательство годности восстановленных кредов (срок годности в блобе доказывает лишь, что
	// они не протухли, но не что аллокация свободна) — см. restoredCredsUnproven в credstate.go.
	NoteTurnAllocationOK()

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	// Keepalive goroutine (TURN binding request)
	var sessionWg sync.WaitGroup
	sessionWg.Add(1)
	go func() {
		defer sessionWg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				tc.SendBindingRequest()
			}
		}
	}()

	useWrap := len(tp.WrapKey) == wrapKeyLen

	var activeConn net.Conn
	var relayWg sync.WaitGroup

	if useWrap && (tp.NoDTLS || tp.RawMode) {
		// ─── Прямой режим: RTP-obfs AEAD прямо поверх TURN relay, без DTLS ───
		obfsCfg, obfsErr := NewObfsConfig(tp.ObfsMode)
		if obfsErr != nil {
			return false, fmt.Errorf("RTP-obfs config: %w", obfsErr)
		}
		obfsWriteState, obfsErr := NewObfsState()
		if obfsErr != nil {
			return false, fmt.Errorf("RTP-obfs state: %w", obfsErr)
		}
		activeConn = &obfsDirectConn{
			relay:      relay,
			peer:       peer,
			wrapKey:    tp.WrapKey,
			cfg:        obfsCfg,
			writeState: obfsWriteState,
			sessionID:  sessionID,
		}
		log.Printf("[WORKER #%d] [DIRECT] No DTLS, RTP-obfs AEAD only OK", sessionID)
	} else {
		// ─── Классический режим: DTLS поверх RTP-obfs (обратная совместимость) ───
		pipeA, pipeB := connutil.AsyncPacketPipe()
		defer pipeA.Close()
		defer pipeB.Close()

		var dtlsObfsCfg *ObfsConfig
		var obfsWriteState *ObfsState
		if useWrap {
			dtlsObfsCfg, err = NewObfsConfig(tp.ObfsMode)
			if err != nil {
				return false, fmt.Errorf("RTP-obfs config: %w", err)
			}
			obfsWriteState, err = NewObfsState()
			if err != nil {
				return false, fmt.Errorf("RTP-obfs state: %w", err)
			}
		}

		relayWg.Add(2)
		stopRelay := context.AfterFunc(sessCtx, func() {
			_ = relay.SetDeadline(time.Now())
			_ = pipeA.SetDeadline(time.Now())
		})
		defer stopRelay()

		// relay → pipeA (UNWRAP: strip RTP header + decrypt)
		go func() {
			defer relayWg.Done()
			defer sessCancel()
			// Max incoming: RTP header (12) + AEAD tag (16) + padding.
			readBufLen := readBufSize + 80
			buf := make([]byte, readBufLen)
			plain := make([]byte, readBufSize)
			var replay replayWindow
			for {
				n, _, readErr := relay.ReadFrom(buf)
				if readErr != nil {
					return
				}
				payload := buf[:n]
				if useWrap {
					if !obfsIsRTPPacket(payload) {
						log.Printf("[SESSION #%d] OBFS unwrap: unexpected packet (n=%d)", sessionID, n)
						continue
					}
					m, wrapErr := obfsUnwrapPacket(tp.WrapKey, payload, plain)
					if wrapErr != nil {
						log.Printf("[SESSION #%d] OBFS unwrap: %v (n=%d)", sessionID, wrapErr, n)
						continue
					}
					if !replay.accept(payload) {
						continue
					}
					payload = plain[:m]
				}
				if atomic.CompareAndSwapUint32(&firstWrapUp, 0, 1) {
					log.Printf("[SESSION #%d] [DEBUG] Successfully decrypted/received FIRST packet from TURN Relay (%d bytes)", sessionID, len(payload))
				}
				if _, writeErr := pipeA.WriteTo(payload, peer); writeErr != nil {
					return
				}
			}
		}()

		// pipeA → relay (WRAP: add RTP header + encrypt)
		go func() {
			defer relayWg.Done()
			defer sessCancel()
			b := make([]byte, readBufSize)
			for {
				n, _, readErr := pipeA.ReadFrom(b)
				if readErr != nil {
					return
				}
				out := b[:n]
				if useWrap {
					if dtlsObfsCfg != nil && obfsWriteState != nil {
						wrapped, wrapErr := obfsWrapPacket(tp.WrapKey, out, dtlsObfsCfg, obfsWriteState)
						if wrapErr != nil {
							log.Printf("[SESSION #%d] OBFS wrap: %v", sessionID, wrapErr)
							return
						}
						out = wrapped
					}
				}
				if atomic.CompareAndSwapUint32(&firstWrapDown, 0, 1) {
					log.Printf("[SESSION #%d] [DEBUG] Successfully encrypted/sent FIRST packet to TURN Relay (%d bytes)", sessionID, len(out))
				}
				if _, writeErr := relay.WriteTo(out, peer); writeErr != nil {
					return
				}
			}
		}()

		// DTLS с поддержкой Connection ID (без SNI)
		cert, certErr := selfsign.GenerateSelfSigned()
		if certErr != nil {
			return false, fmt.Errorf("certificate generation: %w", certErr)
		}

		// Acquire handshake semaphore
		select {
		case handshakeSem <- struct{}{}:
		case <-sessCtx.Done():
			return false, sessCtx.Err()
		}

		dtlsCfg := &dtls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true,
			ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
			CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
			MTU:                   1100,
			// No ServerName (SNI) — less detectable by DPI
		}

		dtlsConn, dtlsErr := dtls.Client(pipeB, peer, dtlsCfg)
		if dtlsErr != nil {
			<-handshakeSem
			return false, fmt.Errorf("DTLS client: %w", dtlsErr)
		}

		// Handshake budget must stay under relayWatchdogTick (15s): with the old 50s
		// timeout, handshakeSem(3) held slots until watchdog cancelled the whole run —
		// no fail LOG ever appeared, just «transport never established». Align with
		// canping path (15s) but leave ~3s headroom so HS errors surface before FIRE.
		const dtlsHandshakeBudget = 12 * time.Second
		hctx, hcancel := context.WithTimeout(sessCtx, dtlsHandshakeBudget)
		log.Printf("[WORKER #%d] [DTLS] Handshake...", sessionID)
		hsErr := dtlsConn.HandshakeContext(hctx)
		hcancel()
		<-handshakeSem // RELEASE SEMAPHORE IMMEDIATELY AFTER HANDSHAKE

		if hsErr != nil {
			dtlsConn.Close()
			if useWrap {
				errStr := strings.ToLower(hsErr.Error())
				if strings.Contains(errStr, "deadline") || strings.Contains(errStr, "timeout") {
					peerStr := ""
					if peer != nil {
						peerStr = peer.String()
					}
					reportWrapNoAnswer(peerStr)
					return false, fmt.Errorf("WRAP_AUTH_TIMEOUT: DTLS timeout, password/WRAP not confirmed")
				}
			}
			errStr := strings.ToLower(hsErr.Error())
			if strings.Contains(errStr, "deadline") || strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "context canceled") || strings.Contains(errStr, "context deadline") {
				return false, fmt.Errorf("DTLS handshake: %w (peer may only speak rawtun on :56003 — switch connMode to Raw IP)", hsErr)
			}
			return false, fmt.Errorf("DTLS handshake: %w", hsErr)
		}
		log.Printf("[WORKER #%d] [DTLS] Connection established OK", sessionID)
		// antinet: третий сигнал relayWatchdog'а (см. его доккоммент). Оба прежних сигнала
		// требуют УЖЕ поднятого транспорта — `wgHandshakeFails` растёт только когда WG есть,
		// `bytesSayRelayDead` считает байты, которых без WG тоже нет. Фаза «транспорт не встал
		// НИ РАЗУ» ими не покрыта: воркеры молча висят в хендшейке, watchdog молчит, и наверх
		// не уходит ничего. Отмечаем ПЕРВОЕ реальное установление, чтобы watchdog мог отличить
		// «ещё поднимаемся» от «релеи не отвечают вообще».
		//
		// ⚠ Прямая ветка выше своей точки здесь НЕ имеет и иметь не может: хендшейка там нет,
		// а сама конструкция obfsDirectConn ничего не доказывает — это структура в памяти, релей
		// на неё не отвечал. Её эквивалент — ПЕРВЫЙ успешно расшифрованный пакет с провода, и
		// сигнал стоит именно там (obfsDirectConn.Read). Если бы вызов остался только здесь,
		// в прямом режиме watchdog валил бы КАЖДУЮ сессию по «transport never established», а
		// хост навсегда залипал бы на статусе `waiting` (парный `ok` эмитится отсюда же).
		noteTransportEstablished()
		activeConn = dtlsConn
	}
	defer activeConn.Close()

	stats.ActiveConnections.Add(1)
	defer stats.ActiveConnections.Add(-1)

	// Запрос конфига
	if getConfig && configCh != nil && tp.RawMode {
		ip, dnsCSV, mtu, confErr := RequestRawConfig(activeConn, deviceID, password)
		if confErr != nil {
			errStr := confErr.Error()
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			log.Printf("[WORKER #%d] RAW config error: %v", sessionID, confErr)
			reportConfigNoAnswer(tp, confErr)
		} else if ip != "" {
			conf := formatRawConf(ip, dnsCSV, mtu)
			select {
			case configCh <- conf:
				configDelivered = true
				log.Printf("[WORKER #%d] RAW config received (ip=%s)", sessionID, ip)
			default:
				configDelivered = true
				log.Printf("[WORKER #%d] RAW config was already delivered by another worker", sessionID)
			}
		} else {
			log.Printf("[WORKER #%d] Server has not assigned a raw IP yet, will retry later", sessionID)
		}
	} else if getConfig && configCh != nil {
		conf, confErr := RequestConfig(activeConn, localPort, deviceID, password)
		if confErr != nil {
			errStr := confErr.Error()
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			log.Printf("[WORKER #%d] Config error: %v", sessionID, confErr)
			reportConfigNoAnswer(tp, confErr)
		} else if conf != "" {
			select {
			case configCh <- conf:
				configDelivered = true
				log.Printf("[WORKER #%d] Config received", sessionID)
			default:
				configDelivered = true
				log.Printf("[WORKER #%d] Config was already delivered by another worker", sessionID)
			}
		} else {
			log.Printf("[WORKER #%d] Server has not issued a WireGuard config yet, will retry later", sessionID)
		}
	} else {
		if authErr := SendAuth(activeConn, deviceID, password); authErr != nil {
			log.Printf("[WORKER #%d] Auth error: %v", sessionID, authErr)
		}
	}

	log.Printf("[WORKER #%d] [READY] Tunnel ready OK", sessionID)

	// Регистрация в диспетчере
	slot := &WorkerSlot{
		ID:     sessionID,
		SendCh: make(chan []byte, workerSendBuf),
		PrioCh: make(chan []byte, prioBuf),
		KeepCh: make(chan []byte, keepBuf),
	}
	// antinet: чем отменить ИМЕННО эту сессию, если её TURN-аллокация не заработает
	// (workerhealth.go). Отмена ведёт в авторский путь: sessCtx → дедлайн на activeConn → ошибка
	// Reader/Writer → возврат из RunSession → retry-цикл воркера в group.go берёт НОВУЮ
	// аллокацию. Своего механизма перезапуска не заводим.
	registerWorkerSession(sessionID, sessCancel)
	defer unregisterWorkerSession(sessionID)

	// Регистрация — сразу, как у автора. ⚠ Пробовали пускать в диспетчер только по доказанному
	// обратному пути: замер выигрыша НЕ дал (доля дозвонов >=1 с по возрасту сессии 90/80/62/21/15
	// против 75/57/38/17/0 без гейта — в пределах разброса), зато появился класс отказа, которого
	// не было, — при недостижимом пороге доказательства без воркеров остаётся весь транспорт.
	// Прогрев аллокации лечится не задержкой регистрации, а самим keepalive (см. ниже).
	d.Register(slot)
	defer d.Unregister(slot)

	// Proxy activeConn ↔ Dispatcher
	var proxyWg sync.WaitGroup
	proxyWg.Add(3) // +1 for keepalive goroutine
	sessionErrCh := make(chan error, 1)

	stopConn := context.AfterFunc(sessCtx, func() {
		_ = activeConn.SetDeadline(time.Now())
	})
	defer stopConn()

	if tp.RawMode {
		// Транспорт — UDP через TURN, у сервера нет способа узнать о разрыве
		// соединения кроме таймаута (см. handleConnRaw). Явно сообщаем о
		// намеренном отключении, чтобы сервер сразу освободил слот в
		// rawRouter вместо того чтобы ждать простоя — иначе "мёртвые"
		// соединения от прошлого сеанса засоряют round-robin в downlinkLoop
		// при быстром переподключении того же устройства.
		// ⚠ Слать НА ЛЮБОМ завершении сессии, а не только на остановке всего транспорта.
		// У автора здесь ветка `case <-sessCtx.Done():` пустая, и это дыра ровно того класса,
		// который описан абзацем выше: сессия ОДНОГО воркера кончается куда чаще, чем весь
		// транспорт (пере-дозвон при смене relay, ошибка, наш гейт односторонних аллокаций), и
		// каждый такой конец оставляет на сервере запись в `r.sessions[ip].workers`. Сервер
		// вычищает её только по `idleTimeout` = 90 с (server/raw.go), а до тех пор продолжает
		// раздавать на неё downlink round-robin'ом — то есть часть обратного трафика уходит в
		// никуда полторы минуты. Это и есть «первую минуту после коннекта всё висит».
		rawGoodbyeWG.Add(1)
		go func() {
			defer rawGoodbyeWG.Done()
			select {
			case <-ctx.Done():
			case <-sessCtx.Done():
			}
			// Дедлайн ставится ПОСЛЕ отмены намеренно: `stopConn` к этому моменту мог обнулить
			// его на activeConn, и без переустановки запись бы гарантированно не ушла.
			_ = activeConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = activeConn.Write([]byte("DISCONNECT_RAW:" + deviceID))
		}()
	}

	// Keepalive: prevents TURN allocation timeout and idle disconnect.
	// Пакет не пишется напрямую в activeConn (это была бы вторая горутина,
	// конкурирующая за conn с основным Writer'ом ниже) — кладётся в
	// slot.PrioCh неблокирующе, тем же путём, что и мелкие ACK-пакеты, и
	// уходит через единственную writer-горутину.
	go func() {
		defer proxyWg.Done()
		t := time.NewTicker(keepaliveInterval)
		defer t.Stop()

		didBytes := make([]byte, 16)
		copy(didBytes, deviceID)

		// mustSend=true только у ПЕРВОГО keepalive: он открывает путь (permission/ChannelBind у
		// TURN), и потерять его нельзя. Остальные — как у автора, неблокирующе: пропущенный пинок
		// NAT не стоит задержки данных. ⚠ Неблокирующая отправка первого и была бы потерей:
		// KeepCh глубиной 1, а Writer стартует той же строкой и может не успеть разгрести.
		send := func(mustSend bool) {
			size := keepaliveMinSize + rand.Intn(keepaliveMaxSize)
			pkt := getPktBuf(size)
			pkt[0] = keepaliveByte
			copy(pkt[1:17], didBytes)
			for i := 17; i < size; i++ {
				pkt[i] = keepaliveByte
			}
			// antinet: KeepCh, а не PrioCh (куда его положил апстрим) — Writer обязан
			// отличать служебный трафик от данных, см. WorkerSlot.KeepCh.
			if mustSend {
				select {
				case slot.KeepCh <- pkt:
				case <-sessCtx.Done():
					putPktBuf(pkt)
				}
				return
			}
			select {
			case slot.KeepCh <- pkt:
			default:
				putPktBuf(pkt)
			}
		}

		// antinet: ПЕРВЫЙ keepalive — сразу, не через keepaliveInterval. У автора горутина ждёт
		// первый тик (10 с), и всё это время свежая TURN-аллокация не отправила НИ ОДНОГО байта:
		// ни relay-permission у TURN, ни сопоставление deviceID→relay на сервере по ней не заведены.
		// Пакеты, которые диспетчер раздал на такого «непредставленного» воркера, теряются, а так
		// как новое TCP-соединение — это ровно один маленький пакет (SYN), потеря видна юзером как
		// зависание на секунду-три (RTO). Замер на боевом сервере: в первые 90 с сессии 23 из 30
		// дозвонов шли >=1 с, на прогретой той же сессии — 4 из 87. Один служебный пакет на воркера
		// снимает разницу между этими двумя состояниями.
		send(true)

		// Фаза прогрева: пока путь не доказан, keepalive идёт каждые warmTick, а не раз в 10 с.
		// Он и есть то, что открывает путь (permission/ChannelBind у TURN), поэтому редкий тик
		// растягивает непригодное состояние аллокации на десятки секунд. Выход — по доказательству
		// либо по отмене сессии гейтом (workerhealth.go), третьего не бывает.
		warm := time.NewTicker(warmTick)
		for !workerProven(sessionID) {
			select {
			case <-sessCtx.Done():
				warm.Stop()
				return
			case <-warm.C:
				send(false)
			}
		}
		warm.Stop()

		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				send(false)
			}
		}
	}()

	// Writer: dispatcher → activeConn. PrioCh (мелкие пакеты/ACK) всегда
	// проверяется первым, минуя SendCh с обычными данными — иначе ACK может
	// простоять в очереди за большим chunk'ом данных.
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		defer func() {
			for {
				select {
				case p := <-slot.PrioCh:
					putPktBuf(p)
				default:
					goto drainSend
				}
			}
		drainSend:
			for {
				select {
				case p := <-slot.SendCh:
					putPktBuf(p)
				default:
					goto drainKeep
				}
			}
			// antinet: третий канал слота (KeepCh) обязан дренироваться наравне с двумя
			// каналами данных — иначе буферы keepalive'ов, оставшиеся в очереди на момент
			// смерти Writer'а, не возвращаются в pktPool.
		drainKeep:
			for {
				select {
				case p := <-slot.KeepCh:
					putPktBuf(p)
				default:
					return
				}
			}
		}()
		for {
			var pkt []byte
			var ok bool
			// isService — antinet: пакет из KeepCh (keepalive). На провод идёт наравне с
			// данными, в data-plane диагностику НЕ идёт (см. recordWorkerTx ниже).
			isService := false
			select {
			case pkt, ok = <-slot.PrioCh:
			default:
				select {
				case <-sessCtx.Done():
					return
				case pkt, ok = <-slot.PrioCh:
				case pkt, ok = <-slot.SendCh:
				case pkt, ok = <-slot.KeepCh:
					isService = true
				}
			}
			if !ok {
				return
			}
			// 3с, не sessionReadTimeout (30 мин). Запись пишет в
			// UDP-сокет к TURN relay, а не читает долгоживущее соединение;
			// 30-минутный дедлайн означал, что зависшая запись (переполненный
			// сокет-буфер ОС, плохая сеть) держала бы Writer колом полчаса,
			// пока очередь SendCh/PrioCh этого воркера копится и/или дропается
			// диспетчером выше (см. readLoop в dispatcher.go).
			_ = activeConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if atomic.CompareAndSwapUint32(&firstWireWrite, 0, 1) {
				log.Printf("[WORKER #%d] [DEBUG] Sent FIRST packet into the connection (%d bytes)", sessionID, len(pkt))
			}
			_, writeErr := activeConn.Write(pkt)
			putPktBuf(pkt)
			if writeErr == nil && !isService {
				// antinet: считаем ТОЛЬКО данные. Keepalive сюда не попадает намеренно —
				// сервер его не эхоит (helper.go), парного rx у него не будет никогда, и
				// засчитанный как tx он ломает и Σtx/Σrx, и условие silent(tx>0,rx=0).
				recordWorkerTx(sessionID) // диагностика, см. workerhealth.go
			}
			if writeErr != nil {
				log.Printf("[WORKER #%d] Writer error: %v", sessionID, writeErr)
				select {
				case sessionErrCh <- fmt.Errorf("transport writer: %w", writeErr):
				default:
				}
				return
			}
		}
	}()

	// Reader: activeConn → dispatcher
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		b := make([]byte, 2000)
		for {
			_ = activeConn.SetReadDeadline(time.Now().Add(sessionReadTimeout))
			n, readErr := activeConn.Read(b)
			if readErr != nil {
				if sessCtx.Err() != nil {
					return
				}
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("[WORKER #%d] Reader error: %v", sessionID, readErr)
				select {
				case sessionErrCh <- fmt.Errorf("transport reader: %w", readErr):
				default:
				}
				return
			}

			recordWorkerRx(sessionID) // antinet: диагностика, см. workerhealth.go — ДО skip'а
			// keepalive'а: для живости важен сам факт, что релей что-то донёс.

			// Skip keepalive pong from server
			if n == 1 && b[0] == keepaliveByte {
				continue
			}

			if atomic.CompareAndSwapUint32(&firstWireRead, 0, 1) {
				log.Printf("[WORKER #%d] [DEBUG] Received FIRST packet from the connection (%d bytes)", sessionID, n)
			}

			pkt := getPktBuf(n)
			copy(pkt, b[:n])
			select {
			case d.ReturnCh <- pkt:
			case <-sessCtx.Done():
				putPktBuf(pkt)
				return
			default:
				// ReturnCh полон — пакет дропается, но эта горутина не
				// блокируется. Раньше здесь не было default: если writeLoop
				// не успевал разгружать ReturnCh (например TUN.Write тормозит
				// на конкретном устройстве), Reader вставал колом на этом
				// select и переставал читать activeConn.Read() вообще — то
				// есть новые пакеты от сервера (включая реальные ответы на
				// пользовательский трафик) переставали вычитываться из
				// UDP-сокета ОС и терялись там, а не здесь. Один раз
				// заполнившийся канал убивал весь дальнейший приём для этого
				// воркера — select должен быть неблокирующим.
				putPktBuf(pkt)
			}
		}
	}()

	proxyWg.Wait()
	sessCancel()
	relayWg.Wait()
	sessionWg.Wait()
	log.Printf("[SESSION #%d] Finished", sessionID)
	select {
	case sessionErr := <-sessionErrCh:
		return configDelivered, sessionErr
	default:
	}
	return configDelivered, nil
}

func RunPing(
	ctx context.Context,
	tp *TurnParams,
	peer *net.UDPAddr,
	creds *Credentials,
) (int64, error) {
	startPing := time.Now()

	if len(creds.TurnURLs) == 0 {
		return 0, fmt.Errorf("no TURN URL")
	}
	selectedURL := creds.TurnURLs[0]

	urlhost, urlport, err := net.SplitHostPort(selectedURL)
	if err != nil {
		return 0, err
	}
	if tp.Host != "" {
		urlhost = tp.Host
	}
	if tp.Port != "" {
		urlport = tp.Port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)

	// Тот же dialTURNConn, что и у боевой сессии — включая выбор UDP/TCP. Мерить пинг по UDP,
	// когда сессия пойдёт по TCP (или наоборот), значит короновать транспорт по цифре, которая
	// к нему не относится: это ровно тот класс, что закрыт на Android-стороне правилом «путь
	// ПИНГА обязан звать applyTcpOptions наравне с коннектом» (root CLAUDE.md § пинг).
	// protect off-TUN живёт внутри dialTURNConn для обеих семей.
	turnConn, turnConnCloser, err := dialTURNConn(turnAddr, tp.TCPTransport)
	if err != nil {
		return 0, err
	}
	defer turnConnCloser.Close()

	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Net:                    new(stdnet.Net),
		Username:               creds.User,
		Password:               creds.Pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          &NullLoggerFactory{},
	})
	if err != nil {
		return 0, err
	}
	defer tc.Close()

	if err = tc.Listen(); err != nil {
		return 0, err
	}

	relay, err := tc.Allocate()
	if err != nil {
		return 0, err
	}
	defer relay.Close()

	pipeA, pipeB := connutil.AsyncPacketPipe()
	defer pipeA.Close()
	defer pipeB.Close()

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	var relayWg sync.WaitGroup
	relayWg.Add(2)

	useWrap := len(tp.WrapKey) == wrapKeyLen
	var obfsCfg *ObfsConfig
	var obfsWriteState *ObfsState
	if useWrap {
		obfsCfg, err = NewObfsConfig(tp.ObfsMode)
		if err != nil {
			return 0, fmt.Errorf("RTP-obfs config: %w", err)
		}
		obfsWriteState, err = NewObfsState()
		if err != nil {
			return 0, fmt.Errorf("RTP-obfs state: %w", err)
		}
	}

	// relay → pipeA
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		buf := make([]byte, readBufSize+80)
		plain := make([]byte, readBufSize)
		var replay replayWindow
		for {
			n, _, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			if useWrap {
				if !obfsIsRTPPacket(payload) {
					continue
				}
				m, err := obfsUnwrapPacket(tp.WrapKey, payload, plain)
				if err != nil {
					continue
				}
				if !replay.accept(payload) {
					continue
				}
				payload = plain[:m]
			}
			_, _ = pipeA.WriteTo(payload, peer)
		}
	}()

	// pipeA → relay
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		for {
			n, _, err := pipeA.ReadFrom(b)
			if err != nil {
				return
			}
			out := b[:n]
			if useWrap {
				wrapped, err := obfsWrapPacket(tp.WrapKey, out, obfsCfg, obfsWriteState)
				if err != nil {
					return
				}
				out = wrapped
			}
			_, _ = relay.WriteTo(out, peer)
		}
	}()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return 0, err
	}

	dtlsCfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
		MTU:                   1100,
	}

	dtlsConn, err := dtls.Client(pipeB, peer, dtlsCfg)
	if err != nil {
		return 0, err
	}
	defer dtlsConn.Close()

	hctx, hcancel := context.WithTimeout(sessCtx, 15*time.Second)
	defer hcancel()

	err = dtlsConn.HandshakeContext(hctx)
	if err != nil {
		return 0, err
	}

	rtt := time.Since(startPing).Milliseconds()
	// Handshake completes -> we have a successful round trip!
	return rtt, nil
}
