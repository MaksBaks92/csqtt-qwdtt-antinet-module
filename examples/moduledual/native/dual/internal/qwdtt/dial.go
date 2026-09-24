// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// dial.go — ЕДИНАЯ точка ВНЕШНЕГО дозвона qWDTT. Всё, что модуль отправляет наружу (VK-auth к API,
// DNS-резолв, bootstrap-TLS для DoH, UDP к TURN-релею), идёт отсюда и обязано нести protect-хук:
// UID helper'а ВКЛЮЧЁН в TUN (Husi-pattern), поэтому незащищённый сокет уходит в НАШ ЖЕ туннель —
// то есть модуль дозванивается до своего сервера через туннель, который сам же и поднимает.
//
// Апстримные creds.go/doh.go конструировали `net.Dialer{...}` прямо на месте; здесь заменены
// ТОЛЬКО эти строки — сама VK-auth/DoH-логика остаётся пристинной.
//
// ⚠ Почему ОБЫЧНЫЕ функции, а не package-level `var f func(...)` + отдельный `init()`: именно та
// форма тут и стояла, и давала 100%-детерминированный краш. `getTokenChain` звал такую переменную
// безусловно на первом же VK-auth-запросе, а заполняющий её `init()` жил в файле, которого не
// существовало НИГДЕ в дереве — вызов nil → `panic: invalid memory address or nil pointer
// dereference` (SIGSEGV) при каждом старте, без единого исключения. `go build` при этом проходил
// чисто: компилятор не проверяет, что переменная-функция заполнена до первого вызова. Функция
// такой дыры не имеет структурно (MODULE_API §4, «Антипаттерн»).

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// protectControl — protect-хук формы `net.Dialer.Control`, ОДИН на весь исходящий трафик модуля.
// Заполняется один раз в `realMain` (run.go) каноном `dialControl(protectPath, nil)`: на Android он
// шлёт каждый fd protect-сервису через SCM_RIGHTS, на десктопе биндит сокет к физическому адаптеру.
//
// Переменная, а не константа, потому что `protectPath` приезжает от хоста в рантайме. nil здесь
// безопасен структурно — `net.Dialer`/`net.ListenConfig` трактуют nil-Control как штатный no-op
// (TUN не поднят, протектить нечего), и это НЕ та же ситуация, что вызов nil-функции.
var protectControl func(network, address string, c syscall.RawConn) error

// protectedDialUDP — UNCONNECTED UDP-сокет для TURN-клиента, идущий через тот же protect, что и
// остальной внешний трафик. Раньше это был голый `net.DialUDP`: TURN control-plane к
// VK-инфраструктуре шёл БЕЗ protect и мог молча утекать в TUN.
//
// ⚠ ОБЯЗАН быть unconnected (`ListenPacket`, НЕ `Dial` с явным remote): `pion/turn`'s
// `ClientConfig.Conn` зовёт `WriteTo(data, addr)` сам, для нескольких пиров на одном сокете
// (STUN-сервер отвечает с другого адреса при keep-alive/permissions). Connected-сокет даёт
// `ErrWriteToConnected` («use of WriteTo with pre-connected connection») на первом же `WriteTo` —
// живо поймано на первой же попытке с первым черновиком этой функции. `addr` здесь не нужен вовсе
// (сокет слушает «любой remote», назначение несёт каждый `WriteTo`), параметр сохранён ради
// сигнатуры call site'ов в session.go.
//
// Возвращает КОНКРЕТНЫЙ `*net.UDPConn`, а не `net.PacketConn`, чтобы session.go мог звать
// `SetReadBuffer`/`SetWriteBuffer` (625 КБ). Дефолтный kernel-буфер при 9 воркерах группы, читающих
// TURN/DTLS-relay КОНКУРЕНТНО НА ОДНОМ сокете, переполняется под burst'ом и молча роняет входящие
// датаграммы ДО прикладного уровня — включая собственный DTLS-handshake (ServerHello/Certificate).
func protectedDialUDP(_ *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: protectControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("protectedDialUDP: %w", err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("protectedDialUDP: unexpected conn type %T", pc)
	}
	return uc, nil
}

// dialContext — защищённый TCP/UDP-дозвон до ОДНОГО конкретного адреса. Заменяет прямую
// конструкцию `net.Dialer{...}.DialContext(...)` в bootstrap-TLS doh.go и в non-DoH DNS-дозвоне
// `setupGlobalResolver` (creds.go).
func dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Control: protectControl}
	return d.DialContext(ctx, network, address)
}

// tlsClientDialerOption — опция для `tlsclient.NewHttpClient`: VK API дозванивается через тот же
// protect. Отдаётся значением на каждый вызов, потому что `tlsclient.WithDialer` принимает
// `net.Dialer` по значению.
func tlsClientDialerOption() tlsclient.HttpClientOption {
	return tlsclient.WithDialer(net.Dialer{Control: protectControl})
}

// dialWithTimeout — `dialContext` со СВОИМ потолком на вызов. Апстрим нёс его прямо в литерале
// `net.Dialer{Timeout: X}` на каждом call site'е (setupGlobalResolver — 3с, bootstrap-dialer
// doh.go — 5с); при сведении в одну функцию потолок стал бы потерян, поэтому он вынесен в явный
// параметр. KeepAlive (был 30с на обоих call site'ах) сознательно не переносится: оба дозвона
// короткоживущие (один DNS-обмен, один DoH HTTP/2-обмен), пробы keepalive идут после длительного
// простоя и на такой connection практически никогда не успевают сработать.
func dialWithTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dialContext(dctx, network, address)
}
