// SPDX-License-Identifier: MIT

package main

// Тесты ГЕЙТОВАННОЙ половины канона shared/dns — кэширующего резолвера dial-таргетов. Отдельный
// файл, а не общий с прокладкой: прокладка инжектируется всегда, резолвер — только по
// `"dnsResolver": true`, и тест, который тянет `newProtectedResolver`, у модуля без флага просто
// не соберётся. Живой случай: qWDTT флага не объявляет, и общий тест-файл ронял ему сборку тестов.
//
// Прогон — `build.py --test` на модуле С флагом (эталон — echo).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestLookupHostNeverFallsBackToDefaultResolver — ловушка на `net.DefaultResolver`.
//
// Проверяется именно ОТСУТСТВИЕ обращения: прежняя редакция канона при пустом списке звала
// `net.DefaultResolver.LookupHost` напрямую, и это было незаметно — резолв формально удавался,
// просто уходил в туннель. Тест ловит возврат такого поведения, а не текущую формулировку кода.
//
// Не параллелится: `net.DefaultResolver` — глобал процесса.
func TestLookupHostNeverFallsBackToDefaultResolver(t *testing.T) {
	saved := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = saved })

	var touched bool
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			touched = true
			return nil, errors.New("trap: DefaultResolver must not be used")
		},
	}

	// Резолвер без единого сервера — ровно то состояние, в котором прежний код уходил в обход.
	r := newProtectedResolver("", "")
	// `.invalid` (RFC 2606) не существует по стандарту: что бы ни ответила ОС, это не сеть и не
	// зависание — важен только факт, что ловушка осталась нетронутой.
	_, _ = r.LookupHost("antinet-canon-probe.invalid")

	if touched {
		t.Fatal("LookupHost ушёл в net.DefaultResolver — это путь в TUN, см. doc-comment прокладки")
	}
}

// TestNilResolverIsAnError — резолвер не создан вовсе. Отдельный случай от «нет серверов»:
// это незаконченная инициализация модуля, и молчаливый обход прятал бы её до боевого запуска.
func TestNilResolverIsAnError(t *testing.T) {
	var r *protectedResolver
	if _, err := r.LookupHost("antinet-canon-probe.invalid"); !errors.Is(err, errNoDNSServers) {
		t.Fatalf("ожидалась errNoDNSServers, получено: %v", err)
	}
}

// TestResolverFollowsHostDNSAutomatically — резолвер сам догоняет смену сети.
//
// Боевой путь целиком: событие хоста → `handleHostEvent` → канон → резолвер. Модуль в этой цепочке
// НЕ участвует, и это главное утверждение: пока обновление было его обязанностью, оно выглядело
// как пять строк в обработчике и ровно так же молча отсутствовало у того, кто про них не прочитал.
func TestResolverFollowsHostDNSAutomatically(t *testing.T) {
	resetHostDNSForTest()
	r := newProtectedResolver("192.0.2.1", "")

	handleHostEvent("dns=198.51.100.5,198.51.100.6")

	got := r.currentServers()
	if len(got) != 2 || got[0] != "198.51.100.5:53" {
		t.Fatalf("резолвер не догнал список от хоста: %v", got)
	}
}

// TestSetServersKeepsPreviousOnEmpty — пустой список НЕ применяется.
//
// Список приходит от хоста, и пустым он бывает ровно тогда, когда хост не смог определить
// физическую сеть. Применить его значило бы сбросить рабочие серверы на системный фоллбэк в
// момент, когда рабочие уже есть на руках.
func TestSetServersKeepsPreviousOnEmpty(t *testing.T) {
	r := newProtectedResolver("192.0.2.1,192.0.2.2", "")
	before := r.currentServers()
	if len(before) != 2 {
		t.Fatalf("подготовка: ожидалось 2 сервера, получено %v", before)
	}

	r.SetServers(nil)
	r.SetServers([]string{"", "   "})

	after := r.currentServers()
	if len(after) != len(before) {
		t.Fatalf("пустой список затёр рабочие серверы: было %v, стало %v", before, after)
	}
}

func TestQueryAllSkipsAAAAWhenAHits(t *testing.T) {
	orig := dnsQueryOne
	t.Cleanup(func() { dnsQueryOne = orig })
	var aaaa atomic.Int32
	dnsQueryOne = func(server, protectPath, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, error) {
		_ = server
		_ = protectPath
		_ = host
		_ = timeout
		if qtype == dnsmessage.TypeAAAA {
			aaaa.Add(1)
			return []string{"2001:db8::1"}, nil
		}
		return []string{"192.0.2.1"}, nil
	}
	r := newProtectedResolver("192.0.2.53,192.0.2.54", "")
	ips, err := r.queryAll("example.test")
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("A must win: ips=%v err=%v", ips, err)
	}
	if aaaa.Load() != 0 {
		t.Fatalf("AAAA must not run when A succeeded: %d", aaaa.Load())
	}
}

func TestQueryAllFallsBackToAAAA(t *testing.T) {
	orig := dnsQueryOne
	t.Cleanup(func() { dnsQueryOne = orig })
	dnsQueryOne = func(server, protectPath, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, error) {
		_ = server
		_ = protectPath
		_ = host
		_ = timeout
		if qtype == dnsmessage.TypeA {
			return nil, fmt.Errorf("no A")
		}
		return []string{"2001:db8::1"}, nil
	}
	r := newProtectedResolver("192.0.2.53", "")
	ips, err := r.queryAll("example.test")
	if err != nil || len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("AAAA fallback: ips=%v err=%v", ips, err)
	}
}

func TestQueryAllRacesAServers(t *testing.T) {
	orig := dnsQueryOne
	t.Cleanup(func() { dnsQueryOne = orig })
	dnsQueryOne = func(server, protectPath, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, error) {
		_ = protectPath
		_ = host
		_ = timeout
		if qtype != dnsmessage.TypeA {
			return nil, fmt.Errorf("unexpected %v", qtype)
		}
		if server == "192.0.2.53:53" {
			time.Sleep(400 * time.Millisecond)
			return []string{"192.0.2.10"}, nil
		}
		return []string{"192.0.2.20"}, nil
	}
	r := newProtectedResolver("192.0.2.53,192.0.2.54", "")
	start := time.Now()
	ips, err := r.queryAll("example.test")
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.20" {
		t.Fatalf("fast A must win: ips=%v err=%v", ips, err)
	}
	if time.Since(start) > 800*time.Millisecond {
		t.Fatalf("A queries must race, took %v", time.Since(start))
	}
}

func TestLookupHostNegativeCache(t *testing.T) {
	orig := dnsQueryOne
	t.Cleanup(func() { dnsQueryOne = orig })
	var calls atomic.Int32
	dnsQueryOne = func(server, protectPath, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, error) {
		_ = server
		_ = protectPath
		_ = host
		_ = qtype
		_ = timeout
		calls.Add(1)
		return nil, fmt.Errorf("nxdomain")
	}
	r := newProtectedResolver("192.0.2.53", "")
	if _, err := r.LookupHost("missing.test"); err == nil {
		t.Fatal("expected negative lookup error")
	}
	first := calls.Load()
	if first == 0 {
		t.Fatal("first lookup must query")
	}
	if _, err := r.LookupHost("missing.test"); err == nil {
		t.Fatal("negative cache must still fail")
	}
	if calls.Load() != first {
		t.Fatalf("negative cache must skip the network: first=%d later=%d", first, calls.Load())
	}
}

func TestDNSCacheCapEvicts(t *testing.T) {
	r := newProtectedResolver("192.0.2.53", "")
	r.mu.Lock()
	for i := 0; i < dnsCacheMax; i++ {
		r.cache[fmt.Sprintf("h%d.test", i)] = dnsCacheEntry{
			ips:     []string{"192.0.2.1"},
			expires: time.Now().Add(time.Hour),
		}
	}
	r.rememberLocked("new.test", dnsCacheEntry{ips: []string{"192.0.2.9"}, expires: time.Now().Add(time.Hour)})
	if len(r.cache) != dnsCacheMax {
		t.Fatalf("cap %d, got %d", dnsCacheMax, len(r.cache))
	}
	if _, ok := r.cache["new.test"]; !ok {
		t.Fatal("new entry must be stored")
	}
	r.mu.Unlock()
}
