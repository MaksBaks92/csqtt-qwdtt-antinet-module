// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// Пер-воркерный учёт пакетов — ДИАГНОСТИКА, не механизм принятия решений.
//
// Зачем. `dispatcher.go` (пристинное ядро автора) раскидывает исходящие WG-пакеты по воркерам
// неблокирующей отправкой, а когда ВСЕ каналы полны — молча выбрасывает пакет (`putPktBuf` в ветке
// `!sent`, dispatcher.go:196-201): ни счётчика, ни лога. Параллельно воркер, чей TURN-мэппинг умер,
// продолжает исправно разгребать свой `SendCh` и писать в живой DTLS-сокет, улетающий в никуда —
// `Активных` остаётся 18, ошибок нет (ровно failure mode, описанный в доккомменте relayWatchdog).
//
// Итог: два независимых способа потерять пакеты, и оба НЕВИДИМЫ. Живой разбор упирается
// именно в это: профиль потерь 10-17% (SYN'ы теряются, крупные данные идут — MTU-версия отпадает),
// при этом в логе ни единой ошибки. Прежде чем чинить, надо увидеть, КАКОЙ из двух механизмов и на
// каких воркерах реально теряет — иначе детектор строится на догадке.
//
// Что считаем. tx/rx РЕАЛЬНЫХ DTLS-операций каждого воркера (обе точки — в session.go, нашем файле;
// пристинный dispatcher.go не трогается). Дропы диспетчера выводятся арифметически, без правки его
// кода: WG отдал `wgTx` байт (штатный UAPI wireguard-go), воркеры записали в DTLS `Σ workerTx`
// пакетов — систематическое расхождение и есть выброшенное в `!sent`-ветке.
//
// ⚠ Это НЕ сигнал живости и НЕ вход watchdog'а. «Воркер шлёт, но не получает» само по себе НЕ
// доказывает его смерть: сервер — один WG-пир, и его endpoint следует за ПОСЛЕДНИМ отправителем,
// поэтому в любой момент обратный трафик идёт лишь через часть воркеров. Осудить воркер по такому
// сигналу — значит городить детектор на непроверенной гипотезе; сперва цифры.

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type workerCounters struct {
	tx atomic.Int64 // пакетов реально записано в DTLS этим воркером
	rx atomic.Int64 // пакетов реально прочитано из DTLS этим воркером
}

var (
	workerStatsMu sync.RWMutex
	workerStats   = map[int]*workerCounters{}
)

// workerCountersFor — счётчики воркера, создаются лениво при первой операции.
func workerCountersFor(sessionID int) *workerCounters {
	workerStatsMu.RLock()
	c := workerStats[sessionID]
	workerStatsMu.RUnlock()
	if c != nil {
		return c
	}
	workerStatsMu.Lock()
	defer workerStatsMu.Unlock()
	if c = workerStats[sessionID]; c == nil {
		c = &workerCounters{}
		workerStats[sessionID] = c
	}
	return c
}

func recordWorkerTx(sessionID int) { workerCountersFor(sessionID).tx.Add(1) }
func recordWorkerRx(sessionID int) { workerCountersFor(sessionID).rx.Add(1) }

// resetWorkerStats — на пере-спавне транспорта: воркеры пересоздаются с теми же ID, старые цифры
// смешивать с новыми нельзя.
func resetWorkerStats() {
	workerStatsMu.Lock()
	workerStats = map[int]*workerCounters{}
	workerStatsMu.Unlock()
}

// ── Пере-дозвон глухой TURN-аллокации ─────────────────────────────────────────────────────────────
//
// Наблюдение, ради которого писались счётчики выше (замеры 2026-09-11, боевой сервер, rawtun,
// 16 воркеров): ОТДЕЛЬНЫЕ TURN-аллокации поднимаются односторонними. Воркер исправно шлёт, счётчик
// tx растёт до сотен, rx остаётся РОВНО НУЛЁМ — и так всю сессию (наблюдалось 16 минут без
// единого принятого пакета), пока все соседи, включая соседей по ТОМУ ЖЕ TURN-серверу, принимают
// нормально. Ошибок при этом нет ни одной: сокет жив, запись проходит, сессия не падает — поэтому
// авторский retry-цикл воркера (group.go) не срабатывает никогда.
//
// Порог взят ИЗ ЗАМЕРОВ, а не из головы. Во всех снятых срезах живой воркер получал первый пакет
// задолго до два-десятка отправленных (худший живой — 7/4), а глухие шли 11/0 → 24/0 → 61/0 →
// 168/0. `deafMinTx = 20` лежит выше любого наблюдавшегося живого разброса.
//
// ⚠ Гейт СРАВНИТЕЛЬНЫЙ, а не абсолютный: воркер объявляется глухим, только если ОСТАЛЬНЫЕ в это
// время слышат. Без этого условия «тишина» у всех сразу (сеть отвалилась, сервер лёг, трафика нет)
// прочиталась бы как поголовная глухота и прибила бы весь транспорт разом.
// Инвариант ОДИН: в раздаче участвует только воркер, чей обратный путь ДОКАЗАН — то есть по его
// TURN-аллокации реально что-то пришло. Отсюда две фазы одного правила, а не два механизма:
//
//   • до первого принятого пакета воркер В ДИСПЕТЧЕР НЕ ПОПАДАЕТ вовсе. Доказательство приезжает
//     само: keepalive уходит сразу при старте сессии (session.go), сервер отвечает pong'ом.
//     Не доказал за `proveTimeout` — сессия отменяется, авторский retry-цикл берёт НОВУЮ аллокацию.
//   • доказавший, но потом замолчавший (rx не растёт, пока соседи принимают) — отменяется так же.
//
// Зачем фаза 1, если раньше был только «глухой навсегда». Замер на боевом сервере показал, что
// главные потери — НЕ у односторонних аллокаций, а в первые ~2 минуты сессии, когда воркеры уже
// зарегистрированы, но их путь ещё не работает: доля дозвонов дольше 1 с шла 75% → 57% → 38% →
// 17% → 0% по мере возраста сессии при пустом туннеле (0.01-0.07 МБ за 3 с — перегрузки нет).
// Новое TCP-соединение это ровно один маленький пакет, и чанк, ушедший в неготового воркера,
// теряется целиком → RTO 1/3/7 с, который юзер видит как «первую минуту всё висит».
//
// ⚠ Оба гейта СРАВНИТЕЛЬНЫЕ: воркер судится только когда ОСТАЛЬНЫЕ в это время принимают. Иначе
// общая тишина (сеть отвалилась, сервер лёг) прочиталась бы как поголовная глухота и снесла бы
// весь транспорт разом.
const (
	// proofPackets — сколько пакетов должно ПРИЙТИ по аллокации, чтобы считать её рабочей.
	// ⚠ РОВНО ОДИН, и это проверено дорогой ценой: порог 3 был поставлен в расчёте, что сервер
	// отвечает pong'ом на каждый keepalive, а он отвечает НЕ ВСЕГДА — за 12 с при 24 отправленных
	// служебных пакетах приходило 0-1. Недостижимый порог осудил все 16 воркеров разом, транспорт
	// ушёл в пере-спавн, и туннель встал целиком (Σtx=0 Σrx=0, 100% отказов дозвона).
	proofPackets = 1
	// warmTick — пока путь не доказан, keepalive идёт часто: он же и есть то, что открывает
	// permission/ChannelBind у TURN. После доказательства — авторский keepaliveInterval.
	warmTick      = 500 * time.Millisecond
	proveTimeout  = 12 * time.Second // не доказал за это — аллокация негодна, пере-дозвон
	deafMinTx     = 20               // отправлено при остановившемся rx, прежде чем судить доказавшего
	deafCheckTick = 2 * time.Second  // как часто смотреть
	deafMaxRedial = 3                // пере-дозвонов одному воркеру за спавн транспорта
	// deafMaxShare — доля воркеров, которую гейт вправе осудить за один тик. Без неё одна общая
	// неприятность (сервер замолчал, сеть моргнула) выносит приговор ВСЕМ сразу — ровно это и
	// случилось при недостижимом пороге выше. Гейт лечит ОТДЕЛЬНЫЕ аллокации, а не транспорт.
	deafMaxShare = 0.25
)

// workerProven — путь воркера доказан: по нему пришло не меньше proofPackets пакетов.
func workerProven(sessionID int) bool {
	return workerCountersFor(sessionID).rx.Load() >= proofPackets
}

type workerSession struct {
	cancel context.CancelFunc
	born   time.Time
	lastRx int64
	lastTx int64
}

var (
	deafMu       sync.Mutex
	deafSessions = map[int]*workerSession{}
	deafRedials  = map[int]int{}
	deafOnce     sync.Once
)

// registerWorkerSession — воркер поднял сессию: запоминаем, чем отменить именно ЕЁ, и обнуляем его
// счётчики (ID переживает пере-дозвон, цифры прошлой аллокации к новой не относятся).
func registerWorkerSession(sessionID int, cancel context.CancelFunc) {
	workerStatsMu.Lock()
	delete(workerStats, sessionID)
	workerStatsMu.Unlock()

	deafMu.Lock()
	deafSessions[sessionID] = &workerSession{cancel: cancel, born: time.Now()}
	deafMu.Unlock()

	deafOnce.Do(func() { go deafWatchLoop() })
}

func unregisterWorkerSession(sessionID int) {
	deafMu.Lock()
	delete(deafSessions, sessionID)
	deafMu.Unlock()
}

// deafWatchLoop — единственная точка, принимающая решения по счётчикам. Живёт на весь процесс:
// пере-спавн транспорта пересоздаёт воркеров с теми же ID, а не watcher.
func deafWatchLoop() {
	t := time.NewTicker(deafCheckTick)
	defer t.Stop()
	for range t.C {
		type verdict struct {
			id     int
			reason string
		}
		var doomed []verdict
		var peersRx int64
		now := time.Now()

		// Снимок счётчиков берём ДО deafMu: иначе получается вложенность deafMu → workerStatsMu,
		// а обратный порядок стоит в registerWorkerSession — класс ABBA, даже если сегодня он там
		// разведён по времени.
		snap := map[int][2]int64{}
		workerStatsMu.RLock()
		for id, c := range workerStats {
			snap[id] = [2]int64{c.tx.Load(), c.rx.Load()}
		}
		workerStatsMu.RUnlock()

		deafMu.Lock()
		for id, s := range deafSessions {
			tx, rx := snap[id][0], snap[id][1]
			grewRx := rx > s.lastRx
			switch {
			case rx < proofPackets && now.Sub(s.born) >= proveTimeout:
				doomed = append(doomed, verdict{id, fmt.Sprintf("return path never proved in %s (tx=%d rx=%d, need %d)", proveTimeout, tx, rx, proofPackets)})
			case rx > 0 && !grewRx && tx-s.lastTx >= deafMinTx:
				doomed = append(doomed, verdict{id, fmt.Sprintf("went one-way (tx +%d, rx frozen at %d)", tx-s.lastTx, rx)})
			}
			if grewRx {
				peersRx += rx - s.lastRx
				s.lastRx = rx
				s.lastTx = tx
			}
		}
		deafMu.Unlock()

		deafMu.Lock()
		total := len(deafSessions)
		deafMu.Unlock()
		if len(doomed) == 0 || peersRx == 0 {
			continue // либо судить некого, либо не принимает НИКТО — это не про воркера (см. ⚠ выше)
		}
		if limit := int(float64(total) * deafMaxShare); len(doomed) > limit {
			log.Printf("[DEAF] %d of %d workers look one-way at once - that is the transport, not the allocations; skipping",
				len(doomed), total)
			continue
		}
		for _, v := range doomed {
			deafMu.Lock()
			s, ok := deafSessions[v.id]
			used := deafRedials[v.id]
			var cancel context.CancelFunc
			if ok && used < deafMaxRedial {
				deafRedials[v.id] = used + 1
				cancel = s.cancel
				delete(deafSessions, v.id) // повторно не дёргать, пока не встанет заново
			}
			deafMu.Unlock()
			if cancel == nil {
				continue
			}
			log.Printf("[WORKER #%d] [DEAF] %s while peers received %d - redialing (%d/%d)",
				v.id, v.reason, peersRx, used+1, deafMaxRedial)
			cancel()
		}
	}
}

// resetDeafState — вместе с resetWorkerStats на пере-спавне транспорта: бюджет пере-дозвонов
// относится к КОНКРЕТНОМУ спавну, иначе после пары хендоверов он исчерпан и гейт мёртв.
func resetDeafState() {
	deafMu.Lock()
	deafRedials = map[int]int{}
	deafMu.Unlock()
}

// workerHealthLine — компактный снимок: `#id:tx/rx` по возрастанию id + суммы. Пустая строка, если
// воркеров ещё нет (транспорт не поднят) — вызывающий такую строку не логирует.
func workerHealthLine() string {
	workerStatsMu.RLock()
	ids := make([]int, 0, len(workerStats))
	for id := range workerStats {
		ids = append(ids, id)
	}
	type snap struct{ id int; tx, rx int64 }
	snaps := make([]snap, 0, len(ids))
	var sumTx, sumRx int64
	for _, id := range ids {
		c := workerStats[id]
		tx, rx := c.tx.Load(), c.rx.Load()
		sumTx += tx
		sumRx += rx
		snaps = append(snaps, snap{id, tx, rx})
	}
	workerStatsMu.RUnlock()
	if len(snaps) == 0 {
		return ""
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].id < snaps[j].id })
	out := ""
	silent := 0
	for _, s := range snaps {
		if s.tx > 0 && s.rx == 0 {
			silent++
		}
		out += fmt.Sprintf(" #%d:%d/%d", s.id, s.tx, s.rx)
	}
	return fmt.Sprintf("Σtx=%d Σrx=%d workers=%d silent(tx>0,rx=0)=%d | %s |%s",
		sumTx, sumRx, len(snaps), silent, dialWindowLine(), out)
}

// ── Скользящее окно исходов дозвона ───────────────────────────────────────────────────────────────
//
// Зачем отдельно от PERFSPLIT: тот пишет КАЖДЫЙ дозвон, и деградацию по нему видно только постфактум,
// сводя лог руками. Здесь — та же информация в агрегате, рядом с пер-воркерными цифрами, чтобы в
// момент жалобы «виснет» одна строка отвечала: транспорт деградирует или проблема выше.
//
// Замер (один цикл, телефон): на осевшем транспорте провалов 0.0%, медленных (>=1с) 2-6%;
// к 15-20 минутам жизни — 2.2% провалов и 14% медленных; полный перезапуск слота вернул 93-107мс.
// Но окно СРАЗУ после re-spawn'а дало 22% провалов — то есть сам re-spawn не бесплатен, и детектор,
// дёргающий его по деградации, рискует лечить хуже болезни. Поэтому здесь ТОЛЬКО счётчик: порог для
// автоматики выбирается по нескольким реальным циклам, а не по одному.
const dialWindowSize = 30

var (
	dialWinMu   sync.Mutex
	dialWinMs   [dialWindowSize]float64 // 0 = слот пуст
	dialWinFail [dialWindowSize]bool
	dialWinPos  int
	dialWinLen  int
)

// recordDialOutcome — исход одного дозвона через туннель. `failed` — дозвон не состоялся вовсе
// (дедлайн/ошибка), в отличие от просто медленного.
func recordDialOutcome(elapsedMs float64, failed bool) {
	dialWinMu.Lock()
	dialWinMs[dialWinPos] = elapsedMs
	dialWinFail[dialWinPos] = failed
	dialWinPos = (dialWinPos + 1) % dialWindowSize
	if dialWinLen < dialWindowSize {
		dialWinLen++
	}
	dialWinMu.Unlock()
}

func dialWindowLine() string {
	dialWinMu.Lock()
	n := dialWinLen
	var slow, fail int
	for i := 0; i < n; i++ {
		if dialWinFail[i] {
			fail++
		} else if dialWinMs[i] >= 1000 {
			slow++
		}
	}
	dialWinMu.Unlock()
	if n == 0 {
		return "dials: no data"
	}
	return fmt.Sprintf("dials(%d): fails=%d(%.0f%%) slow>=1s=%d(%.0f%%)",
		n, fail, float64(fail)*100/float64(n), slow, float64(slow)*100/float64(n))
}
