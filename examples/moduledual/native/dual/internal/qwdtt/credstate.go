// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// credstate.go — antinet: §4.2 контракта (MODULE_API.md), восстановление состояния.
//
// ЗАЧЕМ. qWDTT — образец паттерна «полное восстановление»: получить TURN-креды стоит целой
// VK-цепочки (авторизация, автоклик, перехват turn_server, при неудаче — капча с участием юзера).
// Терять их на каждом рестарте слота/хендовере — значит гонять юзера через капчу на ровном месте.
// На `resume`/`handover` с валидными кредами вся цепочка пропускается целиком.
//
// ГДЕ ХРАНИТСЯ И ПОЧЕМУ НЕ НА ДИСКЕ. §4.2 говорит «персистить», §3 категорически запрещает секретам
// касаться диска — а `username`/`password` TURN это ровно секреты. На Android profileDir приватен
// (0600 внутри /data/data), но ЭТОТ ЖЕ код собирается и под Desktop, где дерево данных НАМЕРЕННО
// world-readable (ShareTreeAllUsers) — там файл с кредами был бы настоящей утечкой, тем же классом,
// что вычищенный из проекта client.cfg.
//
// Разрешение: креды уезжают ХОСТУ непрозрачным блобом (`STATE_SAVE|<base64>` в stdout — тот же
// канал, что PROGRESS|/ACTION_REQUIRED|), хост держит его В ПАМЯТИ и возвращает при следующем
// старте (`MODULE_STATE=` в конфиге). Хост блоб не разбирает и не толкует (§4.1 п.4) — для него это
// строка. Диска блоб не касается ни на одной платформе.
//
// ЧТО ЭТО ПОКРЫВАЕТ. Все реальные сценарии, ради которых §4.2 писался: смерть слота, хендовер,
// обновление модуля, ручная остановка туннеля — во всех них процесс хоста ЖИВ, блоб на месте.
// НЕ переживает полный force-stop приложения: там будет честный `cold` со всей VK-цепочкой. Это
// осознанный размен — секрет на диске хуже одной лишней авторизации после того, как юзер сам убил
// приложение.
//
// СРОК ГОДНОСТИ — наш, не хоста (§4.1 п.4), и берётся ИЗ САМИХ КРЕДОВ.
//
// VK выдаёт TURN-username вида `<unix-expiry>:<id>` (RFC 5766 §10.2). Живой замер: наш старый
// in-memory горизонт был 9 минут от авторизации, а VK-expiry из username — ещё ~8 часов.
// Хост-блоб (§4.2) уже жил по VK-сроку; in-memory кэш догонял его через credsCacheExpiresAt —
// иначе живой процесс каждые ~9 минут снова гнал VK-цепочку и капчу, хотя TURN-креды ещё валидны.
//
// Fallback на короткий credentialLifetime — только если username не разобрался. Плюс гигиенический
// потолок по возрасту блоба (`AcquiredUnix`). Валидность в конечном счёте решает TURN-сервер:
// если креды всё же не приняты, `group.go::refreshCreds` переполучает их реактивно.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dual-antinet/internal/vk"
)

// ── Таймаут дозвона SOCKS5 до цели (см. socks5.go) ──────────────────────────────────────────────
//
// Живёт здесь, а не в socks5.go, чтобы не тащить туда зависимость от разбора конфига: значение
// выставляет helper на старте, потребитель просто читает. Дефолт 10с — обоснование в socks5.go на
// месте использования.
var socksDialTimeoutSec int32 = 10

func setSocksDialTimeoutSec(v int) {
	if v > 0 {
		atomic.StoreInt32(&socksDialTimeoutSec, int32(v))
	}
}

func socksDialTimeout() time.Duration {
	return time.Duration(atomic.LoadInt32(&socksDialTimeoutSec)) * time.Second
}

// persistedCreds — форма блоба. Ссылку целиком НЕ кладём даже в непрозрачный блоб: в ней
// апстримный секрет (`pass=`), а для задачи «заметить, что ссылка стала другой» достаточно
// необратимого отпечатка.
type persistedCreds struct {
	LinkFP       string   `json:"l"` // отпечаток ССЫЛКИ МОДУЛЯ (cfg.Link) — «этот ли конфиг»
	HashFP       string   `json:"h"` // отпечаток VK-хеша, под который выданы ИМЕННО эти креды
	Username     string   `json:"u"`
	Password     string   `json:"p"`
	ServerAddrs  []string `json:"a"`
	ExpiresUnix  int64    `json:"e"`
	AcquiredUnix int64    `json:"t"` // когда креды реально получены (для гигиенического потолка)
}

// ⚠ ДВА РАЗНЫХ отпечатка, и путать их нельзя — на этом §4.2 не работал ни разу с момента написания
// (найдено живым прогоном): `SaveCredsToHost` получает `TurnCredentials.Link`, а это НЕ
// ссылка модуля, а КОНКРЕТНЫЙ VK-хеш звонка (`group.go:67` → `GetCreds(ctx, hash, …)` — у конфига
// их может быть несколько). `LoadRestoredCreds` же сравнивал с отпечатком `cfg.Link` — полной
// ссылки модуля. Две структурно разные строки: сравнение не могло совпасть НИКОГДА, и модуль
// каждый раз честно писал «блоб от ДРУГОЙ ссылки», уходя в полную VK-цепочку.
//
// Теперь в блобе оба: `l` (ссылка модуля — «тот ли это конфиг», сравнивает LoadRestoredCreds) и
// `h` (VK-хеш — «под тот ли звонок выданы креды», сравнивает takeRestoredCreds). Восстановление
// применяется только когда совпали ОБА.
var stateModuleLinkFP atomic.Value // string; ставится один раз на старте из realMain

// SetStateLinkFP — запомнить отпечаток ссылки МОДУЛЯ для §4.2-блоба. Зовётся из realMain до подъёма
// группы: `SaveCredsToHost` вызывается из глубины creds.go, где ссылки модуля в области видимости нет.
func SetStateLinkFP(moduleLink string) {
	stateModuleLinkFP.Store(credsLinkFingerprint(moduleLink))
}

func stateLinkFP() string {
	if v, ok := stateModuleLinkFP.Load().(string); ok {
		return v
	}
	return ""
}

const (
	// Запас к VK-шному expiry: не пытаться поднять сессию на кредах, которым осталось меньше.
	vkCredExpirySafetyMargin = 2 * time.Minute
	// Гигиенический потолок возраста блоба. НЕ утверждение о годности (её решает TURN-сервер,
	// см. шапку файла) — только «не пытаться поднимать заведомо древний секрет и не держать его
	// в памяти хоста бесконечно». Реальная годность VK-креда ≈ 8 ч, так что потолок её не режет.
	restoredCredsMaxAge = 12 * time.Hour
)

// vkTurnCredExpiry — expiry из самого TURN-username'а VK: формат `<unix-expiry>:<id>`
// (RFC 5766 §10.2 ephemeral credentials). Это НАСТОЯЩИЙ серверный срок, в отличие от нашей
// кэш-политики. Не разобралось — (zero, false), вызывающий падает на консервативный fallback.
func vkTurnCredExpiry(username string) (time.Time, bool) {
	i := strings.IndexByte(username, ':')
	if i <= 0 {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(username[:i], 10, 64)
	if err != nil || sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// credsCacheExpiresAt — горизонт in-memory кэша TURN-кредов (и lastCredsByLink, и restored).
//
// Раньше всегда ставили `now + credentialLifetime − запас` (~9 мин). Хост уже переживал
// resume по VK-expiry (~8 ч), а живой процесс каждые ~9 минут снова шёл в getAnonymousToken
// → капча / ACTION_REQUIRED на ровном месте. Берём тот же VK-expiry − запас; fallback —
// прежние 9 минут, если username не разобрался.
func credsCacheExpiresAt(username string) time.Time {
	fallback := time.Now().Add(credentialLifetime - cacheSafetyMargin)
	vkExp, ok := vkTurnCredExpiry(username)
	if !ok {
		return fallback
	}
	exp := vkExp.Add(-vkCredExpirySafetyMargin)
	if !time.Now().Before(exp) {
		return fallback
	}
	return exp
}

func credsLinkFingerprint(link string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(link)))
	return strconv.FormatUint(h.Sum64(), 16)
}

var (
	restoredMu     sync.Mutex
	restoredCreds  *TurnCredentials // непусто = хост вернул годные креды прошлой сессии
	restoredHashFP string           // под какой VK-хеш они выданы (см. коммент к persistedCreds)
)

// restoredCredsUnproven — сессия ИДЁТ НА ВОССТАНОВЛЕННЫХ кредах, и ни одна TURN-аллокация по ним
// ещё не удалась.
//
// Зачем отдельное знание, а не «просто ретраить»: срок годности в блобе (§4.2) доказывает, что
// креды не ПРОТУХЛИ, но не доказывает, что по ним есть СВОБОДНЫЙ слот. VK держит на звонок
// считанные аллокации, и наша же прошлая сессия их занимает ещё какое-то время после разрыва.
// Поэтому первый же `error 486` НА ВОССТАНОВЛЕННЫХ кредах — это не «подождём, слот освободится»,
// а «блоб описывает занятую аллокацию»: лечится он ТОЛЬКО повторным прогоном VK-цепочки, которую
// восстановление и пропустило. Без этого различия воркеры ждут 30-60 с и ретраят теми же кредами
// бесконечно, а модуль не поднимается вовсе (живой лог 2026-09-11 12:17/12:18: девять воркеров,
// `486` у каждого, две волны relayWatchdog, ноль трафика).
//
// Снимается ФАКТОМ, а не таймером: успешной аллокацией (session.go, сразу после `Relay:`) либо
// свежими кредами из `refreshCreds`. Пока факта нет — креды остаются неподтверждёнными.
var restoredCredsUnproven atomic.Bool

// NoteTurnAllocationOK — TURN-аллокация удалась: креды в обороте рабочие, чем бы они ни были.
func NoteTurnAllocationOK() { restoredCredsUnproven.Store(false) }

// NoteFreshCredsObtained — VK-цепочка отработала заново: восстановленных кредов в обороте больше нет.
func NoteFreshCredsObtained() { restoredCredsUnproven.Store(false) }

// RestoredCredsUnproven — идём ли мы на восстановленных кредах, ещё ничем не подтверждённых.
func RestoredCredsUnproven() bool { return restoredCredsUnproven.Load() }

// LoadRestoredCreds — разобрать MODULE_STATE от хоста на старте. Отказ на любой неоднозначности
// (нет блоба, битый base64/JSON, сменилась ссылка, истёк срок, START_REASON=cold) — консервативно:
// лишняя авторизация дешевле, чем сессия на протухших кредах.
func LoadRestoredCreds(blobB64, link, startReason string) {
	// ⚠ КАЖДЫЙ отказ логируется. Прежняя редакция молча возвращалась на ПЯТИ ветках из шести, и
	// живое расследование («почему после kill -9 пошла полная VK-цепочка?») свелось к
	// ручному декодированию блобов из лога и сверке отпечатков — ровно потому, что модуль не
	// сказал ни слова о том, что и почему отклонил.
	if startReason == "cold" {
		log.Printf("[VK Auth] MODULE_STATE: START_REASON=cold - restore not applied")
		return
	}
	if strings.TrimSpace(blobB64) == "" {
		log.Printf("[VK Auth] MODULE_STATE: host did not return a blob (START_REASON=%s) - full chain", startReason)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blobB64))
	if err != nil {
		log.Printf("[VK Auth] MODULE_STATE: broken base64 (%v) - full chain", err)
		return
	}
	var pc persistedCreds
	if err := json.Unmarshal(raw, &pc); err != nil {
		log.Printf("[VK Auth] MODULE_STATE: broken JSON (%v) - full chain", err)
		return
	}
	if pc.LinkFP != credsLinkFingerprint(link) {
		log.Printf("[VK Auth] MODULE_STATE: blob from a DIFFERENT link (%s != %s) - full chain",
			pc.LinkFP, credsLinkFingerprint(link))
		return
	}
	if len(pc.ServerAddrs) == 0 {
		log.Printf("[VK Auth] MODULE_STATE: no TURN addresses in the blob - full chain")
		return
	}
	// Гигиенический потолок по возрасту (см. шапку). Старые блобы без `t` его не проходят и не
	// проваливают — поле просто отсутствует, проверка пропускается.
	if pc.AcquiredUnix > 0 {
		age := time.Since(time.Unix(pc.AcquiredUnix, 0))
		if age > restoredCredsMaxAge {
			log.Printf("[VK Auth] MODULE_STATE: blob is %s old (cap %s) - full chain",
				age.Truncate(time.Second), restoredCredsMaxAge)
			return
		}
	}
	exp := time.Unix(pc.ExpiresUnix, 0)
	if !time.Now().Before(exp) {
		log.Printf("[VK Auth] MODULE_STATE: previous session's creds expired (%s ago) - full chain",
			time.Since(exp).Truncate(time.Second))
		return
	}
	// ExpiresAt — тот же горизонт, что у свежего фетча: VK-expiry − запас (см. credsCacheExpiresAt).
	// Раньше сюда клали ~9 мин и после takeRestoredCreds кэш снова требовал полную VK-цепочку.
	cacheExp := credsCacheExpiresAt(pc.Username)
	if cacheExp.After(exp) {
		cacheExp = exp
	}
	restoredMu.Lock()
	restoredCreds = &TurnCredentials{
		Username:    pc.Username,
		Password:    pc.Password,
		ServerAddrs: pc.ServerAddrs,
		ExpiresAt:   cacheExp,
		// Link здесь — то, чем оперирует creds.go: VK-хеш звонка. Самой строки хеша у нас нет
		// (в блобе только отпечаток), поэтому сверка идёт по нему — см. takeRestoredCreds.
	}
	restoredHashFP = pc.HashFP
	restoredMu.Unlock()
	// RESUME| — тот же класс маркера, что у echo: восстановление наблюдаемо в логе, а не молчаливо.
	fmt.Printf("%s RESUME|TURN creds restored (START_REASON=%s, valid for %s more, urls=%d) — VK chain skipped\n",
		time.Now().Format("15:04:05.000000"), startReason,
		time.Until(exp).Truncate(time.Second), len(pc.ServerAddrs))
	_ = os.Stdout.Sync()
}

// publishTurnSeed mirrors restored/fresh creds into the dual-wide vk cache (csqtt can seed rust).
func publishTurnSeed(hash string, c TurnCredentials, expUnix int64) {
	if hash == "" {
		return
	}
	vk.PutTurn(vk.TurnSeed{
		Hash:        hash,
		Username:    c.Username,
		Password:    c.Password,
		ServerAddrs: append([]string(nil), c.ServerAddrs...),
		ExpiresUnix: expUnix,
	})
}

// takeRestoredCreds — забрать восстановленные креды под конкретную ссылку. Одноразово: после
// первого использования они уже лежат в обычном stream-кэше, и второй раз подменять его не надо.
func takeRestoredCreds(link string) (TurnCredentials, bool) {
	restoredMu.Lock()
	defer restoredMu.Unlock()
	// `link` здесь — VK-хеш звонка (так его зовёт creds.go), сверяем по отпечатку из блоба:
	// у конфига хешей может быть несколько, и подставлять креды чужого звонка нельзя.
	if restoredCreds == nil || restoredHashFP == "" ||
		restoredHashFP != credsLinkFingerprint(link) ||
		!time.Now().Before(restoredCreds.ExpiresAt) {
		return TurnCredentials{}, false
	}
	c := *restoredCreds
	c.Link = link // теперь известна реальная строка хеша — кладём её в in-memory кэш как обычно
	restoredCreds = nil
	restoredHashFP = ""
	// С этой секунды и до первой удачной аллокации сессия идёт на НЕПОДТВЕРЖДЁННЫХ кредах —
	// см. restoredCredsUnproven. Ставится ЗДЕСЬ, в единственной точке выдачи восстановленных
	// кредов: у потребителя (group.go) знания «откуда взялись креды» нет и быть не должно.
	restoredCredsUnproven.Store(true)
	log.Printf("[VK Auth] MODULE_STATE: creds applied to the call (hash-fp %s) - VK chain skipped",
		credsLinkFingerprint(link))
	publishTurnSeed(link, c, c.ExpiresAt.Unix())
	return c, true
}

// SaveCredsToHost — отдать креды хосту. Зовётся на КАЖДОМ успешном получении (первичном и на
// refresh'е), чтобы блоб у хоста не отставал от реальности.
func SaveCredsToHost(c TurnCredentials) {
	if c.Username == "" || len(c.ServerAddrs) == 0 {
		return
	}
	// Годность блоба = VK-expiry − запас (тот же горизонт, что in-memory кэш после
	// credsCacheExpiresAt). Раньше ExpiresAt был ~9 мин, а сюда подставляли VK-срок отдельно.
	expUnix := credsCacheExpiresAt(c.Username).Unix()
	body, err := json.Marshal(persistedCreds{
		LinkFP:       stateLinkFP(),                // ссылка МОДУЛЯ (см. развёрнутый коммент выше)
		HashFP:       credsLinkFingerprint(c.Link), // c.Link здесь = VK-хеш звонка, а не ссылка
		Username:     c.Username,
		Password:     c.Password,
		ServerAddrs:  c.ServerAddrs,
		ExpiresUnix:  expUnix,
		AcquiredUnix: time.Now().Unix(),
	})
	if err != nil {
		return
	}
	publishTurnSeed(c.Link, c, expUnix)
	fmt.Printf("STATE_SAVE|%s\n", base64.StdEncoding.EncodeToString(body))
	_ = os.Stdout.Sync()
}
