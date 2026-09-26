// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// helper.go — точка входа subprocess-helper'а qWDTT для AntiNet (см. ../../README.md, MODULE_API.md).
// Оркестрация: PDEATHSIG → config → protect → qWDTT-транспорт (захват WG-конфига) → wireguard-go
// netstack (peer→127.0.0.1:localPort) → SOCKS5 поверх → socks.port. Прогресс-строки визуального лога
// qWDTT уходят тостами в AntiNet (PROGRESS|-строки в stdout, см. ModuleManager).
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dual-antinet/internal/vk"
)

// Платформенного кода в дереве модуля НЕТ: точки входа даёт канон shared/entry, разговор с хостом —
// shared/hostproto, примитивы жизненного цикла (PDEATHSIG, oom_score_adj, десктопный stdin-читатель
// событий) — shared/lifecycle, а protect-хук `dialControl` приезжает под ОДНИМ именем с обеих
// сторон: shared/protect на Android (SCM_RIGHTS) и shared/offtun на десктопе (bind к физ-адаптеру).
// См. MODULE_API §4.

type helperConfig struct {
	Peer           string `json:"peer"`
	Hashes         string `json:"hashes"`
	Workers        int    `json:"workers"`
	Password       string `json:"password"`
	LocalPort      int    `json:"localPort"`
	SocksPort      int    `json:"socksPort"`
	SocksUser      string `json:"socksUser"`
	SocksPass      string `json:"socksPass"`
	RelayWindowSec int    `json:"relayWindowSec"` // окно детекта обрыва релея (relayWatchdog); 0 = дефолт
	CaptchaMode    string `json:"captchaMode"`    // SETTING_captchaMode (карточка «Модули»): auto/rjs/wv; "" = auto
	VkAuthMode     string `json:"vkAuthMode"`     // SETTING_vkAuthMode: anonymous/account; "" = anonymous (см. vk_account.go)
	VkAnonPath     string `json:"vkAnonPath"`     // SETTING_vkAnonPath: vkcalls/legacy; "" = vkcalls (см. vk_account.go)
	HashMode       string `json:"hashMode"`       // SETTING_hashMode: manual/auto_api/auto_js; "" = manual
	DnsPreset      string `json:"dnsPreset"`      // SETTING_dnsPreset: yandex/cloudflare/google/doh-cloudflare/doh-google; "" = yandex
	// WorkersSource — откуда взяли cfg.Workers (для лога): "setting" | "default".
	WorkersSource string `json:"-"`
	// ─── Транспортные режимы, добавленные автором в 1.4.3 (см. TurnParams в group.go) ───
	// ConnMode повторяет токены апстрима один-в-один (`vpn`/`rawtun`), чтобы настройка читалась
	// так же, как флаг `-mode` у автора. Третий его токен, `socks`, у нас не настройка и не может
	// ею быть: наш порт ВСЕГДА отдаёт хосту SOCKS5 (sing-box цепляет socks-outbound на наш порт),
	// то есть постоянно находится в этом режиме — выбирать тут нечего.
	ConnMode string `json:"connMode"` // SETTING_connMode: vpn/rawtun; "" = vpn
	NoDTLS   bool   `json:"noDtls"`   // SETTING_noDtls: RTP-obfs AEAD прямо поверх TURN, без DTLS
	TurnTCP  bool   `json:"turnTcp"`  // SETTING_turnTcp: TURN по TCP (обход UDP-душения провайдером)
	// Порты ДРУГИХ слушателей сервера. Из ссылки они не выводятся — в ней есть только DTLS- и
	// WG-порт, — а без них `rawtun`/`noDtls` недостижимы в принципе: запрос уходил бы в DTLS-порт,
	// который этих команд не знает. 0 → авторский дефолт (56002 / 56003).
	DirectPort int `json:"directPort"` // SETTING_directPort: порт сервера `-listen-direct`
	RawPort    int `json:"rawPort"`    // SETTING_rawPort:    порт сервера `-listen-raw`
	// antinet §4 — контракт восстановления состояния (credstate.go).
	DialTimeoutSec int    `json:"dialTimeoutSec"` // потолок дозвона SOCKS5 до цели; 0 = дефолт 10с
	StartReason    string `json:"startReason"`    // cold | resume | handover; "" (старый хост) = cold
	ModuleState    string `json:"moduleState"`    // base64-блоб НАШЕГО состояния прошлой сессии, от хоста
	AppLang        string `json:"appLang"`        // APP_LANG (MODULE_API §2.9) — эффективный язык AntiNet, см. qwS ниже
	// ⚠ Поля под generic-ключ `DEVICE_ID` здесь НЕТ намеренно: модуль выводит идентичность
	// устройства сам (`deviceIDFor`, run.go). Неиспользуемое поле в конфиге — двойник, который
	// однажды прочитают по ошибке.
	// Link — СЫРАЯ ссылка как её прислал хост. Нужна ровно для отпечатка в credstate.go («та же
	// ли это ссылка, что при прошлом получении кредов»); в остальном работаем с разобранными
	// Peer/Hashes/Password. На диск не попадает: §3.
	Link string `json:"-"`
}

// parseConfig — ЕДИНЫЙ парсер коннект-конфига для ОБЕИХ платформ: дефолты + декод сырой
// qwdtt://-ссылки из KEY=VALUE-конфига (хост — и Android ModuleManager, и Desktop — пишет
// LISTEN_PORT=…\nSOCKS_USER=…\nSOCKS_PASS=…\nLINK=<сырая ссылка>). Мирор Kotlin
// SubprocessEntry (parseUri + peerWithDtlsPort): DEFAULT_DTLS_PORT=56000, DEFAULT_LOCAL_PORT=9000,
// DEFAULT_WORKERS=16; peer без ":" → peer:56000; socksPort/User/Pass — из LISTEN_PORT/SOCKS_USER/SOCKS_PASS.
const (
	defaultDtlsPort = 56000
	// ⚠ У сервера ТРИ РАЗНЫХ слушателя, и порт зависит от выбранного транспорта, а не только от
	// ссылки: `-listen` (DTLS, 56000, включён всегда), `-listen-direct` (RTP-obfs AEAD без DTLS) и
	// `-listen-raw` (сырой IP без WireGuard) — последние два по умолчанию у сервера ВЫКЛЮЧЕНЫ.
	// Обычный DTLS-слушатель знает только GETCONF:/AUTH: и на GETCONF_RAW: не отвечает НИЧЕМ.
	//
	// Значения — авторские дефолты из его же приложения (SettingsStore: serverDirectPort=56002,
	// serverRawPort=56003); там они и подставляются подменой порта пира при включении режима.
	// Ровно этой подмены у нас не было: настройка меняла протокол, а стучались по-прежнему в
	// DTLS-порт — режим не мог заработать ни при какой конфигурации сервера.
	defaultDirectPort = 56002
	defaultRawPort    = 56003
	defaultLocalPort  = 9000
	// Дефолт при отсутствии SETTING_workers — авторский дефолт CLI (`flag.Int("n", 9, …)`).
	// Число НЕ обязано быть кратным `workersPerGroup`: разбивку делает runTransport ceiling-делением
	// с клампингом последней группы, как у автора.
	defaultWorkers = 9
	// maxWorkers — наш потолок, которого у автора нет и не может быть: у него число воркеров
	// приходит флагом CLI из его же приложения, у нас — из СКАЧАННОЙ ссылки. Без потолка ссылка
	// заказывает произвольное число TURN-аллокаций у VK-аккаунта юзера.
	maxWorkers = 108
)

// summarizeQwdtt — мирор Android SubprocessEntry.summarize (сабкоманда summarize, общая для платформ): qwdtt://-ссылка →
// (имя=q("name")?:peer, сервер=peer). Для UI-карточки. peer — СЫРОЙ (без DTLS-порта, как c.peer Android).
func summarizeQwdtt(link string) (name, server string) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", ""
	}
	q := u.Query()
	qget := func(keys ...string) string {
		for _, k := range keys {
			if v := q.Get(k); v != "" {
				return v
			}
		}
		return ""
	}
	peer := qget("peer")
	if peer == "" {
		return "", ""
	}
	name = qget("name")
	if name == "" {
		name = peer
	}
	return name, peer
}

// qwdttCfg + normalizeQwdtt — мирор SubprocessEntry.{Cfg, normalizeImport, parseAny, parseWdttLegacy,
// parseJson, toLink}: НЕ-link форма (legacy wdtt://, JSON, base64-JSON) → канонический qwdtt://. Уже
// qwdtt:// (или не наш формат) → "". Для импорта не-link форм (Android/Desktop форкают `normalize <raw>`).
type qwdttCfg struct {
	name, peer, hashes, password string
	workers, port                int
}

func (c *qwdttCfg) toLink() string {
	e := url.QueryEscape
	return "qwdtt://config?name=" + e(c.name) + "&peer=" + e(c.peer) + "&hashes=" + e(c.hashes) +
		"&workers=" + strconv.Itoa(c.workers) + "&port=" + strconv.Itoa(c.port) + "&pass=" + e(c.password)
}

func normalizeQwdtt(raw string) string {
	r := strings.TrimSpace(raw)
	if r == "" {
		return ""
	}
	low := strings.ToLower(r)
	if strings.HasPrefix(low, "qwdtt://") {
		return "" // уже канон — AntiNet сам обработает реестром схем
	}
	var c *qwdttCfg
	if strings.HasPrefix(low, "wdtt://") {
		c = parseWdttLegacy(r)
	} else if obj := jsonOrBase64(r); obj != nil {
		c = parseJsonQwdtt(obj)
	}
	if c == nil {
		return ""
	}
	return c.toLink()
}

func parseWdttLegacy(raw string) *qwdttCfg {
	parts := strings.Split(raw[len("wdtt://"):], ":")
	if len(parts) < 6 {
		return nil
	}
	// wdtt://<server_ip>:<dtls_port>:<wg_port>:<local_port>:<password>:<vk_hash> — формат задан
	// автором (его `ProfilesTab.kt::parseQrConfig`, он же генератор в `AdminTab.kt`/`database_bot.go`).
	ip := strings.TrimSpace(parts[0])
	hash := strings.TrimSpace(strings.Join(parts[5:], ":"))
	if ip == "" || hash == "" {
		return nil
	}
	// ⚠ `parts[1]` — DTLS-порт СЕРВЕРА, и он часть адреса пира, а не украшение: автор кладёт в
	// профиль ровно `ip:dtlsPort`. Раньше он здесь молча терялся, в ссылку уходил голый `ip`, и
	// `parseHelperConfig` дописывал `defaultDtlsPort`. Совпало бы это с реальным портом или нет —
	// решала случайность: у сервера на 56000 (нашем дефолте) всё работало, у любого другого
	// конфиг импортировался «успешно» и не подключался никогда.
	if p, e := strconv.Atoi(strings.TrimSpace(parts[1])); e == nil && p > 0 && p < 65536 {
		ip = ip + ":" + strconv.Itoa(p)
	}
	// 0 = эфемерный bind — тот же дефолт, что и у qwdtt://-парсера выше (см. его комментарий
	// про вторую одновременную сессию). Явное значение из ссылки уважается.
	port := 0
	if p, e := strconv.Atoi(strings.TrimSpace(parts[3])); e == nil && p > 0 {
		port = p
	}
	return &qwdttCfg{name: "WDTT " + ip, peer: ip, hashes: hash, workers: defaultWorkers, port: port, password: parts[4]}
}

func parseJsonQwdtt(j map[string]interface{}) *qwdttCfg {
	js := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := j[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	ji := func(def int, keys ...string) int {
		for _, k := range keys {
			if v, ok := j[k]; ok {
				switch n := v.(type) {
				case float64:
					return int(n)
				case string:
					if x, e := strconv.Atoi(strings.TrimSpace(n)); e == nil {
						return x
					}
				}
			}
		}
		return def
	}
	peer := js("peer")
	hashes := js("hashes", "vkHashes")
	if peer == "" || hashes == "" {
		return nil
	}
	name := js("name")
	if name == "" {
		name = peer
	}
	// port: 0 = эфемерный bind — тот же дефолт, что у двух парсеров выше (разбор — там же).
	return &qwdttCfg{name: name, peer: peer, hashes: hashes,
		workers: ji(defaultWorkers, "workers", "workersPerHash"), port: ji(0, "port", "listenPort"),
		password: js("password", "pass")}
}

// jsonOrBase64 — мирор asJsonOrNull ?: base64AsJsonOrNull: сырьё как JSON, либо base64(url/std)→JSON.
func jsonOrBase64(raw string) map[string]interface{} {
	try := func(s string) map[string]interface{} {
		var m map[string]interface{}
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
		return nil
	}
	if m := try(raw); m != nil {
		return m
	}
	s := strings.TrimSpace(raw)
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	if b, e := base64.URLEncoding.DecodeString(s); e == nil {
		if m := try(string(b)); m != nil {
			return m
		}
	}
	if b, e := base64.StdEncoding.DecodeString(s); e == nil {
		if m := try(string(b)); m != nil {
			return m
		}
	}
	return nil
}

// normalizeConnMode — токены режима транспорта, один-в-один с флагом `-mode` апстрима, минус
// неприменимый к нам `socks` (см. helperConfig.ConnMode). Неизвестное значение — это НЕ повод
// падать и не повод молча выбрать «что-нибудь»: откатываемся на прежнее поведение (`vpn`), тот
// же принцип, что уже принят у normalizeCaptchaMode/normalizeObfsMode в этом дереве.
func normalizeConnMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "rawtun":
		return "rawtun"
	default:
		return "vpn"
	}
}

// parseBoolSetting — разбор булевой SETTING_-строки от хоста. Заведён здесь, а не взят готовым,
// потому что готового в дереве не было ни одного (проверено): единственное булево чтение до
// сих пор было `os.Getenv(...) == "1"` в creds_vkcalls.go, то есть не разбор настройки, а
// проверка отладочного env. Принимаем всё, чем булево значение реально может приехать от двух
// разных хостов (Kotlin и Pascal сериализуют по-своему), вместо одного жёсткого литерала.
func parseBoolSetting(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// parseConfig — ЕДИНЫЙ парсер коннект-конфига для ОБЕИХ платформ (MODULE_API §2.2/§2.3):
// KEY=VALUE (LISTEN_PORT/SOCKS_USER/SOCKS_PASS) + LINK = сырая qwdtt://-ссылка,
// декодим её здесь (мирор parseUri + peerWithDtlsPort) — тем же парсером, что summarize/normalize.
func parseHelperConfig(raw string) (helperConfig, error) {
	var cfg helperConfig
	var link string
	var settingHashRaw []string
	var settingWorkers int // UI воркеры (qwdttWorkers ?: workers)
	var settingHashMode string
	var qwdttWorkers int
	var qwdttHashMode string
	var qwdttAuthMode string
	var qwdttHashRaw []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k, v := line[:eq], strings.TrimSpace(line[eq+1:])
		switch k {
		case "LISTEN_PORT":
			cfg.SocksPort, _ = strconv.Atoi(v)
		case "SOCKS_USER":
			cfg.SocksUser = v
		case "SOCKS_PASS":
			cfg.SocksPass = v
		case "RELAY_WINDOW_SEC":
			cfg.RelayWindowSec, _ = strconv.Atoi(v)
		case "SETTING_captchaMode":
			cfg.CaptchaMode = v
		case "SETTING_vkAuthMode":
			cfg.VkAuthMode = v
		case "SETTING_qwdttAuthMode":
			qwdttAuthMode = v
		case "SETTING_vkAnonPath":
			cfg.VkAnonPath = v
		case "SETTING_hashMode":
			settingHashMode = v
		case "SETTING_qwdttHashMode":
			qwdttHashMode = v
		case "SETTING_dnsPreset":
			cfg.DnsPreset = v
		case "SETTING_connMode":
			cfg.ConnMode = normalizeConnMode(v)
		case "SETTING_noDtls":
			cfg.NoDTLS = parseBoolSetting(v)
		case "SETTING_turnTcp":
			cfg.TurnTCP = parseBoolSetting(v)
		case "SETTING_directPort":
			cfg.DirectPort, _ = strconv.Atoi(v)
		case "SETTING_rawPort":
			cfg.RawPort, _ = strconv.Atoi(v)
		case "SETTING_workers":
			// legacy shared UI «Воркеры».
			if w, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && w > 0 {
				settingWorkers = w
			}
		case "SETTING_qwdttWorkers":
			if w, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && w > 0 {
				qwdttWorkers = w
			}
		case "SETTING_dialTimeoutSec":
			// antinet: потолок дозвона SOCKS5 до цели (socks5.go). 0/пусто → дефолт 10с.
			cfg.DialTimeoutSec, _ = strconv.Atoi(v)
		case "SETTING_vkHash1", "SETTING_vkHash2", "SETTING_vkHash3", "SETTING_vkHash4", "SETTING_vkHashes":
			settingHashRaw = append(settingHashRaw, v)
		case "SETTING_qwdttHash1", "SETTING_qwdttHash2", "SETTING_qwdttHash3", "SETTING_qwdttHash4":
			qwdttHashRaw = append(qwdttHashRaw, v)
		case "START_REASON":
			// antinet §4.1 п.3 — cold | resume | handover. Хост лишь называет повод; годность
			// восстановленного состояния решаем мы сами (§4.1 п.4), см. credstate.go.
			cfg.StartReason = v
		case "MODULE_STATE":
			// antinet §4.2 — непрозрачный (для хоста) блоб нашего же состояния прошлой сессии.
			cfg.ModuleState = v
		case "APP_LANG":
			cfg.AppLang = v
		case "LINK":
			link = v
		}
	}
	if qwdttWorkers > 0 {
		settingWorkers = qwdttWorkers
	}
	if strings.TrimSpace(qwdttHashMode) != "" {
		settingHashMode = qwdttHashMode
	}
	if strings.TrimSpace(qwdttAuthMode) != "" {
		cfg.VkAuthMode = qwdttAuthMode
	}
	if len(qwdttHashRaw) > 0 {
		settingHashRaw = append(qwdttHashRaw, settingHashRaw...)
	}
	if link == "" {
		return cfg, fmt.Errorf("no LINK in config")
	}
	cfg.Link = link // antinet §4.2: только для отпечатка в credstate.go, см. поле Link
	u, err := url.Parse(link)
	if err != nil {
		return cfg, fmt.Errorf("parsing LINK %q: %w", link, err)
	}
	q := u.Query()
	qget := func(keys ...string) string {
		for _, k := range keys {
			if val := q.Get(k); val != "" {
				return val
			}
		}
		return ""
	}
	peer := qget("peer")
	hashes := qget("hashes", "vkHashes")
	if peer == "" {
		return cfg, fmt.Errorf("LINK missing peer")
	}
	cfg.HashMode = vk.NormalizeHashMode(settingHashMode)
	// Settings hashes: qwdttHash* first (scheme panel), then legacy vkHash*.
	settingsMap := map[string]string{"SETTING_vkHashes": strings.Join(settingHashRaw, ",")}
	for i, h := range qwdttHashRaw {
		if i < 4 {
			settingsMap[fmt.Sprintf("SETTING_qwdttHash%d", i+1)] = h
		}
	}
	merged := vk.CollectHashesFor(vk.ParseHashList(hashes), settingsMap, "qwdtt")
	if len(merged) == 0 {
		// Нет хешей в ссылке/настройках. «Ручной» без материала невозможен — Авто API
		// (создадим звонки в Run). Явный manual + пустые хеши раньше валил старт целиком.
		if cfg.HashMode == "manual" {
			cfg.HashMode = "auto_api"
		}
	} else {
		hashes = strings.Join(merged, ",")
	}
	// Workers: только SETTING_workers (UI) > defaultWorkers.
	// workers= / workersPerHash в ссылке намеренно игнорируются — иначе shared-линк
	// с workers=18 перекрывал слайдер 72 в карточке.
	cfg.Workers = defaultWorkers
	cfg.WorkersSource = "default"
	if settingWorkers > 0 {
		cfg.Workers = settingWorkers
		cfg.WorkersSource = "setting"
	}
	cfg.Hashes = hashes
	// 0 = эфемерный bind (`run.go`: `127.0.0.1:0`), и это ДЕФОЛТ. Раньше здесь
	// безусловно проставлялся `defaultLocalPort` (9000), из-за чего эфемерная ветка была
	// мертва, а её собственный комментарий («фиксированный дефолт давал детерминированный
	// bind: address already in use… эфемерный устраняет класс гонки целиком») не исполнялся.
	//
	// Живое следствие: вторая одновременная сессия схемы — та, что
	// поднимается ради ПИНГА при активном коннекте, — умирала через 33 мс после старта
	// (`slot 2 died unexpectedly`), потому что второй bind на 127.0.0.1:9000 невозможен.
	// Порт этот чисто внутрипроцессный (loopback между wireguard-go и localConn), наружу
	// не виден: серверу уходит ФАКТИЧЕСКИ занятый порт (`localPortStr`), а не это значение.
	//
	// Явный `port=`/`listenPort=` из ссылки уважается как и раньше — оператор вправе
	// зафиксировать порт, приняв, что второй сессии тогда не будет.
	cfg.LocalPort = 0
	if p, e := strconv.Atoi(qget("port", "listenPort")); e == nil && p > 0 {
		cfg.LocalPort = p
	}
	if !strings.Contains(peer, ":") {
		peer = peer + ":" + strconv.Itoa(defaultDtlsPort)
	}
	cfg.Peer = peer
	cfg.Hashes = hashes
	cfg.Password = qget("pass", "password")
	return cfg, nil
}

// peerForTransport — АДРЕС, по которому реально дозваниваться, с учётом транспортного режима.
//
// ⚠ `cfg.Peer` при этом НЕ меняется, и это не стиль, а требование: из него выводится
// `deviceIDFor(password, peer)`, то есть идентичность устройства для сервера. Подмени его — и все
// уже выданные пароли, привязанные к устройству, начнут получать `DENIED:device_mismatch`.
//
// Порт зависит от режима, потому что у сервера под каждый режим СВОЙ слушатель (`-listen` /
// `-listen-direct` / `-listen-raw`), и обычный DTLS-слушатель на `GETCONF_RAW:` не отвечает
// ничем. Мирор авторского `TunnelService.kt` (`effectiveServerPort` + `PeerAddress.withPort`), там
// же взяты и дефолты. Без этой подмены настройка `connMode`/`noDtls` меняла протокол, а стучались
// по-прежнему в DTLS-порт — режим не мог заработать ни при какой конфигурации сервера.
//
// `noDtls` при `rawtun` ИГНОРИРУЕТСЯ (raw и так без DTLS) — тем же порядком веток, что у автора:
// иначе сохранённый от классического режима флажок увёл бы нас в direct-порт вместо raw.
func peerForTransport(cfg helperConfig) string {
	port := 0
	switch {
	case cfg.ConnMode == "rawtun":
		port = cfg.RawPort
		if port <= 0 {
			port = defaultRawPort
		}
	case cfg.NoDTLS:
		port = cfg.DirectPort
		if port <= 0 {
			port = defaultDirectPort
		}
	default:
		return cfg.Peer // vpn: порт уже тот, что в ссылке
	}
	host, _, err := net.SplitHostPort(cfg.Peer)
	if err != nil {
		return cfg.Peer // разобрать не смогли — не портим адрес догадкой
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// emitProgress/emitLog/emitStatus(+status*-константы)/emitEventAck, handleHostEvent +
// setHostEventHandler, awaitActionResult, parseConfig(KEY=VALUE)/readConfigForEntry и openListener —
// канон `shared/hostproto`. Здесь копий больше нет: дедуп PROGRESS|/STATUS|, обрезка имени события
// по первому '|' и фоллбэк на файл результата действия — часть контракта, а не утилиты модуля.
//
// progressWriter — log идёт сюда: tee в stderr (полный лог в helper.stdout.log) + извлечение
// milestone-строк визуального лога qWDTT в PROGRESS| (тосты в AntiNet). Без re-mapping транспорта.
type progressWriter struct{ inner *os.File }

func (w progressWriter) Write(p []byte) (int, error) {
	if msg := classifyProgress(string(p)); msg != "" {
		emitProgress("%s", msg)
	}
	return w.inner.Write(p)
}

// qwdttStrings — тот же паттерн, что echo's demoStrings/demoStringsFor (MODULE_API §2.9): модуль сам
// отвечает за локализацию своего PROGRESS|/LOG| текста, по APP_LANG из конфига — без этого тосты
// у юзера остаются английскими независимо от языка приложения.
// Wire-протокол (сами ТЕГИ PROGRESS|/LOG|, таймстамп-префикс) остаётся
// ASCII — меняется только payload-текст ПОСЛЕ тега; файл в целом уже UTF-8 (хост декодит явно).
// `log.Printf`/внутренняя dev-диагностика (не PROGRESS|/LOG|), включая debugSilenceWatcher'а —
// dev-only симуляция, недостижимая обычным юзером, — остаются английскими намеренно.
type qwdttStrings struct {
	wrongPassword string
	// Сервер не подтвердил WRAP/DTLS. Отдельная строка, а НЕ переиспользование wrongPassword:
	// таймаут WRAP означает «пароль не подтверждён», что покрывает и неверный пароль, и молчащий
	// сервер — врать «пароль неверный» там, где сервер просто лёг, значит отправить юзера
	// перевыпускать рабочий ключ. Текст называет обе причины и говорит, что делать.
	wrapNotConfirmed string
	vkDnsUnreachable string
	solvingCaptcha   string
	vkAccessObtained string
	establishingDtls string
	// establishingDirect — прямой режим бампа 1.4.3 (`tp.NoDTLS`/`tp.RawMode`): DTLS-слоя нет
	// вовсе. Отдельная строка, а не переиспользование establishingDtls: юзер сам выбрал режим
	// настройкой, и показывать ему «Устанавливаю DTLS-туннель…» там, где DTLS сознательно снят,
	// значит врать ровно в том месте, по которому он и будет проверять, применилась ли настройка.
	establishingDirect  string
	turnSessionOpen     string
	reestablishing      string
	cannotRecoverTunnel string
	allWorkersDied      string
	obtainingVkAccess   string
	lostContactRelay    string
	cannotRecoverRelay  string
	relaySpawnFmt       string // %d, %s — streak, reason (LOG|)
	relayGaveUpFmt      string // %d, %s — streak, reason (LOG|)
	// Эффективный транспорт — ОДНА строка в ВИДИМЫЙ журнал на старте (LOG|, §2.9). Без неё режим
	// снаружи неопознаваем: тост «прямой туннель (без DTLS)» одинаков у `rawtun` и у `vpn+noDtls`,
	// а снимки настроек живут в helper.stdout.log, куда юзер без adb не заглянет. Фразы целиком, а
	// не сборка из кусков: «режим» и «сервер» в разных языках склеиваются по-разному.
	transportRawFmt    string // %s — адрес:порт
	transportDirectFmt string // %s — адрес:порт
	transportDtlsFmt   string // %s — адрес:порт
	// Сервер принял соединение, но на ЗАПРОС КОНФИГА не ответил ничем. Отдельная строка, а не
	// переиспользование wrapNotConfirmed: там пароль не подтверждён, здесь подтверждён — молчит
	// именно control-запрос, и почти всегда потому, что выбранный транспортный режим на ЭТОМ
	// адресе не обслуживается (у автора raw живёт на отдельном `-listen-raw`, no-DTLS — на
	// `-listen-direct`, и оба по умолчанию выключены; обычный DTLS-слушатель знает только
	// GETCONF:/AUTH:). Без этой строки юзер видел только «модуль не запустился».
	configNoAnswerFmt string // %s — режим транспорта (LOG|)
	// WRAP/DTLS так и не встал НИ РАЗУ (peer молчит на :56002, при этом rawtun на :56003
	// часто жив). Отдельная строка от wrapNotConfirmed: тост — «проверьте пароль», LOG —
	// конкретный peer + совет переключить транспорт, иначе юзер ждёт ~95с host probe.
	wrapNoAnswerFmt string // %s — peer host:port (LOG|)
}

var qwdttStringsRU = qwdttStrings{
	wrongPassword:       "Ошибка: неверный пароль подключения",
	wrapNotConfirmed:    "Сервер не ответил на WRAP/DTLS — попробуйте транспорт «Raw IP» или проверьте WG-порт",
	vkDnsUnreachable:    "Ошибка: VK DNS недоступен",
	solvingCaptcha:      "Решаю капчу VK…",
	vkAccessObtained:    "Доступ к звонку VK получен",
	establishingDtls:    "Устанавливаю DTLS-туннель…",
	establishingDirect:  "Устанавливаю прямой туннель (без DTLS)…",
	turnSessionOpen:     "TURN-сессия открыта",
	reestablishing:      "Пересоздаю TURN/DTLS на текущей сети…",
	cannotRecoverTunnel: "Не удаётся восстановить туннель — нужна свежая ссылка/звонок",
	allWorkersDied:      "Все воркеры умерли — перезапускаю транспорт…",
	obtainingVkAccess:   "Получаю доступ к звонку VK…",
	lostContactRelay:    "Потерян контакт с релеем — пересоздаю TURN/DTLS…",
	cannotRecoverRelay:  "Не удаётся восстановить контакт с релеем — звонок мог завершиться",
	relaySpawnFmt:       "relayWatchdog: пересоздание #%d (причина: %s)",
	relayGaveUpFmt:      "relayWatchdog: сдался после %d пересозданий (причина: %s)",
	configNoAnswerFmt:   "Сервер не ответил на запрос конфига в режиме «%s». Скорее всего этот режим на адресе из ссылки не включён — у сервера под него отдельный порт. Верните транспорт в «WireGuard» либо возьмите ссылку с портом нужного режима.",
	wrapNoAnswerFmt:     "Сервер %s не ответил на WRAP/DTLS (WireGuard). На этом порту, похоже, нет DTLS-слушателя — переключите транспорт на «Raw IP» (обычно :56003) или включите WG/DTLS на сервере.",
	transportRawFmt:     "Транспорт: Raw IP — сырые пакеты без WireGuard, сервер %s",
	transportDirectFmt:  "Транспорт: WireGuard без DTLS, сервер %s",
	transportDtlsFmt:    "Транспорт: WireGuard поверх DTLS, сервер %s",
}

var qwdttStringsEN = qwdttStrings{
	wrongPassword:       "Error: wrong connection password",
	wrapNotConfirmed:    "Server did not answer WRAP/DTLS — try \"Raw IP\" transport or check the WG port",
	vkDnsUnreachable:    "Error: VK DNS unreachable",
	solvingCaptcha:      "Solving VK captcha…",
	vkAccessObtained:    "VK call access obtained",
	establishingDtls:    "Establishing DTLS tunnel…",
	establishingDirect:  "Establishing direct tunnel (no DTLS)…",
	turnSessionOpen:     "TURN session open",
	reestablishing:      "Re-establishing TURN/DTLS on the current network…",
	cannotRecoverTunnel: "Cannot recover the tunnel — a fresh link/call is needed",
	allWorkersDied:      "All workers died — restarting transport…",
	obtainingVkAccess:   "Obtaining VK call access…",
	lostContactRelay:    "Lost contact with relay — re-establishing TURN/DTLS…",
	cannotRecoverRelay:  "Cannot recover relay contact — the call may have ended",
	relaySpawnFmt:       "relayWatchdog: re-spawn #%d (reason: %s)",
	relayGaveUpFmt:      "relayWatchdog: gave up after %d re-spawns (reason: %s)",
	configNoAnswerFmt:   "The server did not answer the config request in \"%s\" mode. Most likely that mode is not enabled on the address from the link — the server listens for it on a separate port. Switch the transport back to \"WireGuard\", or use a link with the port for that mode.",
	wrapNoAnswerFmt:     "Server %s did not answer WRAP/DTLS (WireGuard). That port likely has no DTLS listener — switch transport to \"Raw IP\" (usually :56003) or enable WG/DTLS on the server.",
	transportRawFmt:     "Transport: Raw IP — bare packets without WireGuard, server %s",
	transportDirectFmt:  "Transport: WireGuard without DTLS, server %s",
	transportDtlsFmt:    "Transport: WireGuard over DTLS, server %s",
}

// qwdttStringsFor — APP_LANG "ru" → русский стол, всё остальное (в т.ч. пусто/неизвестно) → английский.
func qwdttStringsFor(lang string) qwdttStrings {
	if strings.EqualFold(strings.TrimSpace(lang), "ru") {
		return qwdttStringsRU
	}
	return qwdttStringsEN
}

// qwS — резолвится ОДИН раз в realMain (из cfg.AppLang), ДО любого emitProgress/classifyProgress.
var qwS = qwdttStringsEN // safe default до первого resolve (defensive — realMain резолвит рано)

// settingsLogTag — префикс строк, которые ОПИСЫВАЮТ КОНФИГУРАЦИЮ, а не событие: применённые
// настройки, эффективные параметры сессии, подменённый порт пира. Классификатор ниже их не трогает.
//
// ⚠ Признак КЛАССА, а не очередное исключение под конкретный текст. classifyProgress — эвристика по
// подстроке, и она применяется к КАЖДОЙ строке dev-лога, включая наши же диагностические. Живой
// случай (юзер, 2026-09-11): при `rawtun`+`noDtls` юзер видел тост «Устанавливаю DTLS-туннель…» —
// его породила строка `transport from settings: mode=rawtun noDtls=true`, потому что «noDtls» в
// нижнем регистре СОДЕРЖИТ «dtls». Рядом тем же механизмом врал `[CAPTCHA] mode from settings: auto`
// → «Решаю капчу VK…», хотя капчу никто не решал. Оба — строки, которые я же и добавил ради
// проверяемости настроек, и обе стали источником вранья ровно в том месте, по которому юзер и
// проверяет, применилась ли настройка.
//
// Ветки-исключения под конкретный текст тут уже дважды заводились (`wrap_auth_timeout`, `[direct]`);
// третья по счёту означала бы, что класс не чинится. Снимок конфигурации не событие по определению —
// значит он и не кандидат в тост, а новая настройка получает это свойство даром, просто печатаясь с
// тем же префиксом.
// moduleStopHook — чем свернуть модуль по событию `stop` от хоста. Ставится в realMain (run.go)
// на отмену корневого контекста; до старта транспорта nil, и это нормально — сворачивать нечего.
var moduleStopHook func()

// rawGoodbyeWG — незавершённые отправки DISCONNECT_RAW (session.go). Хост зовёт событие `stop`
// СИНХРОННО (C-ABI на Android, построчный stdin на десктопе), поэтому пауза на прощание живёт
// здесь, а не в хосте: так она ограничена сверху нами и не держит хостовый лок на глазок.
var rawGoodbyeWG sync.WaitGroup

// rawGoodbyeBudget — потолок ожидания. Запись идёт с собственным дедлайном 500 мс на сокет,
// больше этого ждать нечего; исчерпание бюджета означает «сокет не отпустил», а не «ещё чуть-чуть».
const rawGoodbyeBudget = 700 * time.Millisecond

// awaitRawGoodbye — дождаться отправки прощаний, но не дольше бюджета.
func awaitRawGoodbye() {
	done := make(chan struct{})
	go func() { rawGoodbyeWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(rawGoodbyeBudget):
		log.Printf("[HELPER] stop: DISCONNECT_RAW did not drain in %s - leaving the rest to the server idle timeout", rawGoodbyeBudget)
	}
}

// shutdownModule — ЕДИНЫЙ путь сворачивания хелпера: отменить корневой контекст (после чего
// realMain возвращается из `<-rootCtx.Done()`, а слот самоликвидируется) и дождаться прощаний
// RAW-сессий.
//
// ДВА вызывающих, одно тело: (1) событие `stop` от хоста (MODULE_API §2.8) — хост сейчас нас
// убьёт и даёт короткое окно на прощание; (2) relayWatchdog, исчерпавший re-spawn'ы (onSilent).
// Второй заведён 2026-09-11 и именно ЗДЕСЬ, а не своим `os.Exit`, потому что путь завершения
// должен остаться один: прощание серверу (DISCONNECT_RAW) нужно обоим одинаково — без него
// сервер держит наших воркеров 90 с своего idleTimeout и льёт в них downlink следующей сессии.
//
// Зачем сдача watchdog'а вообще завершает процесс. «Сдался» означает: своими силами (свежие
// TURN-сокеты на текущей сети, реюз кэша кредов) транспорт не поднимается. Дальше жить живым
// процессом с мёртвым туннелем — худший из исходов: хост видит `alive=true`, его watchdog смерти
// молчит, а туннель не несёт ни байта (живой инцидент 2026-09-11: полтора часа `up` растёт,
// `down` стоит). Смерть слота — сигнал, который хост УЖЕ умеет обрабатывать:
// `ModuleManager.superviseDeath` поднимает свежий процесс на том же порту (сокетом владеет хост),
// с новыми VK-кредами и новыми аллокациями, а его же crash-loop-guard не даёт этому стать
// tight-loop'ом. Сдача наступает не раньше чем через `relayMaxRespawns` × `relayRespawnCooldown`
// (~2.5 мин), то есть заведомо дольше хостового окна быстрой смерти (15 с) — перезапуск идёт
// штатной веткой, а не через backoff crash-loop'а.
func shutdownModule(reason string) {
	log.Printf("[HELPER] shutting down: %s", reason)
	if h := moduleStopHook; h != nil {
		h()
	}
	awaitRawGoodbye()
}

const settingsLogTag = "[settings]"

// classifyProgress — куратор: ключевые строки лога qWDTT → чистый текст тоста (стиль визуального лога).
func classifyProgress(line string) string {
	l := strings.ToLower(line)
	switch {
	// ⚠ ПЕРВОЙ веткой: снимок конфигурации — не событие, тоста по нему быть не должно (см.
	// settingsLogTag). Стоя ниже, гард не спасал бы: сработала бы более ранняя текстовая ветка.
	case strings.Contains(l, settingsLogTag):
		return ""
	case strings.Contains(l, "fatal_auth") || strings.Contains(l, "неверный пароль"):
		return qwS.wrongPassword
	// ⚠ СТРОГО ВЫШЕ ветки "dtls": строка отказа выглядит как
	// `WRAP_AUTH_TIMEOUT: DTLS timeout, password/WRAP not confirmed | server did not respond…`
	// и содержит «dtls», поэтому без отдельной ветки попадает в неё и показывает юзеру бодрое
	// «Устанавливаю DTLS-туннель…» вместо отказа: конфиг молча висит и уходит в -2, а юзеру
	// непонятно, что вообще с ним происходит.
	case strings.Contains(l, "wrap_auth_timeout") ||
		strings.Contains(l, "password/wrap not confirmed"):
		return qwS.wrapNotConfirmed
	case strings.Contains(l, "vk dns") || strings.Contains(l, "lookup login.vk"):
		return qwS.vkDnsUnreachable
	case strings.Contains(l, "капч") || strings.Contains(l, "captcha"):
		return qwS.solvingCaptcha
	case strings.Contains(l, "joinconversation") || strings.Contains(l, "turn creds") || strings.Contains(l, "vk creds"):
		return qwS.vkAccessObtained
	// ⚠ СТРОГО ВЫШЕ ветки "dtls": строка прямого режима — `[WORKER #N] [DIRECT] No DTLS, RTP-obfs
	// AEAD only OK` — СОДЕРЖИТ подстроку «dtls» (внутри «No DTLS») и без этой ветки попадала бы
	// ниже, показывая юзеру «Устанавливаю DTLS-туннель…» ровно в режиме, где DTLS сознательно
	// снят настройкой. Тот же класс, что уже стоил отдельной ветки wrap_auth_timeout выше.
	case strings.Contains(l, "[direct]"):
		return qwS.establishingDirect
	case strings.Contains(l, "dtls"):
		return qwS.establishingDtls
	// «turn tcp» — бамп 1.4.3 (SETTING_turnTcp). Без него включённый TCP-транспорт терял этот шаг
	// прогресса целиком: строка становится `[SESSION #N] TURN TCP (…)`, а второе плечо условия
	// («сессия» + «turn») в нашем порту не срабатывает НИКОГДА — dev-лог у нас английский, и
	// русского слова «сессия» в нём нет ни одного (плечо унаследовано от апстрима как есть).
	case strings.Contains(l, "turn udp") || strings.Contains(l, "turn tcp") ||
		(strings.Contains(l, "сессия") && strings.Contains(l, "turn")):
		return qwS.turnSessionOpen
	}
	return ""
}

// runTransportSupervised — оркестрация TURN/DTLS-транспорта: супервизор `runTransport` (re-spawn на
// хендовер/естественную смерть, с backoff+cap), relayWatchdog (backstop здоровья релея при живых
// воркерах), debugSilenceWatcher (adb-валидация watchdog'а).
//
// Блокируется до захвата WG-конфига (успех) либо rootCtx.Done() (shutdown, err=rootCtx.Err()).
// Вызывающий (`realMain`, run.go) владеет rootCtx/rootCancel — сам решает, что делать с конфигом
// (bringUpTunnelAndSocks) и когда финально заблокироваться на <-rootCtx.Done().
func runTransportSupervised(rootCtx context.Context, tp *TurnParams, peer *net.UDPAddr, localConn net.PacketConn, localPortStr string, numW int, deviceID string, cfg helperConfig, stats *Stats, profileDir string) (string, error) {
	shutdownCh := make(chan struct{})
	go func() { <-rootCtx.Done(); close(shutdownCh) }()
	go stats.RunLoop(shutdownCh)

	var pauseFlag int32
	wgConfCh := make(chan string, 1)
	onWGConfig := func(c string) {
		select {
		case wgConfCh <- c:
		default:
		}
	}
	// giveUpCh — канал «супервизор сдался САМ». Без него финальный select ниже (wgConfCh /
	// rootCtx.Done()) не мог узнать, что супервизорная горутина вышла внутренним «сдаёмся до
	// реконнекта»: тот return не писал в wgConfCh и не трогал rootCtx, поэтому вся функция — а с ней
	// и держатель командного лока у хоста — висела до ПОСТОРОННЕГО внешнего disconnect'а. Живо
	// воспроизведено: повторная VK-капча status=BOT/ERROR_LIMIT выбивает fastDeaths>=6 на обеих
	// группах воркеров, внешнего disconnect'а при этом нет вовсе. Закрывается ровно один раз —
	// супервизорной горутиной прямо перед её собственным return'ом.
	giveUpCh := make(chan struct{})

	// Транспорт TURN/DTLS-воркеров под СУПЕРВИЗОРОМ — пере-спавним в ДВУХ случаях (оба → re-spawn
	// `runTransport` с НОВЫМИ TURN-сокетами на ТЕКУЩЕЙ сети через protectedDialUDP→protect-callback
	// хоста, переиспользуя in-memory кэш VK-кредов (VK-expiry ≈ часы) → БЕЗ капчи, пока креды валидны; WG-device/
	// dispatcher/SOCKS на 127.0.0.1 НЕ трогаются — переживают, WG не ре-handshake, dispatcher.Shutdown
	// НЕ закрывает localConn):
	//   (1) ХЕНДОВЕР — событие `handover` от хоста (MODULE_API §2.8; C-ABI на Android, stdin на
	//       десктопе): handler ниже cancel'ит ctx текущего поколения → runTransport возвращается
	//       (tctx.Err()!=nil) → немедленный re-spawn.
	//   (2) ЕСТЕСТВЕННАЯ СМЕРТЬ — ВСЕ воркеры вышли терминально (хеш мёртв/FATAL_AUTH/STUN-death) при
	//       ЖИВОМ процессе → runTransport вернулся сам (tctx.Err()==nil). Без супервизора helper висел
	//       бы с 0 воркеров (watchdog молчит — процесс жив; reconnect реюзит живой процесс). Backoff+cap:
	//       на реально мёртвой ссылке re-spawn → GetCreds опять терминал → tight-loop; ≥6 быстрых
	//       (<15с) смертей подряд → сдаёмся (нужна свежая ссылка). Транзиент (релей/сессия/DTLS, НЕ
	//       терминал) сюда НЕ доходит — его лечит сам worker-retry-loop ядра (5-16с), воркеры не выходят.
	var txMu sync.Mutex
	var txCancel context.CancelFunc
	go func() {
		fastDeaths := 0
		for {
			if rootCtx.Err() != nil {
				return
			}
			tctx, tcancel := context.WithCancel(rootCtx)
			txMu.Lock()
			txCancel = tcancel
			txMu.Unlock()
			startedAt := time.Now()
			runTransport(tctx, tp, peer, localConn, localPortStr, numW, deviceID, cfg.Password, stats, &pauseFlag, cfg, profileDir, onWGConfig)
			tcancel()
			if rootCtx.Err() != nil {
				return
			}
			if tctx.Err() != nil { // (1) МЫ отменили (хендовер ИЛИ relayWatchdog) → немедленный re-spawn
				fastDeaths = 0
				emitProgress("%s", qwS.reestablishing)
				continue
			}
			// (2) естественный выход — все воркеры терминальны. Анти-tight-loop.
			if time.Since(startedAt) < 15*time.Second {
				fastDeaths++
			} else {
				fastDeaths = 0
			}
			if fastDeaths >= 6 {
				emitProgress("%s", qwS.cannotRecoverTunnel)
				log.Printf("[HELPER] transport is dying in a loop (%d fast deaths) - giving up until reconnect", fastDeaths)
				// ТИПИЗИРОВАННО хосту (MODULE_API.md §2.13): именно `fatal`, и не по «звучит
				// страшно», а по механике. Если сдача случилась ДО выдачи wgConf, giveUpCh
				// поднимет ошибку в bringUpTunnelAndSocks → процесс умрёт сам, и состояние
				// никому не понадобится. Если ПОСЛЕ — слушателя у giveUpCh уже нет: helper
				// остаётся ЖИВ с нулём воркеров, а этот супервизор только что вышел. Щадящий
				// сигнал хоста (handover → requestTransportRespawn) отменяет ctx поколения,
				// которого больше не существует, то есть не пере-спавнит ничего. Лечит только
				// пересоздание процесса — о чём хост и должен узнать сразу, а не после пяти
				// бесполезных нуджей по лестнице бэкоффа (~11.5 мин).
				emitStatus(statusFatal, "transport supervisor gave up after repeated fast deaths")
				close(giveUpCh) // see this function's own giveUpCh doc-comment — unblocks the final select below
				return
			}
			shift := fastDeaths
			if shift > 3 {
				shift = 3
			}
			delay := time.Duration(int64(1)<<uint(shift)) * time.Second // 2,4,8,8…с
			emitProgress("%s", qwS.allWorkersDied)
			select {
			case <-time.After(delay):
			case <-rootCtx.Done():
				return
			}
		}
	}()

	// requestTransportRespawn — ЕДИНЫЙ триггер пере-спавна транспорта (cancel ctx текущего поколения →
	// супервизор выше, tctx.Err()!=nil, немедленно пере-спавнит TURN/DTLS на ТЕКУЩЕЙ сети, реюз кэша
	// кредов → без капчи). ДВА потребителя (единая логика, не два single-purpose пути): (1) хендовер
	// (событие хоста `handover`, канон shared/hostproto) и (2) relayWatchdog (молчащий релей при
	// живых воркерах).
	requestTransportRespawn := func() {
		txMu.Lock()
		c := txCancel
		txMu.Unlock()
		if c != nil {
			c()
		}
	}

	// Хендовер (MODULE_API §2.8) — ДВА транспорта, ОДНА реакция, оба сходятся в
	// handleHostEvent("handover") → hostEventHandler:
	//   • Android — C-ABI `antinet_module_event("handover")` (канон shared/entry);
	//   • десктоп — строка `handover` в stdin (`startHostEventReader`, канон shared/lifecycle).
	// Третьего пути нет и обработчик SIGUSR1 заводить не надо — сигнала не шлёт ни один хост (на
	// Android он в слот-процессе под ART недетерминирован, на десктопе хост пишет в stdin).
	// ⚠ Грабля этого места: звать requestTransportRespawn НАПРЯМУЮ из сигнального обработчика,
	// минуя handleHostEvent, нельзя — тот должен иметь generic-ветку для
	// не-ACTION_RESULT строк, поэтому реальные события хоста молча дропались.
	setHostEventHandler(func(event string) {
		switch event {
		case "handover":
			requestTransportRespawn()
		case "stop":
			// Хост сейчас нас убьёт и даёт короткое окно на прощание (MODULE_API §2.8).
			// Тело — общее с самоликвидацией watchdog'а, см. shutdownModule.
			shutdownModule("host event: stop")
		}
	})

	// relayWatchdog — backstop здоровья релея (тип ниже): устойчивый обрыв релея при ЖИВЫХ воркерах
	// (наш инцидент: socks5 code=4 ~16мин при «Активных: 9» — ядро автора это НЕ ловит) →
	// детект по PONG'у (session.go Reader пишет relayPongNano) → НЕМЕДЛЕННЫЙ supervisor re-spawn. Свой тикер.
	relayWD := &relayWatchdog{respawn: requestTransportRespawn, stats: stats}
	// ⚠ Kept deliberately (relayWatchdogTick=15s, see its own doc-comment). A clean A/B confirmed
	// that FULLY disabling this goroutine does NOT additionally help a stuck production cascade
	// beyond what the 15s tick already gives (both still hit "context deadline exceeded") — the
	// root cause there was external DPI/traffic-shaping targeting recognizable plain
	// (non-obfuscated) QUIC on the relay↔far-side-peer↔server path, not this watchdog. No reason
	// to sacrifice real relay-dead detection for zero additional benefit.
	go relayWD.run(rootCtx)
	go debugSilenceWatcher(profileDir) // adb-валидация watchdog'а (gated файлом, в проде no-op)

	emitProgress("%s", qwS.obtainingVkAccess)

	select {
	case wgConf := <-wgConfCh:
		return wgConf, nil
	case <-rootCtx.Done():
		return "", rootCtx.Err()
	case <-giveUpCh:
		return "", fmt.Errorf("transport supervisor exhausted retries — need a fresh link/call")
	}
}

// wgHandshakeFails — счётчик ПОДРЯД «Handshake did not complete» от wireguard-go (хук логгера в
// bringUpTunnelAndSocks). WG-device хендшейкает к VPS ЧЕРЕЗ релей (peer=127.0.0.1 → dispatcher →
// TURN/DTLS → релей → VPS): релей форвардит → handshake завершается («Received handshake response»)
// → счётчик в 0; релей мёртв → handshake не доходит → «did not complete» каждые ~5с (REKEY_TIMEOUT)
// → счётчик растёт. WG-НАТИВНЫЙ сигнал живости релея end-to-end: idle-safe (нет трафика → WG не
// хендшейкает → счётчик не растёт → НЕТ ложняка) и быстрый (~15с = 3 фейла). 0xFF-keepalive автора
// для этого НЕ годится — сервер qWDTT его НЕ эхоит (проверено на устройстве: pong не приходит,
// relayPongNano навсегда 0).
var wgHandshakeFails atomic.Int32

// transportEverEstablished — antinet: хоть один воркер довёл транспорт до рабочего состояния с
// момента старта процесса. ТРЕТИЙ сигнал relayWatchdog'а и единственный, работающий ДО подъёма
// туннеля: прежние два по построению требуют уже поднятого туннеля (`wgHandshakeFails` растёт
// только когда WG есть и хендшейкает, `bytesSayRelayDead` сравнивает байты, которых до подъёма
// ещё нет), поэтому фазу «релеи не ответили ни разу» не видели вовсе.
//
// Живой замер: девять TURN-сессий открыты, `[WORKER #1..3] [DTLS] Handshake...`,
// ноль строк `Connection established OK`, ноль входящих пакетов от релея — и watchdog промолчал
// все 40с, потому что WG не стартовал и хендшейкать было нечему. Хост при этом видел только
// «`ready` не появился», а конфиг получал безымянный `-2`.
//
// Имя без «DTLS» — с бампа 1.4.3: у автора появился прямой режим (RTP-obfs AEAD поверх TURN БЕЗ
// DTLS, `tp.NoDTLS`/`tp.RawMode`), где хендшейка нет вовсе и «DTLS установлен» как понятие не
// существует. Смысл флага при этом не изменился ни на йоту — «релеи отвечают, это не холодный
// отказ», — поменялось только доказательство: в классическом режиме им остаётся завершённый
// хендшейк, в прямом это первый успешно расшифрованный и прошедший replay-окно пакет
// (session.go::obfsDirectConn.Read). Оба вызова ведут сюда.
var transportEverEstablished atomic.Bool

func noteTransportEstablished() {
	if !transportEverEstablished.Swap(true) {
		log.Printf("[relayWatchdog] first transport established - relay set is answering")
	}
	// Хосту (MODULE_API.md §2.13): рабочий слот TURN получен — это и есть парный `ok` к
	// `waiting` из ветки квоты. Точка выбрана ИМЕННО здесь, а не «сессия завершилась без
	// ошибки»: RunSession блокируется на всё время сессии, поэтому её успешный ВОЗВРАТ
	// наступает уже после того, как работа кончилась, и залипшее `waiting` держалось бы всё
	// это время — хост пересоздавал бы процесс на каждом отказе, хотя квота давно освободилась.
	// Установление транспорта — момент, когда модуль ДОКАЗАННО обслуживает трафик.
	emitStatus(statusOK, "")
}

// recordWgHandshakeFail / recordWgHandshakeOK — хук логгера wireguard-go (bringUpTunnelAndSocks).
func recordWgHandshakeFail() {
	n := wgHandshakeFails.Add(1)
	if n == 1 || n%3 == 0 {
		log.Printf("[relayWatchdog] WG handshake did not complete #%d (relay not forwarding?)", n)
	}
}
func recordWgHandshakeOK() {
	if wgHandshakeFails.Swap(0) > 0 {
		log.Printf("[relayWatchdog] WG handshake OK - relay is forwarding, counter reset")
	}
}

// debugSilenceWatcher — adb-триггер ВАЛИДАЦИИ watchdog'а без root/iptables (нельзя selective-blackhole
// релея). `run-as ... echo 1 > <profileDir>/debug_relay_silence` → форсим счётчик за порог (stuck) →
// watchdog видит stuck → re-spawn → новый транспорт хендшейкает → recordWgHandshakeOK → recovery.
// Файл в проде не существует → ноль эффекта.
func debugSilenceWatcher(profileDir string) {
	path := filepath.Join(profileDir, "debug_relay_silence")
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		_ = os.Remove(path)
		wgHandshakeFails.Store(relayStuckThreshold) // форсим stuck
		emitProgress("%s", "DEBUG: simulating stuck WG handshake (relay not forwarding)")
		log.Printf("[DEBUG] relay-stuck simulation: counter=%d (watchdog will fire on next tick)", relayStuckThreshold)
		// Авто-сброс через 10с — имитируем «релей восстановился, WG хендшейкнул» (в проде это делает
		// реальный recordWgHandshakeOK на «Received handshake»; фейк-счётчик сам не сбросится, т.к. в
		// тесте WG здоров и ре-handshake не делает). Показывает полный цикл fire→re-spawn→recovery.
		go func() {
			time.Sleep(10 * time.Second)
			recordWgHandshakeOK()
			log.Printf("[DEBUG] relay-stuck simulation: auto-reset (recovery simulation)")
		}()
	}
}

// relayWatchdog — backstop ЗДОРОВЬЯ РЕЛЕЯ при ЖИВЫХ воркерах. Закрывает дыру, которую НЕ ловят ни
// per-worker retry-loop ядра (group.go), ни supervisor (выше), ни хендовер от хоста.
//
// Почему дыра существует (механика ядра автора, изучена по исходнику): воркер, чей релей перестал
// форвардить (DTLS-сокет жив, трафик не идёт), остаётся «Активным» навсегда — RunSession не возвращает
// ошибку (read-deadline 30мин + `continue` session.go:411; 0xFF-keepalive ПИШУЩИЙ, сервер его НЕ
// эхоит) → ядровый retry-loop НЕ срабатывает → авто-recovery НЕТ (наш инцидент: socks5
// code=4 ~16мин при «Активных: 9»; APK автора это сам НЕ восстанавливает).
//
// Сигнал — WG HANDSHAKE-STUCK (wgHandshakeFails, хук логгера wireguard-go). WG-нативная проба живости
// релея end-to-end: релей форвардит → handshake завершается; мёртв → «did not complete» каждые ~5с.
// idle-safe (нет трафика → нет попыток handshake → нет ложняка), быстрый (~15с = 3 фейла). На stuck →
// НЕМЕДЛЕННЫЙ supervisor re-spawn (txCancel, БЕЗ ядрового per-worker retry-delay 5-16с): свежие
// TURN/DTLS-сокеты на ТЕКУЩЕЙ сети → новые NAT-мэппинги + свежий TURN Allocate, реюз кэша кредов (VK-expiry)
// → без капчи; WG/dispatcher/SOCKS переживают. Мирор AWG handshakeStuckThreshold→Reconnect
// ([[project_amneziawg_integration]]): порог подряд → reconnect, reset на «Received handshake response»,
// cooldown + cap-на-выгорание.
const (
	// relayWatchdogTick — частота проверки. 15с, а не 3с: живой A/B на
	// реальном hysteria2-каскаде за qWDTT показал, что `bytesSayRelayDead()`'s `dev.IpcGet()` (полная
	// UAPI-сериализация wireguard-go: `device.peers.RLock()`+per-peer `peer.handshake.mutex.RLock()`+
	// `peer.endpoint.Lock()` — ЕДИНСТВЕННЫЙ EXCLUSIVE лок во всей цепочке — внутри `device.net.RLock()`)
	// на 3-секундном тике систематически мешал успешной доставке ServerHello/Certificate-пакетов
	// первого QUIC-хендшейка через свежую UDP ASSOCIATE-сессию: с отключённым тикером (полный revert
	// вызова `relayWD.run`) клиент ДВАЖДЫ подряд успешно читал Initial-ACK, переключал destination
	// connection ID, обрабатывал AckFrame и получал реальный RTT (~90-105мс) — то, что не происходило
	// НИ РАЗУ за десятки предыдущих попыток с работающим тикером. Механизм (какой именно лок
	// конфликтует с packet-processing hot path) не идентифицирован построчно — фикс снижает частоту
	// самого дорогого вызова (`dev.IpcGet()`) в 5 раз, не убирая watchdog целиком (он ловит реально
	// мёртвый релей — живой инцидент). `relaySilentTicksFor` пересчитывает окно
	// автоматически (тот же RELAY_WINDOW_SEC даёт МЕНЬШЕ тиков при большем шаге тика).
	relayWatchdogTick    = 15 * time.Second // частота проверки — см. коммент выше
	relayRespawnCooldown = 25 * time.Second // не пере-спавнить, пока новый транспорт встаёт (TURN+DTLS+WG handshake)
	relayMaxRespawns     = 6                // re-spawn'ов подряд без оживления → сдаёмся (звонок мёртв, нужна свежая ссылка)
	// antinet: окно холодного старта для третьего сигнала («DTLS не встал ни разу»).
	//
	// ⚠ Порог берётся от ЗАМЕРЕННОЙ НОРМЫ, а не от потолка. Взять 60с «чтобы вместить потолок
	// DTLS-хендшейка 50с (session.go)» неверно дважды: (1) потолок — это максимально допустимое,
	// а не типичное: здоровый релей закрывает хендшейк за 337мс, то есть в 150 раз быстрее;
	// (2) хост в ПИНГ-пути даёт модулю
	// 40с (`helper not ready within auto-wave budget 40000ms`) и убивает хелпер раньше, чем
	// 60-секундный сигнал успел бы сработать — проверено живым прогоном 03:56:07, где не
	// сработало ничего. Окно обязано умещаться внутрь самого короткого бюджета хоста.
	//
	// 15с = ~45× замеренной нормы и вдвое меньше пинг-бюджета: медленный, но живой релей
	// успевает, а мёртвый набор объявляется мёртвым, пока хелпер ещё жив и может re-spawn'уть
	// свежие TURN/DTLS-сокеты. Совпадает с окном двух других сигналов (detection window 15s).
	relayColdStartBudget = 15 * time.Second
)

// relayStuckThreshold — «did not complete» подряд → релей признан мёртвым. Выводится в main из
// RELAY_WINDOW_SEC (окно детекта в секундах: дефолт от модуля / юзер-оверрайд в карточке «Модули»)
// ÷ REKEY_TIMEOUT(5с). Дефолт 3 (~15с). Per-module-конфигурируемо на ОБЕИХ платформах.
var relayStuckThreshold int32 = 3

// configRequestBudget — потолок ожидания ответа на ЗАПРОС КОНФИГА (GETCONF / GETCONF_RAW).
//
// ⚠ Он обязан быть КОРОЧЕ окна relayWatchdog, и это не оптимизация, а условие того, что причина
// вообще станет видна. Живой случай: юзер включил транспорт «Raw IP», сервер по адресу из ссылки
// raw-режим не обслуживает (у автора он живёт на отдельном `-listen-raw`, по умолчанию выключенном,
// а обычный DTLS-слушатель знает только GETCONF:/AUTH:) — запрос ушёл, ответа нет. Дедлайн стоял
// 45с (пришёл из апстрима), окно watchdog'а — 15с, поэтому транспорт прибивали РАНЬШЕ, чем истекал
// дедлайн: в лог не попадало ни одной строки об ошибке, а наружу уходило только «модуль не
// запустился». Исполнитель, чей провал и есть причина неподъёма, обязан отчитаться раньше, чем его
// прибьёт супервизор.
//
// Выводится в realMain из того же RELAY_WINDOW_SEC. Дефолт — окно по умолчанию минус запас на тик.
var configRequestBudget = 12 * time.Second

// ⚠ ВТОРОЙ СИГНАЛ: handshake-сигнала ОДНОГО НЕ ХВАТАЕТ — он слеп к обрыву при СВЕЖЕЙ WG-сессии.
//
// Доккоммент выше опирается на «релей мёртв → "did not complete" каждые ~5с». Это верно ТОЛЬКО когда
// WG вообще пытается делать handshake, а он пытается лишь когда ему нужен ключ: сессия истекла
// (REKEY_AFTER_TIME 120с) либо ключа ещё нет. Если релей замолчал через 30с после успешного
// рукопожатия, у WG на руках валидный keypair — он молча шифрует и шлёт в пустоту, попыток handshake
// НЕТ, wgHandshakeFails остаётся 0, watchdog каждый тик считает релей здоровым.
//
// Живой разбор (телефон, каскад qWDTT→vless): в helper.stdout.log эпизоды, где
// `[СТАТИСТИКА] Трафик` стоит на одном значении 60-93 секунды подряд при 18 «Активных», внутритуннельный
// резолвер не может даже ЗАПИСАТЬ пакет (`write udp 10.66.3.116:...: i/o timeout`), все дозвоны падают
// по своему 10с-дедлайну — и за всё это окно НИ ОДНОЙ строки watchdog'а. Единственное его срабатывание
// за весь лог пришлось на момент рекея (21:03:31), то есть ровно тогда, когда handshake и так был нужен.
//
// Сигнал — счётчики САМОГО ТУННЕЛЯ (`Stats.TotalBytesDown/Up`, их ведёт диспетчер: `down` растёт в
// writeLoop на каждом пакете, который воркеры приняли с релея и он записал в туннель, `up` — в
// readLoop на каждом пакете, ушедшем из туннеля наружу):
//   • down вырос          → релей реально донёс трафик, он ЖИВ                 → сброс;
//   • up вырос, down НЕТ  → шлём (в т.ч. ретрансмиты TCP), не получаем ничего  → тик молчания;
//   • не вырос ни один    → простой, слать нечего                              → сброс (idle-safe,
//     то же свойство, ради которого выбран и handshake-сигнал: ложняка на простое быть не должно).
//
// ⚠ Источник сменён 2026-09-11 (было: rx/tx WG-пиров через UAPI wireguard-go, `relayByteSnapshot`).
// Прежний существовал ТОЛЬКО в режиме `vpn`: в `rawtun` WireGuard'а нет вовсе, `wgDevice` остаётся
// nil, снимок отвечал `ok=false`, и сигнал по построению молчал — вместе с ним молчали и два
// соседних (handshake'ей без WG не бывает; «транспорт не вставал ни разу» гаснет навсегда после
// первого же успешного пакета). То есть в `rawtun` у модуля не оставалось НИ ОДНОГО детектора
// собственной смерти. Живой инцидент 2026-09-11: `Σtx=3962 Σrx=190`, `down` стоит на 0.08 МБ час с
// лишним при растущем `up`, все дозвоны падают по 10с-дедлайну — и ни одной строки watchdog'а.
// Счётчики диспетчера режимо-независимы (диспетчер один на оба режима) и монотонны через
// пере-спавн транспорта (`Stats` живёт в realMain, а не в поколении транспорта), поэтому сигнал
// теперь одинаково видит смерть релея в обоих режимах, а не только там, где случайно есть WG.
//
// Исход общий с handshake-сигналом — тот же onSilent(): тот же cooldown, тот же cap, тот же re-spawn.
// Второго механизма восстановления не заводим, добавляется ровно ещё один способ УВИДЕТЬ ту же смерть.
var relaySilentTicks int32 = 5 // 15с окна ÷ relayWatchdogTick(3с); выводится в main из RELAY_WINDOW_SEC

// configNoAnswerReported — строка про немой запрос конфига печатается ОДИН раз за процесс. Это
// диагноз конфигурации, а не событие: супервизор пере-спавнит транспорт раз за разом, и повтор
// залил бы визуальный лог юзера одной и той же фразой.
var configNoAnswerReported atomic.Bool

// reportConfigNoAnswer — ЕДИНАЯ точка отчёта «сервер не ответил на запрос конфига» для обеих форм
// запроса (GETCONF и GETCONF_RAW): причина у них одна, и расходиться двум текстам незачем.
//
// Молчание — это ИМЕННО таймаут; прочие ошибки (обрыв, мусор в ответе) сюда не попадают, потому что
// про них уже сказано в dev-логе конкретикой, а этот текст назвал бы неверную причину.
//
// ⚠ Предикат таймаута — `net.Error.Timeout()` через `errors.As`, а НЕ
// `errors.Is(os.ErrDeadlineExceeded)`. Первая редакция стояла на `errors.Is` и молчала на живом
// прогоне: relayed-conn от pion/turn возвращает СВОЙ тип ошибки, который `net.Error` реализует, а
// `os.ErrDeadlineExceeded` не оборачивает (текст «i/o timeout» одинаков, происхождение разное).
// Та же форма уже применена в этом дереве — session.go, ветка чтения сессии.
func reportConfigNoAnswer(tp *TurnParams, err error) {
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
		return
	}
	if !configNoAnswerReported.CompareAndSwap(false, true) {
		return
	}
	mode := "vpn (WireGuard)"
	switch {
	case tp.RawMode:
		mode = "rawtun (Raw IP)"
	case tp.NoDTLS:
		mode = "vpn + noDtls"
	}
	emitLog(qwS.configNoAnswerFmt, mode)
}

// wrapNoAnswerReported — отказ WRAP/DTLS на холодном старте печатается и гасит модуль ОДИН раз.
// Без этого 18 воркеров × 12с HS + relayWatchdog re-spawn держали бы host probe ~90с при мёртвом :56002.
var wrapNoAnswerReported atomic.Bool

// reportWrapNoAnswer — fail-fast: peer молчит на WRAP/DTLS (типично WG-порт без слушателя, а
// rawtun на соседнем порту жив). Зовётся из session при WRAP_AUTH_TIMEOUT, пока транспорт ещё
// ни разу не встал. После первого установления — только обычный worker error / watchdog.
func reportWrapNoAnswer(peer string) {
	if transportEverEstablished.Load() {
		return
	}
	if !wrapNoAnswerReported.CompareAndSwap(false, true) {
		return
	}
	if peer == "" {
		peer = "?"
	}
	emitProgress("%s", qwS.wrapNotConfirmed)
	emitLog(qwS.wrapNoAnswerFmt, peer)
	emitStatus(statusFatal, "WRAP/DTLS unanswered")
	shutdownModule("WRAP/DTLS unanswered on cold start")
}

// configRequestBudgetFor — то же окно RELAY_WINDOW_SEC, но как потолок ожидания ответа на запрос
// конфига. Живёт здесь, рядом с самим окном, чтобы «запас на один тик» не повторялся в run.go и не
// разъехался с ним. Минимум 5с — меньше не оставляет шанса медленному, но живому релею.
func configRequestBudgetFor(windowSec int) time.Duration {
	d := time.Duration(windowSec)*time.Second - relayWatchdogTick
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// relaySilentTicksFor — то же окно RELAY_WINDOW_SEC, но в тиках второго сигнала. Живёт здесь, рядом с
// relayWatchdogTick, чтобы деление на тик не пришлось повторять в main (и разъезжаться с ним).
func relaySilentTicksFor(windowSec int) int32 {
	n := int32(windowSec / int(relayWatchdogTick/time.Second))
	if n < 3 {
		n = 3
	}
	return n
}

type relayWatchdog struct {
	mu            sync.Mutex
	lastRespawn   time.Time
	respawnStreak int
	respawn       func()
	// Счётчики туннеля — источник ВТОРОГО сигнала (см. relaySilentTicks). Тот же объект, что
	// печатает `[STATS]`: отдельного учёта для watchdog'а не заводим, иначе появилось бы два
	// представления одного и того же трафика, и расходились бы они молча.
	stats *Stats

	// Состояние второго сигнала. Трогается ТОЛЬКО из run() (одна горутина), но живёт под тем же
	// мьютексом — цена на 3с-тике нулевая, а инвариант «всё состояние watchdog'а под одним локом» целее.
	lastRx, lastTx uint64
	haveBytes      bool
	silentTicks    int32
}

// tunnelByteSnapshot — сколько байт туннель ПРИНЯЛ (`rx`: воркеры взяли с релея, диспетчер записал
// внутрь) и ОТПРАВИЛ (`tx`: диспетчер прочитал изнутри и раздал воркерам) с начала процесса.
// ЕДИНЫЙ источник и второго сигнала, и строки `[WRKDIAG]`; `ok=false` только если счётчиков нет
// вовсе (watchdog создан без `stats` — в боевом пути невозможно, см. runTransportSupervised).
//
// Режима не различает намеренно: счётчики ведёт диспетчер, который в обоих режимах один и тот же,
// меняется лишь источник пакетов (WireGuard-loopback или netstack). Именно поэтому сигнал,
// стоящий на них, работает и там, где WireGuard'а нет.
func (w *relayWatchdog) tunnelByteSnapshot() (rx, tx uint64, ok bool) {
	if w.stats == nil {
		return 0, 0, false
	}
	return uint64(w.stats.TotalBytesDown.Load()), uint64(w.stats.TotalBytesUp.Load()), true
}

// bytesSayRelayDead — второй сигнал (см. relaySilentTicks). true → релей признан молчащим.
func (w *relayWatchdog) bytesSayRelayDead() bool {
	rx, tx, ok := w.tunnelByteSnapshot()
	if !ok {
		return false // счётчиков ещё нет — сравнивать не с чем
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	prevRx, prevTx, had := w.lastRx, w.lastTx, w.haveBytes
	w.lastRx, w.lastTx, w.haveBytes = rx, tx, true
	if !had {
		return false // первый тик: базовая точка снята, сравнение со следующего
	}
	switch {
	case rx > prevRx:
		w.silentTicks = 0
	case tx > prevTx:
		w.silentTicks++
	default:
		w.silentTicks = 0
	}
	if w.silentTicks < relaySilentTicks {
		return false
	}
	log.Printf("[relayWatchdog] relay is silent: tx growing, rx flat for %d ticks in a row (~%ds) - declared dead",
		w.silentTicks, int(time.Duration(w.silentTicks)*relayWatchdogTick/time.Second))
	w.silentTicks = 0 // отдали сигнал — считаем окно заново (cooldown/cap дальше держит onSilent)
	return true
}

// run — на rootCtx. Тикер: wgHandshakeFails ≥ порога → onSilent (re-spawn под cooldown+cap); иначе
// (handshake'и проходят ИЛИ нет попыток на idle) → релей жив, сброс streak.
func (w *relayWatchdog) run(ctx context.Context) {
	t := time.NewTicker(relayWatchdogTick)
	defer t.Stop()
	tick := 0
	started := time.Now() // antinet: база холодного старта для третьего сигнала (см. ниже)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Пер-воркерный снимок раз в 5 тиков (~15с) — ДИАГНОСТИКА, не сигнал (см. workerhealth.go).
		// Нужен, чтобы отличить два невидимых механизма потерь: молчащий воркер (tx>0, rx=0) от
		// дропов диспетчера в `!sent`-ветке. Последние выводятся арифметически: WG отдал wgTx, а
		// воркеры записали в DTLS Σtx — систематическое расхождение и есть выброшенное.
		//
		// Туннельные байты идут в строке ВСЕГДА: это ровно тот счётчик, по которому выносит
		// вердикт второй сигнал, а строка разбора обязана показывать ВХОД решения, а не его
		// приблизительный аналог (прежняя печатала WG-срез, которого в `rawtun` нет вовсе —
		// разбирающий видел одни воркерные суммы и не мог сказать, что «видел» watchdog).
		if tick++; tick%5 == 0 {
			if line := workerHealthLine(); line != "" {
				rx, tx, _ := w.tunnelByteSnapshot()
				wg := ""
				if wgRx, wgTx, ok := relayByteSnapshot(); ok {
					wg = fmt.Sprintf(" wgRx=%dB wgTx=%dB", wgRx, wgTx)
				}
				log.Printf("[WRKDIAG] tunRx=%dB tunTx=%dB%s | %s", rx, tx, wg, line)
			}
		}
		// antinet: ТРЕТИЙ сигнал — «транспорт не встал НИ РАЗУ». Идёт ПЕРВЫМ, потому что оба
		// сигнала ниже по построению требуют уже поднятого транспорта: `wgHandshakeFails` растёт
		// только когда WG есть и хендшейкает, `bytesSayRelayDead` сравнивает байты туннеля,
		// которых до его подъёма ещё нет. Фаза холодного старта ими не покрыта вовсе — воркеры
		// молча висят в хендшейке (или,
		// в прямом режиме, ждут первого пакета с провода), watchdog молчит, и наверх не уходит
		// ничего (замер: девять TURN-сессий открыты, ноль `Connection established
		// OK`, ноль входящих от релея, 40с тишины).
		//
		// Порог — по стенным часам от старта, а не по тикам: сюда попадает и TURN Allocate, и
		// DTLS-хендшейк (у него свой потолок 50с в session.go), поэтому окно берём с запасом за
		// него. Исход ОДИН с остальными сигналами (`onSilent` → re-spawn, а на `relayMaxRespawns`
		// → giveUpCh): свежие TURN-сокеты — единственное, что может помочь, а если и они молчат,
		// модуль обязан сдаться ГРОМКО, а не висеть до бюджета хоста.
		if !transportEverEstablished.Load() && time.Since(started) > relayColdStartBudget {
			w.onSilent("transport never established (relays not answering)")
			continue
		}
		if wgHandshakeFails.Load() >= relayStuckThreshold {
			w.onSilent("WG handshake stuck") // логирует сам (FIRE / СДАЁМСЯ); cooldown-тики молчат
			continue
		}
		// Handshake'и проходят ИЛИ их вообще не пытались — по ПЕРВОМУ сигналу релей не мёртв. Но именно
		// «не пытались» и есть слепое пятно (см. relaySilentTicks): свежая WG-сессия handshake не просит,
		// а релей за это время мог замолчать. Спрашиваем второй сигнал, прежде чем признать релей живым.
		if w.bytesSayRelayDead() {
			w.onSilent("rx silent while tx grows")
			continue
		}
		w.onHealthy()
	}
}

func (w *relayWatchdog) onHealthy() {
	w.mu.Lock()
	w.respawnStreak = 0
	w.mu.Unlock()
}

// onSilent — общий исход ОБОИХ сигналов. `reason` только для лога: раньше строка FIRE жёстко писала
// «WG handshake stuck», и после появления второго сигнала (rx/tx) вводила бы в заблуждение при разборе.
func (w *relayWatchdog) onSilent(reason string) {
	w.mu.Lock()
	if time.Since(w.lastRespawn) < relayRespawnCooldown {
		w.mu.Unlock()
		return // даём только что пере-спавненному транспорту встать (TURN+DTLS+WG handshake)
	}
	var fire func()
	gaveUp := false
	if w.respawnStreak >= relayMaxRespawns {
		gaveUp = true // дальше бессмысленно — supervisor/хендовер/юзер разрулят
	} else if w.respawn != nil {
		w.lastRespawn = time.Now()
		w.respawnStreak++
		fire = w.respawn
	}
	streak := w.respawnStreak
	w.mu.Unlock()
	switch {
	case fire != nil:
		// wgHandshakeFails НЕ сбрасываем: новый транспорт хендшейкнёт → recordWgHandshakeOK обнулит +
		// onHealthy сбросит streak (recovery); не хендшейкнёт (релей реально мёртв) → счётчик растёт,
		// onSilent после cooldown сделает re-spawn #2 (до cap'а). cooldown гасит повторный фаер в окне.
		log.Printf("[relayWatchdog] FIRE re-spawn #%d (%s → txCancel)", streak, reason)
		resetWorkerStats() // воркеры пересоздаются с теми же ID — старые цифры мешать с новыми нельзя
		resetDeafState()   // и бюджет пере-дозвонов: он относится к спавну, а не к процессу
		emitProgress("%s", qwS.lostContactRelay)
		emitLog(qwS.relaySpawnFmt, streak, reason)
		fire()
	case gaveUp:
		log.Printf("[relayWatchdog] GIVING UP after %d re-spawns", streak)
		emitProgress("%s", qwS.cannotRecoverRelay)
		emitLog(qwS.relayGaveUpFmt, streak, reason)
		// ТИПИЗИРОВАННО хосту (MODULE_API §2.13) тем же приёмом, что и сдача супервизора выше:
		// `fatal` = «сам не поднимусь». Стоит ПЕРЕД сворачиванием, чтобы маркер успел уйти в
		// stdout прежде, чем процесс закончится: после смерти сказать уже нечем.
		emitStatus(statusFatal, "relay watchdog exhausted re-spawns")
		// ...и не остаёмся жить трупом: своими силами транспорт не поднимается, значит нужен
		// свежий процесс, а поднять его может только хост — по СМЕРТИ слота (см. shutdownModule).
		shutdownModule("relay watchdog gave up after " + strconv.Itoa(streak) + " re-spawns")
	default:
		// cooldown активен — молчим (re-spawn ещё устанавливается)
	}
}

// deviceIDFor — стабильный device-id (GETCONF; сервер может привязать пароль к устройству).
func deviceIDFor(password, peer string) string {
	h := sha256.Sum256([]byte("antinet-qwdtt|" + password + "|" + peer))
	return hex.EncodeToString(h[:8])
}

// bringUpTunnelAndSocks живёт в socks5.go, рядом с serveSocks5, от которого она зависит.
