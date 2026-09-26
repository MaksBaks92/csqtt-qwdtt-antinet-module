// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

// AntiNet-правка: оригинальный CLI `func main()` (флаги/сигналы/stdin/ping-only/печать конфига) убран —
// точку входа даёт канон `shared/entry`, а тело модуля начинается с `realMain` (run.go). Здесь осталась
// captcha-обвязка (используется creds/captcha кодом) + `runHashChecks`/классификаторы (мёртвый код без
// -check-hashes CLI, безвредно оставлен — Go не ругается на неиспользуемые top-level функции) +
// `runTransport` — вынесенный из старого main() спавн WorkerGroup'ов + захват WG-конфига (GETCONF).
//
// ⚠ Механизма VK_AUTH_REQUIRED/handleTurnCredsStdinLine (stdin-pipe «account»-авторизация) здесь
// НЕТ: он был мёртвым кодом — его не читал ни один хост.
// `requestAccountTurnCreds` (vk_account.go) вместо него реюзит §2.7 ACTION_REQUIRED+action_result
// транспорт (тот же, что captcha уже использует) — доклад о честном оставшемся пробеле (VK OAuth
// access_token без документированной цепочки конвертации в TURN-креды) там же, в её собственном
// doc-comment'е. helperConfig.VkAuthMode (SETTING_vkAuthMode, "" = anonymous по умолчанию) —
// настройка модуля, одна на обе платформы.

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CaptchaResultChan — legacy-канал токена капчи (прежний CAPTCHA_SOLVE-механизм оригинального app).
// Больше НЕ используется: requestWebViewCaptcha переписан на §2.7 ACTION_REQUIRED + action_result-файл.
var CaptchaResultChan = make(chan string, 1)

// moduleProfileDir — writable-каталог helper'а (os.Args[3]); сюда AntiNet пишет action_result.<id> для
// interactive-action капчи (§2.7). Ставится в helper.go main. captchaActionSeq — уникализатор id (стримы/попытки).
var moduleProfileDir string
var captchaActionSeq atomic.Int64

var captchaModeValue atomic.Value

func init() {
	captchaModeValue.Store("auto")
}

func normalizeCaptchaMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "rjs", "wv":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "auto"
	}
}

func setCaptchaMode(mode string) string {
	normalized := normalizeCaptchaMode(mode)
	captchaModeValue.Store(normalized)
	return normalized
}

func getCaptchaMode() string {
	mode, _ := captchaModeValue.Load().(string)
	if mode == "" {
		return "auto"
	}
	return mode
}

// drainCaptchaResult удаляет устаревший результат капчи из канала
func drainCaptchaResult() {
	select {
	case <-CaptchaResultChan:
	default:
	}
}

// runHashChecks / classifyHashCheckError / sanitizeHashCheckMessage — 1:1 upstream v1.3.5, только
// caller (CLI -check-hashes флаг) убран вместе с остальным main(). Оставлены как есть (не мёртвый код в
// строгом смысле — Go допускает недостижимые top-level функции без warning'а); при желании подключить
// hash-check как отдельную сабкоманду helper'а — это готовая точка входа.
func runHashChecks(ctx context.Context, hashes []string) {
	log.Printf("[CHECK] Checking VK hashes: %d", len(hashes))
	for i, hash := range hashes {
		fmt.Printf("HASH_CHECK_START|%d|%s\n", i+1, hash)
		checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, _, turnURLs, err := GetCreds(checkCtx, hash, 9000+i)
		cancel()

		status, message := classifyHashCheckError(err)
		if err == nil {
			status = "ok"
			message = fmt.Sprintf("TURN urls=%d", len(turnURLs))
		}
		fmt.Printf("HASH_CHECK|%d|%s|%s|%s\n", i+1, hash, status, sanitizeHashCheckMessage(message))
	}
}

func classifyHashCheckError(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "captcha_required") || strings.Contains(text, "captcha_wait_required"):
		return "captcha", "VK просит капчу"
	case strings.Contains(text, "call not found") ||
		strings.Contains(text, "joinconversationbylink") ||
		strings.Contains(text, "missing turn_server") ||
		strings.Contains(text, "9000") ||
		strings.Contains(text, "callunavailable"):
		return "dead", "Звонок не найден или закрыт"
	case strings.Contains(text, "flood") || strings.Contains(text, "rate limit") || strings.Contains(text, "error_code:29"):
		return "limited", "VK временно ограничил запросы"
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline") || strings.Contains(text, "lookup") || strings.Contains(text, "network"):
		return "network", "Сетевая ошибка"
	default:
		return "error", err.Error()
	}
}

func sanitizeHashCheckMessage(message string) string {
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	message = strings.ReplaceAll(message, "|", "/")
	if len(message) > 180 {
		return message[:180]
	}
	return message
}

// runTransport — спавн numGroups WorkerGroup'ов (TURN/DTLS/VK + WRAP) + диспетчер UDP-релея на
// localConn + захват WireGuard-конфига из первой группы (GETCONF). onWGConfig зовётся с готовым
// WG-конфигом (MTU гарантирован). Блокирует до завершения всех воркеров (ctx cancel).
// 1:1 со спавн-логикой старого main(); helper.go вызывает это в горутине.
//
// Разбивка на группы — ceiling-деление + per-group startIdx/endIdx/groupSize clamping, дословно как
// у автора (его main.go). Раньше здесь стоял расчёт по готовому numGroups, а вызывающий сам ронял
// число воркеров до кратного 9 — и workers=16 из настроек поднимало 9 релеев вместо 16, молча.
func runTransport(ctx context.Context, tp *TurnParams, peer *net.UDPAddr, localConn net.PacketConn,
	localPort string, numW int, deviceID, connPassword string, stats *Stats,
	pauseFlag *int32, cfg helperConfig, profileDir string, onWGConfig func(string)) {
	numGroups := (numW + workersPerGroup - 1) / workersPerGroup
	log.Printf("[CLIENT] Workers: %d (groups: %d, up to %d each)", numW, numGroups, workersPerGroup) // source logged in Run as [SETTINGS] workers=…

	// В rawtun диспетчер стартует БЕЗ источника пакетов: адрес/DNS/MTU назначает сервер, и
	// netstack можно создать только после RAWCONF (см. AttachTUN ниже). У автора причина та же,
	// только ждёт он не netstack, а TUN-fd от Android.
	var disp *Dispatcher
	if tp.RawMode {
		disp = NewDispatcherPendingTUN(ctx, stats)
	} else {
		disp = NewDispatcher(ctx, localConn, stats)
	}
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}

			if addrs, dns, mtu, ok := parseRawConfLine(rawConf); ok {
				// Режим rawtun. Подъём выполняется ЗДЕСЬ, а не у вызывающего (как это делает
				// режим vpn через onWGConfig → main_native → bringUpTunnelAndSocks), потому что
				// в rawtun netstack — это источник пакетов ДЛЯ ЭТОГО ЖЕ диспетчера: отдать его
				// наверх и получить обратно было бы кружным путём вокруг того же объекта.
				tio, rawErr := ensureRawTunnel(addrs, dns, mtu, profileDir, cfg)
				if rawErr != nil {
					log.Printf("[RAW] Bringing up raw tunnel failed: %v", rawErr)
					return
				}
				disp.AttachTUN(tio)
				log.Println("[RAW] Raw tunnel attached, traffic is flowing")
				// Разблокировать супервизора (wgConfCh): без этого runTransportSupervised ждёт
				// конфиг вечно и модуль выглядит зависшим — тот же класс, что закрыт giveUpCh.
				if onWGConfig != nil {
					onWGConfig(rawConf)
				}
				return
			}
			if strings.HasPrefix(rawConf, rawConfPrefix) {
				// Префикс есть, а разбор не удался — сервер прислал мусор. Молча возвращаться
				// нельзя: супервизор останется без конфига, и наверх уйдёт «зависли», а не
				// «сервер ответил ерундой».
				log.Printf("[RAW] Malformed RAWCONF from server: %q", rawConf)
				return
			}

			finalConf := rawConf
			if !strings.Contains(finalConf, "MTU =") {
				lines := strings.Split(finalConf, "\n")
				var newLines []string
				for _, line := range lines {
					newLines = append(newLines, line)
					if strings.TrimSpace(line) == "[Interface]" {
						newLines = append(newLines, "MTU = 1280")
					}
				}
				finalConf = strings.Join(newLines, "\n")
			}
			if onWGConfig != nil {
				onWGConfig(finalConf)
			}
			// Авторская ветка `activeConnMode == "socks"` (его -mode socks: userspace WG +
			// go-socks5) сюда не портируется — не как отброшенная возможность, а как уже
			// имеющаяся: наш порт ВСЕГДА отдаёт SOCKS5 хосту, причём своей реализацией
			// (socks5.go), которая перекрывает авторскую (auth, UDP ASSOCIATE, DNS-кэш,
			// гейт по семье адреса). Подъём делает main_native через bringUpTunnelAndSocks.
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1
	var prevWaitReady <-chan struct{}

	for g := 0; g < numGroups; g++ {
		isFirst := (g == 0)

		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}
		if g > 0 {
			myWaitReady = prevWaitReady
		}
		if g < numGroups-1 {
			ch := make(chan struct{})
			mySignalReady = ch
			prevWaitReady = ch
		}

		startIdx := g * workersPerGroup
		endIdx := startIdx + workersPerGroup
		if endIdx > numW {
			endIdx = numW
		}
		groupSize := endIdx - startIdx
		if groupSize <= 0 {
			continue
		}

		ids := make([]int, groupSize)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		var cc chan<- string
		if isFirst {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID int, isFirstGroup bool, configChan chan<- string, workerIds []int, startHashIndex int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			WorkerGroup(ctx, groupID, startHashIndex, tp, peer, disp, localPort,
				isFirstGroup, configChan, workerIds, pauseFlag, deviceID, connPassword, stats, waitR, sigR)
		}(gID, isFirst, cc, ids, g, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[CLIENT] All workers finished")
}

