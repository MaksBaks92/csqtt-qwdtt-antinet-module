// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const accountCredsLifetime = 9 * time.Minute

type injectedTurnCreds struct {
	Username  string
	Password  string
	URLs      []string
	ExpiresAt time.Time
}

type turnCredsPayload struct {
	User string   `json:"u"`
	Pass string   `json:"p"`
	URLs []string `json:"urls"`
}

type vkCredsFile struct {
	Hashes map[string]turnCredsPayload `json:"hashes"`
}

var (
	vkAuthModeValue     atomic.Value
	vkAnonPathValue     atomic.Value
	injectedCredsMu     sync.RWMutex
	injectedCredsByLink map[string]injectedTurnCreds
)

func init() {
	vkAuthModeValue.Store("anonymous")
	vkAnonPathValue.Store("vkcalls")
	injectedCredsByLink = make(map[string]injectedTurnCreds)
}

// setVkAuthMode — antinet: ПУСТАЯ строка = anonymous, а не account.
//
// Было `if mode != "anonymous" { mode = "account" }`, то есть пустое значение (ровно тот случай,
// который контракт называет дефолтом) молча включало account-режим — противоположность заявленного.
// Противоречие видно прямо в паре: getVkAuthMode ниже трактует "" как anonymous, но до него дело не
// доходит — setVkAuthMode зовётся на старте (run.go) и кладёт в ячейку уже "account".
// Дефолт "anonymous" объявлен ещё в двух местах: `helperConfig.VkAuthMode` («"" = anonymous») и
// `module.json` (`"default": "anonymous"`). Из четырёх мест расходилось одно — оно и правится.
//
// В проде не выстреливало, потому что хост всегда шлёт `SETTING_vkAuthMode` (override ?: default из
// дескриптора). Выстреливает на хосте, который ключ не шлёт вовсе (старая версия), и на ручном
// конфиге — там модуль уходил в account-путь, у которого есть известный незакрытый пробел
// (конвертация VK OAuth access_token в TURN-креды, см. requestAccountTurnCreds).
func setVkAuthMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "account" {
		mode = "anonymous"
	}
	vkAuthModeValue.Store(mode)
	return mode
}

func getVkAuthMode() string {
	mode, _ := vkAuthModeValue.Load().(string)
	if mode == "" {
		return "anonymous"
	}
	return mode
}

func setVkAnonPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "legacy" {
		vkAnonPathValue.Store("legacy")
		return "legacy"
	}
	vkAnonPathValue.Store("vkcalls")
	return "vkcalls"
}

func getVkAnonPath() string {
	path, _ := vkAnonPathValue.Load().(string)
	if path == "" {
		return "vkcalls"
	}
	return path
}

func injectTurnCreds(link, user, pass string, urls []string) {
	link = strings.TrimSpace(link)
	addresses := turnURLsToAddresses(urls)
	if link == "" || user == "" || pass == "" || len(addresses) == 0 {
		return
	}
	injectedCredsMu.Lock()
	defer injectedCredsMu.Unlock()
	injectedCredsByLink[link] = injectedTurnCreds{
		Username:  user,
		Password:  pass,
		URLs:      cloneStringSlice(addresses),
		ExpiresAt: time.Now().Add(accountCredsLifetime),
	}
}

func getInjectedTurnCreds(link string) (user, pass string, urls []string, ok bool) {
	link = strings.TrimSpace(link)
	injectedCredsMu.RLock()
	creds, exists := injectedCredsByLink[link]
	injectedCredsMu.RUnlock()
	if !exists {
		return "", "", nil, false
	}
	if time.Now().After(creds.ExpiresAt) {
		injectedCredsMu.Lock()
		delete(injectedCredsByLink, link)
		injectedCredsMu.Unlock()
		return "", "", nil, false
	}
	return creds.Username, creds.Password, cloneStringSlice(creds.URLs), true
}

func invalidateInjectedTurnCreds(link string) {
	link = strings.TrimSpace(link)
	injectedCredsMu.Lock()
	delete(injectedCredsByLink, link)
	injectedCredsMu.Unlock()
}

func loadVkCredsFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file vkCredsFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	for link, payload := range file.Hashes {
		injectTurnCreds(link, payload.User, payload.Pass, payload.URLs)
	}
	log.Printf("[VK Auth] Loaded %d account TURN credential set(s) from file", len(file.Hashes))
	return nil
}

// vkAutoJoinSetupJS — JS АВТОКЛИКА, портирован дословно из апстрима
// (proxy-turn-vk-android, app/src/main/java/com/wdtt/client/VkAuthWebViewManager.kt,
// VkAuthJoinScripts.AUTO_JOIN_SETUP). Страница звонка VK показывает промежуточный экран
// «Продолжить в браузере» / «Open in app»; без клика по нужной кнопке до реального захода в звонок
// (а значит и до ответа с turn_server) дело не доходит. Скрипт ставит MutationObserver и жмёт
// наиболее подходящий элемент, отсеивая «открыть в приложении».
//
// ⚠ ЭТО СОДЕРЖИМОЕ ПРИНАДЛЕЖИТ МОДУЛЮ, не AntiNet (§2.7, расширение 6): хост лишь исполняет
// присланный JS и по-прежнему не знает ни строчки про VK. Ровно поэтому скрипт живёт здесь, а не
// в ModuleActionActivity/qwdtt-captcha.
const vkAutoJoinSetupJS = `
(function() {
    if (window.__wdtt_auto_join_ready) return;
    window.__wdtt_auto_join_ready = true;
    window.__wdtt_auto_join_clicks = 0;
    window.__wdtt_auto_join_done = false;

    var rejectPhrases = [
        'открыть в приложении',
        'open in app',
        'open in the',
        'vk звонки',
        'скачать приложение'
    ];

    function norm(s) { return (s || '').replace(/\s+/g, ' ').trim().toLowerCase(); }

    function elementText(el) {
        return norm(el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '');
    }

    function scoreElement(el) {
        var text = elementText(el);
        if (!text || text.length > 120) return -1;
        for (var r = 0; r < rejectPhrases.length; r++) {
            if (text.indexOf(rejectPhrases[r]) !== -1) return -1;
        }
        if (text.indexOf('продолжить в браузере') !== -1 && text.indexOf('открыть') !== -1 && text.length > 30) return -1;
        if (text === 'продолжить в браузере' || text === 'continue in browser') return 100;
        if (text.indexOf('продолжить в браузере') !== -1) return 90 - Math.min(text.length, 80);
        if (text.indexOf('continue in browser') !== -1) return 85 - Math.min(text.length, 80);
        if (text.indexOf('присоединиться к звонку через браузер') !== -1) return 70;
        if (text.indexOf('присоединиться через браузер') !== -1) return 65;
        if (text.indexOf('войти в звонок') !== -1) return 50;
        if (text === 'продолжить' || text === 'continue') return 40;
        if (text.indexOf('продолжить') !== -1 && text.length <= 25) return 35;
        return -1;
    }

    function hasBetterChild(el, parentScore) {
        var kids = el.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]');
        for (var i = 0; i < kids.length; i++) {
            if (kids[i] === el) continue;
            if (scoreElement(kids[i]) >= parentScore) return true;
        }
        return false;
    }

    function pickBest(minScore) {
        var selectors = 'button, a, [role="button"], input[type="button"], input[type="submit"], .vkuiButton, [class*="Button"]';
        var nodes = document.querySelectorAll(selectors);
        var best = null, bestScore = -1, bestLen = 9999;
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var sc = scoreElement(el);
            if (sc < minScore) continue;
            if (hasBetterChild(el, sc)) continue;
            var tlen = elementText(el).length;
            if (sc > bestScore || (sc === bestScore && tlen < bestLen)) { best = el; bestScore = sc; bestLen = tlen; }
        }
        return best ? { el: best, score: bestScore, text: elementText(best) } : null;
    }

    function fireClick(el) {
        try { el.click(); } catch (e1) {}
        try { el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window })); } catch (e2) {}
    }

    window.__wdtt_autoJoinTry = function() {
        if (window.__wdtt_auto_join_done) return '';
        var pick = pickBest(50) || pickBest(35);
        if (!pick) return '';
        fireClick(pick.el);
        window.__wdtt_auto_join_clicks = (window.__wdtt_auto_join_clicks || 0) + 1;
        window.__wdtt_auto_join_done = true;
        return 'clicked(score=' + pick.score + '):' + pick.text.substring(0, 60);
    };

    if (!window.__wdtt_auto_join_observer) {
        window.__wdtt_auto_join_observer = new MutationObserver(function() { window.__wdtt_autoJoinTry(); });
        var root = document.documentElement || document.body;
        if (root) window.__wdtt_auto_join_observer.observe(root, { childList: true, subtree: true });
        // Апстрим дёргает попытку ещё и снаружи (AUTO_JOIN_TRY через evaluateJavascript); у нас
        // хост лишь исполняет присланный JS и наружу его не дёргает — заменяем собственным тиком.
        window.__wdtt_auto_join_timer = setInterval(function() { window.__wdtt_autoJoinTry(); }, 700);
        setTimeout(function() {
            try { window.__wdtt_auto_join_observer.disconnect(); } catch (e) {}
            try { clearInterval(window.__wdtt_auto_join_timer); } catch (e) {}
        }, 45000);
    }
})();
`

// vkTurnServer — форма объекта `turn_server`, который страница звонка VK отдаёт в своём же трафике
// (апстрим ловит его тем же перехватом fetch/XHR). Ровно этот объект хост извлекает целиком
// (расширение 1 схемы: объект уезжает как JSON.stringify, а не "[object Object]").
type vkTurnServer struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
}

// requestAccountTurnCreds — режим авторизации VK «через аккаунт»: TURN-креды забираются НЕ из
// анонимной API-цепочки, а из собственного трафика страницы звонка, открытой в живой VK-сессии.
//
// ИСТОРИЯ И ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ ПРЕЖНЕГО СОСТОЯНИЯ. Раньше здесь висел честно задокументированный
// разрыв: «правило извлекает одну строку, а из access_token в TURN-креды ведёт недокументированная
// VK-цепочка, выдумывать её нельзя». Премисса оказалась НЕВЕРНОЙ — апстрим (склонирован и прочитан,
// VkAuthWebViewManager.kt) access_token в креды НЕ конвертирует вовсе: он открывает НАСТОЯЩУЮ
// страницу звонка (m.vk.ru/call/join/<hash>, 4 URL-кандидата), автокликом проходит промежуточный
// экран и ПЕРЕХВАТЫВАЕТ `turn_server` прямо из трафика страницы. Никаких API-вызовов. Это ровно та же
// техника, что уже используется для капчи, и ровно то, что делает наше `mode=network`-правило —
// разрыв был параметрическим, а не архитектурным.
//
// ⚠ ОДНА СТАДИЯ ВМЕСТО ДВУХ (осознанное отличие от апстрима, не упущение). Апстрим ведёт headless-
// WebView программно и потому разделяет LOGIN → JOIN_CALL, проверяя cookie `remixsid`. У нас окно
// действия показывается ЧЕЛОВЕКУ и живёт в общем cookie-jar хоста: не залогинен — VK сам покажет
// свою форму входа в этом же окне, после входа сам же уведёт на страницу звонка, перехватчик
// сработает. Отдельная LOGIN-стадия дала бы лишний шаг без выигрыша.
//
// ⚠ ПРИВАТНОСТЬ, названо явно: режим требует ЖИВОЙ VK-сессии, и cookie этой сессии остаются в
// cookie-jar AntiNet (WebView Android / webview-бинарь Desktop). Это должно быть написано в карточке
// модуля и в MODULE_API, а не подразумеваться.
//
// requireFields намеренно НЕ используется: хост проверяет его пути от КОРНЯ ответа, а `turn_server`
// приходит то корнем, то внутри `response` — универсального корневого пути нет. Полноту полей
// проверяем здесь, Go-стороной, сразу после разбора.
func requestAccountTurnCreds(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	link = strings.TrimSpace(link)
	if u, p, urls, ok := getInjectedTurnCreds(link); ok {
		return u, p, urls, nil
	}
	if moduleProfileDir == "" {
		return "", "", nil, fmt.Errorf("VK account auth unavailable (profileDir not set)")
	}
	hash := normalizeVKJoinHash(link)
	if hash == "" {
		return "", "", nil, fmt.Errorf("VK account auth: could not extract call hash from link")
	}

	id := fmt.Sprintf("vkaccount-%d-%d", streamID, captchaActionSeq.Add(1))
	// 1:1 апстримовый joinUrlCandidates(hash) — расширение 5 схемы (список URL: не сработало за
	// urlTimeoutSec → следующий кандидат).
	rule := map[string]any{
		"mode": "network",
		"url": []string{
			"https://m.vk.ru/call/join/" + hash,
			"https://vk.ru/call/join/" + hash,
			"https://m.vk.com/call/join/" + hash,
			"https://vk.com/call/join/" + hash,
		},
		// URL ответа со стороны VK непредсказуем → фильтруем по ТЕЛУ (расширение 3), а сам объект
		// берём по первому найденному из двух альтернативных путей (расширение 2).
		"bodyPattern":   "turn_server",
		"jsonPath":      []string{"turn_server", "response.turn_server"},
		"injectJs":      vkAutoJoinSetupJS,
		"urlTimeoutSec": 45,
	}
	pj, _ := json.Marshal(rule)
	fmt.Printf("ACTION_REQUIRED|%s|%s\n", id, base64.StdEncoding.EncodeToString(pj))
	_ = os.Stdout.Sync()
	log.Printf("[STREAM %d] [VK Auth] Waiting for VK login and joining the call (link=%s...)", streamID, shortLink(link))

	// Результат — каналом (канон shared/hostproto); файл остаётся фоллбэком (§3).
	s, gaveUp := awaitActionResult(ctx, moduleProfileDir, id, 5*time.Minute)
	if gaveUp {
		if ctx.Err() != nil {
			return "", "", nil, ctx.Err()
		}
		return "", "", nil, fmt.Errorf("VK account auth timeout")
	}
	if s == "" || s == "CANCELLED" {
		return "", "", nil, fmt.Errorf("VK account auth cancelled")
	}
	if strings.HasPrefix(strings.ToLower(s), "error:") {
		return "", "", nil, fmt.Errorf("VK account auth failed: %s", s)
	}
	// Хост мог отдать значение как есть либо в base64 (та же «эхо-идиома», что у капчи) — принимаем обе формы.
	if dec, derr := base64.StdEncoding.DecodeString(s); derr == nil && strings.HasPrefix(strings.TrimSpace(string(dec)), "{") {
		s = strings.TrimSpace(string(dec))
	}
	var ts vkTurnServer
	if jerr := json.Unmarshal([]byte(s), &ts); jerr != nil {
		return "", "", nil, fmt.Errorf("VK account auth: turn_server does not parse: %v", jerr)
	}
	if ts.Username == "" || ts.Credential == "" || len(ts.URLs) == 0 {
		return "", "", nil, fmt.Errorf("VK account auth: turn_server incomplete (username=%v credential=%v urls=%d)",
			ts.Username != "", ts.Credential != "", len(ts.URLs))
	}
	// injectTurnCreds сам нормализует turn:/turns:-URL в host:port и кладёт в кэш по ссылке —
	// дальше anonymous- и account-пути неотличимы для остального кода.
	injectTurnCreds(link, ts.Username, ts.Credential, ts.URLs)
	u, p, urls, ok := getInjectedTurnCreds(link)
	if !ok {
		return "", "", nil, fmt.Errorf("VK account auth: TURN addresses could not be extracted from urls=%v", ts.URLs)
	}
	log.Printf("[STREAM %d] [VK Auth] Received account TURN creds (urls=%d)", streamID, len(urls))
	return u, p, urls, nil
}

func shortLink(link string) string {
	if len(link) <= 8 {
		return link
	}
	return link[:8]
}

func fetchAccountVkCreds(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	if u, p, urls, ok := getInjectedTurnCreds(link); ok {
		log.Printf("[STREAM %d] [VK Auth] Using injected account creds (urls=%d)", streamID, len(urls))
		return u, p, urls, nil
	}
	return requestAccountTurnCreds(ctx, link, streamID)
}
