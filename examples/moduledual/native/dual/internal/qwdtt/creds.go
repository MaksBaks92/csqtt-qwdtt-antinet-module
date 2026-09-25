// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

// ─── VK Credential Sets (2 stable app_id with rotating fallback) ───

type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "MuAxFaKDYDOICzGnEOhp"},
	{ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"},
}

// CallUnavailableError is a non-retryable VK error about the call/link itself:
// the call was ended/deleted or the join link is invalid. Retrying another
// client_id or solving captcha cannot fix this.
type CallUnavailableError struct {
	Code    int
	Message string
}

func (e *CallUnavailableError) Error() string {
	if e == nil {
		return "VK call is unavailable"
	}
	if e.Message != "" {
		return fmt.Sprintf("VK returns error: %s (error_code=%d)", e.Message, e.Code)
	}
	return fmt.Sprintf("VK call is unavailable (error_code=%d)", e.Code)
}

func asCallUnavailableError(err error) (*CallUnavailableError, bool) {
	var callErr *CallUnavailableError
	if errors.As(err, &callErr) {
		return callErr, true
	}
	return nil, false
}

func fatalCallError(resp map[string]interface{}) *CallUnavailableError {
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		return nil
	}

	code := vkErrorCode(errObj["error_code"])
	switch {
	case code == 951, code == 954:
		// VKCalls messages.*: call not found / invalid join link.
	case code >= 9000 && code <= 9999:
		// Legacy calls.getAnonymousToken call-domain errors.
	default:
		return nil
	}

	msg, _ := errObj["error_msg"].(string)
	return &CallUnavailableError{Code: code, Message: msg}
}

func vkErrorCode(raw interface{}) int {
	switch v := raw.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}

const vkCredentialAttemptLimit = 4

// ─── Credential Caching ───

type TurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	ExpiresAt   time.Time
	Link        string
}

type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

var streamsPerCache = 10

func getCacheID(streamID int) int {
	return streamID / streamsPerCache
}

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	link := c.creds.Link
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)
	if link != "" {
		invalidateLastCredsByLink(link)
	}

	log.Printf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

func cloneStringSlice(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	now := time.Now().Unix()

	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	log.Printf("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	if count >= maxCacheErrors {
		log.Printf("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d", count, cacheID)
		cache.invalidate(streamID)
		return true
	}
	return false
}

// ─── Captcha lockout ───

var globalCaptchaLockout atomic.Int64

const (
	captchaAutoWebViewTimeout     = 10 * time.Second
	captchaManualWebViewTimeout   = 60 * time.Second
	captchaSelectedWebViewTimeout = 120 * time.Second
)

// ─── Random delay ───

func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// ─── Cached credential fetcher ───

func getVkCredsCached(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p := cache.creds.Username, cache.creds.Password
		addr := cache.creds.ServerAddrs[streamID%len(cache.creds.ServerAddrs)]
		addrs := cloneStringSlice(cache.creds.ServerAddrs)
		cache.mutex.RUnlock()
		log.Printf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v, selected=%s, urls=%d)", streamID, cacheID, expires.Truncate(time.Second), addr, len(addrs))
		return u, p, addrs, nil
	}
	cache.mutex.RUnlock()

	// Чужой cache-слот / предыдущий fetch уже получил креды на этот же hash — не открываем
	// капчу/auth снова (G2 при одном хеше, prefetch vs group, и т.п.).
	if shared, ok := findCachedCredsByLink(link); ok {
		cache.mutex.Lock()
		cache.creds = shared
		cache.mutex.Unlock()
		log.Printf("[STREAM %d] [VK Auth] Reusing credentials from another cache slot (link=%s..., urls=%d)", streamID, shortLink(link), len(shared.ServerAddrs))
		return shared.Username, shared.Password, cloneStringSlice(shared.ServerAddrs), nil
	}
	vkRequestMu.Lock()
	if shared, ok := peekLastCredsByLink(link); ok {
		vkRequestMu.Unlock()
		cache.mutex.Lock()
		cache.creds = shared
		cache.mutex.Unlock()
		log.Printf("[STREAM %d] [VK Auth] Reusing credentials from last-fetch map (link=%s..., urls=%d)", streamID, shortLink(link), len(shared.ServerAddrs))
		return shared.Username, shared.Password, cloneStringSlice(shared.ServerAddrs), nil
	}
	vkRequestMu.Unlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double-check inside lock
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		return cache.creds.Username, cache.creds.Password, cloneStringSlice(cache.creds.ServerAddrs), nil
	}

	// antinet §4.2: креды, восстановленные хостом из MODULE_STATE (см. credstate.go). Заходим
	// СЮДА, а не в отдельную ветку выше, ровно по одной причине: это единственное место, откуда
	// стартует вся дорогая VK-цепочка, и подмена именно здесь пропускает её целиком — включая
	// капчу — не размазывая логику восстановления по остальному коду.
	if rc, ok := takeRestoredCreds(link); ok {
		cache.creds = rc
		return rc.Username, rc.Password, cloneStringSlice(rc.ServerAddrs), nil
	}

	user, pass, addrs, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		return "", "", nil, err
	}

	cache.creds = TurnCredentials{
		Username:    user,
		Password:    pass,
		ServerAddrs: addrs,
		ExpiresAt:   time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:        link,
	}
	// antinet §4.2 — отдать свежие креды хосту НЕПРОЗРАЧНЫМ блобом (credstate.go). На каждом
	// успешном получении, включая refresh: иначе блоб у хоста отставал бы от реальности и на
	// следующем resume мы бы восстановились на уже протухших.
	SaveCredsToHost(cache.creds)
	return user, pass, cloneStringSlice(addrs), nil
}

// findCachedCredsByLink — любой непросроченный cache-слот с тем же VK-hash.
// TryRLock: вызывается и из-под cache.mutex.Lock() (fetchVkCredsSerialized) — свой слот
// просто пропускаем, иначе дедлок на нереентерабельном RWMutex.
func findCachedCredsByLink(link string) (TurnCredentials, bool) {
	link = strings.TrimSpace(link)
	if link == "" {
		return TurnCredentials{}, false
	}
	now := time.Now()
	credentialsStore.mu.RLock()
	defer credentialsStore.mu.RUnlock()
	for _, c := range credentialsStore.caches {
		if !c.mutex.TryRLock() {
			continue
		}
		ok := c.creds.Link == link && now.Before(c.creds.ExpiresAt) && len(c.creds.ServerAddrs) > 0
		if !ok {
			c.mutex.RUnlock()
			continue
		}
		out := TurnCredentials{
			Username:    c.creds.Username,
			Password:    c.creds.Password,
			ServerAddrs: cloneStringSlice(c.creds.ServerAddrs),
			ExpiresAt:   c.creds.ExpiresAt,
			Link:        c.creds.Link,
		}
		c.mutex.RUnlock()
		return out, true
	}
	return TurnCredentials{}, false
}

// ─── Serialized (throttled) fetcher ───

var (
	vkRequestMu           sync.Mutex
	globalLastVkFetchTime time.Time
	// lastCredsByLink — креды по VK-hash под vkRequestMu: пока A ещё держит cache.mutex
	// после fetch, B уже может взять vkRequestMu и обязан увидеть чужой результат без
	// повторного ACTION_REQUIRED.
	lastCredsByLink = map[string]TurnCredentials{}
)

func peekLastCredsByLink(link string) (TurnCredentials, bool) {
	link = strings.TrimSpace(link)
	c, ok := lastCredsByLink[link]
	if !ok || time.Now().After(c.ExpiresAt) || len(c.ServerAddrs) == 0 {
		return TurnCredentials{}, false
	}
	out := c
	out.ServerAddrs = cloneStringSlice(c.ServerAddrs)
	return out, true
}

func storeLastCredsByLink(link, user, pass string, addrs []string) TurnCredentials {
	tc := TurnCredentials{
		Username:    user,
		Password:    pass,
		ServerAddrs: cloneStringSlice(addrs),
		ExpiresAt:   time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:        strings.TrimSpace(link),
	}
	lastCredsByLink[tc.Link] = tc
	return tc
}

func invalidateLastCredsByLink(link string) {
	link = strings.TrimSpace(link)
	vkRequestMu.Lock()
	delete(lastCredsByLink, link)
	vkRequestMu.Unlock()
}

func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	if shared, ok := peekLastCredsByLink(link); ok {
		log.Printf("[STREAM %d] [VK Auth] Reusing credentials after queue wait (link=%s..., urls=%d)", streamID, shortLink(link), len(shared.ServerAddrs))
		return shared.Username, shared.Password, cloneStringSlice(shared.ServerAddrs), nil
	}

	// Throttle: 3-6 seconds between requests
	minInterval := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	elapsed := time.Since(globalLastVkFetchTime)

	if !globalLastVkFetchTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		log.Printf("[STREAM %d] [VK Auth] Throttling: waiting %v to prevent rate limit...", streamID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return "", "", nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	user, pass, addrs, err := fetchVkCreds(ctx, link, streamID)
	globalLastVkFetchTime = time.Now()
	if err != nil {
		return "", "", nil, err
	}
	storeLastCredsByLink(link, user, pass, addrs)
	return user, pass, cloneStringSlice(addrs), nil
}

// ─── Main credential fetcher (rotates through stable credential sets) ───

func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	if getVkAuthMode() == "account" {
		return fetchAccountVkCreds(ctx, link, streamID)
	}

	if time.Now().Unix() < globalCaptchaLockout.Load() {
		return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	if getVkAnonPath() == "vkcalls" {
		if user, pass, addrs, err := getVKCredsViaVKCallsPath(ctx, link, streamID); err == nil {
			log.Printf("[STREAM %d] [VK Auth] Success via VK Calls path", streamID)
			return user, pass, addrs, nil
		} else {
			if callErr, ok := asCallUnavailableError(err); ok {
				log.Printf("[STREAM %d] [VK Auth] VK Calls path returned non-retryable call error: %v", streamID, callErr)
				return "", "", nil, callErr
			}
			log.Printf("[STREAM %d] [VK Auth] VK Calls path failed (%s), falling back to legacy", streamID, describeVKCallsFailure(err))
		}
	} else {
		log.Printf("[STREAM %d] [VK Auth] Legacy path selected, skipping VK Calls", streamID)
	}

	var lastErr error
	jar := tlsclient.NewCookieJar()

	for attempt := 0; attempt < vkCredentialAttemptLimit; attempt++ {
		creds := vkCredentialsList[attempt%len(vkCredentialsList)]
		log.Printf("[STREAM %d] [VK Auth] Trying credentials: client_id=%s (attempt %d/%d)", streamID, creds.ClientID, attempt+1, vkCredentialAttemptLimit)

		user, pass, addrs, err := getTokenChain(ctx, link, streamID, creds, jar)

		if err == nil {
			log.Printf("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addrs, nil
		}

		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] Failed with client_id=%s: %v", streamID, creds.ClientID, err)

		if callErr, ok := asCallUnavailableError(err); ok {
			return "", "", nil, callErr
		}

		if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
			return "", "", nil, err
		}

		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "error_code: 29") || strings.Contains(err.Error(), "Rate limit") {
			log.Printf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}

		if attempt%len(vkCredentialsList) == len(vkCredentialsList)-1 && attempt+1 < vkCredentialAttemptLimit {
			wait := time.Duration(900+rand.Intn(900)) * time.Millisecond
			log.Printf("[STREAM %d] [VK Auth] Both VK credentials failed, retrying stable pair after %v...", streamID, wait)
			select {
			case <-ctx.Done():
				return "", "", nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	return "", "", nil, fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// ─── Token chain: anon_token → getCallPreview → getAnonymousToken → OK session → joinConversation → TURN creds ───

func getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials, jar tlsclient.CookieJar) (string, string, []string, error) {
	profile := getRandomProfile()
	if saved, err := LoadProfileFromDisk(); err == nil && saved != nil && strings.TrimSpace(saved.UserAgent) != "" {
		profile = saved.Profile
		log.Printf("[STREAM %d] [VK Auth] Using device profile from vk_profile.json", streamID)
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsClientDialerOption(), // AntiNet: VK API дозванивается off-TUN, под protect'ом (dial.go)
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("[STREAM %d] [VK Auth] Identity - Name: %s | UA: %s", streamID, name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Step 1: get_anonym_token
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 2: getCallPreview (mimics real VK client behavior)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		log.Printf("[STREAM %d] [VK Auth] Warning: getCallPreview failed: %v", streamID, err)
	} else if callErr := fatalCallError(resp); callErr != nil {
		log.Printf("[STREAM %d] [VK Auth] getCallPreview returned non-retryable call error: %v", streamID, callErr)
		return "", "", nil, callErr
	}

	vkDelayRandom(200, 400)

	// Step 3: getAnonymousToken (with captcha handling)
	originalData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	data = originalData
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	var token2 string
	var savedProfile *SavedProfile
	savedProfile, _ = LoadProfileFromDisk()
	// Один WBV на ОДНУ captcha-сессию (SessionToken). Повторный диалог по тому же sid почти
	// никогда не помогает. Новая сессия от VK (другой SessionToken) — новый WBV разрешён:
	// Legacy getAnonymousToken часто требует 2 разных капчи подряд; глобальный «один WBV навсегда»
	// ломал именно Legacy token.
	interactiveSessions := make(map[string]struct{})

	for attempt := 0; ; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			if callErr := fatalCallError(resp); callErr != nil {
				log.Printf("[STREAM %d] [VK Auth] getAnonymousToken returned non-retryable call error: %v", streamID, callErr)
				return "", "", nil, callErr
			}

			captchaErr := parseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.RedirectURI != "" && captchaErr.SessionToken != "" {
				_, alreadyShown := interactiveSessions[captchaErr.SessionToken]
				if attempt >= 3 || alreadyShown {
					if alreadyShown {
						log.Printf("[STREAM %d] [Captcha] VK still rejected after WebView for this captcha session — stopping", streamID)
					} else {
						log.Printf("[STREAM %d] [Captcha] Max attempts reached", streamID)
					}
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				successToken, usedInteractive, solveErr := solveCaptchaBySelectedMode(ctx, streamID, attempt+1, captchaErr, client, profile, savedProfile)
				if solveErr != nil {
					if errors.Is(solveErr, errCaptchaSessionExpired) {
						log.Printf("[STREAM %d] [CAPTCHA] session exhausted - requesting a new captcha from VK", streamID)
						savedProfile, _ = LoadProfileFromDisk()
						data = originalData
						vkDelayRandom(800, 1500)
						continue
					}
					log.Printf("[STREAM %d] [Captcha] Solve failed: %v", streamID, solveErr)
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}
				if usedInteractive {
					interactiveSessions[captchaErr.SessionToken] = struct{}{}
				}

				captchaAttempt := captchaErr.CaptchaAttempt
				if captchaAttempt == "0" || captchaAttempt == "" {
					captchaAttempt = "1"
				}

				data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
					link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaAttempt, token1)
				continue
			}
			return "", "", nil, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", nil, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", nil, fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	vkDelayRandom(100, 150)

	// Step 4: OK.ru anonymLogin
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing session_key in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 5: joinConversationByLink → TURN creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, ok := tsRaw["username"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing username in turn_server")
	}
	pass, ok := tsRaw["credential"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing credential in turn_server")
	}
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, fmt.Errorf("missing or empty urls in turn_server")
	}

	log.Printf("[STREAM %d] [VK Auth] TURN urls (%d total):", streamID, len(urlsRaw))
	for i, u := range urlsRaw {
		log.Printf("[STREAM %d] [VK Auth]   [%d] %v", streamID, i, u)
	}

	var addresses []string
	for _, u := range urlsRaw {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		addresses = append(addresses, turnURLsToAddresses([]string{urlStr})...)
	}

	if len(addresses) == 0 {
		return "", "", nil, fmt.Errorf("no valid TURN addresses found")
	}

	return user, pass, addresses, nil
}

func markCaptchaSessionExpired(streamID int) error {
	if _, err := rotateCaptchaBrowserFP(); err != nil {
		log.Printf("[STREAM %d] [CAPTCHA] failed to refresh browser_fp: %v", streamID, err)
	} else {
		log.Printf("[STREAM %d] [CAPTCHA] browser_fp refreshed after session exhaustion", streamID)
	}
	return errCaptchaSessionExpired
}

// solveCaptchaBySelectedMode returns (token, usedInteractiveWebView, err).
// usedInteractiveWebView=true means an ACTION_REQUIRED dialog was shown; caller must not open another.
func solveCaptchaBySelectedMode(
	ctx context.Context,
	streamID int,
	attempt int,
	captchaErr *VkCaptchaError,
	client tlsclient.HttpClient,
	profile Profile,
	savedProfile *SavedProfile,
) (string, bool, error) {
	if fresh, err := rotateCaptchaProfile(); err == nil {
		savedProfile = fresh
	} else {
		log.Printf("[STREAM %d] [CAPTCHA] profile rotate failed: %v", streamID, err)
	}

	switch getCaptchaMode() {
	case "wv":
		log.Printf("[STREAM %d] [CAPTCHA] WBV: mode from Android settings (attempt %d)", streamID, attempt)
		token, err := requestWebViewCaptcha(streamID, captchaErr, "selected", captchaSelectedWebViewTimeout)
		return token, true, err
	case "rjs":
		log.Printf("[STREAM %d] [CAPTCHA] RJS: Go v2 selected in settings (attempt %d)", streamID, attempt)
		token, solveErr := solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, 2)
		if solveErr == nil {
			return token, false, nil
		}
		if ctx.Err() != nil {
			return "", false, solveErr
		}
		if isCaptchaSessionDead(solveErr) {
			log.Printf("[STREAM %d] [CAPTCHA] RJS: captcha session is dead, requesting a new one from VK", streamID)
			return "", false, markCaptchaSessionExpired(streamID)
		}
		if isCaptchaSessionExhausted(solveErr) {
			log.Printf("[STREAM %d] [CAPTCHA] RJS: rate limit, falling back to WBV Auto", streamID)
			token, err := requestWebViewCaptcha(streamID, captchaErr, "auto", captchaAutoWebViewTimeout)
			return token, true, err
		}
		log.Printf("[STREAM %d] [CAPTCHA] RJS: error, falling back to WBV Auto: %v", streamID, solveErr)
		token, err := requestWebViewCaptcha(streamID, captchaErr, "auto", captchaAutoWebViewTimeout)
		return token, true, err
	}

	log.Printf("[STREAM %d] [CAPTCHA] AUTO: chain start (captcha attempt %d)", streamID, attempt)

	token, solveErr := solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, 2)
	if solveErr == nil {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: Go v2 solved the captcha", streamID)
		return token, false, nil
	}
	if ctx.Err() != nil {
		return "", false, solveErr
	}
	lastErr := solveErr
	if isCaptchaSessionDead(solveErr) {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: captcha session is dead, requesting a new one from VK", streamID)
		return "", false, markCaptchaSessionExpired(streamID)
	}
	if errors.Is(solveErr, errCaptchaV2RateLimit) || strings.Contains(strings.ToLower(solveErr.Error()), "rate limit") {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: rate limit on Go v2, trying WBV", streamID)
	}
	log.Printf("[STREAM %d] [CAPTCHA] AUTO: Go v2 did not solve it in 2 attempts: %v", streamID, solveErr)

	// Один WebView на всю цепочку: раньше было 2× auto + manual = до 3 ACTION_REQUIRED подряд.
	log.Printf("[STREAM %d] [CAPTCHA] AUTO: WBV attempt (timeout %s)", streamID, captchaAutoWebViewTimeout)
	token, solveErr = requestWebViewCaptcha(streamID, captchaErr, "auto", captchaAutoWebViewTimeout)
	if solveErr == nil {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: WBV solved the captcha", streamID)
		return token, true, nil
	}
	if ctx.Err() != nil {
		return "", true, solveErr
	}
	lastErr = solveErr
	if isWebViewCaptchaTimeout(solveErr) {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: WBV timeout, final Go v2 attempt", streamID)
	} else {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: WBV error: %v; final Go v2 attempt", streamID, solveErr)
	}

	token, solveErr = solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, 1)
	if solveErr == nil {
		log.Printf("[STREAM %d] [CAPTCHA] AUTO: final Go v2 solved the captcha", streamID)
		return token, true, nil // WBV already shown once
	}
	if ctx.Err() != nil {
		return "", true, solveErr
	}
	log.Printf("[STREAM %d] [CAPTCHA] AUTO: final Go v2 error: %v", streamID, solveErr)
	if lastErr != nil {
		return "", true, fmt.Errorf("automatic captcha chain failed: %w; final Go v2: %v", lastErr, solveErr)
	}
	return "", true, solveErr
}

// requestWebViewCaptcha — ручное решение VK-капчи через WebView/webview ХОСТА (AntiNet interactive-action,
// MODULE_API §2.7). Эмитит `ACTION_REQUIRED|<id>|<payloadB64>` (payload = JSON {mode,redirectUri,
// sessionToken}) + БЛОКИРУЯСЬ поллит `<profileDir>/action_result.<id>`; результат — VK success_token (тот
// же, что отдаёт Go-решатель) либо CANCELLED/error. Заменяет прежний `CAPTCHA_SOLVE|…→CaptchaResultChan`
// (механизм оригинального net.qwdtt.client app, дропнутый при порте в модуль) проверенным §2.7-контрактом —
// теперь капча-fallback РАБОТАЕТ кроссплатформенно (Android WebView / Desktop встроенный webview).
func requestWebViewCaptcha(streamID int, captchaErr *VkCaptchaError, mode string, timeout time.Duration) (string, error) {
	if captchaErr == nil || captchaErr.RedirectURI == "" || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("webview captcha data is incomplete")
	}
	if moduleProfileDir == "" {
		return "", fmt.Errorf("webview captcha unavailable (profileDir not set)")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "manual" && mode != "selected" {
		mode = "auto"
	}
	if timeout <= 0 {
		timeout = captchaAutoWebViewTimeout
	}

	id := fmt.Sprintf("captcha-%d-%d", streamID, captchaActionSeq.Add(1))
	// ДЕКЛАРАТИВНОЕ ПРАВИЛО вместо прежнего непрозрачного payload'а {mode,redirectUri,sessionToken}
	// (§2.5 контракта, MODULE_API.md). Раньше расшифровать этот payload умела ТОЛЬКО Activity из
	// APK самого модуля — с уходом APK-модели её негде взять, и капча стала бы неразрешимой. Теперь
	// хост исполняет правило сам (Android — ModuleActionActivity, Desktop — actionBinary-webview), а
	// модуль не несёт ни строчки UI.
	//
	// endpointPattern/jsonPath — СТРОГО captchaNotRobot.check → data.response.success_token, ровно то,
	// что принимает VK: скан любого ответа даёт error_code:10 (проверено оригинальным
	// ManlCaptchaActivity). sessionToken в правило не входит — он не нужен исполнителю: страница
	// redirectUri уже содержит сессию, а результат берётся из её собственного трафика.
	pj, _ := json.Marshal(map[string]any{
		"mode":            "network",
		"url":             captchaErr.RedirectURI,
		"endpointPattern": "captchaNotRobot.check",
		"jsonPath":        []string{"response.success_token"},
	})
	_ = mode                                                                         // режим (auto/manual/selected) выбирает СТРАТЕГИЮ модуля, исполнителю правила он не нужен
	fmt.Printf("ACTION_REQUIRED|%s|%s\n", id, base64.StdEncoding.EncodeToString(pj)) // stdout → AntiNet рисует действие
	_ = os.Stdout.Sync()

	// Результат приходит КАНАЛОМ (stdin на desktop / antinet_module_event в Android-слоте), файловый
	// путь остаётся фоллбэком для старого хоста — см. awaitActionResult (канон shared/hostproto, §3).
	res, gaveUp := awaitActionResult(context.Background(), moduleProfileDir, id, timeout)
	if gaveUp {
		return "", fmt.Errorf("webview captcha timed out")
	}
	if res == "" {
		return "", fmt.Errorf("webview captcha returned empty result")
	}
	if res == "CANCELLED" { // §2.7: отмена/нет UI/hard-cap → как fail (caller трактует)
		return "", fmt.Errorf("webview captcha cancelled")
	}
	if strings.HasPrefix(strings.ToLower(res), "error:") {
		return "", fmt.Errorf("webview captcha failed: %s", res)
	}
	// base64-результат от хоста = VK success_token (== выход Go-решателя). Декодим (echo-идиома).
	if dec, derr := base64.StdEncoding.DecodeString(res); derr == nil && len(strings.TrimSpace(string(dec))) > 0 {
		res = strings.TrimSpace(string(dec))
	}
	log.Printf("[STREAM %d] [CAPTCHA] WBV: %s solve succeeded (manual)", streamID, mode)
	return res, nil
}

func isWebViewCaptchaTimeout(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "timed out")
}

func turnURLsToAddresses(urls []string) []string {
	var addresses []string
	for _, urlStr := range urls {
		urlStr = strings.TrimSpace(urlStr)
		if urlStr == "" {
			continue
		}
		clean := strings.Split(urlStr, "?")[0]
		address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if address != "" {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// ─── GetCreds returns TURN credentials for a given stream ───

func GetCreds(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	return getVkCredsCached(ctx, link, streamID)
}

// ─── DNS dialer setup ───

func goDNSServersForPreset(preset string) []string {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "cloudflare":
		return []string{"1.1.1.1:53", "1.0.0.1:53"}
	case "google":
		return []string{"8.8.8.8:53", "8.8.4.4:53"}
	default:
		return []string{"77.88.8.8:53", "77.88.8.1:53"}
	}
}

func isLoopbackDNSAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost" || host == "0.0.0.0"
}

func goDNSServersForArg(arg string) []string {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "custom:") {
		raw := strings.TrimPrefix(arg, "custom:")
		var out []string
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.Contains(part, ":") {
				part += ":53"
			}
			out = append(out, part)
		}
		if len(out) > 0 {
			return out
		}
		return goDNSServersForPreset("yandex")
	}
	return goDNSServersForPreset(arg)
}

func goDNSLabel(arg string) string {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "custom:") {
		return "Свой DNS"
	}
	if strings.HasPrefix(arg, "doh:") {
		return "Свой DoH"
	}
	switch strings.ToLower(arg) {
	case "cloudflare":
		return "Cloudflare"
	case "google":
		return "Google DNS"
	case "doh-cloudflare":
		return "Cloudflare DoH"
	case "doh-google":
		return "Google DoH"
	case "doh-yandex":
		return "Яндекс DoH"
	default:
		return "Яндекс DNS"
	}
}

func formatGoDNSServers(servers []string) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			parts = append(parts, s)
			continue
		}
		if port == "53" {
			parts = append(parts, host)
		} else {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

func setupGlobalResolver(arg string) {
	arg = strings.TrimSpace(arg)
	if goDNSIsDoH(arg) {
		setupDoHResolver(arg, goDoHEndpointsForArg(arg))
		return
	}

	servers := goDNSServersForArg(arg)
	log.Printf(
		"[SETTINGS] DNS for VK: %s (%s) - UDP/TCP :53",
		goDNSLabel(arg),
		formatGoDNSServers(servers),
	)

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var lastErr error
			for _, dns := range servers {
				// AntiNet: DNS-резолв off-TUN, под protect'ом (dial.go) — см. dialWithTimeout's
				// doc-comment про timeout-семантику (mirror прежнего net.Dialer{Timeout:3s}).
				conn, err := dialWithTimeout(ctx, "udp", dns, 3*time.Second)
				if err == nil {
					return conn, nil
				}
				lastErr = err
				conn, err = dialWithTimeout(ctx, "tcp", dns, 3*time.Second)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			address = strings.TrimSpace(address)
			if address != "" && !isLoopbackDNSAddress(address) {
				conn, err := dialWithTimeout(ctx, network, address, 3*time.Second)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no DNS servers available for %q", arg)
			}
			return nil, lastErr
		},
	}
}
