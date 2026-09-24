// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Авто API как в клиенте CSQTT: POST api.vk.com/method/calls.start (fallback api.vk.ru),
// хеши из ok_join_link / join_link, при остановке calls.forceFinish.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	vkAPIMethodBase     = "https://api.vk.com/method/"
	vkAPIVersion        = "5.199"
	workersPerGroup     = 9
	groupsPerVKHash     = 3
	maxWorkers          = 126
	autoCallSmallDelay  = 80 * time.Millisecond
	autoCallLargeDelay  = 202 * time.Millisecond
	autoCallMaxAttempts = 3
	finishCallsTimeout  = 8 * time.Second
)

var (
	errVkTokenInvalid = errors.New("vk access token invalid")
	vkHTTP            = &http.Client{Timeout: 16 * time.Second}
	vkBrowserUA       = "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
)

func configureVkHTTP(protectPath string, resolver *protectedResolver) {
	// Empty DNS_SERVERS → systemResolver under protect (dnsshim). Never hardcode public DNS
	// and never fall through to net.DefaultResolver (MODULE_API §4 — DNS и protect).
	if resolver == nil {
		resolver = newProtectedResolver("", protectPath)
	}
	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl(protectPath, nil),
	}
	vkHTTP = &http.Client{
		Timeout: 16 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ip := host
				if net.ParseIP(host) == nil {
					ips, lerr := resolver.LookupHost(host)
					if lerr != nil {
						return nil, lerr
					}
					if len(ips) == 0 {
						return nil, fmt.Errorf("no DNS records for %s", host)
					}
					ip = pickIPv4(ips)
				}
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
			},
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			ForceAttemptHTTP2:     false,
		},
	}
}

type vkActiveCall struct {
	CallID string
	Hash   string
}

type vkAutoStart struct {
	Hashes    []string
	Calls     []vkActiveCall
	Requested int
	Created   int
}

func (r vkAutoStart) needsRedistribution() bool {
	return r.Created > 0 && r.Created < r.Requested
}

type vkAPIEnvelope struct {
	Response json.RawMessage `json:"response"`
	Error    *struct {
		Code int    `json:"error_code"`
		Msg  string `json:"error_msg"`
	} `json:"error"`
}

type vkStartedCallJSON struct {
	CallID     string `json:"call_id"`
	JoinLink   string `json:"join_link"`
	OkJoinLink string `json:"ok_join_link"`
}

func isVkTokenInvalidCode(code int) bool {
	switch code {
	case 4, 5, 27, 28:
		return true
	default:
		return false
	}
}

func normalizeWorkerCount(requested, maximum int) int {
	if maximum < workersPerGroup {
		maximum = workersPerGroup
	}
	maximum = (maximum / workersPerGroup) * workersPerGroup
	if requested < workersPerGroup {
		requested = workersPerGroup
	}
	if requested > maximum {
		requested = maximum
	}
	return (requested / workersPerGroup) * workersPerGroup
}

func maximumWorkersForHashes(hashCount int) int {
	if hashCount < 1 {
		hashCount = 1
	}
	if hashCount > maxVkHashes {
		hashCount = maxVkHashes
	}
	return normalizeWorkerCount(hashCount*groupsPerVKHash*workersPerGroup, maxWorkers)
}

func callCountForWorkers(workers int) int {
	if workers <= 0 {
		workers = workersPerGroup * 2
	}
	for n := 1; n <= maxVkHashes; n++ {
		if workers <= maximumWorkersForHashes(n) {
			return n
		}
	}
	return maxVkHashes
}

func autoCallDelay(callCount int) time.Duration {
	if callCount <= 4 {
		return autoCallSmallDelay
	}
	return autoCallLargeDelay
}

func hashFromJoinLink(joinLink, okJoinLink string) string {
	hash := strings.TrimSpace(okJoinLink)
	if hash != "" {
		return hash
	}
	link := strings.TrimSpace(joinLink)
	if i := strings.LastIndex(link, "/"); i >= 0 {
		link = link[i+1:]
	}
	return strings.TrimRight(link, "/")
}

func startVkAutoCalls(token string, workers int) (vkAutoStart, error) {
	var out vkAutoStart
	token = strings.TrimSpace(token)
	if token == "" {
		return out, fmt.Errorf("empty vk token")
	}
	out.Requested = callCountForWorkers(workers)
	interval := autoCallDelay(out.Requested)
	nextAt := time.Time{}
	for slot := 0; slot < out.Requested; slot++ {
		if !nextAt.IsZero() {
			if wait := time.Until(nextAt); wait > 0 {
				time.Sleep(wait)
			}
		}
		nextAt = time.Now().Add(interval)

		call, err := vkStartCallWithRetry(token)
		if err != nil {
			if errors.Is(err, errVkTokenInvalid) {
				return out, err
			}
			emitLog("CSQTT: звонок VK не создан · %v", err)
			continue
		}
		out.Calls = append(out.Calls, call)
		out.Hashes = append(out.Hashes, call.Hash)
		out.Created++
		emitLog("CSQTT: звонок VK создан (%d/%d)", out.Created, out.Requested)
	}
	if out.Created == 0 {
		return out, fmt.Errorf("не удалось создать ни одного звонка VK")
	}
	if out.needsRedistribution() {
		emitLog("CSQTT: звонки VK %d/%d · потоки распределены", out.Created, out.Requested)
	}
	return out, nil
}

func vkStartCallWithRetry(token string) (vkActiveCall, error) {
	var last error
	for attempt := 0; attempt < autoCallMaxAttempts; attempt++ {
		call, err := vkStartCall(token)
		if err == nil {
			return call, nil
		}
		last = err
		if errors.Is(err, errVkTokenInvalid) {
			return vkActiveCall{}, err
		}
	}
	if last == nil {
		last = fmt.Errorf("calls.start failed")
	}
	return vkActiveCall{}, last
}

func vkStartCall(token string) (vkActiveCall, error) {
	raw, err := vkAPIRequest(context.Background(), "calls.start", token, url.Values{})
	if err != nil {
		return vkActiveCall{}, err
	}
	var parsed vkStartedCallJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return vkActiveCall{}, fmt.Errorf("calls.start parse: %w", err)
	}
	callID := strings.TrimSpace(parsed.CallID)
	hash := hashFromJoinLink(parsed.JoinLink, parsed.OkJoinLink)
	if callID == "" || hash == "" {
		return vkActiveCall{}, fmt.Errorf("пустой call_id/hash в ответе calls.start")
	}
	return vkActiveCall{CallID: callID, Hash: hash}, nil
}

func finishVkAutoCalls(token string, calls []vkActiveCall) {
	token = strings.TrimSpace(token)
	if token == "" || len(calls) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), finishCallsTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, call := range calls {
		call := call
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := vkForceFinishCall(ctx, token, call.CallID); err != nil {
				emitLog("CSQTT: звонок VK не завершён · %v", err)
				return
			}
			emitLog("CSQTT: звонок VK завершён")
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func vkForceFinishCall(ctx context.Context, token, callID string) error {
	params := url.Values{}
	params.Set("call_id", callID)
	_, err := vkAPIRequest(ctx, "calls.forceFinish", token, params)
	return err
}

func vkAPIRequest(ctx context.Context, method, token string, params url.Values) (json.RawMessage, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("v", vkAPIVersion)
	params.Set("access_token", token)
	body := params.Encode()
	var last error
	hosts := []string{vkAPIMethodBase, "https://api.vk.ru/method/"}
	for i, base := range hosts {
		raw, err := vkAPIRequestOnce(ctx, base+method, token, body)
		if err == nil {
			return raw, nil
		}
		last = err
		if errors.Is(err, errVkTokenInvalid) {
			return nil, err
		}
		if i+1 < len(hosts) && strings.Contains(err.Error(), "dial") {
			continue
		}
		return nil, err
	}
	return nil, last
}

func vkAPIRequestOnce(ctx context.Context, endpoint, token, body string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", vkBrowserUA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	resp, err := vkHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vk api %s dial: %w", endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var env vkAPIEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("vk api %s: HTTP %d: %w", endpoint, resp.StatusCode, err)
	}
	if env.Error != nil {
		if isVkTokenInvalidCode(env.Error.Code) {
			return nil, fmt.Errorf("%w: %s", errVkTokenInvalid, env.Error.Msg)
		}
		return nil, fmt.Errorf("код=%d %s", env.Error.Code, env.Error.Msg)
	}
	if len(env.Response) == 0 {
		return nil, fmt.Errorf("vk api %s: empty response", endpoint)
	}
	return env.Response, nil
}
