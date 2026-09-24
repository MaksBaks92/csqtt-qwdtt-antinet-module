package main

import (
	"fmt"
	"strings"
	"sync"
)

func logVkDNSHint(resolver *protectedResolver) {
	if resolver == nil {
		return
	}
	// Домены апстрима (`Constants.kt`): авторизация и API живут на `vk.ru`.
	hosts := []string{"oauth.vk.ru", "api.vk.ru", "id.vk.ru", "login.vk.ru", "vk.ru"}
	type hit struct {
		host string
		part string
	}
	out := make([]hit, len(hosts))
	var wg sync.WaitGroup
	wg.Add(len(hosts))
	for i, h := range hosts {
		go func(i int, h string) {
			defer wg.Done()
			ips, err := resolver.LookupHost(h)
			if err != nil || len(ips) == 0 {
				out[i] = hit{h, h + "=FAIL"}
				return
			}
			out[i] = hit{h, fmt.Sprintf("%s=%s", h, ips[0])}
		}(i, h)
	}
	wg.Wait()
	parts := make([]string, 0, len(hosts))
	for _, h := range out {
		parts = append(parts, h.part)
	}
	// Диагностика ТОЛЬКО про резолвер самого модуля (канон `shared/dns`, off-TUN): он нужен
	// helper'у для его собственных дозвонов к VK API. К webview хоста отношения не имеет — тот
	// ходит своим стеком, и правило §2.7 даёт ему обычный публичный URL.
	emitLog("CSQTT: DNS off-TUN модуля: %s", strings.Join(parts, ", "))
}
