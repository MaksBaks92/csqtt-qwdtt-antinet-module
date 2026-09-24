// SPDX-License-Identifier: MIT
//
// Ручной ввод VK-хешей — контрактным правилом `type: "form"` (MODULE_API §2.7): хост сам рисует
// нативный диалог с полями на обеих платформах и возвращает значения объектом. Ни HTML, ни
// локального HTTP-сервера, ни разбора URL для этого не нужно.

package main

import (
	"fmt"
	"strings"
	"time"
)

func promptManualHashes(profileDir string, prefill []string, s csqttStrings) ([]string, error) {
	if profileDir == "" {
		if len(prefill) > 0 {
			return prefill, nil
		}
		return nil, fmt.Errorf("%s", s.missingHashes)
	}

	fields := make([]map[string]any, 0, maxVkHashes)
	for i := 0; i < maxVkHashes; i++ {
		f := map[string]any{
			"key":   fmt.Sprintf("hash%d", i+1),
			"label": fmt.Sprintf(s.hashFormLabelFmt, i+1),
			"type":  "text",
		}
		if i < len(prefill) {
			f["default"] = prefill[i]
		}
		fields = append(fields, f)
	}

	emitProgress("%s", s.hashFormProgress)
	id := fmt.Sprintf("vk-hashes-%d", time.Now().UnixNano())
	res, cancelled := runAction(profileDir, id, map[string]any{
		"type":   "form",
		"title":  s.hashFormTitle,
		"text":   s.hashFormHint,
		"fields": fields,
	})
	if cancelled {
		if len(prefill) > 0 {
			return prefill, nil
		}
		return nil, fmt.Errorf("%s", s.hashFormCancelled)
	}
	parsed := parseHashFormResult(res)
	if len(parsed) == 0 {
		return prefill, nil
	}
	return parsed, nil
}

// parseHashFormResult разбирает ответ действия: `{"type":"form","values":{"hash1":…}}`.
// Плоский объект без `values` и голая строка тоже принимаются — ответ приходит каналом от хоста,
// и разбор не должен зависеть от того, завернул ли его хост в конверт.
func parseHashFormResult(res string) []string {
	res = strings.TrimSpace(res)
	if res == "" || strings.EqualFold(res, "CANCELLED") {
		return nil
	}
	if obj := actionResultEnvelope(res); obj != nil {
		if v, ok := obj["values"].(map[string]any); ok {
			obj = v
		}
		raw := make([]string, 0, maxVkHashes)
		for i := 1; i <= maxVkHashes; i++ {
			raw = append(raw, fmt.Sprint(obj[fmt.Sprintf("hash%d", i)]))
		}
		return uniqHashes(raw)
	}
	return uniqHashes([]string{res})
}

func uniqHashes(raw []string) []string {
	seen := make(map[string]struct{}, maxVkHashes)
	out := make([]string, 0, maxVkHashes)
	for _, chunk := range raw {
		if chunk == "<nil>" {
			continue
		}
		for _, h := range splitHashes(chunk) {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
			if len(out) >= maxVkHashes {
				return out
			}
		}
	}
	return out
}
