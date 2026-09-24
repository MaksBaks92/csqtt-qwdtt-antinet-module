// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"context"
	"log"
	"strings"
	"time"

	"dual-antinet/internal/vk"
)

// PrepareSharedAuth configures DNS + captcha + VK auth modes so GetCreds can run
// outside Run() (CSQTT dual path seeding rust turn_seed).
func PrepareSharedAuth(protectPath, dnsPreset, captchaMode, vkAuthMode, vkAnonPath string) {
	protectControl = dialControl(protectPath, nil)
	dnsPreset = strings.TrimSpace(dnsPreset)
	if dnsPreset == "" {
		dnsPreset = "yandex"
	}
	setupGlobalResolver(dnsPreset)
	_ = setCaptchaMode(captchaMode)
	_ = setVkAuthMode(mapAuthModeForQwdtt(vkAuthMode))
	_ = setVkAnonPath(vkAnonPath)
}

func mapAuthModeForQwdtt(csqttOrDual string) string {
	switch strings.ToLower(strings.TrimSpace(csqttOrDual)) {
	case "account":
		return "account"
	case "anonymous":
		return "anonymous"
	case "legacy", "auto_js":
		// CSQTT-native paths — still allow anonymous GetCreds as optional seed.
		return "anonymous"
	default:
		return "anonymous" // vkcalls ≈ anonymous + vkAnonPath=vkcalls
	}
}

// PrefetchTurnSeeds runs GetCreds for each hash and publishes into vk.Turn cache.
// Returns engine-ready seed maps (hash/username/password/server_addrs).
func PrefetchTurnSeeds(ctx context.Context, hashes []string) []map[string]any {
	var out []map[string]any
	for i, hash := range hashes {
		hash = vk.NormalizeHashToken(hash)
		if hash == "" {
			continue
		}
		if seed, ok := vk.LookupTurn(hash); ok {
			out = append(out, turnSeedMap(seed))
			continue
		}
		user, pass, urls, err := GetCreds(ctx, hash, 8000+i)
		if err != nil {
			log.Printf("[VK Auth] shared prefetch hash=%s: %v", hash, err)
			continue
		}
		seed := vk.TurnSeed{
			Hash:        hash,
			Username:    user,
			Password:    pass,
			ServerAddrs: urls,
		}
		vk.PutTurn(seed)
		out = append(out, turnSeedMap(seed))
	}
	return out
}

func turnSeedMap(s vk.TurnSeed) map[string]any {
	return map[string]any{
		"hash":         s.Hash,
		"username":     s.Username,
		"password":     s.Password,
		"server_addrs": s.ServerAddrs,
	}
}

// PrefetchBudget — wall clock for CSQTT shared seed before falling back to rust fetch.
const PrefetchBudget = 45 * time.Second
