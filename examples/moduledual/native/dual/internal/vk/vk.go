// Package vk — shared VK hash / mode layer for the dual module.
//
// Base: CSQTT AntiNet policy (hashMode ↔ vkAuthMode, manual hashes from settings).
// TURN credential fetch stays path-specific:
//   - csqtt:// → rust engine (vkcalls / captcha)
//   - qwdtt:// → internal/qwdtt.GetCreds
//
// This package unifies *which hashes and which VK modes* both branches use.
package vk

import (
	"fmt"
	"strings"
)

// Mode is the CSQTT-aligned pair used before connect.
type Mode struct {
	Hash string // manual | auto_api | auto_js
	Auth string // vkcalls | auto_js | legacy | anonymous | account
}

// NormalizeHashMode mirrors CSQTT helper policy.
func NormalizeHashMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto", "auto_api":
		return "auto_api"
	case "auto_js":
		return "auto_js"
	default:
		return "manual"
	}
}

// NormalizeAuthMode accepts CSQTT and qWDTT setting values.
func NormalizeAuthMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "legacy", "captcha", "капча":
		return "legacy"
	case "auto_js":
		return "auto_js"
	case "anonymous":
		return "anonymous" // qWDTT
	case "account":
		return "account" // qWDTT
	default:
		return "vkcalls"
	}
}

// NormalizeModes — CSQTT VkModePolicy: manual hashes force non-auto_js auth.
func NormalizeModes(hashRaw, authRaw string) Mode {
	hash := NormalizeHashMode(hashRaw)
	auth := NormalizeAuthMode(authRaw)
	if hash == "manual" {
		if auth == "auto_js" {
			auth = "vkcalls"
		}
		return Mode{Hash: "manual", Auth: auth}
	}
	if auth == "auto_js" || hash == "auto_js" {
		return Mode{Hash: "auto_js", Auth: "auto_js"}
	}
	return Mode{Hash: hash, Auth: auth}
}

// NeedsOAuth — CSQTT paths that require a VK access token in the helper.
func NeedsOAuth(m Mode) bool {
	return m.Hash == "auto_api" || m.Hash == "auto_js" || m.Auth == "auto_js"
}

// NormalizeHashToken strips join-link wrappers down to the call hash.
func NormalizeHashToken(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	if i := strings.Index(low, "vk.com/call/join/"); i >= 0 {
		s = s[i+len("vk.com/call/join/"):]
	} else if i := strings.Index(low, "join/"); i >= 0 && strings.Contains(low, "call") {
		s = s[i+len("join/"):]
	}
	if j := strings.IndexAny(s, "?#&"); j >= 0 {
		s = s[:j]
	}
	return strings.Trim(s, "/")
}

func splitHashField(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if h := NormalizeHashToken(part); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// SettingsHashes reads SETTING_vkHash1..4 (and legacy SETTING_vkHashes CSV).
func SettingsHashes(cfg map[string]string) []string {
	var raw []string
	for i := 1; i <= 4; i++ {
		raw = append(raw, cfg[fmt.Sprintf("SETTING_vkHash%d", i)])
	}
	raw = append(raw, cfg["SETTING_vkHashes"])
	return dedupe(splitHashField(strings.Join(raw, ",")))
}

// CollectHashes merges link hashes with settings hashes (link first, then settings). Dedupes.
func CollectHashes(linkHashes []string, cfg map[string]string) []string {
	var all []string
	for _, h := range linkHashes {
		all = append(all, NormalizeHashToken(h))
	}
	all = append(all, SettingsHashes(cfg)...)
	return dedupe(all)
}

// ParseHashList splits a CSV/space hash field from a link.
func ParseHashList(raw string) []string {
	return dedupe(splitHashField(raw))
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
