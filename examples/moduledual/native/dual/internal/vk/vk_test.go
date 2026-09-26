package vk

import "testing"

func TestNormalizeModesManualBlocksAutoJS(t *testing.T) {
	m := NormalizeModes("manual", "auto_js")
	if m.Hash != "manual" || m.Auth != "vkcalls" {
		t.Fatalf("got %+v", m)
	}
}

func TestCollectHashesMergesSettingsAndLink(t *testing.T) {
	cfg := map[string]string{
		"SETTING_vkHash1": "https://vk.com/call/join/abc123",
		"SETTING_vkHash2": "abc123", // dup
	}
	got := CollectHashes([]string{"def456"}, cfg)
	if len(got) != 2 || got[0] != "def456" || got[1] != "abc123" {
		t.Fatalf("got %v", got)
	}
}

func TestCollectHashesForPrefersSchemePrefix(t *testing.T) {
	cfg := map[string]string{
		"SETTING_vkHash1":    "legacyOnly",
		"SETTING_qwdttHash1": "qwdttOnly",
		"SETTING_csqttHash1": "csqttOnly",
	}
	got := CollectHashesFor(nil, cfg, "qwdtt")
	if len(got) != 1 || got[0] != "qwdttOnly" {
		t.Fatalf("qwdtt: got %v", got)
	}
	got = CollectHashesFor(nil, cfg, "csqtt")
	if len(got) != 1 || got[0] != "csqttOnly" {
		t.Fatalf("csqtt: got %v", got)
	}
}

func TestParseHashList(t *testing.T) {
	got := ParseHashList("a, b;c")
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}
