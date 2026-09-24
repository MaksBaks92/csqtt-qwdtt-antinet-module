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

func TestParseHashList(t *testing.T) {
	got := ParseHashList("a, b;c")
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}
