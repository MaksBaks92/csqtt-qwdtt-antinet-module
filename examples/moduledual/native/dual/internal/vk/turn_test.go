package vk

import "testing"

func TestTurnCache(t *testing.T) {
	PutTurn(TurnSeed{
		Hash:        "https://vk.com/call/join/abcHASH",
		Username:    "1:user",
		Password:    "pass",
		ServerAddrs: []string{"turn:x:3478"},
		ExpiresUnix: 0, // no expiry
	})
	s, ok := LookupTurn("abcHASH")
	if !ok || s.Username != "1:user" || len(s.ServerAddrs) != 1 {
		t.Fatalf("lookup failed: ok=%v %#v", ok, s)
	}
	seeds := SeedsForHashes([]string{"abcHASH", "missing"})
	if len(seeds) != 1 {
		t.Fatalf("seeds=%d", len(seeds))
	}
}
