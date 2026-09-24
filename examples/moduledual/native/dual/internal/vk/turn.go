// Package vk — shared VK hash/mode layer and TURN credential seed cache for dual.
package vk

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// TurnSeed is a pre-fetched TURN credential for one VK call hash.
// Used so csqtt:// and qwdtt:// can share the same Go GetCreds result (seeded into the rust engine).
type TurnSeed struct {
	Hash        string   `json:"hash"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	ServerAddrs []string `json:"server_addrs"`
	ExpiresUnix int64    `json:"expires_unix,omitempty"`
}

func (t TurnSeed) Valid() bool {
	if t.Hash == "" || t.Username == "" || t.Password == "" || len(t.ServerAddrs) == 0 {
		return false
	}
	if t.ExpiresUnix > 0 && time.Now().Unix() >= t.ExpiresUnix {
		return false
	}
	return true
}

var turnMu sync.RWMutex
var turnByHash = map[string]TurnSeed{}

// PutTurn stores credentials under the normalized call hash (process-wide).
func PutTurn(seed TurnSeed) {
	seed.Hash = NormalizeHashToken(seed.Hash)
	if !seed.Valid() {
		return
	}
	turnMu.Lock()
	turnByHash[seed.Hash] = seed
	turnMu.Unlock()
}

// LookupTurn returns a still-valid seed for hash, if any.
func LookupTurn(hash string) (TurnSeed, bool) {
	hash = NormalizeHashToken(hash)
	turnMu.RLock()
	defer turnMu.RUnlock()
	s, ok := turnByHash[hash]
	if !ok || !s.Valid() {
		return TurnSeed{}, false
	}
	out := s
	out.ServerAddrs = append([]string(nil), s.ServerAddrs...)
	return out, true
}

// SeedsForHashes returns engine-ready seeds for the given hashes (skip missing/expired).
func SeedsForHashes(hashes []string) []TurnSeed {
	var out []TurnSeed
	for _, h := range hashes {
		if s, ok := LookupTurn(h); ok {
			out = append(out, s)
		}
	}
	return out
}

// FormatSeedSummary for logs (no secrets).
func FormatSeedSummary(seeds []TurnSeed) string {
	if len(seeds) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(seeds))
	for _, s := range seeds {
		parts = append(parts, fmt.Sprintf("%s(%d urls)", truncHash(s.Hash), len(s.ServerAddrs)))
	}
	return strings.Join(parts, ",")
}

func truncHash(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8] + "…"
}
