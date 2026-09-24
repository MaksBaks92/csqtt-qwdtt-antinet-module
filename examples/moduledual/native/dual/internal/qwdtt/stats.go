// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"log"
	"sync/atomic"
	"time"
)

type Stats struct {
	TotalBytesUp      atomic.Int64
	TotalBytesDown    atomic.Int64
	ActiveConnections atomic.Int32
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			active := s.ActiveConnections.Load()
			up := s.TotalBytesUp.Load()
			down := s.TotalBytesDown.Load()
			totalMB := float64(up+down) / (1024.0 * 1024.0)
			upMB := float64(up) / (1024.0 * 1024.0)
			downMB := float64(down) / (1024.0 * 1024.0)

			// Апстрим 1.4.3 добавил разбивку ↓/↑ — берём её, но лейблы остаются АНГЛИЙСКИМИ:
			// это dev-лог (root CLAUDE.md § «Разработческий лог — только английский»).
			log.Printf("[STATS] Active: %d | Traffic: %.2f MB | down %.2f MB / up %.2f MB", active, totalMB, downMB, upMB)
		}
	}
}
