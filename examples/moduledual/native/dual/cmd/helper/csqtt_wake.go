// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"time"
)

// Suspend detector for the helper (mirror of the engine's wake.rs).
//
// Go's monotonic clock is CLOCK_MONOTONIC, which on Android stops while the CPU is suspended
// (doze, screen-off deep sleep); the wall clock keeps going. When wall time advanced noticeably
// more than monotonic time between two ticks, the process was asleep for the difference.
// Timers and tickers do not fire during suspend, so the poll costs nothing while asleep.

const (
	wakePollInterval     = 3 * time.Second
	wakeSuspendThreshold = 20 * time.Second
)

// suspendGap — how long the process was suspended between two time.Now() samples.
// time.Time carries both readings: Sub() uses monotonic, Round(0) strips it → wall.
func suspendGap(prev, now time.Time) time.Duration {
	return suspendGapFrom(now.Sub(prev), now.Round(0).Sub(prev.Round(0)))
}

func suspendGapFrom(monoElapsed, wallElapsed time.Duration) time.Duration {
	if gap := wallElapsed - monoElapsed; gap > 0 {
		return gap
	}
	return 0
}

// startWakeMonitor — calls onWake(gap) from its own goroutine after each detected suspend.
func startWakeMonitor(ctx context.Context, onWake func(gap time.Duration)) {
	go func() {
		t := time.NewTicker(wakePollInterval)
		defer t.Stop()
		prev := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			now := time.Now()
			gap := suspendGap(prev, now)
			prev = now
			if gap >= wakeSuspendThreshold && onWake != nil {
				onWake(gap)
			}
		}
	}()
}
