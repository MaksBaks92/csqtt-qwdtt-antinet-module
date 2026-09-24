// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Soft handover ("rebind"): the phone moved Wi-Fi ↔ cellular, every TURN socket is bound to
//! the old network (VpnService.protect pins the netId) and every relay allocation to the old
//! 5-tuple, so all paths are dead by definition. Instead of stopping the whole engine (which
//! throws away VK credentials, the dispatcher flow table and 3–8 s), bump an epoch: every
//! session ends with `NET_REBIND`, the worker loop immediately re-allocates with the cached
//! credentials over fresh sockets (new network), the dispatcher keeps its flows, TCP inside the
//! tunnel retransmits and survives.
//!
//! Also drives the uplink/downlink stall detector: "we keep sending, nothing comes back" for a
//! few seconds is the black-hole signature of a network that Android still lists as up (Wi-Fi
//! lingering after the phone walked out of range). That triggers a *probe* (`wake::signal`),
//! not a rebind — a Refresh through each path fails fast on dead ones and is harmless on live.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, futures::Notified};

static EPOCH: AtomicU64 = AtomicU64::new(0);

fn notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}

fn notified() -> Notified<'static> {
    notify().notified()
}

/// Resolves once the epoch moves past `seen` (register-then-check idiom).
pub async fn requested(seen: u64) {
    loop {
        let changed = notified();
        if epoch() != seen {
            return;
        }
        changed.await;
    }
}

/// Tear down every session and re-allocate on the current network with cached credentials.
pub fn request(source: &str) {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    notify().notify_waiters();
    crate::log_error!(
        "[СЕТЬ] Смена сети ({source}) — пересоздаю TURN-пути на новой сети с текущими кредами"
    );
}

/// Uplink/downlink stall detector, fed with the cumulative byte counters every `POLL`.
/// Returns true when a probe should be issued: uplink advanced on `STALL_POLLS` consecutive
/// polls while downlink did not, and the previous probe is older than `PROBE_MIN_GAP`.
pub(crate) struct StallDetector {
    last_up: i64,
    last_down: i64,
    stalled_polls: u32,
    last_probe: Option<Instant>,
}

pub(crate) const STALL_POLL: Duration = Duration::from_secs(2);
const STALL_POLLS: u32 = 3;
/// Ignore tiny uplink ticks (TURN keepalive / stats) — only probe when real traffic moved.
const STALL_MIN_UPLINK_DELTA: i64 = 4096;
const PROBE_MIN_GAP: Duration = Duration::from_secs(20);

impl StallDetector {
    pub(crate) fn new(up: i64, down: i64) -> Self {
        Self {
            last_up: up,
            last_down: down,
            stalled_polls: 0,
            last_probe: None,
        }
    }

    pub(crate) fn observe(&mut self, up: i64, down: i64, now: Instant) -> bool {
        let up_delta = up.saturating_sub(self.last_up);
        let up_moved = up_delta >= STALL_MIN_UPLINK_DELTA;
        let down_moved = down != self.last_down;
        self.last_up = up;
        self.last_down = down;
        if down_moved || !up_moved {
            // Either the path answers, or there is no evidence (nothing sent) — not a stall.
            self.stalled_polls = 0;
            return false;
        }
        self.stalled_polls += 1;
        if self.stalled_polls < STALL_POLLS {
            return false;
        }
        if self
            .last_probe
            .is_some_and(|previous| now.duration_since(previous) < PROBE_MIN_GAP)
        {
            return false;
        }
        self.last_probe = Some(now);
        self.stalled_polls = 0;
        true
    }
}

pub async fn stall_monitor(
    stats: std::sync::Arc<crate::stats::Stats>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut detector = StallDetector::new(
        stats.total_bytes_up.load(Ordering::Relaxed),
        stats.total_bytes_down.load(Ordering::Relaxed),
    );
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(STALL_POLL) => {}
        }
        if crate::stats::ACTIVE_PATHS.load(Ordering::Acquire) <= 0 {
            // Nothing READY to probe; workers are already reconnecting.
            continue;
        }
        let up = stats.total_bytes_up.load(Ordering::Relaxed);
        let down = stats.total_bytes_down.load(Ordering::Relaxed);
        if detector.observe(up, down, Instant::now()) {
            crate::wake::signal(Duration::ZERO, "stall: uplink без ответа");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stall_needs_consecutive_polls_of_uplink_without_downlink() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(0, 0);
        assert!(!d.observe(STALL_MIN_UPLINK_DELTA, 0, t0)); // 1
        assert!(!d.observe(STALL_MIN_UPLINK_DELTA * 2, 0, t0)); // 2
        assert!(d.observe(STALL_MIN_UPLINK_DELTA * 3, 0, t0)); // 3 → probe
    }

    #[test]
    fn stall_ignores_tiny_uplink_ticks() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(0, 0);
        for up in [1_i64, 2, 3, 100, 500] {
            assert!(!d.observe(up, 0, t0));
        }
    }

    #[test]
    fn downlink_or_silence_resets_the_streak() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(0, 0);
        assert!(!d.observe(100, 0, t0));
        assert!(!d.observe(200, 50, t0)); // answer arrived → reset
        assert!(!d.observe(300, 50, t0));
        assert!(!d.observe(400, 50, t0));
        assert!(d.observe(500, 50, t0));
        let mut quiet = StallDetector::new(0, 0);
        assert!(!quiet.observe(100, 0, t0));
        assert!(!quiet.observe(100, 0, t0)); // nothing sent → no evidence
        assert!(!quiet.observe(200, 0, t0));
        assert!(!quiet.observe(300, 0, t0));
        assert!(quiet.observe(400, 0, t0));
    }

    #[test]
    fn probes_are_rate_limited() {
        let t0 = Instant::now();
        let mut d = StallDetector::new(0, 0);
        for up in [
            STALL_MIN_UPLINK_DELTA,
            STALL_MIN_UPLINK_DELTA * 2,
            STALL_MIN_UPLINK_DELTA * 3,
        ] {
            let _ = d.observe(up, 0, t0);
        }
        // Still stalled right after a probe: no second probe inside the gap.
        for up in [
            STALL_MIN_UPLINK_DELTA * 4,
            STALL_MIN_UPLINK_DELTA * 5,
            STALL_MIN_UPLINK_DELTA * 6,
        ] {
            assert!(!d.observe(up, 0, t0 + Duration::from_secs(6)));
        }
        // The streak kept growing; once the gap has passed the next stalled poll probes again.
        assert!(d.observe(STALL_MIN_UPLINK_DELTA * 7, 0, t0 + PROBE_MIN_GAP));
        assert!(!d.observe(
            STALL_MIN_UPLINK_DELTA * 8,
            0,
            t0 + PROBE_MIN_GAP + Duration::from_secs(2)
        ));
    }

    #[tokio::test]
    async fn request_wakes_waiters_and_moves_epoch() {
        let seen = epoch();
        let waiter = tokio::spawn(requested(seen));
        tokio::task::yield_now().await;
        request("test");
        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("waiter must resolve")
            .expect("join");
        assert_eq!(epoch(), seen + 1);
    }
}
