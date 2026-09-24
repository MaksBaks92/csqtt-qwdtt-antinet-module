// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Suspend/resume detector ("the tunnel must not oversleep").
//!
//! On Android `Instant` and every tokio timer run on `CLOCK_MONOTONIC`, which **stops while the
//! CPU is suspended** (doze between maintenance windows, screen-off deep sleep). After the phone
//! wakes the engine believes only a few seconds passed: no TURN Refresh is due, no keepalive is
//! due, `allocation_expires_at` is still far away — while the relay allocation, the NAT mapping
//! and the server session aged by minutes. The result is a tunnel that looks alive and forwards
//! nothing until three 20 s dial-timeouts trigger a full engine recycle.
//!
//! `CLOCK_BOOTTIME` keeps counting through suspend. A cheap poll compares the two clocks; when
//! boottime advanced noticeably more than monotonic we were asleep for the difference. That is
//! published as a *wake epoch*: every TURN driver re-validates its path right away (immediate
//! Refresh = request/response through the NAT) or fails fast if the allocation certainly expired,
//! so workers reconnect within seconds instead of a minute.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, futures::Notified};
use tokio_util::sync::CancellationToken;

/// While awake the poll costs one clock read per tick; during suspend the timer does not run.
const POLL: Duration = Duration::from_secs(3);
/// Shorter gaps are covered by the regular 10 s keepalive and RTO machinery.
pub(crate) const SUSPEND_THRESHOLD: Duration = Duration::from_secs(20);

static EPOCH: AtomicU64 = AtomicU64::new(0);
static LAST_GAP_MS: AtomicU64 = AtomicU64::new(0);

fn notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

/// Monotonic-across-suspend clock: `CLOCK_BOOTTIME` on Linux/Android, wall clock elsewhere.
pub(crate) fn boottime_now() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid pointer to a timespec; CLOCK_BOOTTIME is always available on these OSes.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 {
            return Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        }
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// Bumped on every detected wake (or explicit nudge). Drivers compare against the value they saw.
pub(crate) fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}

/// Suspend duration attached to the latest epoch. Zero for an explicit host nudge.
pub(crate) fn last_gap() -> Duration {
    Duration::from_millis(LAST_GAP_MS.load(Ordering::Acquire))
}

/// Registers interest in the next epoch bump. Combine with an `epoch()` check at the top of the
/// loop: `notify_waiters` only reaches futures that are already registered.
pub(crate) fn notified() -> Notified<'static> {
    notify().notified()
}

/// Publish a wake: `gap` is how long monotonic time stood still (0 = "just re-validate").
pub(crate) fn signal(gap: Duration, source: &str) {
    LAST_GAP_MS.store(gap.as_millis().min(u128::from(u64::MAX)) as u64, Ordering::Release);
    EPOCH.fetch_add(1, Ordering::AcqRel);
    notify().notify_waiters();
    if gap.is_zero() {
        crate::log_error!("[КЛИЕНТ] Проверка TURN-путей по запросу ({source})");
    } else {
        crate::log_error!(
            "[КЛИЕНТ] Пробуждение после {}с сна ({source}) — проверяю TURN-пути",
            gap.as_secs()
        );
    }
}

/// Pure decision helper (unit-tested): how long the process was suspended between two samples.
pub(crate) fn suspend_gap(mono_elapsed: Duration, boot_elapsed: Duration) -> Duration {
    boot_elapsed.saturating_sub(mono_elapsed)
}

pub(crate) async fn monitor(cancel: CancellationToken) {
    let mut mono = Instant::now();
    let mut boot = boottime_now();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        let now_mono = Instant::now();
        let now_boot = boottime_now();
        let gap = suspend_gap(
            now_mono.saturating_duration_since(mono),
            now_boot.saturating_sub(boot),
        );
        mono = now_mono;
        boot = now_boot;
        if gap >= SUSPEND_THRESHOLD {
            signal(gap, "suspend");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_gap_is_boottime_minus_monotonic() {
        assert_eq!(
            suspend_gap(Duration::from_secs(3), Duration::from_secs(603)),
            Duration::from_secs(600)
        );
        // Clock jitter in the other direction never yields a bogus wake.
        assert_eq!(
            suspend_gap(Duration::from_secs(3), Duration::from_secs(2)),
            Duration::ZERO
        );
    }

    #[test]
    fn signal_bumps_epoch() {
        // Globals are shared with the other tests in this module (they may run in parallel),
        // so only monotonic growth is asserted.
        let before = epoch();
        signal(Duration::from_secs(42), "test");
        assert!(epoch() > before);
    }

    #[tokio::test]
    async fn notified_wakes_registered_waiter() {
        let waiter = notified();
        tokio::pin!(waiter);
        // Register interest before signalling (the documented idiom).
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );
        signal(Duration::ZERO, "test");
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must be woken by signal");
    }

    #[test]
    fn boottime_is_monotonic_nondecreasing() {
        let a = boottime_now();
        let b = boottime_now();
        assert!(b >= a);
    }
}
