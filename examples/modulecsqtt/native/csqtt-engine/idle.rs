// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Idle scale-down: keep a couple of "keeper" TURN paths while the phone is not sending
//! anything, bring the full worker set back the moment real traffic appears.
//!
//! Why: every READY worker emits a ChannelData keepalive each 10 s plus Refresh / permission /
//! channel maintenance; N unsynchronised workers wake the radio every ~10/N s and keep it out of
//! its idle state — that is the main battery cost of an otherwise silent tunnel. On wake-up from
//! sleep all N paths are dead and reconnect at once. With `keep` keepers both problems shrink to
//! keep/N, and the keepers' control plane (keepalive 10 s, Refresh 300 s, maintenance 175 s) is
//! **independent of user traffic**: it keeps the NAT mapping, the relay allocation and the server
//! session alive even when nothing is sent through the tunnel. The keepers also carry whatever
//! light traffic does happen (push ACKs, DNS) while the rest is parked.
//!
//! N is whatever the user configured (`workers` setting, passed in via `reset`); nothing here is
//! tied to a particular worker count. `keep` is the `idleWorkers` setting (default 2).
//!
//! Enter: uplink stays below one packet-sized delta per poll for `after`. Small chatter (TCP
//! ACKs, DNS, push heartbeats) does not postpone it. Keepers then re-GETCONF with
//! `desired_count = keep` and a bumped `generation` so the server drops the parked workers
//! from its RouteTable (otherwise it would stripe downlink onto dead sessions for up to 10 h
//! and emit STREAM_REPAIR after 30 s).
//! Exit: a real burst — several new TCP connections within a few seconds or a dozen uplink
//! packets within a second. Keepers re-GETCONF with the user's full `workers` count; parked
//! ids reconnect on the same epoch.
//!
//! State is process-global (one engine per process) so that sessions and the packet bridge hot
//! path can consult it without plumbing through every constructor. `netlost` pause is a separate
//! axis (`PauseGate`): parking never tears down paths on pause, only on idle.

use crate::stats::Stats;
use std::{
    sync::{
        Arc, LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, futures::Notified};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_KEEP: usize = 2;
pub const DEFAULT_AFTER: Duration = Duration::from_secs(180);
const POLL: Duration = Duration::from_secs(5);
/// Uplink delta per poll above which the phone is "doing something" (one MTU-sized packet).
const ACTIVE_BYTES_PER_POLL: i64 = 1400;
/// Exit thresholds.
const EXIT_PACKETS: u64 = 12;
const EXIT_PACKETS_WINDOW_MS: u64 = 1_000;
const EXIT_SYNS: u64 = 3;
const EXIT_SYNS_WINDOW_MS: u64 = 3_000;

#[derive(Clone, Copy, Debug)]
pub struct IdleConfig {
    /// Workers kept alive while idle; 0 disables the feature.
    pub keep: usize,
    pub after: Duration,
}

static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static TOTAL_WORKERS: AtomicUsize = AtomicUsize::new(0);
/// `desired_count` advertised in GETCONF (keep while idle, user total otherwise).
static DECLARED: AtomicUsize = AtomicUsize::new(0);
/// Added to the session's base generation so idle enter is a new server epoch.
static GEN_OFFSET: AtomicU64 = AtomicU64::new(0);
/// Bumped on enter/exit so live keepers re-GETCONF without tearing the TURN path.
static ANNOUNCE: AtomicU64 = AtomicU64::new(0);
static PACKET_WINDOW_START_MS: AtomicU64 = AtomicU64::new(0);
static PACKET_WINDOW_COUNT: AtomicU64 = AtomicU64::new(0);
static SYN_WINDOW_START_MS: AtomicU64 = AtomicU64::new(0);
static SYN_WINDOW_COUNT: AtomicU64 = AtomicU64::new(0);
static CLOCK: LazyLock<Instant> = LazyLock::new(Instant::now);
/// `GEN_OFFSET + 1` of the epoch this worker last put on the server. 0 = never joined.
/// Index is the 1-based worker id. Server accepts at most 126.
const JOINED_SLOTS: usize = 127;
static JOINED: [AtomicU64; JOINED_SLOTS] = [const { AtomicU64::new(0) }; JOINED_SLOTS];

fn notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

fn clock_ms() -> u64 {
    CLOCK.elapsed().as_millis() as u64
}

/// Engine (re)start: everything unparked.
pub fn reset(total_workers: usize) {
    TOTAL_WORKERS.store(total_workers, Ordering::Release);
    DECLARED.store(total_workers, Ordering::Release);
    LIMIT.store(usize::MAX, Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
    GEN_OFFSET.store(0, Ordering::Release);
    ANNOUNCE.store(0, Ordering::Release);
    for slot in &JOINED {
        slot.store(0, Ordering::Release);
    }
    notify().notify_waiters();
}

/// Remember the epoch this worker just advertised. `offset` is the `GEN_OFFSET` baked into
/// that GETCONF, not a later read: a bump between send and ack must not look like a join.
pub fn note_path_joined(worker_id: usize, offset: u64) {
    let Some(slot) = JOINED.get(worker_id) else {
        return;
    };
    if worker_id == 0 {
        return;
    }
    slot.store(offset.saturating_add(1), Ordering::Release);
}

/// A live worker died outside idle-park / rebind / repair. Bump generation once per epoch,
/// and only if this worker had actually joined it. A burst on the same epoch is one bump:
/// the first CAS wins, the rest already point at a stale route the new GETCONF drops.
/// A worker that re-GETCONFs onto the new epoch and then dies opens the next epoch, so the
/// server does not stripe that fresh route until STREAM_REPAIR.
pub fn note_path_lost(worker_id: usize) {
    if !allows(worker_id) {
        return;
    }
    let Some(slot) = JOINED.get(worker_id) else {
        return;
    };
    let joined = slot.load(Ordering::Acquire);
    if joined == 0 {
        return;
    }
    let current = GEN_OFFSET.load(Ordering::Acquire);
    if joined - 1 != current {
        return;
    }
    if GEN_OFFSET
        .compare_exchange(
            current,
            current.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    slot.store(0, Ordering::Release);
    ANNOUNCE.fetch_add(1, Ordering::AcqRel);
    notify().notify_waiters();
    crate::log_error!(
        "[ПУТЬ] Воркер {worker_id} упал — новая эпоха, живые пути перерегистрируются вместе"
    );
}

pub fn declared_count() -> usize {
    match DECLARED.load(Ordering::Acquire) {
        0 => TOTAL_WORKERS.load(Ordering::Acquire),
        n => n,
    }
}

pub fn generation(base: u64) -> u64 {
    base.saturating_add(generation_offset())
}

pub fn generation_offset() -> u64 {
    GEN_OFFSET.load(Ordering::Acquire)
}

pub fn announce_epoch() -> u64 {
    ANNOUNCE.load(Ordering::Acquire)
}

/// Resolves once keepers should re-GETCONF (register-then-check).
pub async fn announce_changed(seen: u64) {
    loop {
        let changed = notified();
        if announce_epoch() != seen {
            return;
        }
        changed.await;
    }
}

pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Worker ids are 1-based; keepers are the lowest ids.
pub fn allows(worker_id: usize) -> bool {
    worker_id <= LIMIT.load(Ordering::Acquire)
}

pub fn notified() -> Notified<'static> {
    notify().notified()
}

/// Resolves once `worker_id` is parked. Register-then-check idiom (see `PauseGate`).
pub async fn parked(worker_id: usize) {
    loop {
        let changed = notified();
        if !allows(worker_id) {
            return;
        }
        changed.await;
    }
}

pub fn enter(keep: usize) {
    let total = TOTAL_WORKERS.load(Ordering::Acquire);
    if keep == 0 || total == 0 || keep >= total {
        return;
    }
    if ACTIVE.swap(true, Ordering::AcqRel) {
        return;
    }
    LIMIT.store(keep, Ordering::Release);
    DECLARED.store(keep, Ordering::Release);
    GEN_OFFSET.fetch_add(1, Ordering::AcqRel);
    ANNOUNCE.fetch_add(1, Ordering::AcqRel);
    PACKET_WINDOW_COUNT.store(0, Ordering::Relaxed);
    SYN_WINDOW_COUNT.store(0, Ordering::Relaxed);
    notify().notify_waiters();
    crate::log_error!(
        "[IDLE] Нет трафика — оставляю {keep} из {total} воркеров (GETCONF desired={keep}, новая эпоха); остальные паркую"
    );
}

pub fn exit(reason: &str) {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    LIMIT.store(usize::MAX, Ordering::Release);
    let total = TOTAL_WORKERS.load(Ordering::Acquire);
    DECLARED.store(total, Ordering::Release);
    ANNOUNCE.fetch_add(1, Ordering::AcqRel);
    notify().notify_waiters();
    crate::log_error!("[IDLE] {reason} — поднимаю воркеры до {total}");
}

/// IPv4 TCP segment with SYN set and ACK clear = a new outbound connection.
pub(crate) fn is_tcp_syn(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl + 14 {
        return false;
    }
    let flags = packet[ihl + 13];
    flags & 0x02 != 0 && flags & 0x10 == 0
}

/// Sliding-window counter on atomics: returns true when `limit` events landed within `window_ms`.
fn window_hit(
    start: &AtomicU64,
    count: &AtomicU64,
    now_ms: u64,
    window_ms: u64,
    limit: u64,
) -> bool {
    let started = start.load(Ordering::Relaxed);
    if now_ms.saturating_sub(started) > window_ms {
        start.store(now_ms, Ordering::Relaxed);
        count.store(1, Ordering::Relaxed);
        return limit <= 1;
    }
    count.fetch_add(1, Ordering::Relaxed) + 1 >= limit
}

/// Hot path (`packet_bridge::inject_packet`). One atomic load when not idle.
pub fn note_uplink(packet: &[u8]) {
    if !is_active() {
        return;
    }
    let now_ms = clock_ms();
    if is_tcp_syn(packet)
        && window_hit(
            &SYN_WINDOW_START_MS,
            &SYN_WINDOW_COUNT,
            now_ms,
            EXIT_SYNS_WINDOW_MS,
            EXIT_SYNS,
        )
    {
        exit("новые соединения");
        return;
    }
    if window_hit(
        &PACKET_WINDOW_START_MS,
        &PACKET_WINDOW_COUNT,
        now_ms,
        EXIT_PACKETS_WINDOW_MS,
        EXIT_PACKETS,
    ) {
        exit("всплеск трафика");
    }
}

/// Pure decision helper (unit-tested): quiet for long enough → enter idle.
pub(crate) fn should_enter(quiet_for: Duration, after: Duration, active: bool) -> bool {
    !active && quiet_for >= after
}

pub async fn monitor(config: IdleConfig, stats: Arc<Stats>, cancel: CancellationToken) {
    if config.keep == 0 {
        return;
    }
    let mut last_bytes = stats.total_bytes_up.load(Ordering::Relaxed);
    let mut quiet_since = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        let bytes = stats.total_bytes_up.load(Ordering::Relaxed);
        let delta = bytes - last_bytes;
        last_bytes = bytes;
        // Quiet traffic still uses every worker. The server stripes downlink across
        // the whole route table, so parking half the set cuts upload and download.
        // Only a long silence (idle keepers) shrinks the set.
        if delta > ACTIVE_BYTES_PER_POLL {
            quiet_since = Instant::now();
            continue;
        }
        if should_enter(quiet_since.elapsed(), config.after, is_active()) {
            enter(config.keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn_packet(ack: bool) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // IPv4, IHL=5
        p[9] = 6; // TCP
        p[20 + 13] = if ack { 0x12 } else { 0x02 };
        p
    }

    #[test]
    fn detects_outbound_syn_only() {
        assert!(is_tcp_syn(&syn_packet(false)));
        assert!(!is_tcp_syn(&syn_packet(true))); // SYN-ACK is not a new connection
        let mut udp = syn_packet(false);
        udp[9] = 17;
        assert!(!is_tcp_syn(&udp));
        assert!(!is_tcp_syn(&[0x45; 10]));
    }

    #[test]
    fn window_counts_events_inside_window_and_resets_outside() {
        let start = AtomicU64::new(0);
        let count = AtomicU64::new(0);
        assert!(!window_hit(&start, &count, 10_000, 1_000, 3));
        assert!(!window_hit(&start, &count, 10_200, 1_000, 3));
        assert!(window_hit(&start, &count, 10_400, 1_000, 3));
        // A late event restarts the window instead of accumulating forever.
        assert!(!window_hit(&start, &count, 20_000, 1_000, 3));
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn enter_requires_quiet_period_and_not_already_idle() {
        let after = Duration::from_secs(180);
        assert!(!should_enter(Duration::from_secs(179), after, false));
        assert!(should_enter(Duration::from_secs(180), after, false));
        assert!(!should_enter(Duration::from_secs(600), after, true));
    }

    // Single test for the global state machine: parallel tests would race on the statics.
    #[tokio::test]
    async fn park_lifecycle() {
        reset(27);
        assert!(allows(27));
        enter(2);
        assert!(is_active());
        assert!(allows(1) && allows(2));
        assert!(!allows(3) && !allows(27));
        assert_eq!(declared_count(), 2);
        assert_eq!(generation(7), 8);
        // parked() resolves promptly for a parked id.
        tokio::time::timeout(Duration::from_millis(200), parked(9))
            .await
            .expect("parked id must resolve");
        exit("test");
        assert!(!is_active());
        assert!(allows(27));
        assert_eq!(declared_count(), 27);
        assert_eq!(generation(7), 8); // offset stays; unparked workers join this epoch

        // keep >= total: nothing to park, stays inactive.
        reset(2);
        enter(2);
        assert!(!is_active());
        assert!(allows(2));
        assert_eq!(declared_count(), 2);

        // Same epoch: one death bumps, the other is already stale. A re-join then a death
        // opens the next epoch. A worker that never got GETCONF through does not.
        reset(4);
        assert_eq!(generation(7), 7);
        note_path_joined(1, 0);
        note_path_joined(2, 0);
        note_path_lost(1);
        assert_eq!(generation(7), 8);
        note_path_lost(2);
        assert_eq!(generation(7), 8);
        note_path_joined(2, 1);
        note_path_lost(2);
        assert_eq!(generation(7), 9);
        note_path_lost(2);
        note_path_lost(9);
        assert_eq!(generation(7), 9);
        reset(0);
    }
}
