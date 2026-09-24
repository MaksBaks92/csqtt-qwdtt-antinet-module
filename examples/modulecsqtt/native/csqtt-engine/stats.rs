// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    client_perf::{self, Stage as PerfStage},
    events::Events,
};
use std::sync::{
    Arc,
    atomic::{AtomicI32, AtomicI64, Ordering},
};
use tokio_util::sync::CancellationToken;

/// Process-wide mirror of `Stats::active_connections` for the FFI (`csqtt_engine_active_paths`):
/// the helper reads it before every SOCKS dial so it can hold a CONNECT for a few seconds while
/// workers reconnect after sleep instead of burning the 20 s dial timeout.
pub static ACTIVE_PATHS: AtomicI32 = AtomicI32::new(0);

#[derive(Default)]
pub struct Stats {
    pub total_bytes_up: AtomicI64,
    pub total_bytes_down: AtomicI64,
    pub active_connections: AtomicI32,
}

impl Stats {
    pub async fn run(self: Arc<Self>, events: Events, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        interval.tick().await;
        let mut last_up = 0i64;
        let mut last_down = 0i64;
        let mut last_active = 0i32;
        let mut quiet_ticks = 0u32;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = interval.tick() => {
                    client_perf::measure(PerfStage::StatsEmit, || {
                        let active = self.active_connections.load(Ordering::Relaxed);
                        let up = self.total_bytes_up.load(Ordering::Relaxed);
                        let down = self.total_bytes_down.load(Ordering::Relaxed);
                        let unchanged = active == last_active && up == last_up && down == last_down;
                        last_active = active;
                        last_up = up;
                        last_down = down;
                        if unchanged && active == 0 {
                            quiet_ticks = quiet_ticks.saturating_add(1);
                            if quiet_ticks % 10 != 0 {
                                return;
                            }
                        } else {
                            quiet_ticks = 0;
                        }
                        let total_mb = (up + down) as f64 / (1024.0 * 1024.0);
                        crate::log_error!("[СТАТИСТИКА] Активных: {active} | Трафик: {total_mb:.2} МБ");
                        events.stats(active, up, down);
                    });
                }
            }
        }
    }
}
