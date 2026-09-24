// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! In-process IP packet bridge for AntiNet: Go gVisor ↔ rust engine without
//! localhost UDP. Uplink is a lock-free queue drained by the dispatcher; downlink
//! is an optional C callback into the helper.

use crate::{
    packet::{PacketBuf, PacketPool},
    striped_scheduler::keep_under_pressure,
};
use arc_swap::ArcSwapOption;
use crossbeam_queue::ArrayQueue;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicPtr, Ordering},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub const UPLINK_CAPACITY: usize = 1024;
/// DNS, NTP and other UDP stay here, so a full TCP upload cannot drop them.
pub const UPLINK_LATENCY_CAPACITY: usize = 256;

pub type PacketOutCb = extern "C" fn(*const u8, i32);
/// Batch downlink: `ptrs[i]` is `lens[i]` bytes. Valid only for the duration of the call.
pub type PacketOutBatchCb = extern "C" fn(*const *const u8, *const i32, i32);

static PACKET_OUT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static PACKET_OUT_BATCH: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static BRIDGE_READY: AtomicBool = AtomicBool::new(false);

fn uplink_slot() -> &'static ArcSwapOption<UplinkBridge> {
    static UPLINK: OnceLock<ArcSwapOption<UplinkBridge>> = OnceLock::new();
    UPLINK.get_or_init(ArcSwapOption::empty)
}

pub struct UplinkBridge {
    pub pool: Arc<PacketPool>,
    pub queue: ArrayQueue<PacketBuf>,
    pub latency: ArrayQueue<PacketBuf>,
    pub notify: Arc<Notify>,
    pub cancel: CancellationToken,
}

fn enqueue_uplink(bridge: &UplinkBridge, packet: PacketBuf) -> bool {
    if keep_under_pressure(packet.as_slice()) {
        match bridge.latency.push(packet) {
            Ok(()) => true,
            Err(packet) => {
                // Keep the newest query. A stale NTP/DNS datagram will not be retried by us.
                let _ = bridge.latency.pop();
                bridge.latency.push(packet).is_ok()
            }
        }
    } else {
        bridge.queue.push(packet).is_ok()
    }
}

pub fn set_packet_out(cb: Option<PacketOutCb>) {
    let ptr = cb.map(|f| f as *mut ()).unwrap_or(std::ptr::null_mut());
    PACKET_OUT.store(ptr, Ordering::Release);
}

pub fn set_packet_out_batch(cb: Option<PacketOutBatchCb>) {
    let ptr = cb.map(|f| f as *mut ()).unwrap_or(std::ptr::null_mut());
    PACKET_OUT_BATCH.store(ptr, Ordering::Release);
}

pub fn packet_out() -> Option<PacketOutCb> {
    let ptr = PACKET_OUT.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut (), PacketOutCb>(ptr) })
    }
}

fn packet_out_batch() -> Option<PacketOutBatchCb> {
    let ptr = PACKET_OUT_BATCH.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut (), PacketOutBatchCb>(ptr) })
    }
}

pub fn bridge_ready() -> bool {
    BRIDGE_READY.load(Ordering::Acquire)
}

pub fn clear_bridge() {
    BRIDGE_READY.store(false, Ordering::Release);
    uplink_slot().store(None);
}

pub fn install_uplink(bridge: Arc<UplinkBridge>) {
    uplink_slot().store(Some(bridge));
    BRIDGE_READY.store(true, Ordering::Release);
}

/// Copy `data` into a pool buffer and enqueue for the bridge reader.
/// Returns 0 on success, -1 if bridge is down, -2 if queue is full / pool exhausted.
pub fn inject_packet(data: &[u8]) -> i32 {
    if data.is_empty() || data.len() > crate::packet::PACKET_CAPACITY - crate::packet::PACKET_HEADROOM
    {
        return -3;
    }
    let Some(bridge) = uplink_slot().load_full() else {
        return -1;
    };
    if bridge.cancel.is_cancelled() {
        return -1;
    }
    // Idle scale-down exit trigger; a single atomic load unless we are actually idle.
    crate::idle::note_uplink(data);
    let Some(mut packet) = bridge.pool.try_acquire() else {
        return -2;
    };
    let area = packet.read_area();
    if data.len() > area.len() {
        return -3;
    }
    area[..data.len()].copy_from_slice(data);
    if packet.set_read_len(data.len()).is_err() {
        return -3;
    }
    if !enqueue_uplink(&bridge, packet) {
        return -2;
    }
    // Wake only on empty → nonempty. The reader drains both queues per wake.
    if bridge.latency.len() + bridge.queue.len() == 1 {
        bridge.notify.notify_one();
    }
    0
}

/// Copy a burst from gVisor in one bridge lookup and one reader wake.
pub fn inject_packets(packets: &[&[u8]]) -> i32 {
    if packets.is_empty() {
        return 0;
    }
    let Some(bridge) = uplink_slot().load_full() else {
        return -1;
    };
    if bridge.cancel.is_cancelled() {
        return -1;
    }
    let mut queued = 0i32;
    let mut failed = 0i32;
    for data in packets {
        if data.is_empty() {
            continue;
        }
        crate::idle::note_uplink(data);
        let Some(mut packet) = bridge.pool.try_acquire() else {
            failed += 1;
            continue;
        };
        let area = packet.read_area();
        if data.len() > area.len() {
            failed += 1;
            continue;
        }
        area[..data.len()].copy_from_slice(data);
        if packet.set_read_len(data.len()).is_err() {
            failed += 1;
            continue;
        }
        if !enqueue_uplink(&bridge, packet) {
            failed += 1;
            continue;
        }
        queued += 1;
    }
    if queued > 0 {
        bridge.notify.notify_one();
        return 0;
    }
    if failed > 0 { -2 } else { 0 }
}

pub fn deliver_downlink(packet: &[u8]) {
    if packet.is_empty() {
        return;
    }
    if let Some(batch) = packet_out_batch() {
        let ptr = packet.as_ptr();
        let len = packet.len() as i32;
        batch(&ptr, &len, 1);
        return;
    }
    if let Some(cb) = packet_out() {
        cb(packet.as_ptr(), packet.len() as i32);
    }
}

/// One FFI call for a drained write_bridge batch; falls back to per-packet if only the
/// legacy single-packet callback is registered.
pub fn deliver_downlink_batch(packets: &[PacketBuf]) {
    if packets.is_empty() {
        return;
    }
    if let Some(batch) = packet_out_batch() {
        const MAX: usize = 128;
        let mut ptrs = [std::ptr::null(); MAX];
        let mut lens = [0i32; MAX];
        let mut count = 0usize;
        for packet in packets.iter().take(MAX) {
            let slice = packet.as_slice();
            if slice.is_empty() {
                continue;
            }
            ptrs[count] = slice.as_ptr();
            lens[count] = slice.len() as i32;
            count += 1;
        }
        if count > 0 {
            batch(ptrs.as_ptr(), lens.as_ptr(), count as i32);
        }
        return;
    }
    for packet in packets {
        deliver_downlink(packet.as_slice());
    }
}
