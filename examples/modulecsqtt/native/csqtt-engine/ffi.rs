// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    Arguments, ENGINE_CANCEL, ENGINE_PAUSE, PACKET_PORT, TUN_DNS, TUN_IP, logging, packet_bridge,
    protect, ready_notify, run, runtime_worker_threads,
};
use serde::Deserialize;
use std::{
    ffi::{CStr, CString, c_char},
    slice,
    sync::atomic::Ordering,
    thread,
    time::Duration,
};

#[derive(Deserialize, Default)]
struct EngineJson {
    #[serde(default)]
    peer: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    hashes: String,
    #[serde(default)]
    vk_hash_mode: String,
    #[serde(default)]
    vk_js_token: String,
    #[serde(default)]
    workers: usize,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    captcha_mode: String,
    #[serde(default)]
    vk_auth_mode: String,
    #[serde(default)]
    obfs: String,
    #[serde(default)]
    turn_transport: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    allow_hash_redistribution: bool,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    http_proxy: String,
    #[serde(default)]
    packet_bridge: bool,
    /// Idle scale-down (idle.rs). Absent → engine defaults; 0 workers → off.
    #[serde(default)]
    idle_workers: Option<usize>,
    #[serde(default)]
    idle_after_secs: Option<u64>,
    /// Same-socket selective FEC. Absent/`true` → on (official client).
    #[serde(default = "default_true")]
    fec_duplicate: bool,
}

fn default_true() -> bool {
    true
}

fn arguments_from_json(raw: &str) -> Result<Arguments, String> {
    let cfg: EngineJson = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if cfg.peer.trim().is_empty() || cfg.password.trim().is_empty() {
        return Err("peer and password are required".into());
    }
    let hash_mode = if cfg.vk_hash_mode.trim().is_empty() {
        if cfg.hashes.trim().is_empty() {
            "auto_js".into()
        } else {
            "manual".into()
        }
    } else {
        cfg.vk_hash_mode.trim().to_ascii_lowercase()
    };
    if hash_mode == "auto_js" && cfg.vk_js_token.trim().is_empty() {
        return Err("auto_js requires vk_js_token".into());
    }
    if hash_mode != "auto_js" && cfg.hashes.trim().is_empty() {
        return Err("vk hashes are required".into());
    }
    let workers = if cfg.workers == 0 { 18 } else { cfg.workers };
    Ok(Arguments {
        turn: String::new(),
        port: String::new(),
        listen: "127.0.0.1:0".into(),
        vk: cfg.hashes,
        vk_hash_mode: hash_mode.clone(),
        vk_js_token: cfg.vk_js_token,
        peer: cfg.peer,
        workers,
        allow_hash_redistribution: hash_mode == "auto_js" || cfg.allow_hash_redistribution,
        device_id: if cfg.device_id.is_empty() {
            "antinet".into()
        } else {
            cfg.device_id
        },
        password: cfg.password,
        vk_auth_mode: if cfg.vk_auth_mode.is_empty() {
            "vkcalls".into()
        } else {
            cfg.vk_auth_mode
        },
        captcha_mode: if cfg.captcha_mode.is_empty() {
            "auto".into()
        } else {
            cfg.captcha_mode
        },
        fingerprint: if cfg.fingerprint.is_empty() {
            "firefox".into()
        } else {
            cfg.fingerprint
        },
        client_ids: "8202606,6287487".into(),
        obfs: if cfg.obfs.is_empty() {
            "video".into()
        } else {
            cfg.obfs
        },
        turn_transport: if cfg.turn_transport.is_empty() {
            "udp".into()
        } else {
            cfg.turn_transport
        },
        generation: cfg.generation,
        salt: cfg.salt,
        tun_uds: String::new(),
        packet_bridge: cfg.packet_bridge,
        validate_vk_hashes: false,
        http_proxy: cfg.http_proxy,
        idle_workers: cfg.idle_workers.unwrap_or(crate::idle::DEFAULT_KEEP),
        idle_after_secs: cfg
            .idle_after_secs
            .unwrap_or(crate::idle::DEFAULT_AFTER.as_secs()),
        fec_duplicate: cfg.fec_duplicate,
    })
}

fn c_str<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("null pointer".into());
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|e| e.to_string())
}

fn write_cstr(src: &str, buf: *mut c_char, n: i32) -> i32 {
    if buf.is_null() || n <= 0 {
        return -1;
    }
    let Ok(c) = CString::new(src) else {
        return -1;
    };
    let bytes = c.as_bytes_with_nul();
    if bytes.len() > n as usize {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast(), bytes.len());
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_set_protect(cb: Option<protect::ProtectCb>) {
    if let Some(cb) = cb {
        protect::set_protect(cb);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_start(config_json: *const c_char) -> i32 {
    let Ok(raw) = c_str(config_json) else {
        return -1;
    };
    let args = match arguments_from_json(raw) {
        Ok(v) => v,
        Err(error) => {
            eprintln!("csqtt_engine_start: {error}");
            return -2;
        }
    };
    PACKET_PORT.store(0, Ordering::Release);
    packet_bridge::clear_bridge();
    if let Ok(mut ip) = TUN_IP.lock() {
        ip.clear();
    }
    if let Ok(mut dns) = TUN_DNS.lock() {
        dns.clear();
    }
    thread::spawn(move || {
        let workers = runtime_worker_threads(args.workers);
        let runtime = match crate::build_runtime(workers) {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("csqtt runtime: {error:#}");
                return;
            }
        };
        let failure = runtime.block_on(async {
            match tokio::spawn(run(args)).await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(format!("{error:#}")),
                Err(error) => Some(format!("{error}")),
            }
        });
        if let Some(failure) = failure {
            eprintln!("[CSQTT] {failure}");
            let _ = logging::shutdown(Duration::from_secs(1));
        }
    });
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_wait_ready(timeout_ms: i32) -> i32 {
    let timeout = Duration::from_millis(timeout_ms.max(0) as u64);
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let tun_ready = !TUN_IP.lock().map(|s| s.is_empty()).unwrap_or(true);
        let path_ready =
            PACKET_PORT.load(Ordering::Acquire) != 0 || packet_bridge::bridge_ready();
        if tun_ready && path_ready {
            return 0;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = ready_notify();
    let tun_ready = !TUN_IP.lock().map(|s| s.is_empty()).unwrap_or(true);
    let path_ready = PACKET_PORT.load(Ordering::Acquire) != 0 || packet_bridge::bridge_ready();
    if tun_ready && path_ready {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_packet_port() -> i32 {
    PACKET_PORT.load(Ordering::Acquire) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_tun_ip(buf: *mut c_char, n: i32) -> i32 {
    let ip = TUN_IP.lock().map(|s| s.clone()).unwrap_or_default();
    write_cstr(&ip, buf, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_tun_dns(buf: *mut c_char, n: i32) -> i32 {
    let dns = TUN_DNS.lock().map(|s| s.clone()).unwrap_or_default();
    write_cstr(&dns, buf, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_stop() {
    if let Ok(mut guard) = ENGINE_PAUSE.lock() {
        *guard = None;
    }
    if let Ok(guard) = ENGINE_CANCEL.lock() {
        if let Some(cancel) = guard.as_ref() {
            cancel.cancel();
        }
    }
    packet_bridge::clear_bridge();
}

/// Pause/resume TURN workers without tearing down the engine (doze / netlost).
/// paused != 0 → PAUSE; 0 → RESUME. No-op if engine is not running.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_set_paused(paused: i32) {
    if let Ok(guard) = ENGINE_PAUSE.lock() {
        if let Some(gate) = guard.as_ref() {
            gate.set_paused(paused != 0);
        }
    }
}

/// Number of READY TURN worker sessions right now (0 while reconnecting after sleep).
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_active_paths() -> i32 {
    crate::stats::ACTIVE_PATHS.load(std::sync::atomic::Ordering::Acquire)
}

/// Ask every TURN session to re-validate its path immediately (host detected a wake / stall).
/// The engine also detects suspend on its own (`wake.rs`); this is the explicit trigger.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_nudge() {
    crate::wake::signal(std::time::Duration::ZERO, "host");
}

/// Soft handover: the network changed (Wi-Fi ↔ cellular). Every session is torn down and
/// re-allocated on the current network with the cached credentials; the engine, the VK
/// credentials and the dispatcher flow table stay. Much cheaper than stop/start.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_rebind() {
    crate::rebind::request("host");
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_set_packet_out(cb: Option<packet_bridge::PacketOutCb>) {
    packet_bridge::set_packet_out(cb);
}

#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_set_packet_out_batch(cb: Option<packet_bridge::PacketOutBatchCb>) {
    packet_bridge::set_packet_out_batch(cb);
}

/// Inject one raw IPv4 packet from the AntiNet helper into the engine data path.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_inject_packet(data: *const u8, n: i32) -> i32 {
    if data.is_null() || n <= 0 {
        return -3;
    }
    let bytes = unsafe { slice::from_raw_parts(data, n as usize) };
    packet_bridge::inject_packet(bytes)
}

/// Inject a burst of raw IPv4 packets. Pointers are valid only for this call.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_inject_batch(
    ptrs: *const *const u8,
    lens: *const i32,
    count: i32,
) -> i32 {
    if ptrs.is_null() || lens.is_null() || count <= 0 {
        return -3;
    }
    let n = count as usize;
    let ptrs = unsafe { slice::from_raw_parts(ptrs, n) };
    let lens = unsafe { slice::from_raw_parts(lens, n) };
    let mut packets = Vec::with_capacity(n);
    for i in 0..n {
        if ptrs[i].is_null() || lens[i] <= 0 {
            continue;
        }
        packets.push(unsafe { slice::from_raw_parts(ptrs[i], lens[i] as usize) });
    }
    packet_bridge::inject_packets(&packets)
}

/// Host is about to stop the helper. Send DISCONNECT so the server drops our routes.
#[unsafe(no_mangle)]
pub extern "C" fn csqtt_engine_disconnect() {
    crate::session::signal_stop_disconnect();
}
