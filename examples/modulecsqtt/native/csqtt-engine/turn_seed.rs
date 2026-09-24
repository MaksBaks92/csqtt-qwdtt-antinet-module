// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Optional TURN credentials seeded by the dual Go helper (shared GetCreds / qWDTT cache).

use crate::auth::TurnCredentials;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

fn store() -> &'static Mutex<HashMap<String, TurnCredentials>> {
    static SEEDS: OnceLock<Mutex<HashMap<String, TurnCredentials>>> = OnceLock::new();
    SEEDS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn clear() {
    if let Ok(mut g) = store().lock() {
        g.clear();
    }
}

pub fn install(hash: &str, username: &str, password: &str, urls: &[String]) {
    let hash = hash.trim();
    if hash.is_empty() || username.is_empty() || password.is_empty() || urls.is_empty() {
        return;
    }
    let addrs: Arc<[Arc<str>]> = urls
        .iter()
        .map(|u| Arc::<str>::from(u.as_str()))
        .collect::<Vec<_>>()
        .into();
    if let Ok(mut g) = store().lock() {
        g.insert(
            hash.to_string(),
            TurnCredentials {
                username: Arc::from(username),
                password: Arc::from(password),
                server_addresses: addrs,
            },
        );
    }
}

pub fn lookup(hash: &str) -> Option<TurnCredentials> {
    let hash = hash.trim();
    let g = store().lock().ok()?;
    g.get(hash).cloned()
}
