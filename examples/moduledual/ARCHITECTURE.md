# Dual module architecture

## Upstream qWDTT server (reference only)

Repo: https://github.com/SpaceNeuroX/proxy-turn-vk-android  
License: GPL-3.0  
Studied tree: `server/` + client twin `go_client/`.

### What the server does (we do **not** ship this in the module)

| Piece | Role |
|-------|------|
| `-listen` | DTLS front (default `:56000`) |
| `-listen-direct` | RTP-obfs AEAD without DTLS |
| `-listen-raw` | Raw IP TUN/NAT without WireGuard (`wdttraw0`, 10.70.66.0/16) |
| userspace WG | `wdtt0`, 10.66.66.0/16, internal UDP port |
| Control | `GETCONF:` / `AUTH:` / `GETCONF_RAW:` → WG conf or `RAWCONF:ip\|dns\|mtu` |
| Admin/bot | optional HTTPS admin + Telegram DB for passwords |

Client after VK TURN allocates paths through VK media relay, then speaks **this** control plane to the **user VPS**. That is independent of CSQTT-WIRE-3.

### Control-plane clash (must never mix)

| | CSQTT | qWDTT |
|---|-------|-------|
| GETCONF | `port\|device\|pass\|gen\|salt\|worker\|desired\|rev` | `localPort\|device\|password` |
| Answer | TUNCONF / READY / DENIED (WIRE) | WG text conf / RAWCONF / NOCONF |
| Payload | WRAP+obfs IP to CSQTT peer | WG or raw IP to VPS |

Same name `GETCONF`, different grammar → separate packages, no shared session type.

## Module layout (this skeleton)

```
examples/moduledual/
  module.json          # schemes: [csqtt, qwdtt]
  ARCHITECTURE.md
  VENDOR.md
  native/dual/
    go.mod
    cmd/helper/        # AntiNet entry: realMain / moduleCall
    internal/route/    # scheme from LINK
    internal/csqtt/    # stub → later wire to modulecsqtt engine
    internal/qwdtt/    # stub → later vendor go_client datapath
    internal/vk/       # stub → shared hashes/creds (CSQTT-based)
```

`module.json` `build.rustDir` points at `../modulecsqtt/native/csqtt-engine` only for the CSQTT branch; qWDTT stays Go.

## Runtime flow

```
HOST KEY=VALUE + LINK=
        │
        ▼
  dual helper realMain
        │
        ├─ parse scheme from LINK
        │
        ├─ csqtt:// ──► internal/csqtt.Run  ──► rust engine ──► CSQTT server
        │                 (VK via internal/vk)
        │
        └─ qwdtt:// ──► internal/qwdtt.Run  ──► WG/raw/DTLS ──► qWDTT VPS
                          (VK via internal/vk)
```

Rules for CSQTT safety:

1. No shared mutable globals between `csqtt` and `qwdtt` packages.
2. Host events (handover/netlost) dispatched only to the **active** branch.
3. VK layer is shared read-only helpers + per-run state, not a singleton spanning schemes.
4. Settings that are protocol-specific stay prefixed or documented; do not apply qWDTT `noDtls` to CSQTT.

## What to take as the base

| Layer | Base | Notes |
|-------|------|-------|
| AntiNet shell | this repo `shared/*` + `moduledual` | multi-scheme already in MODULE_API |
| VK hashes/TURN | **CSQTT** (`vkcalls` / auto_js / captcha) | richer than upstream qWDTT; feed both branches |
| CSQTT datapath | `examples/modulecsqtt` as-is | copy or go.mod replace; do not rewrite for dual |
| qWDTT datapath | antinet `qwdtt-module` **or** upstream `go_client/` | server stays external |
| qWDTT server | SpaceNeuroX `server/` | deploy docs only; never in APK |

## License gate

- Combined helper binary: **GPL-3.0-or-later** (qWDTT client is linked in).
- CSQTT engine sources remain PolyForm-Noncommercial-1.0.0 (attribution + commercial restriction on those portions).
- AntiNet canons / `build.py`: MIT.

Details: `examples/moduledual/NOTICE`. qWDTT server is never in the APK.

## Status (0.2.1-dual)

| Phase | State |
|-------|--------|
| 1. Skeleton / router | done |
| 2. Wire CSQTT helper + rust engine | done |
| 3. Vendor qWDTT client (WG + rawtun) | done |
| 4. Shared VK hash/mode layer | done (TURN creds still path-specific) |
| 5. Settings + Android CI | done (`Release module bundles`) |
| 6. First GitHub Release + filled `antinet-module.json` | next |

Engine sync from CSQTT `main`: `python tools/sync_csqtt_engine.py`.
