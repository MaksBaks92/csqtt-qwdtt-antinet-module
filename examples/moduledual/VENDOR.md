# Vendor map (qWDTT)

Upstream: https://github.com/SpaceNeuroX/proxy-turn-vk-android (GPL-3.0)

## Take into the dual **module** (client)

From `go_client/` (or the already-adapted tree in `qwdtt-module/examples/moduleqwdtt/native/qwdtt/`):

| Upstream / antinet file | Role in dual |
|-------------------------|--------------|
| `creds.go`, `creds_vkcalls.go` | TURN creds (later prefer CSQTT VK layer) |
| `group.go`, `dispatcher.go`, `session.go` | multi-worker TURN paths |
| `protocol.go` | GETCONF/AUTH/GETCONF_RAW to **qWDTT VPS** |
| `obfs.go`, `wrap.go` | RTP obfuscation |
| `socks5.go`, WG/raw tun pieces | L3/L4 to VPS |
| `profiles.go`, `vk_account.go`, captcha | keep until shared VK replaces them |

Prefer the **AntiNet-adapted** qwdtt-module sources (`run.go`, `helper.go`, `dial.go`, `credstate.go`, `rawtun.go`) over raw `go_client/` — they already speak hostproto / protect / socks5 canons.

## Do **not** put in the module

| Upstream path | Why |
|---------------|-----|
| `server/*.go` | runs on user VPS; DTLS/WG/raw listeners |
| `app/` Android UI | AntiNet is the host UI |
| Gradle / APK packaging | replaced by `build.py` module bundles |

## Server deploy (docs only)

User still installs SpaceNeuroX (or fork) server with e.g.:

```text
-listen 0.0.0.0:56000
-listen-direct ...   # optional
-listen-raw ...      # optional raw IP
-password ...
```

Module `qwdtt://` link points at that peer; CSQTT links stay on CSQTT servers unchanged.
