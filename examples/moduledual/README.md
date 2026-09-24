# Dual module — CSQTT + qWDTT

Репозиторий: [csqtt-qwdtt-antinet-module](https://github.com/MaksBaks92/csqtt-qwdtt-antinet-module)
(раньше ветка `dual/csqtt-qwdtt` в csqtt-antinet-module).

Один helper, две схемы:

| LINK | Datapath | Сервер |
|------|----------|--------|
| `csqtt://…` | gVisor + rust CSQTT engine (`csqtt_*.go` + `rustDir`) | CSQTT WIRE-3 |
| `qwdtt://…` / `wdtt://…` | vendored client (`internal/qwdtt`, GPL) | VPS SpaceNeuroX `server/` |

## Статус `0.2.1-dual`

- Роутер по `LINK` в `cmd/helper/main.go`
- CSQTT-ветка: полный helper (`csqtt_*.go`) + rust engine
- qWDTT-ветка: клиент `internal/qwdtt` (GPL)
- **Общий VK-слой** `internal/vk`: режимы hash/auth (политика CSQTT) + сбор хешей из settings/link для обеих веток
- TURN-креды по-прежнему раздельно (rust CSQTT / GetCreds qWDTT)
- `go build ./cmd/helper` с inject — OK

Сервер qWDTT **не** в бандле.

См. [ARCHITECTURE.md](ARCHITECTURE.md), [VENDOR.md](VENDOR.md), [NOTICE](NOTICE).

## Сборка

```bash
python build.py --os android --module dual --abis arm64-v8a -y
```

Или desktop smoke: inject + `go build` из `examples/moduledual/native/dual`.
