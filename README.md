# CSQTT + qWDTT AntiNet module

Отдельный репозиторий dual-модуля (раньше ветка `dual/csqtt-qwdtt` в [csqtt-antinet-module](https://github.com/MaksBaks92/csqtt-antinet-module)).

Один helper, две схемы:

| LINK | Datapath | Сервер |
|------|----------|--------|
| `csqtt://…` | gVisor + rust CSQTT engine | CSQTT WIRE-3 |
| `qwdtt://…` / `wdtt://…` | vendored client (`internal/qwdtt`, GPL) | VPS qWDTT |

Версия модуля: см. `examples/moduledual/module.json` (`0.2.1-dual`).

## Сборка

```bash
python build.py --os android --module dual --abis all -y
python build.py --bundle --module dual
```

## Релиз

Тег `v*` на `main` → GitHub Actions собирает Android-бандлы dual и публикует Release.
Либо Actions → **Release module bundles** → Run workflow.

## Лицензии

- CSQTT-ветка / rust engine: PolyForm Noncommercial — `examples/modulecsqtt/LICENSE`
- qWDTT client: GPL-3.0-or-later — см. `examples/moduledual/NOTICE`
- Каноны AntiNet (`shared/`, `build.py`): MIT — корневой `LICENSE`
