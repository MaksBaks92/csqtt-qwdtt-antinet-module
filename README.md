# CSQTT + qWDTT AntiNet module

Отдельный репозиторий dual-модуля (раньше ветка `dual/csqtt-qwdtt` в [csqtt-antinet-module](https://github.com/MaksBaks92/csqtt-antinet-module)).

Один helper, две схемы:

| LINK | Datapath | Сервер |
|------|----------|--------|
| `csqtt://…` | gVisor + rust CSQTT engine | CSQTT WIRE-3 |
| `qwdtt://…` / `wdtt://…` | vendored client (`internal/qwdtt`, GPL) | VPS qWDTT |

Версия модуля: см. `examples/moduledual/module.json` (`0.2.6-dual`).

Один helper обслуживает **оба** протокола (multi-scheme AntiNet). За сессию активна
одна `LINK=` — `csqtt://` или `qwdtt://`; смена схемы = новый конфиг/переподключение.
Оба datapath и общие настройки VK живут в одном бандле.

## Настройки по схемам

В `module.json` общие настройки сверху; блоки **CSQTT** / **qWDTT** —
переключатели (`panelCsqtt` / `panelQwdtt`), по нажатию раскрывают поля схемы
через `visibleWhen`. Helper читает те же `SETTING_*`, что и раньше.

## Общие TURN-креды

`internal/vk` держит process-wide кэш TURN; qWDTT `GetCreds` пишет туда.
CSQTT перед стартом rust-движка делает prefetch через тот же `GetCreds` и передаёт
`turn_seed` в engine JSON — движок не ходит в VK повторно для уже полученных хешей.

## Сборка

```bash
python build.py --os android --module dual --abis all -y
python build.py --bundle --module dual
```

## Релиз

Тег `v*` на `main` → GitHub Actions собирает Android-бандлы dual и публикует Release.
Либо Actions → **Release module bundles** → Run workflow.

## Лицензии

Комбинированный helper (`libdualhelper.so` / `dual-helper`) распространяется
под **GPL-3.0-or-later** (из‑за qWDTT). Детали и атрибуция исходников —
`examples/moduledual/NOTICE`.

- CSQTT-ветка / rust engine: PolyForm Noncommercial — `examples/modulecsqtt/LICENSE`
- qWDTT client: GPL-3.0-or-later — `internal/qwdtt`
- Каноны AntiNet (`shared/`, `build.py`): MIT — корневой `LICENSE`

Коммерческое использование CSQTT-части по-прежнему требует отдельной лицензии
у правообладателя CSQTT (PolyForm NC).

## Синхрон rust engine с CSQTT

```bash
python tools/sync_csqtt_engine.py
# или: python tools/sync_csqtt_engine.py --from D:/csqtt/csqtt-antinet-module
```

Копирует `examples/modulecsqtt/native/csqtt-engine` из соседнего
[csqtt-antinet-module](https://github.com/MaksBaks92/csqtt-antinet-module) (`main`).
