# TEST_REPORT — Node_Install 2.1.2

Дата подготовки: 2026-09-30.

## Изменения под проверкой

2.1.2 добавляет три связанные production-функции без смены общей архитектуры ноды:

1. Закрытый export текущих REALITY-ключей в `/root/reality-keys.txt` и terminal-only показ `PrivateKey`, `PublicKey`, `ShortID` в конце успешной установки.
2. Одноразовый reboot по умолчанию через transient systemd unit с задержкой 30 секунд; `--no-reboot` сохраняет ручной режим.
3. `minClientVer: "1.0.0"` в генерируемом RAW+REALITY profile template для совместимости старых Xray-core.

Ключи не генерируются повторно на финальном этапе: export читает и проверяет уже сохранённый `/etc/vkarmani-node/reality.json`. Secret block не проходит через install-log `tee`.

## Полный набор

**383 теста, 0 failures, 0 errors, 0 skips.**

Выполнены два отдельных полных запуска:

| Среда запуска | Результат |
|---|---|
| root | `Ran 383 tests in 31.423s ... OK` |
| UID 1000 (`oai`), без sudo | `Ran 383 tests in 29.481s ... OK` |

Перед ними отдельно прошли 6 новых targeted tests.

## Новые регрессии 2.1.2

Добавлен `tests/test_212_reality_keys_reboot.py` — 6 проверок:

1. Export создаётся атомарно с `0600`, содержит ровно текущие `PrivateKey`, `PublicKey`, `ShortID` и `minClientVer=1.0.0`.
2. Повторный export использует ту же X25519-пару и не регенерирует `reality.json`.
3. Symlink вместо файла export отклоняется и target symlink не изменяется.
4. Profile policy отклоняет отсутствующий или изменённый `minClientVer`.
5. Default reboot contract: `NO_REBOOT=0`, `--no-reboot` отключает, transient reboot имеет 30-секундную задержку.
6. PrivateKey display идёт через `/dev/tty`, а helper export вызывается с подавленным stdout в общий log.

Также обновлены существующие regression tests для версии 2.1.2 и финального acceptance sequence.

## Сохранённые проверки

Все 377 тестов 2.1.1 сохранены: APT/dpkg lock coordination, терминальный ввод ровно трёх значений, DNS, firewall, SSH, NTP provider, package solver, atomic writes/fault injection, backups, Docker maintenance/rollback, Selfsteal socket, Nginx TLS1.3/HTTP2, cover site, resource snapshot, CI contracts, Node HKDF compatibility и Git workspace contract.

## Реальные данные, уже подтверждённые до выпуска 2.1.2

На Ubuntu 24.04 установка 2.1.1 реально встретила живой `unattended-upgrades` на Docker stage, ждала package-manager lock примерно 588 секунд и затем штатно продолжила установку Docker/Nginx/RemnaNode. На трёх ключевых нодах Ubuntu 24.04 были подтверждены Xray TCP/443, локальный Selfsteal и рабочий VPN; после перехода live REALITY profile на `/dev/shm/nginx.sock` строгая проверка одной ноды дала `REALITY_SELFSTEAL_443 PASS`.

Эти результаты подтверждают базу 2.1.1 и рабочую схему профиля, но **не заменяют** отдельный полный install → auto-reboot → postboot тест именно 2.1.2.

## Что не проверено

- Полная установка **2.1.2** на новой реальной VPS с фактическим terminal key export и автоматическим reboot.
- Поведение transient reboot при реальном отказе systemd-run.
- Полный install/panel/client цикл 2.1.2 на Ubuntu 26.04 и arm64.
- Длительная нагрузка и восстановление после power-loss в момент финального export/reboot.

## Перед массовой раскаткой

Одна чистая Ubuntu 24.04 canary: snapshot/console → 2.1.2 → проверить финальный key block и `/root/reality-keys.txt` (`0600`) → дождаться auto-reboot → новый SSH → `sudo vkarmani-node-check --require-xray` после назначения профиля → браузерный Selfsteal → современный и старый Xray-клиент.
