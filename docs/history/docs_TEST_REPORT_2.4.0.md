# TEST_REPORT — Node_Install 2.4.0

Дата: **2026-10-02**. Статус: **LOCAL_TESTS_PASSED_CANARY_REQUIRED**.

## Проверенная база и границы

Исходная база этого изменения — полный пользовательский архив `Node_Install_2.3.0.zip`, SHA256 `9c83d08603939b7f34994130d696dd3e83d9d3d10a6b22fbc3feb75417d2ff57`. ZIP прошёл CRC-проверку; исходный `SHA256SUMS` проверил 174/174 перечисленных файлов; все **175 исходных файлов** сохранены. Оригинальный архив не изменялся. Семь прежних актуальных документов 2.3.0 сохранены побайтово в `docs/history/` до их актуализации.

Область 2.4.0 намеренно узкая: `NET_ADMIN` стал default capability RemnaNode для новых установок; новая конфигурация сохраняет `allow_net_admin=true`; generated Compose всегда содержит `cap_add: NET_ADMIN`; checker считает совпадающее state/runtime состояние штатным PASS; reviewed-version gates дополнены 2.4.0. Новые runtime-пакеты, порты, контейнеры, сервисы, transport, firewall rules, proxy, БД и зависимости не добавлялись. `NET_RAW` drop, `no-new-privileges`, read-only Selfsteal mount, host Nginx, UFW/Fail2ban, SSH policy, IPv4-only и image digest pinning сохранены.

Обычный повтор installer на уже завершённой 2.3.0 ноде не является скрытой миграцией Compose. Для существующих нод подготовлена отдельная backup/validate/recreate/rollback процедура: [NET_ADMIN_2.4.0.md](NET_ADMIN_2.4.0.md). Эта узкая процедура не заменяет старый 2.3.0 checker: после включения capability он может продолжить показывать исторический `WARN NODE_NET_ADMIN`; фактический CapAdd проверяется самой процедурой.

## Выполненные полные прогоны

| Прогон | Число тестов | Время unittest | Errors / failures / skips |
|---|---:|---:|---|
| Зафиксированный релиз 2.3.0, root | 554 | 20.653 s | 0 / 0 / 0 |
| 2.4.0, root | 555 | 21.868 s | 0 / 0 / 0 |
| 2.4.0, UID 1000 | 555 | 22.311 s | 0 / 0 / 0 |

Журналы: [2.3.0 root](evidence/230-root-tests.txt), [2.4.0 root](evidence/240-root-tests.txt), [2.4.0 UID 1000](evidence/240-uid1000-tests.txt). Два прогона 2.4.0 — повтор одного и того же набора под разными UID, а не 1110 разных тестов. Тесты не отключались ради успешного результата.

Новый поведенческий тест `test_new_install_persists_net_admin_enabled` реально запускает извлечённый helper `init_config` во временном дереве и проверяет, что новый state получает `allow_net_admin=true`. Существующие static/version tests актуализированы под 2.4.0 и новый generated Compose. Старые проверки SSH, UFW/firewall, DNS, REALITY/Profile, TLS/Selfsteal, HTTP/2, Certbot lifecycle, APT/time, network, Docker/image transactions, ENOSPC, timeout/signals, symlink/FIFO/races/tamper и resource diagnostics сохранены.

## Статический контроль

Фактически выполнено:

- `bash -n` для двух shell-файлов (`install.sh`, `tests/run.sh`) — PASS;
- AST/compile для 40 Python-файлов — PASS;
- JSON parse для 22 JSON-файлов — PASS;
- YAML parse workflow — PASS;
- синтаксис 5 встроенных shell payloads — PASS;
- compile 23 встроенных Python payloads — PASS;
- Bash-синтаксис standalone-команды включения `NET_ADMIN` на существующей ноде — PASS;
- контракт `INSTALLER_VERSION=2.4.0` и default `NET_ADMIN` — PASS.

Машиночитаемый результат: [evidence/240-static-validation.json](evidence/240-static-validation.json).

`ShellCheck` в локальной среде отсутствует и **не запускался**. `bash -n`/unit tests не выдаются за ShellCheck.

## Preview/browser и неизменённые части

HTML/CSS/preview/site rendering в рамках 2.4.0 не изменялись. Поэтому браузерный прогон не повторялся только ради изменения Docker capability. Сохранён предыдущий зафиксированный отчёт 2.3.0: **36 PASS** (4 варианта × 9 ширин) в [evidence/230-browser-report.json](evidence/230-browser-report.json). Это наследуемое evidence неизменённой части, а не новый browser-run 2.4.0.

## Что не доказано локальными тестами

Локальная среда не выполняла реальный production-recreate RemnaNode с `NET_ADMIN`, не проверяла «Обозреватель сессий» в живой панели, реальный VLESS-клиент, влияние upstream RemnaNode/Xray с новой capability на UFW/routes/qdisc конкретной VPS, внешний panel→node путь, публичный ACME, reboot/restore, все поддерживаемые Ubuntu/Debian и arm64, длительную нагрузку или remote GitHub Actions.

Поэтому выпуск требует **canary на одной ноде** до массового rollout: provider snapshot/console → изменение → проверка container/state → панель/Session Browser → обычный клиент → host firewall/routes/qdisc → только затем остальные ноды. `NET_ADMIN` при `network_mode: host` увеличивает blast radius; это сознательный эксплуатационный trade-off, а не усиление изоляции.

## Итог

Локальный кодовый/тестовый контракт 2.4.0 подтверждён. Пользовательские серверы, панель, DNS, Cloudflare, Docker daemon, Nginx, UFW и SSH при подготовке релиза не изменялись. Финальный manifest и ZIP проверяются после фиксации всех файлов; внешняя package-attestation поставляется рядом с архивом, чтобы не создавать self-referential hash внутри самого ZIP.
