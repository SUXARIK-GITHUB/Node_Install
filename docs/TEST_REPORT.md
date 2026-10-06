# TEST_REPORT — Node_Install 2.5.2

## 2.5.2 release-candidate validation — 2026-10-06

Baseline remains commit `817b283d813b79bbfa9bde8ced136fc792b48108`; the original uploaded archive and baseline installer SHA256 remain the values recorded by the 2.5.0 specification. 2.5.2 preserves the complete 2.5.0/2.5.1 architecture and adds only listener-acceptance corrections proven on a real Ubuntu 24.04.4 amd64 VPS.

### Real-VPS root causes now covered

- Docker 29.8 canonical `CAP_NET_ADMIN` / `CAP_NET_RAW` inspect representation — fixed in 2.5.1 without widening the exact capability set.
- iproute2 scoped IPv4 such as `127.0.0.53%lo:53` — fixed in 2.5.1.
- preboot `rw-node` may own exactly one AF_INET6 wildcard `NODE_PORT` socket while `bindv6only=0`; IPv4 connectivity was proven to both loopback and public IPv4 even though `ss -4` omitted the socket. 2.5.2 accepts only this proof-based exact state.
- postboot/live `rw-core` legitimately bound `0.0.0.0:443`, matching the generated VLESS profile. 2.5.2 permits public IPv4 or IPv4 wildcard for Xray 443 while retaining process/PID ownership checks; Nginx/80 remains concrete-public-IPv4-only.

### Real Ubuntu 24.04 local reboot canary

The diagnosed node completed install state, rebooted with `ipv6.disable=1`, returned with no IPv6 socket/address/route state, and exposed IPv4 listeners on 22/80/443/2222. After the two 2.5.2 acceptance fixes were applied, full local acceptance passed, `vkarmani-node-postboot.service` rerun completed with `Result=success` and `ExecMainStatus=0`, and `systemctl --failed` reported zero units. `NODE_PLUGINS_PREREQS`, Xray floors, nft runtime, Selfsteal, listener policy and local Node TLS all passed.

This is a **local host/container/reboot canary**, not full production verification. Panel→node external path, Panel Plugin Config assignment, authenticated client traffic, Torrent Blocker detection and regional reachability were not proven by these steps.

### Full local suite

Final suite: **599/599 PASS** as root (33.437 s) and **599/599 PASS** as UID 1000 (33.354 s), with 0 failures / 0 errors / 0 skips in both runs. No baseline test is removed or weakened. New 2.5.2 regressions execute the wildcard-443 rule and the preboot dual-stack NODE_PORT proof path, including negative cases that forbid hiding any other missing listener. Logs: `docs/evidence/252-root-tests.txt` and `docs/evidence/252-uid1000-tests.txt`.

### Static/release gates

- `bash -n install.sh` — PASS;
- `bash -n tests/run.sh` — PASS;
- embedded Node Plugins helper compiles — PASS;
- JSON release metadata validation — PASS;
- `git diff --check` and final `sha256sum --check SHA256SUMS` are release gates before packaging;
- ShellCheck — **NOT_RUN_NOT_INSTALLED**;
- no real installation is executed on the build host.

Current pre-manifest `install.sh` SHA256: `69177096f8d7142ee578a7bcd9f583b0e934ebe8990341d11a4ef07b24dd0523`.

Detailed incident contract: [HOTFIX_2.5.2](HOTFIX_2.5.2.md).

---

## Historical 2.4.3 report (preserved)
Дата: **2026-10-03**. Статус: **LOCAL_TESTS_PASSED_REMOTE_CI_RERUN_REQUIRED**.

## Исправление 2.4.3 по фактическому GitHub Actions failure 2.4.2

После публикации 2.4.2 все три обязательных CI job остановились **до запуска тестов** на `sha256sum --check SHA256SUMS`. Ровно три файла дали mismatch: `evidence/241-ci-ubuntu22-failure.txt`, `evidence/241-ci-ubuntu24-failure.txt`, `evidence/241-ci-ubuntu26-userspace-failure.txt`. В ZIP они имели CRLF, а `.gitattributes` (`* text=auto`) при commit/checkout канонизировал их в LF. Manifest был корректен для ZIP-байтов, но не для clean Git checkout.

В 2.4.3 три evidence-файла нормализованы в LF, manifest пересобран, добавлен regression `test_manifest_text_files_are_git_canonical_lf`, а финальная release-validation включает временный Git repository и clean clone с повторным `sha256sum --check`. Это supply-chain/packaging fix; production runtime logic не менялась. Подробности: [CI_GIT_NORMALIZATION_2.4.3](CI_GIT_NORMALIZATION_2.4.3.md).

## Исправление 2.4.2 по фактическому GitHub Actions failure 2.4.1

После публикации 2.4.1 все три обязательных CI job упали одинаково и только в одном месте: `test_large_fragmented_clienthello_and_proxy_header`. Ubuntu 22.04 (`Python 3.10.12`, `nginx 1.18.0`) завершил 556 тестов с 1 error за 21.692 s; Ubuntu 24.04 (`Python 3.12.3`, `nginx 1.24.0`) — с 1 error за 22.446 s; Ubuntu 26 userspace (`Python 3.14.4`, `nginx 1.28.3`) — с 1 error за 19.741 s. Во всех трёх traceback одинаковый: `BrokenPipeError` при отправке TLS bytes. Полные пользовательские CI-журналы сохранены как `evidence/241-ci-ubuntu22-failure.txt`, `evidence/241-ci-ubuntu24-failure.txt`, `evidence/241-ci-ubuntu26-userspace-failure.txt`.

При этом оба интеграционных TLS-теста, из-за которых создавался 2.4.1, в этих прогонах уже PASS. Значит, cert-reload convergence fix 2.4.1 не откатился; обнаружен отдельный дефект тестового harness.

Детерминированное локальное воспроизведение старого сценария с 10 ms между 7-байтовыми кусками PROXY v1 дало `BrokenPipeError`, а Nginx записал `broken header: "PROXY T" while reading PROXY protocol` (`evidence/242-proxy-fragment-reproduction.txt`). Старый тест случайно зависел от coalescing коротких UNIX-stream writes.

В 2.4.2 тест переименован в `test_large_fragmented_clienthello_after_complete_proxy_header`: PROXY v1 строка отправляется целиком, затем выдерживается 10 ms, а большой TLS 1.3 ClientHello **реально** фрагментируется по 37 байт с 1 ms между чанками. Ошибка не маскируется try/except и timeout не расширяется. Upstream Xray fallback для `xver=1` формирует PROXY v1 в отдельном buffer и пишет его перед копированием fallback payload, поэтому исправленный boundary соответствует фактической архитектуре. Подробный разбор: [CI_PROXY_FRAGMENTATION_2.4.2](CI_PROXY_FRAGMENTATION_2.4.2.md).

Production `install.sh` transport/config behavior не менялся, кроме номера релиза, version markers и reviewed-version allowlists. NET_ADMIN default 2.4.0, cert-deploy convergence 2.4.1, Nginx template, REALITY profile, firewall, SSH, network и runtime dependencies сохранены.

## Предыдущее исправление 2.4.1

GitHub Actions job `ubuntu-24.04` для 2.4.0 завершился ошибкой при **553 успешных и 2 ошибочных** тестах. Ошибки были связаны: `test_real_certificate_rotation_with_same_nginx_process` получил `SELFSTEAL_CERTIFICATE_NOT_RELOADED`, а следующий `test_target_tls_without_reading_html_or_css` — `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`. Это соответствовало переходному overlap graceful reload Nginx.

В 2.4.1 production `VK_CERT_DEPLOY_PY` стал требовать 4 последовательных успешных `vkarmani-selfsteal-check --target-only`; любая промежуточная неудача сбрасывает streak в пределах bounded deadline. Интеграционный cleanup после обратного reload использует тот же принцип. Регрессия `test_single_target_success_is_not_enough_after_graceful_reload` сохранена и проходит в 2.4.3.

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
| 2.4.1, root | 556 | 27.198 s | 0 / 0 / 0 |
| 2.4.1, UID 1000 | 556 | 27.363 s | 0 / 0 / 0 |
| 2.4.2, root | 556 | 26.995 s | 0 / 0 / 0 |
| 2.4.2, UID 1000 | 556 | 27.193 s | 0 / 0 / 0 |
| 2.4.3, root | 557 | 28.199 s | 0 / 0 / 0 |
| 2.4.3, UID 1000 | 557 | 27.882 s | 0 / 0 / 0 |

Журналы: [2.3.0 root](evidence/230-root-tests.txt), [2.4.0 root](evidence/240-root-tests.txt), [2.4.0 UID 1000](evidence/240-uid1000-tests.txt), [2.4.1 root](evidence/241-root-tests.txt), [2.4.1 UID 1000](evidence/241-uid1000-tests.txt), [2.4.2 root](evidence/242-root-tests.txt), [2.4.2 UID 1000](evidence/242-uid1000-tests.txt), [2.4.3 root](evidence/243-root-tests.txt), [2.4.3 UID 1000](evidence/243-uid1000-tests.txt). Root/UID-прогоны каждой версии — повтор одного набора под разными UID, а не сумма разных тестов. Тесты не отключались ради успешного результата.

Новый поведенческий тест `test_new_install_persists_net_admin_enabled` реально запускает извлечённый helper `init_config` во временном дереве и проверяет, что новый state получает `allow_net_admin=true`. Существующие static/version tests сохраняют контракт 2.4.0/2.4.1/2.4.2 и дополнены reviewed-version 2.4.3; generated Compose с default NET_ADMIN не менялся. Старые проверки SSH, UFW/firewall, DNS, REALITY/Profile, TLS/Selfsteal, HTTP/2, Certbot lifecycle, APT/time, network, Docker/image transactions, ENOSPC, timeout/signals, symlink/FIFO/races/tamper и resource diagnostics сохранены.

## Статический контроль

Фактически выполнено:

- `bash -n` для двух shell-файлов (`install.sh`, `tests/run.sh`) — PASS;
- AST/compile для 40 Python-файлов — PASS;
- JSON parse для 26 JSON-файлов — PASS;
- YAML parse workflow — PASS;
- синтаксис 5 встроенных shell payloads — PASS;
- compile 23 встроенных Python payloads — PASS;
- Bash-синтаксис standalone-команды включения `NET_ADMIN` на существующей ноде — PASS;
- контракт `INSTALLER_VERSION=2.4.3`, поддержка reviewed 2.4.0/2.4.1/2.4.2 и default `NET_ADMIN` — PASS;
- canonical LF для UTF-8 text entries из `SHA256SUMS` — PASS;
- clean Git commit/clone round-trip с повторным `sha256sum --check SHA256SUMS` — PASS;
- новый cert-deploy convergence contract (4 consecutive target-only PASS, reset on failure) — PASS.

Машиночитаемые результаты: [2.4.0](evidence/240-static-validation.json), [2.4.1](evidence/241-static-validation.json), [2.4.2](evidence/242-static-validation.json), [2.4.3](evidence/243-static-validation.json).

`ShellCheck` в локальной среде отсутствует и **не запускался**. `bash -n`/unit tests не выдаются за ShellCheck.

## Preview/browser и неизменённые части

HTML/CSS/preview/site rendering в рамках 2.4.3 не изменялись. Поэтому браузерный прогон не повторялся только ради изменения Docker capability. Сохранён предыдущий зафиксированный отчёт 2.3.0: **36 PASS** (4 варианта × 9 ширин) в [evidence/230-browser-report.json](evidence/230-browser-report.json). Это наследуемое evidence неизменённой части, а не новый browser-run 2.4.3.

## Что не доказано локальными тестами

Локальная среда не выполняла реальный production-recreate RemnaNode с `NET_ADMIN`, не проверяла «Обозреватель сессий» в живой панели, реальный VLESS-клиент, влияние upstream RemnaNode/Xray с новой capability на UFW/routes/qdisc конкретной VPS, внешний panel→node путь, публичный ACME, reboot/restore, все поддерживаемые Ubuntu/Debian и arm64, длительную нагрузку или remote GitHub Actions 2.4.3.

Поэтому выпуск требует **canary на одной ноде** до массового rollout: provider snapshot/console → изменение → проверка container/state → панель/Session Browser → обычный клиент → host firewall/routes/qdisc → только затем остальные ноды. `NET_ADMIN` при `network_mode: host` увеличивает blast radius; это сознательный эксплуатационный trade-off, а не усиление изоляции.

## Итог

Локальный кодовый/тестовый контракт 2.4.3 подтверждён; удалённый GitHub matrix Ubuntu 22.04/24.04/26 userspace требует нового запуска после публикации 2.4.3. Пользовательские серверы, панель, DNS, Cloudflare, Docker daemon, Nginx, UFW и SSH при подготовке релиза не изменялись. Финальный manifest и ZIP проверяются после фиксации всех файлов; внешняя package-attestation поставляется рядом с архивом, чтобы не создавать self-referential hash внутри самого ZIP.
