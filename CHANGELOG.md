## 📝 Документационное обновление 2.5.5 · 09.10.2026 (без изменения install.sh)

- Полная переработка `README.md`: главная команда установки по неизменяемому Git commit URL + строго закреплённому SHA256 установщика, без `curl | bash`, с `--no-reboot`; эмоджи, GitHub Markdown-карточки, визуальная карта сети, путеводитель по командам и признакам отказов.
- Полная переработка `SECURITY.md`: private vulnerability disclosure, угрозы/границы доверия, UFW/SSH/NET_ADMIN/RKN/сертификаты, backup, инциденты, сохранены все старые security-notes.
- Полные публичные JSON-примеры RAW+REALITY+Vision и XHTTP+REALITY содержат `log/dns/inbounds/outbounds/routing` и расширенные DNS/finalRules/geoip/geosite/BitTorrent из пользовательского запроса; дополнительные правила **только для ручного staging-теста**, генератор реальной ноды не изменялся.
- Предыдущие `README.md` и `SECURITY.md` 2.5.5 сохранены побайтово в `docs/history`. Добавлены offline-регрессии главной команды, SHA, профилей, Markdown-анкоров, ссылок и секретов.
- **Production runtime неизменён:** `install.sh` SHA256 `ca654e4b36f88338c15f608c1d554acef83d971e68dff9e5c08ddc31822abc40`; Docker, Nginx, UFW, сертификаты, действующие серверы не затронуты. GitHub публикуется только оператором.

---

## 2.5.5 — 2026-10-09 (reviewed RAW/XHTTP examples, documentation, Xray release advisory)

- **README полностью пересобран**, оглавление + полная процедура установки/приёмки, границы Node/Panel, отдельные полные RAW+REALITY+Vision и XHTTP+REALITY JSON с обезличенными ключами и адресами. Исходная README 2.5.4 целиком сохранена в `docs/history/README_2.5.4.md`.
- `examples/inbound-raw-full.example.json` и `examples/inbound-xhttp-full.example.json` повторяют структуру **реального генератора** и различаются только transport/flow/XHTTP settings. Эти примеры не содержат пригодных для production приватных ключей; реальные ключи существуют только в приватном каталоге VPS. Оба примера согласованы с README тестами на побайтовое совпадение.
- Новый **read-only** `sudo bash install.sh --xray-versions [--offline]`: сообщает реальную версию `rw-core` в запущенной RemnaNode и метаданные stable/pre-release официального Xray; ошибок сети не скрывает. Никакой загрузки Xray Core, подмены контейнера, автоматического pre-release, изменения Panel или restart. Подробности и процедура безопасного обновления в `docs/XRAY_CORE_UPDATES_2.5.5.md`.
- Проверен официальный код RemnaNode `CoreLoaderService`: pinned custom Core через `geodata.core.url + sha256` возможен как **отдельное осознанное изменение Xray Config Profile**, не неявная операция установщика. Основной рекомендованный upgrade path остаётся официальным RemnaNode image digest с проверкой совместимости и откатом.
- Исправлены пропущенные разрешённые контракты `2.5.5` в операциях `--check` (XHTTP), `--prepare-xhttp`, RKN Guard, обслуживании cover и проверке завершённой установки. Будущие неизвестные версии продолжают отклоняться.
- Убрано дублирование собственного IPv4/32 в routing запрещённых направлений при совпадении `public_ipv4` и локального интерфейса. Политика блокировки, DNS по умолчанию и внешние сетевые правила не менялись.
- Новые статические/симуляционные тесты Xray release feed, отказ при невалидных данных, Docker probe, полнота и согласованность full examples, повторный запуск, запрет Vision в XHTTP, межверсионные ACL/gates и отсутствие дубликатов CIDR.
- **Не менялись:** действующие SSH/UFW, Docker image, Nginx Selfsteal/ACME/PROXY v1/H2, REALITY identity, RKN timer, Node Plugins, конфигурация Remnawave Panel и live inbound. Локальный offline PASS не означает подтверждения баностойкости или HTTPS/VPN доступности из РФ.
- При **следующей сборке** обязательно сверить новые коммиты `Flecksis/rkn-guard` и источник `shadow-netlab/traffic-guard-lists`, а также changelog/security Xray и RemnaNode, не обновляя непроверенный исполняемый код автоматически.

## 2.5.4 — 2026-10-09

- Реализована поддержка **альтернативного** XHTTP+REALITY inbound вместо RAW+REALITY+Vision, без одновременной работы на одном публичном TCP/443 и без добавления фонового механизма переключения. Выбор inbound полностью вручную в Remnawave Panel, далее штатное применение/рестарт RemnaNode, не reboot Ubuntu.
- Новая установка продолжит безопасную настройку RAW, даже если дополнительный XHTTP-синтаксис не поддерживается текущим образом; XHTTP будет явно NOT_READY до успешного `--prepare-xhttp`.
- Два локальных защищённых импортных шаблона (RAW и XHTTP), одинаковые теги/REALITY ключи/ShortID, один host Nginx Selfsteal Unix-socket PROXY v1 TLS/H2, те же DNS/routing и профильные проверки. XHTTP пустой `flow`, отдельный стабильный HMAC path.
- Команда `sudo bash install.sh --prepare-xhttp` готовит/верифицирует XHTTP-файл на завершённой 2.5.2/2.5.3/2.5.4 ноде без изменения действующего профиля, firewall, Docker Compose, Nginx, RemnaNode или ключей; синтаксис проверяется установленным `rw-core` на staging-file в контейнере. Файл не перезаписывается при отличии от ожидаемого.
- Уточнена read-only проверка профиля с Remnawave API inbound и политика для двух транспортов; старые RAW проверки остаются.
- Полный runbook: [TRANSPORT_SWITCHING_2.5.4](docs/TRANSPORT_SWITCHING_2.5.4.md). Отсутствие реального VPN-canary указано явно; баностойкость не гарантируется.
- Функциональность и ежедневные обновления RKN Guard 2.5.3, UFW/SSH/Nginx/certbot, Docker image management и пр. сохраняются.

## 2.5.3 — 2026-10-09 (RKN data integration, 609 offline tests)

- `Flecksis/rkn-guard` review: вместо небезопасного `curl | bash`/замены чужих UFW правил использован встроенный IPv4-only `ipset` + маркированный UFW hook, источники CIDR — из `shadow-netlab/traffic-guard-lists` согласно upstream.
- Ежедневное `systemd` обновление CIDR по HTTPS с валидацией, атомарным `ipset swap`, сохранением последней успешной загрузки и сохранением существующих правил при сетевых ошибках.
- Исключения IP панели динамические: чтение `panel_ipv4` из конфигурации при загрузке и при каждом обновлении, без закреплённого IP в скрипте.
- Фильтрация только входящих новых TCP/80,443, без IPv6, SSH, Node API 2222, Docker/Nginx/Xray и чужих user.rules. Дополнительные команды: `--enable-rkn-guard`, `--rkn-update`, `--rkn-sync-panel`, `--rkn-status`, `--rkn-disable`.
- Boot-порядок UFW через отдельную `vkarmani-rkn-prepare.service`, UFW before.rules atomic backup/reload/rollback; отдельный runbook [`docs/RKN_GUARD_2.5.3.md`](docs/RKN_GUARD_2.5.3.md).
- Обязательный просмотр репозитория upstream на **каждом будущем релизе** (новые коммиты/версия/новый источник данных). **Автообновление upstream исполняемого кода запрещено**.
- Release status: локальные offline-тесты; реальный VPS/UFW/SSH/Panel→Node/VLESS canary ещё НЕ ПРОВЕРЕН.

# Изменения

## 2.5.2 — 2026-10-06

- Исправлен реальный preboot false-negative: RemnaNode `NODE_PORT` может временно быть AF_INET6 wildcard dual-stack socket до reboot; acceptance принимает его только при exact `rw-node` ownership/PID, `net.ipv6.bindv6only=0` и успешном IPv4 connect к loopback и public IPv4.
- Исправлен postboot false-negative: generated RAW+REALITY profile штатно разрешает `0.0.0.0:443`; public-listener audit теперь разрешает Xray 443 на public IPv4 или IPv4 wildcard, сохраняя строгую проверку owner/PID. TCP/80 остаётся только на конкретном public IPv4.
- Реальная Ubuntu 24.04 нода после reboot подтвердила IPv6 kernel disable, `2222` на IPv4, `rw-core` на `0.0.0.0:443`, `NODE_PLUGINS_PREREQS=PASS`, full local acceptance и успешный postboot systemd service. Panel path и authenticated client не объявляются проверенными.


## 2.5.1 — 2026-10-06

- Исправлен реальный false-negative `NODE_CAPABILITY_POLICY` на Docker Engine 29.8.x: `docker inspect` может возвращать canonical `CAP_NET_ADMIN` / `CAP_NET_RAW`; checker теперь нормализует только допустимый `CAP_` prefix и по-прежнему требует exact `NET_ADMIN` add, exact `NET_RAW` drop и `no-new-privileges`. Дополнительные capabilities не разрешены.
- Исправлен `PUBLIC_TCP_LISTENERS_POLICY FAIL NOT_VERIFIED INVALID_LOCAL_DATA` на Ubuntu 24.04: `ss` может печатать loopback `systemd-resolved` как `127.0.0.53%lo:53`; parser теперь отделяет display scope `%iface`, игнорирует настоящий loopback и продолжает строго проверять non-loopback listeners.
- Добавлен explicit `--repair-acceptance` только для exact незавершённого 2.5.0 final-acceptance failure (`INSTALL_FAILED rc=1 line=6412` + exact reviewed helper SHA). Repair делает private backup, staging, syntax/post-check и rollback; не запускает APT, не меняет SSH/UFW/Nginx/GRUB/sysctl, не restart/recreate Docker/RemnaNode, не меняет Panel и не переписывает исходную `install-version=2.5.0`.
- Реальный Ubuntu 24.04 запуск 2.5.0 теперь зафиксирован как **failed canary evidence**, а не как production verification. Post-fix 2.5.1 VPS canary остаётся обязательным.

[Hotfix detail](docs/HOTFIX_2.5.1.md) · [Node Plugins base contract](docs/NODE_PLUGINS_2.5.0.md) · [Operations](docs/OPERATIONS.md).

## 2.5.0 — 2026-10-06

- Исправлена первопричина acceptance-version bug: одна reviewed contract classification для modern/legacy/unreviewed; 2.4.1–2.4.3 снова используют `ssh_guard.py check` и strict Selfsteal target check, future/malformed versions fail closed.
- До системных изменений добавлен kernel `>=5.7` preflight; `nftables` добавлен в signed distro package plan без запуска сервиса или управления `/etc/nftables.conf`.
- Profile validator защищает sniffing `enabled/routeOnly/http+tls+quic` и существующие TCP/443 RAW+REALITY+Vision+Selfsteal invariants.
- Acceptance проверяет Xray functional floor `26.3.27`, reviewed security floor `26.7.11`, effective `NET_ADMIN`, read-only `ip remnanode` structure и публичную TCP surface. Panel Plugin Config и реальный Torrent detection остаются честно `NOT_VERIFIED`.
- `--diagnose-resources` расширен conntrack, disk/inode percentages, reboot marker и threshold hints без auto-tuning.
- Добавлены reference-only Node Plugin policy, external-path taxonomy/control-vantage runbook, safe replacement и provider-abuse incident guidance. Никаких RST/community auto-blocklists, custom Xray, fingerprint/SNI rotation, нового daemon/container/cron или Panel API mutation.
- Real VPS canary в локальном build environment не выполняется и не должен объявляться `production verified`.

[Node Plugins](docs/NODE_PLUGINS_2.5.0.md) · [Survivability](docs/SURVIVABILITY_2.5.0.md) · [External diagnostics](docs/EXTERNAL_PATH_DIAGNOSTICS_2.5.0.md) · [Replacement](docs/NODE_REPLACEMENT_2.5.0.md).

## 2.4.3 — 2026-10-03

Release/CI integrity fix after the published 2.4.2 tree failed before tests on every runner.

- Root cause: three preserved CI evidence `.txt` files were packaged with CRLF while `.gitattributes` contains `* text=auto`; Git normalized those files to LF during commit/checkout, so the repository bytes no longer matched the CRLF hashes stored in `SHA256SUMS`.
- Normalized `docs/evidence/241-ci-ubuntu22-failure.txt`, `241-ci-ubuntu24-failure.txt`, and `241-ci-ubuntu26-userspace-failure.txt` to canonical LF and rebuilt the release manifest.
- Added `CIContractTests.test_manifest_text_files_are_git_canonical_lf`, which rejects CR/CRLF in UTF-8 text entries covered by `SHA256SUMS`.
- Release validation now includes a real temporary Git repository round-trip (`git add`/commit/clean clone/checksum verification), so ZIP-only hash validation is no longer considered sufficient.
- Production runtime behavior is unchanged from 2.4.2: NET_ADMIN default, Nginx/Selfsteal, certificate reload convergence, Docker, firewall, SSH, profile/network policy and runtime dependencies are unchanged.

[Проверки](docs/TEST_REPORT.md) · [CI-разбор](docs/CI_GIT_NORMALIZATION_2.4.3.md) · [безопасность](SECURITY.md).

## 2.4.2 — 2026-10-03

CI-only contract fix after the published 2.4.1 run failed identically on Ubuntu 22.04, Ubuntu 24.04 and Ubuntu 26 userspace. The only failing test was the synthetic fragmented-PROXY case; the 2.4.1 certificate-reload regressions passed.

- `test_large_fragmented_clienthello_and_proxy_header` incorrectly split the PROXY v1 line into 7-byte writes. Nginx can read the first partial bytes before the rest arrives and rejects that as a malformed PROXY header; on a fast local machine the writes were sometimes coalesced and the test passed accidentally.
- The integration test is renamed to `test_large_fragmented_clienthello_after_complete_proxy_header`. It now sends the complete PROXY v1 line first, waits briefly so Nginx can consume it, then fragments the large TLS ClientHello into 37-byte writes with short pauses. The intended fragmented-TLS coverage therefore remains real and becomes deterministic.
- Local reproduction records Nginx `broken header: "PROXY T" while reading PROXY protocol` and the same client-side `BrokenPipeError` seen in all three CI jobs.
- Upstream Xray fallback code builds PROXY v1 into a dedicated buffer and writes that buffer before copying the fallback payload; the corrected test matches that contract instead of inventing a fragmented PROXY header transport.
- Production `install.sh` behavior is unchanged except the release/version allowlists and version markers: NET_ADMIN default, Selfsteal Nginx config, Xray/REALITY profile, firewall, SSH, cert-deploy convergence logic and runtime package set are unchanged.
- Full local suite remains 556 tests; root and UID 1000 must both pass before packaging.

[Проверки](docs/TEST_REPORT.md) · [CI-разбор](docs/CI_PROXY_FRAGMENTATION_2.4.2.md) · [безопасность](SECURITY.md).

## 2.4.1 — 2026-10-03

Bugfix после реального GitHub Actions failure на Ubuntu 24.04 (`nginx 1.24.0`, Python 3.12): обнаружена гонка graceful reload при проверке нового TLS-сертификата Selfsteal.

- Certbot deploy-hook больше не принимает один успешный `--target-only` probe как достаточное доказательство активации нового leaf-сертификата. Теперь требуются 4 последовательных успешных target-only TLS-проверки; любая промежуточная ошибка сбрасывает серию и проверка продолжается в общем bounded deadline.
- Это не ослабляет acceptance gate и не маскирует ошибку: `CERTIFICATE_NOT_RELOADED`, CA/hostname/leaf failures и timeout по-прежнему являются отказом, если стабильная серия не достигнута.
- Интеграционный Nginx test cleanup теперь также ждёт 4 последовательных подтверждения возврата исходного сертификата после обратного reload и учитывает `ssl.SSLError`, чтобы следующий тест не наследовал переходное состояние предыдущего.
- Добавлена регрессия `test_single_target_success_is_not_enough_after_graceful_reload`. Полный локальный набор: 556 тестов; root и UID 1000 — PASS без errors/failures/skips.
- `NET_ADMIN` default из 2.4.0, Docker Compose, network/firewall/SSH/profile/runtime dependencies не менялись. Reviewed-version allowlists дополнены 2.4.1, поддержка 2.4.0 сохранена.

[Проверки](docs/TEST_REPORT.md) · [безопасность](SECURITY.md).

## 2.4.0 — 2026-10-02

Изменена default capability-политика RemnaNode по прямому требованию эксплуатации: функционал «Обозреватель сессий» должен работать без отдельного opt-in на каждой новой ноде.

- Generated Compose теперь всегда содержит `cap_add: NET_ADMIN`; новая конфигурация и resume 2.4.0 сохраняют `allow_net_admin=true`.
- `--allow-net-admin` оставлен как совместимый CLI-флаг старых команд, но в 2.4.0 capability уже включена по умолчанию.
- Checker больше не выдаёт штатный `NET_ADMIN` как warning: при `allow_net_admin=true` + фактическом capability это PASS; mismatch state/container остаётся FAIL.
- `NET_RAW` drop, `no-new-privileges`, read-only Selfsteal mount, host Nginx, UFW/Fail2ban, SSH password-only, IPv4-only, image digest pin и три обязательных поля не ослаблялись/не менялись.
- Reviewed-version allowlists profile-check/maintenance/cover дополнены 2.4.0 без удаления 2.3.0 и предыдущих поддерживаемых версий.
- Для уже завершённых нод обычный повтор installer по-прежнему не является миграцией. Добавлен отдельный backup/validate/recreate/rollback runbook с `--pull never` и проверкой неизменности image.
- Security-документация теперь явно фиксирует повышенный blast radius `NET_ADMIN` при `network_mode: host`; массовая раскатка требует canary.
- История семи актуальных документов 2.3.0 сохранена побайтово в `docs/history` до их обновления.
- Локальный набор увеличен до 555 тестов: все 554 прежних сохранены, добавлена проверка того, что новый install state действительно фиксирует `allow_net_admin=true`.

[Изменение NET_ADMIN и rollout](docs/NET_ADMIN_2.4.0.md) · [проверки](docs/TEST_REPORT.md) · [безопасность](SECURITY.md).


## 2.3.0 — 2026-10-02

Локально проверенный release-candidate на базе 2.2.0. Полная VPS/клиентская приёмка не заявляется; TECH и рабочие ноды не изменялись.

- Новый явно запрошенный SSH-контракт: password-only, publickey/kbd-interactive/hostbased/GSSAPI off. Пароли, accounts и authorized_keys не удаляются/не переписываются. Ровно три прежних вопроса; проверка локальной shadow/aging/shell без запроса пароля. Условные Match/нестандартные Includes требуют отдельного аудита. Candidate проверяется до atomic replace; безопасные порты и rollback guard сохранены.
- Selfsteal readiness разделена: `--target-only` проверяет PROXY/TLS1.3/CA/hostname/leaf/ALPN без чтения страницы; обычный запуск сохраняет полную WEB_CONTENT-приёмку. Ошибка CSS не маскируется под неактивный сертификат. Config/certificate reading ограничены, private config symlinks/FIFO/дубли JSON отвергаются.
- Certbot deploy: ограниченный по времени `nginx -t` → reload → target verify, private lock и atomic phase/generation receipt. Другие lineages не затрагиваются; сигналы не подавляются retry. Dry-run запускает deploy hooks и требует свежего успешного receipt с текущим сертификатом. Без NAT/перехвата443, новых timers или restart Xray.
- TCP/443 сверяется с PID core внутри работающего host-network RemnaNode. Чужой владелец и неудачный сбор метаданных не получают Xray PASS. Секретные process arguments/environment не читаются.
- Новый generated template добавляет общий Vision `xtls-rprx-vision`, minClientVer остаётся0.0.0. DNS/routing и live-профили не заменяются. Password policy не переносится на TECH.
- Resource helper дополнен FD/soft-hard limits и очередью Selfsteal Unix socket; отсутствие/ошибка чтения отличены. Dpkg/IPv6 checks больше не принимают failed command+empty output за успех.
- 89 новых тестов, всего554: включая настоящий Nginx cert reload и невалидную пару key/cert; SSH/Certbot/systemd/процессные отказы моделируются без установки на runner. Все465 прежних тестов сохранены, ожидания трёх файлов обновлены под явный новый контракт.
- Новых runtime-пакетов, постоянных служб, HAProxy/Caddy/XHTTP/firewall agents нет. Сайт 2.2.0 и CI workflow сохранены. Автоматическая миграция старой установленной части не добавлена.

[Реализация и пределы](docs/RELIABILITY_2.3.0.md) · [проверки](docs/TEST_REPORT.md).


## 2.2.0 — 2026-10-02

Локальный release-candidate собственного Selfsteal. База 2.1.3 сохранена; серверы и GitHub не изменены, полноценный VPS-пилот не заявлен.

- Сохранены RAW/REALITY и собственный Unix-target, host Nginx, UFW/SSH/IPv4/Docker/ACME. XHTTP, HAProxy, NAT/string-firewall и новые зависимости не добавлены.
- HTTP/80: ACME сохранён, redirect фиксирован на собственный домен; другой Host получает 404, разрешены GET/HEAD. TLS: default reject для неизвестного SNI на Nginx >=1.19.4; для старых пакетов ограничение отмечается явно. Неверный Host — 421, пишущий метод — 405.
- Ограничен набор статических путей и доступ через symlink. CSP, nosniff и Referrer-Policy сохраняются на assets/304/404. Хешированные assets кэшируются семь дней, HTML требует revalidation. Ограничены send timeout и Range-запросы.
- Extended target probe: проверка CA/TLS1.3/HTTP1/HTTP2, HEAD, assets/hash/MIME/ETag304, вспомогательных файлов, отрицательных URI/методов/Host/SNI. Чтение файлов ограничено по типу/правам/размеру. PASS не означает успешный VLESS-клиент или доступ с любой внешней сети.
- Четыре собственных встроенных cover-варианта; стабильный случайный seed при первой установке/обновлении, атомарное root-only state без перезаписи, сохранён прежний receipt/rollback. Нет внешних шаблонов, JS или CDN.
- 45 новых регрессионных тестов: локальный Nginx, ACME-пути, отрицательные URI, большой фрагментированный TLS ClientHello, параллельные проверки и identity state. Общий набор — 465 тестов. Браузерная проверка — 36 сочетаний четырёх вариантов и девяти ширин.
- История документов 2.1.3 сохранена побайтово. Автоматической миграции Nginx/helpers старых узлов нет; обновление сайта не подменяет общий upgrade.

[Selfsteal и приёмка](docs/SELFSTEAL_2.2.0.md), [источники](docs/SOURCE_REVIEW_2.2.0.md), [проверки](docs/TEST_REPORT.md).

## 2.1.3 — 2026-10-02

Локальная доработка генератора и проверки профиля; никакого production-deploy, смены транспорта или автоматической миграции старых нод.

- Единая `PROFILE_MIN_CLIENT_VERSION=0.0.0`: generated profile, validator, key export, PANEL-SETUP. X25519/ShortID переиспользуются; остальные поля generated template не менялись.
- Устранён пропуск import-profile проверки для 2.1.2: явный список 2.1.0/1/2/3; future/unknown version — FAIL, known legacy/missing marker — NOT_VERIFIED.
- Проверяются формы DNS/routing, UseIPv4, существование/уникальность outbound tags, прямой IPv4 listener без входящего PROXY protocol. Общий Vision и корректная служебная API-вставка допускаются без изменения supplied JSON.
- Чтение profile-check ограничено regular файлом до 2 MiB, без финального symlink; duplicate fields и NaN/Infinity отвергаются. PASS не выдаётся за проверку фактических TCP/UDP блокировок или клиента.
- Maintenance/cover allowlists дополнены 2.1.3 с сохранением прежних версий.
- 37 новых регрессионных тестов; 420 тестов прошли от root и UID 1000, без skips. Состояние старых нод/ядра/egress не менялось. Ubuntu/VPS/full-client приёмка 2.1.3 пока отсутствует.
- README/SECURITY/OPERATIONS и manifest актуализированы; предыдущие README/SECURITY/TEST_REPORT/RELEASE_VALIDATION 2.1.2 сохранены побайтово в history. Release ZIP без `.git`; оригинальный input ZIP не изменён.

[Область изменения и rollout](docs/PROFILE_COMPATIBILITY_2.1.3.md), [проверки](docs/TEST_REPORT.md).

## 2.1.2 — 2026-09-30

Production-доработка финального этапа установки после проверки трёх реальных нод и перехода на собственный Selfsteal.

- После успешной preboot-проверки создаётся `/root/reality-keys.txt` с правами `0600`: `PrivateKey`, `PublicKey`, `ShortID`, домен, `target`, `xver` и `minClientVer`. Используются уже созданные `/etc/vkarmani-node/reality.json` ключи; повторной генерации на финальном этапе нет.
- Финальный блок `PrivateKey` / `PublicKey` / `ShortID` показывается непосредственно в controlling TTY, обходя `tee`; приватный ключ не дублируется в `/var/log/vkarmani-node-install.log`. При небезопасном существующем symlink/типе/владельце/правах export останавливается без перезаписи.
- Одноразовый reboot после успешной установки теперь включён по умолчанию: transient systemd unit запускает `reboot` через 30 секунд. `--no-reboot` — явный opt-out; `--reboot` сохранён для совместимости. Ошибка постановки transient unit не отменяет уже завершённую локальную установку и требует ручного `sudo reboot`.
- В генерируемый VLESS RAW REALITY template добавлен `minClientVer: "1.0.0"` для подтверждённой на рабочих профилях совместимости старых Xray-core. Selfsteal остаётся `target=/dev/shm/nginx.sock`, `xver=1`, собственный `serverNames` и индивидуальные ключи ноды.
- APT/dpkg coordination 2.1.1, три обязательных вопроса, UFW/Fail2ban, SSH, Docker layout, Nginx/Selfsteal и image pinning не ослаблялись.
- Добавлено 6 регрессий; полный локальный набор: 383 PASS от root и UID 1000, 0 skips. Полный VPS install/reboot именно 2.1.2 ещё не выполнялся.

[Дизайн финального этапа](docs/REALITY_KEYS_AUTOREBOOT_2.1.2.md), [проверки](docs/TEST_REPORT.md), [безопасность](SECURITY.md).

## 2.1.1 — 2026-09-30

Production-исправление координации APT/dpkg после реального инцидента на свежей Ubuntu 24.04.

- Перед `dpkg --audit` и всеми обязательными APT-транзакциями проверяются реальные lock владельцев через `lslocks`; штатные `apt-daily` / `unattended-upgrades` ожидаются до 30 минут.
- Статус ожидания выводится раз в 30 секунд вместо сотен строк `Waiting for cache lock`.
- Чужие `apt`/`dpkg`/`unattended-upgrade` не завершаются, lock-файлы не удаляются, security updates не отключаются.
- Встроенный `DPkg::Lock::Timeout` сокращён до 15 секунд как защита от узкой гонки; повтор выполняется только если код/журнал подтверждают lock-error. Другие APT-ошибки проходят без маскировки.
- `dpkg --audit` выполняется только после освобождения package-manager locks, чтобы не принимать промежуточное состояние активной транзакции за повреждение базы.
- VLESS RAW REALITY, Selfsteal, Nginx, UFW/Fail2ban, SSH, Docker layout и три вопроса не менялись.
- Добавлено 6 регрессий; полный локальный набор: 377 PASS от root и UID 1000, без skips. Полная VPS-установка 2.1.1 после изменения ещё требует пилота.

[Подробности](docs/APT_LOCK_COORDINATION_2.1.1.md), [проверки](docs/TEST_REPORT.md).

## 2.1.0 / ci-fix2 — 2026-09-30

Исправлены две причины из журналов запуска #36679239665. **Production `install.sh` и preview не изменены**, SHA256 установщика прежний: `9420c5a76749fd0ae52c26279e78069fca42b40d8a7bae9d80b950a89b3f976c`.

- Ubuntu 22.04: тестовый JS HKDF-эталон совместим с отсутствием native API в Node 12. Использует native `hkdfSync`, когда он доступен, и RFC 5869 на встроенном `createHmac` иначе. Ошибка существующего native API не перехватывается и не маскируется. Проверка SNI и сравнение с production helper сохранены, stderr Node теперь виден при отказе.
- Ubuntu 26.04 CI-контейнер: отдельный шаг после checkout и до Git-проверок добавляет только точный `$GITHUB_WORKSPACE` в global config текущего shell-контекста. Проверяются абсолютный путь, `.git` и совпадение рабочей папки. Нет wildcard trust, изменения владельцев, `--system` или прав production.
- 15 новых регрессий: 6 HKDF (RFC A.1/A.2/A.3, обе ветви, canonicalization, границы и отказ native API) и 9 Git (порядок шагов, настоящий Git, разные HOME, только один доверенный репозиторий и отказы до записи).
- 371 тест прошёл от root, UID 1000 и UID 1000 с выключенным native HKDF на Node 22. Отдельно воспроизведены реальные разные UID Git без тестового hook. Настоящий Node 12 и Ubuntu-гости локально не запускались; новый удалённый run требуется.
- Исторические README, TEST_REPORT и RELEASE_VALIDATION ci-fix1 сохранены дословно. Полный проект по-прежнему без `.git`: при обновлении clone сохраняйте действующую историю.

[Разбор ci-fix2](docs/CI_FIX2_2.1.0.md), [проверки](docs/TEST_REPORT.md).

## 2.1.0 / ci-fix1 — 2026-09-30

Исправление CI и тестовой среды, **не новая версия production-установщика**. `install.sh` побайтово совпадает с 2.1.0 (SHA256 `9420c5a76749fd0ae52c26279e78069fca42b40d8a7bae9d80b950a89b3f976c`); поддержка ОС, три вопроса, VPN, SSH/firewall, сайт и режимы обслуживания не изменены.

- Настоящий тест APT использует полностью отдельные Dir::State/Cache/Etc/Log, списки, dpkg-status и binary cache. Системный `/var/lib/apt/lists` больше не участвует; проверка работает без sudo. Блокировки не отключаются.
- Все пять временных каталогов тестового Nginx перенаправлены в приватный fixture вместо абсолютных defaults пакетной сборки.
- В userspace-job Ubuntu 26.04 Git и сертификаты устанавливаются до `actions/checkout`; отсутствующая `.git` больше не маскируется поздней установкой Git. Матрица 22.04/24.04/26.04 сохранена.
- Проверка checkout и SHA256SUMS идёт отдельным шагом перед тестами. Git diff после тестов выделен отдельно; выводятся UID и версии инструментов. Нет continue-on-error и нет sudo для набора тестов на VM-runner.
- 349 прежних + 7 новых = 356 тестов. Локальные root/non-root прогоны успешны, но полный лог исходного удалённого запуска не получен; связь каждого удалённого отказа с воспроизведёнными причинами требует нового CI-прогона либо полного лога.
- Прежние README, TEST_REPORT и RELEASE_VALIDATION 2.1.0 сохранены в docs/history.

Разбор и безопасное применение: [CI_FIX_2.1.0](docs/CI_FIX_2.1.0.md).

## 2.1.0 — 2026-09-30

- Ubuntu26.04/Resolute добавлена с точным codename, cgroupv2 и проверкой опций базовых утилит. Подготовлен userspace CI; полноценная VPS-приёмка26.04 не выполнена.
- Docker signing key/repository и общий пакетный план проверяются до SSH/UFW/GRUB. Ошибки apt update не замещаются молчаливо старыми индексами.
- Chrony сохраняет sources/includes/NTS/bootstrap; проверяемая IPv4/client-only добавка вместо полной перезаписи. Timesyncd сохраняется при наличии.
- Необязательный apt clean больше не препятствует приёмке; lock busy, timeout и прочие ошибки различаются. Чужие package processes и lock-файлы не трогаются.
- Новый лёгкий статический сайт; отдельный проверяемый update/rollback только сайта для завершённых2.0.3/2.1.0 без рестартов/изменения VPN.
- Read-only срез ресурсов: CPU/steal/PSI/RAM/swap/TCP/OOM/disk, без автонастройки и без клиентских данных.
- 349 тестов вместо304; плюс визуальный Chromium-тест9 размеров. Длительная VPN-нагрузка и полная установка новой версии на VPS не выполнялись.
- Прежние README/TEST_REPORT/RELEASE_VALIDATION2.0.3 сохранены в docs/history. Полный архив без.git.

Подробности: [IMPROVEMENTS_2.1.0](docs/IMPROVEMENTS_2.1.0.md), [COVER_SITE](docs/COVER_SITE.md), [UBUNTU_26_04](docs/UBUNTU_26_04.md).

## 2.0.3 — 2026-09-30

Исправление фактического раннего отказа APT в 2.0.2: список требовал Chrony, тогда как `--no-remove` запрещал необходимое для него удаление установленного systemd-timesyncd.

- Сохраняется уже установленный поддерживаемый NTP-клиент. Если нет ни Chrony, ни timesyncd — устанавливается Chrony. Неизвестный/неполный/противоречивый daemon вызывает явный отказ, не замену.
- Общий `--no-remove` сохранён в проверке плана и фактической компонентной транзакции. Никаких исключений для удаления timesyncd и никаких `apt autoremove`/`--allow-*`.
- Timesyncd сохраняет источники ОС/хостера, получает проверяемый IPv4-only systemd drop-in. Добавлен встроенный стандартно-библиотечный helper выбора/контроля NTP с общими deadlines, private atomic marker. Chrony использует прежнюю конфигурацию и порог коррекции 0.1 секунды. Backup и postboot учитывают выбранную службу.
- Добавлен узкий защищённый переход с раннего `rc=100 line=2761` 2.0.2: проверка файлов/версии/стадии/старого helper, сохранение ключа и трёх параметров, новая проверенная копия до изменения версии. При срыве backup исходный checkpoint сохранён. Другие стадии и завершённые ноды автоматически не мигрируются.
- 226 прежних + 78 новых = 304 теста. В том числе настоящий APT solver на локальных синтетических метаданных без установки пакетов и без Ubuntu-репозиториев; службы NTP/SSH/Docker на VPS не тестировались.
- Обновлены README, операции, описание инцидента, источники, тестовый отчёт и manifest. Прежние отчёт и validation 2.0.2 сохранены дословно. Рабочий архив поставляется без `.git`, метаданные старого архива сохранены отдельно, чтобы не затирать историю пользователя.

VLESS RAW REALITY, собственный Selfsteal, host Nginx, SSH по паролю, три обязательных значения, политика UFW/Fail2ban, сеть и Docker не переархитектурены. Публикация на GitHub и изменение сервера из среды подготовки не выполнялись.

## 2.0.2 — 2026-09-30

Узкое исправление остановки первой установки на Ubuntu 24.04 / UFW 0.36.2-6. Причина подтверждена присланным выводом: UFW inactive, `show added` — `(None)`, но стандартные `ufw-user-limit*` ошибочно считались пользовательскими правилами.

- Вместо широкого grep проверяются `user.rules` и `user6.rules`: пустой filter-шаблон и только точные служебные limit-правила. Изменённые helper-цепочки, пользовательские input/output/forward-правила, tuple metadata, неизвестные директивы, повреждённая структура, symlink и не-regular файлы отклоняются. Ошибка чтения/awk не считается успехом.
- Проверка только читает файлы, не вызывает ufw/iptables/nft/systemctl, не включает IPv6, не сбрасывает firewall и не добавляет зависимости перед APT. Остальные сетевые и SSH-защиты не отключены.
- Добавлены точные текстовые fixtures инцидента и 48 тестов действительных Bash-функций/точки вызова. Сохранены все прежние 178 тестов; обновлено только ожидание номера версии. Полная установка на VPS здесь не выполнялась.
- README содержит актуальный hash и явное сообщение при несовпадении скачанного файла. Обновлены эксплуатационный регламент, аудит, отчёт о тестах и manifest; отчёт/validation 2.0.1 сохранены дословно в history.
- Три обязательных значения, VLESS RAW REALITY, собственный Selfsteal, Nginx вне Docker, парольный SSH и прежняя политика портов не изменены.

STOP этого инцидента срабатывал до `vk_collect_inputs`, записи version/owned markers и APT. После устранения именно этой причины можно начать первую установку новым файлом; это не миграция уже установленной или частично установленной 2.0.1. GitHub автоматически не обновлялся.

## 2.0.1 — 2026-09-30

Уточнение проекта: **VLESS RAW REALITY + свой Selfsteal**, без новых транспортов, сервисов и дополнительных обязательных входов.

- Исправлен HTTP/2 flow control в проверке Selfsteal; добавлены общий deadline, точная проверка загруженного leaf, отрицательные HTTP/2-сценарии и явный предел cover 128 KiB.
- Добавлена предварительная безопасная проверка/очистка собственного неработающего Unix socket перед стартом Nginx; исправлено исчерпание StartLimit при длительном отказе. Активный/чужой/неоднозначный объект не удаляется.
- Maintenance завершает process group при timeout/signals. Неопределённый Compose apply сохраняет pending и не запускает встречный автоматический rollback. Общий readiness deadline охватывает Docker inspect, probes и ожидание.
- Firewall check обнаруживает пропущенные SSH/80/443/API-разрешения, лишние accept/неподдержанные rules и INPUT drift; учитывает только SSH-port-scoped временные Fail2ban bans.
- Добавлена узкая проверка политики локального/предоставленного RAW REALITY JSON: собственный SNI/локальный target и конфликтующие aliases. Live-панель и владение доменом не подтверждаются.
- Сохранённый digest повторно валидируется; перед возобновлением не перезаписывается незавершённый SSH/UFW backup. Atomic JSON/text синхронизируют родительский каталог; backup синхронизирует архив до публикации успешного checksum.
- 178 тестов вместо 74, включая реальные Nginx crash/recovery, PTY, subprocess и synthetic tar roundtrip; имитация registry/Compose/disk failures. Live VPS/Docker/VPN и массовое внедрение не тестировались.
- Добавлены отчёт отказов, разбор сообщений хостеров, актуальная матрица проверок и ограничения обновления действующей 2.0.0. Исторический TEST_REPORT 2.0.0 сохранён отдельно.

Рабочие 2.0.0/1.3.x не мигрируются автоматически; README-команда устанавливает 2.0.1 только после публикации соответствующего файла в GitHub. Git push не выполнялся.

## 2.0.0 — 2026-09-30

Переработка предоставленного `Node_Install.zip`, в котором `install.sh` объявлял 1.3.4. Это новая версия для чистых выделенных нод, не автоматический in-place upgrade рабочих 1.3.x.

### Поведение установки

- Ровно три обязательных вопроса в порядке: SECRET_KEY, домен ноды, исходящий IPv4 технички. Адрес ноды выбирается по DNS среди назначенных публичных IPv4.
- По умолчанию отключены одноразовый и еженедельный reboot. Сохранены явные opt-in флаги и совместимый `--no-reboot`.
- Убраны массовое обновление ОС, автоматический autoremove и удаление Docker-объектов из обычного сценария.
- Завершённый повторный запуск — только диагностика; незавершённая установка продолжается только в том же поколении.
- Усилены preflight, проверка чужого firewall/пакетов/SSH, приватность ввода, backup manifests и блокировка параллельных операций.

### SSH, сеть и Selfsteal

- Явный парольный SSH без source-IP allowlist; сохранение существующих портов и ключевых настроек. Системные аккаунты и пароли не меняются.
- Аварийный откат фазы SSH/UFW с lock и проверяемыми состояниями armed/running/done; это не внешний тест входа.
- Fail2ban-действие всегда ограничено SSH-портами; нет бессрочного исключения IP технички/администратора.
- Nginx остаётся на хосте. Новый отдельный каталог socket `/run/vkarmani-selfsteal` вместо предоставления контейнеру всего host `/dev/shm`.
- NET_ADMIN — только явный opt-in для соответствующих upstream-функций; default `cap_drop: NET_RAW` и no-new-privileges.
- Добавлены MTU black-hole probing, проверяемый fallback BBR/fq и запись фактических значений. MTU, NIC offload, маршруты и root qdisc не переписываются.
- Неподдерживаемые optional-модули не записываются в обязательную boot-загрузку.
- REALITY-ключи сохраняются, проверяется их пара; routing template дополнительно закрывает собственные public IP и IP панели.

### Диагностика и обслуживание

- API TLS использует выведенный по upstream HKDF SNI, CA и точный leaf pin. Фрагментированный ClientHello; отсутствие клиентского сертификата не выдаётся за успешный mTLS панели.
- Selfsteal проверяется через TLS 1.3, PROXY v1, HTTP/1.1 и реальный HTTP/2 с ожидаемым телом ответа.
- Закреплённый image digest; отдельные backup / refresh-image / rollback-image без повторной настройки ОС.
- Транзакции обновления, сохранение предыдущего Compose/image, автоматическая попытка отката при локальной ошибке и pending marker при неподтверждённом восстановлении.
- Откат явно ограничен Compose и образом, не writable layer, панелью, ОС или клиентскими сессиями.
- Сохранены узкие repair-команды для завершённых 1.3.x; удалён `--remove-orphans` из их запуска Compose.
- Переписаны README/SECURITY, добавлены аудит, регламент эксплуатации, источники, тестовый отчёт, offline-тесты и CI. Git-история не переписана; push не выполнялся.

### Сохраняемые ограничения

GRUB, управляемое ядро, непосредственный публичный IPv4, чистая выделенная VPS и указанные версии ОС. Панель/Cloudflare/провайдер не настраиваются без доступа к их API. Работоспособность панели и реального VPN-клиента проверяется отдельно. Полный стендовый deploy обязателен до массовой production-раскатки.
