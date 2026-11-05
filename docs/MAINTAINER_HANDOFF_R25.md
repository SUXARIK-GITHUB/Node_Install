> **Обновление r26:** Этот документ описывает базовую архитектуру r25. Для новых функций FinalMask/приёмки Xray/сравнения измерений см. `docs/RELEASE_2.5.18_R26_FINALMASK_TRANSPORT_QA.md`, `integrations/finalmask_profile.py`, `scripts/measurement_review.py`, `tests/test_r26_*.py`. Ни один экспорт FinalMask не изменяет Remnawave Panel или серверные inbound; схема `INCOMPLETE_STAGING_ONLY` сохранена.

# Node_Install — инженерный handoff для следующего чата и разработчика

**Важное:** эта инструкция — подробное описание доступной в архиве версии r25, а не повод считать весь проект production-ready. Перед любой правкой *читать исходники*, проверять фактический build ID и воспроизводить имеющиеся тесты. Нельзя доверять формулировке «сделано» из старой переписки без проверки кода.

## 0. Входные данные и неизменяемые требования владельца

- Проект `SUXARIK-GITHUB/Node_Install`, основной код в файле `install.sh` (~11 тысяч строк). ZIP r24 получен отдельно и является исходником текущей сборки. GitHub `main` исторически содержит r19, поэтому **не заменять** локальный r25 архив случайным скачиванием main.
- Назначение: автоматизация установки отдельной RemnaNode на чистую Ubuntu/Debian VPS, Selfsteal Nginx/HTTPS, REALITY и XHTTP, подготовка каскада Entry→Exit, сеть, безопасность, обслуживание и диагностика; **не** сама Remnawave Panel и не клиентский биллинг.
- Основная обычная нода: VLESS + RAW/REALITY/Vision (альтернативный XHTTP/REALITY); TCP/443 принимает Xray, TCP/80 HTTP/ACME, TCP/2222 Node API только с разрешённых IPv4 панели. Selfsteal работает через Unix-сокеты без второго публичного 443.
- Действующий SSL/Nginx и SSH/UFW критичны для доступа. Нельзя менять настройки удалённой VPS, Grub, sysctl, Docker, UFW или SSH без сохранного снимка и тестовой среды. **SSH ключи на нодах НЕ используются; владелец прямо запретил перевод на ключи.** При этом root с паролем — высокий риск: предупреждать, но не менять схему доступа без согласия.
- **Не выполнять полную проверку Panel и клиентов на VPS** — исключено по договорённости с владельцем. Без неё статус production не подтверждён. Не проводить сетевые DPI-тесты против чужих целей без явного разрешения.
- Не удалять существующие файлы, не менять дизайн сайтов и не переносить чужие assets вслепую. Не добавлять стороннее ядро, Caddy, дополнительную панель, DB, прямой выход Entry или новые фоновые службы по умолчанию.
- Нужен **полный готовый ZIP** со всеми файлами и рабочим release manifest/checksums, проверенный после чистой распаковки; нельзя отдавать набор патчей вместо проекта.

## 1. Дерево и ответственность компонентов

| Файл/каталог | Назначение и границы |
|---|---|
| `install.sh` | Главная точка входа, preflight, выбор Ordinary/Cascade, SSH/UFW/sysctl/Docker/Nginx/Certbot, генерация installed payload, postboot-финализация; также определения Python внутри heredoc. Выполнять `bash -n` и тесты, проверять реальные строки скрипта после модификации. |
| `integrations/finalize_install.py` | Финальная транзакция установки и checkpoint; не подменять маркер `INSTALL_COMPLETE` устными утверждениями. |
| `integrations/cascade_deployment.py`, `cascade_profiles.py`, `cascade_live_gate.py`, `cascade_panel_*`, `cascade_recovery.py` | Каскад: парная идентичность, отдельные role bundles, BLOCK/TO_EXIT_VLESS fail-closed, офлайн-аудит данных панели и ограниченный backup роли. Без настоящей Panel не доказывает связность. |
| `integrations/xhttp_profile.py`, `transport_profile_audit.py` | Шаблоны и анализ стандартных RAW/XHTTP REALITY профилей; изменение live-клиентов должно быть отдельно согласовано. |
| `integrations/optional_transports.py` | Только генераторы приватных опциональных bundles XHTTP-TLS/H2, Hysteria2 и AWG2; **не** инсталлятор служб. |
| `integrations/transport_readiness.py` (r25) | Проверка приватных bundles, совпадения auth/key/route/port/role, без публикации секретов; вывод REVIEW, не ставит и не запускает сервисы. |
| `integrations/selfsteal_chain.py`, `selfsteal_health.py`, `selfsteal_runtime_probe.py` | Аудит Nginx/Unix TLS/SNI/PROXY и HTTPS; хранить socket permissions root:www-data, а не 0666. |
| `integrations/network_health.py`, `node_diagnostics.py`, `connection_quality.py`, `path_mtu_diagnostics.py`, `quality_probe.py`, `throughput_probe.py` | Наблюдение TCP/UDP, qdisc, потерь, MTU и отдельные ограниченные пробы; хостовые счётчики не равны качеству трафика пользователя. |
| `integrations/network_tuning.py` | Только измеренный backlog, применяемый по явному подтверждению на staging; shared installer lock, receipt и возобновляемый rollback. Остальные sysctl не трогать. |
| `integrations/rkn_guard.py` | Закрытый набор проверяемых CIDR/UFW/ipset правил; защищать исключения Panel/Entry и SSH. |
| `scripts/site_catalog.py`, `signature_sites.py`, `cover_rich.py`, `cover_variants.py` | Каталог 120 тем, генераторы и 12 исторических handmade cover; 96 тем общие генераторы, 12 дополнительные отдельные композиции. |
| `site-catalog/` | 108 дополнительных тем × 9 статических файлов. `cover-variants/` — старые 12 × 4 файла. |
| `scripts/site_manager.py`, `staging_web_deploy.py`, `site_audit.py` | Просмотр, установка и смена сайтов, HTTPS и Nginx пробы, транзакционный rollback; r25 чинит прерванный rollback-переключение. |
| `scripts/network_compare.py` | Чисто read-only разница между двумя снимками сетевых счётчиков (не оценка скорости VPN). |
| `tests/` | Автоматические unit/контракт/отказные офлайн-тесты. `tests/run.sh` запускает все `test_*.py` в отдельном интерпретаторе. |
| `docs/`, `preview/site-gallery/` | Операционная документация, релизы/инциденты и визуальная галерея (исторические отчёты не считать свежими). |
| `scripts/build_staging_archive.py`, `scripts/verify_release.py`, `BUILD_MANIFEST.json`, `SHA256SUMS` | Воспроизводимая сборка, список всех файлов, контроль SHA-256 и статуса staged. Новые пути обязаны попасть в `UNTRACKED_ALLOWED` до сборки. |

## 2. Последовательность обычной установки

1. Чистая выделенная VPS Ubuntu 22.04/24.04/26.04 или Debian 12/13, systemd+GRUB, минимум 900 MiB RAM, 6 GiB свободного места, публичный IPv4 и DNS A; нужен проверенный snapshot и доступ к консоли хостера.
2. Предпроверки чужих служб, сетевых правил, APT, SSH, ресурсов и IP. Выбор Ordinary/Cascade; секрет RemnaNode, домен и IPv4 панели. Нельзя публиковать секреты или `.env`.
3. Сохранение исходных конфигов; создание `/etc/vkarmani-node`, `/var/lib/vkarmani-node` и marker/transaction state, подготовка ОС/Docker/Certbot/SSH/UFW.
4. Xray через RemnaNode на TCP/443; Nginx обслуживает HTTPS Selfsteal за socket fallback; внешний REALITY SNI может использовать Nginx stream; Node API на TCP/2222 привязан к Panel ACL.
5. Проверки конфигурации, site HTTP/TLS, Node API, финализация; создание `INSTALL_COMPLETE`. `--site-theme` публикуется **после** успешной основной финализации.
6. r25: если необязательный сайт отказал, статус `INSTALL_RESULT=PARTIAL`, код 20 и нет авто-reboot. **Не** маркировать ошибкой основную уже завершённую установку.
7. После reboot отдельно проверять реальные listeners, Node API и консольный SSH, UFW, системные службы, сертификаты, socket permission и маршруты. Без разрешённого живого стенда не утверждать прохождение.

## 3. Состояние на хосте, секреты и откаты

- `/etc/vkarmani-node/` — конфиги и секреты, включая `remnanode.env` с SECRET_KEY: не включать в публичные архивы.
- `/var/lib/vkarmani-node/` — `INSTALL_COMPLETE`, `owned-installation`, финализационный checkpoint, транзакции, журналы/backup. Не удалять маркеры наугад.
- `/opt/vkarmani-node/compose.yaml` — RemnaNode Docker Compose, постоянный образ после pulling фиксируется digest; host network/NET_ADMIN увеличивают область риска.
- `/run/vkarmani-selfsteal/` — сокеты, directory 0750 root:www-data, аккуратный tmpfiles на reboot.
- `/etc/nginx/`, `/var/www/vkarmani-node/`, `/etc/letsencrypt/` — сайт/Nginx/ACME; `nginx -t` до reload; проверка TLS после.
- `/etc/ufw/`, `/etc/ssh/sshd_config`, `/etc/sysctl.d/`, GRUB и systemd — hostwide изменения, без snapshot live не трогать.
- `/run/lock/vkarmani-node-installer.lock` — общий mutex для ключевых операций; `network_tuning` r25 использует его и свой receipt. Не вводить новую конкурирующую блокировку в обход этой.
- `integrations/cascade_recovery.py` создаёт **ограниченный** role backup без `remnanode.env`; не является полной резервной копией Secret Key или всей VPS.
- Для rollback сетевого backlog использовать `sudo bash install.sh --network-tuning rollback --confirm-staging` на подходящей завершённой staging ноде, не удалять receipt руками.
- Для rollback темы: `sudo bash install.sh --site-manager rollback --confirm-staging`. Нужны целый журнал и проверяемый backup. При чужом изменении остановиться и разбирать SHA-256/снимок.
- Docker image rollback и отдельный cover rollback не заменяют полноценный snapshot.

## 4. Команды без изменения VPS (исполнять в извлечённом полном ZIP)

```bash
bash install.sh --version
bash install.sh --help
bash install.sh --site-manager list
bash install.sh --site-manager preview --theme 111-atlas-docs --output /tmp/site-preview
bash install.sh --diagnose-network
bash install.sh --diagnose-selfsteal
bash install.sh --transport-audit examples/inbound-raw-full.example.json
bash install.sh --transport-readiness xhttp-tls --bundle /root/xhttp-private --expected-domain node.example.com
bash install.sh --transport-readiness hysteria2 --bundle /root/hysteria-private --expected-domain node.example.com --strict
python3 scripts/site_audit.py --rich
python3 scripts/verify_release.py --root .
sha256sum --check SHA256SUMS
bash -n install.sh
bash tests/run.sh
```

Замечания: `--diagnose-network` может зависеть от наличия `ip/tc` и выдаёт read-only INFO/REVIEW; `--transport-readiness` требует **фактически созданного приватного bundle**, строгий режим вернёт `2` при REVIEW, что ожидаемо. `--site-manager status` на ноде требует `sudo`; многие диагностики тоже требуют повышенных прав к закрытым файлам. Не запускайте полную установку в тестовом окружении анализатора ради проверки синтаксиса.

## 5. Скрытность, Hysteria2, AWG2 и FinalMask — честное разграничение

- Действующая основа маскировки: REALITY + Vision + локальный selfsteal; XHTTP + REALITY как альтернативный подготовленный профиль. 120 локальных статических сайтов обслуживаются Nginx; сайт — не доказательство отсутствия узнаваемости самого VPN потока для DPI.
- XHTTP/TLS/H2 staging: существует путь генерации и `nginx-location.conf`/grpc_pass, но **нет подтверждённого живого Xray backend и клиентского подключения**.
- Hysteria2 и AWG2: **только приватные reference генераторы и новые валидаторы**, без установки runtime, сертификатных hooks, UDP rules, NAT, системной службы, обратимого удаления и реальной совместимости. Не помещать новые service units в install.sh без сквозной тестовой среды.
- `FinalMask` описан современным Xray, но включение без однозначной версии Core и соответствующего клиента может сломать транспорт. Не включать по умолчанию или на существующей ноде.
- BBR/CUBIC, qdisc, netdev, MTU/MSS и conntrack нельзя «оптимизировать» большими универсальными значениями. Сначала две сопоставимые диагностические выборки, затем ограниченный эксперимент на staging с откатом.
- Требования пользователя по сети/маскировке и исходные 27 внешних репозиториев зафиксированы в ранее приложенной полной истории беседы и отчёте аудита; не считайте сторонние тексты проверенным кодом. Все переносы проверять на лицензии/атрибуции и совместимость.

## 6. Проверки при изменении кода

1. Чисто распаковать выданный ZIP в отдельную директорию, проверить counts/sha256/манифест; не перепутать с GitHub `main`.
2. Исследовать зависимые модули и все heredoc/embedded Python в `install.sh` (исполняется и Python, а не только Bash).
3. Для опасного изменения написать регрессию, сначала воспроизводящую старый дефект, затем фиксирующую результат. Для восстановления специально инжектировать отказ после физического изменения, перед записью receipt.
4. Проверить `bash -n install.sh`, Python compile, JSON/HTML/CSS, `python3 scripts/site_audit.py --rich`, `bash tests/run.sh`. При значимых Nginx изменениях нужна отдельная проверка на доступном безопасном экземпляре Nginx.
5. Не объявлять offline тесты замером DPI, WAN скорости, доступности клиентов, реальной VPS и panel. Отдельно фиксировать `NOT_VERIFIED` и `REVIEW`.
6. Новые файлы вписать в `UNTRACKED_ALLOWED` `scripts/build_staging_archive.py`, собрать ZIP, затем независимо проверить **чистую распаковку**, сопоставить файлы исходного ZIP и запустить все тесты из неё. Не удалять `.env.example`, docs/history, картинки, тесты и миграции.
7. Хранить секреты только в приватном каталоге/на VPS, умаск 077. Ни приватные X25519/AWG ключи, ни SECRET_KEY, UUID и логи запросов пользователей в release ZIP не включать.

## 7. Не сделано / очередь следующих работ (НЕ выдавать за готовое)

| Сфера | Остаток | Условие безопасного продолжения |
|---|---|---|
| XHTTP/TLS/H2 runtime | Отдельное создание Xray inbound, версионная проверка, согласованность с панелью, Nginx reload, полный rollback | Совместимый runtime на выделенном стенде, артефакты испытаний и профиль клиента |
| Hysteria2 | Реальный процесс, версия/обновления, TLS, UDP/UFW, maintenance, отзыв credential/удаление | Отдельный staging-host, проверенный архив бинарника и наличие сертификата |
| AmneziaWG2 | Реальный AWG2 daemon/module, TUN, routing/NAT, collision checks, service lifecycle | Изолированный стенд и проверенная совместимость kernel/userspace; никаких изменений живой ноды без snapshot |
| FinalMask | Версионно согласованный TCP/UDP профиль и обратимость | Поддерживаемые Core+Client, экспериментальная VPS, метрики, никакого тихого включения |
| Измерения сети | BBR vs CUBIC и transport comparison/MTU blackholes | Внешний разрешённый тестовый endpoint и одинаковая нагрузка, журнал до/после |
| Сайты | Визуальная разнообразность 96 общих генераторных тем; перенос чужих наборов | Отбор реального контента, лицензионные права, браузерная сверка, сохранение текущего каталога |
| Реальная эксплуатация | Panel/Node/Client, outage/long session, DPI | **Исключено пользователем из текущего объёма**, нельзя автоматически утверждать prod readiness |

**Не изменять пользовательские правила:** два захода, текущий r24 является первой законченной частью, SSH без ключей, не проверять live Panel/Client VPS, архив должен сохранять все исходники. Документы r25 предоставляют точку восстановления контекста при переносе диалога.
