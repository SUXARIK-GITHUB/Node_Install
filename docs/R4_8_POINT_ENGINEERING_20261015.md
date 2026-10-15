# Node_Install 2.5.10 / r4: инженерное исполнение восьми задач

**15.10.2026 · `INCOMPLETE_STAGING_ONLY` · не опубликовано в GitHub, не допущено в production**

**Сфера работ:** только копия исходников. Существующие VPS, панель, БД, Node API, Cloudflare, пользовательские inbounds, подписки и репозиторий не изменялись. Оригинальная ветка первой ordinary-установки по-прежнему неизменна; в меню выбор `2` безопасно останавливает установку. Нельзя ставить r4 на существующий рабочий каскад.

Обозначения: `CODE` — рабочая проверяемая логика в исходниках; `OFFLINE TEST` — автономный тест; `BLOCKED` — нельзя честно считать пункт закрытым без двух VPS/реального клиента; `MANUAL` — намеренно не выполняемая программой операция в Remnawave Panel. Не путать offline PASS и успешную доступность извне.

## Восьмипунктная матрица

| # | Задача | Конкретный результат в r4 | Статус |
|---|---|---|---|
| 1 | Документы, CI и release integrity | Сохранены существующие файлы; актуализированы README, SECURITY, CHANGELOG, TEST_REPORT, RELEASE_VALIDATION, матрица требований; расширены checksum и архивный валидатор; добавлены регрессии. GitHub CI для локального ZIP не запускался | CODE/OFFLINE; CI публикации BLOCKED |
| 2 | Живая staging-приёмка ordinary | Создан машинно-проверяемый чеклист evidence по SHA архива, сетевые тесты и backup/rollback gate; **VPS/клиент/панель отсутствуют** | BLOCKED |
| 3 | RKN, права панели, смена IP | Read-only сравнение `config.json` и UFW ACL с fail-closed; RKN теперь фиксирует раздельно время последней успешной проверки и последнего изменения набора CIDR; автоматические опасные изменения UFW **не выполняются** | CODE/OFFLINE; kernel/network BLOCKED |
| 4 | Вход/выход каскада | Генератор двух полноценных staging-профилей VLESS/REALITY + строгая структура, AsIs/no DNS на entry, первичный BLACKHOLE, разрешённый bridge только на exit; проверка 0600, без overwrite и вывода секретов | CODE/OFFLINE; полноценный role installer BLOCKED |
| 5 | Service-user, Node/Host/Profile/Squad | Генератор подготавливает private configs и `panel-plan.json`; инструкция без admin API токена, для ручного назначения по официальному UI. Автоматическая безопасная работа с реальной Panel **не реализована** | MANUAL/BLOCKED |
| 6 | Сквозная двухсерверная проверка | Матрица негативных/позитивных кейсов и evidence gate, в том числе DNS/маршрут, no DIRECT при потере exit, cold boot в разном порядке, peer rotation | BLOCKED |
| 7 | Backup/restore, безопасность обновлений, расписания, мониторинг | Для ролей cascade ночной перезапуск теперь fail-closed **SKIPPED** до подтверждённой координации; отдельный мониторинг/evidence gate. Старые транзакционные инструменты и ordinary не менялись. Full VPS restore и live canary невозможны без тестовой VM | CODE/OFFLINE; live BLOCKED |
| 8 | Шесть cover-сайтов, nginx HTTP/TCP proxy | Шесть самостоятельных статических сайтов `cover-variants/{01..06}`, отдельный CLI подготовки; генератор конфигов Nginx для **loopback-only** HTTP и TCP stream; никогда не занимает 80/443/Node API | CODE/OFFLINE; nginx -t в нужной VM и deploy BLOCKED |

**Итог:** в исходниках закрыта безопасная разработка *подготовительных частей* всех восьми направлений; сквозная готовность и реальные установки **не закрыты**. Держать статус release `INCOMPLETE_STAGING_ONLY` до реального staging и QA. Не подменять `Not tested` статусом `PASS` только потому, что написан тест/шаблон.

## A. Генерация двух staging профилей каскада (без установки)

Программа: `integrations/cascade_profiles.py` (Python stdlib; без скачивания чужого кода). Работает на доверенной локальной машине оператора с приватным JSON; отказывает при symlink, слишком широких правах, дублированных тегах, неверных IPv4/REALITY/UUID и существующей директории результата. Все созданные файлы имеют `0600`, папка `0700`.

Структура **приватного** входа (значения ниже сознательно нерабочие):

```json
{
  "schema": 1,
  "entry": {
    "domain": "entry.example.org", "ipv4": "REPLACE_WITH_REAL_PUBLIC_IPV4",
    "private_key": "REPLACE_WITH_PRIVATE_X25519", "public_key": "REPLACE_WITH_MATCHING_PUBLIC_X25519",
    "short_id": "a1b2c3d4", "inbound_tag": "VK_ENTRY_UNIQUE_TAG"
  },
  "exit": {
    "domain": "exit.example.org", "ipv4": "REPLACE_WITH_OTHER_PUBLIC_IPV4",
    "private_key": "REPLACE_WITH_PRIVATE_X25519", "public_key": "REPLACE_WITH_MATCHING_PUBLIC_X25519",
    "short_id": "e5f6a7b8", "inbound_tag": "VK_EXIT_UNIQUE_TAG"
  },
  "bridge": {"service_user_uuid": "REPLACE_WITH_REAL_SERVICE_USER_UUID"}
}
```

**Приватный ключ и public key обязательно должны быть парой, сгенерированной `xray x25519` на соответствующей тестовой ноде.** Offline tool проверяет кодировку, но **не может криптографически доказать соответствие пары без Xray**; его отсутствие запрещает статус ACCEPTED. UUID service-user должен быть выдан действующей панелью, **не** admin API-token.

```bash
# Только на локальной доверенной dev машине, не на панели/production!
umask 077
chmod 600 ./cascade-private-input.json
python3 integrations/cascade_profiles.py \
  --config ./cascade-private-input.json \
  --output ./cascade-candidate-private
# Итог: entry-profile.json, exit-profile.json, panel-plan.json, SHA256SUMS.
# Не отправляйте эти файлы в Git, мессенджеры или тикеты.
(cd cascade-candidate-private && sha256sum -c SHA256SUMS)
```

Никакой автоматической установки RemnaNode, UFW, Core, сертификатов, Node/Host/Profile/Squad нет. Generated profile — только кандидат для ручного импорта на **чистом staging**. `entry-profile.json` имеет `routing.domainStrategy=AsIs`, отсутствует `dns` и любой `freedom` outbound, самый первый outbound `blackhole`. `exit-profile.json` имеет DIRECT с `finalRules` запрета приватных/reserved IPv4 и всего IPv6; передача реальных клиентских данных в DIRECT допускается только на выходе.

**Примечание DNS:** `AsIs` предотвращает встроенное DNS-разрешение клиентских доменов при сопоставлении IP-rule на входе, но не доказывает отсутствия системных DNS-запросов, другого влияния панели или утечек через другие сервисы. Внешний `tcpdump` на входе и выходе обязателен для закрытия пункта. Не добавлять global `routing` из старого ordinary профиля, не сливать Panel snippets без повторного `rw-core -test`.

## B. Конфигурация панели — строго изолированные объекты

1. На отдельных staging VPS установить **обычные** базовые RemnaNode только на **чистых серверах**, либо дождаться утверждённой ролевой установки. В production не использовать ordinary direct как замаскированный entry каскада.
2. В Remnawave Panel создать две **новые** Node с независимыми `SECRET_KEY` для своих RemnaNode; на каждой — свой IPv4, Node Port, сертификат и Selfsteal. Ни этот инструмент, ни `SECRET_KEY` не вызывают Panel admin API.
3. Создать два **отдельных** Config Profiles и импортировать соответствующие файлы, уникальные `inboundTag` не должны совпадать с уже существующими в БД панели. Проверить вычисленную конфигурацию после сохранения (Panel может менять clients и snippets).
4. Создать Host только для клиентской entry-ноды; использовать её настоящий `domain`, REALITY public key и shortId. Не выдавать клиентам Host выхода.
5. Создать отдельную Internal Squad для разрешённого клиентского entry-inbound и, отдельно, bridge Internal Squad только для exit-inbound.
6. Создать service-user bridge с отдельной UUID, назначить **исключительно** bridge Squad. UUID должен совпадать с единственным `TO_EXIT_VLESS.settings.vnext[0].users[0].id` во входном профиле. Не добавлять обычных пользователей в bridge Squad.
7. Прежде импорта сверить домены, ключи и группы; выполнить `rw-core run -test` именно активного computed profile на **каждой** staging Node, убедиться что Panel API остаётся доступным; лишь после этого включать профиль.
8. При отключении exit или неверном service UUID клиент входа должен потерять выход **без прямого fallback**. Это нужно измерить внешним IP-тестом, системными логами и egress capture; нельзя выводить этот факт только из JSON.

Официальные источники: https://docs.rw/learn-en/server-routing/ (демонстрационный пример, не production), https://docs.rw/learn-en/config-profiles/ и https://docs.rw/learn-en/squads/; Xray Routing: https://xtls.github.io/en/config/routing.html и Freedom finalRules: https://xtls.github.io/en/config/outbounds/freedom.html.

## C. RKN / UFW / смена IP панели (сначала read-only)

Выпуск r4 **не** меняет автоматически source IP в UFW — это может отключить существующий Panel→Node доступ. В `integrations/panel_acl_audit.py` добавлен CLI read-only: сравнение точного TCP Node Port и набора разрешённых public IPv4 с `config.json`. Wildcard allow, IPv6, UDP, лишние/отсутствующие IP, неактивный UFW → FAIL. Это не доказывает доступность через firewall провайдера.

```bash
# На staging узле, после snapshot. Эта операция ТОЛЬКО читает UFW и config.
sudo python3 integrations/panel_acl_audit.py --config /etc/vkarmani-node/config.json
# Offline при разборе проверенных выписок:
python3 integrations/panel_acl_audit.py --config ./sanitized-config.json \
  --ufw-status-file ./ufw-status.txt
```

**Если IP панели изменился:** согласовать новый backend IPv4 и изменение firewall провайдера; сначала сохранить текущий allow и временно разрешить новый **точный IPv4** в UFW, проверить SSH и новый Panel→Node TCP и авторизацию; затем корректировать `panel_ipv4` в проектной записи с root-only permissions под ручным контролем и выполняющийся `--rkn-sync-panel`; **только после двухсторонней проверки** удалить прежнее правило. Нельзя слепо выполнять команды с выдуманными адресами, открывать `2222/tcp` всему миру или запускать это автоматически на живом сервере. Проверить rollback и автоматические timers.

RKN `last-check.json` теперь имеет `checked_at_utc` и `content_changed_at_utc` (с сохранением предыдущего времени при неизменных данных). `RKN_LAST_CONTENT_CHANGE` — дата последнего известного изменения **локально нормализованного CIDR-набора**; при переходе со старого checkpoint без истории честно выдаётся `UNKNOWN`, **не** аутентифицированная дата upstream commit; сравнение содержимого не гарантирует корректность данных и не заменяет независимый review источника. Если обновление оборвалось, checkpoint и kernel sets откатываются по существующему сценарию.

## D. Ночное обслуживание / обновления / backup

- Обычная нода: прежний `nightly_maintenance.py` перезапускает локальный контейнер с marker-at-most-once; не утверждает, что пользовательский VPN работает после restart.
- **Каскад:** если в `role.json` указано `cascade-entry` или `cascade-exit`, фоновый таймер останавливается **без рестарта** с `MAINTENANCE=SKIPPED CASCADE_REQUIRES_PEER_COORDINATION`. В r4 **нет** ложного stagger scheduler, который без связи между VPS может одновременно порвать цепь.
- Обновления старых установок: **автомиграции нет**. Снимать снапшот провайдера и offline `vkarmani-node-maintain --backup`, проверять digest backup, отдельно планировать образ и откат. Не подменять snapshot backup конфигов.
- Двухузловая координация пока ручная: сначала проверить второй узел, restart одного, измерить внешний canary; затем другой. Регулярную автоматику включать **только** после E2E-метрик, независимых Node API и смены worker таймеров без race.

## E. Подтверждение staging без подмены результатов

В `scripts/staging_acceptance.py` хранятся два списка обязательных пунктов, ordinary (14) и cascade (28). Программа может выдать JSON-шаблон с `BLOCKED` для всех проверок и вычислить полноту сдачи. Каждый `PASS` требует UTC времени, пути/ссылки на артефакт и идентификатора оператора. Программа проверяет только **форму метаданных**, а не подлинность внешнего TCP/снимка.

```bash
python3 scripts/staging_acceptance.py \
  --create-template ordinary --zip-sha256 PUT_REAL_ARCHIVE_SHA256 \
  > /tmp/ordinary-acceptance.json
python3 scripts/staging_acceptance.py \
  --create-template cascade --zip-sha256 PUT_REAL_ARCHIVE_SHA256 \
  > /tmp/cascade-acceptance.json
python3 scripts/staging_acceptance.py --evaluate /tmp/cascade-acceptance.json
# Ожидается EVIDENCE_REVIEW=INCOMPLETE, exit 1, пока нет реальных проверок.
```

Условие релиза — evidence для **точного** SHA построенного ZIP, отдельные positive/negative client tests, восстановление snapshot и rollback после неисправностей, external allow/deny Node Port. Две VPS на разных адресах, reboot в двух порядках, неверный peer service UUID, DNS leakage capture, TCP/UDP, HTTP/TLS1.2+1.3, certbot renewal, 24-часовая нагрузка. При одном `FAIL` или `BLOCKED` статус остаётся staging.

## F. Шесть новых cover-сайтов и прокси без конфликта портов

Папки `cover-variants/01-atelier`, `02-archive`, `03-observatory`, `04-fieldnotes`, `05-readingroom`, `06-foundry` содержат по **две готовые статические составляющие: HTML-страницу и CSS-файл**. Без JS, внешних API, шрифтов, tracking и загрузки чужих ресурсов; responsive, с CSP, проверены offline. **Существующий production-сайт не изменён**.

```bash
python3 scripts/cover_variants.py --list
python3 scripts/cover_variants.py --name 01-atelier --output ./local-preview-new
# Просмотр в браузере: открыть local-preview-new/index.html
```

Генератор HTTP/TCP Nginx: `scripts/nginx_proxy_plan.py`, порт прослушивания и upstream **только 127.0.0.1**; `22`, `80`, `443`, `2222` зарезервированы; повторная генерация на тот же файл отклоняется. Это *действительный* `proxy_pass` и для http, и для `stream`, но скрипт **не включает и не активирует** конфиг. Для HTTP файл включается внутри `http {}`; для TCP — `stream {}` **только на верхнем уровне** Nginx, при наличии stream module. На целевой staging VM перед reload проверить фактические слушатели, `nginx -V`/stream, `nginx -t` и внешний port/health-check. Не добавлять второй публичный 443 и не перехватывать REALITY. Для публичного reverse proxy требуется отдельно утверждённая топология / отдельный адрес или порт, куда кто подключается и как маршрутизируется TLS.

```bash
python3 scripts/nginx_proxy_plan.py --kind http --listen 9000 --backend 9100 --output ./http-loopback.conf
python3 scripts/nginx_proxy_plan.py --kind tcp  --listen 9200 --backend 9300 --output ./stream-loopback.conf
# НЕ копировать файлы напрямую в боевой /etc/nginx без staging проверки.
```

## G. Проверки и откат

1. До каждого live шага: snapshot VPS, проверка restore по отдельному экземпляру, консоль хостера, одновременный второй SSH-доступ; сохранённые конфиги Nginx/UFW/SSH и каталог конфигураций Node/Panel, проверка free disk и текущего core digest.
2. Изменения **одной** роли на staging → `nginx -t`, `docker compose config --quiet`, Xray `run -test`, UFW policy, external Panel API с allow и deny IP → реальный клиент + внешний IPv4 → DNS/UDP/negative tests → reboot → повтор тех же тестов.
3. При ошибке без изменения production: удалить staging VPS/наработки или восстановить snapshot. **Не** применять `docker compose down -v`, `prune`, удаление UFW, GRUB и таблиц БД. Для существующего ordinary использовать только известные ограниченные команды обслуживания `--rollback-image` / `--rollback-cover`, предварительно изучив их маркеры и лог.
4. GitHub/CI: до публикации сверить архив по отдельному SHA, провести pull request, GitHub Actions именно для HEAD после загрузки; статус опубликованной `main 2.5.9` **не** распространяется на этот ZIP.

## H. Не закрытые до реальной инфраструктуры условия

- Два независимых сервера, SSH/домен/сертификат каждого, `rw-core` реальные версии, реальная панель с группами/host/user, клиент и capture DNS/egr; выбор `2` в install.sh намеренно остаётся fail-closed.
- Независимые Node API/подписки, никакого DIRECT fallback с entry при выходе из строя exit, устойчивость после reboot, секреты/ротация peer, single-node и pair rollback, no leaks.
- Реальные порты Docker/Nginx/UFW/Provider FW, RKN на netfilter-ядре, имитация повреждённого kernel ipset, health canary, сертификаты renew.
- Проверка на Ubuntu 22.04/24.04/26.04/Debian 12/13 и amd64/arm64, 24 часа нагрузки, выпуск после CI на GitHub.

**Ничего из перечисленного не заявлено как PASS на основании одного исходного файла, regex, ZIP CRC или unit-тестов.**
