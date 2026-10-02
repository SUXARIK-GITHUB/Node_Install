# Node_Install 2.1.3 — generator / supplied-profile validation

Дата выпуска: 2026-10-02. База: полный `Node_Install_2.1.2_docs_ci_fixed.zip` SHA256 `2a64f7036466aa791ac06038048984f0d9280be9c89a91f1e420a31916bfcadb`.

## Область

Первый локально проверенный выпуск по итогам диагностики. Исправлены minClientVer и пропуск profile-check; усилены ограниченные проверки supplied JSON. Без XHTTP/дополнительного транспорта, новых зависимостей, контейнеров, прокси, frontend/design-правок, политик firewall/SSH/DNS/routing, изменения образа RemnaNode или выбора версии Xray.

В исходной 2.1.2 generator/validator/guide/export использовали 1.0.0, хотя оператор выбрал 0.0.0. Acceptance проверяла profile только для regex `^2\.1\.(0|1)$`, пропуская 2.1.2. В новом коде значение вынесено в одну константу; проверка выполняется для явно рассмотренных версий, а новая неизвестная версия не считается проверенной автоматически.

## Что изменилось в generated profile

Только `realitySettings.minClientVer: "1.0.0" -> "0.0.0"`. Сохраняются:

- один публичный RAW/REALITY inbound, индивидуальный tag/domain/key/ShortID;
- собственный socket `/dev/shm/nginx.sock`, `xver=1`, host Nginx;
- отсутствие принудительного Vision в generated template (custom live Vision не меняется);
- DNS `1.1.1.1, 8.8.8.8`, UseIPv4;
- DIRECT/BLOCK, IPOnDemand, существующий набор запретов private/special/own/panel IPv4 и `::/0`.

Сохранённый шаблон не равен custom live JSON с дополнительными DNS options и internet/block/AsIs. Не импортировать его поверх рабочего профиля без отдельной проверки. В частности, block IP панели затрагивает и публичные пользовательские сервисы на этом IP. Усиление/изменение конечной egress policy отложено, а не объявлено выполненным.

## Что теперь проверяет profile-check

Проверка supplied-файла остаётся без mutation/сетевых обращений. Проверяются IPv4 listener, DNS queryStrategy и типы options, Freedom UseIPv4, непустые routing rules, однозначные теги, существование outbound/inbound ссылок, непротиворечивые aliases raw/tcp и target/dest, отсутствие требования входящего PROXY protocol на прямом listener. `xver=1` — отдельный исходящий контракт до Nginx, не выключается.

Допускается один сервисный API inbound RemnaNode: `REMNAWAVE_API_INBOUND`, tunnel/dokodemo-door, abstract `@xtls-api-*` либо IPv4-loopback с портом. Требуются `api.tag`, непустой список services и первый routing-rule исключительно для этого inbound. API tag не должен совпадать с обычным outbound. Публичный service API и неизвестные дополнительные inbounds отвергаются; это узкий контракт, не универсальный validator всех Xray JSON.

Общий `settings.flow=xtls-rprx-vision` может сосуществовать с пустыми/отсутствующими client flows. Validator не дописывает их и не перечисляет UUID/email. Автоматическое извлечение source JSON через abstract Unix-socket из предыдущих диагностических команд НЕ встроено в installer: это отдельная функция, здесь проверяется только файл, предоставленный оператором.

Официальная первичная опора для семантики Vision и API:

- https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/infra/conf/vless.go — общий flow наследуется пустыми clients.
- https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/infra/conf/dns.go — DNS query strategies отделены от routing strategies.
- https://xtls.github.io/config/api.html — служебный API создаёт outbound по api.tag.

Код закреплённого релиза использован для семантики, не как доказательство эффективности против блокировок на новую дату.

## Границы PASS

- Это не проверка полного engine schema или всех неизвестных ключей.
- Не проверяются содержимое DNS hosts/геобаз, фактическое разрешение доменов, полный список запрещённых назначений, TCP/UDP enforcement, клиентская аутентификация и Host/Squad.
- Наличие PASS не означает, что прямой маршрут на закрытые адреса безопасен: необходим отдельный аудит политики выхода.
- Не читаются core memory или live-панель. `IMPORT_PROFILE_POLICY` не переименован в LIVE PASS.
- Unknown install-version даёт FAIL; known legacy/missing marker — явный NOT_VERIFIED для сохранения старого diagnostic/repair пути, не подтверждение его profile policy.
- Размер supplied JSON ограничен 2 MiB; финальный symlink, FIFO, duplicate keys, NaN/Infinity отвергаются. Рекурсивно недоверенное дерево root этим не изолируется.

## Проверки

383 прежних + 37 новых = 420 tests. Полные прогоны от root и UID 1000 в Debian 13/x86_64 прошли без skips. Есть реальные изолированные проверки Nginx TLS/HTTP2, APT solver на synthetic metadata и Git; Docker/services/firewall в соответствующих тестах имитируются. Новый module дополнительно исполняет сам Bash version-gate с fake helper, а не только ищет regex в строке.

Старые результаты 2.1.2 сохранены в `docs/history`. Текущий отчёт — `TEST_REPORT.md`, machine-readable — `RELEASE_VALIDATION.json`.

## Использование / обновление / rollback

### Проверить распакованный проект локально

Из каталога Node_Install:

```bash
sha256sum --check SHA256SUMS
bash -n install.sh
bash install.sh --version
```

Ожидается 2.1.3. Эти команды не запускают установку. Тесты выполняются отдельно в disposable dev/CI-среде с нужными инструментами, не как часть диагностики production.

### Git

ZIP содержит все рабочие файлы проекта, но не `.git`. Для clone сохранить свою действующую историю. Не удалять clone вместе с `.git`, не копировать туда `.git` из старого input archive, не force-push/reset ради этой поставки. До публикации проверить diff и manifest. GitHub в этой работе не менялся; README download command проверяет hash и остановится на старом main.

### Новая VPS — только пилот

Snapshot + проверка доступа к restore/provider console + working SSH password. Для ручного окна приёмки стартовать проверенный installer с `--no-reboot`. После назначения профиля проверить новый SSH-вход, `sudo vkarmani-node-check --require-xray`, визитку и реальные клиенты, затем отдельно подготовить reboot и postboot. Без `--no-reboot` сохранено старое поведение: один auto-reboot через 30 секунд после успешных локальных проверок.

Full install 2.1.3 на VPS, actual bundled-Xray run-test, panel/client, Ubuntu matrix, arm64 и reboot в лабораторной работе НЕ выполнялись. Read-only диагностика старых нод не заменяет этот пилот.

### Работающие ноды 2.1.0/2.1.1/2.1.2

Обычный запуск нового файла вызывает СТАРЫЙ установленный checker; это не migration. Не копировать один helper/checker, не менять install-version или generated profile вручную. Действующий live-профиль не менять ради установки release. Подготовка безопасного selective helper upgrade остаётся отдельным этапом: verified per-file backup, review current local template, согласованная замена и checksum rollback. Такой новый mutating режим этим релизом не добавлен.

### Rollback

До deployment достаточно вернуть исходники предыдущей версии в dev, не меняя серверы. После первой установки на тестовую VPS полный rollback — проверенный snapshot до установки. При ручном назначении candidate-профиля отдельно вернуть сохранённые прежние profile/Node/Host/Squad assignments; это может разорвать активные подключения. Нет причин для DB restore, firewall reset или массового перезапуска нод из-за этих локальных исправлений.
