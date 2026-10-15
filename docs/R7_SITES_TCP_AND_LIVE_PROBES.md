# Node_Install 2.5.10 r7 — шесть сайтов, Nginx TCP и real-client probe

**Уточнение r7c:** DNS-проверка требует настоящей IN/A-записи с публичным IPv4 и проверяет DNS compression pointers; положительного счётчика ANCOUNT недостаточно. Transactional deployment и rollback сохраняют исходные mode bits (права доступа) существующих файлов. Реальные VPS не проверялись.

**Дата:** 15.10.2026 · **Статус:** `INCOMPLETE_STAGING_ONLY / NOT_PRODUCTION_VALIDATED / NOT_PUBLISHED`.  
Это дополнение к [r6 operating gates](R6_CASCADE_OPERATIONS_AND_GATES.md) и [r5 install](CASCADE_R5_ROLE_INSTALL_AND_PANEL.md). **Действующую production-ноду, каскад, сервер подписок и Panel не менять.** Код выполнен и автономно проверен; реальные VPS, клиенты, публичные TLS и проверка после отключения Exit **ещё не тестировались**.

## 1. Проверенное в коде

- `scripts/staging_web_deploy.py`: **opt-in** установка каждой из шести существующих `cover-variants/*`, rollback и status. Используется **только на новой завершённой staging VPS этой версии** и только из проверенного полного архива. Точечно добавляет разрешение статического `/style.css` в собственный Nginx Selfsteal `20-vkarmani-selfsteal.conf`, не меняя порты, TLS/cert, Xray, Panel, Docker, UFW/SSH/GRUB или действующие inbound. До изменений проверяет собственное состояние установки, домен, отсутствие незаконченных транзакций, исходный Selfsteal и `nginx -t`. Перед заменой сохраняет index, CSS (если существовал) и nginx fragment в отдельном root-only журнале. Вставка — атомарными файлами, CSS сначала, HTML последним. После `nginx -t` реально выполняет `systemctl reload nginx`, сверяет Selfsteal helper, **делает запрос `/style.css` через HTTPS на реальный публичный IPv4/REALITY** и сравнивает тело с установленным CSS. При ошибке пробует restore; после hard crash сохранён `pending` и доступен явный rollback с проверкой хешей. Любые чужие изменения останавливают откат, чтобы их не затереть.
- `scripts/staging_web_deploy.py tcp-deploy`: **opt-in** локальный TCP stream только `127.0.0.1:LISTEN → 127.0.0.1:BACKEND`, порты `>=1025` и не `2222/443`. Порт назначения должен уже иметь запущенный локальный сервис, порт listen — быть свободным. Новый top-level `stream {include ...;}` устанавливается в `/etc/nginx/nginx.conf` и включает единственный управляемый fragment `server {}` под `/etc/nginx/vkarmani-stream-r7/servers.conf`. **Не** создаёт новый слушатель 80/443, не меняет REALITY fallback и не трогает `http {}` или другие серверы. `nginx -t` + reload + локальная TCP connect-проверка + rollback по точному SHA. При отсутствии Nginx stream module `nginx -t` откажет и скрипт попробует откатить. **Автоматического APT/install нового stream-module нет**: изменение пакетов требует отдельного контролируемого решения и snapshot.
- `scripts/cascade_live_probe.py`: выполняет **реальные** TCP HTTPS и DNS-over-UDP проверки *через запущенный локальный SOCKS5 тестового VPN-клиента*. HTTPS endpoint отдаёт public IPv4 plain-text, он сравнивается с публичным IP **Exit**, проверяется цепочка TLS по системным корневым CA и hostname; UDP/DNS выполняется по RFC 1928 через `UDP ASSOCIATE` на заданный IPv4 резолвера:53, со сверкой ID DNS, вопроса, ожидаемого источника и наличия ответа. Дополнительный generic UDP-тест посылает одноразовый случайный пакет на отдельно предоставленный оператором test echo-service (отражение bytes/адреса/порта); это не DNS-тест и не автоматический публичный сервер. SOCKS target для HTTPS — домен, чтобы клиент не разрешал его локальным DNS перед прокси. Три явные фазы: baseline → operator-controlled exit outage → recovery. Скрипт **никогда не останавливает** контейнер/Exit и не отключает firewall. Каждый отдельный JSON receipt создаётся впервые с правами `0600`, имеет метку UTC и fingerprint тестовых параметров; неверная последовательность и ложное IP совпадение останавливают проверку. `PASS` здесь означает **наблюдаемый результат через конкретный SOCKS5**, **не** сертификат полной безопасности на Entry. В фазе outage требуется отдельный внешний референс остановки тестового Exit; сам скрипт этого не доказывает.

## 2. Безопасная установка сайта только на новой выделенной staging VPS

**Подготовка:** зафиксировать независимый SHA ZIP; проверить снимок VPS и восстановление на отдельной машине; доступ к консоли провайдера; выполнить обычный или каскадный install и назначение тестовых объектов в *отдельной* Panel; убедиться, что `vkarmani-selfsteal-check` даёт успешный результат **до** изменения, Nginx работает и публичный TLS уже отвечает. Сайт будет иметь HTTPS-домен самой ноды, а не какой-либо новый произвольно созданный поддомен.

```bash
cd /root/Node_Install    # реальная папка доверенного распакованного ZIP
python3 scripts/verify_release.py --root .
sha256sum --check SHA256SUMS
sudo /usr/sbin/nginx -t
sudo /usr/local/sbin/vkarmani-selfsteal-check
python3 scripts/cover_variants.py --list

# Домен не придумывать; должен строго совпасть с /etc/vkarmani-node/config.json.
NODE_DOMAIN="$(sudo python3 -c 'import json;print(json.load(open("/etc/vkarmani-node/config.json"))["domain"])')"
sudo python3 scripts/staging_web_deploy.py status
sudo python3 scripts/staging_web_deploy.py site-deploy \
  --theme 01-atelier --expected-domain "$NODE_DOMAIN" --confirm-staging
sudo python3 scripts/staging_web_deploy.py status
```

Тема выбирается из: `01-atelier`, `02-archive`, `03-observatory`, `04-fieldnotes`, `05-readingroom`, `06-foundry`. **За один раз активна одна тема;** для смены выполнить `site-rollback`, проверить доступ и потом `site-deploy` другой темы. Не запускать старое `install.sh --update-cover` параллельно или после r7-deploy без отката темы; старый updater не знает r7-журнал и его CSS. `--update-cover` сам по себе не является методом смены темы.

```bash
# Rollback последнего r7-site-deploy — только если содержимое не меняли другие процессы.
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
sudo /usr/sbin/nginx -t
sudo /usr/local/sbin/vkarmani-selfsteal-check
```

**Механика:** резервные bytes не удаляются, журнал `/var/lib/vkarmani-node/r7-web-deploy` доступен только root. На `pending` после сбоя нужно изучить статус/логи и выполнить явный rollback. Если `THIRD_PARTY_CHANGE_REFUSE_ROLLBACK` — не удалять журнал и не выполнять ручной `rm`; сохранить snapshot и разбирать конфликт. **Rollback возвращает только принадлежащие этой операции HTML/CSS и Nginx fragment**; сам VPS/Panel возвращается только из provider snapshot.

## 3. Nginx TCP stream: строгая топология

**Только localhost.** Для необходимости публичного TCP endpoint нужна отдельная архитектура с портами, SNI и firewall — не публиковать этот loopback listener и не подменять Xray `:443`.

Nginx на Ubuntu/Debian часто собирается с `--with-stream=dynamic`; **это не означает, что dynamic module загружен**. До запуска проверить `nginx -V` и `nginx -T`/`/etc/nginx/modules-enabled`. Если модуль отсутствует, `tcp-deploy` вернёт ошибку `nginx -t` и rollback. Не подменять Nginx своим `load_module` наугад и не добавлять `stream {}` внутрь `/etc/nginx/conf.d` (обычно это контекст `http {}`).

```bash
# На отдельной staging VPS с заранее работающим локальным TCP backend.
# Подставить ФАКТИЧЕСКИЕ свободный LISTEN_PORT и доступный BACKEND_PORT.
read -r -p "Свободный TCP LISTEN_PORT (>1024, не 2222/443): " LISTEN_PORT
read -r -p "Порт реально слушающего локального TCP backend: " BACKEND_PORT
sudo python3 scripts/staging_web_deploy.py tcp-deploy \
  --listen "$LISTEN_PORT" --backend "$BACKEND_PORT" --confirm-staging
sudo /usr/sbin/nginx -t
sudo ss -lntp | grep -F "127.0.0.1:$LISTEN_PORT"
sudo python3 scripts/staging_web_deploy.py status

# Откат только созданного r7 stream config с проверкой контента.
sudo python3 scripts/staging_web_deploy.py tcp-rollback --confirm-staging
```

TCP connect после reload доказывает **только локальную доступность порта**, не передачу пользовательских данных и не глобальную доступность. Для подтверждения payload нужно проверить реальный тестовый echo/backend-протокол извне **через согласованную тестовую топологию**, отдельно проверить target service, направление трафика, ошибки и логи. Для публичного сервиса потребуются firewall/VPS и отдельный IP/порт; r7 их намеренно не меняет.

## 4. Реальный тестовый клиент, DNS, UDP, отключение Exit

На **отдельном компьютере или чистой test VM** запустить реальный тестовый VPN-клиент c клиентским Host из *TEST Remnawave Panel*. Клиент должен предоставить **локальный** SOCKS5 без аутентификации на `127.0.0.1` с поддержкой `UDP ASSOCIATE`. Для Xray необходимо включить `settings.udp=true` (по умолчанию false), иначе UDP-тест честно завершится ошибкой. Не использовать production-подписку. Не публиковать local SOCKS порт наружу. Нужен также **отдельный разрешённый тестовый UDP echo-сервис** с известным IPv4/портом и управляемым доступом; этот проект не поднимает на VPS публичный echo daemon. В рамках допуска провайдера он должен возвращать байты пакета неизменёнными. Без него baseline/recovery обоснованно не станут PASS.

На выбранном оператором HTTPS echo URL должен возвращаться **только plain-text глобальный IPv4** без редиректов (например, `https://api.ipify.org/`; оператор обязан подтвердить использование внешнего сервиса и его приватность). Выбрать настоящий IP Exit, IP доступного DNS resolver и реальное DNS-имя. Внутри POSIX shell переменные заполняются локально:

```bash
umask 077
mkdir -m 700 /root/vk-cascade-acceptance     # или приватная папка клиента
read -r -p "Локальный SOCKS5 порт тестового клиента: " SOCKS_PORT
read -r -p "Настоящий публичный IPv4 Exit: " EXIT_IPV4
ECHO_URL=https://api.ipify.org/
DNS_IPV4=1.1.1.1
read -r -p "IPv4 отдельного разрешённого тестового UDP echo-сервиса: " ECHO_IPV4
read -r -p "Порт отдельного тестового UDP echo-сервиса (>1024): " ECHO_PORT

# Фаза 1: оба узла РАБОТАЮТ. Ожидаются HTTPS-IPv4 именно Exit + SOCKS5 UDP DNS.
python3 scripts/cascade_live_probe.py --phase baseline \
  --socks-port "$SOCKS_PORT" --exit-ipv4 "$EXIT_IPV4" \
  --https-echo-url "$ECHO_URL" --udp-resolver-ipv4 "$DNS_IPV4" \
  --dns-name example.org \
  --udp-echo-ipv4 "$ECHO_IPV4" --udp-echo-port "$ECHO_PORT" \
  --output /root/vk-cascade-acceptance/baseline.json

# Оператор отдельно останавливает ТОЛЬКО TEST Exit и документирует факт
# в provider console/журнале. НИКАКОЙ автоматической остановки этим тестом нет.
read -r -p "ID независимого подтверждения остановки TEST Exit: " OUTAGE_REFERENCE
python3 scripts/cascade_live_probe.py --phase outage \
  --socks-port "$SOCKS_PORT" --exit-ipv4 "$EXIT_IPV4" \
  --https-echo-url "$ECHO_URL" --udp-resolver-ipv4 "$DNS_IPV4" \
  --dns-name example.org \
  --udp-echo-ipv4 "$ECHO_IPV4" --udp-echo-port "$ECHO_PORT" \
  --previous /root/vk-cascade-acceptance/baseline.json \
  --outage-reference "$OUTAGE_REFERENCE" \
  --output /root/vk-cascade-acceptance/outage.json

# Exit восстановлен, маршрут снова рабочий; та же тестовая конфигурация.
python3 scripts/cascade_live_probe.py --phase recovery \
  --socks-port "$SOCKS_PORT" --exit-ipv4 "$EXIT_IPV4" \
  --https-echo-url "$ECHO_URL" --udp-resolver-ipv4 "$DNS_IPV4" \
  --dns-name example.org \
  --udp-echo-ipv4 "$ECHO_IPV4" --udp-echo-port "$ECHO_PORT" \
  --previous /root/vk-cascade-acceptance/outage.json \
  --output /root/vk-cascade-acceptance/recovery.json
```

**ПРИЁМКА НЕ ОГРАНИЧИВАЕТСЯ ЭТИМИ ТРЕМЯ ЧИСЛАМИ.** Во время baseline/outage/recovery собрать на TEST Entry ограниченный egress packet capture выбранных контрольных направлений, доказать отсутствие клиентского DNS/DIRECT, проверить что прокси клиента продолжал работать в outage, объективно зафиксировать остановку Exit, проверить вывод сервера Exit и Xray runtime (не только cold config). Не записывать реальные UUID, ключи, токены и контент чужих соединений в публичные логи. Тест SOCKS5 UDP проверяет DNS и отдельный UDP echo, но **не эквивалентен** проверке всего QUIC/всех UDP-приложений.

В **отсутствие доступа к двум VPS и test Remnawave Panel** результат live-теста: `NOT_RUN`. Локальный mock SOCKS5 relay в `tests/test_2510_r7_live_probe.py` — только проверка собственного кода, без claims о живом Xray/клиенте. Критерий production: дополнить `scripts/staging_acceptance.py` real evidence с независимым SHA ZIP и операторской ссылкой, выполнить reboot и восстановление, не считать изолированный `LIVE_PROBE=PASS` полным acceptance.

## 5. Чек-лист риска и совместимости

- Нельзя применять команды r7 к незавершённой/чужой ноде; требуются `owned-installation`, `INSTALL_COMPLETE` 2.5.10 и отсутствие флагов другой транзакции.
- TCP `stream` разрешён только на loopback `>=1025`; не меняет `443/80/2222`. Модуль stream НЕ устанавливается автоматически.
- Сайты изменяют **визуальную тему только по явному запросу**; preview и шестёрка оригиналов не удаляются, текущий site assets сохраняется.
- Новые команды не встроены в фоновое обслуживание/таймеры и не запускаются автоматически на существующей ноде.
- Ошибка Nginx reload/test/curl/selfsteal приводит к попытке вернуть исходные байты; после power loss нужна явная read-only проверка состояния/rollback.
- Rollback не восстанавливает потерянный provider snapshot или объект Remnawave.
- Публичные ссылки и функциональные тесты надо исполнять на реальных test-host/client, нельзя использовать только локальную fixture как доказательство.

**Проверяемая документация:** [Nginx stream context](https://nginx.org/en/docs/stream/ngx_stream_core_module.html), [динамические модули](https://docs.nginx.com/nginx/admin-guide/dynamic-modules/dynamic-modules/), [SOCKS5 / UDP ASSOCIATE — RFC 1928](https://www.rfc-editor.org/rfc/rfc1928), [Xray Socks inbound / udp](https://xtls.github.io/en/config/inbounds/socks.html).
