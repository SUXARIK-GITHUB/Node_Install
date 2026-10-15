# Каскад двух отдельных RemnaNode — r5, staging-инсталлятор Entry / Exit

**Статус: STAGING_ROLE_INSTALLER / LIVE_NOT_TESTED / NOT_PRODUCTION_VALIDATED.** Этот релиз действительно содержит отдельную установочную ветку `--cascade-role entry|exit` и генерирует реальные независимые RAW+REALITY/Vision-профили, но **НЕ создаёт объекты в Remnawave Panel** и **НЕ подтверждает работоспособность трафика двух VPS**. Без ручного назначения в тестовой панели и внешних сетевых испытаний считать каскад работающим нельзя.

## Граница применимости

- **Только две совершенно новые выделенные VPS** с отдельными публичными IPv4 и доменными именами: входной `entry.example.org` и выходной `exit.example.org` (домен и адреса — заменяемые примеры). DNS A каждого имени должен однозначно указывать на *собственный* глобальный IPv4 интерфейса VPS, без AAAA, Cloudflare Proxy или NAT-only.
- На обеих VPS не должно быть других Docker-контейнеров, Nginx, UFW-правил, старых ключей или чужой ноды. **Не применять** к техничке, Panel, действующим inbound, подпискам или ранее существовавшим каскадам.
- Перед использованием нужны проверенный snapshot **каждой** VPS, консоль хостера, актуальный пароль SSH администратора, известный исходящий IPv4 backend тестовой панели и **две корректно создаваемые в тестовой панели Node Secret Key**. Парольный SSH и GRUB/IPv6/firewall меняются точно как в ordinary-ветке. Нет полного rollback ОС. Используйте `--no-reboot` для контролируемого теста.
- Автоматический Panel API provisioning **намеренно не выполняется**: для него не предоставлены тип/версия панели, изолированная тестовая учётная запись, разрешения и токен. `SECRET_KEY` — не токен административного API.

## 1. Создание пары офлайн (операторская доверенная машина с Python 3 и cryptography)

Нужно проверенное содержимое ZIP и отдельная доверенная SHA256 исходного ZIP. Распакуйте его в закрытую папку и перейдите в `Node_Install/`. Команды ниже примерные, исполнять на **доверенной** машине, не на действующем сервере:

```bash
umask 077
python3 integrations/cascade_deployment.py create-pair \
  --entry-domain entry.example.org --entry-ipv4 203.0.113.10 \
  --exit-domain exit.example.org --exit-ipv4 203.0.113.20 \
  --output /root/cascade-private-pair.json
python3 integrations/cascade_deployment.py prepare \
  --pair /root/cascade-private-pair.json \
  --output /root/cascade-private-split
python3 integrations/cascade_deployment.py validate \
  --role entry --bundle /root/cascade-private-split/entry/role-bundle.json
python3 integrations/cascade_deployment.py validate \
  --role exit --bundle /root/cascade-private-split/exit/role-bundle.json
```

**Важно:** документационные адреса `203.0.113.*` — зарезервированные примеры, `create-pair` намеренно отклонит их. Подставьте **оба настоящих глобальных IPv4** и правильные DNS-имена, иначе генерация остановится. Не храните master-pair в Git, чатах, backup без шифрования и на VPS. `pair.json` содержит **ОБА** приватных ключа; отделённые `role-bundle.json` содержат **ТОЛЬКО** приватный ключ своего сервера и UUID мостового пользователя; `panel-plan.json` содержит лишь публичную информацию (без UUID). Все закрытые файлы — `0600`, приватные директории — `0700`.

На **выходную VPS** передать защищённым каналом **только** `exit/role-bundle.json`. На **входную VPS** — **только** `entry/role-bundle.json`. Не копировать master pair или чужой bundle, не использовать публичные preview JSON из `examples/`. Не показывать содержимое bundle в логах/публичных issue.

## 2. Инсталляция на двух чистых staging VPS

На обе VPS разместить **полное** проверенное дерево `Node_Install/` (одного `install.sh` для этого режима недостаточно: нужны `integrations/cascade_profiles.py` и `cascade_deployment.py`). Каждому серверу копировать только **его** root-private bundle. Следите за `root:0600` и безопасными каталогами `root:0700`.

На **Exit**, под root:

```bash
sudo bash ./install.sh --cascade-role exit \
    --cascade-bundle /root/cascade/exit/role-bundle.json --no-reboot
```

На **Entry**, под root:

```bash
sudo bash ./install.sh --cascade-role entry \
    --cascade-bundle /root/cascade/entry/role-bundle.json --no-reboot
```

В каждом случае установщик спросит скрыто `SECRET_KEY` **именно этой** Node из **тестовой** панели, FQDN **именно этой** VPS и исходящий IPv4 backend панели. Меню «2 — каскад» также работает для первичной установки (потребует роль и путь закрытого bundle).

До APT зафиксируются роль, SHA256 bundle и домен, затем будут проверены локальный IP, X25519 keypair, Node secret, сеть, SSH, Nginx, сертификат, RemnaNode и **синтаксис полученного Xray профиля реальным bundled core**. Установщик **не активирует** это Xray-содержимое сам: профиль направляется в Panel вручную.

Сохранённые на каждой VPS пути (все root-only): `/etc/vkarmani-node/cascade-role.json`, `/var/lib/vkarmani-node/role.json`, `/etc/vkarmani-node/profile.json`, `/etc/vkarmani-node/reality.json`, `/etc/vkarmani-node/PANEL-SETUP.txt`. Bundle является неизменяемым для этой инсталляции. Повторный запуск **без `--cascade-*`** после частичного сбоя проверяет сохранённую роль; повторная регистрация или переключение ролей на рабочей ноде запрещены. Осиротевший маркер означает **STOP и разбор**, не автоматический переход на ordinary.

Обычная ветка не получает каскадные ключи/конфигурации и не меняет текущую схему RAW/XHTTP. На каскаде XHTTP-шаблон отключён — только строго проверяемый RAW/Vision.

## 3. Ручные объекты Remnawave Panel (ТОЛЬКО отдельная тестовая панель)

1. Создайте две **новые** Node, привяжите к их `SECRET_KEY` и менеджмент-портам (2222 TCP допускается только от IPv4 backend Panel); проверьте отдельно видимость каждой Node. На каждой создайте свой **новый** Config Profile из закрытого `/etc/vkarmani-node/profile.json`. Никогда не присоединяйте профиль к действующей ordinary-ноде.
2. Не изменяйте сгенерированные `inbound.tag` (у каждого сервера уникальный тег), `privateKey`, `shortIds`, `serverNames`, `target` и `xver`. **Entry:** ровно два outbound, `BLOCK` первым и `TO_EXIT_VLESS` вторым; DNS-блока и DIRECT не должно быть; `routing.domainStrategy=AsIs`. **Exit:** только `DIRECT` и `BLOCK`, `DIRECT` только в ответ на собственный bridge inbound, фильтр приватных адресов.
3. Создайте отдельного **служебного пользователя для моста** с UUID из **закрытого** `role-bundle.json` (прочтите его локально офлайн, не пересылайте в чат) и выделенный **Internal Squad**, дающий доступ **ТОЛЬКО** к inbound **Exit**. Клиентов нельзя включать в этот Squad. Bridge-user нельзя включать в Entry.
4. Для настоящих тестовых пользователей выделите **другой Internal Squad**, разрешающий **ТОЛЬКО** inbound Entry. Создайте клиентский Host *только* на Entry с его FQDN:443 и правильным `publicKey`/`shortId`/SNI; не создавайте публичный клиентский Host для Exit.
5. Убедитесь, что Snippets/правила маршрутизации панели не добавляют на Entry другой DIRECT/balancer/routing. Снимите **полный фактически вычисленный** Xray JSON для каждой Node **из тестовой Panel** после назначений, сохранив файлы root:0600 на защищённом операторском окружении. Запустите read-only проверки:

```bash
python3 integrations/cascade_panel_audit.py \
  --role-bundle /root/cascade-private-split/entry/role-bundle.json \
  --computed-profile /root/entry-computed-from-test-panel.json
python3 integrations/cascade_panel_audit.py \
  --role-bundle /root/cascade-private-split/exit/role-bundle.json \
  --computed-profile /root/exit-computed-from-test-panel.json
```

**Получение холодной конфигурации именно со staging Node (read-only):** официальная Rescue CLI Remnawave Node поддерживает `docker exec -i remnanode cli --dump-config`. После назначения профиля и Internal Squad выполните это **на каждой своей новой тестовой VPS**, не на действующей ноде:

```bash
umask 077
sudo install -d -m 0700 /root/vk-cascade-audit
sudo sh -c 'umask 077; docker exec -i remnanode cli --dump-config > /root/vk-cascade-audit/cold-xray.raw'
sudo chmod 0600 /root/vk-cascade-audit/cold-xray.raw
sudo jq -e 'type == "object" and (.inbounds | type == "array")' /root/vk-cascade-audit/cold-xray.raw > /dev/null
```

Вывод может содержать **реальные приватные ключи, UUID клиентов и служебные данные**; перенесите результат в отдельное защищённое операторское хранилище как `entry-computed-from-test-panel.json` или `exit-computed-from-test-panel.json` и проверьте аудитором из этого архива. Если команда возвращает не чистый JSON (например, ANSI-баннер), `jq` должен отказать — ничего автоматически не вырезайте и не выводите в публичный лог. Внимание: *cold config* не является доказательством успешно активированного соединения; дополнительно нужны live handshake, журнал Node и внешний тест клиента. Первоисточник: [Remnawave Node Rescue CLI](https://docs.rw/features/rescue-cli/).

Аудитор допускает только известные динамические поля клиентов и ограниченную локальную служебную API-конфигурацию. Формат служебных компонентов Xray зависит от версии Panel: **аудитор может строго отклонить настоящий формат**; это означает необходимость **отдельного ревью с безсекретной обезличенной структурой**, а **не** удаления защиты. `PASS` говорит только о предоставленном JSON, **не об активной конфигурации на Node**. Сверьте fingerprint/hash фактически активной версии и логи применений Node.

> Внешний источник: [Remnawave Server Routing](https://docs.rw/learn-en/server-routing/) — официальный пример помечен *Demonstration Only | Not Production-Ready*. [Internal Squads](https://docs.rw/learn-en/squads/) и [Config Profiles](https://docs.rw/learn-en/config-profiles/) описывают правила доступа.

## 4. Гейты для настоящей двухузловой приёмки (не выполнялись в этом ZIP)

| Гейт | Что зафиксировать для каждой staging VPS и клиента |
|---|---|
| Подлинный Node API | Panel backend IPv4→Node port разрешён, остальные source IPv4 запрещены, без изменения UFW для действующих VPS |
| Xray REALITY | Core `run -test` + подтверждённый применённый computed JSON и успешная TLS REALITY handshake |
| TCP / UDP | Независимые соединения тестового клиента, QUIC/UDP по плану, HTTP(S) и DNS |
| Внешний IPv4 | Клиент видит **только** глобальный IPv4 Exit при авторизованном доступе; на Entry нет клиентского egress |
| Отказ Exit | При обрыве peer, DNS выхода или неверном bridge UUID клиент получает отказ, **НЕ** идёт в Интернет через Entry |
| RKN | С Exit после включения фильтра доступны входные соединения Entry:443; peer IPv4 **может попадать в блок-лист**. Автоматическое peer-исключение RKN не реализовано; НЕ открывать firewall вслепую. При несовместимости фильтра — не выпускать в production |
| Перестарт/сертификаты | Отдельные Nginx и TLS сертификаты, перевыпуск; повторный запуск контейнеров/Node/Panel, reboot в разном порядке |
| UFW/SSH | Консоль провайдера, внешний повторный вход после reboot, Fail2ban и Node ACL |
| Таймеры | Автоматический контейнерный restart каскадных ролей **отключён до координации** (SKIPPED), weekly reboot запрещён |
| Backup/rollback | Создать и **проверить восстановление** снимков обеих VPS; `--rollback-image/cover` не являются полным rollback |
| Совместимость | Проверить реальные версии RemnaNode/rw-core, Ubuntu/Debian, kernel, hardware и внешний reverse proxy/Cloudflare |
| Деградация | Проверить DNS failure, restart Core, systemd/network fault, неверный shortId/SNI и аварийную потерю Exit |

Результаты должны содержать точный SHA256 ZIP, время, идентификаторы **тестовых** Node и версию Panel/Core **без токенов и UUID**; лучше вести [staging evidence](../scripts/staging_acceptance.py). Тесты DNS на Entry выполняются внешней точкой с `tcpdump`/метриками без данных реальных пользователей.

## 5. Обязательные ограничения

- Никаких автоматических миграций действующих inbound/клиентов/панели, открытых Node API, новых UI или сервисов без отдельного разрешения.
- Полные backup/rollback для двух VPS **не созданы** автоматически. Никаких destructive-команд, пока не проверены snapshots и доступ через консоль.
- Блокировка пользовательского DIRECT на Entry **не запрещает системный трафик самой VPS**: DNS для Let's Encrypt, APT, NTP, RKN и управление работают локально. Нельзя называть это общесистемным egress lockdown.
- Смена bridge secret/REALITY ключей и безопасная атомарная миграция двух активных Node не автоматизированы; для такой смены нужна новая staging-пара и план контролируемого обслуживания.
- `r5` содержит **установку двух ролей и проверку шаблонов**, но не гарантирует успешную сеть до создания объектов в тестовой панели и live-приёмки. **Статус остаётся `INCOMPLETE_STAGING_ONLY`.**
