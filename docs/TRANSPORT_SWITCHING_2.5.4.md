# Node_Install 2.5.4 — ручной выбор RAW или XHTTP через Remnawave Panel

Дата: 2026-10-09. Статус: **локально проверенная реализация; реальное клиентское подключение и сценарий смены активного профиля на VPS ещё не проверены**.

## 1. Пользовательский сценарий

Никакого демона-переключателя, синхронизации конфигов из панели по таймеру, дополнительного публичного listener, второго Xray или второго контейнера. Оператор самостоятельно редактирует **ОДИН активный VLESS inbound** в Config Profile Remnawave Panel и применяет его штатным способом. При необходимости оператор перезапускает **RemnaNode**, НЕ Ubuntu/VPS. Для возврата он восстанавливает прежнее содержимое inbound и снова применяет его. Нельзя одновременно держать два VLESS inbound, занимающих `0.0.0.0:443`.

### Существующая архитектура — остаётся без изменений

- Клиент → **IPv4 TCP/443 → Xray в RemnaNode**, `network_mode: host`; `network: raw` ИЛИ `network: xhttp`.
- Клиентский REALITY SNI остаётся доменом ноды; existing server `privateKey`, `shortIds`, идентичность и tag сохраняются.
- Не прошедший REALITY соединение → `target: /dev/shm/nginx.sock`, `xver: 1` → существующий **host Nginx** на `/run/vkarmani-selfsteal/nginx.sock` (TLS, PROXY protocol v1, HTTP/2) → существующий сайт-прикрытие.
- `docker compose` bind-mount `/run/vkarmani-selfsteal` в `/dev/shm` (read-only); нет `ports:` и нового host proxy.
- Отдельный ACME HTTP-01 путь, Nginx SSL, certbot renewal hook, IPv4-only, UFW, RKN Guard с динамической панельной allowlist, SSH, NET_ADMIN, DNS и маршрутизация не затрагиваются.
- `profile.json` и `profile-xhttp.json` — **Шаблоны для импорта в панель**, а НЕ текущие настройки работающего Xray; редактирование файлов на VPS само по себе НЕ переключает inbound.

## 2. Транспортный контракт: при смене нужен не только `network`

| Настройка | Текущий RAW | XHTTP |
|---|---|---|
| `protocol` | `vless` | `vless` |
| `port` | `443/tcp` | `443/tcp` |
| `tag` | прежний | **тот же прежний** |
| `streamSettings.network` | `raw` | `xhttp` |
| `streamSettings.security` | `reality` | `reality` |
| `settings.flow` | `xtls-rprx-vision` | `""` |
| VLESS client `flow` | совместимый Vision | **пустой** |
| `streamSettings.xhttpSettings` | отсутствует | `host`, `path`, `mode: auto` |
| `realitySettings` | действующие | **те же** |
| `realitySettings.target` | `/dev/shm/nginx.sock` | тот же socket |
| `realitySettings.xver` | `1` | `1` |
| Nginx/SSL | host Nginx, PROXY v1, HTTP/2 | тот же Nginx/SSL |

`mode: auto` — консервативный старт без экспериментальной настройки padding/XMUX и без HTTP/3/UDP. XHTTP `path` генерируется для каждого узла детерминированно как HMAC на основе **существующего закрытого REALITY-ключа и домена** (первые 128 бит SHA256), поэтому не требует нового секрета, стабилен после рестарта и не равен ShortID. Нельзя публиковать server privateKey, секрет панели или полный `profile-*.json` в чате, тикете или логах; в них есть закрытый ключ.

Дополнительное `xhttpSettings.host` должно совпадать с доменом ноды; при обновлении подписки и Host transport overrides клиентские `path` и `host` должны соответствовать выбранному inbound. Если Host/Subscription Template переопределяют транспорт, необходимо обновить их **в панели**. Поддержка XHTTP зависит также от приложения и ядра Xray клиента. Remnawave Sing-box generator в части версий не поддерживает XHTTP: совместимость подписок проверяется отдельно, а не предполагается.

Официальный референс: https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP-Reality/minimal-steal_others ; Xray XHTTP design: https://github.com/XTLS/Xray-core/discussions/4113 ; Remnawave Node: https://github.com/remnawave/node .

## 3. Свежая установка 2.5.4

Устанавливать на чистый отдельный VPS только по общим требованиям README; сделать snapshot VPS и обеспечить аварийную консоль. Предварительно `sha256sum --check SHA256SUMS`, `bash -n install.sh`. На успешном этапе создания профилей создаются **два шаблона**, оба проверяются локальной политикой, а затем **синтаксис XHTTP проверяется установленным `rw-core` внутри действующего RemnaNode контейнера**, но **не применяется в работающий процесс**. Если текущий core отвергает XHTTP, первая установка **не отменяет рабочий RAW**; XHTTP-шаблон остаётся NOT_READY (до успешной команды `--prepare-xhttp` после проверки совместимости образа), журнал проверки остаётся в закрытом каталоге state. Проверка синтаксиса не доказывает отсутствие DPI-блокировки и успешное подключение клиента.

Файлы с приватным содержимым:

- `/etc/vkarmani-node/profile.json` — неизменённый RAW/REALITY/Vision; root:0600.
- `/etc/vkarmani-node/profile-xhttp.json` — альтернативный XHTTP/REALITY; root:0600.
- `/etc/vkarmani-node/reality.json` — исходные REALITY-ключи, **никогда не заменять ради смены транспорта**.
- `/etc/vkarmani-node/PANEL-SETUP.txt` — локальная инструкция по ручному созданию/редактированию.
- `/usr/local/lib/vkarmani-node/xhttp_profile.py` — источник генератора, устанавливается при первой установке.

## 4. Уже установленная нода 2.5.2/2.5.3

Не запускайте установку с нуля поверх working production. Сделайте backup/snapshot (включая export/backup Config Profile и Host из Remnawave Panel; бэкап файла с VPS **не** заменяет бэкап панели). Перейдите в папку распакованного проверенного полного архива `Node_Install_2.5.4` и выполните:

```bash
sha256sum --check SHA256SUMS
bash -n install.sh
sudo bash install.sh --prepare-xhttp
```

Это **узкая, отдельная операция**, которая требует проверенного завершённого Node_Install 2.5.2/2.5.3/2.5.4, валидных root:0600 исходных файлов, запущенного RemnaNode в `host` network, исправного TLS target и отсутствия конфликта installer lock. Она временно копирует шаблон в контейнер для `rw-core run -test -config`, удаляет временный файл и лишь при успехе создаёт **один новый** `/etc/vkarmani-node/profile-xhttp.json`. Она **не** переписывает RAW template, ключи, panel API, Nginx, certbot, firewall, Docker Compose или работающий Xray; не вызывает reboot. Повторный запуск идемпотентен; если существующий XHTTP-шаблон не совпадает с детерминированной версией, перезапись запрещена. Замену содержимого профиля в самой панели выполняет оператор.

При отказе: не переустанавливайте Docker и не делайте `ufw reset`; изучите причину, состояние Selfsteal, версию/core compatibility, сохранённый локальный приватный журнал. Команда не включает XHTTP сама по себе.

## 5. Порядок смены в панели (один inbound/tag/443)

1. **Сохранить копию текущего Config Profile и Host.** Проверить доступ к панели отдельно от VPN. Установить и документировать текущий рабочий RAW inbound и клиентскую подписку.
2. Из файла `/etc/vkarmani-node/profile-xhttp.json` *локально и безопасно* взять альтернативные настройки **того же** `tag`. Не публиковать приватный JSON. В панели заменить соответствующий VLESS inbound XHTTP-шаблоном; оставить исходные ключи, inbound `tag`, TCP/443, routing, outbound и Selfsteal target.
3. Убедиться, что активный профиль содержит ровно **один VLESS listener на TCP/443**. Не добавлять XHTTP параллельно с RAW на тот же endpoint.
4. Проверить Remnawave Host, transport options, Internal Squads, overrides/subscription template. При сохранённом теге обычное переназначение Host не требуется, но overrides клиента могут оставаться RAW; синхронизировать `network=xhttp`, `path`, `host`, `flow=""` и SNI. Составить резервный рабочий способ доступа.
5. Дождаться подтверждения, что RemnaNode получила обновлённую конфигурацию. Если нужно перезапустить, предпочтительнее штатное управление нодой в Panel; при ручном сервисном восстановлении проверять `docker restart remnanode` только после резервного копирования и понимания влияния на активных пользователей. **Не перезагружать VPS ради смены inbound.** При рестарте клиентские соединения оборвутся.
6. Проверить **серверный уровень**: контейнер запущен; Xray успешно стартовал; 443 принадлежит ожидаемому процессу; обычный TLS ClientHello без REALITY возвращает ожидаемый HTTPS Selfsteal; `vkarmani-node-check` и Nginx ACME renewal работоспособны. Проверка портов сама по себе не доказывает VPN.
7. Проверить **клиентский уровень**: клиент обновил подписку, умеет XHTTP+REALITY, `flow` пустой, SNI и path корректны; успешное подключение, TCP/UDP egress, DNS, reconnection, скорости, сравнение путей из разных операторских сетей. Если подписка закэширована, клиент не переключится «сам» после изменения панели — требуется обновление.

**Откат:** в Panel вернуть сохранённый RAW inbound (тот же `tag`, `network=raw`, удалить `xhttpSettings`, `flow=xtls-rprx-vision`), обновить Host/Subscription overrides, применить Config Profile, перезапустить ноду при необходимости, вернуть клиентам совместимую подписку; проверить Selfsteal, VPN и соединение панели. Не удалять `/etc/vkarmani-node/reality.json`, certbot/Let's Encrypt, Nginx, volumes или RKN rule set.

## 6. Разграничение проверок и рисков

- **Local tests:** проверяют сериализацию, ключи, инвариант одного listener, разрешённые JSON-поля, запрет Vision при XHTTP, ограничения root:0600, неизменность RAW/DNS/routing, существующий Nginx+PROXY v1, отказ от подмены файлов и версионные проверки.
- **Runtime core check на VPS:** должен выполниться именно установленным `rw-core` в образе по digest. `rw-core -test` = проверка разбора конфигурации, не успешности HTTPS, подписки или DPI.
- **Полноценный E2E canary:** требуется на реальном VPS. Тестовая среда релиза **не имеет** действующего Docker/Remnawave Panel/публичного маршрута из российских сетей и не может выдавать production proof.
- **Незаметность:** ни REALITY, ни XHTTP, ни настоящий Selfsteal, ни RKN Guard не гарантируют отсутствие блокировок IP/ASN/префикса и не обещают невидимость для DPI. Изменение транспорта может помочь при некоторых видах фильтрации, но при заблокированном IP не восстановит маршрут.
- **Модель отказа:** некорректный inbound в панели может остановить Xray; текущий исходный RemnaNode restart path не гарантирует возврат к последней рабочей конфигурации. Поэтому сначала backup конфигурации панели, staging-проверка и доступ к альтернативной ноде.
- **TLS fallback:** одинаковый REALITY target и xver=1 необходимы для host Nginx на Unix сокете. Не устанавливать второй Nginx на 443; не включать reverse proxy для REALITY через Cloudflare Orange Cloud.
- **Конфиденциальность:** не печатать приватные REALITY-ключи или `SECRET_KEY` в диагностике; не отправлять `profile-xhttp.json` как вложение в публичные чаты.
- **RKN Guard:** правила TCP/80,443 и динамический panel allowlist остаются прежними; XHTTP не требует `iptables`-нат, новых IP/портов и других exception.
- **Upstream:** перед следующим Node_Install-релизом проверять изменения Xray XHTTP/REALITY, Remnawave Node/Backend/subscription generators и списки Flecksis/rkn-guard по правилам RKN_GUARD_2.5.3.md.

## 7. Проверки и rollback на VPS

Read-only/стандартные команды (пути образца для управляемой VPS):

```bash
sudo bash install.sh --prepare-xhttp         # ОДИН РАЗ для ранее установленной ноды
sudo bash install.sh --check                 # проверка локального сервера
sudo nginx -t
sudo docker inspect remnanode --format '{{.State.Running}}|{{.HostConfig.NetworkMode}}'
sudo docker logs --since 10m remnanode       # смотреть локально, не выкладывать секреты
sudo ss -lntp                                # владелец TCP/443 и управляющего порта
sudo systemctl status vkarmani-node --no-pager
```

Бэкапы: snapshot/backup VPS + export Config Profile/Hosts из Remnawave Panel + сохранение подписок клиентов, если планируется откат. **Откат транспорта = откат изменений в Panel, не удаление/переустановка ноды.** Изменений существующих services/network configuration команда `--prepare-xhttp` не выполняет.
