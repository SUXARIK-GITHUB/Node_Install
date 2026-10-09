# VKarmani Node Install 2.5.5

> **Релиз-кандидат · 09.10.2026 · выделенная Remnawave Node · Ubuntu 22.04/24.04/26.04 или Debian 12/13.**
>
> Один публичный IPv4, один активный клиентский TCP/443, VLESS+RAW+REALITY+Vision **или** VLESS+XHTTP+REALITY. Nginx Selfsteal работает на хосте, вне Docker. IPv6 отключается. UFW, Fail2ban, Docker Compose, Let's Encrypt, мониторинг, backup, rollback, RKN Guard и диагностика сохраняются.
>
> **Статус:** локальные проверки и тесты ≠ подтверждённый production. Прежде чем раскатывать на все серверы, нужен canary на отдельной VPS с реальным подключением панели и клиента.

## Оглавление

1. [Назначение и модель ответственности](#1-назначение-и-модель-ответственности)
2. [Подготовка VPS и обязательный backup](#2-подготовка-vps-и-обязательный-backup)
3. [Запуск установки](#3-запуск-установки)
4. [Архитектура, Nginx и Selfsteal](#4-архитектура-nginx-и-selfsteal)
5. [Настройка Remnawave Panel](#5-настройка-remnawave-panel)
6. [Полный профиль RAW+REALITY+Vision](#6-полный-профиль-rawrealityvision)
7. [Полный профиль XHTTP+REALITY](#7-полный-профиль-xhttpreality)
8. [Ручная смена inbound без изменения VPS](#8-ручная-смена-inbound-без-изменения-vps)
9. [Стабильность, DNS, routing и уменьшение наблюдаемости](#9-стабильность-dns-routing-и-уменьшение-наблюдаемости)
10. [Версии Xray и безопасные обновления](#10-версии-xray-и-безопасные-обновления)
11. [RKN Guard: автоматическое обновление списков](#11-rkn-guard-автоматическое-обновление-списков)
12. [Обслуживание и диагностика](#12-обслуживание-и-диагностика)
13. [Расположение конфигурации и секретов](#13-расположение-конфигурации-и-секретов)
14. [Полная приёмка, сбои и rollback](#14-полная-приёмка-сбои-и-rollback)
15. [Тестирование, ограничения, исходники](#15-тестирование-ограничения-исходники)

## 1. Назначение и модель ответственности

Установщик **только готовит выделенную VPS RemnaNode**. Он проверяет окружение, настраивает ОС/SSH/UFW, ставит Docker и Nginx, выпускает сертификат и создаёт конфигурацию ноды и **два приватных шаблона** для Remnawave. Он **не создаёт** Panel Node, Config Profile, Host, Internal Squad, подписки и пользователей через API и **не изменяет** их автоматически.

- **Работающий конфиг Xray** приходит из Remnawave Panel. Локальные `profile.json` и `profile-xhttp.json` — **примеры импорта**, а не автоматически включённые inbounds.
- **RAW:** `network=raw`, VLESS `flow=xtls-rprx-vision`, REALITY + Selfsteal.
- **XHTTP:** `network=xhttp`, VLESS `flow=""`, `xhttpSettings.host/path/mode`, REALITY + тот же Selfsteal.
- На каждой ноде выбирается **один из этих inbound на TCP/443**. Другой слушатель на 443 не создаётся.
- Cover/REALITY **не гарантируют** защиты от DPI, обнаружения узла, блокировки IPv4, ASN или провайдера.
- Смена транспорта сама по себе не снимает блокировку IP/ASN/провайдера и **не гарантирует невидимости для DPI**. Для реальной отказоустойчивости нужны резервные IP/ASN, подходящие клиенты и внешние измерения.

Если предыдущая версия уже работает в production — **не запускайте первичную установку заново** ради добавления XHTTP. Используйте специальный `--prepare-xhttp`, предварительный backup и canary.

## 2. Подготовка VPS и обязательный backup

### Поддерживаемый профиль сервера

- Чистая **отдельная** VPS (не Panel, БД, бот, общий хост с чужими контейнерами).
- Ubuntu **22.04, 24.04, 26.04** / Debian **12, 13** на поддерживаемой архитектуре; реально проверенная ранее перезагрузка относится к Ubuntu 24.04, **не ко всем комбинациям**.
- Root/sudo, доступ к **консоли/recovery хостера** и заведомо рабочий пароль SSH **до начала**.
- Рекомендован запас RAM, CPU и диска; минимальные требования RemnaNode см. [официальные требования](https://docs.rw/install/requirements/). Инсталлятор выполняет собственные preflight-проверки.
- `node.example.com` в примерах — **не рабочий адрес**: свой домен должен иметь **одну A-запись** на публичный IPv4 VPS, **без AAAA**, а в Cloudflare — **DNS only** (серое облако), без проксирования REALITY через CDN.
- Доступные порты: **TCP/80** (ACME и HTTP redirect), **TCP/443** (Xray), **TCP/2222** либо заданный Node API port **только с IPv4 панели**, плюс существующие TCP-порты SSH. Не открывайте 2222 для всего Интернета.
- На сервере не должно быть чужого сервиса, владеющего 443, UFW/Nginx/iptables или сетевой политикой; preflight **останавливается**, а не удаляет неизвестные ресурсы.

### Почему нужен snapshot

Установка меняет **SSH, UFW, Fail2ban, Docker, Nginx, сертификаты, GRUB, sysctl, NTP, systemd**. Она может отключить SSH-вход по ключу в соответствии с текущей password-only политикой проекта; аккаунты/пароли не создаёт. После успешной проверки **по умолчанию планируется одна перезагрузка через 30 секунд**; используйте `--no-reboot` для ручного контроля. Встроенные откаты частичны и **не заменяют snapshot VPS**.

Безопасная последовательность: snapshot → проверить восстановление/консоль → убедиться, что второй SSH-login возможен → запуск → тест → reboot → повторный тест.

## 3. Запуск установки

### Приоритетный способ — полный проверенный архив

**История Git:** вложенная `.git` унаследована от исходного ZIP и может указывать на устаревший commit; она не является фиксацией релиза 2.5.5. Перед GitHub-публикацией используйте отдельную проверенную ветку, сравнение с актуальным `main`, полный манифест и зелёный CI; не выполняйте `git push --force` из распакованного архива.

Новая версия **не опубликована автоматически** в `SUXARIK-GITHUB/Node_Install/main`. Пока там другая версия, не используйте старую инструкцию `curl raw/main/install.sh`, не правьте SHA «чтобы заработало». Распакуйте именно `Node_Install_2.5.5.zip` и выполните:

```bash
cd Node_Install
sha256sum --check SHA256SUMS
bash -n install.sh
bash install.sh --version               # 2.5.5
sudo bash install.sh --no-reboot         # рекомендуемый первый canary
```

На чистой VPS скрипт запрашивает **ровно три значения**: `SECRET_KEY` ноды из панели, домен ноды, публичный IPv4 панели (адрес технички, **не IP этой ноды**). Собственный IPv4 VPS определяется по проверенным локальным адресам и DNS. Для ввода нужен интерактивный терминал; если подключились без PTY, используйте SSH с `-t`.

Другие параметры:

```bash
sudo bash install.sh                     # обычный режим, с одной reboot после успеха
sudo bash install.sh --weekly-reboot     # отдельно включить еженедельную перезагрузку
sudo bash install.sh --image 'remnawave/node:3.4.2' # осознанно выбранная официальная версия
```

`--image` — только для новой/допустимой незавершённой установки; **не обновление запущенной ноды**. После получения образа Compose использует сохранённый **digest**. Не используйте скрипт установки как механизм принудительного скачивания неизвестного `latest` Xray.

### Если узел уже установлен

```bash
sudo bash install.sh --check
sudo bash install.sh --backup
sudo bash install.sh --prepare-xhttp    # готовит только приватный XHTTP-шаблон
```

`--prepare-xhttp` работает только для поддерживаемых завершённых версий 2.5.2+; проверяет **реальный `rw-core` внутри контейнера** через `run -test`, не изменяет панель, Docker Compose, UFW или слушатели. Если тест Core не прошёл, шаблон не должен считаться готовым и RAW остаётся как был.

## 4. Архитектура, Nginx и Selfsteal

```text
VPN-клиент / обычный HTTPS-проверяющий
            |
       публичный IPv4:443  (TCP; UDP/443 не открывается)
            |
    RemnaNode -> один Xray inbound
        /                \\
 RAW+Vision          XHTTP+REALITY
          \          /
    REALITY недоверенный TLS/не-VLESS
            |
  target=/dev/shm/nginx.sock, xver=1
            |
  Docker bind-mount read-only (/dev/shm в контейнере)
            |
  /run/vkarmani-selfsteal/nginx.sock (Unix socket на хосте)
            |
  host Nginx: TLS 1.3 + HTTP/2 + PROXY protocol v1
            |
  статический сайт + настоящий Let's Encrypt
```

**Что уже правильно сделано и сохраняется:** Xray владеет TCP/443; Nginx слушает только приватный Unix-сокет для TLS Selfsteal; HTTP/80 выделен под ACME HTTP-01 и HTTP-redirect; сайт выдаёт настоящий контент, неизвестные хосты/пути отклоняются; Nginx проверяется через `nginx -t`, затем выполняется graceful reload. Certbot обновляет сертификат с отдельной проверкой фактически принятого leaf и HTTPS-ответа.

**Не делайте** одновременно `listen 443 ssl` у Nginx и `VLESS port 443` у Xray; не прокидывайте внешний proxy protocol на Xray inbound — `xver=1` относится **только к внутреннему REALITY → Nginx**. Не переводите Cloudflare orange-cloud в расчёте на прозрачный REALITY. Не меняйте `xver` без одновременной правки Nginx `proxy_protocol`, не переносите REALITY target на случайный внешний домен.

Локальный Selfsteal probe проверяет **TLS 1.3 с верификацией сертификата**, ALPN `h2` и `http/1.1`, настоящие HTTP/2 DATA и точное тело страницы. Это проверка локального таргета; дополнительно нужен внешний HTTPS-тест **через Xray:443** и проверка неизвестного SNI. Приватные сертификаты Let's Encrypt **не передаются контейнеру**; Nginx читает их на хосте.

## 5. Настройка Remnawave Panel

После установки прочитайте **локальную** инструкцию:

```bash
sudo cat /etc/vkarmani-node/PANEL-SETUP.txt
```

Дальше в Remnawave Panel: **Nodes → Management** создайте Node, внесите `SECRET_KEY`/Node Address/Node Port, выберите **один** Config Profile, активируйте **один нужный inbound**, настройте **Hosts** с правильным `inboundTag`, затем Internal Squads/пользователей и выдачу подписок. В разных версиях панели названия меню могут различаться.

Для любой конфигурации сохраняйте точные значения **этой VPS**: `tag`, `port`, `serverNames`, `privateKey`, `shortIds`, `target=/dev/shm/nginx.sock`, `xver=1`; для XHTTP — дополнительно уникальный `path` и `host`. **Не заменяйте ключи из настоящей ноды тестовыми значениями из README.** Действующие файлы с приватными ключами не отправляйте в публичный Git/чат/логи.

**Клиент:** Host/Subscription должны содержать адрес ноды, `SNI`, REALITY `publicKey` (публичная половина ключа), `shortId`, ALPN/fingerprint согласно поддерживаемому Core. Для XHTTP нужны совпадающие `host`/`path`/`mode` и **нет Vision flow**. Клиент, не поддерживающий XHTTP, нельзя «вылечить» только обновлением серверного inbound. Sing-box-генератор подписок в некоторых версиях Remnawave не поддерживает XHTTP — проверяйте используемый клиентский формат и не выдавайте несовместимый профиль.

## 6. Полный профиль RAW+REALITY+Vision

**Это полный JSON по текущему генератору установщика, но с *публикационно безопасными заглушками*.** `node.example.com`, `203.0.113.10` и `198.51.100.20` — учебные значения, не существующие адреса вашей инфраструктуры. `privateKey`, `shortIds`, `tag` должны быть взяты **из `/etc/vkarmani-node/profile.json` на своей VPS**. Именно этот локальный файл уже содержит корректные параметры и реальные секреты, его проще импортировать целиком, не копируя значения из примера. `clients: []` штатно заполняются Remnawave.

<!-- BEGIN RAW FULL EXAMPLE -->

```json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "VK_RAW_REALITY_REPLACE_WITH_NODE_TAG",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": "xtls-rprx-vision"
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "node.example.com"
          ],
          "privateKey": "REPLACE_WITH_PRIVATE_KEY_FROM_NODE",
          "shortIds": [
            "REPLACE_WITH_SHORT_ID_FROM_NODE"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "203.0.113.10/32",
          "::/0",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      }
    ]
  }
}
```

<!-- END RAW FULL EXAMPLE -->

Особенности RAW: `streamSettings.network="raw"`; `settings.flow="xtls-rprx-vision"`; `security="reality"`; Selfsteal: Unix-сокет и `xver=1`. `sniffing.routeOnly=true` и IPv4 routing сохраняются. **Ни `xhttpSettings`, ни отдельного inbound на 443 тут нет.**

## 7. Полный профиль XHTTP+REALITY

**Это второй полный JSON, а не «вставьте три поля куда-нибудь».** Для реальной ноды используйте результат `--prepare-xhttp`: `/etc/vkarmani-node/profile-xhttp.json`. Он использует **те же X25519/private/public/ShortID, inbound tag, routing, DNS и socket**, что существующий RAW, а HTTP-path детерминированно выводится локально из ключа и домена без публикации самого ключа. Два профиля являются **альтернативами** на TCP/443.

<!-- BEGIN XHTTP FULL EXAMPLE -->

```json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "VK_RAW_REALITY_REPLACE_WITH_NODE_TAG",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": ""
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "node.example.com"
          ],
          "privateKey": "REPLACE_WITH_PRIVATE_KEY_FROM_NODE",
          "shortIds": [
            "REPLACE_WITH_SHORT_ID_FROM_NODE"
          ]
        },
        "xhttpSettings": {
          "host": "node.example.com",
          "path": "/REPLACE_WITH_NODE_GENERATED_XHTTP_PATH",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "203.0.113.10/32",
          "::/0",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      }
    ]
  }
}
```

<!-- END XHTTP FULL EXAMPLE -->

Особенности XHTTP: `flow=""` на inbound и у клиентов, `network="xhttp"`, `xhttpSettings.mode="auto"`, `host` равен домену ноды, `path` совпадает между сервером и клиентом. `xtls-rprx-vision` **не применяется вместе с XHTTP**. Для начала не настраивайте экспериментальные заголовки, `XMUX`, нестандартный padding, HTTP/3 и UDP/443: в текущей схеме остаёмся на TCP и проверяем производительность отдельно.

**Важно:** реальное поведение XHTTP зависит от версии `rw-core`, клиента, режима XHTTP и Host/subscription. Само наличие правильного JSON на диске не доказывает успешного соединения пользователя.

## 8. Ручная смена inbound без изменения VPS

Это именно желаемый сценарий, **без таймера/демона автоматического переключения**:

1. Сохраните резервную копию Config Profile и Host **в панели**, сделайте snapshot или `--backup` ноды.
2. На ноде: `sudo bash install.sh --prepare-xhttp` → убедитесь, что `XHTTP_TEMPLATE=PASS; XRAY_SYNTAX=PASS`.
3. В **существующем** Config Profile замените поля одного VLESS inbound из локального приватного `profile-xhttp.json`. **Tag, ключи REALITY, порт, адрес, Host и Internal Squads сохраняются.** Не создавайте одновременно две VLESS-записи на 443.
4. Проверьте серверную конфигурацию в панели, примените её; при необходимости выполните **штатный рестарт RemnaNode**, а **не reboot всей VPS**.
5. Проверьте локальную доступность, `sudo vkarmani-node-check --require-xray`, внешнюю страницу-прикрытие через 443, затем обновите подписку совместимого клиента и проверьте авторизованный трафик.
6. Для возврата используйте **сохранённый RAW JSON** с `network=raw`, `flow=xtls-rprx-vision`, удалив XHTTP-настройки; примените и перезапустите ноду тем же способом.

**Предупреждение о downtime:** RemnaNode при изменении базовой конфигурации останавливает предыдущий процесс Xray перед запуском нового. Ошибочная конфигурация может оставить клиентов без сервиса. **Автоматического бесшовного rollback в панели этот установщик не обеспечивает.** Храните копию заведомо работающего профиля **до** переключения и вначале тестируйте одну ноду.

## 9. Стабильность, DNS, routing и уменьшение наблюдаемости

### Проверенные настройки по умолчанию

- IPv4-only: `dns.queryStrategy=UseIPv4`, `freedom.domainStrategy=UseIPv4`, `routing.domainStrategy=IPOnDemand`, блокирование loopback/RFC1918/CGNAT/link-local/multicast/IPv6, собственных IP и управляющего IPv4 панели. Установщик не меняет MTU и маршруты вслепую.
- Nginx выдаёт **настоящий HTTPS**, TLS 1.3/h2, корректный сертификат, фиксированную статическую страницу, неизвестный SNI/Host обрабатывает предсказуемо. Не следует рандомизировать TLS-fingerprint сервера или менять заголовки «для невидимости» без измерений.
- Производительность зависит от реального RTT/потерь/CPU/сервера/клиента. BBR/fq включается только там, где ядро поддерживает его и значения проходят локальную проверку; это не универсальная гарантия скорости.
- Сканирование и пассивные сигнатуры могут выдавать наличие прокси; **ни REALITY, ни XHTTP, ни Selfsteal не обещают абсолютной незаметности и защиты от IP/ASN-блокировки**.

### Необязательное развитие DNS (только после `rw-core run -test`)

В современных Xray есть параметры `serveStale`, `disableCache`, `serveExpiredTTL` и `enableParallelQuery`. Их пример:

```json
{
  "dns": {
    "servers": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "serveStale": true,
    "serveExpiredTTL": 3600,
    "enableParallelQuery": true
  }
}
```

**Это только JSON-фрагмент `dns` для включения в полный профиль после теста**, а не отдельный готовый Xray Config Profile. Больше одновременных DNS-запросов ≠ автоматически меньше RTT; `serveStale` может временно возвращать устаревшие IP. Поэтому в установленном профиле сохраняются прежние проверенные значения. Не включайте DoH/DoT/удалённый DNS/proxying без понимания сетевой маршрутизации и доступности DNS из этого VPS.

### BitTorrent, дополнительные outbound `finalRules`, геоданные

В твоём примере есть `routing.protocol=["bittorrent"]`, `geosite:private`, `geoip:private`, `freedom.settings.finalRules`. Эти функции могут быть полезны, но **не автоматически эквивалентны** текущему профилю. При `sniffing.destOverride=["http","tls","quic"]` правило BitTorrent нельзя считать гарантированным детектором всего торрент-трафика; нужны поддержка sniffing, соответствующая policy, валидные geoip/geosite, правильный порядок правил и проверка фактического поведения. Не копируйте чужой полный routing в production без отдельной приёмки.

В штатном профиле уже предусмотрено блокирование обращений к приватным сетям и собственным IP, без добавления внешних списков и сервисов. Дополнительные `finalRules` проверяйте на staging с конкретным bundled Core. Если в панели меняются routing/внутренний API inbound, убедитесь, что правило сервисного API остаётся корректным и не блокируется.

### Метрики, помогающие найти причину «бана»

Проверяйте отдельно: доступность IPv4 из целевой сети; TCP SYN/SYN-ACK; TLS/SNI+реальный Selfsteal; согласованный реальный VLESS-клиент; DNS/Cloudflare; `conntrack`, PSI/CPU/RAM/disk, TCP retransmits; логи RemnaNode/Xray без секретов. Это позволяет отличать DPI/IP-блокировку от падения контейнера, ошибки сертификата или подписки. Мониторинг извне нельзя заменить командой `docker ps`.

## 10. Версии Xray и безопасные обновления

**Новое с 2.5.5: проверка версий в один вызов, без изменений на сервере:**

```bash
sudo bash install.sh --xray-versions           # установленный Core + свежие GitHub Releases
sudo bash install.sh --xray-versions --offline # только текущий Core, без сети
sudo bash install.sh --refresh-image           # ОБНОВЛЕНИЕ ОБРАЗА, отдельная операция с рисками
sudo bash install.sh --rollback-image          # ОТКАТ ОБРАЗА, если разрешает transaction state
```

Проверка сравнивает `rw-core version` из контейнера с публичными метаданными GitHub и отдельно показывает **новейший опубликованный релиз, в том числе pre-release**, и `latest` стабильного канала. При ошибке GitHub выводит `NOT_VERIFIED`; она **никогда** не скачивает и не запускает исполняемый файл. Не путайте version-check с security audit и не предполагайте, что newest upstream автоматически совместим с RemnaNode.

Официальный RemnaNode уже имеет **нативный механизм** `geodata.core = {url, sha256}`: он скачивает *сырой исполняемый файл по HTTPS*, сверяет SHA256, проверяет версию и управляет symlink `rw-core`. Удаление override возвращает встроенный Core. Для его применения нужны управляемая публикация проверенного бинарника и изменения **в Panel Xray Config Profile**, которых наш установщик без доступа к панели **не делает**.

**Не используйте** `docker exec ... wget latest > /usr/local/bin/rw-core`, монтирование случайного host-файла поверх `rw-core`, автоматическую загрузку непроверенного pre-release или подмену Core до тестирования обоих инбаундов, Node Plugins, геоданных и отката. Детально: [docs/XRAY_CORE_UPDATES_2.5.5.md](docs/XRAY_CORE_UPDATES_2.5.5.md).

## 11. RKN Guard: автоматическое обновление списков

Встроена **наша совместимая реализация** сканер-фильтра на `ipset`/UFW, источник сетей — `shadow-netlab/traffic-guard-lists`, связанный с проектом [Flecksis/rkn-guard](https://github.com/Flecksis/rkn-guard). Данные обновляются **раз в сутки** (`systemd timer`, `Persistent=true`). Код стороннего репозитория **не запускается и не обновляется автоматически от root**. Перед каждым будущим релизом нужно сверять upstream-код и обновления источника.

```bash
sudo bash install.sh --enable-rkn-guard # на завершённой совместимой ноде
sudo bash install.sh --rkn-status
sudo bash install.sh --rkn-update       # внеплановая синхронизация списка
sudo bash install.sh --rkn-sync-panel   # перечитать IPv4 панели из config.json
sudo bash install.sh --rkn-disable     # отключить только нашу фильтрацию
systemctl list-timers --all | grep vkarmani-rkn
```

Фильтр затрагивает **только новые входящие TCP/80 и TCP/443**, SSH и TCP/2222 не блокирует; IPv4 панели читается из `panel_ipv4` текущего состояния, а не жёстко вшит в скрипт. При ошибке получения списка сохраняется last-known-good; при сбое подготовки должен сохраняться доступ (fail-open узкой функции).

**Важно:** основной UFW ACL порта 2222 существует **отдельно** от исключений RKN. Если внешний адрес панели изменился, недостаточно обновить RKN: потребуется согласованно изменить UFW/провайдерский firewall по отдельной безопасной процедуре с backup и rollback. Блокировка трафика HTTP-01 на TCP/80 может помешать Certbot renew — проверяйте снаружи до и после включения фильтра. Подробности и инциденты: [docs/RKN_GUARD_2.5.3.md](docs/RKN_GUARD_2.5.3.md).

## 12. Обслуживание и диагностика

| Команда | Назначение | Побочные действия |
|---|---|---|
| `sudo bash install.sh --check` | базовый локальный acceptance | Только диагностика |
| `sudo vkarmani-node-check --require-xray` | Xray TCP/443 + внешний путь к Selfsteal | Только диагностика; требует live inbound |
| `sudo bash install.sh --diagnose-resources` | CPU/RAM/PSI/disk/conntrack/TCP | Только диагностика |
| `sudo bash install.sh --xray-versions [--offline]` | текущий Core / публичные релизы | Только чтение; network только без `--offline` |
| `sudo bash install.sh --prepare-xhttp` | создаёт root-only XHTTP-шаблон | Только файл-шаблон, **не** panel switch |
| `sudo bash install.sh --backup` | конфигурационный архив с SHA | Создаёт закрытый backup |
| `sudo bash install.sh --refresh-image` | транзакционное обновление RemnaNode Docker image | Остановка/пересоздание контейнера возможны |
| `sudo bash install.sh --rollback-image` | откат закреплённого image | Ограниченный rollback image/Compose |
| `sudo bash install.sh --update-cover` | обновление статического Selfsteal-сайта | Заменяет сайт с собственным rollback |
| `sudo bash install.sh --rollback-cover` | возвращает сайт | Не восстанавливает все данные VPS |
| `sudo bash install.sh --rkn-status` | информация о списке и исключениях | Только диагностика |
| `sudo bash install.sh --rkn-update` | загрузка и замена `ipset` | Изменяет правила фильтрации |
| `sudo bash install.sh --rkn-disable` | выключить управляемую фильтрацию | Изменяет узкие правила |

Дополнительно доступны **узкие legacy-режимы** `--repair-network`, `--repair-node` (завершённые 1.3.x) и `--repair-acceptance` (строго определённый незавершённый 2.5.0); **не используйте их как универсальный upgrade**. `--allow-net-admin` оставлен для совместимости; `NET_ADMIN` уже включён для RemnaNode по умолчанию в нашей схеме. При `network_mode: host` это увеличивает права контейнера по отношению к хосту.

Операционные команды без изменений:

```bash
sudo systemctl status nginx --no-pager
sudo nginx -t
sudo docker compose -f /opt/vkarmani-node/compose.yaml ps
sudo docker exec remnanode rw-core version
sudo ss -H -lntp
sudo ufw status numbered
sudo systemctl --failed --no-pager
sudo journalctl -u nginx -n 60 --no-pager
sudo journalctl -u vkarmani-node-postboot -n 80 --no-pager
sudo systemctl list-timers --all --no-pager
```

Не публикуйте вывод переменных окружения контейнера, `SECRET_KEY`, приватные REALITY-ключи или полные профили с ключами. Запросы `curl -k`, `wget --no-check-certificate`, `docker prune` в штатном продакшн-обслуживании не рекомендуются.

## 13. Расположение конфигурации и секретов

| Путь | Роль |
|---|---|
| `/etc/vkarmani-node/config.json` | публичный IPv4, домен, `panel_ipv4`, параметры; root-only |
| `/etc/vkarmani-node/remnanode.env` | **SECRET_KEY**, Node API; секрет |
| `/etc/vkarmani-node/reality.json` | X25519 private/public и ShortID; **секрет** |
| `/etc/vkarmani-node/profile.json` | **готовый RAW-шаблон**, содержит PrivateKey |
| `/etc/vkarmani-node/profile-xhttp.json` | **готовый XHTTP-шаблон**, содержит PrivateKey и путь |
| `/etc/vkarmani-node/PANEL-SETUP.txt` | локальная инструкция для оператора |
| `/root/reality-keys.txt` | приватный экспорт параметров REALITY |
| `/opt/vkarmani-node/compose.yaml` | официальный pinned RemnaNode image |
| `/run/vkarmani-selfsteal/nginx.sock` | Unix-сокет Nginx на хосте |
| `/dev/shm/nginx.sock` | доступный контейнеру read-only bind-путь |
| `/etc/nginx/conf.d/10-vkarmani-http.conf` | TCP/80 ACME и redirect |
| `/etc/nginx/conf.d/20-vkarmani-selfsteal.conf` | TLS+HTTP/2+PROXY v1 на Unix-сокете |
| `/var/www/vkarmani-node/` | статический cover + webroot ACME |
| `/etc/letsencrypt/` | сертификаты и закрытые TLS-ключи |
| `/var/lib/vkarmani-node/backups/` | конфигурационные backup |
| `/var/lib/vkarmani-node/image-transactions/` | состояние транзакций Docker image |
| `/usr/local/lib/vkarmani-node/` | проверочные и эксплуатационные helpers |
| `/var/log/vkarmani-node-install.log` | журнал установки; root-only |

Полная карта файлов, права, системы восстановления и требования redaction — [SECURITY.md](SECURITY.md), [docs/OPERATIONS.md](docs/OPERATIONS.md).

## 14. Полная приёмка, сбои и rollback

### Минимальная матрица реальной приёмки

| Шаг | Ожидаемое |
|---|---|
| A. Snapshot и SSH | есть console/recovery, второй SSH-login, backup проверен |
| B. OS/службы | `nginx -t`, Docker, systemd, UFW, IPv4-only / reboot политика без ошибок |
| C. Сертификат | ACME HTTP-01 по TCP/80, действительный TLS leaf и корректный renewal |
| D. Selfsteal | socket/PROXY v1/TLS1.3 HTTP1.1+H2; сайт по публичному Xray TCP/443 |
| E. Node API | TLS/локальный listener **и внешний** Panel → Node путь с нужным IPv4/ACL |
| F. RAW | полный импорт, один inbound, действующий клиент с Vision, real egress |
| G. XHTTP | Xray `run -test`, импорт, клиент без Vision и правильный `path`, real egress |
| H. Возврат | XHTTP → RAW → клиент/Host/Subscriptions/443/cover без отклонений |
| I. Защита | RKN timer/списки/исключения, никаких потерь SSH/Panel/ACME |
| J. Нагрузка | RAM/CPU/retransmits/conntrack/стабильность, мониторинг из нужных сетей |

### Типичные симптомы и первичная диагностика

| Симптом | Проверка |
|---|---|
| Node offline при работающем контейнере | правильный Panel `SECRET_KEY`, реальный source IPv4 панели, TCP/2222 ACL у хостера/UFW, TLS/API сертификат |
| Xray не слушает 443 | корректный inbound из панели, ошибки Core, docker logs, конфликт слушателя |
| Selfsteal проходит локально, но снаружи 443 отказ | корректный `target=/dev/shm/nginx.sock`, `xver=1`, SNI/REALITY, host TCP/443 |
| RAW работает, XHTTP нет | `flow` на всех уровнях, `xhttpSettings.host/path/mode`, актуальный клиент, supported `rw-core` |
| После XHTTP→RAW нет клиентов | восстановить исходный Profile, тег и привязки Hosts, обновить подписки, проверить Core restart |
| Списки RKN устарели | `--rkn-status`, доступность upstream, timer, логи; не удалять старый last-known-good |
| Certbot renew отказал | DNS-only, публичный HTTP/80, UFW/RKN/провайдер/ACME path, Certbot logs |
| Зависают сайты/скачивания | CPU/RAM, MTU/PMTUD, DNS, conntrack, RTT/потери, используемый client-core |
| Сбой image update | transaction state `PENDING/UNKNOWN`, pinned digest, предыдущий image; **не удалять markers** |

### Порядок безопасного отката

1. Сохраните логи/статус **без секретов**, не очищая транзакционные markers.
2. Если сломалась только смена транспорта — восстановите **сохранённый Panel Config Profile/Host**, верните RAW и проверьте Node/client. Перезагрузка VPS не нужна.
3. Если отказ вызван обновлением Docker-образа — выполните **предусмотренный** `--rollback-image`, только когда состояние транзакции однозначно.
4. Если отказ сайта — используйте `--rollback-cover`; он не восстанавливает Node/OS.
5. Если потеряны SSH/UFW/сеть или повреждена система — консоль провайдера и заранее проверенный provider snapshot. Локальные механизмы не обещают полного отката.

**Межверсионное resume:** незавершённую первичную установку продолжайте **тем же установщиком того же поколения**, за исключением документированных узких repair-вариантов. Нельзя слепо менять `/var/lib/.../install-version` или `INSTALL_COMPLETE` для «починки» чужой ошибки.

## 15. Тестирование, ограничения, исходники

Для **offline**-тестов исходного архива (без установки ноды на машину с тестами):

```bash
bash -n install.sh
bash tests/run.sh
sha256sum --check SHA256SUMS
```

Тесты содержат моки Docker, UFW, ошибки сети/прав, TLS/H2/PROXY, idempotence, обновление/откат и валидаторы профилей. **Реальные серверные эффекты и доступность из РФ не подтверждаются offline-тестами.** Прежде чем считать версию production-verified, нужно выполнить отдельный пилот Ubuntu 24.04 и в дальнейшем других OS/arch, матрицу клиентов, Panel→Node и долгосрочное наблюдение.

### Ссылки и источники

- [Remnawave Node](https://github.com/remnawave/node), [документация Node](https://docs.rw/install/remnawave-node/), [список Nodes/Profiles](https://docs.rw/learn-en/nodes/).
- [Xray Core](https://github.com/XTLS/Xray-core), [XHTTP](https://github.com/XTLS/Xray-core/discussions/4113), [XHTTP+REALITY reference](https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP-Reality/minimal-steal_others).
- [RemnaNode CoreLoaderService](https://github.com/remnawave/node/blob/main/src/modules/xray-core/core-loader.service.ts) — официальный механизм `geodata.core` с HTTPS+SHA256.
- [Flecksis/rkn-guard](https://github.com/Flecksis/rkn-guard), [источник списков](https://github.com/shadow-netlab/traffic-guard-lists).

**Документы проекта:** [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md) · [docs/OPERATIONS.md](docs/OPERATIONS.md) · [docs/TEST_REPORT.md](docs/TEST_REPORT.md) · [docs/TRANSPORT_SWITCHING_2.5.4.md](docs/TRANSPORT_SWITCHING_2.5.4.md) · [docs/RKN_GUARD_2.5.3.md](docs/RKN_GUARD_2.5.3.md) · [docs/XRAY_CORE_UPDATES_2.5.5.md](docs/XRAY_CORE_UPDATES_2.5.5.md) · [docs/history/README_2.5.4.md](docs/history/README_2.5.4.md) — **полная прежняя README сохранена без сокращений**.

**Публичная поставка:** новая версия не загружалась в GitHub и не развёртывалась на VPS. При будущей публикации сначала должен совпасть manifest и CI; **только тогда** допустима команда загрузки с `main` с независимым закреплённым SHA. На сервере всегда храните отдельный snapshot, working Profile и plan rollback.
