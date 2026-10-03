# 🚀 VKarmani Node Install 2.4.2


> **2.4.2: исправлен CI-контракт fragmented TLS / PROXY v1 без изменения production transport.** После публикации 2.4.1 все три GitHub Actions runner-а (Ubuntu 22.04, 24.04 и Ubuntu 26 userspace) одинаково выявили ошибку только в `test_large_fragmented_clienthello_and_proxy_header`: тест искусственно разрезал саму строку PROXY v1 по 7 байт. Nginx при чтении неполной строки корректно закрывает соединение как `broken header`, поэтому результат зависел от того, успеет ли локальный UNIX-stream склеить куски до первого чтения. В 2.4.2 PROXY v1 header отправляется тестом целиком, затем делается короткая пауза, а **большой TLS ClientHello по-прежнему принудительно фрагментируется** по 37 байт с паузами между чанками. Это делает проверку детерминированной и соответствует фактической Xray fallback-логике: Xray формирует PROXY v1 в отдельном буфере и записывает его до копирования fallback payload. `install.sh` production transport, Nginx config, NET_ADMIN, firewall, SSH, сертификатный deploy и runtime dependencies не менялись.
>

> **2.4.1: стабилизирована проверка активации сертификата после graceful reload Nginx.** GitHub Actions на Ubuntu 24.04 выявил гонку: одного успешного `--target-only` probe недостаточно, пока старый worker ещё может кратковременно перекрываться с новым. Deploy-hook теперь требует **4 последовательных успешных TLS-проверки** нового leaf-сертификата; любая промежуточная неудача сбрасывает серию. Это не ослабление проверки и не `sleep`-костыль: подтверждение стало строже. Интеграционный cleanup также ждёт устойчивого возврата исходного сертификата, чтобы тесты не загрязняли друг друга. Production transport, NET_ADMIN, Docker/Nginx layout, firewall и SSH policy не менялись.
>
> **2.4.0: `NET_ADMIN` включён по умолчанию для RemnaNode.** Это необходимо для функций, которым нужен доступ к сетевому состоянию хоста, включая используемый в панели «Обозреватель сессий». В генерируемом Compose теперь всегда есть `cap_add: [NET_ADMIN]`; состояние `allow_net_admin=true` сохраняется в конфигурации, а локальный checker требует совпадения state и фактической capability. `NET_RAW` по-прежнему сброшен, `no-new-privileges` и read-only Selfsteal mount сохранены. Изменение повышает blast radius контейнера при `network_mode: host`, поэтому оно отдельно задокументировано в [NET_ADMIN_2.4.0](docs/NET_ADMIN_2.4.0.md). Остальные контракты 2.3.0 — password-only SSH, Selfsteal/TLS checks, Vision, IPv4-only и ровно три поля — сохранены.
>
> GitHub этой поставкой не изменён. Команда загрузки из `main` ниже намеренно остановится по SHA256, пока проверенный `install.sh` 2.4.2 не опубликован. Для локальной проверки используйте файл из полного архива. Архив выпуска не содержит `.git`: при обновлении clone сохраняйте свою Git-историю; исторические актуальные документы 2.3.0, 2.4.0 и 2.4.1 сохранены в `docs/history`; исходный архив 2.4.1 не изменяется.

Production-установщик выделенной Remnawave-ноды: **VLESS + RAW + REALITY + Vision**, Selfsteal через **Nginx на хосте**, IPv4-only, UFW, Fail2ban, Docker Compose, Let's Encrypt, BBR/fq при поддержке ядром, диагностика, backup и контролируемое обновление образа.

> **Запускать только на отдельной чистой VPS-нode, не на сервере Remnawave-панели или БД.**
> До установки сделайте snapshot VPS, проверьте консоль/recovery хостера и убедитесь, что действующий пароль администратора действительно работает. Установщик меняет SSH, UFW, системные параметры и GRUB. После успешных локальных preboot-проверок `2.4.2` по умолчанию планирует **одну автоматическую перезагрузку через 30 секунд**. Для запрета используйте `--no-reboot`.

---

## ⚡ Установка

### Рекомендуемый запуск с GitHub

Блок ниже сначала скачивает **весь `install.sh`**, проверяет SHA256 именно выпуска `2.4.2`, затем Bash-синтаксис и номер версии — и только после этого запускает установку. Живой поток `curl | bash` не используется.

```bash
sudo bash <<'INSTALL'
set -Eeuo pipefail
set +x
umask 077
command -v curl >/dev/null || { echo 'Нужен curl; другой вариант — install.sh из полного архива.' >&2; exit 1; }
work=$(mktemp -d /root/vkarmani-install.XXXXXXXX)
cd "$work"
curl --fail --show-error --silent --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 180 --retry 3 \
  'https://raw.githubusercontent.com/SUXARIK-GITHUB/Node_Install/main/install.sh' \
  --output install.sh
if ! printf '%s  install.sh\n' \
  'f82ee13fa48771e0493ecbabbe4b264a544e7c0e302d7b57accf2dd4e58573a5' \
  | sha256sum --check; then
    echo 'STOP: файл GitHub не совпадает с выпуском 2.4.2. Не запускаю; нужен новый install.sh в main либо файл из архива 2.4.2.' >&2
    exit 1
fi
bash -n install.sh
[[ $(bash install.sh --version) == 2.4.2 ]] || { echo 'STOP: неверная версия установщика.' >&2; exit 1; }
exec bash install.sh
INSTALL
```

Если в ветке `main` опубликован другой файл, проверка SHA256 должна остановить запуск. **Не заменяйте ожидаемый хеш на хеш случайно скачанного файла только ради прохождения проверки.** Контрольная сумма подтверждает соответствие файла этому README, но не заменяет доверие к источнику самого README.

Репозиторий: [SUXARIK-GITHUB/Node_Install](https://github.com/SUXARIK-GITHUB/Node_Install) · прямой файл: [install.sh](https://raw.githubusercontent.com/SUXARIK-GITHUB/Node_Install/main/install.sh)

### Установка из полного архива

Распакуйте release в отдельную папку, перейдите в `Node_Install`, проверьте manifest и только затем запускайте:

```bash
sha256sum --check SHA256SUMS
bash -n install.sh
sudo bash install.sh
```

На первой чистой установке задаются **ровно три значения, именно в таком порядке**:

1. `SECRET_KEY` RemnaNode из вашей Remnawave-панели;
2. домен ноды, например `node.example.com`;
3. публичный **исходящий IPv4 backend панели**, с которого панель подключается к Node API.

IPv4 самой ноды установщик **не спрашивает**. Он проверяет DNS и выбирает тот публичный IPv4, который одновременно указан в A-записи домена и реально назначен интерфейсу VPS.

После успешной preboot-приёмки `2.4.2`:

- сохраняет ту же рабочую REALITY-пару и ShortID в `/root/reality-keys.txt` с правами `root:0600`;
- выводит в терминал `PrivateKey`, `PublicKey` и `ShortID`;
- не дублирует `PrivateKey` в `/var/log/vkarmani-node-install.log`;
- создаёт `INSTALL_COMPLETE` только после успешных локальных проверок;
- по умолчанию ставит одноразовый reboot через transient systemd unit с задержкой 30 секунд.

Если перед reboot нужно вручную проверить новую SSH-сессию:

```bash
sudo bash install.sh --no-reboot
```

Не закрывая старую SSH-сессию, откройте **новую** парольную сессию, убедитесь, что доступ работает, после чего выполните:

```bash
sudo reboot
```

---

## 🧩 Что сделать в Remnawave после установки

Установщик намеренно **не авторизуется в административном API панели** и не создаёт объекты Panel/Node/Profile/Host/Squad. Введённый `SECRET_KEY` — это не администраторский API-token панели.

Готовая инструкция конкретной ноды создаётся здесь:

```bash
sudo cat /etc/vkarmani-node/PANEL-SETUP.txt
```

Сгенерированный профиль находится здесь:

```text
/etc/vkarmani-node/profile.json
```

> `profile.json` содержит **приватный REALITY-ключ**. Это секретный файл. Не отправляйте его в публичный issue, чат, screenshot или лог.

### Правильный порядок в панели

Для принятой в проекте схемы **одна нода → один профиль → один отдельный inbound**:

1. **Config Profiles** — создайте профиль этой ноды и вставьте её JSON.
2. **Node / Management** — `Address` = домен ноды либо другой публичный IPv4, реально назначенный этой же VPS; `Node Port = 2222`; выберите профиль и его inbound.
3. **Host** — выберите тот же inbound; `Address` = домен ноды; `Port = 443`. Advanced Options лучше оставить **DEFAULT**, если нет конкретной причины для override. SNI в нормальной схеме наследуется из REALITY inbound.
4. **Internal Squads** — разрешите новый inbound нужной группе пользователей. Если этот шаг забыть, Node может быть online, но пользователи не получат новый Host в подписке.
5. Обновите подписку в клиенте и проверьте реальное подключение извне.

Если для dedicated Host используете поле `Nodes`, выбирайте **только соответствующую ноду**. Не добавляйте вручную SNI/ALPN/Security Layer/MUX/SockOpt без необходимости: Host override может заменить корректное значение, уже заданное в inbound.

### Пример JSON для Remnawave без реальных секретов

Ниже безопасный шаблон. Он не содержит боевых ключей. Заменяйте только явные placeholders данными, сгенерированными **на этой же ноде**. Не переносите PrivateKey/ShortID одного сервера на другой, если используете per-node профили.

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
      "tag": "VK_RAW_REALITY_NODE_EXAMPLE",
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
          "privateKey": "REPLACE_WITH_PRIVATE_KEY_FROM_THIS_NODE",
          "shortIds": [
            "REPLACE_WITH_SHORT_ID_FROM_THIS_NODE"
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
          "NODE_PUBLIC_IPV4/32",
          "PANEL_BACKEND_IPV4/32",
          "::/0"
        ],
        "outboundTag": "BLOCK"
      }
    ]
  }
}
```

Этот пример сохраняет архитектурную политику локального шаблона `2.3.0`: **VLESS + RAW + REALITY + Vision**, собственный домен в `serverNames`, Selfsteal `target=/dev/shm/nginx.sock`, `xver=1`, без VLESS fallbacks, плюс блокировка private/special диапазонов и адресов ноды/панели от проксируемого outbound-доступа.

#### Единая политика minClientVer в 2.3.0

Генератор, локальный validator, `PANEL-SETUP.txt` и export ключей используют **одну константу**:

```json
"minClientVer": "0.0.0"
```

Это устраняет расхождение выпуска 2.1.2 с выбранной оператором политикой live-профилей. Значение снимает нижний version-gate, но не добавляет старому клиенту отсутствующую поддержку REALITY/RAW/Vision. Отсутствующее поле, число `0`, строка `"0"` и `"1.0.0"` не проходят новую локальную policy.

Новый checker не пропускает `profile-check` для 2.1.2/2.1.3/2.2.0/2.3.0/2.4.0/2.4.1/2.4.2. Неизвестная версия отмечается FAIL; историческая версия/отсутствие marker — явным NOT_VERIFIED, без выдуманной проверки.

`profile-check` теперь дополнительно проверяет форму DNS-полей, `UseIPv4`, ссылки routing/outbounds и запрещает ожидание входящего PROXY protocol на прямом RAW/REALITY listener. Допускается один служебный локальный API inbound RemnaNode с корректным `api.tag` и первым API routing-rule. Это не разрешение на второй VPN-протокол.

**Проверка supplied JSON не делает сетевых запросов и не читает core memory.** Корректный общий `settings.flow` с пустыми пользовательскими `flow` допускается без изменения файла. Полный security-аудит конечных TCP/UDP назначений и `xray run -test` не подменяются строкой PASS.

**Начиная с 2.3.0 новый generated template содержит `settings.flow="xtls-rprx-vision"`.** Это согласует его с выбранной RAW/REALITY/Vision-схемой. Пустые `clients[].flow` допустимы при общем flow. Рабочий профиль панели автоматически не меняется, массив пользователей не переписывается. Перед импортом нового шаблона нужен отдельный клиентский тест и сохранённые назначения Profile/Host/Squad.

**DNS/routing генератора оставлены как в 2.1.2** (`DIRECT`/`BLOCK`, `IPOnDemand`, явные закрытые диапазоны и IP ноды/панели); это не копия действующих custom live-профилей `internet`/`block`/`AsIs`. Блок всего IP панели также блокирует пользовательские сервисы на том же IP через этот outbound. Не импортируйте шаблон поверх работающего custom-профиля без отдельной проверки нужного доступа. В 2.3.0 политика выхода не расширялась и `finalRules` не добавлялись.

### Проверка после назначения профиля

На VPS:

```bash
sudo vkarmani-node-check --require-xray
```

После этого отдельно проверьте:

- Node online в Remnawave;
- правильные Profile/inbound у Node;
- правильный Host/inbound;
- наличие inbound в Internal Squad;
- обновлённую подписку клиента;
- реальный VPN-клиент из внешней сети;
- обычный `https://node.example.com` — должна открываться локальная Selfsteal-страница.

Локальный `PASS` **не доказывает** panel mTLS, назначение Host/Squad или пользовательский VPN-трафик.

---

## 🗺️ Как устроена нода

```text
Интернет / IPv4
    ├── SSH на сохранённых портах → sshd (только пароль) + Fail2ban
    ├── TCP/80 → host Nginx → HTTP-01 ACME / HTTPS redirect
    └── TCP/443 → Xray внутри RemnaNode (network_mode: host)
                     ├── аутентифицированный VLESS/RAW/Vision → routing/outbound
                     └── HTTPS / Selfsteal → target=/dev/shm/nginx.sock, xver=1
                                               │ read-only bind отдельного каталога
                                               ▼
                                  /run/vkarmani-selfsteal/nginx.sock
                                               │
                                    host Nginx / свой TLS / статический сайт

Публичный egress IPv4 backend панели → UFW source allowlist → rw-node TCP/2222

TLS-target требуется для установления REALITY; Nginx не является HTTP-прокси
всего аутентифицированного пользовательского VPN-трафика.
```

Ключевые границы:

- **Публичный TCP/443 принадлежит Xray.** Host Nginx не должен конкурировать за этот порт.
- Nginx обслуживает Selfsteal через Unix socket, а не через публичный `443`.
- RemnaNode работает в `network_mode: host`; Docker `ports:` для него не используются.
- В контейнер read-only монтируется только отдельный каталог Selfsteal socket; приватные ключи Let's Encrypt в Xray-контейнер не монтируются.
- `NET_ADMIN` по умолчанию выдаётся RemnaNode для функций управления/наблюдения сетевых соединений, включая «Обозреватель сессий»; `NET_RAW` остаётся сброшен, `no-new-privileges` включён.
- `2222` — управляющий API ноды, **не клиентский порт**.
- Наличие listener на `2222` не доказывает, что панель успешно прошла mTLS.

---

## 🔑 Три значения и откуда их брать

| Вопрос установщика | Что вводить | Что не вводить |
|---|---|---|
| `SECRET_KEY` | Полный `SECRET_KEY` RemnaNode, выданный вашей панелью | API-token панели, SSH-пароль, случайный ключ, секрет другой панели |
| Домен ноды | Например `node.example.com`; одна публичная A-запись на IPv4 этой VPS | `https://...`, путь, порт, домен панели, проксируемую CDN-запись |
| IPv4 технички | Публичный **egress IPv4 backend панели**, с которого backend идёт на Node API | домашний IP администратора, Cloudflare IP, Docker private IP, IPv4 самой ноды |

Ввод `SECRET_KEY` скрыт. Установщик проверяет структуру секрета/сертификатов, не печатая сам секрет.

На multi-IP VPS A-запись может указывать на любой публичный IPv4, реально назначенный серверу; он не обязан быть default-source адресом. Management Address ноды в Remnawave при необходимости тоже может использовать другой локальный публичный IPv4, тогда как клиентский Host/SNI остаётся доменом ноды.

---

## ✅ Требования к VPS и DNS

| Область | Требование |
|---|---|
| ОС | Чистая Ubuntu `22.04`, `24.04`, `26.04` или Debian `12`, `13` |
| Ubuntu 26.04 | Адаптация реализована, но перед массовым rollout нужна отдельная полная VPS-приёмка |
| Архитектура | `amd64` или `arm64` |
| Виртуализация | Полноценная VM/выделенный сервер с управляемым ядром; не LXC/OpenVZ/Docker |
| Загрузка | systemd + GRUB, `update-grub`, `/boot/grub/grub.cfg`, `/etc/default/grub` |
| RAM | >= 900 MiB; для Ubuntu 26.04 >= 1536 MiB; это порог допуска, не оценка пользовательской ёмкости |
| Диск | >= 6 GiB свободно перед установкой; для образов/backups нужен дополнительный запас |
| Сеть | Прямой публичный IPv4 назначен интерфейсу; NAT-only и IPv6-only ноды не поддерживаются |
| DNS | Ровно одна A-запись на локальный публичный IPv4; AAAA отсутствует; домен ноды — DNS-only, не CDN/proxy |
| SSH | Существующая IPv4 SSH-сессия и рабочий локальный пароль root/sudo-пользователя |
| Recovery | Проверенная console/recovery хостера + snapshot до изменений |
| Чистота сервера | Нет чужих контейнеров, web/firewall stack или конфликтующих Docker-пакетов без отдельного аудита |

При неподдерживаемом или неоднозначном состоянии установщик должен остановиться, а не делать `ufw reset`, переписывать netplan/маршруты, переустанавливать загрузчик или удалять чужие пакеты «чтобы продолжить».

### Порты

| Порт | Назначение | Источник | Назначение |
|---|---|---|---|
| существующие SSH TCP-порты | администрирование | любой IPv4, кроме временных Fail2ban-банов | SSH listeners VPS |
| `80/tcp` | Let's Encrypt HTTP-01 + redirect | любой IPv4 | выбранный IPv4 домена ноды |
| `443/tcp` | VLESS RAW REALITY / Selfsteal | любой IPv4 | выбранный IPv4 домена ноды |
| `2222/tcp` | RemnaNode management API | только заданный backend IPv4 панели | локальные публичные IPv4 ноды |

UFW по умолчанию запрещает входящий/маршрутизируемый трафик и разрешает исходящий. Provider security groups, upstream ACL, anti-DDoS, DNS и Cloudflare находятся **вне управления установщика**.

---

## ⚙️ Что установщик делает по порядку

| Этап | Что происходит | Защитная логика |
|---|---|---|
| Preflight | ОС, arch, GRUB, RAM/disk, systemd, dpkg, SSH, чужое состояние | STOP до опасных изменений на неподдерживаемой системе |
| Три значения | SECRET_KEY, домен, backend IPv4 | скрытый ввод секрета; Node IPv4 не спрашивается |
| Первичный backup | сохраняются важные исходные конфиги | закрытый каталог + SHA256 manifest; это не полный snapshot VPS |
| Базовые пакеты | необходимые подписанные APT-пакеты | без full-upgrade и без autoremove |
| APT coordination | ожидание штатных `apt/dpkg/unattended-upgrades` locks | lock-файлы не удаляются, пакетные процессы не убиваются |
| DNS/SECRET | проверка домена/секрета и выбор Node IPv4 | NAT/чужой/неоднозначный IPv4 не угадывается |
| Время | сохраняется поддерживаемый timesyncd/Chrony | установленный time-daemon не удаляется только ради замены другим |
| Ядро/сеть | консервативные sysctl, BBR/fq при поддержке, MTU probing | MTU/routes/netplan не переписываются; fallback явно виден |
| IPv6 | runtime disable + GRUB `ipv6.disable=1` | полная проверка socket-level только после reboot |
| SSH/UFW | password-only SSH, key login off, сохранение портов, API allowlist | backup фазы + временный rollback guard + `sshd` validation |
| Fail2ban | баны только по SSH | нет постоянного SSH allowlist панели/администратора |
| Docker | официальный repo, Engine, Compose | проверка signing-key fingerprint и daemon config |
| Nginx/ACME | host Nginx, socket, сертификат, renewal | `nginx -t` → reload → TLS-only проверка; dry-run с deploy hook и новым receipt; полная проверка сайта отдельно |
| RemnaNode | официальный image, host network, restart policy | после pull image закрепляется точным digest |
| REALITY | постоянная X25519-пара + ShortID + RAW/REALITY profile | пара валидируется; при resume ключи не генерируются заново |
| Завершение | helpers, panel guide, postboot, export ключей | `INSTALL_COMPLETE` только после local acceptance; reboot ставится последним |

### SSH

**2.3.0 отключает вход по SSH-ключам** и оставляет только метод `password`: `PasswordAuthentication yes`, `PubkeyAuthentication no`, `AuthenticationMethods password`, `KbdInteractiveAuthentication no`, `HostbasedAuthentication no`, `GSSAPIAuthentication no`, `PermitEmptyPasswords no`. Порты сохраняются; постоянного source-IP allowlist нет.

Пароль администратора уже должен работать **до запуска**. Установщик не спрашивает его четвёртым полем, не меняет пароль/аккаунт, не разблокирует root и не удаляет `authorized_keys`. Проверяется локальная запись пароля, её срок и login shell; `Match`, ограничения пользователей и нестандартные Include требуют ручного аудита. Проверки `sshd -t/-T` не являются реальным входом: после установки с `--no-reboot` откройте вторую парольную сессию, не закрывая первую. Для TECH политика SSH не меняется — этот установщик туда не предназначен.

Это сознательный компромисс. Нужен длинный уникальный случайный пароль и доступ к console/recovery. Fail2ban снижает риск bruteforce, но не делает слабый/повторно используемый пароль безопасным.

### Сеть, BBR и MTU

Запрашиваются BBR + fq, но установка проверяет фактически принятые sysctl. Если ядро не поддерживает нужный режим, рабочий fallback сохраняется и диагностируется, а не выдаётся за BBR.

Установщик **не** уменьшает MTU «на всякий случай», не переписывает routes/netplan, не меняет NIC offloads, не ставит сторонний kernel/«BBR plus». `net.ipv4.tcp_mtu_probing=1` используется для TCP black-hole recovery вместо универсального hardcoded MTU.

### Синхронизация времени

Уже установленный поддерживаемый `systemd-timesyncd` или Chrony сохраняется. Установщик не удаляет timesyncd только потому, что раньше в списке пакетов был Chrony. Состояние `active` само по себе недостаточно — должна подтверждаться реальная синхронизация.

### APT/dpkg locks

На свежем образе `unattended-upgrades` часто уже держит package-manager locks. Установщик ждёт настоящих владельцев lock в пределах bounded deadline и показывает прогресс. Он **не** удаляет `/var/lib/dpkg/lock*`, не убивает `apt/dpkg/unattended-upgrade` и не отключает security updates ради скорости.

---

## 🛠️ Полезные команды

### Основная приёмка

```bash
# Обычная локальная проверка после reboot:
sudo vkarmani-node-check

# До первого reboot, когда GRUB-параметр IPv6 ещё не активен:
sudo vkarmani-node-check --preboot

# Требовать Xray TCP/443 + ожидаемый Selfsteal через REALITY path:
sudo vkarmani-node-check --require-xray

# Не перепроверять внешний DNS, сохранив остальные локальные проверки:
sudo vkarmani-node-check --local

# Отдельно management API TLS и Selfsteal:
sudo vkarmani-node-tls-check
sudo vkarmani-selfsteal-check --target-only
sudo vkarmani-selfsteal-check
```

Коды диагностики: `0` — запрошенные локальные условия выполнены; `1` — локальная ошибка; `2` — неверные аргументы либо strict Xray/Selfsteal ещё не подтверждён. Код `0` **не означает**, что панель авторизовалась и пользовательский VPN уже работает.

### Сервисы и listeners

```bash
sudo systemctl --failed --no-pager
sudo systemctl status docker containerd nginx fail2ban systemd-timesyncd --no-pager
sudo systemctl status vkarmani-node-postboot.service --no-pager
sudo systemctl list-timers --all --no-pager
sudo ss -4 -lntp
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}'
```

Если выбран Chrony, не предполагайте наличие `systemd-timesyncd`:

```bash
sudo cat /etc/vkarmani-node/time-provider
sudo systemctl status chrony.service --no-pager
```

### Firewall и SSH

```bash
sudo ufw status verbose
sudo ufw status numbered
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | grep -E '^(port|addressfamily|passwordauthentication|permitrootlogin|pubkeyauthentication|authenticationmethods) '
sudo fail2ban-client ping
sudo fail2ban-client status sshd
```

Снять только подтверждённый ошибочный SSH-бан можно точечно:

```bash
# sudo fail2ban-client set sshd unbanip A.B.C.D
```

Не отключайте UFW и не открывайте `2222/tcp` всему Интернету как «временную диагностику».

### Логи

```bash
sudo tail -n 120 /var/log/vkarmani-node-install.log
sudo tail -n 120 /var/log/vkarmani-node-postboot.log
sudo journalctl -u nginx.service -n 100 --no-pager
sudo journalctl -u docker.service -n 100 --no-pager
sudo journalctl -u fail2ban.service -n 100 --no-pager
```

Логи могут содержать IP/имена пользователей. Перед публикацией редактируйте персональные данные. Финальный PrivateKey-блок специально не пишется в общий install log.

### Nginx / сертификат / Selfsteal

```bash
sudo nginx -t
sudo test -S /run/vkarmani-selfsteal/nginx.sock
sudo docker exec remnanode test -S /dev/shm/nginx.sock
sudo vkarmani-selfsteal-check --target-only
sudo vkarmani-selfsteal-check
```

Отдельная активная ACME-проверка, только в согласованном окне: обращается к staging CA, может запускать hooks и выполнять временные действия. Это **не read-only** сборщик.

```bash
sudo certbot renew --dry-run --non-interactive
```

### Backup и image maintenance

```bash
# Закрытый configuration backup + checksums:
sudo vkarmani-node-maintain backup

# Явное обновление образа в maintenance window:
sudo vkarmani-node-maintain refresh-image

# Возврат предыдущего pinned image, если transaction state это допускает:
sudo vkarmani-node-maintain rollback-image
```

Эквивалентные entry points через проверенный `install.sh`:

```bash
sudo bash install.sh --backup
sudo bash install.sh --refresh-image
sudo bash install.sh --rollback-image
```

Не используйте Docker prune в штатном обслуживании: предыдущий image может понадобиться для rollback.

### Только cover-site

```bash
# Обновить только статическую Selfsteal-страницу:
sudo bash install.sh --update-cover

# Вернуть только страницу из сохранённой копии:
sudo bash install.sh --rollback-cover
```

Это не обновление всей ноды.

### Read-only срез ресурсов

```bash
sudo bash install.sh --diagnose-resources
sudo bash install.sh --diagnose-resources --seconds 5
```

### Версия и справка

```bash
bash install.sh --version
bash install.sh --help
```

### Флаги первой установки и специальные режимы

| Флаг / режим | Назначение | Важно |
|---|---|---|
| `--no-reboot` | отключить одноразовый reboot после успешной установки | удобно для ручной проверки второй SSH-сессии |
| `--reboot` | явно оставить auto-reboot включённым | совместимый explicit-флаг; это и так default `2.4.2` |
| `--weekly-reboot` | включить регулярный reboot по понедельникам в `04:00` МСК | по умолчанию выключен |
| `--allow-net-admin` | совместимый флаг старых команд | в `2.4.2` ничего дополнительно не включает: `NET_ADMIN` уже является default; риск host networking описан в SECURITY |
| `--image remnawave/node:TAG` или `@sha256:DIGEST` | задать допустимый официальный image для новой/незавершённой установки | это флаг, а не четвёртый вопрос |
| `--check` | вызвать установленную локальную диагностику | завершённая нода не переустанавливается |
| `--backup` | configuration backup | не заменяет provider snapshot |
| `--refresh-image` | обновить только RemnaNode image | без APT/SSH/UFW/Nginx/kernel reconfigure |
| `--rollback-image` | вернуть предыдущий image, если transaction state позволяет | не full VPS rollback |
| `--update-cover` | обновить только статический cover-site | поддерживается для завершённых reviewed project-owned версий вплоть до `2.4.2`; system fixes этим не ставятся |
| `--rollback-cover` | откатить только cover-site | не откатывает ноду/OS/image |
| `--diagnose-resources` | read-only срез CPU/RAM/PSI/swap/TCP/disk | не меняет sysctl/MTU/services |
| `--repair-network` | узкий legacy-repair для поддерживаемого завершённого `1.3.x` state | не миграция на `2.4.2` |
| `--repair-node` | узкий legacy-repair для поддерживаемого завершённого `1.3.x` state | не миграция на `2.4.2` |

### Повторный запуск и resume

- Незавершённую `2.4.2` продолжайте тем же `2.4.2`: сохранённые три значения, REALITY keys, `allow_net_admin=true` и выбранный image digest переиспользуются, а не генерируются заново.
- Незавершённую `2.1.0`/`2.1.1`/`2.1.2`/`2.1.3`/`2.2.0`/`2.3.0`/`2.4.0`/`2.4.1` не «превращайте» в `2.4.2` ручной заменой markers. Используйте исходный installer той же версии либо восстановите snapshot.
- На завершённой project-owned установке обычный повторный запуск не должен заново выполнять APT/UFW/SSH/ACME/image pull; он переходит к установленной диагностике.
- Cross-version resume по умолчанию запрещён. Историческое узкое исключение для конкретного раннего `2.0.2` package-stage описано отдельно в [docs/TIME_SYNC_FIX.md](docs/TIME_SYNC_FIX.md); не обобщайте его на другие состояния.

### Автозапуск и плановое обслуживание

- Контейнер RemnaNode использует Docker `restart: always`; отдельный wrapper не должен конкурировать с Docker как второй supervisor.
- Каталог Selfsteal socket восстанавливается через systemd-tmpfiles после boot.
- Сертификаты обслуживает `certbot.timer`; renewal должен сохранять доступный TCP/80 для HTTP-01.
- Cleanup ограничен APT-cache и старыми журналами; backups, volumes, images, containers и packages автоматически не prune-ятся.
- Weekly reboot не включён без `--weekly-reboot`.

---

## 🔄 Обновление image и rollback

Первая установка получает допустимый официальный RemnaNode image и записывает **точный digest** в Compose/state. Уже установленная нода не должна бесконтрольно следовать за moving `latest` при каждом restart.

`refresh-image` — отдельная maintenance-транзакция, а не повторная установка. Она не перенастраивает APT/SSH/UFW/Nginx/kernel. Перед apply проверяется локальное состояние, создаётся backup, сохраняются before/after Compose/digest и поддерживается rollback path, когда он однозначен.

Если Docker apply оборвался после того, как daemon мог уже принять запрос, состояние может стать `IMAGE_APPLY=UNKNOWN`. **Не удаляйте pending marker** и не запускайте встречные update/rollback вслепую. Сначала проверьте фактическое состояние Docker.

Rollback image не равен полному rollback VPS. Он не возвращает объекты/БД панели, пакеты ОС, уже потерянный writable layer контейнера, пользовательские сессии или provider firewall. Для whole-system rollback нужен проверенный snapshot хостера.

---

## 📂 Где что находится

| Путь | Назначение / чувствительность |
|---|---|
| `/etc/vkarmani-node/config.json` | проверенные параметры установки; внутренний файл |
| `/etc/vkarmani-node/remnanode.env` | **SECRET_KEY**, Node Port, timezone; секрет |
| `/etc/vkarmani-node/reality.json` | **REALITY PrivateKey**, PublicKey, ShortID; секрет из-за PrivateKey |
| `/etc/vkarmani-node/profile.json` | generated Remnawave/Xray template; **секрет**, содержит PrivateKey |
| `/etc/vkarmani-node/PANEL-SETUP.txt` | операторская инструкция с параметрами Node/Profile и публичными REALITY-данными |
| `/usr/local/lib/vkarmani-node/ssh_guard.py` | проверка парольного SSH, без изменения паролей |
| `/usr/local/lib/vkarmani-node/cert_deploy.py` | применение и проверка сертификата после Certbot |
| `/var/lib/vkarmani-node/cert-deploy-status.json` | root:0600; последняя фаза/result/fingerprint, не секреты |
| `/root/reality-keys.txt` | удобный export ключей; **секрет**, `root:0600` |
| `/etc/vkarmani-node/ssh-ports` | сохранённые SSH TCP-порты |
| `/etc/vkarmani-node/time-provider` | выбранный проверенный NTP-клиент |
| `/opt/vkarmani-node/compose.yaml` | управляемый Compose-проект с pinned image |
| `/run/vkarmani-selfsteal/nginx.sock` | Selfsteal socket на хосте |
| `/dev/shm/nginx.sock` | тот же endpoint внутри RemnaNode контейнера |
| `/var/www/vkarmani-node/` | статический local cover + ACME webroot |
| `/etc/nginx/conf.d/10-vkarmani-http.conf` | HTTP/80 ACME + redirect |
| `/etc/nginx/conf.d/20-vkarmani-selfsteal.conf` | TLS/PROXY-v1 на Unix socket |
| `/etc/letsencrypt/` | сертификаты/account data и **приватные TLS-ключи** |
| `/usr/local/sbin/vkarmani-*` | диагностика, maintenance и recovery helpers |
| `/var/lib/vkarmani-node/backups/` | закрытые configuration backups; автоматически не чистятся |
| `/var/lib/vkarmani-node/image-transactions/` | состояние image-транзакций |
| `/var/lib/vkarmani-node/network-effective.json` | реально принятые BBR/qdisc/fallback параметры |
| `/var/lib/vkarmani-node/INSTALL_COMPLETE` | завершение локальной установки, **не статус VPN** |
| `/var/log/vkarmani-node-install.log` | закрытый install log |
| `/var/log/vkarmani-node-postboot.log` | результаты postboot-проверки |

Секретные файлы не публикуйте. Полная политика redaction/incident response — в [SECURITY.md](SECURITY.md).

---

## 🧯 Быстрая карта диагностики

| Симптом | Сначала проверить | Чего нельзя заключать автоматически |
|---|---|---|
| installer STOP до APT | точный preflight message, ОС/GRUB/virtualization/чужое состояние | что конфликтующие файлы безопасно удалить |
| Node IPv4 не выбирается | A/AAAA, DNS-only, локальные public IPv4, NAT | что IP с внешнего «what is my IP» обязательно правильный |
| local TLS `2222` PASS, но Node offline | реальный backend egress IP, provider firewall/ACL, Node Address/Port, route | что local listener доказал panel mTLS |
| во время попытки панели на `2222` на интерфейсе `0 packets` | upstream/provider path либо panel-side route/source | что UFW/container уже успели отбросить пакет |
| Xray `443` не слушает | доставка live profile, Node connection, выбранный Profile/inbound, Xray errors | что host Nginx должен занять public 443 |
| Selfsteal socket PASS, public cover FAIL | REALITY `target`, `xver`, `serverNames`, live profile, Host/SNI overrides | что socket/Nginx обязательно сломан |
| пользователи не видят Host | Internal Squad, Host visibility, inbound assignment, subscription refresh | что Node online автоматически выдаёт доступ пользователю |
| новые клиенты работают, старые нет | `minClientVer`, поддержка REALITY/RAW старым core, fingerprint/flow | что `0.0.0` добавит отсутствующие функции древнему core |
| часть сайтов зависает | route/loss/PMTU/CPU/provider limits/client path | что всем VPS нужен один hardcoded MTU |
| image update оставил pending | transaction state, Docker daemon, previous image | что удаление marker = rollback |
| после reboot нет сети | provider console, GRUB/kernel log, provider routing | что preboot local PASS гарантировал внешний доступ |

Подробный регламент: [docs/OPERATIONS.md](docs/OPERATIONS.md) · сетевые/hosting-инциденты: [docs/HOSTING_AND_INCIDENTS.md](docs/HOSTING_AND_INCIDENTS.md)

---

## 🧪 Что проверено и что остаётся за оператором

В release-архиве `2.4.2` зафиксировано **556 regression/integration тестов**, локально пройденных от root и UID 1000 без пропусков. CI-инцидент 2.4.1 не скрыт: сохранены журналы всех трёх runner-ов и отдельное воспроизведение Nginx `broken header` для искусственно фрагментированного PROXY v1. Исправленный интеграционный тест отправляет PROXY header целиком и затем детерминированно фрагментирует большой TLS ClientHello. Preview/site rendering в 2.4.2 не менялись, поэтому новый browser-run не выполнялся; сохранён предыдущий evidence 2.3.0 — 36 PASS (четыре варианта × девять ширин). Это не тест через production REALITY. Проверяются встроенные payload установщика, password-only SSH и его отказы, фазы cert-deploy и реальный локальный Nginx reload, владелец TCP/443, FD/очереди, профиль и Selfsteal HTTP-policy, REALITY key export, отказ от unsafe symlink, terminal-only вывод PrivateKey, default auto-reboot/`--no-reboot`, APT-lock coordination и более ранние сценарии отказов сети/Nginx/SSH/image maintenance.

Запуск test suite без установки ноды:

```bash
bash tests/run.sh
```

В зависимости от тестов нужны Python 3.10+, `cryptography`, PyYAML, Nginx/OpenSSL, APT, Git и Node.js. В среде, где внешних инструментов нет, отдельные проверки могут быть явно отмечены как skip; release-validation выполнялась без пропусков.

Локальные тесты не могут доказать за ваш конкретный хостер:

- provider firewall/security-group и anti-DDoS;
- реальный panel→node маршрут и mTLS через Интернет;
- DNS/Cloudflare propagation вне VPS;
- поведение Host/Squad/subscription в вашей версии панели;
- реальный пользовательский VPN и throughput;
- ёмкость под вашу CPU/RAM/нагрузку/лимиты провайдера;
- полный Ubuntu 26.04 lifecycle без отдельного pilot;
- возможность whole-VPS restore из provider snapshot.

Production rollout должен оставаться последовательным:

```text
snapshot
  → одна canary-нода
  → установка
  → export REALITY keys
  → reboot
  → новый SSH login
  → vkarmani-node-check
  → Remnawave Profile / Node / Host / Internal Squad
  → vkarmani-node-check --require-xray
  → реальный внешний VPN-клиент
  → наблюдение под реальной нагрузкой
  → следующая страна / провайдер
```

---

## 📚 Документация проекта

- [docs/SELFSTEAL_2.2.0.md](docs/SELFSTEAL_2.2.0.md) — точный объём новой серверной части и границы приёмки.
- [docs/SOURCE_REVIEW_2.2.0.md](docs/SOURCE_REVIEW_2.2.0.md) — Selfsteal / iptables / HAProxy / Nginx, источники и решения.
- [preview/README.md](preview/README.md) — четыре локальных HTML-preview и браузерные изображения.

- [SECURITY.md](SECURITY.md) — trust boundaries, секреты, firewall/container security, supply chain и incident response.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — эксплуатация, диагностика, backup, maintenance и recovery.
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — точная матрица тестов и ограничения.
- [docs/REALITY_KEYS_AUTOREBOOT_2.1.2.md](docs/REALITY_KEYS_AUTOREBOOT_2.1.2.md) — export REALITY keys и auto-reboot.
- [docs/APT_LOCK_COORDINATION_2.1.1.md](docs/APT_LOCK_COORDINATION_2.1.1.md) — безопасное ожидание dpkg/APT locks.
- [docs/COVER_SITE.md](docs/COVER_SITE.md) — обновление/rollback cover-site.
- [docs/HOSTING_AND_INCIDENTS.md](docs/HOSTING_AND_INCIDENTS.md) — provider restrictions и reachability diagnostics.
- [docs/UBUNTU_26_04.md](docs/UBUNTU_26_04.md) — статус Ubuntu 26.04 и pilot plan.
- [docs/TIME_SYNC_FIX.md](docs/TIME_SYNC_FIX.md) — timesyncd/Chrony и границы resume.
- [docs/UFW_PREFLIGHT_FIX.md](docs/UFW_PREFLIGHT_FIX.md) — почему preflight UFW намеренно строгий.
- [docs/FAILURE_AUDIT.md](docs/FAILURE_AUDIT.md) — сценарии отказов и остаточные риски.
- [docs/AUDIT.md](docs/AUDIT.md) — технический аудит и границы архитектуры.
- [docs/RESEARCH.md](docs/RESEARCH.md) — основания технических решений.
- [CHANGELOG.md](CHANGELOG.md) — история версий.

---

## 🔐 Коротко: чего не делать

- Не запускать installer на панели/БД.
- Не отключать checksum/preflight/lock guards ради «быстрее поставить».
- Не открывать `2222/tcp` всему Интернету.
- Не публиковать `SECRET_KEY`, REALITY PrivateKey, `profile.json`, `reality.json`, `/root/reality-keys.txt`, Let's Encrypt private keys и backups.
- Не переиспользовать один REALITY PrivateKey/ShortID на разных per-node профилях без осознанного решения.
- Не закрывать старую SSH-сессию до проверки новой либо provider console.
- Не считать local PASS доказательством panel connectivity или пользовательского VPN.
- Не считать image rollback заменой provider snapshot.
- Не раскатывать новый OS/provider/image массово до полного canary-цикла.
