# 🔐 Безопасность VKarmani Node Install 2.1.3

Этот файл описывает security-модель **установщика ноды**, а не всей Remnawave-инфраструктуры. Installer работает с root-правами на выделенной VPS и намеренно меняет SSH, UFW, GRUB, sysctl, Nginx, Docker и systemd. Безопасность зависит и от встроенных guard-проверок, и от внешних компонентов, которые установщик не контролирует: хостер, панель, DNS, Cloudflare, рабочая станция администратора и клиентские устройства.

> **Базовое условие:** отдельная чистая VPS-нода, snapshot, независимая console/recovery хостера, проверенный пароль администратора, доверенный release-файл/контрольная сумма и одна canary-нода до массовой раскатки.

---

## 1. Модель доверия и границы

```text
Устройство администратора
          │ SSH / пароль / terminal
          ▼
Выделенная VPS ноды
          ├── host OS / root / systemd / UFW / Fail2ban
          ├── host Nginx + private key Let's Encrypt
          ├── Docker daemon
          └── RemnaNode container (host networking)
                  │
                  ├── management API :2222  ◄── Remnawave backend / mTLS
                  └── Xray public :443      ◄── REALITY-клиенты

Внешние зоны, не управляемые installer:
provider hypervisor / security group / upstream ACL / anti-DDoS
DNS / Cloudflare account
Remnawave panel и её БД
рабочая станция / terminal logging администратора
клиентские приложения / subscription storage
```

Успешная локальная проверка доказывает только тот слой, который реально проверен. Listener на `2222` не доказывает panel mTLS; Xray на `443` не доказывает Host/Squad/subscription; local Selfsteal PASS не доказывает user VPN.

Установщик нельзя запускать:

- на VPS панели/БД;
- на сервере с чужими production-контейнерами/службами;
- на машине с нестандартным firewall/network/boot stack без отдельного аудита;
- там, где потеря SSH без provider console делает recovery невозможным.

---

## 2. Парольный SSH — сознательная политика проекта

По требованиям проекта password SSH сохраняется, постоянный source-IP allowlist не создаётся, существующие SSH-порты сохраняются.

Installer не:

- создаёт OS-пользователей;
- задаёт/меняет пароли;
- разблокирует заблокированный root;
- удаляет существующие `authorized_keys`;
- требует SSH-key;
- добавляет бессрочный SSH allowlist для панели/администратора.

При уже действующем root-пароле root password login может оставаться доступным. Это сознательно рискованнее key-only SSH. Используйте длинный уникальный случайный пароль и password manager. Fail2ban снижает bruteforce-нагрузку, но не защищает от повторно используемого пароля, malware на рабочей станции, утечки terminal log или root-compromise.

Перед изменением SSH/UFW создаётся phase-specific backup и короткий rollback guard. Этот guard страхует **конкретную фазу**, но не доказывает внешний SSH-вход и не откатывает всю ОС.

Безопасный порядок:

1. не закрывать старую SSH-сессию;
2. после изменений открыть новую парольную сессию;
3. проверить root/sudo;
4. держать console/recovery хостера доступной до post-reboot приёмки.

Не выключайте UFW/Fail2ban и не добавляйте широкий постоянный `ignoreip` ради unban. Через provider console или сохранённую trusted-сессию снимайте только точный подтверждённый бан.

---

## 3. Секреты и чувствительные данные

### Критические секреты

| Данные | Почему чувствительны |
|---|---|
| RemnaNode `SECRET_KEY` | используется в control relationship ноды; это не panel admin API token |
| `/etc/vkarmani-node/remnanode.env` | содержит `SECRET_KEY` |
| REALITY `PrivateKey` | приватный X25519 key сервера |
| `/etc/vkarmani-node/reality.json` | содержит REALITY PrivateKey |
| `/etc/vkarmani-node/profile.json` | содержит REALITY PrivateKey |
| `/root/reality-keys.txt` | явный export PrivateKey/PublicKey/ShortID; `root:0600` |
| `/etc/letsencrypt/**/privkey.pem` | приватный TLS key |
| `/etc/letsencrypt/` account/private state | чувствительное ACME-состояние |
| configuration backups | агрегируют системные и application-конфиги |
| live config/environment dumps | могут содержать секреты/идентификаторы/ключи |

`PublicKey`, `ShortID`, домен и клиентские параметры не эквивалентны PrivateKey, но полные production topology/config dumps тоже не нужно публиковать без необходимости.

### Что нельзя выкладывать публично

Не отправляйте без redaction:

```text
.env / *.env
/etc/vkarmani-node/remnanode.env
/etc/vkarmani-node/reality.json
/etc/vkarmani-node/profile.json
/root/reality-keys.txt
/etc/letsencrypt/
полные configuration backups
полный `docker inspect`
полный `docker compose config`
`docker exec ... env`
полный live Xray/Remnawave config dump
production VLESS subscription links
```

VLESS-ссылка сама является access material. Для внешнего тестера создавайте отдельного ограниченного test-user и отзывайте его после проверки.

### Как installer обращается с секретами

Используются `set +x`, restrictive `umask`, скрытый ввод из TTY и root-only файлы. `SECRET_KEY` не должен передаваться обычным argv внешней команды и не печатается в штатный вывод. Crypto/maintenance errors не должны dump-ить payload.

В `2.1.3` `/root/reality-keys.txt` создаётся только после успешной local acceptance. Файл пишется атомарно и должен оставаться regular root-owned `0600`. Existing symlink, non-regular type, чужой owner или слишком широкие права вызывают STOP вместо перезаписи.

Финальный блок REALITY keys выводится напрямую в controlling TTY, поэтому PrivateKey не дублируется в общий install log. Это **не** защищает от:

- MobaXterm/terminal session logging;
- scrollback;
- screenshot/screen recording;
- root access;
- Docker socket access;
- privileged memory inspection.

Base64 — кодирование, а не шифрование. Configuration backup tar не становится encrypted только потому, что хранится в закрытой директории. Нужные backups переносите в защищённое off-host хранилище и отдельно проверяйте restore.

---

## 4. Сетевая поверхность

Ожидаемые входящие порты:

| Порт | Роль | Ожидаемый источник |
|---|---|---|
| существующие SSH TCP-порты | администрирование | IPv4 Internet с временными Fail2ban-банами |
| `80/tcp` | ACME HTTP-01 + redirect | IPv4 Internet к выбранному Node-domain IPv4 |
| `443/tcp` | Xray VLESS RAW REALITY / Selfsteal | IPv4 Internet к выбранному Node-domain IPv4 |
| `2222/tcp` | RemnaNode management API | **только** заданный backend egress IPv4 панели |

`2222/tcp` нельзя открывать всему Интернету как troubleshooting shortcut. Source-IP allowlist уменьшает поверхность, но не заменяет mTLS RemnaNode.

UFW использует deny incoming/routed и allow outgoing. Installer проверяет ожидаемую UFW/INPUT-топологию, но не утверждает, что полностью понимает любой внешний/низкоуровневый фильтр:

- provider security group / ACL;
- upstream anti-DDoS;
- custom nftables raw/mangle hooks;
- eBPF;
- hypervisor firewall;
- маршрут из другой страны/ASN.

Не накладывайте второй firewall manager поверх этой схемы без отдельного design review.

### Multi-IP ноды

Домен ноды должен указывать на публичный IPv4, реально назначенный VPS. На multi-IP сервере management `Address` в Remnawave может использовать другой публичный IPv4 **той же VPS**, а клиентский Host/SNI продолжит использовать домен ноды.

UFW допускает backend панели к `2222` на локальных публичных IPv4 ноды именно для такого сценария. Это не повод убирать source restriction панели.

---

## 5. IPv4-only и DNS

Проект сознательно IPv4-only:

- у домена ноды ровно одна A-запись на прямой local public IPv4 VPS;
- AAAA у домена ноды отсутствует;
- Cloudflare record ноды — DNS-only, не proxied/CDN;
- IPv6 отключается runtime и через GRUB `ipv6.disable=1`;
- полная socket-level проверка выполняется после reboot.

NAT-only, IPv6-only, LXC/OpenVZ и неподдерживаемый boot layout не адаптируются «на глаз». Installer должен STOP-нуться, а не угадывать routes/IP или переписывать provider network config.

Локальный `vkarmani-node-tls-check` не проходит реальный Internet path panel→node. Его PASS не исключает upstream firewall, PMTU, anti-DDoS или route problem.

---

## 6. Безопасность контейнера RemnaNode

RemnaNode работает в `network_mode: host`. Это часть выбранной архитектуры и означает общий network namespace с хостом. Это **не** полноценная network isolation.

По умолчанию:

- `NET_ADMIN` не выдаётся;
- `NET_RAW` сброшен;
- включён `no-new-privileges`;
- в контейнер read-only монтируется только dedicated Selfsteal socket directory;
- private keys Let's Encrypt в Xray не монтируются;
- после pull image фиксируется точным digest.

`--allow-net-admin` существует только для осознанно выбранных upstream-функций управления IP/network. При host networking `NET_ADMIN` может позволить контейнеру менять сеть хоста. Не включайте capability «про запас».

Доступ к Docker socket остаётся root-equivalent. Container hardening не защищает от root/Docker-daemon compromise.

---

## 7. REALITY / Selfsteal

Архитектура проекта — **VLESS + RAW + REALITY**. В `serverNames` используется собственный домен ноды. Обычный HTTPS/не-REALITY путь отправляется через:

```text
target=/dev/shm/nginx.sock
xver=1
```

Внутри контейнера `/dev/shm/nginx.sock` — read-only bind-представление host-каталога с:

```text
/run/vkarmani-selfsteal/nginx.sock
```

Nginx на хосте обслуживает TLS/cover на Unix socket. Публичный TCP/443 принадлежит Xray. Не заставляйте host Nginx слушать public 443 в этой архитектуре.

Не используйте чужие домены/IP как REALITY target/SNI в рамках этого проекта. Владение доменом, правила провайдера и допустимость сервиса по договору остаются обязанностью оператора. Рабочий сертификат/DNS подтверждают только технический контроль в ограниченном смысле.

Cover-site не является гарантией «невидимости». Он не скрывает IP сервера, связь доменов, TLS/client fingerprints, публичный SSH и все характеристики трафика. Не ослабляйте TLS/security checks на основании неподтверждённых «anti-DPI/undetectable» советов.

### `minClientVer`

Выпуск **2.1.3** генерирует и локально проверяет именно выбранную политику совместимости:

```json
"minClientVer": "0.0.0"
```

Она снимает нижний version-gate и согласована между profile, validator, guide и export. Это не обещание безопасности/работоспособности произвольного старого клиента и не реализация отсутствующих в нём функций. Генератор 2.1.2 использовал `1.0.0`; его оригинальная документация сохранена в `docs/history`.

**Никаких удалённых профилей installer не переписывает.** Старые установленные helpers автоматически не обновляются. Не заменяйте отдельный helper на рабочей ноде и не перегенерируйте `profile.json` ради прохождения нового validator: разные поколения template требуют отдельной согласованной миграции.

`profile-check` читает только предоставленный regular JSON-файл размером до 2 MiB, отвергает финальный symlink, FIFO, duplicate JSON keys и NaN/Infinity. При отказе значения секретов/сырой JSON не выводятся. Это защита границ чтения, не sandbox от конкурирующего root.

Структурный PASS подтверждает перечисленные DNS/IPv4/routing-ссылки и Selfsteal-контракт, **не полноту правил блокировки и не фактическую недоступность private/metadata/IP-панели через TCP/UDP**. Для этого нужны отдельные контролируемые тесты конечного выхода. Общий Vision и служебный API RemnaNode учитываются, но не создаются validator.

---

## 8. Nginx / TLS / ACME

Nginx работает на хосте. Public TCP/80 нужен HTTP-01 и redirect. Selfsteal TLS обслуживается через local Unix socket. Сертификаты/private keys остаются на хосте.

Перед ручной правкой Nginx:

1. backup точных изменяемых файлов;
2. `sudo nginx -t`;
3. только после успешного syntax test — reload;
4. `sudo vkarmani-selfsteal-check`;
5. при ожидаемом live Xray — `sudo vkarmani-node-check --require-xray`.

Проверка renewal:

```bash
sudo certbot renew --dry-run --non-interactive
```

Не используйте `--force-renewal` как повседневную диагностику. Если сохраняется HTTP-01, TCP/80 должен оставаться доступен для renewal.

---

## 9. Целостность APT/dpkg и time provider

Нельзя «чинить» APT locks удалением lock-файлов или убийством штатных `apt`, `dpkg`, `unattended-upgrade`. В `2.1.1+` installer ждёт реальных владельцев package-manager lock в bounded deadline, затем делает `dpkg --audit` и продолжает только из согласованного состояния.

Security updates не отключаются только ради более быстрой установки.

Исправленный ранее конфликт time-daemon решён сохранением поддерживаемого существующего `systemd-timesyncd` или Chrony. Общий принцип `--no-remove` сохраняется: installer не должен молча удалять посторонние пакеты, чтобы удовлетворить новый APT plan.

Если пакетная операция остановилась или состояние dpkg подозрительно:

```bash
sudo dpkg --audit
```

Сначала восстановите реальное package state. Незавершённую установку продолжайте **той же generation/version**, если нет документированного узкого migration path. Не редактируйте version/state markers вручную ради cross-version resume.

---

## 10. Supply chain

### Получение `install.sh`

Не используйте live `curl | bash`. Команда из README:

1. скачивает полный файл;
2. сверяет известный SHA256 release;
3. делает `bash -n`;
4. проверяет `--version`;
5. запускает только после всех проверок.

SHA256 `install.sh` для этого `2.1.3`:

```text
40124966b043e280f843cea06f681472b39ac01447e9692566d4dbeb82a59b1b
```

Если `install.sh` изменён, README и release manifest должны обновляться согласованно после review. Никогда не вычисляйте новый хеш из недоверенного изменившегося файла и не называйте его после этого «проверенным».

### OS packages и Docker

Пакеты ставятся из подписанных repositories. Fingerprint Docker signing key проверяется. Не обходите fingerprint failure без сверки нового ключа по авторитетному источнику vendor.

RemnaNode image ограничивается ожидаемым official namespace и после pull закрепляется digest. Namespace/digest pinning улучшает repeatability, но не является полной cryptographic attestation содержимого image или доказательством совместимости с конкретной версией панели.

### CI

CI предназначен для test/validation, а не production deployment. Production secrets/deploy credentials не должны появляться там только ради удобства тестов. Не используйте `pull_request_target`-подходы, исполняющие недоверенный contributor code с privileged secrets.

---

## 11. Backup и rollback

Configuration backups установщика полезны, но **не равны provider snapshot**. Snapshot/recovery остаётся whole-system boundary.

`vkarmani-node-maintain backup` создаёт закрытый configuration archive + checksums. Относитесь к archive как к secret. Проверяйте его до того, как рассчитывать на restore, и храните off-host copy, если backup входит в recovery plan.

Image update/rollback не возвращает:

- OS packages;
- GRUB/sysctl;
- уже потерянный writable layer пересозданного контейнера;
- Remnawave DB/objects;
- user subscriptions/sessions;
- provider network/firewall state.

При `IMAGE_APPLY=UNKNOWN` сначала проверяется реальное состояние Docker. Не удаляйте pending state и не запускайте параллельные update/rollback.

SSH/UFW rollback helper возвращает только принадлежащий ему phase backup. Это не rollback всей установки.

---

## 12. Auto-reboot

В `2.1.3` один post-install reboot включён по умолчанию. Он ставится через transient systemd unit только после успешной local preboot acceptance и export ключей.

Для ручного окна проверки:

```bash
sudo bash install.sh --no-reboot
```

Это особенно важно, если provider console/recovery ненадёжна.

Если transient reboot unit не удалось поставить, installer сообщает `AUTO_REBOOT=FAILED`; успешный `INSTALL_COMPLETE` при этом не удаляется. Reboot выполняйте вручную только после проверки состояния.

Weekly reboot остаётся opt-in через `--weekly-reboot` и по умолчанию выключен.

---

## 13. Безопасная диагностика и redaction

Предпочитайте узкий read-only вывод:

```bash
sudo vkarmani-node-check
sudo vkarmani-node-check --require-xray
sudo systemctl --failed --no-pager
sudo ufw status verbose
sudo ss -4 -lntp
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}'
sudo fail2ban-client status sshd
```

Перед отправкой диагностики удалите/замаскируйте:

- домашний/admin public IP, если он не нужен для анализа;
- имена пользователей, не относящиеся к проблеме;
- `SECRET_KEY`;
- REALITY PrivateKey;
- TLS private keys;
- user UUID/VLESS subscription link;
- cookies/tokens/authorization headers;
- полный `.env`/container environment;
- backup archives.

PublicKey/ShortID/domain иногда нужны для protocol troubleshooting, но всё равно публикуйте только минимально необходимое.

При проблеме panel→node packet capture **на самой ноде** позволяет отличить «пакет вообще не дошёл до интерфейса» от «его отбросили UFW/service», не требуя изменений на панели. PCAP/tcpdump содержит IP metadata — храните его приватно либо редактируйте перед публикацией.

---

## 14. Incident response

### Утечка `SECRET_KEY` / REALITY PrivateKey

1. Сохранить provider console access и минимально необходимую закрытую диагностику.
2. Прекратить дальнейшую публикацию logs/screenshots/config dumps.
3. Определить, что именно было раскрыто: `SECRET_KEY`, REALITY key, TLS key, SSH password, backup, root/panel credential.
4. Согласованно ротировать material в панели/Node/client configuration. Простое удаление/перегенерация только на VPS может оставить панель со старыми данными.
5. Обновить subscriptions/clients там, где credentials изменились.
6. Удалить публичные копии, но считать уже опубликованный secret скомпрометированным даже после удаления поста.

### Подозрение на root compromise

Не доверяйте локальным integrity checks, выполненным из потенциально скомпрометированной root-среды. Безопаснее поднять чистую VPS из доверенного image, ротировать соответствующие credentials и переносить только просмотренные данные/config.

### Потерян SSH

Используйте provider console/recovery. Не отвечайте на проблему открытием всех портов/выключением firewall через сомнительный путь.

### Панель не достаёт `2222`

Не открывайте `2222` всему миру. Сначала:

```bash
sudo ss -4 -lntp | grep ':2222'
sudo ufw status numbered
sudo vkarmani-node-tls-check
```

Затем на ноде можно захватить только управление `2222`, параллельно инициировав попытку панели:

```bash
sudo timeout 120 tcpdump -ni <interface> -nn -tttt -vv 'tcp port 2222'
```

Если во время заведомой попытки панели SYN вообще не приходит на interface, проблема находится до UFW/RemnaNode на этом path: egress/route панели, provider ACL/anti-DDoS и т.п. Если SYN приходит — дальше проверяются UFW/TCP/mTLS/service layers. Не называйте это «баном провайдера», пока evidence не показывает, где именно фильтрация.

---

## 15. Сообщение о security-проблеме

Не придумывайте несуществующий security email. Используйте приватный contact method владельца репозитория/platform, если он доступен. Если есть только public issue tracker, публикуйте только просьбу дать private channel — без exploit details, secrets и production identifiers.

Хороший redacted report содержит:

- installer version;
- OS/architecture;
- clean/new node или existing install;
- точный stage/error code;
- минимальные отредактированные log lines;
- reproducible steps на disposable test-node;
- expected vs actual;
- отдельно — что уже проверено на provider firewall/panel/client уровне.

---

## 16. Что security-модель не обещает

Проект не обещает:

- отсутствие provider blocking/route failures;
- «невидимый/неопределяемый» трафик;
- защиту от скомпрометированного root/Docker daemon;
- безопасность слабого/повторно используемого SSH-пароля;
- работоспособность панели/клиента только потому, что local tests PASS;
- совместимость любого древнего core после `minClientVer=0.0.0`;
- автоматическое понимание любого custom nftables/eBPF/provider firewall;
- full OS rollback из configuration backup;
- безопасный mass rollout без canary и provider-specific acceptance.

Не обходите STOP/guard только потому, что другой сервер установился. STOP может защищать другое состояние: boot layout, firewall, package manager, provider image или уже существующий production config.

---

## 17. Связанные документы

- [README.md](README.md) — установка, Remnawave, архитектура и operator commands.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — эксплуатация, диагностика и recovery.
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — test coverage и явные gaps.
- [docs/REALITY_KEYS_AUTOREBOOT_2.1.2.md](docs/REALITY_KEYS_AUTOREBOOT_2.1.2.md) — secure key export и auto-reboot.
- [docs/APT_LOCK_COORDINATION_2.1.1.md](docs/APT_LOCK_COORDINATION_2.1.1.md) — package-manager lock policy.
- [docs/HOSTING_AND_INCIDENTS.md](docs/HOSTING_AND_INCIDENTS.md) — provider/network incidents.
- [docs/COVER_SITE.md](docs/COVER_SITE.md) — cover-site update/rollback boundaries.
- [docs/UFW_PREFLIGHT_FIX.md](docs/UFW_PREFLIGHT_FIX.md) — strict saved-UFW rules handling.
- [docs/TIME_SYNC_FIX.md](docs/TIME_SYNC_FIX.md) — сохранение поддерживаемого time provider.
- [docs/UBUNTU_26_04.md](docs/UBUNTU_26_04.md) — статус 26.04 и требования canary.
- [docs/FAILURE_AUDIT.md](docs/FAILURE_AUDIT.md) — failure modes и остаточные риски.
