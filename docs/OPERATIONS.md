# Эксплуатация, диагностика и восстановление

Версия 2.0.3, 2026-09-30. Регламент относится к **ноде**, не к панели/БД. Команды, меняющие состояние, выполняйте в согласованное окно с проверенным snapshot и консолью хостера. Не используйте эту инструкцию как автоматический rollback всей ОС.

## Перед первой production-раскаткой

Сначала подготовьте одну canary-VM того же провайдера/образа ОС/архитектуры, что и будущая группа нод. Один успешный сервер у другого хостера не проверяет особенности загрузчика, маршрутов, cloud firewall и ядра текущего.

Проверьте snapshot не только по наличию: должен быть понятен и доступен процесс восстановления через панель хостера. Проверяйте restore на тестовой VM, не перезаписывайте живую ноду ради проверки. Убедитесь, что консоль доступна независимо от SSH, вы знаете действующий пароль и можете отличить VPS ноды от VPS панели.

Примеры read-only проверок на целевой ноде:

```bash
hostnamectl
cat /etc/os-release
uname -r
systemd-detect-virt
ip -4 -brief address
ip -4 route
free -h
df -h /
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | grep -E '^(port|addressfamily|passwordauthentication|permitrootlogin|authenticationmethods) '
sudo systemctl --failed --no-pager
```

Для multi-IP машины адрес домена должен быть назначен интерфейсу, но не обязан быть default-source адресом. IP технички — фактический egress backend, не IP браузера и не Cloudflare. DNS only относится к **домену ноды**; настройки проксирования домена панели здесь автоматически не меняются.

Установите проверенную версию из архива/README. Не закрывайте исходную SSH-сессию. После локального завершения откройте **новую парольную** сессию, проверьте sudo при его использовании, затем перезагрузите сервер и убедитесь, что он вернулся без ручного запуска Docker/Nginx.

## Приёмка после установки и reboot

```bash
sudo vkarmani-node-check
sudo systemctl --failed --no-pager
sudo systemctl status vkarmani-node-postboot.service --no-pager
sudo systemctl list-timers --all --no-pager
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
sudo ufw status verbose
```

До первого reboot применим `sudo vkarmani-node-check --preboot`: обычный режим вправе сообщать, что GRUB-параметр ещё не активен. После reboot проверьте наличие `ipv6.disable=1` в `/proc/cmdline`; строгая проверка также требует невозможности создать IPv6 socket.

Завершите действия из `/etc/vkarmani-node/PANEL-SETUP.txt`, затем:

```bash
sudo vkarmani-node-check --require-xray
```

Подтвердите Node online/подключение в панели, актуальный профиль и права пользователя. С внешней сети, отличной от самой VPS, проверьте загрузку подписки, подключение VPN, несколько обычных сайтов, крупную передачу данных и поведение при переподключении. Результат `LOCAL_XRAY_COVER_OK_CLIENT_NOT_TESTED` относится к cover-маршруту, не к трафику авторизованного пользователя.

Нагрузочные пороги устанавливаются по вашей CPU/RAM, лимитам провайдера, числу одновременных сессий и маршрутам. Не объявляйте ноду «на 1000 пользователей» только по 1 GiB RAM или настроенному BBR. Нужен период наблюдения с фактической нагрузкой перед массовой раскаткой.

## Диагностическая карта

| Симптом | Проверять сначала | Что нельзя заключать автоматически |
|---|---|---|
| Скрипт остановился до APT | Сообщение preflight, ОС/GRUB/контейнеризация/чужие конфиги/пароль | Что нужно удалить все конфликтующие файлы |
| Не выбран IPv4 | A/AAAA снаружи, локальные IP, DNS only, NAT | Что IP от `curl ifconfig…` обязательно правильный |
| Ошибка секрета | Полный ключ именно вашей панели; часы; срок и структура bundle | Что любой TCP listener на 2222 означает правильный ключ |
| API TLS local FAIL | Контейнер, сохранённый секрет, CA/leaf, derived SNI, часы | Что виноват исключительно UFW или внешний MTU |
| API local PASS, панель offline | Egress IP backend, внешний firewall, Node Address/Port, совместимость/сертификаты панели | Что панель успешно прошла mTLS |
| 443 не слушает | Профиль/inbound в панели, доставка live-конфига, ошибки Xray | Что надо ставить Nginx на публичный 443 |
| Socket FAIL | Nginx config/TLS, `/run/vkarmani-selfsteal`, bind в Compose | Что нужно разрешить запись во весь host `/dev/shm` |
| Selfsteal direct PASS, 443 cover FAIL | REALITY target/xver/serverName, назначенный inbound, порт | Что VPN-клиент обязательно неисправен |
| Часть сайтов зависает | Реальный маршрут/потери/CPU/ограничения, PMTUD, клиент | Что для всех хостеров надо выставить MTU 1280/1420 |
| Pending image update | Transaction state и доступность предыдущего image | Что безопасно удалить pending marker и обновиться ещё раз |
| После reboot нет сети | Консоль, загрузчик, provider routing/DNS, kernel log | Что локальный старый PASS гарантировал доступ извне |

## SSH и Fail2ban

Read-only диагностика:

```bash
sudo /usr/sbin/sshd -t
sudo systemctl status ssh.service ssh.socket --no-pager
sudo ss -4 -lntp
sudo fail2ban-client ping
sudo fail2ban-client status sshd
sudo journalctl -u ssh.service -n 80 --no-pager
sudo journalctl -u fail2ban.service -n 80 --no-pager
```

Журналы могут содержать имена пользователей/IP. Просматривайте локально; перед публикацией редактируйте персональные данные. `PasswordAuthentication yes` не отменяет блокировку аккаунта, PAM/expiration и невозможность войти с неверным паролем.

Если заблокирован ваш адрес, используйте проверенную существующую сессию либо **консоль провайдера**. Посмотрите `status sshd`; удаляйте только конкретный ошибочный бан:

```bash
# Замените АДРЕС на точный IPv4 из списка банов:
# sudo fail2ban-client set sshd unbanip АДРЕС
```

Не выключайте ради unban весь UFW, не открывайте API миру и не добавляйте широкое постоянное ignoreip. Причину повторяющихся ошибок входа устраните до нового подключения. Внешние bans/security groups у хостера Fail2ban не снимает.

### Незавершённый защитный откат SSH/UFW

Во время изменения SSH/UFW запускается transient systemd timer примерно на 180 секунд. Он и установщик используют отдельный lock. Состояния находятся в `/var/lib/vkarmani-node/network-rollback-armed`, `network-rollback-running`, `network-rollback-done`.

Если остался armed/running, не удаляйте эти файлы ради повторного запуска. Через консоль проверьте закрытый `/var/lib/vkarmani-node/network-backup`, затем при необходимости выполните:

```bash
sudo /usr/local/sbin/vkarmani-network-rollback
sudo /usr/sbin/sshd -t
sudo systemctl status ssh.service ssh.socket --no-pager
sudo ufw status verbose
```

Команда возвращает **сохранённую фазой** конфигурацию SSH/UFW и проверяет локальный сервис. Она не возвращает APT, GRUB, runtime sysctl, timezone или образ. Если backup создавался при неактивном UFW, откат возвращает именно неактивное состояние: нода не должна считаться принятой в эксплуатацию. Проверьте внешний доступ и восстановите безопасную политику до возврата пользователей.

После успешного завершения фазы marker снимается; вызов guard без armed/running ничего не меняет. Для отката всей установки нужен проверенный снимок или разбор исходного backup, а не ручное создание armed на работающем сервере.

## Nginx, Selfsteal и сертификат

```bash
sudo nginx -t
sudo vkarmani-selfsteal-check
sudo systemctl status nginx.service certbot.timer --no-pager
sudo journalctl -u nginx.service -n 80 --no-pager
sudo journalctl -u certbot.service -n 80 --no-pager
sudo test -S /run/vkarmani-selfsteal/nginx.sock
sudo docker exec remnanode test -S /dev/shm/nginx.sock
```

Nginx должен принимать TLS на Unix socket, а не конкурировать с Xray за 443. Не меняйте путь только с одной стороны. Каталог `/run` временный; его восстанавливает tmpfiles. Bind всего каталога обеспечивает видимость нового socket после Nginx restart, но не устраняет ошибку прав/профиля/сертификата.

Плановая безопасная проверка renewal требует рабочего DNS и открытого TCP/80:

```bash
sudo certbot renew --dry-run --non-interactive
```

Обычный `--dry-run` проверяет тестовое продление, но **сам по себе не означает запуск deploy hook**. Выполните `nginx -t` и Selfsteal check отдельно; при использовании опции запуска deploy hooks сначала проверьте поведение установленной версии Certbot. Не запускайте тест многократно без причины и не используйте `--force-renewal` как повседневную диагностику.

После собственного изменения Nginx сначала backup и `nginx -t`; только при успехе `sudo systemctl reload nginx`, затем Selfsteal и strict check. Не копируйте приватный TLS-ключ в Xray-контейнер: текущая схема его там не требует.

## Сеть, DNS и MTU

```bash
ip -4 -brief address
ip -4 route
ip link show
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_mtu_probing
sudo tc -s qdisc show
sudo ss -s
sudo journalctl -k -n 100 --no-pager
```

`network-effective.json` объясняет fallback BBR/fq. Файл sysctl с желаемым BBR не является доказательством, что ядро его включило. `default_qdisc` и фактический qdisc каждого NIC — разные проверки.

Диагностика `vkarmani-node-tls-check` проходит loopback/локальные IPv4; даже большой фрагментированный ClientHello **не проходит международный путь от панели**, поэтому не доказывает отсутствие внешнего PMTU black hole. Проверяйте путь с реального backend и реального клиента, учитывая фильтрацию ICMP, overlay/VPN, NAT и лимиты провайдера. Инструменты `tracepath`/`mtr` полезны при их наличии, но фильтрация диагностических ответов не равна доказанным потерям полезного трафика.

Не меняйте MTU, offload и sysctl пачкой. Сохраните состояние, сформулируйте проверяемую гипотезу, изменяйте один параметр на canary и сравнивайте один и тот же тест до/после. IPv4 DNS, APT и NTP должны оставаться доступны после полного выключения IPv6; скрипт не переключает resolver провайдера наугад.

## Backup: что сохраняется и как проверить

Установка сохраняет исходные конфиги в `/var/lib/vkarmani-node/backups/<timestamp>-<pid>/` с `MANIFEST.sha256`. Пути `first-backup-path` и `latest-backup-path` указывают на первую и последнюю копию. Первая копия создаётся после сбора входов и создания owned/state, но **до изменений системных конфигов APT/SSH/UFW/GRUB**; это не полная точка восстановления ОС.

Завершённая 2.0.3 поддерживает:

```bash
sudo vkarmani-node-maintain backup
```

Maintenance создаёт закрытый `node-config.tar.gz`, `FILES.txt` и `SHA256SUMS`. Внутри — конфиги ноды/SSH/UFW/Nginx/Docker/Certbot/Fail2ban/Chrony/timesyncd/systemd/GRUB/sysctl/APT, helpers, cover-сайт и верхнеуровневые state-файлы. Не входят Docker layers/volumes, содержимое swap, БД/объекты панели, все вложенные старые backups и полная история каталогов image-transactions.

Проверка последнего maintenance backup без извлечения в `/`:

```bash
sudo bash <<'CHECK'
set -Eeuo pipefail
umask 077
p=$(cat /var/lib/vkarmani-node/latest-maintenance-backup-path)
case "$p" in /var/lib/vkarmani-node/backups/maintenance-*) ;; *) echo 'Unexpected backup path'; exit 1;; esac
cd "$p"
sha256sum --check SHA256SUMS
tar -tzf node-config.tar.gz >/dev/null
printf 'Проверены checksum и читаемость: %s\n' "$p/node-config.tar.gz"
CHECK
```

Хеш и читаемость tar **не доказывают возможность полного restore**. Перенесите архив через защищённый канал off-host и проверьте восстановление в отдельной VM. Конфигурационный backup содержит секреты, не зашифрован и не должен лежать в публичном Git/облаке без защиты. Автоматической ротации backup нет: проверяйте диск и удаляйте только осознанно выбранные уже продублированные старые копии.

## Обновление image и аварийное восстановление

Перед обновлением проверьте совместимость выбранного Node image с вашей версией панели на canary, состояние панели, snapshot и свободное место. Maintenance требует минимум 2 GiB в DockerRootDir и не менее двойного размера текущего image, а для backup — запас не менее 512 MiB. Это начальный guard, не обещание, что любой необычно большой новый образ поместится.

```bash
sudo vkarmani-node-maintain backup
sudo vkarmani-node-maintain refresh-image
sudo vkarmani-node-check --require-xray
```

Если нужен конкретный проверенный image, передайте `--image remnawave/node:TAG` либо `--image remnawave/node@sha256:DIGEST`; подставьте реальные значения. Без `--image` используется сохранённый источник. Повторный plain install — не механизм смены версии.

При подтверждённом завершении Compose и сбое локальной проверки кандидата выполняется попытка возврата старого Compose/image. При `IMAGE_APPLY=UNKNOWN` (таймаут/сигнал внутри Compose apply) встречный rollback автоматически не запускается: Docker daemon мог продолжить принятую операцию. Сначала через консоль проверьте состояние daemon/контейнера и отсутствие продолжающегося recreate. Убийство CLI само по себе не отменяет запрос daemon. Если после SIGKILL, пропадания питания или неподтверждённого rollback остался `image-update-pending`, используйте:

```bash
sudo vkarmani-node-maintain rollback-image
```

Проверяются принадлежность transaction path, SHA256 конфигов и отсутствие посторонней правки Compose. При drift или отсутствии старого локального image команда останавливается, а не перетирает неизвестное состояние. Не удаляйте pending и не правьте метаданные, чтобы пройти проверку: сохраните закрытую копию state и разбирайте конкретный разрыв через консоль.

Успешный локальный rollback не восстанавливает sessions/writable layer/live state панели. Если панель не может вновь прислать профиль, старый image может быть исправен, но клиентский 443 не поднимется. Не выполняйте обновление при недоступной панели, рассчитывая на «полностью автономный откат». Проверьте панель, строгую диагностику и настоящий клиент после любого update/rollback.

### Восстановление всей VPS / конфигов

Предпочтителен **проверенный snapshot хостера** из нужной точки, с пониманием изменения DNS/IP и последующих обновлений панели. Обратная установка старого DEB-пакета или копирование всего tar поверх `/` не является штатным rollback установщика.

Для выборочного restore распакуйте backup в новый закрытый каталог, проверьте manifest и diff только нужных файлов. Не извлекайте непроверенный tar напрямую в rootfs. Сохраняйте текущие файлы перед заменой; SSH сначала `sshd -t`, Nginx `nginx -t`, Compose `config --quiet`, Docker `dockerd --validate`, GRUB — проверка загрузочной схемы и консоль. Не меняйте ключи отдельно от соответствующих объектов панели. Не выдавайте копирование config-only backup за восстановление образов, транзакций, пользователей ОС или панели.

## Сбой первой установки и три сохранённых значения

Read-only сначала: этап/код в `/var/log/vkarmani-node-install.log`, `/var/lib/vkarmani-node/INSTALL_FAILED`, наличие guard marker, свободный диск и причина ошибки. Не публикуйте полный backup/секрет. Установщик не делает автоматический rollback всех уже установленных пакетов и конфигов.

При `network-rollback-armed` или `network-rollback-running` сначала через консоль разберите/завершите уже подготовленный `vkarmani-network-rollback`; новые backup-файлы не должны затереть единственную копию доступа до сбоя. Этот guard использует runtime-таймер: он не даёт гарантии восстановления после внезапного отключения питания/перезагрузки.

После устранения причины запускайте **тот же файл той же версии, которым начата установка** повторно. Для новой установки этой поставки это 2.0.3, а незавершённую 2.0.0/2.0.1 новым файлом не продолжают. При успешном `config.json` используются сохранённые значения; до него — `/etc/vkarmani-node/inputs.pending` (тоже секретный файл). Нет повторной генерации REALITY-ключей для обхода ошибки.

Исключение 2.0.3: точная ранняя остановка компонентов 2.0.2 с `rc=100 line=2761` до Docker/сети может пройти отдельный read-only gate и продолжиться с backup. Проверяются исходный helper по SHA256, закрытые файлы состояния и отсутствие артефактов поздних этапов. При ошибке создания новой копии исходные version/failure markers не заменяются (`RESUME_FAILED` отдельно); после подтверждённой копии дальнейшее продолжение выполняется уже только 2.0.3. Вручную менять markers запрещено. Полный регламент: [TIME_SYNC_FIX](TIME_SYNC_FIX.md).

Если неверный ключ/домен попал только в pending и `config.json` ещё не создан, после разбора причины можно переместить pending в закрытую резервную копию, чтобы следующий запуск заново спросил три значения:

```bash
sudo bash <<'RESET_PENDING'
set -Eeuo pipefail
umask 077
p=/etc/vkarmani-node
[[ ! -e "$p/config.json" ]] || { echo 'Config уже существует: автоматическая смена входов запрещена'; exit 1; }
[[ -f "$p/inputs.pending" && ! -L "$p/inputs.pending" ]] || { echo 'Обычный pending-файл не найден'; exit 1; }
mv -- "$p/inputs.pending" "$p/inputs.rejected.$(date +%Y%m%d-%H%M%S).$$"
echo 'Сохранена закрытая копия неверных входов; следующий запуск спросит их заново.'
RESET_PENDING
```

При уже созданном config, изменении домена/IP/ключа на живой ноде или смене secret-generation нужен отдельный согласованный план: UFW, сертификат, env, REALITY/профиль, панель и клиенты должны остаться согласованными. Массовое удаление `/etc/vkarmani-node`/state ради «чистой переустановки» не допускается.

## Совместимость с 1.3.x

Старые `--repair-network` и `--repair-node` оставлены для **завершённых собственных 1.3.x** и перед изменениями проверяют состояние. Network repair касается применения sysctl при полностью выключенном IPv6. Node repair обновляет ограниченный набор своих helper/unit/Fail2ban/socket-настроек, проверяет image identity и имеет файловый rollback. Это не обещание починить произвольную поломку панели или сети.

Они не мигрируют рабочую ноду на новый layout 2.0.3, не должны использоваться вместо canary/snapshot и не меняют боевую PKI/профиль панели. Прежде repair сохраните полный snapshot; заранее изучите затрагиваемую функцию `install.sh`, поскольку узкое исправление всё равно меняет сервисные файлы и может перезапускать службы.

Для 2.0.x repair-команды 1.3.x намеренно отклоняются. Незавершённую старую установку новой версией не продолжают, кроме описанного точного раннего package-stage перехода 2.0.2 → 2.0.3. Перенос на новую ноду безопаснее неподтверждённой автоматической миграции загрузчика, SSH, capabilities и socket на рабочем VPS.

## Репозиторий, публикация и контрольные суммы

Архив содержит исходную Git-историю плюс изменённое рабочее дерево; автоматического commit/push нет. Заменять можно папку исходного репозитория после её локальной резервной копии, **не рабочие `/opt/vkarmani-node` или `/etc/vkarmani-node` на VPS**.

Перед публикацией:

```bash
bash tests/run.sh
git diff --check
git status --short
git diff -- install.sh README.md SECURITY.md .gitignore .gitattributes
sha256sum --check SHA256SUMS
```

**Архив 2.0.3 — полный рабочий проект без `.git`.** Сначала резервная копия локального clone, затем обновление его рабочих файлов с сохранением действующей `.git`. Не заменяйте её метаданными из старого архива и не удаляйте подключённую папку репозитория целиком. При новых коммитах на remote нужны Fetch/Pull и разбор конфликтов, не force push. Отдельный архив прежней `.git` предназначен только для сохранности исходной истории.

Новые файлы просмотрите отдельно: `git diff` без staging не показывает содержимое untracked. Убедитесь, что нет runtime-секретов и ненужных файлов. После любого изменения installer пересчитайте checksum в установочной команде README. Manifest `SHA256SUMS` перечисляет обычные файлы поставки, исключая сам manifest и `.git`; он не является подписанным релизом. Не фиксируйте устаревший manifest при собственных изменениях. Публикацию выполняет владелец репозитория после review и canary, без секретов CI/CD.


## Обновление исходников и уже установленная 2.0.0

Этот полный архив обновляет репозиторий, а не автоматически содержимое `/usr/local/sbin`, `/usr/local/lib`, `/etc` на работающей VPS. У завершённой 2.0.0 обычный запуск нового `install.sh` остаётся диагностическим; выполняется **старая установленная** команда проверки. Смена контейнерного образа также не обновляет host helpers.

Не копируйте отдельные heredoc-фрагменты вручную, не подменяйте `install-version`/`INSTALL_COMPLETE`, не запускайте repair для 1.3.x на 2.0.0. В этом выпуске нет проверенной in-place миграции рабочего 2.0.0 сервера. Безопасный путь для проверки исправлений — отдельная чистая canary 2.0.3; существующие production-ноды остаются без изменений. In-place обновление потребует отдельного снимка фактического состояния, backup, стендовой проверки именно перехода и обратного плана.

## Selfsteal: stale socket, сертификат и ограничения проверяющего кода

Проверка без изменений:

```bash
sudo nginx -t
sudo systemctl status nginx --no-pager
sudo /usr/local/sbin/vkarmani-selfsteal-check
sudo journalctl -u nginx --since '-15 minutes' --no-pager
```

Сначала просмотрите вывод локально; перед отправкой удалите IP/домены/чувствительные строки. `SELFSTEAL_CERTIFICATE_NOT_RELOADED` означает, что диск и реально отданный leaf не совпали. Проверяйте deploy hook, `nginx -t`, reload и последующий `vkarmani-wait-selfsteal`, а не отключайте верификацию сертификата. После renewal reload может занять небольшое время; hook ждёт готовность в общем 60-секундном бюджете.

`STALE_REMOVED` означает: собственный socket существовал, connect получил отказ/исчезновение, повторная проверка не увидела смены inode, и объект удалён перед штатным стартом. `LIVE_SOCKET_UNCHANGED`, `NOT_OWNED_SOCKET`, `LIVENESS_NOT_PROVEN` и `INODE_CHANGED_UNCHANGED` — остановка, не разрешение на `rm -f`. Не запускайте Nginx параллельно вне его systemd unit. Проверка не защищает от произвольных конкурентных действий другого root-процесса.

Nginx повторяет запуск с интервалом 5 секунд без исчерпания StartLimit; это помогает после исправления причины или появления адреса, но **не исправляет** повреждённую конфигурацию/просроченный сертификат. Длительный restart loop требует вмешательства и проверки журналов.

Лимит cover `index.html` — 128 KiB. Проверка намеренно поддерживает HPACK-ответ собственного Nginx, не является универсальным HTTP/2-клиентом и отклоняет неизвестные варианты вместо ложного успеха. Это не изменение RAW-транспорта VPN.

## Проверка политики RAW REALITY в JSON

Для локального шаблона только на ноде, где установлен helper с командой `profile-check` (в том числе 2.0.2/2.0.3):

```bash
sudo python3 /usr/local/lib/vkarmani-node/node_helper.py profile-check
```

Для выгруженного **raw Xray JSON**, предварительно сохранённого оператором в закрытый файл `/root/node-profile-audit.json`, передайте этот путь после `profile-check`. Не публикуйте файл: там могут быть ключи и клиенты. API-обёртка JSON не считается профилем. `network`/`method` и `target`/`dest` проверяются совместно, конфликтующий alias не пропускается.

Это проверка переданного файла: один VLESS/443, RAW/REALITY, собственный SNI, локальный target, PROXY v1 и отсутствие дополнительных протоколов/туннельных outbounds в поддерживаемом шаблоне. Она не является полным `xray run -test`, аудитом маршрутизации/всех дополнительных полей, доказательством юридического владения доменом, подтверждением Host override либо снимком live-конфига панели.

## Ложный UFW STOP на чистой VPS в 2.0.1

В 2.0.1 сочетание `Status: inactive`, `ufw show added` → `(None)` и служебных `-A ufw-user-limit*` могло остановить первую установку. Исправлено в 2.0.2 без очистки firewall. Полный разбор и область допуска: [UFW_PREFLIGHT_FIX](UFW_PREFLIGHT_FIX.md).

Если остановка произошла именно здесь, до трёх вопросов/записи состояния, используйте проверенный `install.sh` актуальной поставки 2.0.3 на этой же VPS. Не удаляйте файлы UFW, `/etc/vkarmani-node`, `/opt/vkarmani-node`, `owned-installation` или version markers. При наличии уже начатой установки новый скрипт по-прежнему откажется смешивать версии вне отдельного точного раннего перехода, описанного в TIME_SYNC_FIX.

Смена только исходного файла до начала установки не меняет сеть; отдельного rollback firewall для этого исправления нет. Перед последующим полным запуском всё равно нужен snapshot и доступная консоль. После завершения проверьте новую SSH-сессию до закрытия старой, затем выполните плановый reboot и приёмку из начала этого документа.

На уже завершённой 2.0.1 обычный запуск нового файла остаётся диагностикой **старым установленным helper**, не обновлением host-составляющих. `refresh-image` меняет только контейнерный образ. Правила совместимости выше распространяются и на установленную 2.0.1; ручная подмена markers не допускается.


## Синхронизация времени в 2.0.3

Выбранный daemon сохранён в закрытом `/etc/vkarmani-node/time-provider`. Для просмотра и проверки **без изменения состояния**:

```bash
sudo python3 /usr/local/lib/vkarmani-node/time_helper.py provider
sudo python3 /usr/local/lib/vkarmani-node/time_helper.py check
```

Для узла с timesyncd:

```bash
sudo systemctl status systemd-timesyncd.service --no-pager
sudo systemctl show systemd-timesyncd.service -p RestrictAddressFamilies
sudo timedatectl show --property=NTPSynchronized --value
sudo timedatectl show-timesync --property=ServerAddress --value
sudo journalctl -b -u systemd-timesyncd.service -n 60 --no-pager
```

Для узла с Chrony:

```bash
sudo systemctl status chrony.service --no-pager
sudo chronyc -n tracking
sudo chronyc -n sources
sudo journalctl -b -u chrony.service -n 60 --no-pager
```

`TIME_PROVIDER_DRIFT` — сохранённый и установленный daemon разошлись; `UNSUPPORTED_TIME_DAEMON` — найден другой провайдер виртуального time-daemon; `INCOMPLETE_TIME_DAEMON_PACKAGE` — неполное состояние dpkg. Не исправляйте это удалением маркера, `apt remove`, принудительным unmask или одновременным включением двух служб. Сначала установите причину и согласуйте отдельное изменение.

При `NTP_SYNC_TIMEOUT` проверьте локально журналы, действующие NTP-источники, исходящий IPv4/UDP к ним и firewall хостера. Наличие DNS A-ответа и `active` не гарантирует синхронизацию. Автоматической замены источников хостера или отключения проверки времени нет. Лог установщика не следует публиковать без просмотра; `remnanode.env`, `inputs.pending`, `reality.json` и приватные ключи не отправляются.

Повторная установка активирует и перезапускает только выбранную службу. Перед продолжением нужен snapshot и консоль. Backup включает исходные timesyncd-конфиги и весь `/etc/systemd/system`, включая drop-ins, но не является откатом установленных пакетов/всей VPS. Восстановление частично изменённой ОС — через проверенный snapshot либо отдельный план; `rollback-image` здесь не помогает.
