# VKarmani Node Install 2.5.3 — интеграция данных rkn-guard

**Дата проекта:** 2026-10-09. **Статус:** реализация и изолированные offline-тесты; **применение на реальном VPS, reboot, UFW/netfilter, Panel→Node и VPN-клиент ещё не проверены**. На production применять только после canary/snapshot и проверки консоли хостера.

## 1. Что именно интегрировано

Upstream: <https://github.com/Flecksis/rkn-guard> (ветка `master`).
Источник сетевых данных, на который ссылается документация upstream: <https://github.com/shadow-netlab/traffic-guard-lists/blob/main/public/government_networks.list> (ветка `main`).

В Node_Install **НЕ встраивается бинарник, Go-код, интерактивное меню и установочный shell-скрипт `rkn-guard`**. Их прямой запуск может менять чужие firewall-состояния, ставить собственные systemd-сервисы и добавлять IPv6-правила, тогда как Node_Install имеет строгий контракт IPv4-only и управляет UFW самостоятельно. Вместо этого встроена **реализация совместимого принципа защиты** (подтверждённый upstream источник CIDR → ipset `hash:net` → узкая цепочка iptables внутри UFW). Лицензия/исходники Flecksis не копировались.

Это не полная функциональная замена upstream-продукта: нет его меню/агрегированной статистики, IPv6, arbitrary source URL, глобального блокирования SSH/2222 или автообновления исполняемого кода. Эти ограничения намеренные.

## 2. Контракт безопасности

- Только входящие **новые TCP-соединения на порты 80 и 443**, направленные через `ufw-before-input`; правила существующих SSH и Node API **не изменяются**.
- `ESTABLISHED,RELATED` → `RETURN`, затем `panel_ipv4` → `RETURN`, затем CIDR-блоклист → `DROP`.
- `RETURN` в собственной цепочке **не даёт общего разрешения в UFW**: доступ на 2222 и других портах продолжает регулироваться прежними правилами.
- Только IPv4. IPv6 из upstream-списка намеренно пропускается; `ip6tables` не меняется.
- Входные IP-подсети строго проверяются (IPv4, не зарезервированные, префикс не шире `/16`, лимит 65536 записей, 4 MiB загрузки, минимум 100 сетей; резкие скачки размера списка отклоняются).
- IP панели **не записывается в UFW managed-блок и не фиксируется в коде**. При каждом `prepare`/`update` считывается `panel_ipv4` (1–16 IPv4) из `/etc/vkarmani-node/config.json`, обновляется отдельный `ipset` `vkarmani_rkn_pan4`. До заменяемого blockset выполняется его swap.
- Важно: этот динамический IP касается **только исключения из RKN-блокировки**. Ранее созданные разрешающие правила UFW для Node API TCP/2222 и внешняя ACL хостера не редактируются. При смене IP панели требуется отдельно согласовать эти существующие ACL.
- Смена списка не переписывает основной `iptables INPUT`, UFW user.rules, правила Fail2ban, Nginx, Docker или Xray.
- ВАЖНО: TCP/80 используется для Let's Encrypt HTTP-01. Если IP валидатора ACME неожиданно попадёт в обновлённый список, сертификат может не продлиться. После включения и периодически проверяйте `certbot renew --dry-run` в согласованном окне; не запускайте этот non-read-only тест автоматически в ежедневном обновлении списка. Порт 443 может также отсеять легитимного клиента из заблокированной подсети — это ожидаемый эффект фильтра, а не скрытая изоляция VPN.

## 3. Порядок и периодичность

На чистой VPS пакет `ipset` ставится через подписанный системный репозиторий с остальными узловыми пакетами. После успешной локальной проверки основной ноды установщик разворачивает `rkn_guard.py` + systemd, создаёт/проверяет ipset, добавляет **строго маркированный** UFW-фрагмент, проверяет `iptables-restore --test`, применяет `ufw reload` и пытается получить первый список. После добавления фильтра повторно запускается штатная preboot-проверка ноды; при ухудшении она отключает RKN-фрагмент и повторяет проверку, а при неподтверждённом rollback не допускает auto-reboot.

Если первый HTTP-запрос неудачен, UFW/нода продолжают работать: активный список остаётся прежним (или пустым при первой установке), а система повторит попытку по таймеру. При неудаче изменения правил UFW попытка выполняет rollback исходных байтов `before.rules` и повторный `ufw reload`; если это невозможно, результат **не считается проверенным**, установщик останавливается до auto-reboot и нужен доступ к консоли VPS.

При загрузке системы сервис `vkarmani-rkn-prepare.service` восстанавливает проверенный список из локального кеша и актуализирует исключения панели **до** UFW. Чтобы UFW не стартовал до создания ipset, добавляется конкретный собственный drop-in `ufw.service.d/90-vkarmani-rkn.conf` (`Requires`/`After`). При повреждённой конфигурации панели подготовка очищает блокирующий набор — **fail-open для фильтра**, не блокирует запуск UFW. Если сама подсистема ipset неисправна, UFW может не загрузить before.rules; это требует VPS canary/hoster console и мониторинга.

`vkarmani-rkn-update.timer`: `OnCalendar=daily`, `Persistent=true`, `RandomizedDelaySec=20min`, `AccuracySec=5min`. На каждом выполнении данные скачиваются по HTTPS из ветки `main` списка `shadow-netlab/traffic-guard-lists`, валидируются и атомарно активируются через `ipset swap`. **Изменения списка в GitHub не моментально, но автоматически попадут на VPS при следующем успешном ежедневном обновлении**. Если GitHub недоступен, прежние данные сохраняются. В журнале указана причина отказа.

**Важно: исполняемый код Flecksis/rkn-guard не обновляется автоматически** — это потенциально небезопасное удалённое выполнение с правами root. Так же и локальный Node_Install сам не скачивает новый release-код.

## 4. Команды оператора

```bash
# Для готовой управляемой ноды Node_Install 2.5.2 либо 2.5.3,
# без повторной установки RemnaNode/Docker/Nginx/SSH/GRUB:
sudo bash install.sh --enable-rkn-guard

# Статус блока/источника/IP панели/последней успешной загрузки:
sudo bash install.sh --rkn-status
# либо напрямую (на установленной ноде):
sudo vkarmani-rkn-guard status

# Обновление немедленно (требуется интернет):
sudo bash install.sh --rkn-update

# Если изменился panel_ipv4: перечитать исключения, интернет не нужен.
# При невалидном config.json возвращает код 1, не блокируя SSH/UFW:
sudo bash install.sh --rkn-sync-panel

# Экстренно отключить ТОЛЬКО RKN-фильтр, не сбрасывая UFW:
sudo bash install.sh --rkn-disable

# Таймер и журналы:
systemctl list-timers --all vkarmani-rkn-update.timer
systemctl status vkarmani-rkn-prepare.service vkarmani-rkn-update.timer
journalctl -u vkarmani-rkn-update.service -n 100 --no-pager
journalctl -u vkarmani-rkn-prepare.service -b --no-pager

# Проверка сетевого фильтра без записи в конфиги:
sudo ipset list vkarmani_rkn_blk4
sudo ipset list vkarmani_rkn_pan4
sudo iptables -S VKARMANI_RKN
sudo iptables -S ufw-before-input
sudo ufw status verbose
```

`--rkn-disable` оставляет сохранённые данные и скрипты для повторного `--enable-rkn-guard` и **не удаляет системный пакет `ipset`**. Он удаляет только свой маркированный UFW-блок, выключает таймер и снимает своё UFW drop-in. Не очищайте UFW глобально, `iptables -F`/`ipset destroy` вручную не применяйте на production.

## 5. Владение и резервные копии

| Расположение | Содержимое |
|---|---|
| `/usr/local/lib/vkarmani-node/rkn_guard.py` | встроенный Python-модуль, root:0700 |
| `/usr/local/sbin/vkarmani-rkn-guard` | управление, root:0755 |
| `/var/lib/vkarmani-node/rkn/current-v4.txt` | последнее успешно активированное IPv4-содержимое |
| `/var/lib/vkarmani-node/rkn/last-check.json` | дата/контрольная сумма/число сетей; нет приватных ключей |
| `/var/lib/vkarmani-node/rkn/ufw-before-pre-rkn` | резервная копия UFW before.rules перед применением |
| `/etc/ufw/before.rules` | только блок `BEGIN/END VKARMANI-RKN-GUARD` |
| `/etc/systemd/system/vkarmani-rkn-*` | вспомогательные сервисы и ежедневный таймер |
| `/etc/systemd/system/ufw.service.d/90-vkarmani-rkn.conf` | зависимость UFW от подготовки ipset |

Перед включением на работающем production получите snapshot VPS и проверенную off-host конфигурационную backup-копию (`sudo bash install.sh --backup` для управляемой ноды 2.5.2+). Данная backup-команда **не заменяет snapshot VPS**. После установки убедитесь, что IP панели доступен по 2222 и свежая клиентская сессия подключается по 443. Даже при локально успешном `--rkn-status` это не проверяется автоматически.

## 6. Обязательный upstream-review при КАЖДОЙ следующей сборке Node_Install

**НЕ удалять этот раздел и ссылку из следующих README/CHANGELOG/release-checklist.** Проверка изменений upstream — обязательная часть подготовки каждой новой версии.

1. Открыть <https://github.com/Flecksis/rkn-guard> и проверить `master`, новые коммиты, tags/releases, README, `cmd/main.go`, `internal/service/iptables.go`, `ipset_replace.go`, `downloader.go`, `systemd_templates.go`, `ufw_rules.go`, инсталлер и тесты. Сопоставить с предыдущим зафиксированным upstream SHA и выписать функциональные изменения, исправления безопасности, новые зависимости, порядок UFW и новые источники.
2. Открыть <https://github.com/shadow-netlab/traffic-guard-lists> и убедиться, что именно эта ветка/файл всё ещё официально используются upstream; проверить формат списка, сохранность HTTP URL, признаки переименования/переноса, новые форматы и ограничения. Не переключать источник автоматически на неизвестный URL.
3. Разобрать upstream-изменения и при необходимости **внести вручную проверенные улучшения** в `integrations/rkn_guard.py`, сгенерированный payload `VK_RKN_GUARD_PY` в `install.sh`, инструкции и тесты, с обязательной сохранностью IPv4-only/SSH/2222/UFW/NET_ADMIN/REALITY/Selfsteal.
4. Повторно прогнать offline-тесты, mock UFW rollback, проверку системных зависимостей и `SHA256SUMS`, затем canary VPS: boot ordering, UFW reload, offline GitHub, изменение panel IP, успешный внешний Panel→Node, реальный VLESS клиент и возврат после `--rkn-disable`.
5. В release notes указать **ссылку на проверенный upstream commit SHA и на источник списков**, найденные изменения, применённые/отложенные обновления и ограничения. Не утверждать «rkn-guard auto-updated», если обновлялись только списки.

На дату разработки был просмотрен upstream Flecksis `master` с HEAD `34ed9c13bfa1280d32226164084da25b33a4c155`. Сверять эту запись с живой GitHub-историей при следующей сборке, не считать её закреплённой актуальной версией навсегда. GitHub-данные меняются независимо от Node_Install.

## 7. Ограничения проверки

Проведены только изолированные tests/mock-проверки Python и всей поставки, Bash-синтаксис и файловый манифест. Не выполнялись `ipset`, `ufw reload`, `iptables-restore`, `systemctl` на реальном сервере; нет проверки bootstrap до UFW/reboot, ресурсов ядра `xt_set`, успешного доступа панели, реального VPN-трафика и доступности GitHub **именно с каждого VPS**. Не считать production-ready по одному успешному unit test.
