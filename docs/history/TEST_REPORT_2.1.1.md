# TEST_REPORT — Node_Install 2.1.1

Дата подготовки: 2026-09-30.

## Изменение под проверкой

2.1.1 меняет production-код только в части координации APT/dpkg и номера выпуска. Перед `dpkg --audit` и обязательными APT-командами добавлено ожидание фактических системных lock до 1800 секунд; `DPkg::Lock::Timeout` внутри отдельной попытки — 15 секунд для гонки. Установщик не удаляет lock-файлы, не завершает `apt`/`dpkg`/`unattended-upgrade` и не отключает автоматические security updates.

VLESS RAW REALITY, Selfsteal, Nginx, UFW/Fail2ban, SSH, Docker Compose layout и три обязательных вопроса не менялись.

## Полный набор

**377 тестов, 0 failures, 0 errors, 0 skips.**

Выполнены два отдельных полных запуска:

| Среда запуска | Результат |
|---|---|
| root | `Ran 377 tests ... OK` |
| UID 1000, без sudo и дополнительных групп | `Ran 377 tests ... OK` |

Логи подготовки сохранены вне release manifest при сборке как `full-tests-1.log` и `full-tests-uid1000.log`; в финальный проект они не требуются для работы установщика.

## Новые регрессии 2.1.1

Добавлен `tests/test_211_apt_coordination.py` — 6 проверок:

1. Контракт общего ожидания 1800 секунд, период статуса 30 секунд, poll 5 секунд и короткий внутренний lock-timeout 15 секунд.
2. В APT-coordination коде нет удаления системных dpkg/apt lock и нет `kill`/`pkill`/`killall` package-manager процессов.
3. Fixture формата реального `lslocks` с владельцем `unattended-upgr` ждётся, затем проходит после освобождения.
4. Превышение общего бюджета возвращает явный временный отказ и не меняет lock.
5. Узкая lock-race повторяется, а произвольная APT-ошибка с тем же кодом 100 не маскируется повтором.
6. `dpkg --audit` вызывается после ожидания lock и до сбора пользовательских значений.

Также обновлён изолированный package-plan test: production fragment теперь вызывается через настоящий `vk_apt_run`, а fake APT остаётся тестовым и не запускает dpkg.

## Сохранённые проверки

Все 371 тест 2.1.0/ci-fix2 сохранены: валидация, терминальный ввод ровно трёх значений, firewall, SSH, DNS, APT solver, NTP provider, Chrony/NTS, atomic writes/ENOSPC/EIO, backup, maintenance/rollback, socket recovery, Nginx/TLS1.3/HTTP2, cover-site, resource snapshot, CI contracts, Node 12 HKDF compatibility и Git safe.directory contract.

## Что фактически не проверено

- Полная установка **2.1.1** на настоящей VPS после новой APT-координации.
- Реальное ожидание живого `unattended-upgrades` установщиком 2.1.1 на Ubuntu — причиной изменения послужил реальный инцидент 2.1.0, но новый код на той VPS не запускался.
- Полный install/reboot/panel/client на Ubuntu 26.04 и arm64.
- Реальный Docker/Xray/ACME/UFW/Fail2ban в среде подготовки этой версии.
- Длительная нагрузка, OOM/power-loss, маршруты разных стран и внешняя фильтрация.

Проверенная пользователем работа нескольких нод 2.1.0 на Ubuntu 24.04 не подменяет пилот 2.1.1.

## Перед массовой раскаткой

Сначала одна чистая Ubuntu 24.04 VPS: snapshot/консоль → установка 2.1.1 → reboot → `vkarmani-node-check` → подключение панели → реальный VLESS RAW REALITY клиент. Отдельно желательно воспроизвести ситуацию, когда `apt-daily-upgrade` уже держит lock, и подтвердить `APT_WAIT` без вмешательства в чужую транзакцию.

Подробности алгоритма: [APT_LOCK_COORDINATION_2.1.1](APT_LOCK_COORDINATION_2.1.1.md).
