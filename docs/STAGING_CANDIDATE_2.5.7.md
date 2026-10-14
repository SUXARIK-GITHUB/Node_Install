# Node_Install 2.5.7 · локальный staging-кандидат от 14.10.2026

**Не опубликовано в GitHub. Не предназначено для production/технички/существующего каскада.**

## Происхождение

Основа: архив Node_Install_2.5.6.zip с Git HEAD `e0e076678d92daa074daa8289db2df3a3a395a42`. Ветка GitHub не изменялась. Проверки и состояние сборки фиксируются во внешнем отчёте с SHA256 выдаваемого ZIP. Предыдущий несуществующий 3.0.0-rc.1 не использовался.

## Что реально реализовано

- `install.sh`: RKN safe shutdown вместе со штатным и аварийным путями, общий installer lock для CLI операций, отказ без ложного PASS при daemon-reload и иных сбоях.
- `integrations/rkn_guard.py` + встроенная копия: корректная boot-degradation если ipset не удалось подготовить, сохранение основной UFW конфигурации, явно разделённый статус данных и правил.
- `integrations/docker_local.sh` + встроенная копия: локальный Unix socket, пустой Docker CLI config и очищенное окружение вместо DOCKER_HOST/DOCKER_CONTEXT оператора. Встроенная Python-диагностика и обслуживание обновлены.
- `PY_CAPS` (в check helper): строгий no-new-privileges и негативные комбинации.
- `PY_HELPER` (в installer): аудит профиля обрабатывает оба заявленных alias.
- `integrations/nightly_maintenance.py` + встроенная копия: системный таймер новых ordinary-нód и локальный перезапуск только работающего контейнера.
- `docs/history/`: исправлены относительные пути к действительно существующим документам; исходное содержимое результатов не переименовано и не пересчитано.

## Nightly и временное окно

По Europe/Moscow: `OnCalendar=*-*-* 03:00:00 Europe/Moscow`, `RandomizedDelaySec=59min`, `FixedRandomDelay=yes`, `Persistent=false`, `AccuracySec=1s`. Случайный разнос с фиксированным seed может совпасть у двух серверов; координация каскадной пары пока отсутствует.

Плановая операция использует общий установочный lock, игнорирует запуск вне 03:00–03:59, не запускает остановленный администратором контейнер, создаёт at-most-once отметку даты до restart, выполняет только `/usr/local/sbin/vkarmani-docker-local restart --time 25 remnanode`. Проверяет Docker running/host, `nginx -t` и активность UFW до/после; **не проверяет удалённую аутентификацию, публичный HTTPS и живой VPN-выход**. Настройка преднамеренно затрагивает только новые ordinary-ноды, не мигрирует существующие.

## Не реализовано (обязательные блокирующие требования полного ТЗ r2)

- Согласованное создание/назначение peer в панели и полноценный вход→выход VLESS/REALITY маршрут; анти-DIRECT fail-closed, DNS policy и двухузловая проверка внешнего IP.
- Ролевое объединение полного функционала ordinary/cascade entry/cascade exit и транзакционная смена peer.
- Nginx TCP stream перед REALITY со сквозными клиентскими проверками; шесть новых публичных сайтов.
- Полный stateful backup/restore новой роли, проверка реального восстановительного пути.
- Live Docker/systemd/UFW/netfilter на независимой одноразовой VM, reboot, TLS/SNI/client+Panel connectivity, 24h soak.

**Поэтому релиз не может считаться production-ready.** Исправления critical предназначены для code review и стендовой оценки.

## Наблюдения и предостережения

- Команда `--rkn-disable` должна запускаться только после snapshot и доступа к внешней консоли. Результат локального mock-теста недостаточен.
- Если подготовка RKN отклонена, base UFW должен оставаться рабочим, а scanner-filter будет DEGRADED и потребует диагностики источника/ipset. Нельзя писать «защищено», если нет списка.
- Docker socket должен существовать локально; DOCKER_CONFIG root не используется и не изменяется. Для приватных registry отдельная поддержка не добавлялась.
- Восстановление config-only backup не восстанавливает Docker volumes/layers, объекты панели, сертификаты вне комплекта. Перенос роли и pairing **не реализован**, не пытаться восстановить выход как обычный node.

## Контрольный сценарий в изолированной VM

1. Snapshot и restore-test, консоль провайдера, проверенная независимая SSH-сессия.
2. В исходниках `bash -n install.sh`, `python3 -m unittest discover -s tests -v`, `sha256sum -c SHA256SUMS`.
3. Установка только на *новую* тестовую VPS, затем проверка `systemctl status ufw nginx docker`, `ufw status verbose`, `ss -lntup`, `nginx -t`, `docker compose config`, `docker inspect remnanode`.
4. Отдельный тест RKN failed ipset/daemon-reload/disable/reboot на snapshot VM с доступом через консоль. При сбое остановить миграцию, снять диагностические данные, восстановить snapshot; никогда не использовать `ufw disable`/`iptables -F`.
5. Проверка `--maintenance-status`, ручного отключения timer, пропуска окна, а также restart только контейнера в ночном окне и сквозного canary клиента.
6. Rollback на snapshot или на файловую копию до любых изменений; не считать config-only архив полным OS откатом.

Подробная таблица требований и статусов: [Матрица ТЗ r2](TZ_R2_IMPLEMENTATION_MATRIX.md).

## Внешние источники

- [systemd Requires/Wants](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- [Docker CLI flags/env](https://docs.docker.com/reference/cli/docker/)
- [Remnawave server routing: demonstration only](https://docs.rw/learn-en/server-routing/)
- [Xray REALITY](https://github.com/XTLS/REALITY)
