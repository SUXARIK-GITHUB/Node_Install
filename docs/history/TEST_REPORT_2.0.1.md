# 🧪 Отчёт о проверках 2.0.1

Дата: **2026-09-30**. Проверяется фактический `install.sh` этой поставки. База сравнения — полный архив 2.0.0; его 74 теста повторно прошли до внесения изменений. Предыдущий отчёт сохранён без сокращений в [history/TEST_REPORT_2.0.0.md](history/TEST_REPORT_2.0.0.md).

**Итог: 178 отдельных тестов — PASS, 0 пропусков в локальных контрольных прогонах.** Пять последовательных повторов полного набора также завершились успешно: **8,167 / 8,119 / 7,538 / 7,499 / 7,389 секунды**. Это пять повторов тех же 178 сценариев, а не 890 разных тестов и не долговременный production soak test.

Полная установка не запускалась; никакая production-нода не изменялась. Тесты не доказывают доступность из России или другой страны, работоспособность конкретного RemnaNode image и отсутствие любых ошибок.

## Среда и границы полномочий

Debian 13, amd64; kernel 6.18.44; Python 3.13.5; OpenSSL 3.5.5; cryptography 46.0.4; PyYAML 6.0.3; Nginx 1.26.3; Node.js 22.16.0. Тестирование — в контейнере, не в полноценной VM. Нет работающего systemd init, Docker/Compose daemon, sshd, fail2ban-client и ShellCheck. Нет прав CAP_NET_ADMIN/CAP_SYS_ADMIN/CAP_SYS_BOOT/CAP_SYS_MODULE для испытания реального firewall, reboot, модулей и host networking.

Nginx запускается отдельным процессом с временными `-p/-c`, локальным Unix socket, synthetic site/CA; системные `/etc/nginx` и службы не меняются. API TLS — временный loopback listener с тестовыми сертификатами, не реальный RemnaNode. Process/PTY/tar tests работают только с временными файлами. Рабочие secrets пользователя не использовались и не запрашивались.

## Матрица автоматических тестов

| Файл | Число | Что фактически проверено | Тип |
|---|---:|---|---|
| `test_static.py` | 12 | Bash/Python синтаксис, inert CLI/source, три prompt, Compose/Fail2ban/boot шаблоны, отсутствие mass-upgrade/prune | Parser/структурные проверки |
| `test_validation.py` | 27 | Валидация входов/crypto/key pairs, DNS-конфликты и выбор IPv4, SSH rendering | Реальная локальная криптография/файлы; DNS/SSH-сервер не live |
| `test_network.py` | 11 | Sysctl parser, readback, BBR/fq fallback, неподдержанные/повреждённые состояния | Временный proc-tree/имитация команд |
| `test_tls_integration.py` | 11 | Реальные TLS 1.3/fragmented ClientHello, CA/leaf/SNI negative cases, отсутствие mTLS панели; Node.js HKDF; Nginx PROXY/HTTP1/HTTP2 | Реальные локальные sockets/Nginx/Node.js |
| `test_maintenance.py` | 13 | Commit/rollback/pending, Compose drift, digest policy, checksum/path, redacted errors | Docker mock; реальные private files и shell error |
| `test_firewall.py` | 23 | Missing SSH/80/443/API rules, broad allows, extra rules, INPUT bypass/default, source restrictions, временные SSH-only bans | Parser на synthetic iptables output; UFW не применяется |
| `test_profile_policy.py` | 23 | Один VLESS/RAW/REALITY, собственный SNI/target, aliases, отказ других протоколов/fallback/tunnel outbounds; flow не изменяется | Фактический Python helper на synthetic JSON |
| `test_socket_prepare.py` | 9 | Отсутствующий/stale/live socket, symlink, чужой UID, EACCES, наблюдаемая смена inode | Реальные Unix sockets/файлы; UID/часть syscall faults имитируются |
| `test_faults.py` | 13 | Descendant cancellation, SIGTERM/TERM-ignore, FD leaks; ENOSPC/EIO/atomic permissions/fsync | Реальные процессы/файлы; инъекция syscall errors |
| `test_nginx_faults.py` | 10 | 96/128 KiB и превышение лимита; leaf mismatch; три SIGKILL/recovery-цикла; live socket; 404/missing PROXY; параллельные probes | Реальный изолированный Nginx |
| `test_backup.py` | 5 | Tar + restore synthetic config, modes/symlink/checksum; truncated archive; tar/fsync failure; запрет overwrite | Реальный tar/filesystem, инъекция I/O errors; не restore всей VPS |
| `test_update_faults.py` | 8 | Unknown Compose apply, SIGTERM, registry/JSON/disk failures, commit failure, общий health deadline | Docker mock/виртуальные часы, реальные transaction files |
| `test_input_terminal.py` | 5 | Три вопроса, скрытый ключ 8192 байт, нормализация домена; восстановление TTY после TERM; invalid secret/no TTY/repeat config | Реальный PTY; выполняются только input functions |
| `test_protocol_faults.py` | 8 | HTTP/2 non-200/DATA-before-headers/RESET/bad SETTINGS/oversize/continuation; slow drip deadline; TCP accept без TLS | Synthetic HTTP/2 peer + реальные socketpair/loopback faults |
| **Всего** | **178** | | |

Из installer извлекаются реальные heredoc payload; отдельная «улучшенная копия», не используемая установщиком, не подставляется в тесты. Полный `vkarmani_main` в тестах не выполняется. Старые тесты сохранены; изменены только ожидаемая версия и subprocess-boundary тест, который теперь действительно запускает безвредный локальный процесс для проверки редактирования ошибки.

## Измеренные аварийные результаты

**Старый firewall:** при наличии одного правильного API allow и отсутствии SSH/HTTP/REALITY allow код возвращал 0. Новая проверка отклоняет такие состояния.

**Старый HTTP/2 checker:** реальный исправный Nginx с cover 96 KiB — TimeoutError примерно через 5,02 с. Новый checker возвращает flow-control credit; 96 и 128 KiB проходят. Более крупная страница даёт явный лимит, не молчаливое зависание. Основа протокола: [RFC 9113](https://datatracker.ietf.org/doc/html/rfc9113).

**Старый subprocess timeout:** фоновый потомок создавал маркер после сообщения COMMAND_TIMEOUT. Новые тесты проверяют отсутствие такого позднего эффекта, эскалацию TERM → KILL и отсутствие утечки FD после 30 последовательных команд. Это не отмена уже принятой Docker daemon операции.

**Nginx crash:** три цикла SIGKILL → отказ connect на оставшемся socket → проверяемая очистка → запуск → успешные HTTP/1.1+HTTP/2. Отдельно активный socket не удаляется, при подмене/неопределённой liveness выполнение останавливается.

**Конкурентность:** 128 Selfsteal-проверок через ThreadPoolExecutor с **16 workers**. Каждая проверка устанавливает две TLS-сессии; это **256 локальных TLS/HTTP-сессий** в данном тесте. Это не 128 одновременно обслуживаемых VPN-пользователей, не iperf и не оценка скорости международного канала.

**Backup:** реальное создание tar, распаковка в отдельный временный каталог, сравнение synthetic content, modes и symlink, сверка SHA256; повреждённый tar отвергается. Живые `/etc`, Docker layer/volume, панель и весь сервер не архивировались/не восстанавливались.

**TTY:** реальный управляющий терминал подтверждает отключение echo до prompt, передачу 8192-байтового synthetic ключа, возвращение echo/canonical mode при завершении и SIGTERM. Вторая/третья строки не требуют четвёртого вопроса. Структуру настоящего SECRET_KEY отдельно проверяют crypto-тесты.

## Дополнительная проверка service-конфигурации

`systemd-analyze verify` выполнил offline разбор distro `nginx.service` + нового drop-in в отдельном временном root. Код возврата **0**. Exec paths и targets в этом root были синтетическими заглушками только для dependency/exec-path проверки; они не запускались. Это **не проверка** реального systemd boot, restart rate limiting, ожидания адреса у провайдера или OOM recovery.

## Что не выполнено

**Нет end-to-end установки** на Ubuntu 22.04/24.04 либо Debian 12/13; нет arm64; нет boot/GRUB/reboot/power-loss, live UFW/Fail2ban/PAM/password SSH, Docker Compose/config/up/pull/host bind/capabilities, реального Xray `run -test`, аккаунта ACME/renewal, API/mTLS настоящей панели и VLESS-клиента.

Не выполнялись международные пробы, отключение внешней сети, реальные провайдерские ограничения, VPN download/upload benchmark, долгий нагрузочный/soak test, failover между VPS, реальная disk-full/OOM авария всего сервера. ENOSPC/EIO здесь — целевые инъекции, а не заполнение rootfs. Нет автоматической in-place миграции работающей 2.0.0.

Проверки `sshd -t`, `fail2ban-client -t`, `docker compose config`, `dockerd --validate`, Certbot dry-run, Xray run-test предусмотрены сценариями установки/эксплуатации, но здесь не исполнялись на настоящих службах. Bash parser не заменяет ShellCheck. GitHub Actions подготовлен прежним выпуском и охватывает новые test-файлы через discovery, но удалённо не запускался.

Истинный runtime-статус произвольной VPS нельзя вывести из этих 178 PASS. Неподдержанные хостерские образы/NAT/загрузчики намеренно не адаптируются вслепую.

## Повторяемость

```bash
bash tests/run.sh
```

Нужны Python 3.10+, cryptography, PyYAML; Nginx и Node.js — для интеграционных проверок. Без соответствующего binary будут явные skip; такой прогон нельзя выдавать за местный результат «0 пропусков». Используйте отдельную рабочую папку исходников/CI, не запуск установщика в production ради тестов.

## Поставка и контроль целостности

Перед выдачей выполняются проверка Bash-блоков Markdown без исполнения, relative file links, README SHA256, manifest полного дерева обычных release-файлов (кроме `.git` и самого manifest), `git diff --check`/`git fsck --full`, сравнение исходной `.git` и отсутствие потерянных исходных файлов. ZIP проходит CRC/duplicate/path-проверки, отдельную распаковку, повторную сверку manifest и запуск всех 178 тестов на распакованном дереве. Результаты финального release gate сохранены в [RELEASE_VALIDATION.json](RELEASE_VALIDATION.json).

В runtime отсутствуют необходимые сервисы для live deployment; никакие файлы отчёта не объявляют такой deployment выполненным. Snapshot/console/проверенный restore и canary остаются обязательными перед массовой раскаткой.
