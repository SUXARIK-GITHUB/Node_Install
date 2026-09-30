# 🧪 Отчёт о проверках 2.0.2

Дата: **2026-09-30**. База — полный предоставленный архив 2.0.1, SHA256 его `install.sh`: `f1e10cb9ff5b5c2c3014cf6f318b4ae6db20fa4140567d558dddd2b5f1913779`. Все 178 старых тестов повторно прошли до изменений; incident-fixture также воспроизвёл ошибку прежнего grep.

**226 отдельных тестов — PASS, 0 пропусков.** 178 сохранённых + 48 новых, а не 226 новых сценариев. Три последовательных прогона финального исходного файла: **6.272 / 6.226 / 6.235 секунды**. Повторение не является долговременным soak test. На отдельно распакованном финальном архиве полный набор также проверяется перед выдачей; машинный журнал поставки — [RELEASE_VALIDATION](RELEASE_VALIDATION.json).

Предыдущие материалы сохранены дословно: [отчёт 2.0.1](history/TEST_REPORT_2.0.1.md), [validation 2.0.1](history/RELEASE_VALIDATION_2.0.1.json), [отчёт 2.0.0](history/TEST_REPORT_2.0.0.md). Их результаты — исторические, не новые измерения. Относительные ссылки внутри дословных исторических копий отражают прежнее расположение файлов.

## Среда и границы

Контейнер Debian 13, amd64, kernel 6.18.44, Python 3.13.5, OpenSSL 3.5.5, cryptography 46.0.4, PyYAML 6.0.3, Nginx 1.26.3, Node.js 22.16.0. Это не Ubuntu VPS и не запуск реального установщика до конца. Полный `vkarmani_main` не вызывался; доступны только source-safe функции, извлечённые helpers и узкий фрагмент preflight с перенаправленным каталогом fixtures.

Правила на вашей VPS не применялись/не менялись. Nginx запускается только в отдельном временном каталоге с локальными сокетами и тестовыми сертификатами; production secrets не используются. Docker/Compose/sysctl/firewall boundary остаются mock, PTY/процессы/локальные TLS/tar — реальные внутри контейнера.

## Матрица

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
| `test_ufw_preflight.py` | 48 | Точные fixtures инцидента, настоящий Bash gate, input/output/forward IPv4/IPv6, modified helpers/metadata/custom rules, структура/тип файла/ошибка awk, отсутствие записи и firewall-вызовов | Реальный Bash/awk и временные файлы; kernel firewall не применяется |
| **Всего** | **226** | | |


## Главные результаты этого исправления

Точные `user.rules` и `user6.rules` из предоставленного вывода: **старый predicate ошибочно останавливает; новая функция и настоящий install-gate проходят**. Сохранённое пользовательское правило меняет результат на STOP до следующего шага. Новый формат не включает IPv6: проверяется только текст сохранённого файла.

Отдельные тесты отклоняют inbound/outbound/forward для обеих семей, настоящий `ufw limit` с input jump, изменённые limit helpers, неизвестные цепочки/директивы/таблицы/политики, tuple без rule, пустой/обрезанный/дублированный файл, symlink/FIFO/каталог и ошибку awk. Зафиксирована неизменность SHA256, mode, mtime и inode входных файлов на успешном и неуспешном пути. Подставленные запрещающие ufw/nft/iptables/systemctl wrappers не вызываются.

Все прежние отрицательные проверки TLS/HTTP2, процессы/таймауты, Nginx crash/recovery, 128 probes через 16 workers, PTY и mock image transactions также снова прошли. Это не измерение VPN throughput и не 128 одновременно обслуживаемых VPN-пользователей.

## Команда установки из README

Отдельно исполнены четыре изолированных сценария bootstrap: корректный файл 2.0.2, прежний 2.0.1, обрезанный файл и имитация curl timeout. HTTPS-загрузка заменена копированием локального fixture; финальный `exec bash install.sh` перехвачен без запуска полной установки. Только правильный файл достигает этой точки. SHA mismatch выводит явный STOP; при сетевой ошибке/неполной загрузке запуск не происходит. Это не реальный запрос GitHub.

## Целостность и поставка

Проверяются `bash -n` основного и генерируемых scripts, Python compile, инертные help/version/source, три prompt, синтаксис текущих Bash-блоков Markdown без их исполнения, YAML workflow, относительные file-links текущей документации (не исторических копий). Fragment anchors не проверяются. README содержит SHA256 именно финального `install.sh`.

Проверяются сохранность всех исходных путей и точное совпадение всех файлов `.git` с архивом 2.0.1, `git diff --check`, `git fsck --full`, manifest обычных файлов, отсутствие лишних кешей/логов, ZIP CRC/уникальность и безопасность путей. ZIP распаковывается отдельно; hashes сверяются и тесты повторяются. ZIP checksum хранится снаружи ZIP. Итоговые факты: [RELEASE_VALIDATION](RELEASE_VALIDATION.json).

## Что НЕ проверено

Нет полного install на Ubuntu 22.04/24.04 или Debian 12/13 VPS; нет arm64, GRUB/reboot, настоящего UFW/Fail2ban/SSH/PAM, Docker daemon/Compose, Xray, панели, ACME issuance/renewal или клиентского RAW REALITY. Нет проверки external provider firewall, международных маршрутов, реальных power-loss/OOM/disk-full, длительной нагрузки и автоматического перехода установленной 2.0.1 на 2.0.2.

ShellCheck отсутствует; `bash -n` не заменяет его. Offline `systemd-analyze verify` из предыдущего отчёта здесь не повторялся. GitHub Actions не запускался. Текущий raw `main/install.sh` не удалось независимо получить/hash-проверить; публикация GitHub не выполнялась. Новая проверка намеренно не принимает неизвестные варианты saved-UFW templates без анализа и не доказывает чистоту всех before/after/provider firewall policies.

Итого PASS доказывает прохождение перечисленных локальных сценариев, **не отсутствие всех возможных ошибок**. Для этой ноды устранён подтверждённый preflight blocker; результат следующего реального запуска остаётся предметом проверки.

## Воспроизведение

```bash
bash tests/run.sh
```

Нужны Python 3.10+, cryptography, PyYAML, Bash/awk; Nginx и Node.js нужны для соответствующих интеграционных тестов. Без binary тесты могут явно пропускаться — такой результат нельзя выдавать за текущий прогон с 0 пропусков. Набор не запускает установку на тестируемом хосте.
