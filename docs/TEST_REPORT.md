# 🧪 Отчёт о проверках 2.0.3

Дата: **2026-09-30**. База — предоставленный полный архив 2.0.2. SHA256 исходного `install.sh`: `373f56cd7d7bb38b4f93493251d6ba6fbee85ea4228886be5488b17ab7297105`. До правок все **226** прежних тестов прошли за 6.366 секунды. Присланный журнал отдельно выявил отсутствие покрытия конфликта выбора time-daemon в компонентной APT-транзакции; прежние PASS этот дефект не опровергают.

**304 отдельных теста — PASS, 0 пропусков:** 226 сохранённых + 78 новых, а не 304 новых сценария. Текущие последовательные прогоны после финальной правки основного кода: **12.596 / 12.763 / 13.081 секунды**. Полный набор повторяется после окончательной подготовки и отдельной распаковки ZIP; итог упаковочных проверок — [RELEASE_VALIDATION](RELEASE_VALIDATION.json). Повторение набора не является долговременным soak test или приёмкой VPS.

Исторические отчёт и validation 2.0.2 сохранены дословно: [TEST_REPORT_2.0.2](history/TEST_REPORT_2.0.2.md), [RELEASE_VALIDATION_2.0.2](history/RELEASE_VALIDATION_2.0.2.json). Также сохранены прежние отчёты 2.0.0/2.0.1. Их цифры и ссылки относятся к моменту соответствующей поставки, не являются новыми измерениями.

## Среда и безопасная изоляция

Контейнер Debian 13, amd64/x86_64, kernel 6.18.44; Bash, Python 3.13.5, OpenSSL 3.5.5, cryptography 46.0.4, PyYAML 6.0.3, Nginx 1.26.3, Node.js 22.16.0, APT 3.0.3. Это не Ubuntu 24.04 VPS. Полный `vkarmani_main`, реальная настройка time/SSH/firewall/Docker/GRUB, deploy и reboot **не выполнялись**.

Пакетные тесты настоящего APT задают отдельные `APT_CONFIG`, dpkg status, sources, lists/cache/logs и локальный `file://`-индекс во временном каталоге. Запросов к сетевым репозиториям и установки `.deb` нет. Метаданные моделируют `Provides/Conflicts: time-daemon`; не заявляется полная эквивалентность Ubuntu Noble dependencies. Это позволяет проверять настоящее поведение решателя/`--no-remove`, не затрагивая установленную систему.

Новые Python helpers используют только стандартную библиотеку. В tests fixture старого `node_helper.py` — публичный программный код из 2.0.2, не секрет и не копия runtime-конфигурации пользователя. Реальный SECRET_KEY из журнала отсутствует и не использовался.

## Матрица новых проверок — 78

| Область | Тестов | Что фактически проверялось |
|---|---:|---|
| `test_time_provider.py` | 43 | Parsing dpkg status/Provides, held и arch-пакеты, remnants, unsupported/multiple/partial daemon, private marker, atomic write failure, saved drift, bounded subprocess/deadline, отрицательные NTP-ответы, шаблоны и отсутствие записи sources; scope версии/IPv4 |
| `test_resume_ntp.py` | 26 | Точный ранний stage/marker/версия, SHA256 настоящего старого helper, private perms/type/uid, backup pointer, секрет без вывода, 18 поздних путей, read-only hashes/inodes/mtime, guard/backup ordering и настоящий shell error handler до/после version commit |
| `test_package_plan.py` | 9 | 4 выполнения реального извлечённого Bash-фрагмента с boundary spies + 5 запусков настоящего изолированного решателя APT |

### Пять сценариев настоящего APT solver

1. Старый запрос Chrony при установленном timesyncd → exit 100 и `Packages need to be removed but remove is disabled`.
2. Исправленный полный список компонентов с timesyncd → успешный план без удаления.
3. Chrony уже установлен → успешный план без удаления.
4. Ни одного поддерживаемого daemon нет → план установки Chrony без удаления.
5. Не связанная со временем конфликтная замена пакета → exit 100; общий запрет не ослаблен.

APT видит искусственные доступные версии 1.0; это **не скачанные реальные пакеты Chrony/systemd/Ubuntu**. Реальная APT-планировка с текущими репозиториями конкретного хостера выполняется самим установщиком на ноде, перед настоящим install, и может выявить иное препятствие.

### Отрицательные NTP и resume сценарии

Активная служба с `NTPSynchronized=no`, отсутствующий marker, symlink вместо marker, IPv6/пустой/невалидный адрес источника, ошибки/таймаут команды, ненормальный Leap status Chrony не принимаются за успех. Runtime-ответы этих служб имитируются: живого SNTP/NTP-обмена и оценки точности нет.

Resume отвергает несовпадающие version/rc/line, повреждённый helper, небезопасные файлы и признаки поздних стадий. Проверена неизменность fixture до/после read-only gate. При отказе backup shell-handler сохраняет старый checkpoint и пишет RESUME_FAILED; после смены версии фиксирует новый INSTALL_FAILED. Это **не тест полного выключения питания в момент реального system-wide resume**.

## Сохранённые проверки — 226

Все прежние test cases выполнены повторно. Изменено только ожидание номера текущего выпуска в static test; тесты инцидента UFW и fixtures не удалены.

| Область | Метод и граница |
|---|---|
| Синтаксис и конфигурация | Bash syntax, извлечение/компиляция Python payloads, YAML/Compose templates, flags, версия, профили, DNS и криптографические fixtures |
| Selfsteal/Nginx | Настоящий изолированный локальный Nginx: TLS 1.3, PROXY protocol, HTTP/1.1 и HTTP/2, 96/128 KiB, сертификат/CA/SNI/HTTP errors, три SIGKILL/recovery-цикла |
| Конкурентность | 128 проверок через 16 workers, два протокола — 256 локальных TLS-сессий; не 128 VPN-пользователей и не network speedtest |
| Процессы и ввод | Настоящие PTY, hidden input, восстановление терминала, фоновые процессы, process groups, timeout/сигналы, descriptor checks |
| Файлы и backup | Настоящий tar roundtrip синтетического набора, права/ссылки, SHA256, повреждение архива, инъекции ENOSPC/EIO; диск не заполнялся |
| Maintenance / firewall / сеть | Реальный helper-код с имитацией Docker/iptables/UFW/sysctl и ошибок; не live daemon и не применение firewall на VPS |
| UFW preflight | 48 сохранённых положительных/отрицательных Bash-проверок, точные текстовые fixtures первого инцидента и подтверждение отсутствия вызова firewall-management commands |

## Поставка и повторяемость

Команда локального набора:

```bash
bash tests/run.sh
```

Не запускайте `sudo bash install.sh` ради проверки на рабочей машине. Тесты не требуют настоящего SECRET_KEY и не устанавливают ноду. Для APT integration необходим установленный apt-get; для остальных runtime fixtures — Bash, Python с cryptography/PyYAML, OpenSSL, Nginx, Node.js. CI workflow сохранён; удалённый GitHub Actions здесь не запускался.

Перед выдачей проверяются syntax Bash-блоков документов, относительные ссылки на существующие файлы, SHA256SUMS, CRC ZIP, отсутствие duplicate/path traversal/junk, сохранение всех прежних не-Git файлов, исторических отчётов и отдельной Git-копии. Основной архив **полный рабочий проект без `.git`**; original Git database сохранена в отдельном metadata ZIP, чтобы не заменять существующую локальную историю пользователя. Проверка `git fsck --full` в рабочей копии не выявила повреждений; сообщение `dangling tree` — неназначенный объект исходной истории, не потеря файлов.

## Что не проверено

Полный install/resume/reboot/restore на VPS, real dpkg installation с Ubuntu/Debian repositories, запуск и sandbox systemd-timesyncd/Chrony, реальный UDP/IPv4 NTP, drift/accuracy часов, Docker daemon и RemnaNode/Xray, получение конфига панели, парольный SSH/PAM, UFW/Fail2ban, GRUB, выпуск/продление ACME, arm64, реальные OOM/disk-full/power-loss, provider network outages, международные маршруты и VPN throughput. Сценарий рабочего production upgrade со старых 2.0.x не реализован и не объявляется проверенным.

SHA256 и синтаксис не являются доказательством безопасного полного deploy. На ноде нужны snapshot/консоль, новый парольный SSH-вход до закрытия старого, плановый reboot, postboot-проверка, приёмка панели/RAW REALITY-клиента и контроль времени/сертификата. Любая новая фактическая ошибка разбирается отдельно, а не скрывается автоматическим отключением проверки.
