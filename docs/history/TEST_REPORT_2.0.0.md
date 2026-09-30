# Отчёт о проверках 2.0.0

Дата: 2026-09-30. Исходник для тестов — `install.sh` этой поставки. **Полная установка не запускалась** в среде подготовки; никакая production-нода не изменялась.

## Фактическое окружение

Локальный контейнер Debian 13, amd64, Python 3.13.5, Bash, OpenSSL 3.5.5, Nginx 1.26.3, cryptography 46.0.4, PyYAML 6.0.3, Node.js 22.16.0. Nginx запускался отдельным процессом с временными `-p/-c`, Unix socket и тестовым CA. Системные `/etc`, systemd-сервисы, firewall и Docker daemon не использовались для установки.

Нет Docker/Compose, sshd, fail2ban-client и ShellCheck в этой среде. Эти инструменты не считаются проверенными через похожую Python-валидацию.

## Выполнено

Команда: `bash tests/run.sh`.

**74 теста: PASS; пропусков в зафиксированном локальном прогоне нет.** Результат относится к перечисленным ниже сценариям, не к полной production-сертификации. Финальная сборка дополнительно проверена на синтаксис, manifest/ZIP и целостность исходной структуры; release manifest содержит хеши обычных файлов.

| Группа | Что именно проверялось |
|---|---|
| Синтаксис | `bash -n install.sh`, синтаксис генерируемых Bash helpers; компиляция встроенных Python payload |
| Вызовы без установки | `--help`, `--version`, отклонение неизвестной опции, inert sourcing; установка из тестов не вызывается |
| Требования/шаблоны | Ровно три prompt в нужном порядке; Compose host mode, capability opt-in, read-only socket mount; отсутствие mass-upgrade/prune; port-scoped Fail2ban action; одиночное владение boot |
| Валидация | Домены/IP, типы и неизвестные поля, official image reference, приватные права файлов |
| Криптография | Полный временный secret bundle, неправильный CA, несовпадающий private key, истёкший cert, отсутствие секрета в ошибках, сохранение/повреждение REALITY key pair |
| DNS — имитация ответов | Multi-IP выбор по DNS, conflicting resolvers, AAAA, несколько A, CDN/чужой IP, NAT, недоступный resolver, stale system resolver |
| SSH rendering | Сохранение исходного body и socket-only портов, first-value policy, повторная генерация, отказ при повреждённом marker/портах; не live sshd |
| Network — временный proc/mock commands | Parser, неизвестные/повторяющиеся sysctl, отсутствие IPv6-путей, отказ по обязательным ключам, BBR fallback/readback, повреждённое состояние |
| Реальный API TLS локально | TLS 1.3 на loopback, ordinary/fragmented ClientHello >1500 байт, неверные CA/leaf/SNI, закрытый порт |
| Граница mTLS | Тестовый сервер требует client certificate; probe подтверждает только server TLS, сервер не аутентифицирует probe как панель |
| HKDF SNI | Сравнение Python derivation с независимым cryptography HKDF и Node.js crypto |
| Реальный Nginx Selfsteal | Generated config, Unix socket, PROXY v1, TLS 1.3, HTTP/1.1 и HTTP/2, ожидаемое тело; неверный hostname/body; recreate socket; синтаксис старой HTTP/2 формы |
| Image maintenance — Docker MOCK | Atomic private writes, single-line image update, compose drift, official source, checksum/path checks, success commit, identical digest no recreate, failed candidate rollback, failed rollback retains pending, secret-safe command errors |

Тесты извлекают **фактические heredoc-payload** из installer, поэтому изменения встроенных helpers отражаются на тестировании. Тестовые сертификаты/ключи генерируются временно и не включаются в поставку. Docker boundary в транзакционных тестах намеренно подменён: его PASS не означает, что реальный Docker исполнил команды.

## Не выполнено и обязательно для canary

Не проверены полноценные install/reinstall/backup restore на Ubuntu 22.04/24.04 и Debian 12/13, arm64, загрузка с GRUB, фактический reboot/power loss, Socket activation OpenSSH, парольный вход, реальные UFW bans/Fail2ban journal events, networking провайдера, Docker pull/Compose config/up/inspect/capabilities/read-only mount и run-test выбранного Xray binary.

Не выполнялись ACME выдача/renewal против Let's Encrypt, фактические APT/Docker repository обращения, принятие supplied SECRET_KEY реальной панелью, её mTLS, доставка профиля и пользователей, клиентский VPN, маршруты из разных стран, benchmark, failover, длительный soak test. Реального пользовательского SECRET_KEY для таких тестов не было и в отчёт не подставлялся фиктивный «успешный» результат.

`sshd -t`, `fail2ban-client -t`, `docker compose config --quiet`, `dockerd --validate`, Certbot dry-run и Xray run-test встроены в установочный сценарий, но **не запускались здесь**, поскольку нет требуемых целевых сервисов/окружения. Реальный `nginx -t` выполнен только на изолированных временных конфигурациях. ShellCheck не выполнялся; Bash parser не заменяет shell lint. GitHub Actions workflow подготовлен, но в удалённом репозитории не запускался.

## Как воспроизвести тесты

```bash
bash tests/run.sh
```

Нужны Python 3.10+, cryptography и PyYAML. Без Nginx/Node.js соответствующие интеграционные проверки будут явно помечены skip, а не посчитаны пройденными. Workflow устанавливает тестовые зависимости только на одноразовом runner Ubuntu, не устанавливает ноду и не получает production secrets.

## Release gate для владельца

На canary той же архитектуры/хостера: backup → реальный restore drill → install с выбранным image digest → новая парольная SSH-сессия → reboot → local/strict checks → Node online в панели → пользователь с правильным доступом → реальный трафик → update/rollback в окне обслуживания → повторная проверка. Отдельно проверьте недоступность API 2222 с посторонней машины, доступность с backend панели и сохранение SSH без постоянного IP-allowlist.

Рекомендуемые негативные сценарии на **одноразовом стенде**, не в production: неверный DNS/key, отсутствие места, отключённый NTP, pull failure, неподдержанный BBR, разрыв установки, повреждённый transaction hash и недоступная панель во время recreate. Нельзя намеренно ронять production для того, чтобы заполнить эту матрицу.

## Контроль комплектности поставки

Проверены `git diff --check`, `git fsck --full`, сохранение всех файлов исходного архива и побайтовая неизменность исходных Git objects/refs. Исходный и итоговый репозитории содержат один и тот же ранее существовавший dangling tree; `git fsck` завершился с кодом 0, история не очищалась и не переписывалась.

Все 24 Bash-блока документации разобраны через `bash -n` без выполнения. Относительные Markdown-ссылки на файлы разрешаются; якоря заголовков отдельно не проверялись. Хеш `install.sh` совпадает со значением в команде README. YAML workflow разобран локально; удалённый GitHub Actions не запускался.

В рабочем дереве и 64 Git blob выполнен поиск ограниченного набора шаблонов: полные private PEM blocks, похожие на GitHub tokens строки, URL со встроенными credentials и длинные literal SECRET_KEY assignments. Совпадений этих шаблонов нет; это **не математическое доказательство отсутствия любых секретов**.

Финальный ZIP проверен на CRC, повторы путей и небезопасные имена, распакован в отдельный каталог. Для распакованной копии повторно выполнены `sha256sum --check SHA256SUMS`, `git fsck --full`, `git diff --check` и полный набор из 74 тестов — PASS без пропусков. Manifest охватывает все обычные release-файлы, кроме `.git` и самого manifest; исходная `.git` отдельно включена в полный архив. Временные сертификаты, Python cache, логи тестов и скрипты подготовки поставки в ZIP не включены.
