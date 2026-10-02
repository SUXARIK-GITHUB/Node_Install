# TEST_REPORT — Node_Install 2.1.3

Дата выпуска: 2026-10-02. Статус: **LOCAL_TESTS_PASSED_VPS_PILOT_REQUIRED**.

## Проверенная база

Исходный ZIP 2.1.2 docs-ci-fixed проверен по SHA256, CRC и 101 записи SHA256SUMS. Перед правками заново выполнены 383 теста от root — все прошли. После прогонов все 102 файла исходного worktree сравнены с байтами исходного ZIP, изменений нет.

## Изменения под проверкой

1. Единый `PROFILE_MIN_CLIENT_VERSION='0.0.0'` в generated JSON, validator, PANEL-SETUP и key export.
2. Исправлен пропуск `profile-check` в acceptance для версии 2.1.2; 2.1.3 добавлена в reviewed allowlists acceptance/maintenance/cover.
3. Структурная проверка DNS/IPv4/routing/tags, прямого listener без входящего PROXY protocol, общего Vision и корректной служебной API-вставки RemnaNode.
4. Ограниченное чтение supplied JSON с отказом на symlink/FIFO/duplicate keys/NaN/Infinity, без вывода содержимого.

Нет изменений transport, DNS/routing/flow generated template (кроме minClientVer), картинки/страницы, workflow, системной сети/SSH/firewall/ACME. По сравнению embedded payloads 21 блок полностью совпадает, ещё три изменены только для allowlist/version-comment; CLI help изменён только номером релиза.

## Результаты

| Прогон | Ran | Время из unittest | Ошибки / failures / skips |
|---|---:|---:|---|
| База 2.1.2, root | 383 | 17.945 s | 0 / 0 / 0 |
| 37 новых регрессий | 37 | 0.384 s | 0 / 0 / 0 |
| Полный 2.1.3, root | 420 | 19.345 s | 0 / 0 / 0 |
| Полный 2.1.3, UID 1000 | 420 | 18.458 s | 0 / 0 / 0 |

Это четыре выполненных запуска, не оценка будущего времени установки. Среда: Debian 13/x86_64. Точные версии Python и контрольные значения — в `RELEASE_VALIDATION.json`.

Логи:

- [baseline root](evidence/profile-baseline-root.txt)
- [новые регрессии](evidence/profile-targeted-213.txt)
- [полный root](evidence/profile-213-root.txt)
- [полный UID 1000](evidence/profile-213-uid1000.txt)
- [сохранённые payloads и политика](evidence/profile-policy-preserved-2.1.3.json)

## Что проверяют 37 новых тестов

Исполняется код из текущих heredoc payloads installer, а не независимая копия validator. Исполняется настоящий Bash version-gate с fake helper. Проверены:

- единое значение версии клиента; отказ на 1.0.0/число/отсутствие поля;
- повторный key export без изменения X25519/ShortID;
- сохранение прежних DNS/outbounds/routing/отсутствия forced Vision при генерации;
- неверные DNS strategies, типы booleans/TTL, серверные overrides;
- общий Vision с пустыми/отсутствующими client flows, users alias, неправильные flow;
- IPv4 listener, ошибочный входящий PROXY protocol;
- потерянные/дублированные tags, пустые или некорректные routing rules;
- synthetic expanded RemnaNode JSON со 150 тестовыми записями и API outbound, создаваемым через api.tag;
- ошибочный/public API, перенаправление VPN на API, неправильный порядок API rule;
- отсутствие mutation и вывода тестовых privateKey/ShortID/socket name;
- duplicate JSON fields, NaN/Infinity, symlink, FIFO, directory, oversized input;
- 2.1.0/1/2/3 выполняют profile-check; helper failure не подавлен; future versions не получают молчаливый PASS; legacy/missing marker явно NOT_VERIFIED;
- предыдущие допустимые версии maintenance/cover не потеряны.

Эти тесты НЕ доказывают полный security-аудит любого routing или всех полей произвольного Xray JSON.

## Остальные проверки

Bash syntax installer и встроенных Bash payloads, Python compile всех Python payloads, статическая обработка тестов, синтаксис 46 Bash-блоков четырёх current документов, закрытие Markdown code fences, относительные ссылки. Документальные команды не исполнялись.

Исторические README, SECURITY, TEST_REPORT и RELEASE_VALIDATION 2.1.2 скопированы в `docs/history` побайтово. Исходный архив, `.git` snapshot, пользовательские handover и результаты VPS-диагностики не изменены. Новые release-архивы не включают `.git` или временные файлы.

## Что не проверено

- Полная установка 2.1.3 на VPS, реальная замена системных пакетов/сети и reboot.
- Генерируемый JSON на настоящем bundled Xray пользовательской ноды в этом шаге.
- Прямой API Remnawave, реальные клиентские подключения, скорость и блокировки.
- Проверка конечной защиты private/metadata/own/panel по TCP/UDP.
- Ubuntu 22.04/24.04/26.04 matrix, arm64, power-loss/полное восстановление VPS.
- Удалённый GitHub Actions запуск после публикации; GitHub не менялся.

Тесты Docker/systemd/firewall используют имитации. Часть существующих тестов действительно запускает временный локальный Nginx/TLS/HTTP2, APT solver на synthetic metadata и Git, но не production install.

## Перед применением

Проверенный snapshot/recovery и новый тестовый сервер. Для ручного окна пилота — `--no-reboot`. После назначения профиля — новый SSH, local/strict checks, браузерный Selfsteal и реальные клиенты; reboot только отдельным этапом. На работающих старых нодах обычный запуск не устанавливает новый helper — автоматическая миграция в 2.1.3 не добавлена. Откат исходников до deployment не требует каких-либо команд на нодах/TECH.
