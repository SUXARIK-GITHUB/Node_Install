> **Дополнение 14.10.2026, 2.5.8 (staging):** HSTS (`max-age=300`, named HTTPS only), TLS 1.2/1.3 и публичный 443/HTTP80 verification добавлены для *новой ordinary-ноды*. Это НЕ завершает каскадный пункт r2 и НЕ является обновлением действующих нод. Внешние VPN/Node-Port проверки остаются BLOCKED. [Обоснование и приёмка](EDGE_HARDENING_2.5.8.md).

# Матрица технического задания r2 — кандидат 2.5.7, 14.10.2026

**Статус: ЧАСТИЧНО. Не выпускать в production.** Это не обещание полного каскада.

Соглашения: `PASS` — исполнен указанный **конкретный** тест; `FAIL` — обязательная функция отсутствует или не завершена; `BLOCKED` — нужна недоступная здесь отдельная VPS/панель/контрольный клиент; `SKIPPED` — отложено сознательно с причиной. Синтаксис, mock и CRC не доказывают live-работоспособность. Отдельный отчёт конечной выдачи содержит SHA256 **точного ZIP**, результат полного набора тестов **из его распаковки** и перечень проверок.

## Матрица ролей и функций

| Функция | ordinary | cascade-entry | cascade-exit | Реализация/проверка |
|---|---|---|---|---|
| Выделенная установка IPv4-only | Существующий код 2.5.6 с правками | **FAIL: нет install flow** | **FAIL: нет install flow** | `install.sh`; штатные unit-тесты; live VPS BLOCKED |
| Сервис RemnaNode/панель | Исходный режим сохранён | **FAIL: нет ролевых объектов** | **FAIL: нет ролевых объектов** | Нет действующей панели в тестовом окружении |
| RAW/XHTTP, профили | Исходный режим сохранён | **FAIL: нет клиента→межнодовый outbound** | **FAIL: нет отдельного peer inbound** | `tests/test_profile_policy.py`; тесты ролевой цепи отсутствуют |
| Nginx и local Selfsteal | Исходная схема не заменялась | **FAIL: нет отдельного контракта** | **FAIL: нет отдельного контракта** | Старый Nginx и Unix socket; новые live тесты BLOCKED |
| Настоящий HTTP/TCP reverse proxy | Старый сайт/Unix socket, новый proxy **не добавлен** | **FAIL** | **FAIL** | Нельзя называть статическую выдачу HTTP reverse proxy |
| Сертификаты, независимый домен/ключи | Исходное поведение | **FAIL: сценарий не создан** | **FAIL: сценарий не создан** | Live CA/renew BLOCKED |
| RKN Guard | Обновлены отказ и отключение | **FAIL: не установлен по роли** | **FAIL: не установлен по роли** | `tests/test_r2_critical.py`; реальный systemd/UFW BLOCKED |
| Docker local-only, проверки SecurityOpt | Обновлены | Общая библиотека имеется, **не интегрирована в роль** | То же | `integrations/docker_local.sh`, `test_r2_critical` |
| Ночной рестарт | Включён только на **новой ordinary-нódе** | **FAIL: нет разнесения пары** | **FAIL: нет разнесения пары** | `integrations/nightly_maintenance.py`; timer mock tests |
| Проверка локального состояния | Частично реализовано | **FAIL: нет peer-диагностики** | **FAIL: нет peer-диагностики** | Нет false PASS для непроверенного выхода |
| Обновление и rollback | Исходная поддержка образов; новый Docker wrapper | **FAIL: нет сохранения роли** | **FAIL: нет сохранения роли** | Старые тесты и новые Docker тесты |
| Backup/restore | Исходная config-only модель, **VPS restore не проверено** | **FAIL: нет state роли** | **FAIL: нет state роли** | Изолированное реальное восстановление BLOCKED |
| Сайт из 6 новых шаблонов | **FAIL: не добавлены** | **FAIL** | **FAIL** | Существующий сайт оставлен без редизайна |
| Реальный защищённый two-hop VLESS/REALITY | Неприменимо: обычный прямой маршрут | **FAIL: не реализовано** | **FAIL: не реализовано** | Два независимых VPS и панель BLOCKED |
| Невозможность прямого fallback при отказе выхода | Неприменимо: ordinary direct | **FAIL: нет route** | **FAIL: нет route** | Не заявлено как PASS |
| Peer credential/rotation | Неприменимо: нет peer | **FAIL** | **FAIL** | Нет безопасной транзакционной реализации |

## Проверки исправлений и поставки

| Сценарий | Среда | Ожидаемый результат | Факт / доказательство | Статус |
|---|---|---|---|---|
| RKN отключение: порядок | Bash с изолированным systemd/UFW mock | `daemon-reload` до `stop prepare` | `tests/test_r2_critical.py` | PASS |
| RKN отключение: ошибочный `daemon-reload` | Bash mock | Нет остановки prepare и нет PASS | `test_failed_reload_never_stops_prepare...` | PASS |
| RKN отключение: чужой drop-in | Bash mock | Без изменений чужих файлов | `test_foreign_dropin_never_mutated` | PASS |
| RKN отключение: прерванная операция/повтор | Bash mock | Повторяемое безопасное завершение | `test_interrupted_deletion_resumes_idempotently` | PASS |
| RKN остановка prepare завершилась ошибкой | Bash mock | Ненулевой статус, backup для восстановления | `test_failed_prepare_stop_reports_error` | PASS |
| RKN невозможность создать ipset | Python mock | Удалён свой блок, базовая UFW-структура сохранена | `test_no_ipset_creation...` | PASS |
| RKN на настоящей Linux VM после reboot | Отдельная VM/консоль | Базовый firewall и SSH доступны | Нет VM доступа | BLOCKED |
| Конкурентные CLI операции RKN | Синтаксическая проверка lock + mock | Нет пересечения внутри одного installer lock | `test_dynamic_caller...`; kernel runtime не проверен | PASS (ограниченно) |
| Docker HOST/CONTEXT/CONFIG | Фальшивый Unix socket и CLI | Реальный запуск wrapper не наследует переменные | `test_wrapper_effectively_sanitizes_context` | PASS |
| Docker без локального socket | Bash mock | Явная ошибка, нет удалённого fallback | `test_wrapper_blocks_missing_local_socket...` | PASS |
| Docker на настоящем daemon | VPS/VM | Только локальный Docker, штатный запуск | Docker в среде отсутствует | BLOCKED |
| no-new-privileges true/false/мусор/дубли | Исходный Python валидатор, stdlib | false и противоречия отклонены | `test_all_security_opt_variants` | PASS |
| `method` вместо `network` | Настоящая функция проверки профиля | Нет KeyError | `test_alias_method_audit...` | PASS |
| Ночное окно и пропуск | Python + systemd unit static | 03:00–03:59 МСК, `Persistent=false` | `test_window_timezone`, `test_timer_not_persistent...` | PASS |
| Ручной stop/at-most-once | Python mock | Нет автозапуска остановленной ноды | `test_manual_stop_and_at_most_once` | PASS |
| Night timer + client canary live | VM + RemnaNode | Есть local+peer+client приёмка | Нет live окружения | BLOCKED |
| ZIP: старый код под новым именем | Фикстура verifier | Отказ | `test_old_binary_under_new_name_is_rejected` | PASS |
| ZIP: новый файл отсутствует | Фикстура verifier | Отказ | `test_missing_new_helper_is_rejected` | PASS |
| ZIP: некорректный README | Фикстура verifier | Отказ | `test_wrong_readme_version_detected_even_if_rehashed` | PASS |
| ZIP: неверный SHA/лишние файлы | Фикстура verifier | Отказ | `test_modified_manifest_is_detected`, `test_unmanifested_file_refused` | PASS |
| Full suite из окончательного ZIP | Чистая распаковка | Все тесты без падений | Результат **только во внешнем отчёте с SHA256 ZIP** | BLOCKED до конечной выдачи |
| Манифест/CRC/байтовое сравнение полного ZIP | Повторная распаковка | Совпадение | `scripts/verify_release.py`; внешний паспорт сборки | PASS после сверки итогового ZIP |
| Рендер сайтов, два узла, сертификаты | Отдельная VM/VPS | HTTPS и авторизованный VPN обоих ролей | Невозможно в текущей среде | BLOCKED |
| 24 часа под нагрузкой | VPS клиент+панель | Замеры в одинаковых условиях | Не выполнялось | SKIPPED: требует длительного стенда |
| GitHub CI новой версии | Push/PR в GitHub | Workflow для именно нового SHA | Изменения не публиковались | BLOCKED |

## Актуальные ограничения и следующая независимая приёмка

1. В среде доступны Bash, Python, nginx, локальные фикстуры; нет реального управляемого Docker daemon/системного UFW и двух VPS с панелью.
2. Проверенные автономные сценарии не дают права запускать опасный RKN/перезапуск на production; сначала snapshot + restore-check + консоль провайдера + SSH canary на тестовой VM.
3. Исходный обычный REALITY-транспорт, маршруты, права панели, SSH, сайт и пользовательские подписки не переделывались без необходимости.
4. Не используйте этот кандидат для существующего каскада, технички и панели. Функционал двухузлового каскада в нём отсутствует.
