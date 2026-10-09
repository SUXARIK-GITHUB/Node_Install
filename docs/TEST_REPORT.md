# 🧪 TEST_REPORT — Node_Install 2.5.6

Дата: 09.10.2026. Основа: `8780852ac1adc15293758aae2d8ce1b7584b0380` (2.5.5 с обновлёнными README/Security). Это **новая кодовая сборка**, а не повторное описание старых тестов. Предыдущий отчёт целиком сохранён в [истории](history/TEST_REPORT_2.5.5.md), предыдущая release validation — [здесь](history/RELEASE_VALIDATION_2.5.5.json).

## Выполненные прогоны

| Проверка | Результат | Время / источник |
|:--|:--|:--|
| Независимый исходный baseline 2.5.5, UID 0 | 637/637, без failures/errors/skips | 21.734 s, локальный контроль исходного архива |
| Полный набор 2.5.6, UID 0 | 695/695, без failures/errors/skips | 23.19 s, [256-root-tests.txt](evidence/256-root-tests.txt) |
| Полный набор 2.5.6, UID 65534 | 695/695, без failures/errors/skips | 23.682 s, [256-unprivileged-tests.txt](evidence/256-unprivileged-tests.txt) |

**Окружение:** Debian 13 container userspace, system Python 3.13; nginx и OpenSSL используются в существующих локальных integration fixtures. PyYAML из уже установленного окружения подключён только для тестового Python. Новых runtime-зависимостей проекта нет. Это не доказательство установки/reboot на всех поддерживаемых ОС. Живые Docker, systemd, NTP и firewall в новых finalization-тестах заменены явным контролируемым runner.

Первый прогон новой версии выявил две старые статические привязки к удалённому shell-фрагменту финализации: они заменены проверкой соответствующей операции в новом helper, включая quiet-экспорт и остановку при неудачном rollback. Поведенческие проверки не удалены и не пропущены. Дополнительные tests защищают прежние 13 embedded network/cover/RKN payloads и шесть существующих файлов от изменений.

## Что проверено новыми сценариями

**NTP:** окно 21→31 секунда от restart, повторная синхронизация, сброс серии при смене InvocationID/источника, stale marker, `PacketCount=0`, `Ignored=yes`, ненормальный leap/stratum/mode, отсутствие поля/дубликат, IPv6 вместо IPv4, deadline при постоянном отказе. Два успешных наблюдения не могут продлевать общий бюджет. Исполняется и реальный Bash-блок приёмки: успех/отказ каждого режима.

**Финальная фаза:** source/snapshot checksums, private ownership/modes, повреждённый backup и path traversal, отсутствие checkpoint, чужая версия/IP/image, изменение ключей/профиля, symlink, optional-file drift, реальный файловый commit и его прерывание, повторная попытка без APT/SSH/Docker reinstall, RKN activation failure и rollback failure, таймаут потомков процесса. Без доказанного rollback и повторной успешной приёмки `INSTALL_COMPLETE` не записывается. Результаты фикстур не означают реального выполнения UFW на VPS.

**Ресурсы:** `daemon_fds.verified=false` больше не теряется в `review_summary`; `--strict` даёт rc=2, default-сбор JSON сохраняет совместимость rc=0. Нулевая выборка процессов не считается проверенной, stopped-container не получает OK. Дополнительно разобран JSON из реального предоставленного аудита: [replay](evidence/256-resource-audit-replay.json) ожидаемо возвращает REVIEW_REQUIRED по частичным FD. Это повторная обработка журнала, не новый сбор с сервера.

**Smoke:** `--finish-install` без записанного checkpoint на тестовом хосте отвергнут до изменения установочного состояния. `--diagnose-resources --strict` в среде без установленной ноды вернул rc=2, а не ложный успех.

## Сохранённые границы и непроверенное

Новая 2.5.6 не устанавливалась на реальную VPS. Не выполнены реальный reboot 2.5.6, внешняя Panel authentication, VPN-клиент, публичный Let's Encrypt challenge/renewal, новый запуск daily RKN по таймеру и kernel-level fault injection. Старая нода 2.5.5 уже успешно прошла операторскую послезагрузочную проверку, но это не live-сертификация нового кода. Инициатор старых повторных запусков timesyncd неизвестен; исправлена доказанная гонка приёмки, а не выдуманная причина restart.

Runtime Nginx, Selfsteal, RAW/XHTTP profile examples, секреты, рабочие VPS и удалённый GitHub не менялись. Новый GitHub CI появится только после публикации. Сведения по упаковке и финальной повторной проверке после распаковки — в сопровождающем release-отчёте.
