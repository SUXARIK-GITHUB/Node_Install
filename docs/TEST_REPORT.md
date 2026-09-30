# 🧪 Проверки Node_Install 2.1.0 / ci-fix2

Дата: **30 сентября 2026**. Полный проект на базе ci-fix1. `install.sh` остаётся `2.1.0` и побайтово не изменён: SHA256 `9420c5a76749fd0ae52c26279e78069fca42b40d8a7bae9d80b950a89b3f976c`. Preview тоже не изменён. Исторические результаты не переименованы в новые измерения.

## Предоставленные оператором результаты GitHub

Для запуска #36679239665 получены полный лог 22.04 и текст ошибки 26.04. Ubuntu 22.04 запустила **356 тестов**, получила **1 error** в `test_sni_matches_nodejs_hkdf`; Node `v12.22.9` не предоставляет `crypto.hkdfSync`. Ubuntu 26.04 получила **код 128 на git rev-parse до тестов**, `detected dubious ownership`. Ubuntu 24.04 успешна по пользовательской сводке; полного её лога здесь нет.

[Полный пользовательский лог 22.04](evidence/ci2_user_ubuntu22.txt) · [Фрагмент 26.04](evidence/ci2_user_ubuntu26_excerpt.txt). Не утверждается, что все файлы удалённого commit побайтово сравнены с архивом.

## Локальное воспроизведение и исправление

| Опыт | Фактический результат |
|---|---|
| Старый JS oracle на Node 22 с выключенным hkdfSync | rc=1, `TypeError: crypto.hkdfSync is not a function` |
| Реальный Git: репозиторий owner UID 0, процесс UID 1000 | Без исключения rc=128, после точного workspace exception rc=0 |
| Другой root-owned repo после исправления первого | По-прежнему rc=128; wildcard-доверия нет |
| Разные HOME при той же папке | Исключение в первом HOME не исправляет второй; actual workflow step пишет в нужный контекст |
| Отказы trust step | Пустой/относительный workspace, другая рабочая папка, отсутствие `.git` останавливают до записи config |

[Ошибка старого oracle](evidence/ci2_old_hkdf_reproduction.txt) · [реальные разные UID Git](evidence/ci2_real_git_ownership.json) · [целевые тесты](evidence/ci2_targeted_tests.txt).

## Полные прогоны ci-fix2

**371 отдельный тест = 356 сохранённых + 6 HKDF + 9 Git.** Ни один прежний тест не удалён. Все нижеуказанные прогоны завершились кодом 0 и без пропусков.

| Среда запуска | Тесты | Время unittest | Результат |
|---|---:|---:|---|
| root, native Node HKDF | 371 | 20.176 s | OK, 0 skips |
| UID 1000, без дополнительных групп и sudo | 371 | 18.878 s | OK, 0 skips |
| UID 1000, native hkdfSync искусственно отключён | 371 | 19.667 s | OK, 0 skips |
| Свежий Git clone, owner UID 0 / запуск UID 1000 | 371 | 19.794 s | OK, 0 skips |

[Полный root лог](evidence/ci2_fixed_root.txt) · [полный non-root лог](evidence/ci2_fixed_unprivileged.txt) · [полный fallback лог](evidence/ci2_fixed_without_native_api.txt).

[Свежий Git clone: полный ход проверки](evidence/ci2_fresh_clone_flow.txt): исходный rc=128 → exact trust step → worktree и SHA256SUMS → 371 тест → `git diff --check` / `git diff --exit-code` → повторный manifest. Шаги Git/trust взяты непосредственно из YAML, владельцы действительно разные. Нормализация строк Git не нарушила manifest. Это локальный аналог последовательности шагов, не GitHub Actions runner. Последующие записи текущего отчёта и упаковка проверяются отдельно после распаковки ZIP.

HKDF сверяется с фиксированными RFC 5869 A.1/A.2/A.3, Python cryptography и реальным извлечённым production payload. При наличии API сохраняется native comparison; его ошибки не подавляются. Git-тесты используют приватный HOME и реальный Git; большинство применяет только в subprocess тестовый флаг GIT_TEST_ASSUME_DIFFERENT_OWNER. Отдельный опыт с реальными разными UID не использует этот флаг.

Все прежние реальные Nginx/TLS/PROXY/HTTP2, APT-lock, PTY и fault-injection проверки прошли вместе с новыми. Настройки Docker, systemd, firewall и NTP в соответствующих offline-тестах по-прежнему имитируются. Прогоны не устанавливают ноду и не создают production-сервисов.

## Среда и ограничения

**Debian 13 / x86_64**, Python 3.13.5, cryptography 46.0.4, PyYAML 6.0.3, Node.js 22.16.0, Git 2.47.3, Nginx 1.26.3. Это не GitHub-hosted runner и не Ubuntu 26.04 userspace.

Загрузить настоящий Node 12.22.9 не удалось: DNS/download в текущем окружении недоступны. Поэтому API-совместимость локально проверена отключением `hkdfSync` у Node 22, а не запуском Node 12. Сама исходная несовместимость подтверждена пользовательским логом 22.04 и официальной документацией о появлении API в версии 15.

**Не выполнялись:** новый GitHub Actions run, настоящие гости Ubuntu 22.04/24.04/26.04, Python 3.10/3.12/3.14, VPS install/reboot, Docker daemon/Compose/Xray, SSH/UFW/Fail2ban, GRUB, ACME, NTP/NTS и VPN-нагрузка. Браузерный тест не перезапускался, потому что сайт не менялся. Работающая нода пользователя и GitHub не изменялись.

Проверки приёмки самого архива: YAML, Bash-синтаксис всех run-шагов, Python compile, неизменность install.sh/preview, сохранение всех исходных файлов, manifest, ZIP CRC и отсутствие небезопасных путей. После формирования архив отдельно распаковывается и полный набор выполняется снова; окончательные результаты этого запуска записываются **снаружи запечатанного архива** в `Node_Install_2.1.0_ci_fix2_RELEASE_VALIDATION.json`. Так для записи результата не меняется уже проверяемый ZIP.

## История и повторение

Предыдущие [README ci-fix1](history/README_2.1.0_ci_fix1.md), [TEST_REPORT ci-fix1](history/TEST_REPORT_2.1.0_ci_fix1.md) и [RELEASE_VALIDATION ci-fix1](history/RELEASE_VALIDATION_2.1.0_ci_fix1.json) сохранены дословно. Все ещё более ранние документы также оставлены. [Разбор и применение ci-fix2](CI_FIX2_2.1.0.md).

```bash
bash tests/run.sh
```

Команда предназначена для отдельной Linux dev/CI-среды с тестовыми зависимостями. Не устанавливайте их на работающую VPN-ноду ради исправления GitHub Actions. Все три задания нужно подтвердить новым push/run.
