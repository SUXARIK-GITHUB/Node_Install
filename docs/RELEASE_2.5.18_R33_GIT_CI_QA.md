# Node Install 2.5.18 r33 — Git / GitHub / CI QA (staging)

**Статус:** `INCOMPLETE_STAGING_ONLY`. Архив основан на r32. Не опубликован в `main`; публикация, SSH/VPS-установка и запуск GitHub Actions именно для r33 НЕ производились.

## Что подтверждено

- Реальный публичный репозиторий `SUXARIK-GITHUB/Node_Install`: ветка `main`, SHA `88854bf09b50a3e629cce7ffd3afc9b4f6da00b2`, содержит r29 на момент проверки 2026-11-06. Последний GitHub Actions 2026-11-05 завершён с `success` по пяти заданиям: Ubuntu 22.04 и 24.04, Ubuntu 26.04 userspace, Debian 12 и 13. Это результаты **r29**, не r33.
- Для r32 локально отдельно выполнены все 101 автономных тестовых модуля: 1111 тестов прошли; Git stage/commit → bare push → `git clone --depth 1` → SHA256SUMS → verify_release → `git diff --exit-code` прошли. Изменение отслеживаемого README обнаружено обоими механизмами. `.env` и `.pem` при тестовой проверке не попадают в Git index.
- Наличие SHA256SUMS и BUILD_MANIFEST в ZIP доказывает внутреннюю целостность, **не криптографическое авторство**: внешний доверенный digest / подпись и staging-проверка обязательны.
- Прямой `git ls-remote` из изолированной проверочной среды недоступен из-за DNS; состояния репозитория и workflow-run получены через GitHub API. Публикацию r33 GitHub не выполняли.

## Найденная и исправленная ошибка в CI

Раньше после тестов все три CI jobs выполняли только `git diff --check` и `git diff --exit-code`. Они **не замечают** ни новые untracked файлы, ни staged-only изменения. В локальном git-репозитории оба случая воспроизведены с возвратом `0`.

Добавлена команда `git status --porcelain=v1 --untracked-files=all` и завершающий код `1` при любых незамаскированных изменениях после тестов. Команда безопасна: не удаляет, не сбрасывает, не делает `git reset`, не меняет рабочую копию. Проверяется в трёх CI jobs. Добавлен отрицательный регрессионный тест для обоих ранее пропущенных сценариев.

После полного регрессионного прогона исправлен устаревший тест исторического GitHub bootstrap: он теперь проверяет именно закреплённую r29-команду, не привязывая её заголовок к будущей версии staging. Также обновлён явный r33 хеш-контракт GitHub Actions в `tests/test_preserved_policy_256.py`: прежние r4/r6 контрольные суммы сохранены, добавлена отдельная проверка одобренного изменения CI, остальные интеграции неизменны.

## Что изменено

`.github/workflows/check.yml`, `README.md`, `CHANGELOG.md`, `scripts/verify_release.py`, `scripts/build_staging_archive.py`, корректировка двух тестов документации и теста исторических контрольных сумм CI и новые `tests/test_r33_git_ci_audit.py`, `docs/RELEASE_2.5.18_R33_GIT_CI_QA.md`. `install.sh`, Docker, Nginx, UFW, SSH, systemd, база данных и другие runtime-модули **не изменены**.

## Что НЕ проверено

Живая установка/удаление ноды, reboot, настоящий nftables/iptables, клиентские VPN-сессии, REALITY и Remnawave Panel, публичный TLS, обновления systemd/Docker, MobaXterm, реализация внешних сетевых API, реальный GitHub Actions run после публикации r33. Возврат по snapshot требует отдельного VPS и контроля доступа.

## Безопасный приёмочный Git-цикл после публикации

После публикации отдельным разрешённым действием: проверить commit SHA и workflow run, `git clone --depth 1` в **новую папку** (не поверх действующего checkout), `sha256sum --check SHA256SUMS`, `python3 scripts/verify_release.py --root .`, `bash tests/run.sh`, `git status --porcelain=v1 --untracked-files=all`; убедиться, что установленный build_id совпадает с **ожидаемым именно r33**. Никогда не использовать `git reset --hard`, `git clean -fdx` или установку поверх действующей VPS без утверждённого snapshot/rollback.
