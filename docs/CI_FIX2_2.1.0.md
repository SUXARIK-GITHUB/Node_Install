# 🔧 Node_Install 2.1.0 / ci-fix2 — точные причины оставшихся отказов

Дата: 30 сентября 2026. Основа: полный архив `Node_Install_2.1.0_ci_fix1.zip`, предоставленные оператором журнал Ubuntu 22.04 и фрагмент Ubuntu 26.04 из запуска **36679239665**.

**Это изменение CI и тестов, а не версии production-установщика. На VPS ничего выполнять не нужно.** `install.sh` побайтово сохранён: версия `2.1.0`, SHA256 `9420c5a76749fd0ae52c26279e78069fca42b40d8a7bae9d80b950a89b3f976c`. HTML/CSS/SVG, три вопроса, VLESS RAW REALITY, SSH, firewall, Docker и служба Nginx не изменены. GitHub в этой работе не изменялся.

## 1. Что теперь подтверждено журналами, а не предположением

В [полном присланном журнале 22.04](evidence/ci2_user_ubuntu22.txt): Python 3.10.12, Nginx 1.18.0, **Node v12.22.9**, APT 2.4.14, UID 1001. Выполнены все 356 тестов ci-fix1; ровно одна ошибка в `test_sni_matches_nodejs_hkdf`. В traceback виден вызов `crypto.hkdfSync(...)`. Все три ранее исправленных настоящих APT-теста прошли. Установщик в runner не запускался.

При включении журнала в Git нормализованы только окончания строк CRLF → LF; строки вывода не сокращены. Иначе Git text-normalization изменила бы SHA256 после checkout.

`crypto.hkdfSync` появился в Node 15 — это указано в [официальной документации Node](https://nodejs.org/download/release/v22.16.0/docs/api/crypto.html#cryptohkdfsyncdigest-ikm-salt-info-keylen). В Node 12 такого API нет. Пользовательский traceback не включает stderr самого Node; конкретная строка TypeError отдельно воспроизведена локально, а не приписана удалённому выводу.

Во [фрагменте журнала 26.04](evidence/ci2_user_ubuntu26_excerpt.txt) показано другое:

```text
Run git rev-parse --is-inside-work-tree
fatal: detected dubious ownership in repository at '/__w/Node_Install/Node_Install'
Error: Process completed with exit code 128.
```

Это остановка **перед запуском набора тестов** на защите Git от репозитория другого владельца. Точные удалённые UID, HOME и значения config в этом фрагменте не показаны. Не утверждается, что measured HOME точно менялся: установлена недостаточность effective trust для текущего Git-процесса. Это не прежний сценарий `Not a git repository` с кодом 129 и не ошибка VPN или Ubuntu 26.04 как ОС.

Успех задания Ubuntu 24.04 подтверждён присланной оператором сводкой/скриншотом. Его полный лог в текущем сообщении не приложен. Нового удалённого запуска ci-fix2 пока нет.

## 2. Исправление совместимости HKDF только в тестах

Использовать случайный новый Node на VPS или менять криптографию RemnaNode не требуется. Системный Node из APT оставлен тестовой зависимостью CI; новые внешние Actions/npm-пакеты/репозитории не добавлены.

В `tests/node_hkdf_oracle.py` выделен JavaScript-эталон. Если API `crypto.hkdfSync` существует, эталон продолжает использовать **native HKDF**, как прежде. Если API отсутствует, HKDF-SHA256 вычисляется через встроенный `crypto.createHmac` по RFC 5869: Extract, затем Expand с counter. Это тот же алгоритм, не замена HKDF на иной KDF. Ошибка существующего native API не ловится и не превращается в успешный fallback.

`tests/test_tls_integration.py` по-прежнему сравнивает SNI с реальным встроенным Python payload из `install.sh`. В Node передаются только публичные поля временного test bundle; stderr явно включён в сообщение неуспеха. Проверка не удалена и не пропускается из-за старого Node.

Добавлены шесть регрессий в `tests/test_hkdf_compat.py`. Фиксированные SHA-256-векторы A.1/A.2/A.3 взяты из [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A): обычный salt/info, длинные данные и несколько Expand-блоков, пустые salt/info. Ожидаемые значения не вычисляются тестируемой функцией. Проверены обе ветви, совпадение с cryptography HKDF, нормализация PEM, допустимые длины и явный отказ native API. Старые проверки Python cryptography и локального TLS сохранены.

**Граница локальной проверки:** настоящий Node 12 загрузить не удалось (DNS/download недоступны). API отсутствовал искусственно в Node 22.16.0. Это проверяет fallback и полный набор в таких условиях, но не подменяет настоящий Ubuntu 22.04/Node12 CI-run. Совместимость синтаксиса JS рассчитана на Node 12; подтверждение точного runner требует нового push.

## 3. Исправление Git trust только внутри одноразового 26.04 job

В `.github/workflows/check.yml` после `actions/checkout` добавлен отдельный шаг:

```bash
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
[[ "$GITHUB_WORKSPACE" == /* ]]
test -d "$GITHUB_WORKSPACE/.git"
test "$(pwd -P)" = "$(cd -- "$GITHUB_WORKSPACE" && pwd -P)"
git config --global --add safe.directory "$GITHUB_WORKSPACE"
```

Этот блок **уже находится в workflow**; не нужно запускать его на ноде или прописывать `/__w/...` на компьютере. Он выполняется в том же shell-контексте контейнера, где идут последующие Git-проверки. Абсолютный путь берётся из переменной runner, а не хардкодится под конкретный репозиторий.

Защита Git не отключена: `safe.directory=*` не используется, остальные репозитории не добавляются, владельцы/права не переписываются, конфигурация всей ОС через `--system` не меняется. Проверка `.git` сохраняет отказ на архивной выгрузке без настоящей истории. Работа с protected config и различие scoped exception/wildcard описаны в [документации Git](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory). Случаи разных HOME при контейнерных Actions описаны в [issue репозитория runner](https://github.com/actions/runner/issues/2033), но они не заменяют измерения конкретного запуска.

Девять новых тестов в `tests/test_git_workspace.py` выполняют именно тело шага из YAML с настоящим Git и изолированными HOME. Для повторяемой проверки без root используется `GIT_TEST_ASSUME_DIFFERENT_OWNER=1`. Отдельный локальный опыт **без этого hook** использовал root-owned repo и процесс UID 1000: до исключения `128`, после `0`, соседний repo остался `128`. [JSON опыта](evidence/ci2_real_git_ownership.json). Чужой HOME и `.git/config` не изменились.

## 4. Что сохранено и что изменилось

Предыдущая изоляция APT/Nginx и установка Git до checkout сохранены. Матрица 22.04/24.04/26.04, read-only token, закреплённый checkout action, запрет запуска install.sh и отсутствие `continue-on-error` не менялись. Задание Ubuntu 24.04 не переделывалось.

Код затронут только в пяти файлах:

| Файл | Изменение |
|---|---|
| `.github/workflows/check.yml` | Один scoped trust step в 26.04 job |
| `tests/test_tls_integration.py` | Совместимый независимый oracle и читаемая ошибка Node |
| `tests/node_hkdf_oracle.py` | Новый test-only JS oracle |
| `tests/test_hkdf_compat.py` | Шесть регрессий |
| `tests/test_git_workspace.py` | Девять регрессий |

README, CHANGELOG, отчёт, validation и manifest актуализированы. Предыдущие документы ci-fix1 сохранены в `docs/history`, предыдущий `CI_FIX_2.1.0.md` не переписан. Все 76 файлов прежнего архива сохранены по исходным путям; файл production и preview побайтово прежние. Новый полный архив не содержит `.git`, кэшей тестов, бинарников Node или приватных runtime-данных.

## 5. Применение и откат в репозитории

Сначала сохраните копию локального clone вместе с его актуальной `.git` и несохранёнными изменениями. Распакуйте `Node_Install_2.1.0_ci_fix2.zip` отдельно, перенесите полное содержимое папки `Node_Install` в существующий clone, **включая скрытую `.github`**, сохраняя `.git`. Не удаляйте папку подключённого repo целиком.

Сверьте Changes в GitHub Desktop: установщик и preview относительно 2.1.0/ci-fix1 не должны меняться. Согласуйте чужие удалённые изменения обычным Fetch/Pull, сохраните правку новым коммитом, выполните обычный Push. Не используйте force push/reset --hard и не добавляйте общее доверие всем каталогам Git.

Проверяйте **новый запуск на новом commit**, а не старый Re-run jobs. Старый запуск выполняет прежнюю ревизию. Нужны зелёные три задания; для 26.04 должно быть видно прохождение trust/worktree/manifest и начало полного набора. Новый полный удалённый run здесь не выполнен и не объявляется успешным заранее.

На работающей VPS не нужны установка пакетов, перезапуск Docker/Nginx/Xray, обновление сайта или reboot. Откат — отмена CI-коммита через отдельный revert-коммит после проверки diff либо возврат сохранённого исходного дерева; он не затрагивает VPS и не требует переписывания Git history.
