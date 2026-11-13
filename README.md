<a id="install"></a>
## 🚀 Установка Node Install — два способа

**Версия:** `2.5.18`, сборка `r58 Selfsteal assets hotfix 3`, статус `INCOMPLETE_STAGING_ONLY`.
**Это текущая staging-сборка**, её ещё нельзя считать проверенной на production VPS.

**Исправление Selfsteal (r58 hotfix 3):** восстановлена совместимость проверок локального HTTPS с хешированным CSS и favicon многостраничных сайтов. Для уже установленной staging-ноды предусмотрен отдельный проверяемый ремонт `scripts/selfsteal_checker_repair.py`; он не переустанавливает ноду. См. [документ исправления](docs/RELEASE_2.5.18_R58_SELFSTEAL_ASSET_HOTFIX.md).

**Исправление Debian 12:** резервное копирование в установщике использует относительные пути от `/`, чтобы исключить ошибку `cp -a --parents` из coreutils 9.1. Обновлены регрессионные тесты; серверная приёмка всё ещё необходима.
Команды ниже запускают **только интерактивное меню**: установку вы выбираете вручную.
Используйте **открытую интерактивную SSH-сессию от root на новой staging VPS**; выход из меню не удаляет предыдущие версии проекта.

### 1. 🐙 С GitHub

После публикации **всех файлов** нового релиза в ветке `main` репозитория [SUXARIK-GITHUB/Node_Install](https://github.com/SUXARIK-GITHUB/Node_Install) скопируйте **весь блок целиком** в терминал. Команда клонирует проект в новый уникальный каталог, проверяет два закреплённых SHA-256, весь манифест, идентификатор сборки и Bash-синтаксис, затем открывает меню. **Не запускайте отдельный `install.sh` по ссылке на raw-файл**: для работы необходимы `integrations/`, `scripts/`, сайты и остальные файлы.

```bash
bash <<'NODE_INSTALL_GITHUB'
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'STOP: требуется root'; exit 1; }
for bin in git python3 sha256sum; do
  command -v "$bin" >/dev/null || { echo "STOP: не установлен $bin"; exit 1; }
done
export GIT_TERMINAL_PROMPT=0
checkout="$(mktemp -d /root/NodeInstall-git-XXXXXXXX)"
git clone --depth 1 https://github.com/SUXARIK-GITHUB/Node_Install.git "$checkout"
[[ "$(git -C "$checkout" branch --show-current)" == main ]] || { echo 'STOP: нужна ветка main'; exit 1; }
cd "$checkout"
printf '%s  %s\n' 'e9622cba1676c2eadbcd24390b97c8d8bb920ab01685e03efca2c1353bd465c3' 'install.sh' | sha256sum --check
printf '%s  %s\n' '644db1a4dbafa043d44715539290809d531e2281d7156f760bd874a483af885d' 'scripts/verify_release.py' | sha256sum --check
sha256sum --check --status SHA256SUMS || { echo 'STOP: файлы репозитория не совпадают с SHA256SUMS'; exit 1; }
python3 scripts/verify_release.py --root .
python3 - <<'PY_BUILD'
import json
from pathlib import Path
m = json.loads(Path('BUILD_MANIFEST.json').read_text(encoding='utf-8'))
if (m.get('version'), m.get('build_id'), m.get('release_status')) != (
    '2.5.18', '20261113-r58-github-site-selfsteal-assets-hotfix3d-staging', 'INCOMPLETE_STAGING_ONLY'
):
    raise SystemExit('STOP: GitHub содержит другую сборку; меню не запускается')
PY_BUILD
bash -n install.sh
bash ./install.sh --menu < /dev/tty
NODE_INSTALL_GITHUB
```

**Важно:** если вы ещё не загрузили именно эту сборку в `main`, скрипт корректно завершится с `STOP`. Отсутствие TTY (запуск через cron/CI/pipe без интерактивной сессии) не позволяет открыть меню. Команда **не использует `curl | bash`**, не удаляет старые каталоги, не изменяет SSH или firewall до действий в самом меню. SHA-256 внутри репозитория не является цифровой подписью: перед первым развёртыванием сверяйте полученный ZIP с контрольной суммой из независимого доверенного источника.

### 2. 📦 Из полного ZIP-архива

Скопируйте полный архив `Node_Install_2.5.18-docs-menu_20261113-r58-github-site-selfsteal-assets-hotfix3d-staging.zip` в `/root` staging VPS. Папка новой распаковки создаётся отдельно от предыдущих версий. Нужны `unzip`, `sha256sum`, `python3` и `bash`.

```bash
bash <<'NODE_INSTALL_ARCHIVE'
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'STOP: требуется root'; exit 1; }
archive="/root/Node_Install_2.5.18-docs-menu_20261113-r58-github-site-selfsteal-assets-hotfix3d-staging.zip"
[[ -f "$archive" ]] || { echo "STOP: архив не найден: $archive"; exit 1; }
checkout="$(mktemp -d /root/NodeInstall-zip-XXXXXXXX)"
unzip -q "$archive" -d "$checkout"
cd "$checkout/Node_Install"
sha256sum --check --status SHA256SUMS
python3 scripts/verify_release.py --root .
bash -n install.sh
bash ./install.sh --menu < /dev/tty
NODE_INSTALL_ARCHIVE
```

### Перед публикацией на GitHub

**Загружайте содержимое каталога `Node_Install/`, а не вложенную папку `Node_Install/` и не один ZIP.** В корне ветки `main` должны находиться `README.md`, `install.sh`, `BUILD_MANIFEST.json`, `SHA256SUMS`, папки `integrations/`, `scripts/`, `tests/`, `site-catalog/`, `cover-variants/`, `docs/`, `preview/` и `.github/` (скрытые файлы тоже обязательны). Существующие рабочие каталоги/данные VPS не переносятся и не удаляются.

В локальном клоне, **после** переноса содержимого `Node_Install/` и **до** `git push`, выполните:

```bash
sha256sum --check SHA256SUMS
python3 scripts/verify_release.py --root .
bash -n install.sh
git add -A
git diff --cached --check
git status --short
```

Проверьте показанные изменения, создайте обычный commit и опубликуйте в `main` без `--force`. После публикации убедитесь, что GitHub Actions завершился успешно и в [манифесте ветки main](https://github.com/SUXARIK-GITHUB/Node_Install/blob/main/BUILD_MANIFEST.json) указан `20261113-r58-github-site-selfsteal-assets-hotfix3d-staging`. Если файлы будут загружены не полностью либо от другой сборки, проверки намеренно остановят запуск.

> ⚠️ **Перед реальной установкой:** необходимы проверенный snapshot VPS и доступ к аварийной консоли хостера. Установщик может менять SSH, UFW, Docker, Nginx, systemd, IPv6/GRUB и сетевые правила. **Вход по SSH-ключам не включается** — оставлена предусмотренная проектом авторизация по паролю; её риски и защиту от перебора учитывайте отдельно. Установка/reboot/backup-restore на VPS и реальная публикация сайтов по-прежнему не проверены. Итоги ранее выполненного аудита: [этап 5](docs/RELEASE_2.5.18_R58_PASS5_FINAL_AUDIT.md), контроль GitHub-публикации: [r58 GitHub QA](docs/RELEASE_2.5.18_R58_GITHUB_PUBLICATION_QA.md).

---

<div align="center">

# 🌌 VKARMANI · NODE INSTALL

**Серверная нода под контролем: от проверки VPS до REALITY и каскада**

`2.5.18 · r58` · `Ubuntu / SSH` · `VLESS · REALITY · Vision` · `IPv4`

[🗺 Карта проекта](#project-map) · [🟦 Обычная нода](#ordinary-map) · [🟪 Каскад](#cascade-map) · [🎛 Remnawave](#panel) · [📚 Документация](#documentation)

</div>

**Предыдущий r57 (ЭТАП 4, STAGING ONLY):** обновлена предметная графика и композиция первого экрана у 96 каталожных сайтов, сохранены 12 classic и 12 signature. Четыре основных раздела 120 сайтов проверены Chromium на 1280/768/390/320 px (офлайн, без публичного HTTPS). Проверены локальные ссылки, 404, CSP, 120 комплектов и воспроизводимость 108 статических копий. Новые обзорные материалы и 96 SVG не затрагивают установщик, SSH, VPN, Nginx или сеть. **Это не проверка скрытности трафика, DNS/ASN и не разрешение на production**. См. [отчёт этапа 4](docs/RELEASE_2.5.18_R57_PASS4_VISUAL_PUBLICATION.md).

**История r53 (STAGING ONLY, ПРЕДМЕТНЫЕ МАТЕРИАЛЫ ДЛЯ 120 ТЕМ):** добавлены 64 индивидуальных предметных практикума с последовательностью действий, контрольными вопросами и ограничениями. 16 тематик r51 и 40 тематик r52 сохранены. Все 120 тем получили выделенный содержательный раздел, **но это не оценка полноты или независимого редакционного качества**: короткие статьи и страницы «О проекте» требуют дальнейшей работы. Установщик, Nginx и сетевые настройки не изменены; проверки на реальной VPS не проводились. См. [docs/RELEASE_2.5.18_R53_ALL_TOPIC_GUIDES.md](docs/RELEASE_2.5.18_R53_ALL_TOPIC_GUIDES.md).

**Режим r52 (STAGING ONLY, ПРОДОЛЖЕНИЕ РЕДАКЦИОННОЙ РАБОТЫ):** добавлены 40 вручную подготовленных предметных практикумов с последовательностью, справочными таблицами и ограничениями: 16 тематических сайтов, 12 классических и все 12 самостоятельных дизайнов. Вместе с 16 материалами r51 **56 из 120** сайтов имеют отдельный углублённый раздел, остальные 64 ещё требуют такого наполнения. Все 120 требуют независимой содержательной редакторской проверки. Новые разделы видны в существующих страницах «Материалы» и доступны с главных страниц, не добавляют сервисов, внешних подключений и маршрутов. Отчёт: [docs/RELEASE_2.5.18_R52_PRACTICAL_WORKBOOKS.md](docs/RELEASE_2.5.18_R52_PRACTICAL_WORKBOOKS.md).

**Режим r51 (STAGING, ЧАСТИЧНАЯ РЕДАКЦИОННАЯ ПЕРЕРАБОТКА; НЕ Готово к production):** выявлен реальный дефект качества r50: все 96 сайтов общего генератора имеют близкий каркас, 4 краткие статьи, страницы «О проекте» объёмом примерно 45 слов. Для них введены семь информационных архитектур и собственное расположение первых экранов в 16 визуальных семействах, добавлены тематические навигационные блоки и предметные практикумы. Только **16 из 120 сайтов** получили новые полноценные разборы с примерами; у остальных содержание всё ещё требует редакционного расширения и ручной проверки. Диагностический `scripts/site_quality_review.py` перечисляет недостатки по всем 120 сайтам; технический PASS не равен качеству. Новых услуг, авторов и результатов не выдумывали, VPN/Nginx и установщик не меняли. Отчёт: [docs/RELEASE_2.5.18_R51_CONTENT_GAP_AND_ARCHITECTURES.md](docs/RELEASE_2.5.18_R51_CONTENT_GAP_AND_ARCHITECTURES.md).

**Режим r50 (STAGING, самостоятельность содержания и оформления):** 96 тематических изданий получили 384 авторских предметных продолжения статей и 288 различающихся вопросов; 12 исходных сайтов — 60 расширенных заметок и оглавления с пятью якорями. Шесть внутренних композиций чтения и локальные предметные SVG-акценты делают разделы более самостоятельными. Все 120 тем остаются статическими, без JavaScript, внешних ресурсов, трекеров и новых серверных маршрутов. Не изменялись Xray/REALITY, Nginx, SSH, DNS, IP/ASN или установщик: устойчивость VPN к DPI/ТСПУ не измерялась. См. [docs/RELEASE_2.5.18_R50_EDITORIAL_IDENTITY.md](docs/RELEASE_2.5.18_R50_EDITORIAL_IDENTITY.md).

**Режим r49 (STAGING, публичная поверхность сайтов):** убраны служебные CSS-комментарии во всех 120 публикационных комплектах. Новый fail-closed аудит запрещает технические строки VPN/VLESS/Xray/REALITY/Remnawave, ASN/ТСПУ и комментарии в публичных HTML/CSS/SVG/robots/sitemap, до модификации файлов при публикации. Для 96 тематических журналов доступны возврат к оглавлению и подсветка материала, для всех 120 — режим печати без JavaScript и внешних запросов. Никаких изменений IP/ASN, TLS, REALITY, Nginx, SSH или firewall. См. [docs/RELEASE_2.5.18_R49_PUBLIC_SITE_SURFACE.md](docs/RELEASE_2.5.18_R49_PUBLIC_SITE_SURFACE.md).

**Режим r48 (STAGING, качество сайтов):** у 96 каталожных журналов добавлено локальное оглавление четырёх статей с проверяемыми якорями, адаптивными стилями и русскими/английскими заголовками. При транзакционной публикации многостраничного сайта проверяется не только содержимое опубликованных страниц/CSS, но и иконка, а также точный HTML страницы 404 **с кодом HTTP 404** для неизвестного пути; несоответствие вызывает штатный откат. 120 тем, URL, приватность, CSP и все VPN/REALITY-настройки сохранены; live-VPS и ТСПУ не проверялись. См. [docs/RELEASE_2.5.18_R48_SITE_READING_INDEX_AND_404.md](docs/RELEASE_2.5.18_R48_SITE_READING_INDEX_AND_404.md).

**Режим r47 (STAGING, сайты):** у всех 120 тем теперь есть проверяемые `canonical` и Open Graph-метаданные с доменом конкретной ноды; страницы 404 помечены `noindex`, у 96 каталожных тем FAQ отвечает на реальные вопросы по их тематическим материалам, а описания разделов больше не повторяют друг друга. Исправлены языковые подписи иллюстраций/навигации. HTML/ссылки/CSP проверяются офлайн перед публикацией. Все 120 тем, пути, стили, клиентские профили, REALITY, Nginx и механизмы отката сохранены. Это улучшение качества сайта, **не гарантия невидимости для ТСПУ**. См. [docs/RELEASE_2.5.18_R47_SITE_IDENTITY_FAQ.md](docs/RELEASE_2.5.18_R47_SITE_IDENTITY_FAQ.md).

**Режим r46 (STAGING, сайты):** расширены редакционные материалы 96 каталожных и 12 индивидуальных тем: 384 проверяемых предметных пояснения и 48 дополнительных заметок, исправлены подписи ссылок пропуска навигации, удалён повторяемый общий контекст статей. Сохранены все 120 тем, URL, стили, локальные ресурсы и механизмы публикации с откатом. Добавлен отдельный браузерный просмотр статей на настольном и мобильном экранах. **Серверные компоненты не менялись, устойчивость к DPI не измерялась.** См. [docs/RELEASE_2.5.18_R46_SITE_TOPIC_GUIDES.md](docs/RELEASE_2.5.18_R46_SITE_TOPIC_GUIDES.md).

**Режим r45 (STAGING, сайты):** отдельно обновлён каталог 120 статических HTTPS-сайтов: для 96 тем общего генератора подготовлены 384 предметные редакционные заметки, шесть дополнительных вариантов компоновки, отдельные карточки со ссылками на статьи, обновлённые тексты, контраст акцентов и мобильные правила. Сохранены 12 классических и 12 самостоятельных дизайнерских тем; год убран из статических футеров. Все сайты остаются локальными: без JavaScript, внешних шрифтов, трекеров, фиктивных отзывов и форм. Серверные конфигурации Xray, Nginx, Docker, SSH и nftables **не менялись**. Новый HTML не гарантирует незаметности для DPI. Подробнее: [docs/RELEASE_2.5.18_R45_SITE_EDITORIAL_LAYOUT.md](docs/RELEASE_2.5.18_R45_SITE_EDITORIAL_LAYOUT.md).

**Режим r44 (STAGING):** исправлен контроль действующих ограничений трафика nftables: проверяются не только таблица и счётчики, но и цепочки, интерфейс, исключения SSH/Node API, порядок правил, значения квот и скорость. При неполной или чужой таблице операции `status/apply/snapshot/reset` останавливаются без автоматического сброса квот и без изменения firewall. Изменение предусмотрено для новых установок; ранее установленный скрипт на VPS автоматически не заменяется. Подробности: [docs/RELEASE_2.5.18_R44_TRAFFIC_RULESET_INTEGRITY.md](docs/RELEASE_2.5.18_R44_TRAFFIC_RULESET_INTEGRITY.md).

**Режим r43 (STAGING):** функции r42 (проверенный выбор темы и HTTP/2-аудит) сохранены. Добавлены **необязательные** и ограниченные проверки TCP/443 и загрузки заранее размещённого собственного HTTPS-файла, офлайн-сопоставление отчётов из разных сетей, аудит потенциальных клиентских `direct`-маршрутов и матрица REALITY/XHTTP для проверенных версий клиентов. Эти средства **не** меняют Xray, Remnawave, Nginx, firewall, SSH, подписки и каскад. При наличии `direct` или отсутствующей проверки маршрута инструмент не утверждает, что утечек нет. Сравнение сетевых путей не доказывает вмешательство ТСПУ. Подробнее: [docs/RELEASE_2.5.18_R43_STEALTH_PATH_EVIDENCE.md](docs/RELEASE_2.5.18_R43_STEALTH_PATH_EVIDENCE.md).

**Восстановление экрана SSH:** интерфейс автоматически повторяет полную перерисовку после простоя, включая свёрнутое окно. Если окно PuTTY/MobaXterm по-прежнему чёрное, нажмите `Ctrl+L` — это перерисует текущий экран без перезапуска процесса и установки.

Node Install — инструмент для развёртывания и обслуживания серверной части VKARMANI. Он собирает установку, проверку VPS, работу с маскирующим сайтом и диагностику в одно терминальное меню. Его задача — сделать сложные серверные действия понятными и воспроизводимыми, а не скрывать от администратора, что именно меняется на машине.

**Здесь есть две схемы работы:** одна обычная нода либо каскад из двух независимых VPS. Ниже — путь трафика, состав проекта и то, что потребуется настроить в Remnawave. Подробная история изменений находится в [CHANGELOG.md](CHANGELOG.md), а не в начале README.

<a id="navigation"></a>
## 🧭 Где что находится

| Нужно сделать | Открыть |
|:--|:--|
| Запустить на новой VPS | [🐙 GitHub или 📦 ZIP](#install) |
| Понять, из чего состоит проект | [🗺 Карта проекта](#project-map) |
| Настроить одну ноду | [🟦 Ordinary](#ordinary-map) · [RAW](#raw) · [XHTTP](#xhttp) |
| Собрать Entry → Exit | [🟪 Каскад](#cascade-map) · [Профили](#cascade) · [Порядок установки](#cascade-setup) |
| Подключить ноды в панели | [🎛 Remnawave](#panel) |
| Проверить VPS и экспортировать отчёт | [🔎 Диагностика](#diagnostics) |
| Включить фильтр рекламы | [🛡 Blocky](#adblock) |
| Выбрать маскирующий сайт | [🎨 120 сайтов](#sites-tcp-probes) |
| Проверить безопасность и восстановление | [🛡 Границы и откат](#safety) · [🛠 Команды](#operations) |

<a id="project-map"></a>
## 🗺 Карта проекта

```mermaid
flowchart TB
    ADMIN["👤 Администратор<br/>SSH / Terminal"] --> MENU["🎛 install.sh --menu<br/>Проверка VPS · Установка · Управление"]
    MENU --> DIAG["🔎 Диагностика<br/>IP / ASN / DNS / TLS / RTT / ресурсы"]
    MENU --> WIZARD["🧭 Мастер установки<br/>Ordinary / Entry / Exit"]
    MENU --> OPS["🛠 Обслуживание<br/>Журнал · Сайт · Backup · Проверки"]
    OPS --> ADBLOCK["🛡 Blocky · необязательно<br/>HaGeZi Normal · loopback DNS"]
    NODE -.->|DNS только при маршрутизации из Panel| ADBLOCK
    WIZARD --> CORE["⚙️ install.sh<br/>Сценарии установки и отката"]
    CORE --> HOST["🖥 Ubuntu VPS<br/>SSH · UFW · systemd · Docker · Nginx"]
    CORE --> NODE["🔐 RemnaNode / Xray<br/>REALITY · Vision"]
    CORE --> WEB["🎨 Сайт-прикрытие<br/>120 тем · Selfsteal"]
    NODE -.-> PANEL["🎛 Remnawave Panel<br/>Node API · Config Profiles"]
    OPS --> WEB
    DIAG --> REPORT["📄 Отчёт<br/>TXT · JSON · PNG"]
    TESTS["🧪 tests/ · GitHub Actions"] -.-> CORE
    TESTS -.-> DIAG
    classDef operator fill:#dbeafe,stroke:#2563eb,color:#1e40af,stroke-width:1.5px;
    classDef action fill:#e0f2fe,stroke:#0284c7,color:#075985,stroke-width:1.5px;
    classDef host fill:#dcfce7,stroke:#16a34a,color:#166534,stroke-width:1.5px;
    classDef control fill:#fef3c7,stroke:#d97706,color:#78350f,stroke-width:1.5px;
    class ADMIN operator;
    class MENU,WIZARD,CORE,DIAG,OPS action;
    class HOST,NODE,WEB,REPORT host;
    class PANEL,TESTS,ADBLOCK control;
```

<details>
<summary>📁 Структура репозитория — что за что отвечает</summary>

```text
Node_Install/
├── install.sh                  Главный CLI и установщик
├── scripts/
│   ├── terminal_ui.py          Терминальное меню и навигация
│   ├── verify_release.py       Контроль состава, хешей и версии
│   ├── staging_web_deploy.py   Развёртывание и откат сайта
│   ├── site_manager.py         Управление каталогом тем
│   └── ...                     Диагностика, подготовка, аудит
├── integrations/
│   ├── vps_dashboard.py        Сбор данных диагностики
│   ├── vps_report.py           Разделы отчёта и экспорт PNG
│   ├── traffic_limits.py      Лимиты скорости/объёма
│   ├── adblock.py             Blocky / HaGeZi Normal, локальный DNS
│   ├── cascade_*.py           Подготовка и проверки каскада
│   └── ...                     Сетевые и Xray-модули
├── site-catalog/              108 тем статических сайтов
├── cover-variants/            12 исходных отдельных тем
├── preview/                   Локальная галерея и превью
├── examples/                  Образцы полных Xray JSON
├── tests/                     Автономные тесты и сценарии отказа
├── docs/                      Инструкции, исследования, история
├── .github/workflows/         GitHub Actions (матрица ОС)
├── BUILD_MANIFEST.json        Состав и SHA-256 релиза
└── SHA256SUMS                 Контрольные суммы файлов
```

</details>

### Что уже можно делать

- **🔎 Проверять VPS.** Русскоязычный экран с девятью разделами: ресурсы, IP/ASN, геолокация, сайты/API, DNS/TLS, задержки, CDN и сеть. Отчёт можно сохранить в TXT/JSON/PNG.
- **🟦 Разворачивать Ordinary.** RAW + REALITY + Vision — основной сценарий; XHTTP — альтернативный профиль, а не второй слушатель на том же порту.
- **🟪 Готовить каскад.** Отдельные роли Entry и Exit, собственные ключи и закрытый служебный мост; для работы требуются настройки Remnawave.
- **🎨 Выбирать сайт.** В комплекте **120 тематик**: 12 отдельных исходных и 108 в каталоге, включая 12 дополнительно оформленных композиций. Это не 120 полностью независимых движков.
- **🧰 Обслуживать установленную ноду.** Просмотр журнала, диагностика, управляемые изменения сайта, ограниченные сценарии rollback и проверка конфигурации.
- **🛡 Включить Blocky (необязательно).** Автоматическая установка DNS-фильтра с HaGeZi Normal, ежедневное обновление списка и безопасное выключение фильтрации. **DNS клиентов Remnawave настраивается в Panel отдельно**, поскольку профиль ноды управляется панелью.

<a id="roles"></a>
## 🧩 Два режима работы

| | 🟦 Обычная нода | 🟪 Каскад Entry → Exit |
|:--|:--|:--|
| VPS | **1 сервер** | **2 независимых сервера** |
| Путь | Клиент → Ordinary → Интернет | Клиент → Entry → Exit → Интернет |
| Роль сервера | Принимает и выпускает трафик | Entry принимает; Exit выпускает |
| Профили Panel | Один Ordinary | Два разных: Entry и Exit |
| Публичный Host клиента | На Ordinary | **Только на Entry** |
| При потере следующего узла | Нет второго узла | На Entry **нет DIRECT fallback** |

<a id="architecture"></a>
<a id="ordinary-map"></a>
### 🟦 Карта 1 · Обычная нода

```mermaid
flowchart LR
    CLIENT["📱 Клиент<br/>VLESS / REALITY"] -->|"TCP 443 · RAW / Vision"| XRAY["🔐 Ordinary VPS<br/>Xray / RemnaNode"]
    XRAY -->|"Разрешённый IPv4 / DIRECT"| FW["🛡 Фильтрация<br/>UFW / outbound rules"]
    FW --> NET["🌍 Интернет"]
    XRAY -.->|"Неавторизованный TLS"| NGX["🪟 Nginx Selfsteal<br/>Unix socket / PROXY v1"]
    NGX --> SITE["🎨 Выбранная тема<br/>HTTPS-сайт"]
    PANEL["🎛 Remnawave Panel"] -.->|"Node API TCP 2222<br/>ACL IP/FQDN панели"| XRAY
    XRAY -.->|"Закрытые файлы 0600"| KEYS["🗝 REALITY-ключи<br/>RAW / XHTTP профили"]
    XRAY -.->|"DNS только при явной настройке в Panel"| BLOCKY["🛡 Blocky / HaGeZi<br/>127.0.0.1:15353"]
    classDef client fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a,stroke-width:1.5px;
    classDef core fill:#cffafe,stroke:#0891b2,color:#164e63,stroke-width:2px;
    classDef net fill:#dcfce7,stroke:#16a34a,color:#14532d,stroke-width:1.5px;
    classDef ctl fill:#fef3c7,stroke:#d97706,color:#78350f,stroke-width:1.5px;
    class CLIENT client;
    class XRAY core;
    class FW,NET,NGX,SITE net;
    class PANEL,KEYS,BLOCKY ctl;
```

**Как читать карту.** Клиент подключается к публичному домену и TCP/443. Успешно авторизованный VLESS-трафик после правил фильтрации уходит в Интернет с IPv4 ноды. Другой TLS-трафик может попадать в локальную цепочку Nginx Selfsteal, где отображается выбранный сайт. Панель управляет Node API по отдельному порту с ограничением источника — **не открывайте 2222 всему Интернету**.

Для Ordinary нужен один Node, один активный профиль и Host в Remnawave. RAW и XHTTP выбираются **альтернативно**, не одновременно на TCP/443. Полные образцы ниже: [RAW + REALITY + Vision](#raw) и [XHTTP + REALITY](#xhttp).

<a id="cascade-map"></a>
### 🟪 Карта 2 · Каскад Entry → Exit

```mermaid
flowchart LR
    CLIENT["📱 Клиент"] -->|"VLESS / REALITY :443"| ENTRY["🟪 ENTRY VPS<br/>Клиентский inbound"]
    ENTRY -->|"TO_EXIT_VLESS<br/>служебный UUID / REALITY"| EXIT["🟩 EXIT VPS<br/>Bridge inbound"]
    EXIT -->|"DIRECT после фильтров"| NET["🌍 Интернет<br/>Внешний IPv4 Exit"]
    ENTRY -.->|"Exit недоступен"| DENY["⛔ Блокировать<br/>без DIRECT fallback"]
    PANEL["🎛 Remnawave Panel"] -.->|"Node API · ACL"| ENTRY
    PANEL -.->|"Node API · ACL"| EXIT
    ENTRY -.->|"Selfsteal"| SITE1["🖥 Nginx Entry"]
    EXIT -.->|"Selfsteal"| SITE2["🖥 Nginx Exit"]
    EXIT -.->|"DNS при настройке Panel"| BLOCKY["🛡 Blocky<br/>только Exit · необязательно"]
    classDef user fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a,stroke-width:1.5px;
    classDef entry fill:#ede9fe,stroke:#7c3aed,color:#4c1d95,stroke-width:2px;
    classDef exit fill:#dcfce7,stroke:#16a34a,color:#14532d,stroke-width:2px;
    classDef ctl fill:#fef3c7,stroke:#d97706,color:#78350f,stroke-width:1.5px;
    classDef denied fill:#fee2e2,stroke:#dc2626,color:#7f1d1d,stroke-width:1.5px;
    class CLIENT user;
    class ENTRY entry;
    class EXIT,NET,SITE1,SITE2 exit;
    class PANEL,BLOCKY ctl;
    class DENY denied;
```

**Суть каскада:** клиент знает адрес **Entry**; Entry принимает соединение и передаёт разрешённый трафик в **Exit** по отдельному служебному соединению. Внешний IPv4 для сайтов — адрес **Exit**. Если Exit недоступен, Entry не должен переключаться на прямой Интернет. Это обязательное свойство конфигурации, которое нужно проверить живым тестом, а не только наличием правил в JSON.

На каждой VPS своя пара REALITY-ключей, свой профиль, свой сайт и свой Node в Panel. Клиентский Host публикуется **только на Entry**. Bridge-user (service-user) назначается отдельным пользователем и Internal Squad **только Exit**. Правильный порядок развёртывания: **сначала Exit, затем Entry**, на разных чистых VPS. [Практический runbook](docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md).

<a id="requirements"></a>
## ✅ Что подготовить до установки

| Что | Зачем |
|:--|:--|
| **Новая VPS с Ubuntu** и root-доступом | Установщик меняет общесистемные службы и доступ |
| **Публичный IPv4 и домен с DNS A** | Клиентское подключение и сертификат |
| **IP или домен Remnawave Panel** | Настройка ACL для Node API TCP/2222 |
| **SECRET_KEY ноды** | Подключение Ordinary к панели; не публикуйте его |
| **Snapshot и аварийная консоль** | Восстановление SSH/сети при неудачной установке |
| **Для каскада — два отдельных role-bundle.json** | Не смешивать ключи Entry/Exit; права `0600` |

**Парольный SSH:** текущая политика проекта использует парольный вход вместо SSH-ключей. Это осознанная конфигурация, требующая сильного пароля, защиты от перебора и доступа к консоли провайдера. Не делайте неподготовленную смену SSH/UFW на рабочем сервере.

<a id="diagnostics"></a>
## 🔎 Проверка VPS перед установкой

Выбери первый пункт и дождись отчёта — никаких IP, адресов или настроек вводить не придётся. Первый пункт меню — не просто «доступен / недоступен». Он помогает понять, какой сервер вы получили: ресурсы, IP и ASN, разные ответы GeoIP, DNS, доступность HTTPS-сервисов, задержки, потери, маршрут и CDN. Результаты разделены по девяти экранам и снабжены русскими пояснениями.

**Управление:** колесо мыши (если SSH-клиент передаёт события), стрелки и `PgUp/PgDn`; `0` — сводка, `1–9` — разделы, `E` — сохранение **TXT / JSON / PNG** в приватную папку. **Ничего вводить не нужно:** при выборе «Проверка VPS» автоматически запускаются все разделы, включая щадящий тест CPU/RAM (0,25 секунды CPU), временную запись диска (8 MiB) и небольшую HTTPS-проверку входящей/исходящей скорости до Cloudflare (не более 2 MiB на направление). Случаи ошибки показываются как «не измерено», а не заменяются выдуманными цифрами. Цветные статусы помогают быстро читать отчёт, но не подменяют измерения: `403` не всегда означает блокировку, а GeoIP не доказывает «чистоту» адреса.

Подробности: [автоматическая проверка](docs/RELEASE_2.5.18_R35_AUTOMATIC_VPS.md) · [диагностика VPS](docs/RELEASE_2.5.18_R32_VPS_DASHBOARD.md) · [о качестве сети](docs/EXTERNAL_PATH_DIAGNOSTICS_2.5.0.md).

<a id="adblock"></a>
## 🛡 Блокировка рекламы · Blocky / HaGeZi Normal

В **«Дополнительных настройках»** новой Ordinary/Exit-ноды включи Blocky или используй **«Управление нодой → Блокировка рекламы»** после установки. Blocky v0.35.0 устанавливается только по твоему выбору, автоматически загружает проверенный HaGeZi Normal и обновляет его по расписанию без ручной замены файлов. Отключение фильтрации не выключает DNS-службу, чтобы клиенты не теряли разрешение доменов.

**Главное ограничение:** ноде не передаются учётные данные или права на изменение панели. Blocky слушает только `127.0.0.1:15353`, а рабочий Xray-профиль доставляет Remnawave Panel. Поэтому установка Blocky сама по себе **не означает, что DNS всех VPN-клиентов направлен на него**. Пример DNS для профиля сохраняется локально; перед эксплуатацией требуется отдельная проверка маршрутизации и реальных клиентов. На Cascade Entry Blocky не устанавливается — только на Exit.

<details><summary>Команды управления</summary>

```bash
sudo bash install.sh --adblock status
sudo bash install.sh --adblock enable
sudo bash install.sh --adblock disable
sudo bash install.sh --adblock update
sudo bash install.sh --adblock probe
```

</details>

Подробности безопасности и ограничения: [Интеграция Blocky r37](docs/RELEASE_2.5.18_R37_ADBLOCK_BLOCKY.md).

<a id="panel"></a>
## 🎛 Remnawave — что создать в панели

Установщик на VPS **не создаёт автоматически** Nodes, Hosts и Internal Squads в панели. Их назначает администратор. В `Config Profiles` используется готовый JSON своей роли, затем профиль связывается с Node, включается inbound и задаются права пользователей.

| Объект | 🟦 Ordinary | 🟪 Entry / Exit |
|:--|:--|:--|
| **Nodes** | Один Ordinary | Два разных: Entry и Exit |
| **Config Profile** | [RAW](#raw) **или** [XHTTP](#xhttp) | [Entry](#cascade-entry-json) **и** [Exit](#cascade-exit-json) |
| **Активный inbound** | Уникальный `VK_RAW_*` | `VK_CASCADE_ENTRY_*` и `VK_CASCADE_EXIT_*` |
| **Host в подписке** | На Ordinary TCP/443 | **Только Entry** TCP/443 |
| **Internal Squad** | Клиенты Ordinary | Клиенты → Entry; service-user → **только Exit** |
| **Bridge VLESS UUID** | Не требуется | На Entry — **VLESS UUID service-user на Exit** |

**После успешной Ordinary-установки:** приватный полный профиль RAW находится в `/root/vkarmani-raw-profile.json`; альтернативный XHTTP-шаблон — в `/root/vkarmani-xhttp-profile.json` (когда он подготовлен). Их нельзя публиковать: внутри есть чувствительные параметры. Для панели используют только профиль, подходящий фактическому inbound.

Не переносите `REPLACE_WITH_*` из примеров в работающую панель: образцы показывают структуру, а реальные ключи и идентификаторы должны быть сгенерированы на своих нодах. Убедитесь, что `inbound.tag` не повторяет другие активные inbound.

[Официальная документация Config Profiles](https://docs.rw/learn-en/config-profiles/) · [Hosts](https://docs.rw/learn-en/hosts/) · [Internal Squads](https://docs.rw/learn-en/squads/).

<a id="selfsteal"></a>
<a id="firewall"></a>
<a id="safety"></a>
## 🛡 Сеть, Selfsteal и безопасность

- **Публичный HTTP/80** нужен для ACME/редиректа; HTTPS/TLS проверяйте также снаружи VPS.
- **Node API TCP/2222** должен быть доступен только разрешённым IP панели (или IPv4, полученным из её домена). Не открывайте управляющий порт всему Интернету.
- **IPv6** выключается в соответствии с текущей политикой проекта; после перезагрузки проверяйте реальную маршрутизацию, а не только настройки файлов.
- **Selfsteal и REALITY** помогают организовать TLS-цепочку с локальным сайтом. Они не являются гарантией отсутствия блокировок, обнаружения или сетевых ограничений. Cover/REALITY **не гарантируют** доступность из любой сети.
- **Незавершённая установка** — повод проверить журнал и checkpoint, а не запускать установку поверх повреждённых конфигов. Полное восстановление системы выполняется из проверенного snapshot, а не из кнопки «удалить».

<a id="inbounds"></a>
## 📋 Полные образцы профилей Xray для Remnawave

Код ниже оставлен без сокращений: каждый полный JSON можно сверить с файлами в `examples/`. Он помещён под раскрывающиеся заголовки, чтобы README можно было читать без погружения в Xray-синтаксис.


Все примеры **полные Xray JSON**. Они содержат `REPLACE_WITH_*`, зарезервированные IP и демонстрационные FQDN — не реальные ключи. Для практического развертывания используйте **сгенерированный профиль своей VPS**, а примеры — для проверки структуры и правил.

<a id="raw"></a>
### ⚡ Ordinary · RAW + REALITY + Vision

RAW — основной профиль, `flow: xtls-rprx-vision`; один listener `0.0.0.0:443`. Пример совпадает с [`examples/inbound-raw-full.example.json`](examples/inbound-raw-full.example.json).

<details>
<summary><b>Показать полный RAW inbound + outbound + routing</b></summary>

<!-- BEGIN RAW FULL EXAMPLE -->

```json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "serveStale": true,
    "serveExpiredTTL": 3600,
    "enableParallelQuery": true
  },
  "inbounds": [
    {
      "tag": "VK_RAW_REALITY_REPLACE_WITH_NODE_TAG",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": "xtls-rprx-vision"
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "node.example.com"
          ],
          "privateKey": "REPLACE_WITH_PRIVATE_KEY_FROM_NODE",
          "shortIds": [
            "REPLACE_WITH_SHORT_ID_FROM_NODE"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4",
        "finalRules": [
          {
            "ip": [
              "geoip:private",
              "::/0"
            ],
            "action": "block"
          }
        ]
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private",
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "203.0.113.10/32",
          "::/0",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      }
    ]
  }
}
```

<!-- END RAW FULL EXAMPLE -->

</details>

<a id="xhttp"></a>
### 🌐 Ordinary · XHTTP + REALITY

Альтернатива RAW, **не второй одновременный listener на 443**. `flow` пустой, `xhttpSettings.path` генерируется самой нодой. Переключение профиля — в Panel; `--prepare-xhttp` только готовит JSON. [Runbook XHTTP](docs/TRANSPORT_SWITCHING_2.5.4.md).

<details>
<summary><b>Показать полный XHTTP inbound + outbound + routing</b></summary>

<!-- BEGIN XHTTP FULL EXAMPLE -->

```json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "serveStale": true,
    "serveExpiredTTL": 3600,
    "enableParallelQuery": true
  },
  "inbounds": [
    {
      "tag": "VK_RAW_REALITY_REPLACE_WITH_NODE_TAG",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": ""
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "node.example.com"
          ],
          "privateKey": "REPLACE_WITH_PRIVATE_KEY_FROM_NODE",
          "shortIds": [
            "REPLACE_WITH_SHORT_ID_FROM_NODE"
          ]
        },
        "xhttpSettings": {
          "host": "node.example.com",
          "path": "/REPLACE_WITH_NODE_GENERATED_XHTTP_PATH",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4",
        "finalRules": [
          {
            "ip": [
              "geoip:private",
              "::/0"
            ],
            "action": "block"
          }
        ]
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private",
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "203.0.113.10/32",
          "::/0",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      }
    ]
  }
}
```

<!-- END XHTTP FULL EXAMPLE -->

</details>

<a id="cascade"></a>
## ⛓️ Каскад · два независимых inbound

| Параметр | 🧭 Entry (вход) | 🌍 Exit (выход) |
|---|---|---|
| Клиенты `clients` | Управляет Panel, только тестовые клиенты | **Только мостовой service-user** через отдельный Squad |
| Transport | `raw` + `reality`, Vision | `raw` + `reality`, Vision |
| `target` и `xver` | Локальный Nginx `/dev/shm/nginx.sock`, `1` | Свой локальный Nginx `/dev/shm/nginx.sock`, `1` |
| Основной outbound | `TO_EXIT_VLESS` | `DIRECT` **после проверки bridge-user** |
| Безопасный fallback | `BLOCK` — **первый outbound** | `BLOCK` и `finalRules` для приватных IP |
| DNS | `domainStrategy: AsIs`, **без встроенного DNS** | IPv4 DNS на Exit; локальная обработка только там |
| REALITY | **Своя** пара ключей и короткий ID | **Другая** пара ключей и короткий ID |

Полные JSON ниже **синхронизированы с `integrations/cascade_profiles.py`**. Они включают inbound, outbound, правила private-IP/IPv6 block и обработку клиентских соединений. При замене всех плейсхолдеров важны совпадение UUID, публичного ключа и `shortId` Exit с мостовым outbound Entry. Разные inbound tags обязательны: дубликат `tag` Remnawave отклонит.

<a id="cascade-entry-json"></a>
### 🧭 1. Entry — клиентский inbound и мост в Exit

[Справочный JSON Entry](examples/cascade-entry-profile.reference.json) · [Ролевой генератор](integrations/cascade_profiles.py)

- **Вход:** VLESS RAW/REALITY/Vision, `0.0.0.0:443`; `clients` назначаются Panel.
- **Маршрут:** block для BitTorrent и private/IPv6, затем весь разрешённый клиентский трафик в `TO_EXIT_VLESS`. **Никакого DIRECT, DNS-resolver или balancer на Entry.**
- **Мост:** Exit IPv4:443, `service_user_uuid` именно пользователя Exit, `serverName`/`publicKey`/`shortId` **выходной** ноды.

<details>
<summary><b>Показать полный JSON Entry · inbound + TO_EXIT_VLESS + routing</b></summary>

<!-- BEGIN CASCADE ENTRY FULL EXAMPLE -->
```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "VK_CASCADE_ENTRY_REALITY_REPLACE_WITH_REAL_TAG",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": "xtls-rprx-vision"
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "entry.example.com"
          ],
          "privateKey": "REPLACE_WITH_ENTRY_PRIVATE_KEY",
          "shortIds": [
            "REPLACE_WITH_ENTRY_SHORT_ID"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    },
    {
      "tag": "TO_EXIT_VLESS",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "198.51.100.20",
            "port": 443,
            "users": [
              {
                "id": "REPLACE_WITH_EXIT_SERVICE_USER_UUID",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "serverName": "exit.example.com",
          "fingerprint": "chrome",
          "publicKey": "REPLACE_WITH_EXIT_PUBLIC_KEY",
          "shortId": "REPLACE_WITH_EXIT_SHORT_ID",
          "spiderX": "/"
        }
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "::/0",
          "203.0.113.10/32",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "inboundTag": [
          "VK_CASCADE_ENTRY_REALITY_REPLACE_WITH_REAL_TAG"
        ],
        "outboundTag": "TO_EXIT_VLESS"
      }
    ]
  }
}
```
<!-- END CASCADE ENTRY FULL EXAMPLE -->

</details>

<a id="cascade-exit-json"></a>
### 🌍 2. Exit — bridge inbound и фильтр выхода

[Справочный JSON Exit](examples/cascade-exit-profile.reference.json) · [Сценарий установки](docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md)

- **Вход:** отдельный VLESS/REALITY на 443. Только назначенный **Panel service-user** из закрытого Exit Internal Squad.
- **Выход:** `DIRECT` через IPv4 после фильтров `routing` и `freedom.finalRules`, с запретом частных/служебных/IPv6 сетей; BitTorrent блокируется.
- **Fallback:** собственный Nginx и независимые REALITY ключи; **никаких** исходящих `TO_EXIT_VLESS` на Exit.

<details>
<summary><b>Показать полный JSON Exit · inbound + DIRECT + routing</b></summary>

<!-- BEGIN CASCADE EXIT FULL EXAMPLE -->
```json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "VK_CASCADE_EXIT_REALITY_REPLACE_WITH_REAL_TAG",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "flow": "xtls-rprx-vision"
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nginx.sock",
          "xver": 1,
          "minClientVer": "0.0.0",
          "spiderX": "/",
          "serverNames": [
            "exit.example.com"
          ],
          "privateKey": "REPLACE_WITH_EXIT_PRIVATE_KEY",
          "shortIds": [
            "REPLACE_WITH_EXIT_SHORT_ID"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4",
        "finalRules": [
          {
            "ip": [
              "0.0.0.0/8",
              "10.0.0.0/8",
              "100.64.0.0/10",
              "127.0.0.0/8",
              "169.254.0.0/16",
              "172.16.0.0/12",
              "192.0.0.0/24",
              "192.0.2.0/24",
              "192.168.0.0/16",
              "198.18.0.0/15",
              "198.51.100.0/24",
              "203.0.113.0/24",
              "224.0.0.0/4",
              "240.0.0.0/4",
              "::/0",
              "203.0.113.10/32",
              "198.51.100.20/32"
            ],
            "action": "block"
          }
        ]
      },
      "streamSettings": {
        "sockopt": {
          "domainStrategy": "ForceIPv4"
        }
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "224.0.0.0/4",
          "240.0.0.0/4",
          "::/0",
          "203.0.113.10/32",
          "198.51.100.20/32"
        ],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "inboundTag": [
          "VK_CASCADE_EXIT_REALITY_REPLACE_WITH_REAL_TAG"
        ],
        "outboundTag": "DIRECT"
      }
    ]
  }
}
```
<!-- END CASCADE EXIT FULL EXAMPLE -->

</details>

> [!CAUTION]
> Это **образцы для разбора**, не готовые для импорта: у них несуществующие приватные ключи, UUID и документационные IP. Не заменяйте автоматически весь профиль реальной панели. Для использования сначала генерируется **закрытая пара**, после чего каждая VPS получает только собственный приватный ключ. Проверка конфигурации — обязательна перед первым клиентским подключением.

<a id="cascade-setup"></a>
### 🔧 Подготовка и установка каскада на двух чистых staging VPS

На **защищённой машине оператора** с установленной зависимостью `cryptography` создайте пару, указав свои **реальные** IPv4/FQDN (не `203.0.113.0/24`, не `198.51.100.0/24`). Каталог `/root` и создаваемые bundles должны оставаться root-only:

```bash
umask 077
sudo python3 integrations/cascade_deployment.py create-pair \
  --entry-domain "$ENTRY_DOMAIN" --entry-ipv4 "$ENTRY_IPV4" \
  --exit-domain "$EXIT_DOMAIN" --exit-ipv4 "$EXIT_IPV4" \
  --output /root/cascade-private-pair.json
sudo python3 integrations/cascade_deployment.py prepare \
  --pair /root/cascade-private-pair.json \
  --output /root/cascade-private-split
```

**Разделить секреты:** на Exit передать **только** `exit/role-bundle.json`; на Entry — **только** `entry/role-bundle.json`. Не помещать закрытые JSON в Git, чат или открытые журналы.

```bash
# Сначала Exit, затем Entry; команды на РАЗНЫХ VPS.
# EXIT VPS:
sudo bash ./install.sh --cascade-role exit \
  --cascade-bundle /root/cascade/exit/role-bundle.json --no-reboot

# ENTRY VPS:
sudo bash ./install.sh --cascade-role entry \
  --cascade-bundle /root/cascade/entry/role-bundle.json --no-reboot
```

Далее назначить объекты тестовой Panel согласно [пошаговому runbook](docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md), проверить фактический JSON командой аудитора и только затем — реальных клиентов. Автоматического создания Panel Nodes/Hosts/Squads здесь **нет**.

<a id="sites-tcp-probes"></a>
## 🎨 Сайты и маскирующие страницы

В комплекте **120 тем**: 12 оригинальных вариантов в `cover-variants/` и 108 в `site-catalog/` (из них 12 — дополнительные авторские HTML-композиции). У каждой темы есть основные ресурсы и страница HTTP 404; это не 120 разных веб-движков. Локальную галерею можно открыть в браузере: `preview/site-gallery/index.html`.

**Изменить тему на уже установленной тестовой ноде** можно после snapshot, строго с проверкой домена и Nginx:

```bash
sudo python3 scripts/staging_web_deploy.py site-change --theme 110-blue-harbor --expected-domain node.example.com --confirm-staging
sudo python3 scripts/staging_web_deploy.py status
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
```

Новая тема при обычной установке публикуется лишь после успешной финализации основной ноды. Ошибка публикации сайта может дать код `20` при уже установленном ядре — это **не полный успех**: проверяйте журнал и откат сайта. Подробности: [каталог и безопасность](docs/RELEASE_2.5.18_R21_CATALOG_AND_SAFETY.md) · [управление сайтом](docs/RELEASE_2.5.18_R24_PHASE1_SITES_SELFSTEAL_NETWORK.md).

<a id="rkn"></a>
## 🛡 RKN / UFW / доступ панели

Отдельные RKN-списки не заменяют основной ACL Node API. При смене IP панели проверяйте реальные разрешённые источники; не используйте слепой сброс UFW на работающей машине.

```bash
sudo bash ./install.sh --rkn-status
sudo bash ./install.sh --rkn-update
sudo bash ./install.sh --rkn-sync-panel
```

[Политика RKN](docs/RKN_FAILSAFE_2.5.9.md) · [Security](SECURITY.md).

<a id="operations"></a>
## 🛠 Обслуживание и диагностика

| Команда | Для чего |
|:--|:--|
| `bash ./install.sh --menu` | Открыть главное меню; выход возвращает SSH-оболочку |
| `sudo bash ./install.sh --check` | Локальная проверка ноды, не замена тесту клиента |
| `bash ./install.sh --diagnose-network` | Счётчики и сетевое состояние |
| `bash ./install.sh --diagnose-selfsteal` | Диагностика Nginx / Selfsteal |
| `bash ./install.sh --diagnose-resources --seconds 15` | Краткая динамика ресурсов |
| `bash ./install.sh --vps-check --format table full` | Проверка VPS в текстовом виде |
| `bash ./install.sh --help` | Все доступные опции CLI |

При установке из терминального меню живой журнал пишется в закрытый файл `/root/node-install-*.log` (права `0600`). Доступ к приватным REALITY-ключам также ограничен: отображение `PrivateKey` требует отдельного действия, копирование через OSC 52 зависит от клиента SSH. Нельзя выкладывать такие файлы в Issues, логи CI или общедоступные чаты.

Если установку пришлось прервать, **сначала прочитайте журнал**. Не удаляйте `/var/lib/vkarmani-node`, checkpoint, Docker volumes и резервные копии ради «чистого повтора». Для восстановления системных настроек используйте проверенный snapshot и [документацию оператора](docs/OPERATIONS.md).

<a id="verification"></a>
## 🧪 Проверки перед реальным использованием

```bash
# Из каталога чисто распакованного исходного релиза
sha256sum --check SHA256SUMS
python3 scripts/verify_release.py --root .
bash -n install.sh
bash tests/run.sh
```

Релизный манифест и контрольные суммы проверяют содержимое исходного пакета. GitHub Actions проверяет код на нескольких Linux-окружениях. Эти тесты **не заменяют** установку на отдельной VPS с последующей перезагрузкой и проверкой SSH, DNS/TLS, Docker, Nginx, панели и реального клиента.

Для каскада обязательна отдельная проверка фактического выхода через Exit, DNS/UDP и поведения при его отключении. **XHTTP, Hysteria2, AmneziaWG2 и FinalMask нельзя считать автоматически установленными или проверенными на живой сети только по наличию JSON/шаблонов**. Подробнее: [готовность транспортов](docs/RELEASE_2.5.18_R25_TRANSACTION_AND_TRANSPORT_READINESS.md) и [проверки каскада](docs/R7_SITES_TCP_AND_LIVE_PROBES.md).

<a id="documentation"></a>
## 📚 Документация и история

| Раздел | Ссылка |
|:--|:--|
| Все изменения проекта, включая r22–r35 | [CHANGELOG.md](CHANGELOG.md) |
| Системная безопасность | [SECURITY.md](SECURITY.md) |
| Повседневная эксплуатация | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Схема и логика каскада | [Каскад r5](docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md) · [r6](docs/R6_CASCADE_OPERATIONS_AND_GATES.md) |
| Состояние REALITY / Nginx / Selfsteal | [Общий обзор](docs/SELFSTEAL_2.2.0.md) |
| Версии Xray | [Xray Core](docs/XRAY_CORE_UPDATES_2.5.5.md) |
| Архивная документация 2.5.15 | [Исторический README](docs/history/README_2.5.4.md) |
| Ранние архитектурные решения 2.5.13 и защита сети 2.5.9 | [Темы r12](docs/RELEASE_2.5.13_R12_SITES.md) · [RKN](docs/RKN_FAILSAFE_2.5.9.md) |

---

<div align="center">

**VKARMANI · Node Install 2.5.18**

[⬆️ Две команды установки](#install) · [🗺 Проект](#project-map) · [🟦 Ordinary](#ordinary-map) · [🟪 Каскад](#cascade-map) · [🔐 Security](SECURITY.md)

</div>
