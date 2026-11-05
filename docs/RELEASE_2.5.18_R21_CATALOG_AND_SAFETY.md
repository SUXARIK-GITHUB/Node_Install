# Node_Install 2.5.18 r21 — независимые сайты и проверяемая диагностика

**Состояние: `INCOMPLETE_STAGING_ONLY`.** 2026-11-05. Базовый исходник: полный ZIP r20, созданный поверх исходного архивного r19; GitHub `main` не менялся. Этот выпуск не является проверенным production-релизом.

## Что действительно сделано в r21 (в отличие от r20)

| Область | r20 | r21 |
|---|---|---|
| Тематически разных сайтов | 12 | **108**: 12 исходных неизменённых и **96 новых** статических сайтов |
| Генерируемые файлы сайтов в rich-режиме | 108 | **972**, по 9 на сайт, в том числе **540 HTML-страниц** (5 на сайт, считая 404) |
| Визуальные семейства нового каталога | Не существовали | 16 семейств CSS-композиции, самостоятельные названия, темы, тексты и SVG; сайты внутри семейства используют общий движок, это **не 96 разных движков** |
| Выбор темы | 12 исходных | `site-catalog` (108), локальный `site-preview`; галерея `preview/site-gallery/index.html` |
| Развёртывание | Единственное первое staging-развёртывание и откат к исходной странице | `site-deploy`, **`site-change`**, `site-rollback` с проверяемым журналом и возвращением предыдущей рабочей темы |
| Selfsteal | Локальная диагностика установки | Новый **read-only** `--diagnose-selfsteal` с проверкой Unix socket, Nginx и прав `0750 root:www-data` без вывода секретов |
| Сеть | Читающая диагностика BBR/fq, ошибок и conntrack | Дополнительные читающие TCP buffers, listen drops, TCP timeouts, sockstat, без `sysctl -w` |
| Тесты | Предыдущие | Новые тесты 108 тем, локального Nginx, переключения/отката и диагностики; предыдущие regression-тесты сохранены |

**Исходные 12**: каталог `cover-variants/` (без изменений). **Новые 96**: каталог `site-catalog/` (девять физических файлов на каждую тему). Темы покрывают техническую документацию, мониторинг, редакционные журналы, архитектуру, библиотеки, мастерские, музыку, культуру, фотографию, образование, природу, еду, путешествия и др.; несколько языков. У каждой темы свой контент, favicon, заголовок, цветовая схема и одна из 16 структур оформления. Изображения — локальный SVG, без внешних зависимостей, JavaScript, форм или CDN. Это оригинальные вновь сгенерированные материалы; **готовые HTML/CSS/PNG шаблоны из сторонних GitHub-репозиториев не переносились**. Никакого утверждения о том, что сайты прошли полноценную визуальную экспертизу на реальных телефонах, нет.

## Просмотр и проверка **без** доступа root и без изменения сервера

Из **полностью распакованного ZIP** открыть `preview/site-gallery/index.html` локально. Карточки ведут к физическим HTML-файлам соответствующей темы. В новых темах ссылки и CSS относительные, поэтому работают также с `file://`; сайт с доменом `preview.example.test` — автономный предпросмотр, а не работающий публичный домен.

```bash
python3 scripts/build_site_gallery.py --check
python3 scripts/staging_web_deploy.py site-catalog
python3 scripts/site_audit.py --rich
python3 scripts/staging_web_deploy.py site-preview \
  --theme 13-cloud-ledger \
  --domain preview.example.test \
  --output /tmp/node-cover-preview-unique-new-dir
```

Каталог вывода предварительного просмотра должен ещё не существовать. Ни одна из команд выше не изменяет хост или сеть.

## Установка и переключение **ТОЛЬКО на отдельной staging VPS**

Перед запуском нужен **проверенный snapshot всей VPS**, доступ к аварийной консоли, успешная штатная установка `INSTALL_COMPLETE` на изолированной staging-нoде, собственный FQDN с валидным HTTPS и свободный от чужих изменений контролируемый сайт. Развёртывание само по себе НЕ устанавливает Remnawave Panel/Node. Не выполняйте эти команды на production без отдельной согласованной процедуры.

```bash
# После установки Node на STAGING:
sudo python3 scripts/staging_web_deploy.py site-deploy \
  --theme 13-cloud-ledger --expected-domain node.example.com \
  --rich-pages --confirm-staging

# Переход на другую тему — со снимком и проверкой предыдущей:
sudo python3 scripts/staging_web_deploy.py site-change \
  --theme 79-glass-workshop --expected-domain node.example.com --confirm-staging

sudo python3 scripts/staging_web_deploy.py status

# Вернуться на предыдущую проверенную тему:
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
```

`node.example.com` — заменить реальным FQDN, которому соответствует сертификат и штатный `config.json`. Деплой намеренно **отказывает**, если конфигурация Nginx или сайт не совпадают с проверенной схемой (strict allowlist, отказ для неизвестных путей). `site-change` требует активной версии rich site, валидных хешей текущих файлов и журнала; при ошибке новой темы откатывается. Цепочка откатов допускает возвращение к предыдущей теме после нескольких смен. При ошибке/неполноте восстановления — STOP и восстановление VPS из снапшота, **не удаляйте receipt-файлы вручную**. Скрипт не меняет REALITY-ключи, UUID, Profile/Host панели, SSL-сертификат, порт 443, Docker, SSH или ядро.

## Только читающая диагностика

```bash
bash install.sh --diagnose-network
bash install.sh --diagnose-selfsteal
```

`--diagnose-network` читает фактический TCP congestion control, qdisc, MTU probing, интерфейсные ошибки, softnet, conntrack и агрегированные TCP/socket counters. Значения `ListenOverflows`, `ListenDrops`, `TCPTimeouts` — **накопительные счетчики, а НЕ скорость потерь и НЕ доказательство проблемы конкретного VPN-клиента**. Ничего не меняет в `/etc/sysctl.d`, ядре, qdisc, firewall, Docker или маршрутах.

`--diagnose-selfsteal` читает безопасный whitelist путей и проверяет конфигурацию, права каталога `/run/vkarmani-selfsteal`, типы ожидаемых Unix-сокетов и наличие сайта. Не проверяет фактическую TLS-сессию/доступ по интернету, для этого используйте существующий отдельный selfsteal health-check на staging. Скрипты не выводят содержимое токенов, private keys, client IP и сертификатов.

## Проверки для данного ZIP

```bash
python3 scripts/verify_release.py --root .
sha256sum --check SHA256SUMS
bash -n install.sh
python3 scripts/site_audit.py --rich
python3 scripts/build_site_gallery.py --check
python3 -m unittest discover -s tests -p 'test_*.py'
```

На Linux с Nginx новые тесты используют **только изолированный loopback HTTP server**, не трогая `/etc/nginx`, сервисы или чужие порты. Они проверяют ответ статических страниц и отказ в неразрешённых URL. Нельзя делать вывод о тестировании сертификата внешнего FQDN или REALITY-клиента из этих тестов.

## Что из большого исходного плана **НЕ сделано**

- **НЕ** внедрены новые REALITY/XHTTP/TLS/H2 маршруты, FinalMask, Hysteria2, AmneziaWG; не менялись существующие транспортные профили и безопасность каскада.
- **НЕ** изменялся алгоритм BBR, системное ядро, IP, IPv6, `sysctl`, MSS/MTU или сетевые очереди. Нет автоматических сетевых «ускорителей».
- **НЕ** проведены тесты Remnawave Panel → RemnaNode → real VPN client, блокировок/DPI, многосуточной нагрузки и работающих production-серверов.
- **НЕ** выполнена полноценная визуальная проверка на реальном десктопном и мобильном браузере; offline HTML/Nginx tests не являются её заменой.
- **НЕ** импортированы чужие HTML/CSS/брендовые активы: ориентировались на архитектурные подходы из присланных ссылок, но исходные внешние шаблоны не были доступны для надежного упаковочного переноса и лицензионного аудита.

## Backup / rollback и критерии staging

**Backup:** snapshot VPS с проверяемым восстановлением + отдельно сохраняйте данные Remnawave Panel/секреты Node вне ZIP. `site-rollback` сохраняет управляемую прежнюю статическую тему, но не восстанавливает OS, Panel, Firewall или потерянные сертификаты. Не использовать для миграции поверх частично неудачной установки.

**Тестовый gate:** nginx -t; проверка внешнего TLS/HTTP2; ответ на `/`, страницы, `robots.txt`, CSS и SVG; недоступность `/.env`, hidden/admin и произвольных путей; REALITY-клиент; обычный и cascade через Panel с отказом Exit; перезагрузка; восстановление из snapshot. Пока эти проверки не проведены на реальном оборудовании, статус `INCOMPLETE_STAGING_ONLY` неизменен.

## Краткий перечень изменений

Добавлены `site-catalog/` (864 статических файла), `scripts/site_catalog.py`, `scripts/build_site_gallery.py`, `preview/site-gallery/index.html`, `integrations/selfsteal_health.py`, новые тесты `tests/test_r21_*.py` и эта документация. Изменены `scripts/cover_rich.py`, `scripts/site_audit.py`, `scripts/staging_web_deploy.py`, `integrations/network_health.py`, `install.sh`, README/CHANGELOG, builder/verifier и манифест SHA256. Исторические оригинальные `cover-variants/` сохранены без изменений.
