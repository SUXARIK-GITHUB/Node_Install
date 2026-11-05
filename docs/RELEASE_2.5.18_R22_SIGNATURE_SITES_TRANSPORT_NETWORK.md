# Node_Install 2.5.18 r22 — исправление качества каталога и офлайн-проверки

**Статус: `INCOMPLETE_STAGING_ONLY`**. 2026-11-05. Исходники: пользовательский r19 ZIP → r20 → r21 → r22. GitHub `main` не изменялся. Никаких изменений на production или staging VPS не применялось.

## Фактическая комплектация сайтов

- 12 исходных тематик из `cover-variants/` — все 48 исходных файлов не изменены.
- 96 тематик из `site-catalog/13-...` — разработаны общим движком r21, 16 визуальных компоновок и исходные тексты. Это **не 96 вручную нарисованных сайтов**.
- 12 новых тематик `site-catalog/109-...` … `120-...` — отдельные DOM-композиции и оригинальные специализированные заметки, CSS и SVG; новый исходник `scripts/signature_sites.py`.
- **120 вариантов** × 9 файлов = **1080 файлов** для rich-развёртывания: главная, три внутренние страницы, 404, CSS, favicon, robots, sitemap. **600 HTML-страниц**. Новые 12 тем имеют разные информационные архитектуры; не заменяют полноценную продакшен-публикацию реальной компании.
- Все сайты локальные и статические, без JS, внешних шрифтов/изображений/CDN, авторизации и сбора данных. Готовые шаблоны из сторонних GitHub-репозиториев не импортировались. Использованы только архитектурные идеи; оригинальные темы созданы специально для этого ZIP.

## Каталог и безопасность: только чтение

```bash
python3 scripts/build_site_gallery.py --check
python3 scripts/site_audit.py --rich
python3 scripts/staging_web_deploy.py site-catalog
python3 scripts/staging_web_deploy.py site-preview --theme 110-blue-harbor --domain preview.example.test --output /tmp/vk-signature-preview-NEW-DIR
```

Для локального просмотра откройте `preview/site-gallery/index.html` после полной распаковки. Веб-браузерные снимки в этой среде не получены: тесты DOM/CSS не доказывают, что дизайн одинаково хорошо выглядит на всех телефонах.

## Реальная установка сайта: ТОЛЬКО на отдельной staging VPS

Нужны проверенный snapshot VPS, аварийная консоль, успешный `INSTALL_COMPLETE`, действующий собственный домен и HTTPS. Нельзя запускать поверх незавершённой установки или на production без отдельного согласованного процесса.

```bash
sudo python3 scripts/staging_web_deploy.py site-deploy --theme 110-blue-harbor --expected-domain node.example.com --rich-pages --confirm-staging
sudo python3 scripts/staging_web_deploy.py site-change --theme 119-type-lab --expected-domain node.example.com --confirm-staging
sudo python3 scripts/staging_web_deploy.py status
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
```

`site-change` проверяет Nginx/HTTPS и возвращает предыдущую рабочую тему при сбое. `site-rollback` — только для управляемого сайта; он не заменяет восстановление snapshot VPS.

## Новые инструменты без изменений системных настроек

```bash
python3 integrations/transport_profile_audit.py examples/inbound-raw-full.example.json --expected-domain node.example.com
python3 integrations/transport_profile_audit.py examples/inbound-xhttp-full.example.json --expected-domain node.example.com
bash install.sh --diagnose-network > before.json
# Получите второй снимок позднее; укажите фактический интервал между ними:
bash install.sh --diagnose-network > after.json
python3 scripts/network_compare.py before.json after.json --seconds 60
```

`transport_profile_audit.py` **не** является Xray-core `-test`, проверкой валидности ключей, proof of DPI resistance, сертификата, клиента или связи с Remnawave Panel. Вывод содержит только имена режимов и коды ошибок. Проверка XHTTP/TLS отмечает необходимость live-сценария, не активирует его.

`network_compare.py` читает два агрегированных JSON-снимка, показывает дельты и отмечает новые ошибки; при смене интерфейса отказывается от ложного сопоставления. Не собирает адреса, не меняет MTU/MSS, BBR, TCP buffers, firewall и Docker. **Ни одно значение sysctl не было повышено из сторонних проектов.**

## Что не реализовано из обсуждавшегося большого плана

Новые VPN-протоколы (Hysteria2/AmneziaWG), альтернативный TLS+H2 Nginx transport в эксплуатации, Xray FinalMask, изменение ядра/BBR2/BBR3, оптимизация производительности под реальной нагрузкой, тесты доступа из цензурируемых сетей, профессионально отрисованные копии чужих 30–38 сайтов. Имеющиеся RAW/REALITY/Vision, XHTTP/REALITY, режимы SNI и каскад Entry → Exit намеренно не модифицированы без полноценной staging-проверки и контрольной точки отката.

## Проверки, backup и статус

```bash
python3 scripts/verify_release.py --root .
sha256sum --check SHA256SUMS
python3 -m unittest discover -s tests -p 'test_*.py'
bash -n install.sh
python3 -m compileall -q integrations scripts tests
python3 scripts/build_site_gallery.py --check
python3 scripts/site_audit.py --rich
```

Проверки в ZIP не означают live-тестирование реального RemnaNode на VPS, контроль DPI и работу с боевыми клиентами. Для production требуется снапшот → восстановление снапшота на тестовом окружении → доступность SSH/Panel → живые REALITY/XHTTP соединения → проверка selfsteal, Nginx и rollback. Если любой шаг провален, откатить через снимок; не удалять вручную `INSTALL_FAILED` и другие checkpoints.

## Изменённые и добавленные исходники

Добавлены `scripts/signature_sites.py`, `integrations/transport_profile_audit.py`, `scripts/network_compare.py`, `tests/test_r22_signature_sites.py`, `tests/test_r22_transport_profile_audit.py`, `tests/test_r22_network_compare.py`, 108 файлов в `site-catalog/109–120/` и этот документ. Обновлены `scripts/site_catalog.py`, `scripts/build_site_gallery.py`, галерея, документация README/CHANGELOG, релизные проверки, упаковщик и тесты r21 на расширяемое количество тем. Старые 397 файлов r19 сохраняются.
