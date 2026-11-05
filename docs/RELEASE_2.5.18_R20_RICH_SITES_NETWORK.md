# Node_Install 2.5.18 r20 — Rich site / Network diagnostics staging candidate

**Сборка:** `20261105-r20-rich-sites-network-readonly`  
**Дата:** 2026-11-05  
**Статус:** `INCOMPLETE_STAGING_ONLY`, *не утверждён для production*.  
**Основа:** полный архив Node_Install 2.5.18 r19; версия установщика и совместимость сохранены. Сборка r20 распространяется только полным проверяемым ZIP; GitHub main содержит исходный r19. Поле `source_commit` в унаследованном манифесте исходного ZIP указывает на прежний базовый коммит и не является утверждением о GitHub HEAD на дату r20; `source_tree_has_local_changes=true`. Результат не проверен на VPS/клиентских устройствах или против фильтрации.

## Изменения в коде

1. `scripts/cover_rich.py` — детерминированный расширенный HTML/CSS для всех **12** исходных авторских тем. На каждую тему девять файлов: `index.html`, `style.css`, `404.html`, `favicon.svg`, `journal.html`, `about.html`, `questions.html`, `robots.txt`, `sitemap.xml`. Контент локальный, без внешнего JS, CDN, форм, учётных записей и серверного backend; смартфонная вёрстка расширена стилями rich pages. Никакие готовые чужие сайты и их сторонние ресурсы не копировались.
2. `scripts/site_audit.py` — офлайн-проверка строгого состава файлов, CSP, viewport, title, HTML-навигации, локальных URL/якорей, CSS/SVG, валидного XML sitemap и соответствия домену, размера файлов; при проблеме — STOP. Поддерживает исходные 12 стандартных тем (`--rich` отключен).
3. `scripts/staging_web_deploy.py` — опциональный флаг `--rich-pages`: атомарно размещает только известные файлы и точные Nginx `location =` для `/journal.html`, `/about.html`, `/questions.html`, `/sitemap.xml`; существующее `/robots.txt` допускается к замене только при точном совпадении штатного содержимого. Нет wildcard-маршрута или нового публичного порта. Journal включает Nginx конфиг и каждый изменённый сайт-файл, защищает от частичной записи и изменения стороннего файла. Проверяется `nginx -t`, reloaded Nginx, локальный selfsteal и **каждый новый HTTPS URI** через `curl --http2 --tlsv1.3 --resolve` с проверкой публичного сертификата. При ошибке откат; при невосстановимом состоянии — STOP с ручным восстановлением из snapshot. Ключи REALITY, Panel и RemnaNode НЕ трогает.
4. `integrations/network_health.py`, встроенная равная копия в `install.sh` и `--diagnose-network`: read-only inspection **без** сетевых запросов. Показывает фактический congestion control, доступные CC, default vs active qdisc (включая mq), MTU, per-interface cumulative drops/errors, softnet, conntrack usage, параметры `tcp_mtu_probing`, `rp_filter`, `ip_forward`, backlog. Фильтрует MAC, IP шлюза, IP peers и секреты. Нет автоматической смены `sysctl`, `tc`, NIC offload, `ip_forward`, MTU, GRUB или UFW.
5. `integrations/cascade_recovery.py` + `docs/R6_CASCADE_OPERATIONS_AND_GATES.md`: исправлены описания ограниченного backup роли, явно предупреждают об отсутствии `remnanode.env`/SECRET_KEY. Функциональность recovery не изменена.
6. `tests/test_r20_network_health.py`, `tests/test_r20_rich_site.py`: диагностические сценарии, фактическая локальная Nginx проверка allowlist/404, проверки враждебных/отсутствующих ресурсов, rollback, несанкционированных файлов, сохранения старых профилей. Нет запуска реального установщика на хосте.

## Установка и выбор сайта — **только новая STAGING VPS**

**Перед любым изменением ОС:** snapshot *всего диска* и проверка восстановления у провайдера, аварийная консоль, DNS A уникального домена на IPv4 VPS, проверенный доступ к test Remnawave Panel. Не запускать на действующей production ноде. Основная штатная установка изменяет SSH, UFW, Docker, Nginx и GRUB, может автоматически перезагрузить VPS.

1. Проверить SHA-256 загруженного ZIP независимым каналом, затем `python3 scripts/verify_release.py --root .` и `sha256sum --check SHA256SUMS` в распакованном `Node_Install/`.
2. Локально, без модификации хоста:

```bash
bash install.sh --version
bash install.sh --diagnose-network
python3 -B scripts/site_audit.py
python3 -B scripts/site_audit.py --rich
python3 -B scripts/cover_rich.py --list
python3 -B scripts/cover_rich.py --name 01-atelier --domain node.example.test --output /tmp/vk-preview-01
```

3. После подтверждённого завершения **штатной** установки `bash ./install.sh` на чистой тестовой VPS, сертификата, TLS и подключения RemnaNode к test Panel — явно активировать opt-in страницы (поменять `node.example.com` на реальный FQDN ноды):

```bash
sudo python3 scripts/staging_web_deploy.py site-deploy \
  --theme 01-atelier \
  --expected-domain node.example.com \
  --rich-pages --confirm-staging
sudo python3 scripts/staging_web_deploy.py status
```

Этот режим требует установленного Nginx, знакомой selfsteal-конфигурации, оригинальных штатных файлов и успешной baseline selfsteal-проверки. При нестандартных конфигурациях, устаревших Nginx locations, неподтверждённом сертификате или конфликтующих файлах он остановится без изменения (если ошибка до записи) либо попытается откатить транзакцию. Вмешательство в production не поддерживается.

**Откат сайта на staging:**

```bash
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
sudo nginx -t
sudo systemctl is-active nginx
```

При обрыве питания во время записи сначала разобраться с `r7-web-deploy` receipt и состоянием файлов, не удалять journal вручную. Если штатный rollback не восстановил состояние — использовать **проверенный snapshot VPS** через консоль провайдера. Для неудавшейся **первой установки** восстановление только из чистого provider snapshot, не `--finish-install` без checkpoint.

## Что оставлено неизменным

- Обычный `bash ./install.sh`, CLI, версия `2.5.18` и default single-page selfsteal; старые 4-файловые темы и receipts.
- Host Nginx, Unix socket selfsteal, `ssl_preread` hybrid SNI, TLS1.3, ACME/Certbot, R19-права `0750 root:www-data` для `cover.sock`.
- Remnawave Node Docker/SECRET_KEY/Panel profiles, RAW+REALITY+Vision и XHTTP+REALITY, X25519 keys, отдельные Entry/Exit и fail-closed cascade.
- BBR/fq, IPv4-only, `tcp_mtu_probing=1`, UFW/iptables, RKN и корневые сетевые параметры. Нет лишних host-wide sysctl, новых драйверов и сторонних ядер.

## Staging acceptance matrix — необходимо выполнить вручную

| Проверка | Offline покрытие | Нужен настоящий VPS/Panel |
| --- | --- | --- |
| Все 12 тем, все новые ссылки/ресурсы | Да, аудит 108 файлов | Визуальный и мобильный просмотр |
| Nginx exact URL allowlist, .env не отдаётся | Да, отдельный локальный Nginx | Реальный `nginx -t`, 80/443, сертификат |
| Публикация и rollback сайта | Да, изолированный mock + fail tests | Проверка после Nginx reload/reboot |
| REALITY, XHTTP и selfsteal Socket | Старые offline regression | RemnaNode + test Panel + live клиент |
| BBR/fq/MTU/NIC/drop counters | Parser и CLI smoke | Измерение реальных интерфейсов |
| Entry→Exit fail-closed | Старые offline regression | Сценарий отключения Exit, DNS/UDP |
| Качество/доступность в разных сетях | НЕ проверено | Нужен отдельный маршрутный тест |
| DPI/блокировка или влияние маскировки | НЕ проверено | Нет гарантии; нужны реальные измерения |

## Источники идей, объём использования и ограничения

Изучены исходники и документация предоставленных внешних проектов: `SkunkBG/SelfstealCaddy` (контракт HTTP и аудит страниц), `proxyboy228/SNI-Templates` и `vtslynet-cyber/selfsteal-templates` (многостраничные темы), `Inch1337/Remnawave-Selfsteal-Nginx` (certbot/Nginx проверки), `DigneZzZ/remnawave-scripts` (транзакции), `alekvol/remnanode-bootstrap` (проверка реального qdisc), `Case211/remnanode-install` (сетевые сценарии), `Itman75/Nginx-L4-Stream-Router-Mask-for-3x-ui` (MSS и сетевые лимиты) и другие из пользовательского списка. **Сторонний код, CSS, HTML, картинки и конфиги не копировались**, поэтому не требуется переносить чужие лицензии на новые файлы. В перспективе лицензии и авторство каждого копируемого фрагмента должны быть оформлены отдельно.

**Не реализовано в r20** (нужно проектирование, CI и staging): альтернативный Hysteria2/QUIC, AmneziaWG, полноценный XHTTP/TLS reverse-proxy, Caddy, перенос 38+ чужих тем, BBR2/BBR3/XanMod, автоматическое изменение `somaxconn`, `nf_conntrack_max`, MSS/MTU, NIC offload, SSH-ключевая миграция, новая панель управления, обновление текущих production узлов. Включать это «для галочки» без проверенных VPS опасно.

## Команды проверки готового архива

```bash
python3 scripts/verify_release.py --root .
sha256sum --check SHA256SUMS
bash -n install.sh
python3 -B scripts/site_audit.py --rich
bash tests/run.sh
```

Статус `INCOMPLETE_STAGING_ONLY` сохраняется до сквозной проверки на доступной тестовой инфраструктуре.
