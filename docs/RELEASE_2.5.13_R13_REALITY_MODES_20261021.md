# VKARMANI Node Install 2.5.13 r13 · Ordinary REALITY modes · 21.10.2026

**Статус: INCOMPLETE_STAGING_ONLY. Только новая disposable VPS, snapshot + аварийная консоль.**

## Объём и совместимость

Предыдущая сборка: r12 от 18.10.2026, опубликованная в GitHub `main`, commit `197cd273f7954a84e8445ea1d333224304777eac`. Эта r13 **локальная модификация полного архива** и отсутствует в GitHub. Сохранены скрипты cascade, RKN, Docker, GRUB, SSH, firewall, 12 статических сайтов, systemd и все исторические миграции.

После выбора `1 — Ordinary` интерактивное меню предлагает пять вариантов:

| Вариант | `reality_mode` | `target` | `serverNames` | `xver` | HTTPS собственного сайта на публичном 443 |
|---|---|---|---|---:|---|
| Обычный | `local` | `/dev/shm/nginx.sock` | свой FQDN | 1 | да, через локальный Nginx Unix socket |
| MAX | `max.ru` | `max.ru:443` | `max.ru` | 0 | нет |
| Yandex | `ya.ru` | `ya.ru:443` | `ya.ru` | 0 | нет |
| RuTube | `rutube.ru` | `rutube.ru:443` | `rutube.ru` | 0 | нет |
| Mail | `mail.ru` | `mail.ru:443` | `mail.ru` | 0 | нет |

Не смешивать пары `target` / SNI / `xver`, не копировать приватные ключи из примеров. Для внешнего режима установщик до записи `/etc/vkarmani-node` проверяет IPv4 DNS, глобальность адресов, TLS 1.3, доверенную CA и совпадение имени сертификата. Если проверка не прошла, установка прекращается до записи состояния. Доступность цели после установки зависит от DNS, маршрута и провайдера и может измениться.

### JSON-инбаунды Ordinary

- `RAW+REALITY+Vision`: один `vless`, `network=raw`, `security=reality`, `flow=xtls-rprx-vision`, `clients=[]`, `sniffing` с `routeOnly`, актуальный ключ/ShortID и tag, DNS IPv4 с `serveStale`/`enableParallelQuery`, запрет private/IPv6 и `bittorrent`. Приватный экспорт: `/root/vkarmani-raw-profile.json` (`0600`).
- `XHTTP+REALITY`: альтернативный, **не второй** listener `443`; `network=xhttp`, пустой `flow`, `mode=auto`, `host` соответствует SNI, `path` HMAC от текущего приватного ключа. Те же REALITY ключи/tag и защитные правила. Экспорт `/root/vkarmani-xhttp-profile.json` создаётся только после проверки bundled core.
- `Entry/Exit`: исходные каскадные генераторы без изменений. Entry не получает прямой выход к Интернету. Нельзя одновременно назначить RAW и XHTTP как два слушателя на `0.0.0.0:443`.

Имеющиеся правила безопасности (`finalRules` повторно блокирует private/IPv6 после DNS-резолва, deny для `bittorrent`, защита управляющих адресов) сохранены. `sockopt.domainStrategy=ForceIPv4` добавлен только к Ordinary DIRECT; IPv6 по политике не используется.

### Nginx и обратное проксирование

- Локальный Selfsteal: сохраняется UNIX socket и PROXY v1, `xver=1`; HTTPS собственного сайта доступен через REALITY fallback.
- Внешний REALITY target: `xver=0` (не передавать PROXY header чужому серверу); на публичном HTTP/80 отключён редирект на `https://свой-домен`, который в таком режиме не может быть обслужен через HTTPS. Для HTTP/80 остаётся `404` + отдельный `/.well-known/acme-challenge/` для Certbot.
- Локальный Nginx Selfsteal socket продолжает существовать, его локальные тесты и обновление сертификата сохранены. Не добавляется второй публичный слушатель 443 и не меняется текущая модель Docker.

### Актуальная информация о ТСПУ / DPI на 21.10.2026

Повсеместная масштабная блокировка именно 21.10.2026 **не подтверждена независимыми опубликованными источниками в момент подготовки**. Достоверные технические материалы указывают на активное выявление VPN-трафика по IP/ASN, TLS ClientHello, JA3/JA4, поведенческим паттернам (размеры/периодичность пакетов, долговременные сессии, сбросы соединений). Эти эвристики зависят от оператора и региона; универсальной «невидимости» нет.

Источники для дополнительного изучения:
- Xray REALITY: https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/reality.md
- XHTTP: https://github.com/XTLS/Xray-core/discussions/4113
- Пример внешнего REALITY/XHTTP SNI: https://github.com/XTLS/Xray-core/discussions/5174
- Исследование DPI: https://habr.com/ru/articles/1047442/ и https://habr.com/ru/articles/1009542/

Практический подход: вести измерения из нескольких сетей и регионов (TCP reachability, TLS handshake, реальный Xray клиент, DNS/IPv4, пакетные потери, скорость, длительность), фиксировать точные версии ядра и клиента, сравнивать RAW vs XHTTP только в рамках совместимого набора и не менять JA3/JA4 «вслепую». Случайный домен и SNI крупного провайдера не обеспечивают работу по IP-белому списку. Избегать новых зависимостей, ложных fingerprint claims и экспериментальных манипуляций пакетами на production без воспроизводимого staging proof.

### Обязательные staging-gates

1. Снимок VPS и проверенный внешний доступ через KVM/консоль хостера. Запускать на **чистой**, не действующей VPN-нode; под root только после проверки SHA256 ZIP / SHA256SUMS / release verifier.
2. Все пять вариантов на отдельных VPS или после полного restore clean snapshot. Ввод invalid-опции, TLS fail/timeout, missing DNS, restart from `inputs.pending`, кросс-подмена ключа/target/xver.
3. `nginx -t`, `systemctl status nginx`, Certbot HTTP-01/reload, `curl` TCP/80 для своего domain, проверка server HTTP/443 fallback по SNI именно выбранной цели, CA и TLS1.3; соединение от внешней сети без proxy.
4. `remnanode` image digest и `xray -test -config` для **обоих** профилей с фактическим bundled core; в панели активировать только один профиль 443, проверить явные error/unsupported fields, UFW/SSH safety/Node API IPv4 ACL.
5. `vkarmani-node-check --require-xray` после перезагрузки, запись статуса панели, клиент VLESS+REALITY, правильный SNI, RAW Vision и XHTTP без Vision; TCP, UDP/QUIC, DNS, idle/long-lived sessions, IPv4 egress и real peer fallback.
6. Каскад на отдельных VPS по прежней процедуре, дополнительно negative test Exit-off = без DIRECT с Entry; данные и роли не мигрировать поверх живой установки.
7. Проверить пользовательские сценарии под слабым интернетом / 1 ГБ RAM, и не объявлять релиз production-ready до gate sign-off.

### Backup, rollback и развёртывание

**Перед первым запуском**: снимок целого диска VPS у провайдера и доказанная процедура возврата через KVM. Из-за изменений SSH/UFW/GRUB/системных пакетов только rollback отдельных конфигов не является полной гарантией восстановления. При сбое на staging — отказ от автоматического повторного запуска; диагностика на консоли и **восстановление целого snapshot** вместо переустановки поверх частично изменённого состояния. На production работающих серверах **ничего не менять**. Для потенциального обновления впоследствии нужна отдельная миграционная спецификация.

**Источники секретов:** `SECRET_KEY`, ключи Reality, private JSON, role-bundle и `*.pending` хранить с `root:0600`, не отправлять в GitHub/чат и не публиковать в логи. В публичные отчёты и тикеты прикладывать только отредактированные/обезличенные параметры. Встроенная формальная валидация не равнозначна тесту настоящего клиента.
