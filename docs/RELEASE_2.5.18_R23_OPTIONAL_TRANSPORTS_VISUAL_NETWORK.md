# Node_Install 2.5.18 r23 — расширение проверок и экспериментальных транспортов

**Дата:** 2026-11-05. **Статус:** `INCOMPLETE_STAGING_ONLY`. **Основной установщик, конфигурации существующих серверов и GitHub не изменены удалённо.** Это полный исходный ZIP, а не патч. Сохраняются все файлы и прежние режимы r22/r19.

> По заданию владельца проекта **не включаем в объём задачи полноценную проверку Remnawave Panel и клиентов на VPS**. Поэтому все новые профили представляют собой локально проверенные конфигурационные заготовки/инструменты с явными staging-гейтами, а не доказательство успешного VPN-туннелирования или устойчивости к DPI. Режимы Hysteria2 и AmneziaWG не становятся автоматически доступными после обычной установки.

## 1. Сайты-прикрытия: визуальная проверка 120 тем

Сохранены 120 тематик (12 исторических, 96 общего генератора, 12 индивидуальных композиций). В новой проверке Chromium каждая тема открыта с локально встроенным CSS при разрешениях **1280×800** и **390×844**. Всего **240 проверок**: наличие главной структуры, навигации, заголовка, видимого содержимого и горизонтального переполнения. Итог: **0 технических ошибок компоновки**; это не свидетельствует об уникальности всех текстов и не заменяет художественную оценку/реальное HTTPS.

Результаты в архиве:

- `preview/site-gallery/index.html` — исходная интерактивная локальная галерея ссылок на все темы;
- `preview/site-gallery/visual-review-desktop.jpg` — все 120 десктопных снимков на одном листе;
- `preview/site-gallery/visual-review-mobile.jpg` — мобильные снимки;
- `preview/site-gallery/visual-review-r23.json` — отчёт по каждому сайту и разрешению;
- `scripts/site_visual_review.py` — повторяемая проверка с Playwright/Chromium/Pillow **только для окружений разработки**, не обязательна на VPS.

Для повторения на компьютере с Playwright/Chromium/Pillow:

```bash
python3 scripts/site_visual_review.py --start 0 --count 12 --output /tmp/vk-visual-batch-NEW
```

Папка вывода должна отсутствовать. Проверка не открывает публичные URL и не меняет встроенные страницы: CSP убирается только из изолированной версии HTML в памяти для локального просмотра без `file://`.

## 2. Selfsteal/Nginx: реальная проверка локального HTTPS и откат

Добавлен `integrations/selfsteal_runtime_probe.py` и CLI `--selfsteal-runtime-probe`. Он подключается **только к указанному Unix-сокету**, при необходимости отправляет PROXY protocol v1, выполняет корректный TLS/SNI-handshake с проверкой сертификата и читает HTTP-статус. Данные сертификатов/HTML/адресов посетителей не сохраняются и не выводятся.

```bash
# Для конфигурации с proxy_protocol на сервере (укажите свой домен/сокет):
bash install.sh --selfsteal-runtime-probe --domain node.example.com \
  --socket /run/vkarmani-selfsteal/cover.sock --proxy-v1 --strict
```

**Не применяйте `--proxy-v1` там, где на listener не настроен PROXY protocol.** Старый `/usr/local/sbin/vkarmani-selfsteal-check` сохраняется. В изолированном Nginx успешно протестировано реальное TLS-соединение по Unix-сокету с PROXY v1 и отрицательная проверка чужого SNI. Успех этого теста НЕ подтверждает авторизацию REALITY.

## 3. XHTTP + TLS + HTTP/2 (отдельный optional staging-режим)

Используется уже имеющийся сертификат собственного домена и локальный h2c backend Xray `127.0.0.1:33643`. На принимающем HTTPS-сервере Nginx добавляется строго один разрешённый `location ^~ /api/<путь>/` с `grpc_pass`; остальные адреса, публичный 443, Docker, UFW и каскад не переписываются.

**Подготовка вне репозитория (приватная папка 0700 и файлы 0600):**

```bash
bash install.sh --optional-transport xhttp-tls --domain node.example.com \
  --backend-port 33643 --output /root/vk-xhttp-review
python3 integrations/transport_profile_audit.py /root/vk-xhttp-review/profile-xhttp-tls.json \
  --expected-domain node.example.com
```

Сначала отдельно включите XHTTP inbound в проверенном тестовом Xray/RemnaNode, выполните **`xray -test` на фактическом бинарнике** и убедитесь, что backend 127.0.0.1:33643 уже слушает. Это НЕ делает наш скрипт, поскольку он не имеет доступа к runtime Xray/Panel, и не должен заменять чужой живой конфиг. Затем при проверенном снимке staging VPS и рабочем `INSTALL_COMPLETE`:

```bash
sudo python3 scripts/staging_web_deploy.py xhttp-tls-deploy \
  --expected-domain node.example.com --path /api/REPLACE_WITH_GENERATED_PATH \
  --backend-port 33643 --confirm-staging
sudo python3 scripts/staging_web_deploy.py status
# Сначала откатить управляемый сайт, если он был включён ПОСЛЕ XHTTP:
sudo python3 scripts/staging_web_deploy.py site-rollback --confirm-staging
sudo python3 scripts/staging_web_deploy.py xhttp-tls-rollback --confirm-staging
```

**Укажите тот же `path`, который был сгенерирован в `profile-xhttp-tls.json`.** CLI отклоняет небезопасные пути, чужие конфигурации и уже активную транзакцию сайта. При `nginx -t`/reload/HTTPS отказе исходная Nginx-конфигурация восстанавливается из hash-verified backup. В тестах проверена и последовательность `xhttp → сайт → site rollback → xhttp rollback`. Это не end-to-end проверка передачи XHTTP-трафика.

**Внимание:** Nginx может обрабатывать HTTPS у selfsteal, а VLESS клиентский запрос должен быть направлен по корректному TLS-профилю. Нельзя бездумно отправить XHTTP на старый RAW REALITY inbound или сделать h2c порт публичным.

## 4. Hysteria2 / QUIC — приватный профиль, без автоматической установки

`bash install.sh --optional-transport hysteria2 --domain node.example.com --udp-port 443 --output /root/vk-hysteria-review` генерирует конфигурацию Xray Hysteria версии 2, случайный длинный пароль, QUIC/TLS и клиентский справочник в приватной директории. Профиль содержит ссылку на обычный Let's Encrypt сертификат и **не включает права контейнера читать приватный ключ**. При этом нет Docker Compose/systemd/UFW изменений, UDP-порт 443 может быть занят, а поддержка выбранной версией Xray не проверена.

Фактическое развёртывание требует отдельной установки/активации совместимого ядра Xray, безопасного доступа к TLS-ключу, проверки UDP-порта и firewall. Стандартная реализация Hysteria2 не является VLESS/REALITY и не управляется автоматически существующей Remnawave Panel. **Нельзя переносить напрямую-выходящий профиль на cascade Entry.**

## 5. AmneziaWG2 — отдельный приватный bundle

`bash install.sh --optional-transport awg2 --domain node.example.com --udp-port 51820 --output /root/vk-awg-review` создаёт две пары X25519, уникальный pre-shared key, согласованные серверный и клиентский конфиги с четырьмя **непересекающимися случайными диапазонами H1–H4** (AWG 2.x), заданной подсетью, базовыми `S1–S4` и `Jc`.

**Это ещё не развернутый AWG-сервер.** Нужны совместимые amneziawg-go/awg-tools или проверенный kernel module, изолированная сеть/подсеть без пересечений, доступ к TUN, явная маршрутизация/NAT, выбранный DNS, UFW и проверка MTU. Автоматической установки ядра, DKMS, системного сервиса, открытия UDP или `ip_forward` нет — это гарантирует, что обычная установка Node_Install не ломается при отсутствии AWG. Нельзя разворачивать на cascade Entry с DIRECT.

## 6. Реальные метрики: ограниченные и добровольные

1. `bash install.sh --quality-probe --domain node.example.com --ip YOUR_PUBLIC_IPV4 --samples 8` — проверяемый TLS + HTTPS GET `/`, TCP/TLS/TTFB и ответы. До 20 запросов, последовательные, без API ключей и redirect, сертификат проверяется. **Это метрики собственного HTTPS-сайта, не скорость VPN.**
2. `bash install.sh --throughput-probe --server YOUR_IPERF3_SERVER_IPV4 --seconds 5 --samples 2` — реальный **TCP iperf3 client** до принадлежащего вам тестового сервера. Максимум 3 запуска по 15 секунд, 1 поток. В выводе только Mbps и retransmits, без IP/сырых ответов. `iperf3` должен быть уже установлен, сам сервис не устанавливается. Внутренний/loopback IPv4 требует явного `--allow-private`. **Трафик не проходит через VPN сам по себе** и не характеризует DPI.
3. `bash install.sh --diagnose-network > /root/vk-before.json` и повторный снимок `vk-after.json`; `python3 scripts/network_compare.py ... --seconds <INTERVAL>` — дельты ошибок и очередей. Снимки и их пути надо хранить приватно.

В этой среде запущены **реальные тестовые локальные TLS соединения и Nginx**. Доступного удалённого iperf3-узла и VPN сервера для реальных цифр Mbps нет. Скорость внешнего VPN, поведение при блокировках и реальные сетевые потери НЕ измерялись; выдумывать их нельзя.

## 7. Measured Network Tuning (staging-only)

Новый `integrations/network_tuning.py` предлагает увеличение только `net.core.somaxconn` и `net.ipv4.tcp_max_syn_backlog` до 8192 — и только если **между двумя сопоставимыми снимками выросли ListenDrops/ListenOverflows**, а текущие значения ниже порога. Если данных недостаточно, план `NO_CHANGE`.

```bash
bash install.sh --network-tuning plan /root/vk-before.json /root/vk-after.json --seconds 60
# ТОЛЬКО после снимка VPS, независимого подтверждения причин переполнения и dev/staging:
sudo bash install.sh --network-tuning apply /root/vk-before.json /root/vk-after.json \
  --seconds 60 --confirm-staging
sudo bash install.sh --network-tuning rollback --confirm-staging
```

Применение защищено lock, ownership/checkpoint, обнаружением существующего чужого файла, актуальным readback, атомарной записью `/etc/sysctl.d/98-vkarmani-measured.conf`, чеком после `sysctl -p`, receipt/backup и откатом при отказе. Если receipt требует ручного восстановления, новый apply запрещён. **BBR2/BBR3, XanMod, conntrack миллион, MTU/MSS, IPv6, qdisc, драйверы NIC и маршруты НЕ меняются автоматически.** Без измерений безопаснее оставить текущий BBR/fq.

## 8. Тесты и границы приёмки

- Тесты: обычный `unittest`-набор проекта + новые offline-прогоны генераторов, правил XHTTP, сетевых транзакций и ограниченных измерений.
- Изолированный настоящий Nginx: `nginx -t` на сгенерированном H2 location; отдельный TLS/Unix/PROXY v1 тест; отрицательная проверка TLS имени.
- Визуально: 120 десктопных и 120 мобильных Chromium скриншотов, 0 технических нарушений компоновки; снимки приложены.
- В исходном ZIP нет приватных файлов `--output /root/...`, клиентских UUID, password или приватных X25519 ключей.
- Нет автоматических изменений production/Panel/клиентов или GitHub. Стабильные RAW/REALITY/Vision, XHTTP/REALITY, SNI, каскад, Docker, SSH/UFW/ACME используются без изменения маршрутов по умолчанию.

**Остаются неподтверждёнными:** способность реального Xray/RemnaNode принимать сгенерированный экспериментальный Hysteria2/XHTTP/TLS профиль; работоспособность AWG2 в выбранной реализации; реальная пропускная способность и отказоустойчивость на вашем внешнем сетевом пути; эффективность маскировки против конкретного DPI. Это не подтверждается offline CI и не должно называться production-ready. Проверка Panel и клиентов на VPS исключена по заданию.

Основные источники для ручной сверки параметров:
- [Xray Hysteria inbound](https://xtls.github.io/en/config/inbounds/hysteria.html)
- [Xray Hysteria transport](https://xtls.github.io/en/config/transports/hysteria.html)
- [XHTTP discussion and Nginx grpc_pass](https://github.com/XTLS/Xray-core/discussions/4113)
- [AmneziaWG 2.0/3.1 protocol details](https://docs.amnezia.org/documentation/amnezia-wg/)
