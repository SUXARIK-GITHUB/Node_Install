# Источники технических решений

Изучение и сверка: **2026-09-30**. Ниже — источники, реально использованные при переработке. Документация/ветки `main` могут измениться; это не обещание совместимости с их будущим состоянием. Выводы о собственном установщике основаны на предоставленном архиве и тестах, а не на чужом гайде.

## R1. Remnawave Node

- [Официальная установка Remnawave Node](https://docs.rw/install/remnawave-node/): Node Port — служебный API, не клиентский порт; назначение Config Profile через панель; ограничение API адресом панели; host network.
- [Squads](https://docs.rw/learn-en/squads/): доступ пользователей и inbound/профили относятся также к объектам панели, их нельзя считать созданными локальным shell-скриптом.
- [Rescue CLI](https://docs.rw/features/rescue-cli/): live config/debug доступны через upstream tooling; дамп может содержать чувствительные данные, поэтому не вызывается автоматически ради публичного отчёта.

Применено: раздельные 2222/443, явное `PANEL_CONNECTION=NOT_VERIFIED`, готовый import template вместо несуществующей авторизации административным API.

## R2. Актуальный исходный код RemnaNode

- [src/main.ts](https://github.com/remnawave/node/blob/main/src/main.ts): TLS 1.3, требование клиентского сертификата, server-side verification и условная SNI-проверка.
- [decode-servername.util.ts](https://github.com/remnawave/node/blob/main/src/common/utils/decode-node-payload/decode-servername.util.ts): канонизация публичных PEM, HKDF-SHA256 с info `rw-v1`, длина 22 байта и формат derived SNI.
- [Dockerfile](https://github.com/remnawave/node/blob/main/docker/Dockerfile), [init-env.sh](https://github.com/remnawave/node/blob/main/docker/rootfs/etc/s6-overlay/scripts/init-env.sh): актуальная структура образа/init, внутренние сокеты и окружение. Изучение исходников не заменяет запуск конкретного digest.
- [Issue #41: egressFilter and host egress](https://github.com/remnawave/node/issues/41): конкретный отчёт пользователя upstream о влиянии сетевой функции на host egress. Это сигнал о возможном blast radius, не доказательство дефекта всех версий или всех инсталляций.

Применено: не отправлять ключ/клиентский сертификат ради локального probe; проверить CA+leaf и derived SNI; отдельно подтвердить, что probe не аутентифицирует панель. NET_ADMIN — явный opt-in, без обещания работоспособности зависимых от неё plugins в default-конфигурации.

## R3. Docker

- [Установка Docker Engine на Ubuntu](https://docs.docker.com/engine/install/ubuntu/) — официальный APT repository, конфликтующие пакеты, compose plugin.
- [Установка Docker Engine на Debian](https://docs.docker.com/engine/install/debian/) — distro-specific repository и поддержка версий.
- [Host network driver](https://docs.docker.com/engine/network/drivers/host/) — общее сетевое пространство, отсутствие пользы от `ports:` в host mode.
- [Packet filtering / firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/) — отличие published bridge ports от host networking; нельзя переносить UFW-выводы между схемами механически.
- [Restart policies](https://docs.docker.com/engine/containers/start-containers-automatically/) — один механизм владения автозапуском, без конкурирующего systemd supervisor контейнера.

Применено: один host-network контейнер, digest pin, no published bridge ports, отдельный явный update, отсутствие prune и сохраняемый предыдущий image. Поддержка более новой ОС в документации Docker не означает её автоматическую поддержку всей комбинацией нашего installer/GRUB/SSH/Nginx.

## R4. OpenSSH

- [sshd_config manual](https://man.openbsd.org/sshd_config) — first obtained value, PasswordAuthentication, PermitRootLogin, AuthenticationMethods, Match и Port.
- [Ubuntu OpenSSH server](https://ubuntu.com/server/docs/how-to/security/openssh-server/) — файловая конфигурация, проверка и применение.

Применено: bounded block в начале main config, а не предположение, что поздний `99-*.conf` перекроет раннее значение; `sshd -t/-T`; сохранение портов и отказ от слепого переписывания чужого Match/Allow/Deny. Окончательное поведение определяется установленным sshd/PAM/account state, поэтому обязателен реальный парольный вход.

## R5. Ядро и MTU

- [Linux IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html) — tcp_mtu_probing, rp_filter, redirects, TCP и IPv4 параметры.
- [Linux kernel parameters](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html) — семантика загрузочных параметров, включая отключение IPv6.

Применено: MTU probing в режиме обнаружения black hole, без универсальной замены MTU; проверка фактического sysctl; BBR/fq с fallback; отсутствие произвольной гигантской настройки буферов. Локальный TLS probe не рассматривается как проверка MTU на внешнем маршруте.

## R6. Nginx и Xray REALITY

- [Nginx HTTP core module](https://nginx.org/en/docs/http/ngx_http_core_module.html) — Unix listen, PROXY protocol, listen-параметры.
- [Nginx HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html) — отдельная директива `http2 on` в новых версиях.
- [Nginx SSL module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html) — TLS/ALPN/certificate settings.
- [Xray REALITY](https://xtls.github.io/en/config/transports/reality.html) — параметры REALITY transport/target.
- [Xray examples: fallback Nginx](https://github.com/XTLS/Xray-examples/blob/main/All-in-One-fallbacks-Nginx/README.md) — дополнительный архитектурный пример, не готовый контракт всех актуальных версий.

Применено: Nginx вне Docker; отдельный socket с PROXY v1; version-aware HTTP/2; настоящий тест body/ALPN/TLS. Не заявляется гарантия неотличимости Selfsteal или обхода любой сетевой фильтрации.

## R7. ACME и Certbot

- [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/) — публичный HTTP-01 через TCP/80.
- [Certbot usage](https://eff-certbot.readthedocs.io/en/stable/using.html) — webroot, renewal, deploy hooks и dry-run.

Применено: DNS only/single A/без AAAA в IPv4-only проекте, открытый TCP/80, automatic renewal, Nginx validation до reload и Selfsteal после. Аккаунт без email не считается системой уведомлений; backup TLS/ACME закрыт.

## R8. Fail2ban

- [Официальный репозиторий](https://github.com/fail2ban/fail2ban) — jail/backend/action settings.
- [Официальное UFW action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/ufw.conf) — необходимость понимать семантику app/port и границы создаваемого firewall rule.

Применено: systemd journal backend и собственное обязательное SSH-port-scoped UFW action. Не добавлен CrowdSec или второй firewall manager, поскольку это расширило бы архитектуру без необходимости.

## R9. GitHub Actions

- [Официальные releases checkout](https://github.com/actions/checkout/releases).
- [Закреплённый commit v7.0.1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).

Применено: read-only permissions, `persist-credentials: false`, полная SHA action, отсутствие production credentials и deployment в тестовом workflow. Удалённый workflow при подготовке архива не запускался.

## Практика сообщества: рассмотрена, но не источник гарантии

- [Reddit networking: tcp_mtu_probing](https://www.reddit.com/r/networking/comments/52mzzd/netipv4tcp_mtu_probing_how_does_it_work/) — старое обсуждение PMTUD/black-hole probing; неоднозначные комментарии перепроверены по kernel documentation. Дата обсуждения не выдаётся за современный benchmark.
- [Reddit selfhosted: опыт настройки Fail2ban](https://www.reddit.com/r/selfhosted/comments/1hnd6cj/guide_to_fail2ban_it_works_but_its_quite/) — операционные сложности и альтернативы; мнения не служат основанием добавлять новые сервисы или обещать блокировку всех атак.
- [eGamesAPI/remnawave-reverse-proxy](https://github.com/eGamesAPI/remnawave-reverse-proxy) — пример community Selfsteal/Unix socket; сам проект оговаривает учебный характер. Широкие mounts/capabilities не перенесены без анализа.
- [DigneZzZ/remnawave-scripts](https://github.com/DigneZzZ/remnawave-scripts) — дополнительный практический ориентир по версиям/операциям; окончательные решения сверялись с upstream source.
- [Xray-core issue #5923](https://github.com/XTLS/Xray-core/issues/5923) — частный отчёт о различии RAW/XHTTP; не основание самовольно переводить этот проект на другой транспорт.

Не копировались целиком сторонние установщики и не принимались «магические ускоряющие sysctl» из комментариев. Совместимость и скорость конкретной VPS не выводятся из лайков/звёзд, числа комментариев или чужого результата speedtest. Итоговые ограничения и тестовый статус описаны в [AUDIT](AUDIT.md) и [TEST_REPORT](TEST_REPORT.md).


## R10. Повторный аудит 2.0.1: протоколы, процессы и notices

- [RFC 9113, HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113): начальное окно flow control, WINDOW_UPDATE, SETTINGS и DATA. Применено в локальном диагностическом клиенте; проверено реальным Nginx на страницах 96/128 KiB. HTTP/2 здесь относится к сайту Selfsteal, не к переводу VLESS на другой транспорт.
- [Python subprocess](https://docs.python.org/3/library/subprocess.html): timeout, Popen, start_new_session и процессный lifecycle. Дополнительно воспроизведено локально, что завершение одного родителя не гарантирует завершение потомка; новая process-group отмена проверена реальными shell-процессами.
- [Xray transport configuration](https://xtls.github.io/en/config/transport.html) и [REALITY](https://xtls.github.io/en/config/transports/reality.html): разделение протокола/транспорта/security и target. В проверке учтены network/method aliases без самовольного изменения установленного ядра или client flow. Обязательно валидировать выбранный бинарник на стенде.
- [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) и [TCP 16–20 checker](https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/): первичный пример специализированных проверок. Это **не подтверждение**, что он является указанным пользователем DPI//Checker, и не доказательство /32 или /24 для ваших адресов.

Сообщение о начале адресной фильтрации 20.09.2026 и сообщение об оферте до 01.10.2026 получены от пользователя. Поиск по формулировкам и датам не установил надёжный первоисточник именно этих сообщений. Имя хостера, URL оферты и однозначный URL DPI//Checker отсутствуют. Их текст полезен как операционный риск и требование собственного Selfsteal, но не основание приписывать одинаковую политику всем хостерам или подтверждать конкретный механизм блокировки.

Официальная web-страница systemd.unit была недоступна при повторном чтении; доступные локальные unit/утилита использованы для изолированного offline разбора merged Nginx unit. Live systemd restart semantics не проверялись и не заявляются результатом этого parser-теста.

## R11. UFW preflight 2.0.2

Первичный источник инцидента — предоставленный оператором вывод Ubuntu 24.04.4, пакет UFW 0.36.2-6, с точным содержимым `user.rules` / `user6.rules`, `inactive`, `(None)` в `show added` и пустыми nftables/iptables dumps. Эти два файла сохранены как fixtures, без hostname/IP/секретов. Это не скачанный пакет Ubuntu и не удалённая проверка этой VPS.

Официальная [ufw(8), раздел REPORTS](https://manpages.debian.org/bookworm/ufw/ufw.8.en.html#REPORTS) различает добавленные правила (`show added`) и состояние работающего firewall (`status`). Там же `reset` описан как отключение и возврат к defaults, поэтому он не используется для исправления распознавания. Решение не основано только на CLI-отчёте: сами сохранённые файлы тоже проверяются на точный допустимый формат.

Текущий raw `install.sh` GitHub не удалось скачать для независимого пересчёта hash: web fetch отказал, контейнерный запрос завершился DNS-ошибкой. Контрольные суммы получены из предоставленного архива и подготовленного локального выпуска; факт обновления GitHub не заявляется.
