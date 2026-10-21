# VKARMANI Node Install 2.5.16 r17 — GitHub CI и read-only multi-IPv4 диагностика

**Дата:** 2026-10-21. **Статус:** `INCOMPLETE_STAGING_ONLY`. Базовый код: опубликованная r16 с коммитом `580fb94dd57b680e2aa8f38b295d9563d2bca686`. Релиз не предназначен для обновления существующего production.

## Воспроизведённая причина двух CI failures

Ubuntu 22.04/24.04 запускали `tests/test_2513_r14_hybrid_selfsteal.py` от UID 1001, а выполняемый непосредственно helper из `VK_SOCKET_PREPARE` вызывал `main()` с жёсткой проверкой `os.geteuid()==0`. Оба режима (`local` и `max.ru`) выдавали `SELFSTEAL_SOCKET_PREPARE=FAIL ROOT_NO_ARGUMENTS_REQUIRED`. В Debian-контейнерах тест работал под root и не обнаруживал несовместимость.

**Решение:** тестовый дочерний процесс на искусственных временных путях подменяет только `os.geteuid()` через `unittest.mock.patch`, но исполняет реальную `main()` из embedded helper. Отдельный тест принудительно задаёт непривилегированный UID и доказывает отказ. Production-код helper и root-проверка не ослаблены. Никакой доступ к `/etc`, `/run` или systemd в тесте не требуется.

## Диагностика разных типов проблем

```bash
bash ./install.sh --diagnose-node --domain your-node.example.com
bash ./install.sh --diagnose-node
bash ./install.sh --diagnose-resources --seconds 15
```

`--diagnose-node` — отдельный read-only статический срез (Python standard library; может запускаться от непривилегированного пользователя). Команда НЕ обращается к клиентам, не раскрывает UUID, cookie, private keys, клиентские IP или полные логи. С `--domain` проверяет A-запись через **системный** DNS-резолвер (НЕ независимую авторитетную DNS-консенсусную проверку) и сравнивает с реально назначенными IP. Без домена внешних запросов нет.

- `addresses`: все назначенные публичные IPv4, интерфейсы, маски, MTU, secondary, состояние интерфейсов. Дополнительные IPv4 не теряются и не удаляются.
- `domain_alignment`: `PASS` только при одном публичном A-адресе, назначенном VPS. Ошибки DNS и неразрешимый домен — `REVIEW` / `UNVERIFIED`.
- `outbound_route`: источник, который ядро выбирает для исходящего маршрута к 1.1.1.1; при отличии от IP домена — **замечание, не автоматическая ошибка**. Это не DNS-запрос и не реальная проверка доступа к 1.1.1.1.
- `network_configuration`: только наличие признаков конфигурации ifupdown, Netplan, NetworkManager, systemd-networkd, cloud-init. Нельзя делать вывод об активном backend по одному наличию каталога.
- `conntrack`: used/max, предупреждение >=85%; без счётчиков статус `UNVERIFIED`.
- `tcp_kernel`: текущие значения BBR/qdisc/MTU-probing, без записи sysctl. Значение `default_qdisc=fq` не означает `fq` на всех живых интерфейсах.
- `interface_qdiscs`: фактически назначенные qdisc на интерфейсах; без попытки включить BBR/fq или изменить MTU.
- `docker_node`: только статус контейнера `remnanode`, никаких env, mounts или названий чужих контейнеров.
- `tcp_listeners`: номера портов, а не IP клиентов; порт listen не означает доступность извне или исправность firewall.
- `--diagnose-resources`: интервальная нагрузка CPU, RAM, TCP retransmits, UDP errors, softnet, netdev drops, FD, OOM и conntrack — анализируется **совместно** со статическим срезом.

Проверять реальные UDP/packet loss, полное TLS-рукопожатие, сертификаты, Remnawave-клиентов и bottleneck VPS отдельно; эти скрипты не заменяют live E2E. Одна команда не доказывает причины проблемы 50% клиентов.

## Несколько IPv4 и /etc/network/interfaces

На Ubuntu актуальным конфигуратором может быть Netplan/cloud-init; на Debian — ifupdown; на отдельных VPS systemd-networkd/NetworkManager. Одна и та же инструкция редактирования `/etc/network/interfaces` неприемлема для всех хостеров. Простое изменение `gateway`, `address`, `src` или `ifdown` по SSH может потерять вторичные IPv4 и весь доступ.

**Действующий безопасный механизм:** инсталлятор через `ip -j -4 address show scope global` получает все фактические public IP; проверяет A-запись домена через публичные DNS; выбирает **ровно один** совпадающий public IP. Не выбирает первый IP по умолчанию и не удаляет вторичные. Если назначено 4 адреса, а DNS указывает на третий — выбирается третий. Случай multiple A, AAAA, CDN Proxy, отсутствующего IP не обходит fail-closed preflight.

Дополнительные изменения конфигов сети намеренно не автоматизированы. Если реально требуется управление первичным IP, нужны провайдерский конфиг, netplan/ifupdown backend, backup/snapshot, web-консоль, тест с `netplan try`/проверяемый rollback после отдельного разрешения. От исходящего default-route source не зависит IP назначения входящего подключения.

## Nginx, Selfsteal, Docker и ограничения

Гибридный Nginx Stream обрабатывает fallback-трафик REALITY, не основной авторизованный поток. Nginx stream `ssl_preread` и TLS passthrough используют прежнюю архитектуру, без автоматического изменения тайм-аутов/worker limit. Клиентский TCP/443 Xray и Node API TCP/2222 остаются прежними. Docker `network_mode=host` нужен для текущего deployment и не имеет своего IP: дополнительный публичный адрес не требует Docker bridge/NAT.

Никаких новых неограниченных reverse proxy, внешних сервисов, туннелей и изменённых правил firewall не добавлено. Риск маскировки по SNI и IP/ASN остаётся; обещать «невидимость» VPN нельзя. Изменения Nginx, XHTTP, congestion control, Docker layers и ограничений клиентов требуют реальных проблем/замеров, а не допущений.

## Приёмка и rollback

1. Запустить офлайн-набор под root и **отдельно UID 1001** на Linux, проверить, что Socket Prepare никогда не трогает host. GitHub Actions должен показать PASS 5/5.
2. На disposable VPS с двумя–четырьмя IP и однозначным DNS A проверить `--diagnose-node --domain`, установку обычной ноды и каскадное меню; убедиться, что ни один вторичный IP/route не удалён.
3. Перед staging-инсталляцией сделать snapshot, проверить доступ к провайдерской консоли. Проверить `nginx -t`, `systemctl status nginx`, TLS-сайт/ACME, REALITY RAW/XHTTP, связь панели, UDP, перезагрузку, socket fallback, `docker inspect` без показа секретов.
4. При ошибке установки восстановить *полный snapshot* тестового VPS; исходную конфигурацию сети вручную не переписывать. По результатам диагностики на работающей ноде изменения не требуются — rollback = не нужен.

**GitHub:** команда из README предназначена для опубликованного `main` той же версии/проверенного SHA. Пока PR не объединён и CI не зелёный, она обязана останавливаться до запуска `install.sh`.
