# Node_Install 2.5.18 r24 — Часть 1 из 2: сайт, Nginx/selfsteal, сетевые проверки

**Статус: INCOMPLETE_STAGING_ONLY, 2026-11-05. Только ZIP, не GitHub/production.**

Это первый из двух согласованных заходов. Основа — полный архив r23. Все файлы r23 сохраняются. Здесь НЕ устанавливаются новые протоколы и не переключается реальный Xray. Проверка Panel и клиентов на VPS исключена по требованию оператора. **SSH остаётся password-only, SSH-ключи на нодах не внедряются.** Новые опции не меняют `sshd_config`, `authorized_keys`, Docker, firewall, GRUB и сетевые маршруты.

## Сделано в первом заходе

1. `scripts/site_manager.py` и `install.sh --site-manager ...` объединяют **все 120 сайтов** в одном пользовательском CLI (`list`, `preview`, `status`, `deploy`, `change`, `rollback`, `menu`). Используют существующий транзакционный `NodeWeb`: private journal, SHA256 резервных копий, проверка Nginx/HTTPS и автоматический откат, включая сохранение предыдущего активного сайта. Для записи — обязательное `--confirm-staging`; интерактивное меню дополнительно требует ввести `STAGING` и точный FQDN. Новые записи дополнительно сериализуются с основным lock установщика. Никаких wildcard-правил публикации, новых портов или внешних сайтов.
2. `install.sh --site-theme <ID>` разрешает **выбрать одну из 120 тем на новой обычной staging-ноде**. Выбор и полная целостность ZIP/манифеста проверяются **до изменения ОС**, но применяется только после успешного `INSTALL_COMPLETE`, а не во время APT, Certbot или настройки Xray. Если site-only развертывание не подтверждено, его rollback выполняет `NodeWeb`, core node не переустанавливается, auto-reboot отменяется, а оператор должен проверить receipt перед последующими действиями. **Выбор темы не хранится в `inputs.pending` вместе с SECRET_KEY.** При прерывании сверяйтесь с маркерами установки; при сохранённом `finalization` разрешён только узкий `--finish-install` без `--site-theme`, после чего используйте `--site-manager deploy`. Повторный запуск обычного установщика на частично изменённой VPS без разбора checkpoint запрещён. Не использовать для каскада/ранее установленной ноды. `--site-theme` предполагает присутствие полного ZIP.
3. `integrations/selfsteal_chain.py` и `install.sh --selfsteal-verify` дают единый **read-only локальный** результат: статические права и config, TLS/SNI/HTTP через `nginx.sock` с PROXY protocol v1, `nginx -t`. `--public-check` отдельно запускает существующий установленный HTTPS-чекер. Вывод без домена, IP, токенов и приватных ключей. Никаких утверждений об успешной REALITY-аутентификации или обходе DPI.
4. `integrations/path_mtu_diagnostics.py` и `install.sh --path-mtu` читают путь до указанного IPv4, интерфейс и MTU. **Без `--probe` не отправляют сетевые пакеты**; при явном `--probe` — не больше 4 ICMP-запросов до адреса, контролируемого оператором. Не печатают адрес назначения, MAC или gateway. Не меняют MTU/MSS/qdisc/sysctl. Пропуск ICMP — не доказательство MTU black hole.
5. `install.sh --transport-audit FILE.json` подключает уже реализованный в r22 статический валидатор REALITY/Vision/XHTTP к единой CLI-точке входа. Не выдаёт секреты и не устанавливает inbound.

## Команды, не изменяющие VPS

```bash
bash install.sh --site-manager list
bash install.sh --site-manager preview --theme 111-atlas-docs --output /tmp/vk-preview-new
sudo bash install.sh --site-manager status
bash install.sh --selfsteal-verify --strict
bash install.sh --selfsteal-verify --public-check --strict  # отдельная HTTPS проверка своего сайта
bash install.sh --path-mtu --target YOUR_OWN_IPV4
bash install.sh --path-mtu --target YOUR_OWN_IPV4 --probe  # до 4 ICMP только по явному запросу
bash install.sh --transport-audit examples/inbound-raw-full.example.json
```

## Управление сайтом, только на завершённой staging-ноде

```bash
# перед работой: snapshot всего VPS, аварийная консоль, verify_release, текущий Nginx HTTPS
sudo bash install.sh --site-manager menu
# либо явно, строго заданный домен именно этой ноды:
sudo bash install.sh --site-manager deploy --theme 111-atlas-docs --expected-domain node.example.com --confirm-staging
sudo bash install.sh --site-manager change --theme 116-vinyl-room --expected-domain node.example.com --confirm-staging
sudo bash install.sh --site-manager rollback --confirm-staging
```

**Первая новая тестовая ordinary-нода:**

```bash
sudo bash install.sh --site-theme 111-atlas-docs --no-reboot
```

`--site-theme` не выполняет миграцию существующих установок и не сохраняется в закрытом `inputs.pending`. При финализационном checkpoint нужно закончить `--finish-install` и затем отдельно применить тему через `--site-manager deploy`. Каскад Entry/Exit продолжает использовать прежнюю проверенную архитектуру без автоматической смены темы. На production не запускать до проверки dev/staging/снимка и точного доступа. Если не завершилась install transaction, восстанавливать **полный снимок хостера**, не удалять маркеры и не запускать repair наугад. Если **только site transaction** отказала, сначала изучить закрытый журнал `/var/lib/vkarmani-node/r7-web-deploy/` и инструкции `docs/R7_SITES_TCP_AND_LIVE_PROBES.md`. Резервные копии не являются snapshot всей ОС.

## Что остаётся на второй заход

- Завершение optional transports: XHTTP/TLS/H2 runtime и конфигурационный жизненный цикл, отдельно Hysteria2 и AmneziaWG с требованиями UDP/TLS, firewall, service-management, reversible deployment, **только по явному согласию**; не создавать DIRECT на cascade Entry.
- Транспортная матрица, безопасные проверяемые альтернативные режимы, дополнительные проверки SNI/ALPN/TLS и совместимости, исследование FinalMask и fingerprint. Никаких обещаний полной невидимости от DPI.
- Дополнительные измерения сети (BBR/CUBIC, queues, MTU, RTT, loss, TCP window) по одинаковым нагрузкам и **консервативная, откатываемая** оптимизация только при доказанной причине. Ни одно ядро или сторонний BBR не ставить автоматически.
- Закрытие обязательных offline тестов и отчёта по коду. Реальные Panel+клиенты на VPS **исключены из задания**, поэтому любые нуждающиеся в них результаты остаются unverified, а не объявляются рабочими.

## Что не проверяется offline

Соединение REALITY клиента, доступность из блокируемых сетей, фактическая эффективность маскировки DPI, эксплуатация при настоящем certificate renewal / реальных сетевых сбоях и производительность внешнего туннеля. Ничего из этого не заменяется успешным `nginx -t` или `unittest`.
