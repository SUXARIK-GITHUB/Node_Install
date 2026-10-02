# Node_Install 2.3.0 — SSH password-only и надёжность Selfsteal

Дата: 2026-10-02. База: полный `Node_Install_2.2.0.zip`, SHA256 `464ebf0c03a5cd9221fb2e8845f697f23ffcb9c9b54af55f6f3aef1eec4465a1`.

## Границы выпуска

Разработка выполнена в отдельной локальной копии. Оригинальные 157 пути поставки сохранены. Нельзя считать этот выпуск уже развёрнутым на TECH/Venom/Wardogs/Stellaris. Ни пользовательские VPS, ни GitHub, ни БД/Profiles/Hosts/Squads не изменялись.

Сохранены host Nginx, собственный Selfsteal на Unix socket, VLESS/RAW/REALITY, IPv4-only, Nginx/Certbot из ОС, RemnaNode host-network Docker, текущий UFW/Fail2ban, существующие SSH порты, BBR/fq с fallback. Не добавлены XHTTP, HAProxy, Caddy/Angie, second firewall manager, CDN/JS, агенты или новые runtime пакеты. Четыре прежние статические визитки/стабильный seed не перерисованы.

**Изменено требование SSH:** раньше publickey-policy сохранялась, теперь ключевой вход отключается. Это прямой запрос оператора, а не обещание улучшения криптографической безопасности.

## Только три входных значения

1. `SECRET_KEY` RemnaNode из панели.
2. Домен ноды.
3. Публичный исходящий IPv4 backend панели.

Адрес ноды определяется DNS + локальными адресами. `SECRET_KEY` не является SSH-ключом и не даёт admin API панели. Пароль существующего администратора — предварительное условие, а не четвёртое поле. Учётные записи, пароли, authorized_keys и настройки TECH не создаются/не меняются.

## SSH

Управляемая политика:

```text
PasswordAuthentication yes
PubkeyAuthentication no
AuthenticationMethods password
KbdInteractiveAuthentication no
HostbasedAuthentication no
GSSAPIAuthentication no
PermitEmptyPasswords no
PermitRootLogin yes
AddressFamily inet
```

`PermitRootLogin yes` не разблокирует аккаунт и не создаёт root-пароль. До изменения проверяются локальная запись/hash-present, lock/expiry/password-change flags и исполняемый login shell пользователя `SUDO_USER` либо root. Shadow никогда не печатается. Для неподдерживаемой условной/Include/Allow/Deny-политики — STOP, не удаление.

`ssh_guard.py` проверяет политику файлов, а не только `sshd -T`: общая конфигурация сама по себе не доказывает отсутствие разрешающего Match. Поддерживается стандартный distro include `/etc/ssh/sshd_config.d/*.conf`; неизвестная и recursive Include требуют аудита. Symlink/FIFO и доступные для посторонней записи policy-файлы не принимаются. Candidate `sshd_config` сначала пишется в private temp, проверяется `sshd -t/-T`, затем атомарно публикуется. Ошибка проверки сохраняет исходный файл. Shadow и authorized_keys не меняются.

Это не реальная парольная авторизация и не доказательство работоспособности PAM или внешнего маршрута. Перед установкой проверить парольный вход, snapshot и независимую консоль; для ручного окна использовать прежний `--no-reboot`. После — открыть вторую парольную сессию. По умолчанию один reboot через 30 секунд после завершения сохранён по прежнему запросу; weekly reboot не включается без своего флага.

## Четыре уровня проверки

| Уровень | Подтверждение | Не подтверждает |
|---|---|---|
| TARGET_TLS | Unix socket, PROXY v1, TLS 1.3, CA/hostname, активный leaf, ALPN HTTP/1.1/H2 | HTML, внешний путь, VLESS credentials |
| WEB_CONTENT | обычный selfsteal-check: HTML, CSS/SVG/hash/MIME, headers, HEAD/cache/negative requests | пользовательскую VLESS-аутентификацию |
| PUBLIC_PATH | владелец TCP/443 — core данного RemnaNode, HTTPS к своему IPv4/домену и ожидаемый index | доступность со всех операторов и передачу через VLESS |
| VLESS_AUTH | отдельный клиентский пилот | **не выполнен данным выпуском локально** |

Новая команда `vkarmani-selfsteal-check --target-only` не читает webroot. Полная команда без флага остаётся строгой и обязательной для приёмки страницы. В image maintenance и cert-activation используется именно readiness, чтобы повреждение оформления не означало ложный отказ сертификата.

Новая проверка TCP/443 не читает `cmdline`, `environ` или URL источника конфигурации с token. Читаются только безопасные поля inspect, `docker top -eo pid,comm` и IPv4 listener PIDs. Контейнер/набор core PID перепроверяются; недоступные данные/смена процесса отмечаются отдельно. Это моментный снимок, не длительный мониторинг. Отсутствующий до назначения панелью профиль по-прежнему не выдаётся за VPN-ready.

## Сертификаты

Host Certbot остаётся единственным владельцем certificate lifecycle. HTTP-01 продолжает использовать webroot на TCP/80. Нет временного NAT на TCP/443 и нет остановки Xray для renewal.

Новый `/usr/local/lib/vkarmani-node/cert_deploy.py` вызывается прежним deploy hook. Проверяет `RENEWED_LINEAGE` и `RENEWED_DOMAINS`: пропускает другой lineage; отсутствие или несогласованность своего контекста не считается успехом. В течение 75 секунд:

```text
PRECHECK: certificate fingerprint + nginx -t
RELOAD:   systemctl reload nginx
VERIFY_TARGET_TLS: ограниченные повторные проверки TLS-only
COMPLETE: текущий cert совпадает с начальным, receipt PASS
```

Один вызов команды ограничен 20 секундами. Reload не повторяется в retry-цикле. При SIGINT/TERM/HUP отказ отмечается и не проглатывается. Private lock исключает параллельные deploy; receipt root:0600 атомарно записывается с generation/phase/result/cert fingerprint без private key. После SIGKILL/power loss возможно RUNNING, не PASS; абсолютный автоматический recovery не заявлен. Helper не откатывает файлы Certbot и не вмешивается в чужой firewall.

Первоначальный `certbot renew --dry-run --run-deploy-hooks` требует **нового** успешного receipt, не исторического PASS. При таком dry-run Certbot передаёт hook активный текущий сертификат, а не staging-сертификат. Это проверка challenge и пути активации, не утверждение, что был получен новый production certificate. Dry-run — не read-only команда: CA-запросы, challenge и reload выполняются осознанно.

## Профиль и ресурсы

В новый generated template добавлен `settings.flow=xtls-rprx-vision`, согласованный с выбранной схемой. `minClientVer=0.0.0` остаётся. Пустые per-client flow допускаются при общем Vision. Пользователи и служебный API заполняются Remnawave, не installer. DNS/routing генератора не заменены custom live-профилем; в частности, сохранён прежний запрет panel IP. Импорт поверх рабочего custom-профиля без отдельной проверки недопустим: публичные сервисы на том же IP могут оказаться закрыты этим routing.

Resource helper дополнен FD count/soft-hard limit для nginx/rw-core/xray/rw-node и очередью собственного Unix socket. Не читаются fd targets/адреса клиентов. PID reuse, недоступный proc/ss или неправильные данные не маскируются нулём. Эти счётчики не доказывают утечку, перегрузку хостера или прирост скорости. MTU, NIC offloads и sysctl buffer tuning не добавлялись.

## Уже установленные версии

Default повтор на завершённой ноде вызывает **установленный** checker, не миграцию. `--update-cover` меняет страницу, `--refresh-image` — image. Они не отключают SSH-ключи, не устанавливают новые helpers/Nginx-policy и не меняют marker установленной версии. Не копировать helper отдельно и не менять `install-version` ради обхода guards.

Для существующих 2.1.x/2.2.0 полный безопасный in-place upgrade остаётся отдельной задачей: нужны baseline/config drift и проверенная транзакция. Этот выпуск предназначен для проверки новой установки. Старый installer поверх нового — не OS downgrade.

## Проверка/откат

До запуска: контрольные суммы и версия, snapshot с проверкой восстановления, доступная консоль, работающий пароль. Пилот — отдельная VPS, не TECH/БД и не загруженная production-нода. Предпочтительно `--no-reboot` для второго парольного входа и ручной приёмки. Затем Nginx/target/web/preboot, профиль и реальный клиент, согласованная перезагрузка и повторная проверка.

Полный откат установки — восстановление проверенного snapshot. Встроенный rollback guard относится только к изменяемой SSH/UFW фазе; это не откат пакетов/GRUB. Откат статической страницы и image имеют прежние отдельные процедуры/backup. Никакое наличие SHA backup не считается автоматически доказанным whole-VPS restore.

## Первичные источники механизма (не сетевой benchmark)

- OpenSSH sshd_config: https://man.openbsd.org/sshd_config — first obtained value, AuthenticationMethods, PubkeyAuthentication и Match.
- Certbot user guide: https://eff-certbot.readthedocs.io/en/stable/using.html — dry-run, deploy hooks, --run-deploy-hooks и активный certificate.
- Nginx control: https://nginx.org/en/docs/control.html — reload и старые workers.
- Xray 26.7.28: https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/infra/conf/vless.go — общий Vision и пустые per-user flow.

Точный состав реальных/имитированных прогонов и непроверенные уровни указаны в [TEST_REPORT](TEST_REPORT.md). Нет гарантии скорости, срока до блокировки, поддержки любого клиента или безотказности конкретного хостера.
