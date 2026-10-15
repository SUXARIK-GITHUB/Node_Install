# QA/матрица r5 · каскадные роли (Node_Install 2.5.10)

**Статус:** `INCOMPLETE_STAGING_ONLY / NOT_PRODUCTION_VALIDATED / NOT_PUBLISHED`.

## Изменения и границы

Новая роль `entry`/`exit` для **двух новых** VPS (`install.sh`, `integrations/cascade_deployment.py`), строгое сохранение ролевых закрытых пакетов до APT, разделение REALITY privateKeys и подтверждение соответствия публичному ключу, REALITY RAW/Vision от своей роли, `BLOCK`+`TO_EXIT_VLESS` на entry и `DIRECT`+`BLOCK` на exit, отказ от XHTTP/автоперезапуска каскада. Read-only аудит вычисленного Xray JSON тестовой панели (`integrations/cascade_panel_audit.py`) запрещает добавочные outbounds, чужих клиентов и DIRECT на entry. Историческая ordinary-ветка не должна меняться.

Инструменты не подключаются к живой панели, не получают её административный API-токен, не создают Service User/Squad/Host/Node, не переносят автоматом секреты по SSH и не выполняют миграцию старой ноды. Ролевые JSON подготавливаются для **ручного назначения в TEST Panel**. Нельзя подтверждать сетевой каскад по локальным JSON.

## Контроль исходников и тестов

Используйте **только** SHA256 итогового ZIP из отдельного `.sha256`. Встроенные `SHA256SUMS` / `BUILD_MANIFEST.json` подтверждают внутреннюю целостность архива и не являются независимой подписью.

| Проверка | Тип | Ограничение |
|---|---|---|
| Закрытые роли/криптографическая ключевая пара/приватность | unit/negative | Нет межузлового обмена пакетами |
| Сохранение role marker, запрещённый role switch и повторный запуск | unit/source | Нет аварийной перезагрузки VPS |
| Реальная `PY_HELPER` из `install.sh` с ролевым профилем | Python embedded-unit | Не запущен реальный rw-core |
| Панельный computed JSON, fail-closed outbound/routing/API/clients | unit/negative | Реальный формат зависит от Panel/core |
| Ordinary regressions + packaging + CI | offline suite | Нет реального Docker daemon/OS |
| Реальный host install на Exit/Entry | **NOT EXECUTED** | Нужны две чистые staging VPS + snapshots |
| Две Node/Host/Squad + service-user | **NOT EXECUTED** | Нужна отдельная Test Panel |
| Реальные клиент, tcp/udp/dns, pcap, peer down, reboot, RKN | **NOT EXECUTED** | Нужна внешняя сеть и 2 VPS |

Проверка закрытого архива осуществляется **после** сборки (`unzip`→`SHA256SUMS`→`verify_release.py`→`tests/run.sh`). Финальный счёт и SHA256 в выдаваемом внешнем QA-отчёте, если прогон завершён успешно. Исторические результаты 2.5.6/2.5.9/r4 не выдавать за r5.

## Критические будущие gate и последствия

1. **P0:** хостовая установка двух ролей на новой staging паре; proof `rw-core run -test`, local role checkpoints, Nginx Selfsteal HTTP/TLS certificates, Node PORT ACL + SSH после reboot.
2. **P0:** две новые Node, два изолированных Profile, bridge service-user только на Exit, клиентский Squad/Host только на Entry. Проверять **активный** computed JSON, а не только локальный файл.
3. **P0:** проверить внешний IP через Exit и **жёсткий отказ** клиента при отключенном Exit. Проверить отсутствие обходного DIRECT/DNS resolution на Entry при обычном и отказном пути.
4. **P1:** RKN может заблокировать IP Entry на Exit, исключение peer IP автоматически **не создаётся**. Требуется тест и отдельно согласованный способ разрешения, не отключая базовую UFW или открывая порт всем.
5. **P1:** ротация действующего peer, двухузловая координация ночного restart, full snapshot-restore отсутствуют. Любое обновление production до выполнения этих gate запрещено.
6. **P1:** проверить версию real bundled Core на используемом контейнере: RAW/REALITY/Vision chained и FREEDOM `finalRules`; JSON syntax и offline mock недостаточны.

Runbook для staging: [CASCADE_R5_ROLE_INSTALL_AND_PANEL.md](CASCADE_R5_ROLE_INSTALL_AND_PANEL.md). GitHub не изменён, серверы/Panel/БД не изменены; r5 — локальный ZIP.
