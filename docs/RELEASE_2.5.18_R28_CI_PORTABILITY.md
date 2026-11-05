# Node Install 2.5.18 r28 — GitHub Actions CI portability hotfix

**Состояние:** `INCOMPLETE_STAGING_ONLY`. Дата 2026-11-05. Основа r27, пользовательские серверы и панели не менялись.

## Причины ошибок в GitHub Actions r27

- Ubuntu 22.04 (Python 3.10) и Debian 12 (Python 3.11): `scripts/site_catalog.py` использовал повторное цитирование строк в f-string. Такой синтаксис доступен с Python 3.12, но не в заявленной матрице. Вынесен расчёт `color_scheme` перед f-string без изменения HTML.
- Ubuntu 24.04 без root: два теста Nginx обращались к стандартному `/var/log/nginx/access.log`. Изолированные конфиги тестов теперь явно отключают журнал запросов; это не меняет production Nginx. Тесты исполняются без sudo.
- Ubuntu 26.04 userspace: проверка Xray отклоняла системный `true`, если `/usr/bin/true` был ссылкой. Для тестов используется временный локальный исполняемый файл с безопасными правами, без ослабления проверки Xray.

## Распределение проверок

1. Git: чистота checkout и целостность `SHA256SUMS`, `BUILD_MANIFEST.json`.
2. Bash: `bash -n` основного установщика и исполняемых сценариев.
3. Python: проверка компиляции всех `.py` в `integrations`, `scripts`, `tests` под фактическим интерпретатором матрицы до выполнения тестов. Компиляция в памяти, без `.pyc` и без побочных действий.
4. Модули: каждый `tests/test_*.py` в отдельном интерпретаторе через `tests/run.sh`.
5. Интеграционные offline-сценарии: изолированные Nginx/TLS, ошибки/rollback, Casсade, XHTTP, приватные настройки и Node CLI.
6. Финальная проверка: `git diff --check`, `git diff --exit-code`, пересчёт манифеста и контрольных сумм полного ZIP.

Полный список матрицы: Ubuntu 22.04, Ubuntu 24.04, Ubuntu 26.04 userspace, Debian 12 и Debian 13 userspace. Проверка не является развёртыванием на VPS, измерением реального VPN или доказательством production-готовности.

## Запуск локально

```bash
cd Node_Install
sha256sum --check SHA256SUMS
python3 scripts/verify_release.py --root .
bash tests/run.sh
python3 scripts/site_audit.py --rich
python3 scripts/build_site_gallery.py --check
```

**Для изменения уже установленной VPS:** сначала отдельный snapshot и проверка аварийной консоли; этот hotfix не требует переустановки нод и не изменяет сетевые службы. При сбое CI не разрешать выпуск и не обновлять `main`.
