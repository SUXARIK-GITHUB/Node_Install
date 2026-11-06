# Node Install 2.5.18 r38 — переносимость тестов Blocky в GitHub Actions

**Дата:** 2026-11-06 · **Статус:** `INCOMPLETE_STAGING_ONLY`

## Проблема r37 после публикации

В пяти окружениях GitHub Actions завершались с ошибкой только новые тесты `tests/test_r37_adblock.py`. Предварительные проверки, тесты прежних подсистем, Python/Bash-синтаксис проходили.

* **Ubuntu 22.04, Debian 12/13, Ubuntu 26.04 userspace:** стенд не обязан иметь `systemctl` в `PATH`, однако `FakeHost` имитирует systemd только на уровне выполнения команд. Из-за реальной проверки `shutil.which` появлялся `SYSTEMD_REQUIRED`.
* **Ubuntu 24.04 без root:** fixture `TemporaryDirectory` и файлы-маркеры принадлежат CI-пользователю, а production-код Blocky корректно требует `uid=0` (`UNSAFE_FILE:.../INSTALL_COMPLETE`). В локальном запуске от root ошибка не проявлялась.

## Исправление

В `integrations/adblock.py` выделены два проверяемых условия `root_owned(st)` и `systemctl_available()`. **Их production-поведение не изменено:** uid строго равен 0, бинарник `systemctl` обязателен.

В фикстуре `FakeHost` только на время отдельных тестов подменяются эти две зависимости: ожидаемым владельцем фиктивных файлов считается запускающий тест пользователь, а наличие systemd имитируется вместе с уже мокированными командами и состояниями сервисов.
Все остальные условия `regular_file`, `managed_directory`, `locked`, права доступа, `O_NOFOLLOW`, запреты на symlink/hardlink и проверка ролей продолжают исполняться настоящим кодом. Добавлены отдельные тесты реального root-owner/systemctl-предиката и отказа при небезопасных ссылках/правах.

## Проверки для приёмки

```bash
python3 -m unittest discover -s tests -p test_r37_adblock.py -q
sudo -u nobody python3 -m unittest discover -s tests -p test_r37_adblock.py -q
bash tests/run.sh
sha256sum --check --status SHA256SUMS
python3 scripts/verify_release.py --root .
```

Тест `nobody` запускайте только в каталоге, доступном непривилегированному пользователю; на CI runner тесты уже выполняются от него. Не запускайте `--adblock enable` на production ради QA.

Ни CI, ни архивные проверки не подтверждают работу клиентов Remnawave через Blocky: как и в r37, `CLIENT_DNS=NOT_VERIFIED`. Для подтверждения на VPS нужны отдельные тесты DNS-маршрута на Ordinary/Exit. Реальный GitHub Actions r38 должен пройти после публикации — локальный прогон не равен успешному удалённому CI.
