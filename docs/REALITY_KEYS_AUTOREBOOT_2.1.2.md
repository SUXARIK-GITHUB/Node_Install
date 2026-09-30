# REALITY keys export и auto-reboot — 2.1.2

## Задача

После успешной установки оператору нужны три значения для Remnawave: `PrivateKey`, `PublicKey`, `ShortID`. Они должны быть доступны сразу в терминале и в закрытом root-файле. После этого нода должна сама выполнить обязательный reboot, нужный для окончательной IPv6/kernel-проверки.

## Реализация

Источник ключей не меняется: `/etc/vkarmani-node/reality.json`. Финальный этап **не запускает `xray x25519` повторно** и не создаёт вторую пару. Helper повторно проверяет сохранённую X25519-пару и ShortID, затем атомарно формирует `/root/reality-keys.txt`.

Файл:

- fixed path `/root/reality-keys.txt`;
- regular file, не symlink;
- mode `0600`;
- на штатной установке owner root;
- содержит домен, `PrivateKey`, `PublicKey`, `ShortID`, `target=/dev/shm/nginx.sock`, `xver=1`, `minClientVer=1.0.0`, SNI;
- при существующем небезопасном объекте не перезаписывается.

Финальный секретный блок направляется в `/dev/tty`, а не в stdout после включённого `tee`. Поэтому `PrivateKey` виден оператору, но не добавляется в `/var/log/vkarmani-node-install.log`. Это не защищает от terminal scrollback/screen recording/root.

## Reboot

`NO_REBOOT=0` по умолчанию. После `INSTALL_COMPLETE` и финального вывода ключей создаётся transient systemd unit с `--on-active=30s /usr/bin/systemctl reboot`. Это переживает закрытие SSH-сессии и не требует фонового shell-процесса.

`--no-reboot` отключает только этот одноразовый reboot. `--weekly-reboot` остаётся отдельным opt-in расписанием.

Если `systemd-run` не смог поставить reboot, завершённая установка не превращается в повреждённую: выводится `AUTO_REBOOT=FAILED`, после чего оператор выполняет `sudo reboot` вручную.

## Совместимость старых Xray-core

Генерируемый import profile фиксирует `minClientVer: "1.0.0"`. Это сохраняет рабочую совместимость со старыми клиентскими ядрами, обнаруженную при переходе трёх ключевых нод на собственный Selfsteal. Остальная политика остаётся: VLESS + RAW + REALITY, `target=/dev/shm/nginx.sock`, `xver=1`, собственный домен в `serverNames`.

## Rollback / отказ

Изменение не мигрирует завершённые production-ноды автоматически. Для новой версии сначала используется canary VPS. На уже установленной 2.1.0/2.1.1 обычный повторный запуск новой версии не является механизмом миграции.
