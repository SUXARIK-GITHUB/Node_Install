# Node_Install 2.4.0 — default `NET_ADMIN`

Дата: **2026-10-02**.

## Причина изменения

RemnaNode работает с `network_mode: host`. Для функций, которым нужен доступ к сетевому состоянию хоста, в том числе используемого оператором «Обозревателя сессий», контейнеру требуется capability:

```yaml
cap_add:
  - NET_ADMIN
```

В 2.3.0 эта capability была только явным opt-in через `--allow-net-admin`. В 2.4.0 проектная политика изменена: **новая установка выдаёт `NET_ADMIN` по умолчанию**.

## Что изменено в installer

- `INSTALLER_VERSION=2.4.0`.
- Новая конфигурация сохраняет `allow_net_admin=true`.
- Resume незавершённой 2.4.0 также приводит state к `allow_net_admin=true`.
- Generated `/opt/vkarmani-node/compose.yaml` всегда содержит `cap_add: NET_ADMIN`.
- `--allow-net-admin` остаётся принятым CLI-флагом только для совместимости старых команд; отдельного opt-in в 2.4.0 больше нет.
- `vkarmani-node-check` считает совпадение `allow_net_admin=true` + фактический `NET_ADMIN` нормальным PASS. Несовпадение state/container остаётся ошибкой capability policy.
- Reviewed-version allowlists для profile-check, maintenance и cover дополнены 2.4.0, при этом прежние поддерживаемые версии не удалены.

Не изменены: `NET_RAW` drop, `no-new-privileges`, read-only Selfsteal mount, host Nginx, UFW, Fail2ban, SSH policy, IPv4-only, порты, REALITY/Selfsteal, image digest pinning, APT plan и число обязательных вопросов.

## Security trade-off

`NET_ADMIN` при host networking увеличивает blast radius контейнера. Процесс с этой capability может воздействовать на сетевые объекты общего namespace VPS в пределах возможностей ядра/capability: интерфейсы, маршрутизацию, qdisc и firewall/network state. Это не эквивалент полного root хоста, но это заметно шире, чем default 2.3.0 без `NET_ADMIN`.

Поэтому массовая раскатка должна идти canary → проверка панели/клиента/host network → остальные ноды. Provider snapshot перед массовым изменением остаётся предпочтительным rollback.

## Существующие ноды

Обычный повторный запуск installer на уже завершённой ноде намеренно выполняет диагностику и **не переписывает Compose**. Поэтому завершённые 2.3.0/ранние project-owned ноды не получают новую capability автоматически только от запуска 2.4.0.

Для них используется узкая операция ниже. Она:

1. берёт общий installer lock;
2. проверяет project-owned state, Compose, container и host networking;
3. создаёт root-only backup `compose.yaml` и `config.json`;
4. атомарно добавляет `cap_add: NET_ADMIN`, только если Compose имеет ожидаемую структуру;
5. сохраняет `allow_net_admin=true` штатным installed helper;
6. выполняет `docker compose config --quiet`;
7. делает `docker compose up -d --pull never` — без pull и без restart Docker daemon;
8. проверяет `NET_ADMIN`, running/stable container и неизменность image ID;
9. при apply-failure возвращает оба файла из backup и пытается поднять прежний Compose.

```bash
sudo bash <<'ENABLE_NET_ADMIN'
set -Eeuo pipefail
set +x
umask 077
export LC_ALL=C LANG=C PYTHONUTF8=1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

STATE=/var/lib/vkarmani-node
ETC=/etc/vkarmani-node
COMPOSE=/opt/vkarmani-node/compose.yaml
HELPER=/usr/local/lib/vkarmani-node/node_helper.py
LOCK=/run/lock/vkarmani-node-installer.lock

[[ $EUID -eq 0 ]] || { echo 'STOP: нужен root.' >&2; exit 1; }
for cmd in docker python3 flock cp install date; do command -v "$cmd" >/dev/null || { echo "STOP: нет команды $cmd" >&2; exit 1; }; done
docker compose version >/dev/null
[[ -f "$STATE/owned-installation" && -s "$STATE/INSTALL_COMPLETE" ]] || { echo 'STOP: завершённая project-owned VKarmani Node не найдена.' >&2; exit 1; }
[[ -f "$COMPOSE" && ! -L "$COMPOSE" && -f "$ETC/config.json" && ! -L "$ETC/config.json" && -s "$HELPER" ]] || { echo 'STOP: отсутствуют или небезопасны Compose/config/helper.' >&2; exit 1; }
[[ ! -e "$STATE/image-update-pending" && ! -e "$STATE/network-rollback-armed" && ! -e "$STATE/network-rollback-running" ]] || { echo 'STOP: есть незавершённая транзакция. Сначала разберите её.' >&2; exit 1; }
mkdir -p /run/lock
exec 9>"$LOCK"
flock -n 9 || { echo 'STOP: другой installer/maintenance уже работает.' >&2; exit 1; }

docker compose -f "$COMPOSE" config --quiet
[[ $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]] || { echo 'STOP: remnanode сейчас не running; сначала разберите исходное состояние.' >&2; exit 1; }
[[ $(docker inspect remnanode --format '{{.HostConfig.NetworkMode}}' 2>/dev/null) == host ]] || { echo 'STOP: remnanode не использует ожидаемый host network.' >&2; exit 1; }
IMAGE_BEFORE=$(docker inspect remnanode --format '{{.Image}}')
[[ -n "$IMAGE_BEFORE" ]] || { echo 'STOP: не удалось определить текущий image ID.' >&2; exit 1; }

BK="$STATE/backups/net-admin-$(date +%Y%m%d-%H%M%S)-$$"
install -d -m 0700 "$BK"
cp -a -- "$COMPOSE" "$BK/compose.yaml.before"
cp -a -- "$ETC/config.json" "$BK/config.json.before"

rollback() {
    local rc=${1:-1}
    trap - ERR INT TERM HUP
    set +e
    echo "ERROR: включение NET_ADMIN не завершено (rc=$rc). Возвращаю Compose/config из $BK" >&2
    cp -a -- "$BK/compose.yaml.before" "$COMPOSE"
    cp -a -- "$BK/config.json.before" "$ETC/config.json"
    docker compose -f "$COMPOSE" config --quiet
    docker compose -f "$COMPOSE" up -d --pull never
    echo 'ROLLBACK_ATTEMPTED: проверьте docker inspect remnanode и работу ноды.' >&2
    exit "$rc"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM
trap 'rollback 129' HUP

python3 - "$COMPOSE" <<'PY'
import os
import stat
import tempfile
from pathlib import Path

path = Path(__import__('sys').argv[1])
st = path.lstat()
if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
    raise SystemExit('STOP: compose.yaml должен быть regular root-owned и не writable для group/other')
raw = path.read_bytes()
if len(raw) > 2 * 1024 * 1024:
    raise SystemExit('STOP: неожиданный размер compose.yaml')
text = raw.decode('utf-8')
expected = '    cap_add:\n      - NET_ADMIN\n'
if expected in text:
    raise SystemExit(0)
if '\n    cap_add:\n' in text:
    raise SystemExit('STOP: найден нестандартный cap_add; автоматическое изменение запрещено')
anchor = '    cap_drop:\n      - NET_RAW\n'
if text.count(anchor) != 1:
    raise SystemExit('STOP: ожидаемый cap_drop: NET_RAW не найден ровно один раз')
text = text.replace(anchor, anchor + expected, 1)
fd, name = tempfile.mkstemp(prefix='.compose.net-admin-', dir=path.parent)
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
        fd = -1
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    os.replace(name, path)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
PY

python3 "$HELPER" allow-net-admin true
[[ $(python3 "$HELPER" get allow_net_admin) == true ]] || { echo 'STOP: state allow_net_admin не стал true.' >&2; false; }
docker compose -f "$COMPOSE" config --quiet
docker compose -f "$COMPOSE" up -d --pull never

[[ $(docker inspect remnanode --format '{{.State.Running}}') == true ]]
[[ $(docker inspect remnanode --format '{{json .HostConfig.CapAdd}}') == *NET_ADMIN* ]]
[[ $(docker inspect remnanode --format '{{.Image}}') == "$IMAGE_BEFORE" ]] || { echo 'STOP: image неожиданно изменился.' >&2; false; }
R1=$(docker inspect remnanode --format '{{.RestartCount}}')
sleep 5
R2=$(docker inspect remnanode --format '{{.RestartCount}}')
[[ "$R1" == "$R2" && $(docker inspect remnanode --format '{{.State.Running}}') == true ]] || { echo 'STOP: контейнер не стабилен после recreate.' >&2; false; }

trap - ERR INT TERM HUP
echo "NET_ADMIN=ENABLED; container=running; image=unchanged; backup=$BK"
echo 'Теперь проверьте Обозреватель сессий в панели и обычное клиентское подключение.'
ENABLE_NET_ADMIN
```

> Для существующей 2.3.0 ноды эта узкая операция **не заменяет установленный `vkarmani-node-check` на версию 2.4.0**. Старый checker 2.3.0 при `allow_net_admin=true` + фактическом capability штатно выводит `WARN NODE_NET_ADMIN` (в той версии это был explicit opt-in). Сама команда выше независимо проверяет `HostConfig.CapAdd`, running/stability и неизменность image ID. Не копируйте новый checker отдельно только ради смены WARN на PASS.

### Rollback вручную

Если после уже успешной команды требуется **осознанно** вернуть предыдущий Compose/config, используйте конкретный путь backup, напечатанный командой. Сначала сделайте новый snapshot/backup текущего состояния. Не подставляйте случайный каталог и не удаляйте backup до проверки.

Возврат `NET_ADMIN` обратно в выключенное состояние меняет runtime container и снова требует recreate. Этот rollback не является откатом image, ОС, firewall или данных панели.

## Что проверять после rollout

- `docker inspect remnanode --format '{{json .HostConfig.CapAdd}}'` содержит `NET_ADMIN`;
- container остаётся `running`, RestartCount не растёт;
- image ID не изменился при узком обновлении существующей ноды;
- Node API/панель продолжают работать;
- реальный VLESS-клиент подключается;
- «Обозреватель сессий» показывает ожидаемые данные;
- UFW/host routes/qdisc не получили неожиданных изменений.

Локальные unit/integration tests не могут доказать последний набор пунктов на конкретной production VPS. Нужна canary-проверка.
