#!/usr/bin/env bash
# Stream-safe entry point: the complete function must parse before any setup runs.
vkarmani_main() {
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
# VKarmani Remnawave Node Installer 1.2.0 — 2026-09-25
# Dedicated fresh Ubuntu 22.04/24.04 or Debian 12/13, systemd + GRUB, amd64/arm64.
# One self-contained file; no remote shell scripts are downloaded/executed.
# WARNING: updates packages, modifies firewall/boot settings and reboots by default.
# Node-only mode: does not create or edit panel objects. Keep the VPS console available.
set -Eeuo pipefail
set +x
umask 077
export LC_ALL=C LANG=C PYTHONUTF8=1 DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset CDPATH ENV BASH_ENV
VERSION=1.2.0
ETC=/etc/vkarmani-node
STATE=/var/lib/vkarmani-node
LIB=/usr/local/lib/vkarmani-node
OPT=/opt/vkarmani-node
LOG=/var/log/vkarmani-node-install.log
# No built-in panel IP, domain or credential. Values are collected before APT.
NODE_PORT_DEFAULT=2222
NO_REBOOT=0
REFRESH_IMAGE=0

usage() {
    cat <<'HELP'
VKarmani Remnawave Node Installer 1.2.0

  sudo bash install.sh
  sudo bash install.sh --no-reboot
  sudo bash install.sh --refresh-image

Первый запуск: чистая выделенная VPS, Ubuntu 22.04/24.04 или Debian 12/13,
GRUB, systemd, amd64/arm64, публичный IPv4, >= 900 MiB RAM и >= 6 GiB свободно.
Существующую панель/ноду или чужую Docker/UFW/nginx-конфигурацию не мигрирует.
После успешной установки автоматический reboot, если не указан --no-reboot.
Первый запуск: SECRET_KEY → публичный IPv4 основного сервера → домен ноды.
Три вопроса заданы ДО APT-обновлений. Повтор использует сохранённые параметры.
Управляющий порт 2222 разрешён только с введённого IPv4 панели.
Карточка Node, Config Profile, Host и Internal Squad настраиваются в панели отдельно.
Сертификат: аккаунт Let's Encrypt без email, с автоматическим принятием условий CA.
--refresh-image разрешает обновить уже зафиксированный образ RemnaNode.
HELP
}
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --no-reboot) NO_REBOOT=1; shift ;;
        --refresh-image) REFRESH_IMAGE=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
@@COLLECT_INPUT@@
[[ $EUID -eq 0 ]] || { echo 'Запустите через sudo bash или от root.' >&2; exit 1; }
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo 'Bash >= 4 required' >&2; exit 1; }
command -v flock >/dev/null || { echo 'util-linux/flock required' >&2; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/vkarmani-node-installer.lock
flock -n 9 || { echo 'Установщик уже запущен.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'Требуется сервер с systemd.' >&2; exit 1; }
if systemd-detect-virt --container --quiet; then
    echo 'LXC/OpenVZ/Docker не поддерживаются: ядро и полное отключение IPv6 контролирует хост.' >&2
    exit 1
fi
[[ -r /etc/os-release ]] || exit 1
# Only distro-owned os-release is sourced. User input is always JSON, never shell.
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) echo "ОС вне поддерживаемого списка: ${PRETTY_NAME:-unknown}. Никаких изменений не выполнено." >&2; exit 1 ;;
esac
OS_ID=$ID
OS_CODENAME=$VERSION_CODENAME
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) echo 'Только amd64/arm64' >&2; exit 1 ;; esac
[[ -f /boot/grub/grub.cfg && -f /etc/default/grub ]] && command -v update-grub >/dev/null || {
    echo 'Нужна загрузка через GRUB: update-grub, /boot/grub/grub.cfg, /etc/default/grub.' >&2; exit 1;
}
if _contains -al 'systemd-boot' /sys/firmware/efi/efivars/LoaderInfo-* 2>/dev/null; then
    echo 'Обнаружен systemd-boot, этот установщик изменяет только GRUB. Остановка.' >&2; exit 1
fi
[[ "${SSH_CONNECTION:-}" != *:* ]] || { echo 'Текущая SSH-сессия использует IPv6. Сначала подключитесь по IPv4.' >&2; exit 1; }
[[ -x /usr/sbin/sshd ]] || { echo 'Требуется установленный OpenSSH server.' >&2; exit 1; }
install -d -m 0755 /run/sshd
/usr/sbin/sshd -t
MEM_MB=$(awk '/MemTotal:/{print int($2/1024)}' /proc/meminfo)
FREE_MB=$(df -Pm / | awk 'NR==2{print $4}')
[[ "$MEM_MB" -ge 900 && "$FREE_MB" -ge 6144 ]] || {
    echo "Нужно >=900 MiB RAM и >=6144 MiB свободного места. Сейчас RAM=$MEM_MB, disk=$FREE_MB MiB." >&2; exit 1;
}
[[ -z "$(dpkg --audit)" ]] || { echo 'dpkg сообщает незавершённые операции. Исправьте пакетную базу прежде установки.' >&2; exit 1; }
[[ -z "$(apt-mark showhold)" ]] || { echo 'Есть удерживаемые пакеты (apt-mark showhold). Полное обновление без снятия hold невозможно; остановка.' >&2; exit 1; }
FRESH=1
[[ -f "$STATE/owned-installation" ]] && FRESH=0
if [[ $FRESH -eq 0 && -f "$ETC/config.json" ]] && ! grep -F '"installation_mode": "secret-key-only"' "$ETC/config.json" >/dev/null; then
    echo 'Найдена установка другой версии/режима. Этот вариант не мигрирует API-установку: используйте чистую VPS.' >&2
    exit 1
fi
if [[ $FRESH -eq 1 ]]; then
    for p in "$ETC" "$OPT" /etc/vkarmani /opt/remnanode /opt/remnawave; do
        [[ ! -e "$p" ]] || { echo "Уже существует $p. Автоматическая миграция/удаление не выполняется." >&2; exit 1; }
    done
    if command -v docker >/dev/null; then
        [[ -z "$(docker ps -aq 2>/dev/null)" ]] || { echo 'Найдены чужие Docker containers. Нужна выделенная чистая VPS.' >&2; exit 1; }
    fi
    if command -v ufw >/dev/null && ufw status | _contains -F 'Status: active'; then
        echo 'UFW уже активен. Чужой firewall не перезаписывается: используйте чистую VPS.' >&2; exit 1
    fi
    for service in firewalld nftables netfilter-persistent nginx apache2 caddy; do
        if systemctl is-active --quiet "$service"; then
            echo "Активен $service. Нужна чистая выделенная VPS, без старого web/firewall стека." >&2; exit 1
        fi
    done
    if ss -H -lnt | awk '{print $4}' | _contains -E ':(80|443|8444)$'; then
        echo 'Порты 80/443/8444 уже заняты.' >&2; exit 1
    fi
    # Refuse a separate unmanaged nftables/iptables ruleset, even when its unit is inactive.
    if command -v nft >/dev/null && [[ -n "$(nft list tables 2>/dev/null)" ]]; then
        echo 'Обнаружены существующие nftables tables. Нужен чистый firewall.' >&2; exit 1
    fi
    for p in /etc/docker/daemon.json /etc/nginx/conf.d /etc/nginx/sites-enabled; do
        if [[ -f "$p" ]] || { [[ -d "$p" ]] && find "$p" -mindepth 1 -maxdepth 1 ! -name default -print -quit | _contains .; }; then
            echo "Найдена пользовательская конфигурация $p. Не перезаписываю." >&2; exit 1
        fi
    done
fi
# Input is from /dev/tty, never from the downloaded shell script stream.
vk_collect_inputs
# Package maintainer scripts must not read answers from the operator's terminal.
# All installer questions have been answered; unexpected package prompts fail safely.
exec </dev/null
install -d -m 0700 "$ETC" "$STATE" "$LIB" "$OPT"
touch "$LOG"; chmod 0600 "$LOG"
# No xtrace, no printing of SECRET_KEY, private keys or Docker environment.
exec > >(exec 9>&-; tee -a "$LOG") 2>&1
stage() { printf '\n[%s] %s\n' "$(date -Is)" "$*"; }
die() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
on_error() {
    local rc=$? line=${1:-unknown}
    trap - ERR
    printf '\nINSTALL_FAILED rc=%s line=%s\nСм. %s. Ребут НЕ запланирован.\n' "$rc" "$line" "$LOG" >&2
    printf 'rc=%s line=%s at=%s\n' "$rc" "$line" "$(date -Is)" > "$STATE/INSTALL_FAILED"
    if [[ -f "$STATE/image-update-pending" && -s "$STATE/compose.previous.yaml" ]]; then
        printf 'Возвращаю предыдущий образ RemnaNode после неудачного обновления.\n' >&2
        cp -a "$STATE/compose.previous.yaml" "$OPT/compose.yaml"
        cp -a "$STATE/image-digest.previous" "$STATE/image-digest"
        if docker compose -f "$OPT/compose.yaml" up -d; then
            rm -f "$STATE/image-update-pending"
        else
            printf 'Автооткат образа не подтверждён. Нужна проверка Docker через консоль VPS.\n' >&2
        fi
    fi
    if [[ -f "$STATE/network-rollback-armed" ]]; then
        /usr/local/sbin/vkarmani-network-rollback || true
    fi
    exit "$rc"
}
trap 'on_error "$LINENO"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
stage "VKarmani installer $VERSION — проверка и резервная копия"
BK="$STATE/backups/$(date +%Y%m%d-%H%M%S)-$$"
install -d -m 0700 "$BK"
for p in etc/ssh etc/ufw etc/default/ufw etc/default/grub etc/default/grub.d etc/sysctl.d \
         etc/docker etc/nginx etc/fail2ban etc/chrony etc/default/chrony etc/fstab; do
    if [[ -e "/$p" ]]; then cp -a --parents "/$p" "$BK/"; fi
done
printf '%s\n' "$BK" > "$STATE/latest-backup-path"
# Mark ownership only after all destructive-operation preconditions pass.
touch "$STATE/owned-installation"

stage 'Базовые инструменты из подписанного репозитория ОС'
cat > /etc/apt/apt.conf.d/99-vkarmani-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
Acquire::Retries "3";
DPkg::Lock::Timeout "300";
EOF
APT=(apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update
"${APT[@]}" install ca-certificates curl gnupg python3 python3-cryptography dnsutils jq iproute2 openssl
cat > "$LIB/node_helper.py" <<'PY_HELPER'
@@PYTHON_HELPER@@
PY_HELPER
chmod 0700 "$LIB/node_helper.py"
helper() { python3 "$LIB/node_helper.py" "$@"; }
# printf is a Bash builtin: SECRET_KEY is not passed as argv/env to an external process.
printf '%s\n%s\n%s\n' "$VK_INPUT_SECRET" "$VK_INPUT_PANEL_IPV4" "$VK_INPUT_DOMAIN" | helper init "$NODE_PORT_DEFAULT"
unset VK_INPUT_SECRET VK_INPUT_PANEL_IPV4 VK_INPUT_DOMAIN
DOMAIN=$(helper get domain)
PUBLIC_IP=$(helper get public_ipv4)
NODE_PORT=$(helper get node_port)
IMAGE=$(helper get image)
mapfile -t PANEL_IPS < <(helper get panel_ipv4)
mapfile -t SSH_PORTS < <({ /usr/sbin/sshd -T | awk '$1=="port"{print $2}';
    if [[ -n "${SSH_CONNECTION:-}" ]]; then awk '{print $4}' <<< "$SSH_CONNECTION"; fi
    if systemctl is-active --quiet ssh.socket; then
        systemctl show ssh.socket -p Listen --value | python3 -c 'import re,sys; print("\n".join(re.findall(r"(?:[:\s]|^)([0-9]+) \(Stream\)", sys.stdin.read())))'
    fi; } | sed '/^$/d' | sort -nu)
[[ ${#SSH_PORTS[@]} -gt 0 ]] || die 'Не удалось определить SSH-порт.'
for port in "${SSH_PORTS[@]}"; do
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || die 'Некорректный SSH-порт.'
    [[ "$port" != "$NODE_PORT" && "$port" != 80 && "$port" != 443 && "$port" != 8444 ]] || die 'SSH-порт конфликтует с портами ноды.'
done
printf '%s\n' "${SSH_PORTS[@]}" > "$ETC/ssh-ports"
if [[ ! -f "$STATE/image-digest" ]] && ss -H -lnt | awk '{print $4}' | _contains -E ":${NODE_PORT}$"; then
    die "Управляющий порт $NODE_PORT занят. Измените NODE_PORT_DEFAULT в начале установщика ДО первой установки."
fi
helper dns
# Direct public IPv4 only. NAT instances need separate forwarding support and are deliberately refused.
if ! ip -4 -o address show scope global | awk '{print $4}' | cut -d/ -f1 | _contains -Fx "$PUBLIC_IP"; then
    die 'Публичный IPv4 должен быть назначен интерфейсу этой VPS. NAT/проброс портов не поддержан.'
fi
stage 'Полное обновление пакетов ОС (без смены релиза дистрибутива)'
"${APT[@]}" -o APT::Get::Always-Include-Phased-Updates=true full-upgrade
"${APT[@]}" install openssh-server ufw fail2ban nginx certbot chrony logrotate unattended-upgrades \
    ethtool kmod util-linux procps dbus python3-systemd
# Update already-installed snaps, but do not install snapd merely for this installer.
if command -v snap >/dev/null && systemctl is-active --quiet snapd; then
    timeout 1800 snap refresh
fi

stage 'MSK, синхронизация времени и ограничение журналов'
timedatectl set-timezone Europe/Moscow
cat > /etc/chrony/chrony.conf <<'EOF'
pool time.cloudflare.com iburst maxsources 2
pool ntp.ubuntu.com iburst maxsources 2
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
leapsectz right/UTC
keyfile /etc/chrony/chrony.keys
logdir /var/log/chrony
cmdport 0
port 0
EOF
printf 'DAEMON_OPTS="-F 1 -4"\n' > /etc/default/chrony
# Both Debian and Ubuntu chrony units use DAEMON_OPTS (verified again locally below).
if ! systemctl cat chrony.service | _contains 'DAEMON_OPTS'; then
    die 'Неизвестный chrony unit: параметр DAEMON_OPTS не поддерживается.'
fi
chronyd -p -f /etc/chrony/chrony.conf >/dev/null
systemctl enable --now chrony
systemctl restart chrony
chronyc waitsync 60 0.1 0.0 2
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/90-vkarmani-limits.conf <<'EOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
MaxRetentionSec=14day
EOF
systemctl restart systemd-journald
cat > /etc/apt/apt.conf.d/90-vkarmani-security-updates <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

stage 'IPv4-only: ядро, GRUB, UFW, SSH; BBR + fq'
cat > /etc/sysctl.d/99-vkarmani-node.conf <<'EOF'
# Leading '-' makes these safe even when ipv6.disable=1 removes the IPv6 sysctls.
-net.ipv6.conf.all.disable_ipv6 = 1
-net.ipv6.conf.default.disable_ipv6 = 1
-net.ipv6.conf.lo.disable_ipv6 = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
vm.swappiness = 10
EOF
printf 'tcp_bbr\nsch_fq\n' > /etc/modules-load.d/vkarmani-node.conf
modprobe tcp_bbr
modprobe sch_fq
sysctl -p /etc/sysctl.d/99-vkarmani-node.conf
for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ ! -f "$f" ]] || printf '1\n' > "$f"
done
install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-vkarmani-ipv4.cfg <<'EOF'
# Applied to all regular/recovery kernel entries, not only GRUB_CMDLINE_LINUX_DEFAULT.
GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} ipv6.disable=1"
EOF
update-grub
_contains -E '^[[:space:]]*linux[^[:space:]]*[[:space:]].*ipv6.disable=1' /boot/grub/grub.cfg || die 'Параметр IPv6 не попал в grub.cfg.'
cat > /usr/local/sbin/vkarmani-node-network <<'EOF'
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
modprobe tcp_bbr
modprobe sch_fq
sysctl -p /etc/sysctl.d/99-vkarmani-node.conf >/dev/null
for attempt in $(seq 1 60); do
    if ip -4 route get 1.1.1.1 >/dev/null 2>&1; then break; fi
    sleep 2
done
IFACE=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[[ -n "$IFACE" && -d "/sys/class/net/$IFACE" ]]
tc qdisc replace dev "$IFACE" root fq
[[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == bbr ]]
tc qdisc show dev "$IFACE" | _contains -E 'qdisc fq '
EOF
chmod 0755 /usr/local/sbin/vkarmani-node-network
cat > /etc/systemd/system/vkarmani-node-network.service <<'EOF'
[Unit]
Description=VKarmani persistent IPv4-only BBR and fq
Wants=network-online.target
After=network-online.target
Before=vkarmani-node.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-network
TimeoutStartSec=180
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vkarmani-node-network
systemctl restart vkarmani-node-network

# Keep SSH authentication and keys unchanged. Convert socket activation to an IPv4
# ssh.service, whose KillMode=process preserves established SSH child sessions.
[[ "$(systemctl show ssh.service -p KillMode --value)" == process ]] || die 'SSH unit KillMode не process; безопасное переключение не подтверждено.'
AUTH_BEFORE=$(/usr/sbin/sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|kbdinteractiveauthentication) ')
NETBK="$STATE/network-backup"
install -d -m 0700 "$NETBK"
cp -a /etc/ssh/sshd_config "$NETBK/sshd_config"
cp -a /etc/ufw "$NETBK/"
cp -a /etc/default/ufw "$NETBK/default-ufw"
systemctl is-enabled ssh.socket > "$NETBK/socket-enabled" 2>/dev/null || true
systemctl is-active ssh.socket > "$NETBK/socket-active" 2>/dev/null || true
cat > /usr/local/sbin/vkarmani-network-rollback <<'EOF'
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
set -u
B=/var/lib/vkarmani-node/network-backup
[[ -e /var/lib/vkarmani-node/network-rollback-armed ]] || exit 0
# This narrowly rolls back only our SSH/UFW operation, never package upgrades or panel objects.
cp -a "$B/sshd_config" /etc/ssh/sshd_config
ufw --force disable || true
cp -a "$B/ufw/." /etc/ufw/
cp -a "$B/default-ufw" /etc/default/ufw
if _contains '^ENABLED=yes' /etc/ufw/ufw.conf; then ufw --force enable || true; fi
systemctl daemon-reload
if _contains -x enabled "$B/socket-enabled"; then systemctl enable ssh.socket || true; fi
if _contains -x active "$B/socket-active"; then
    systemctl stop ssh.service || true
    systemctl start ssh.socket || true
else
    systemctl restart ssh.service || true
fi
rm -f /var/lib/vkarmani-node/network-rollback-armed
EOF
chmod 0700 /usr/local/sbin/vkarmani-network-rollback
touch "$STATE/network-rollback-armed"
ROLLBACK_UNIT="vkarmani-network-rollback-$$"
systemd-run --collect --unit="$ROLLBACK_UNIT" --on-active=180s /usr/local/sbin/vkarmani-network-rollback
# First-value-wins: prepend only our single global directive, preserve the complete original file.
python3 - <<'PY'
from pathlib import Path
import re
p=Path('/etc/ssh/sshd_config')
s=p.read_text()
line='AddressFamily inet # VKarmani IPv4 only\n'
s=s.replace(line, '')
# Keep ports used only by previous ssh.socket configuration as well.
import subprocess
existing=set(re.findall(r'^port ([0-9]+)$', subprocess.check_output(['/usr/sbin/sshd','-T'],text=True),re.M))
ports=Path('/etc/vkarmani-node/ssh-ports').read_text().split()
# An implicit default port disappears when the first explicit Port is added.
if any(x not in existing for x in ports):
    extra=''.join('Port '+x+' # VKarmani preserved socket port\n' for x in ports)
else:
    extra=''
p.write_text(line+extra+s)
PY
/usr/sbin/sshd -t
AUTH_AFTER=$(/usr/sbin/sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|kbdinteractiveauthentication) ')
[[ "$AUTH_BEFORE" == "$AUTH_AFTER" ]] || die 'Параметры SSH-аутентификации неожиданно изменились.'
if systemctl is-active --quiet ssh.socket; then systemctl stop ssh.socket; fi
systemctl disable ssh.socket 2>/dev/null || true
systemctl enable ssh.service
systemctl restart ssh.service
# UFW is the only managed host firewall. Node uses host networking, never published bridge ports.
systemctl stop fail2ban
ufw --force reset
sed -i -E 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
for port in "${SSH_PORTS[@]}"; do ufw allow "$port/tcp" comment 'VKarmani SSH preserved'; done
ufw allow 80/tcp comment 'VKarmani ACME HTTP-01'
ufw allow 443/tcp comment 'VKarmani XHTTP REALITY'
for panel in "${PANEL_IPS[@]}"; do
    ufw allow proto tcp from "$panel" to any port "$NODE_PORT" comment 'VKarmani panel only'
done
ufw logging low
ufw --force enable
systemctl enable ufw
for port in "${SSH_PORTS[@]}"; do
    ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${port}$" || die "SSH IPv4:$port не слушает."
done
/usr/sbin/sshd -T | _contains -Fx 'addressfamily inet'
ufw status | _contains -F 'Status: active'
rm -f "$STATE/network-rollback-armed"
systemctl stop "$ROLLBACK_UNIT.timer"

stage 'Fail2ban для SSH (без принудительного включения root/password login)'
ADMIN_IP=$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")
if [[ -n "$ADMIN_IP" ]]; then
    python3 - "$ADMIN_IP" <<'PY'
import ipaddress,sys
ipaddress.IPv4Address(sys.argv[1])
PY
fi
SSH_PORT_LIST=$(IFS=,; echo "${SSH_PORTS[*]}")
cat > /etc/fail2ban/jail.d/99-vkarmani-sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $SSH_PORT_LIST
mode = normal
banaction = ufw
ignoreip = 127.0.0.1/8 $ADMIN_IP
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
bantime.maxtime = 24h
EOF
fail2ban-client -t
systemctl enable fail2ban
systemctl restart fail2ban

stage 'Swap при небольшой памяти'
if [[ $(helper get create_swap) == true && "$MEM_MB" -lt 2048 ]]; then
    if [[ -z "$(swapon --show --noheadings)" ]]; then
        FS_TYPE=$(findmnt -n -o FSTYPE /)
        [[ "$FS_TYPE" == ext4 || "$FS_TYPE" == xfs ]] || die 'Авто-swap поддержан только на ext4/xfs. Отключите create_swap для другой ФС.'
        if [[ ! -f /swapfile-vkarmani ]]; then
            dd if=/dev/zero of=/swapfile-vkarmani bs=1M count=1024 status=none
            chmod 0600 /swapfile-vkarmani
            mkswap /swapfile-vkarmani
        fi
        swapon /swapfile-vkarmani
        _contains -F '/swapfile-vkarmani ' /etc/fstab || printf '/swapfile-vkarmani none swap sw 0 0\n' >> /etc/fstab
    fi
fi

stage 'Официальный Docker Engine и Compose plugin'
for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | _contains -F 'ok installed'; then
        die "Установлен конфликтующий пакет $package. Не удаляю его автоматически вместе с чужими данными."
    fi
done
install -d -m 0755 /etc/apt/keyrings
curl -4 --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --retry 3 \
    "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker-vkarmani.asc
# Validate the official Docker CE signing-key fingerprint before trusting the repository.
gpg --show-keys --with-colons /etc/apt/keyrings/docker-vkarmani.asc | \
    awk -F: '$1=="fpr"{print $10}' | _contains -Fx '9DC858229FC7DD38854AE2D88D81803C0EBFCD88' || die 'Неожиданный fingerprint ключа Docker.'
chmod 0644 /etc/apt/keyrings/docker-vkarmani.asc
cat > /etc/apt/sources.list.d/docker-vkarmani.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$OS_ID
Suites: $OS_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker-vkarmani.asc
EOF
apt-get update
"${APT[@]}" install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
helper docker-config
dockerd --validate --config-file=/etc/docker/daemon.json
systemctl enable docker.service containerd.service
systemctl restart docker
[[ $(docker network inspect bridge --format '{{.EnableIPv6}}') == false ]] || die 'Docker bridge IPv6 включён.'

stage 'Nginx HTTP-01 + локальный TLS-сайт для REALITY'
install -d -m 0755 /var/www/vkarmani-node/acme /var/www/vkarmani-node/site
cat > /var/www/vkarmani-node/site/index.html <<'HTML'
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title><body><main><h1>Welcome</h1><p>This site is available.</p></main></body></html>
HTML
chmod 0644 /var/www/vkarmani-node/site/index.html
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/10-vkarmani-http.conf <<EOF
server {
    listen 0.0.0.0:80;
    server_name $DOMAIN;
    server_tokens off;
    access_log off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/vkarmani-node/acme;
        default_type text/plain;
        try_files \$uri =404;
    }
    location = /__vkarmani_health { return 204; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOF
# On a resumed installation retain the working TLS cover; never temporarily delete it.
nginx -t
systemctl enable nginx
systemctl restart nginx
[[ $(curl --noproxy '*' -4fsS --max-time 10 -o /dev/null -w '%{http_code}' \
    --resolve "$DOMAIN:80:127.0.0.1" "http://$DOMAIN/__vkarmani_health") == 204 ]] || die 'Nginx HTTP health check failed.'
certbot certonly --webroot --webroot-path /var/www/vkarmani-node/acme \
    --domain "$DOMAIN" --cert-name "$DOMAIN" --register-unsafely-without-email \
    --agree-tos --non-interactive --keep-until-expiring --key-type ecdsa --preferred-challenges http
cat > /etc/nginx/conf.d/20-vkarmani-reality-cover.conf <<EOF
server {
    listen 127.0.0.1:8444 ssl http2;
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:VKARMANI:2m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    root /var/www/vkarmani-node/site;
    index index.html;
    access_log off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    keepalive_timeout 30s;
    location = /__vkarmani_health { return 204; }
    location / { try_files \$uri \$uri/ =404; }
}
EOF
nginx -t
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx <<'EOF'
#!/bin/sh
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx
systemctl enable --now certbot.timer
if [[ $(helper get certbot_dry_run) == true && ! -f "$STATE/certbot-dry-run-pass" ]]; then
    certbot renew --cert-name "$DOMAIN" --dry-run --non-interactive
    touch "$STATE/certbot-dry-run-pass"
fi

stage 'RemnaNode: проверка введённого SECRET_KEY, образ по digest, автозапуск'
helper secret
if [[ ! -s "$STATE/image-digest" || $REFRESH_IMAGE -eq 1 ]]; then
    docker pull "$IMAGE"
    DIGEST=$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}')
    [[ "$DIGEST" =~ ^(remnawave/node|ghcr.io/remnawave/node)@sha256:[a-f0-9]{64}$ ]] || die 'Не удалось зафиксировать официальный образ по digest.'
    if [[ -s "$STATE/image-digest" && -f "$OPT/compose.yaml" && "$DIGEST" != "$(cat "$STATE/image-digest")" ]]; then
        cp -a "$STATE/image-digest" "$STATE/image-digest.previous"
        cp -a "$OPT/compose.yaml" "$STATE/compose.previous.yaml"
        # Keep one rollback image tagged so a concurrent dangling-image cleanup cannot remove it.
        docker tag "$(cat "$STATE/image-digest")" remnawave/node:vkarmani-rollback
        touch "$STATE/image-update-pending"
    fi
    printf '%s\n' "$DIGEST" > "$STATE/image-digest"
fi
DIGEST=$(cat "$STATE/image-digest")
cat > "$OPT/compose.yaml" <<EOF
name: vkarmani-node
services:
  remnanode:
    image: $DIGEST
    container_name: remnanode
    hostname: remnanode
    network_mode: host
    restart: always
    stop_grace_period: 30s
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    env_file:
      - $ETC/remnanode.env
    logging:
      driver: local
      options:
        max-size: "10m"
        max-file: "3"
EOF
# Compose config can expand secrets; never print its output.
docker compose -f "$OPT/compose.yaml" config --quiet
cat > /etc/systemd/system/vkarmani-node.service <<'EOF'
[Unit]
Description=VKarmani RemnaNode Compose stack
Requires=docker.service
Wants=network-online.target nginx.service vkarmani-node-network.service ufw.service
After=network-online.target docker.service nginx.service vkarmani-node-network.service ufw.service
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/vkarmani-node
ExecStart=/usr/bin/docker compose -f /opt/vkarmani-node/compose.yaml up -d --remove-orphans
ExecStop=/usr/bin/docker compose -f /opt/vkarmani-node/compose.yaml stop
TimeoutStartSec=180
TimeoutStopSec=90
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vkarmani-node
# Explicit up also reconciles a resumed run when the oneshot unit already says active.
docker compose -f "$OPT/compose.yaml" up -d --remove-orphans
systemctl start vkarmani-node
for attempt in $(seq 1 60); do
    if helper control-ready >/dev/null 2>&1; then break; fi
    sleep 2
 done
helper control-ready
[[ $(docker inspect remnanode --format '{{.State.Running}}') == true ]] || die 'RemnaNode не запущен.'
helper keys
CORE=$(docker exec remnanode sh -c 'command -v rw-core || command -v xray')
[[ "$CORE" == /* && "$CORE" != *$'\n'* ]] || die 'Xray/rw-core не найден в официальном образе.'
# Validate the generated IMPORT template with the bundled Xray; do not inject it as live config.
docker cp "$ETC/profile.json" remnanode:/tmp/vkarmani-profile-test.json >/dev/null
if ! docker exec remnanode "$CORE" run -test -config /tmp/vkarmani-profile-test.json > "$STATE/xray-config-test.log" 2>&1; then
    docker exec remnanode rm -f /tmp/vkarmani-profile-test.json || true
    die "Xray отклонил конфиг. Закрытый журнал: $STATE/xray-config-test.log"
fi
docker exec remnanode rm -f /tmp/vkarmani-profile-test.json

stage 'Профиль и параметры для панели (без API-токена, без изменения панели)'
helper panel-guide
printf 'Профиль: /etc/vkarmani-node/profile.json\nИнструкция: /etc/vkarmani-node/PANEL-SETUP.txt\n'
printf 'Карточка ноды и назначение профиля выполняются в панели. Секрет не является API-токеном.\n' 

stage 'Еженедельный reboot в понедельник 04:00 Europe/Moscow'
cat > /etc/systemd/system/vkarmani-weekly-reboot.service <<'EOF'
[Unit]
Description=VKarmani scheduled Monday 04:00 Moscow reboot
ConditionPathExists=/etc/vkarmani-node/weekly-reboot-enabled
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reboot
EOF
cat > /etc/systemd/system/vkarmani-weekly-reboot.timer <<'EOF'
[Unit]
Description=VKarmani reboot every Monday at 04:00 Europe/Moscow
[Timer]
OnCalendar=Mon *-*-* 04:00:00 Europe/Moscow
AccuracySec=1s
RandomizedDelaySec=0
Persistent=false
Unit=vkarmani-weekly-reboot.service
[Install]
WantedBy=timers.target
EOF
touch "$ETC/weekly-reboot-enabled"
cat > /usr/local/sbin/vkarmani-node-cleanup <<'EOF'
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
exec 8>/run/lock/vkarmani-node-cleanup.lock
flock -n 8 || exit 0
# Only apt cache, unneeded distro packages, archived journal retention and
# aged untagged Docker images. Never delete volumes, containers or all /tmp.
apt-get -y -o DPkg::Lock::Timeout=300 autoremove --purge
apt-get clean
journalctl --rotate
journalctl --vacuum-time=14d --vacuum-size=200M
if command -v docker >/dev/null && systemctl is-active --quiet docker; then
    docker image prune -f --filter dangling=true --filter until=168h
fi
EOF
chmod 0755 /usr/local/sbin/vkarmani-node-cleanup
cat > /etc/systemd/system/vkarmani-node-cleanup.service <<'EOF'
[Unit]
Description=VKarmani bounded cache and old journal cleanup
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-cleanup
TimeoutStartSec=900
EOF
cat > /etc/systemd/system/vkarmani-node-cleanup.timer <<'EOF'
[Unit]
Description=VKarmani weekly safe cleanup
[Timer]
OnCalendar=Sun *-*-* 03:10:00 Europe/Moscow
Persistent=false
[Install]
WantedBy=timers.target
EOF
cat > /etc/logrotate.d/vkarmani-node <<'EOF'
/var/log/vkarmani-node-install.log /var/log/vkarmani-node-postboot.log {
    weekly
    rotate 4
    maxsize 10M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su root root
}
EOF

stage 'Контроль после перезагрузки и диагностическая команда'
cat > /usr/local/sbin/vkarmani-node-check <<'CHECK'
@@HEALTH_SCRIPT@@
CHECK
chmod 0755 /usr/local/sbin/vkarmani-node-check
cat > /etc/systemd/system/vkarmani-node-postboot.service <<'EOF'
[Unit]
Description=VKarmani node post-boot acceptance
Wants=network-online.target vkarmani-node.service nginx.service chrony.service fail2ban.service
After=network-online.target vkarmani-node.service nginx.service chrony.service fail2ban.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-check --postboot
TimeoutStartSec=720
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vkarmani-node-postboot
systemctl enable --now vkarmani-weekly-reboot.timer vkarmani-node-cleanup.timer

stage 'Финальная очистка и проверка обновлений'
/usr/local/sbin/vkarmani-node-cleanup
"${APT[@]}" -o APT::Get::Always-Include-Phased-Updates=true full-upgrade
apt-get clean
# Do not label held/phased/pinned candidate updates as fully installed.
if apt-get -s -o APT::Get::Always-Include-Phased-Updates=true dist-upgrade | _contains '^Inst '; then
    die 'Остались доступные обновления. Ребут не запланирован; проверьте apt.'
fi
/usr/local/sbin/vkarmani-node-check --preboot
printf 'version=%s\nat=%s\nimage=%s\n' "$VERSION" "$(date -Is)" "$DIGEST" > "$STATE/INSTALL_COMPLETE"
rm -f "$STATE/INSTALL_FAILED" "$STATE/image-update-pending"
stage 'Установка завершена; проверки ДО перезагрузки пройдены'
printf 'Домен: %s\nIPv4: %s\nУправляющий порт: %s (только IP панели)\n' "$DOMAIN" "$PUBLIC_IP" "$NODE_PORT"
printf 'Разрешённые IPv4 панели: %s\n' "${PANEL_IPS[*]}"
printf 'Профиль и действия в панели: /etc/vkarmani-node/PANEL-SETUP.txt\n'
printf 'SSH-порты сохранены: %s\n' "${SSH_PORTS[*]}"
printf 'Проверка после входа: sudo vkarmani-node-check\nЖурнал: /var/log/vkarmani-node-postboot.log\n'
printf 'Резервная копия: %s\nПолное отключение IPv6 проверяется ПОСЛЕ загрузки нового ядра.\n' "$BK"
systemctl list-timers --no-pager vkarmani-weekly-reboot.timer
if [[ $NO_REBOOT -eq 0 && $(helper get auto_reboot) == true ]]; then
    # Scheduled by systemd rather than a background shell; survives SSH closure.
    systemd-run --collect --unit="vkarmani-install-reboot-$(date +%s)" --on-active=15s /usr/bin/systemctl reboot
    echo 'AUTO_REBOOT=ARMED. SSH отключится; после загрузки все настроенные службы запустятся автоматически.'
    sync
else
    echo 'REBOOT_REQUIRED: автоматический reboot отключён параметром. Выполните sudo reboot.'
fi

}
# VKARMANI_COMPLETE_PAYLOAD_1_2_0
vkarmani_main "$@"
