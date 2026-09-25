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
# Three inputs before any APT/network/boot changes. No Python/curl dependency here.
# This file is embedded in install.sh, not downloaded at run time.
vk_input_error() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
vk_trim() {
    local value=$1
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}
vk_validate_ipv4() {
    local value=$1 octet
    local -a parts=()
    [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for octet in "${parts[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    # Early reject of local/reserved addresses. Python revalidates is_global after APT.
    ((parts[0] > 0 && parts[0] < 224)) || return 1
    case "$value" in
        10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.0.2.*|198.51.100.*|203.0.113.*) return 1 ;;
    esac
    if ((parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31)); then return 1; fi
    if ((parts[0] == 100 && parts[1] >= 64 && parts[1] <= 127)); then return 1; fi
    if ((parts[0] == 198 && (parts[1] == 18 || parts[1] == 19))); then return 1; fi
}
vk_validate_domain() {
    local value=$1 part
    local -a parts=()
    [[ ${#value} -le 253 && "$value" == *.* && "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
    [[ ! "$value" =~ ^[0-9.]+$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for part in "${parts[@]}"; do
        [[ ${#part} -ge 1 && ${#part} -le 63 && "$part" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}
vk_restore_tty() {
    if [[ -n "${VK_TTY_STATE:-}" && -n "${VK_TTY_FD:-}" ]]; then
        stty "$VK_TTY_STATE" <&"$VK_TTY_FD" 2>/dev/null || true
        VK_TTY_STATE=''
    fi
}
vk_collect_inputs() {
    # Never inherit exported attributes or tracing for a credential variable.
    set +x
    set +a
    unset VK_INPUT_SECRET VK_INPUT_PANEL_IPV4 VK_INPUT_DOMAIN
    VK_INPUT_SECRET='' VK_INPUT_PANEL_IPV4='' VK_INPUT_DOMAIN=''
    if [[ -s "$ETC/config.json" ]]; then
        printf 'Повторный запуск: используются сохранённые параметры; вопросов нет.\n'
        return 0
    fi
    command -v stty >/dev/null || { vk_input_error 'Требуется stty (coreutils).'; return 1; }
    exec {VK_TTY_FD}<>/dev/tty || { vk_input_error 'Нужен интерактивный SSH-терминал (при ssh-команде используйте ssh -t).'; return 1; }
    VK_TTY_STATE=$(stty -g <&"$VK_TTY_FD") || return 1
    trap 'vk_restore_tty' EXIT
    trap 'vk_restore_tty; exit 130' INT
    trap 'vk_restore_tty; exit 143' TERM
    trap 'vk_restore_tty; exit 129' HUP
    printf '\nVKarmani: SECRET_KEY → IPv4 основного сервера → домен ноды.\n' >&"$VK_TTY_FD"
    printf 'После трёх значений — автоматическая установка и reboot. Нужны снимок VPS и консоль хостера.\n' >&"$VK_TTY_FD"
    printf 'Будут изменены firewall/загрузка, отключён IPv6; условия Let\047s Encrypt принимаются автоматически.\n' >&"$VK_TTY_FD"
    printf 'IPv4 основного сервера — исходящий адрес backend панели, НЕ Cloudflare и НЕ IP этой ноды.\n\n' >&"$VK_TTY_FD"
    # Noncanonical mode also permits long (>4096 byte) single-line SECRET_KEY bundles.
    # Disable echo BEFORE displaying the prompt, so immediate paste cannot reveal the key.
    stty -echo -icanon min 1 time 0 <&"$VK_TTY_FD"
    printf '[1/3] SECRET_KEY ноды (скрытый ввод): ' >&"$VK_TTY_FD"
    if ! IFS= read -r -u "$VK_TTY_FD" VK_INPUT_SECRET; then
        vk_restore_tty; vk_input_error 'Ввод SECRET_KEY прерван.'; return 1
    fi
    vk_restore_tty
    printf '\n' >&"$VK_TTY_FD"
    VK_INPUT_SECRET=$(vk_trim "$VK_INPUT_SECRET")
    if [[ "$VK_INPUT_SECRET" == SECRET_KEY=* ]]; then VK_INPUT_SECRET=${VK_INPUT_SECRET#SECRET_KEY=}; fi
    if [[ "$VK_INPUT_SECRET" == \"*\" || "$VK_INPUT_SECRET" == \'*\' ]]; then
        VK_INPUT_SECRET=${VK_INPUT_SECRET:1:${#VK_INPUT_SECRET}-2}
    fi
    [[ ${#VK_INPUT_SECRET} -ge 64 && ${#VK_INPUT_SECRET} -le 65536 && "$VK_INPUT_SECRET" =~ ^[A-Za-z0-9_+/=-]+$ ]] || {
        unset VK_INPUT_SECRET; vk_input_error 'Некорректный формат SECRET_KEY. Вставьте значение из панели одной строкой.'; return 1;
    }
    printf '[2/3] Публичный IPv4 основного сервера (панели): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_PANEL_IPV4 || { vk_input_error 'Ввод IPv4 прерван.'; return 1; }
    VK_INPUT_PANEL_IPV4=$(vk_trim "$VK_INPUT_PANEL_IPV4")
    vk_validate_ipv4 "$VK_INPUT_PANEL_IPV4" || { vk_input_error 'Нужен публичный IPv4 панели, без порта, CIDR и https://.'; return 1; }
    printf '[3/3] Домен ноды (например, ee1.example.com): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_DOMAIN || { vk_input_error 'Ввод домена прерван.'; return 1; }
    VK_INPUT_DOMAIN=$(vk_trim "$VK_INPUT_DOMAIN")
    VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN,,}; VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN%.}
    vk_validate_domain "$VK_INPUT_DOMAIN" || { vk_input_error 'Некорректный домен: без https://, порта и пути; IDN в punycode.'; return 1; }
    exec {VK_TTY_FD}>&-
    unset VK_TTY_FD
    trap - EXIT INT TERM HUP
    printf '\nВсе три значения приняты. Далее вопросов нет; SECRET_KEY не выводится.\n'
}
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
#!/usr/bin/env python3
"""VKarmani 1.2.0: node-only installer. No panel API, credentials or POST requests.
Three inputs are collected by Bash before APT and passed via stdin. Python 3.10+.
"""
import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
MODE = 'secret-key-only'
class Failure(Exception):
    pass

def read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (ValueError, OSError) as e:
        raise Failure('Не удалось прочитать JSON: ' + str(path)) from e


def atomic_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink()


def domain(value):
    if not isinstance(value, str):
        raise Failure('Домен должен быть строкой.')
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value:
        raise Failure('Нужен полный DNS-домен, без https:// и пути.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
           for p in value.split('.')):
        raise Failure('Некорректный домен. IDN укажите в punycode.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Failure('Вместо IP нужен DNS-домен.')


def public_ipv4(value):
    try:
        ip = ipaddress.IPv4Address(value)
        if not isinstance(value, str) or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError()
        return str(ip)
    except (ValueError, TypeError) as e:
        raise Failure('Нужен глобальный публичный IPv4-адрес, не CIDR.') from e


def dns_check(c):
    for server in (None, '1.1.1.1', '8.8.8.8'):
        answers = {}
        for kind in ('A', 'AAAA'):
            cmd = ['dig', '-4', '+time=4', '+tries=2', '+noall', '+comments', '+answer']
            if server:
                cmd.append('@' + server)
            cmd += [c['domain'], kind]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.returncode or not re.search(r'status: NOERROR[, ]', r.stdout):
                raise Failure('DNS-запрос не выполнен: ' + (server or 'system resolver'))
            answers[kind] = {line.split()[-1] for line in r.stdout.splitlines()
                             if len(line.split()) >= 5 and line.split()[-2] == kind}
        if answers['A'] != {c['public_ipv4']} or answers['AAAA']:
            raise Failure('DNS: требуется ровно один A на IPv4 ноды и отсутствие AAAA. Проверьте DNS-only, без CDN proxy; resolver=' + (server or 'system'))
    print('DNS: A подтверждён тремя резолверами, AAAA отсутствует.')


def make_keys_profile(c):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    path = ETC / 'reality.json'
    if path.exists():
        keys = read_json(path)
    else:
        key = X25519PrivateKey.generate()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        keys = {'private_key': enc(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                'public_key': enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                'short_id': secrets.token_hex(8), 'xhttp_path': '/' + secrets.token_hex(16) + '/'}
        atomic_json(path, keys)
    suffix = hashlib.sha256(c['domain'].encode()).hexdigest()[:12]
    tag = 'VK_XHTTP_' + suffix.upper()
    # No Vision flow on XHTTP. Clients are filled by Remnawave, never hard-coded here.
    profile = {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': ['1.1.1.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [{'tag': tag, 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                      'settings': {'clients': [], 'decryption': 'none'},
                      'sniffing': {'enabled': True, 'routeOnly': True, 'destOverride': ['http', 'tls']},
                      'streamSettings': {
                          'network': 'xhttp', 'security': 'reality',
                          'xhttpSettings': {'path': keys['xhttp_path'], 'mode': 'auto'},
                          'realitySettings': {'show': False, 'target': '127.0.0.1:8444', 'xver': 0,
                                              'serverNames': [c['domain']], 'privateKey': keys['private_key'],
                                              'shortIds': [keys['short_id']]}}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                      {'tag': 'BLOCK', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
            {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                                    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
                                    '224.0.0.0/4', '240.0.0.0/4', c['public_ipv4'] + '/32', '::/0'],
             'outboundTag': 'BLOCK'}]}}
    atomic_json(ETC / 'profile.json', profile)
    return 'VK-' + suffix, tag, profile


def docker_config():
    p = Path('/etc/docker/daemon.json')
    cfg = read_json(p) if p.exists() else {}
    if not isinstance(cfg, dict):
        raise Failure('daemon.json не является объектом.')
    cfg.update({'ipv6': False, 'ip6tables': False, 'live-restore': True,
                'log-driver': 'local', 'log-opts': {'max-size': '10m', 'max-file': '3'}})
    atomic_json(p, cfg)
    os.chmod(p, 0o644)


def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
    finally:
        if temp.exists():
            temp.unlink()


def normalize_config(raw):
    if not isinstance(raw, dict) or raw.get('installation_mode') != MODE:
        raise Failure('Нужна конфигурация secret-key-only. API-установка не мигрируется.')
    allowed = {'installation_mode', 'domain', 'public_ipv4', 'node_port', 'panel_ipv4',
               'image', 'auto_reboot', 'certbot_dry_run', 'create_swap'}
    if set(raw) - allowed:
        raise Failure('Неизвестные поля конфигурации. API-параметры здесь не используются.')
    c = dict(raw)
    c['domain'] = domain(c.get('domain'))
    c['public_ipv4'] = public_ipv4(c.get('public_ipv4'))
    ips = c.get('panel_ipv4')
    if not isinstance(ips, list) or not 1 <= len(ips) <= 16:
        raise Failure('panel_ipv4: от 1 до 16 публичных IPv4 панели, без CIDR.')
    c['panel_ipv4'] = sorted({public_ipv4(x) for x in ips})
    port = c.get('node_port', 2222)
    if type(port) is not int or not 1024 <= port <= 65535 or port == 8444:
        raise Failure('node_port: целое 1024–65535, кроме 8444 и SSH-порта.')
    c['node_port'] = port
    image = c.get('image', 'remnawave/node:latest')
    if not isinstance(image, str) or not re.fullmatch(
        r'(?:remnawave/node|ghcr\.io/remnawave/node)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?', image):
        raise Failure('Допускается только официальный образ Remnawave Node.')
    c['image'] = image
    for name in ('auto_reboot', 'certbot_dry_run', 'create_swap'):
        value = c.get(name, True)
        if type(value) is not bool:
            raise Failure(name + ': требуется JSON true/false.')
        c[name] = value
    return c


def detect_public_ipv4():
    try:
        r = subprocess.run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'],
                           capture_output=True, text=True, timeout=10, check=True)
        routes = json.loads(r.stdout)
        # ip route get performs a kernel route lookup, not a request to 1.1.1.1.
        value = routes[0].get('prefsrc') or routes[0].get('src')
        return public_ipv4(value)
    except (subprocess.SubprocessError, ValueError, IndexError, KeyError, TypeError, Failure) as e:
        raise Failure('Не определён прямой публичный IPv4. NAT/IPv6-only VPS не поддерживаются.') from e


def normalize_pem(value):
    value = value.replace('\\n', '\n').replace('\r\n', '\n')
    value = re.sub(r'(-----BEGIN [A-Z ]+-----)', r'\1\n', value)
    value = re.sub(r'(-----END [A-Z ]+-----)', r'\n\1', value)
    return re.sub(r'\n+', '\n', value).strip() + '\n'


def normalize_secret(value, check_dates=False):
    """Validate the actual mTLS/JWT bundle, not an arbitrary 16-char password.
    No key, PEM, invalid input, or third-party exception text is put in errors.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, padding
    if not isinstance(value, str):
        raise Failure('SECRET_KEY должен быть строкой.')
    value = value.strip()
    if value.startswith('SECRET_KEY='):
        value = value[len('SECRET_KEY='):].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not re.fullmatch(r'[A-Za-z0-9+/_-]{32,50000}={0,2}', value):
        raise Failure('Некорректный формат SECRET_KEY: вставьте значение из панели одной строкой.')
    try:
        payload = json.loads(base64.b64decode(value + '=' * (-len(value) % 4),
                                             altchars=b'-_', validate=True))
        fields = ('nodeCertPem', 'nodeKeyPem', 'caCertPem', 'jwtPublicKey')
        if not isinstance(payload, dict) or any(not isinstance(payload.get(k), str) for k in fields):
            raise ValueError()
        pem = {k: normalize_pem(payload[k]).encode('ascii') for k in fields}
        cert = x509.load_pem_x509_certificate(pem['nodeCertPem'])
        ca = x509.load_pem_x509_certificate(pem['caCertPem'])
        key = ser.load_pem_private_key(pem['nodeKeyPem'], password=None)
        ser.load_pem_public_key(pem['jwtPublicKey'])
        encode_public = lambda k: k.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        if encode_public(cert.public_key()) != encode_public(key.public_key()):
            raise ValueError()
        if cert.issuer != ca.subject or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError()
        ca_key = ca.public_key()
        if isinstance(ca_key, ec.EllipticCurvePublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(ca_key, rsa.RSAPublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(ca_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            raise ValueError()
    except Exception as e:
        raise Failure('SECRET_KEY не прошёл проверку mTLS/JWT, сертификата или пары ключей. Возьмите новый из панели.') from e
    if check_dates:
        now = dt.datetime.now(dt.timezone.utc)
        for item in (cert, ca):
            if hasattr(item, 'not_valid_before_utc'):
                start, end = item.not_valid_before_utc, item.not_valid_after_utc
            else:
                start = item.not_valid_before.replace(tzinfo=dt.timezone.utc)
                end = item.not_valid_after.replace(tzinfo=dt.timezone.utc)
            if not start <= now <= end:
                raise Failure('Сертификат внутри SECRET_KEY ещё не действителен или истёк. Проверьте время и возьмите новый ключ.')
    return value


def check_secret(c, check_dates=True):
    path = ETC / 'remnanode.env'
    try:
        if path.stat().st_mode & 0o077:
            raise Failure('remnanode.env должен иметь права 0600.')
        lines = path.read_text(encoding='ascii').splitlines()
        if len(lines) != 3 or lines[0] != f'NODE_PORT={c["node_port"]}' or lines[2] != 'TZ=Europe/Moscow':
            raise Failure('remnanode.env не соответствует сохранённой конфигурации.')
        if not lines[1].startswith('SECRET_KEY='):
            raise Failure('В remnanode.env отсутствует SECRET_KEY.')
        normalize_secret(lines[1][len('SECRET_KEY='):], check_dates)
    except OSError as e:
        raise Failure('Не удалось прочитать сохранённый SECRET_KEY. Файл: /etc/vkarmani-node/remnanode.env') from e


def init_config(node_port='2222', inputs=None):
    """No prompts here. Bash collects all inputs before dependency installation.

    Fresh install: stdin consists of SECRET_KEY, panel IPv4, domain, each on one line.
    Resume: the persisted root-only configuration wins, and stdin is not consumed.
    """
    if (ETC / 'config.json').exists():
        c = normalize_config(read_json(ETC / 'config.json'))
        if detect_public_ipv4() != c['public_ipv4']:
            raise Failure('IPv4 сервера изменился. Не меняю адрес и ключи существующей установки автоматически.')
        check_secret(c, check_dates=False)
        print('Продолжение установки: домен, IPv4 панели и SECRET_KEY взяты из файлов root.')
        return
    if not re.fullmatch(r'[0-9]{4,5}', node_port):
        raise Failure('Некорректный NODE_PORT_DEFAULT.')
    if inputs is None:
        # Bound untrusted input without echoing it in exceptions.
        text = sys.stdin.read(70001)
        if len(text) > 70000:
            raise Failure('Слишком большой блок входных данных.')
        inputs = text.splitlines()
    if not isinstance(inputs, (tuple, list)) or len(inputs) != 3:
        raise Failure('Нужны три заранее введённых значения: SECRET_KEY, IPv4 панели, домен.')
    secret = normalize_secret(inputs[0])
    panel_ip = public_ipv4(inputs[1])
    name = domain(inputs[2])
    detected = detect_public_ipv4()
    if panel_ip == detected:
        raise Failure('IPv4 панели совпадает с IPv4 этой ноды. Нужен отдельный сервер ноды и исходящий IPv4 панели.')
    c = normalize_config({'installation_mode': MODE, 'domain': name, 'public_ipv4': detected,
                          'panel_ipv4': [panel_ip], 'node_port': int(node_port)})
    # Validate DNS before committing inputs. A typo can be corrected simply by rerunning.
    dns_check(c)
    # Secret first, config last: a crash cannot commit usable config without its key.
    atomic_text(ETC / 'remnanode.env', f'NODE_PORT={c["node_port"]}\nSECRET_KEY={secret}\nTZ=Europe/Moscow\n')
    atomic_json(ETC / 'config.json', c)
    print('Параметры проверены. SECRET_KEY сохранён с правами 0600, без вывода в журнал.')


def write_panel_guide(c):
    name, tag, _ = make_keys_profile(c)
    keys = read_json(ETC / 'reality.json')
    txt = f'''VKarmani RemnaNode 1.2.0 — действия в панели

Сервер: {c['domain']} / {c['public_ipv4']}
Разрешённый исходящий IPv4 панели: {', '.join(c['panel_ipv4'])}
Управляющий порт NODE_PORT: {c['node_port']} / TCP (НЕ клиентский порт!)

1. Config Profiles: создайте профиль {name} и вставьте JSON из
   /etc/vkarmani-node/profile.json
   Этот файл содержит приватный REALITY-ключ: не публикуйте его.
2. Nodes -> Management: создайте/отредактируйте карточку ЭТОЙ ноды:
   адрес {c['public_ipv4']}, Node Port {c['node_port']}.
   Используйте ту же панель, из которой взят введённый SECRET_KEY.
   Выберите профиль {name} и включите inbound {tag}.
3. Hosts: выберите этот профиль/inbound; Address={c['domain']}, Port=443.
   Security=DEFAULT (из профиля), SNI={c['domain']}, Fingerprint=chrome.
   Не задавайте Vision flow. XHTTP path берётся из профиля; при ручном
   переопределении Path должен быть {keys['xhttp_path']}.
4. Internal Squads: разрешите inbound {tag} группе своих пользователей.
   Обновите подписку в клиенте и проверьте соединение извне.

Транспорт шаблона: VLESS + XHTTP + REALITY, xhttp mode=auto.
REALITY target: 127.0.0.1:8444; xver=0; serverName={c['domain']}.
REALITY publicKey: {keys['public_key']}
ShortID: {keys['short_id']}

Скрипт НЕ авторизуется в панели, НЕ создаёт и НЕ меняет её объекты.
Локальный profile.json — шаблон для импорта, НЕ live-конфиг ноды.
Если у вас уже назначен готовый профиль, он не перезаписывается.
При использовании своего профиля согласуйте SNI/target и порт 443
с этим Nginx; приватные ключи и параметры берите из своего профиля.
До получения профиля от панели отсутствие Xray TCP/443 ожидаемо:
NODE_SETUP=PASS может сочетаться с VPN_STATUS=WAITING_FOR_PANEL_PROFILE.
TCP/2222 сам по себе не доказывает связь с панелью и работу VPN.

Проверка: sudo vkarmani-node-check
Строгая локальная проверка Xray/cover: sudo vkarmani-node-check --require-xray
Лог после reboot: /var/log/vkarmani-node-postboot.log
'''
    atomic_text(ETC / 'PANEL-SETUP.txt', txt)


def control_ready(c):
    try:
        with socket.create_connection(('127.0.0.1', c['node_port']), timeout=3):
            pass
    except OSError as e:
        raise Failure('Управляющий IPv4-порт RemnaNode ещё не слушает. Проверьте контейнер и SECRET_KEY.') from e


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'get', 'dns', 'keys', 'secret', 'docker-config', 'panel-guide', 'control-ready'])
    parser.add_argument('arg', nargs='?')
    args = parser.parse_args()
    if args.action == 'init':
        init_config(args.arg or '2222')
        return
    if args.action == 'docker-config':
        docker_config()
        return
    c = normalize_config(read_json(ETC / 'config.json'))
    if args.action == 'get':
        if args.arg not in c:
            raise Failure('Поле конфигурации не найдено.')
        v = c[args.arg]
        print('\n'.join(str(x) for x in v) if isinstance(v, list) else
              ('true' if v else 'false') if isinstance(v, bool) else v)
    elif args.action == 'dns':
        dns_check(c)
    elif args.action == 'keys':
        make_keys_profile(c)
    elif args.action == 'secret':
        check_secret(c)
        print('SECRET_KEY_VALID=PASS')
    elif args.action == 'panel-guide':
        write_panel_guide(c)
    elif args.action == 'control-ready':
        control_ready(c)
        print('NODE_CONTROL_IPV4=PASS')


if __name__ == '__main__':
    try:
        main()
    except Failure as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('Ввод прерван.', file=sys.stderr)
        sys.exit(130)
    except Exception:
        print('ERROR: ошибка чтения/проверки данных. Секретные значения не выведены.', file=sys.stderr)
        sys.exit(1)
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
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
# Read-only acceptance except for timestamped result/log files.
set -uo pipefail
set +x
umask 077
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID -eq 0 ]] || { echo 'Run as root: sudo vkarmani-node-check'; exit 1; }
MODE=${1:---normal}
case "$MODE" in --normal|--preboot|--postboot|--local|--require-xray) ;; *) echo 'Usage: vkarmani-node-check [--local|--preboot|--postboot|--require-xray]'; exit 2 ;; esac
ETC=/etc/vkarmani-node
STATE=/var/lib/vkarmani-node
HELPER=/usr/local/lib/vkarmani-node/node_helper.py
F=0
XRAY_PRESENT=0
XRAY_COVER_OK=0
pass(){ printf '%-33s PASS\n' "$1"; }
fail(){ printf '%-33s FAIL %s\n' "$1" "${2:-}"; F=1; }
warn(){ printf '%-33s NOTE %s\n' "$1" "${2:-}"; }
helper(){ python3 "$HELPER" "$@"; }
if [[ "$MODE" == --postboot ]]; then
    touch /var/log/vkarmani-node-postboot.log
    chmod 0600 /var/log/vkarmani-node-postboot.log
    exec > >(tee -a /var/log/vkarmani-node-postboot.log) 2>&1
    rm -f "$STATE/POSTBOOT_SETUP_PASS" "$STATE/POSTBOOT_FAIL"
fi
printf '\n=== VKarmani node acceptance %s mode=%s ===\n' "$(date -Is)" "$MODE"
DOMAIN=$(helper get domain) || exit 1
NODE_PORT=$(helper get node_port) || exit 1
helper secret >/dev/null 2>&1 && pass SECRET_KEY_VALID || fail SECRET_KEY_VALID
[[ "$(timedatectl show -p Timezone --value)" == Europe/Moscow ]] && pass TIMEZONE_MOSCOW || fail TIMEZONE_MOSCOW
if [[ "$MODE" == --preboot ]]; then
    if [[ ! -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ]] || [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) == 1 ]]; then
        pass IPV6_RUNTIME_OFF
    else
        fail IPV6_RUNTIME_OFF
    fi
    if _contains -w 'ipv6.disable=1' /proc/cmdline; then pass IPV6_KERNEL_PARAMETER; else warn IPV6_KERNEL_PARAMETER 'requires reboot'; fi
else
    _contains -w 'ipv6.disable=1' /proc/cmdline && pass IPV6_KERNEL_PARAMETER || fail IPV6_KERNEL_PARAMETER 'GRUB change not active'
    if python3 - <<'PY'
import socket,sys,errno
try:
    s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
except OSError as e:
    sys.exit(0 if e.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT) else 1)
else:
    s.close()
    sys.exit(1)
PY
    then pass IPV6_SOCKET_DISABLED; else fail IPV6_SOCKET_DISABLED 'IPv6 sockets can still be created'; fi
    IPV6_LISTENERS=$(ss -H -6 -lntup 2>/dev/null || true)
    [[ -z "$IPV6_LISTENERS" ]] && pass NO_IPV6_LISTENERS || fail NO_IPV6_LISTENERS
fi
if ip -6 address show 2>/dev/null | _contains 'inet6'; then fail NO_IPV6_ADDRESSES; else pass NO_IPV6_ADDRESSES; fi
if ip -6 route show 2>/dev/null | _contains .; then fail NO_IPV6_ROUTES; else pass NO_IPV6_ROUTES; fi
/usr/sbin/sshd -t >/dev/null 2>&1 && pass SSH_CONFIG || fail SSH_CONFIG
/usr/sbin/sshd -T 2>/dev/null | _contains -Fx 'addressfamily inet' && pass SSH_IPV4_ONLY || fail SSH_IPV4_ONLY
while IFS= read -r port; do
    if ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${port}$"; then pass "SSH_TCP_$port"; else fail "SSH_TCP_$port"; fi
done < "$ETC/ssh-ports"
for service in docker containerd nginx fail2ban chrony ufw vkarmani-node-network vkarmani-node; do
    if systemctl is-active --quiet "$service"; then pass "SERVICE_$service"; else fail "SERVICE_$service"; fi
done
ufw status | _contains -F 'Status: active' && pass UFW_ACTIVE || fail UFW_ACTIVE
if python3 - <<'PY'
import json,subprocess,shlex,sys
from pathlib import Path
c=json.loads(Path('/etc/vkarmani-node/config.json').read_text())
r=subprocess.run(['iptables','-S','ufw-user-input'],capture_output=True,text=True)
if r.returncode: sys.exit(1)
expected={x+'/32' for x in c['panel_ipv4']}
found=set()
ssh=set(Path('/etc/vkarmani-node/ssh-ports').read_text().split())
for line in r.stdout.splitlines():
    w=shlex.split(line)
    if '-j' not in w or w[w.index('-j')+1]!='ACCEPT': continue
    if '--dport' not in w: sys.exit(1)  # no blanket ACCEPT or unreviewed multiport rule
    p=w[w.index('--dport')+1]
    if p==str(c['node_port']):
        if '-s' not in w: sys.exit(1)
        source=w[w.index('-s')+1]
        if source not in expected: sys.exit(1)
        found.add(source)
    elif p not in ssh | {'80','443'}:
        sys.exit(1)
sys.exit(0 if found==expected else 1)
PY
then pass UFW_PANEL_ALLOWLIST; else fail UFW_PANEL_ALLOWLIST; fi
[[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) == bbr ]] && pass TCP_BBR || fail TCP_BBR
[[ $(sysctl -n net.core.default_qdisc 2>/dev/null) == fq ]] && pass DEFAULT_FQ || fail DEFAULT_FQ
IFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
if [[ -n "$IFACE" ]] && tc qdisc show dev "$IFACE" | _contains -E 'qdisc fq '; then pass INTERFACE_FQ; else fail INTERFACE_FQ; fi
if [[ "$MODE" == --postboot ]]; then
    for _ in $(seq 1 60); do
        if ss -H -4 -lnt | awk '{print $4}' | _contains -E ':443$'; then break; fi
        sleep 2
    done
    chronyc waitsync 60 0.1 0.0 2 >/dev/null 2>&1 || true
fi
chronyc tracking 2>/dev/null | _contains -E 'Leap status[[:space:]]*:[[:space:]]*Normal' && pass NTP_SYNC || fail NTP_SYNC
if [[ $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]]; then
    R1=$(docker inspect remnanode --format '{{.RestartCount}}' 2>/dev/null)
    sleep 5
    R2=$(docker inspect remnanode --format '{{.RestartCount}}' 2>/dev/null)
    if [[ "$R1" == "$R2" && $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]]; then
        pass NODE_RUNNING_STABLE
    else fail NODE_RUNNING_STABLE; fi
else fail NODE_RUNNING_STABLE; fi
[[ $(docker inspect remnanode --format '{{.HostConfig.NetworkMode}}' 2>/dev/null) == host ]] && pass NODE_HOST_NETWORK || fail NODE_HOST_NETWORK
[[ $(docker inspect remnanode --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null) == always ]] && pass NODE_RESTART_POLICY || fail NODE_RESTART_POLICY
[[ $(docker network inspect bridge --format '{{.EnableIPv6}}' 2>/dev/null) == false ]] && pass DOCKER_IPV6_OFF || fail DOCKER_IPV6_OFF
if python3 - "$NODE_PORT" <<'PY'
import socket,sys
try:
    with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=5): pass
except OSError:
    sys.exit(1)
PY
then pass NODE_CONTROL_IPV4; else fail NODE_CONTROL_IPV4; fi
if ss -H -4 -lnt | awk '{print $4}' | _contains -E ':443$'; then
    XRAY_PRESENT=1
    pass XRAY_TCP443
else
    warn XRAY_TCP443 'WAITING_FOR_PANEL_PROFILE: назначьте профиль ноде в панели'
fi
ss -H -4 -lnt | awk '{print $4}' | _contains -Fx '127.0.0.1:8444' && pass NGINX_LOOPBACK8444 || fail NGINX_LOOPBACK8444
nginx -t >/dev/null 2>&1 && pass NGINX_CONFIG || fail NGINX_CONFIG
openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -checkend 604800 >/dev/null 2>&1 && pass TLS_VALID_7DAYS || fail TLS_VALID_7DAYS
for port in 8444 443; do
    [[ "$port" != 443 || "$XRAY_PRESENT" -eq 1 ]] || continue
    CODE=$(curl --noproxy '*' -4 --fail --silent --show-error --http2 --tlsv1.3 --tls-max 1.3 \
        --connect-timeout 5 --max-time 20 --resolve "$DOMAIN:$port:127.0.0.1" \
        -o /dev/null -w '%{http_code}' "https://$DOMAIN:$port/__vkarmani_health" 2>/dev/null || true)
    if [[ "$CODE" == 204 ]]; then
        pass "TLS13_COVER_$port"
        [[ "$port" != 443 ]] || XRAY_COVER_OK=1
    elif [[ "$port" == 443 ]]; then
        warn TLS13_COVER_443 'порт открыт, но профиль не подтверждён для локального Nginx/SNI; см. PANEL-SETUP.txt'
    else
        fail "TLS13_COVER_$port" 'certificate/local TLS cover/HTTP failure'
    fi
done
# HTTP/2 ALPN is required by this local REALITY camouflage profile.
ALPN=$(timeout 12 openssl s_client -connect 127.0.0.1:8444 -servername "$DOMAIN" -tls1_3 -alpn h2 </dev/null 2>/dev/null || true)
_contains -F 'ALPN protocol: h2' <<< "$ALPN" && pass COVER_ALPN_H2 || fail COVER_ALPN_H2
fail2ban-client ping 2>/dev/null | _contains pong && pass FAIL2BAN_PING || fail FAIL2BAN_PING
fail2ban-client status sshd >/dev/null 2>&1 && pass FAIL2BAN_SSHD_JAIL || fail FAIL2BAN_SSHD_JAIL
for timer in certbot vkarmani-weekly-reboot vkarmani-node-cleanup; do
    systemctl is-active --quiet "$timer.timer" && pass "TIMER_$timer" || fail "TIMER_$timer"
    systemctl is-enabled --quiet "$timer.timer" && pass "BOOT_$timer" || fail "BOOT_$timer"
done
_contains -Fx 'OnCalendar=Mon *-*-* 04:00:00 Europe/Moscow' /etc/systemd/system/vkarmani-weekly-reboot.timer \
    && pass REBOOT_MONDAY_0400_MSK || fail REBOOT_MONDAY_0400_MSK
[[ -e "$ETC/weekly-reboot-enabled" ]] && pass WEEKLY_REBOOT_GATE || fail WEEKLY_REBOOT_GATE
warn PANEL_CONNECTION 'NOT_VERIFIED: API не используется; состояние подключения смотрите в панели'
if [[ "$MODE" != --local ]]; then
    helper dns && pass DOMAIN_IPV4_ONLY || fail DOMAIN_IPV4_ONLY
fi
if [[ "$F" -eq 0 ]]; then
    echo 'NODE_SETUP=PASS'
else
    echo 'NODE_SETUP=FAIL — исправьте ошибки настройки VPS.'
fi
if [[ "$XRAY_PRESENT" -eq 0 ]]; then
    VPN_STATUS=WAITING_FOR_PANEL_PROFILE
elif [[ "$XRAY_COVER_OK" -eq 1 ]]; then
    VPN_STATUS=LOCAL_XRAY_COVER_OK_CLIENT_NOT_TESTED
else
    VPN_STATUS=PORT443_PRESENT_PROFILE_NOT_CONFIRMED
fi
printf 'VPN_STATUS=%s\nPANEL_CONNECTION=NOT_VERIFIED\n' "$VPN_STATUS"
echo 'Клиентский VPN-трафик, назначение Host и доступ пользователя этой командой не проверяются.'
if [[ "$MODE" == --postboot ]]; then
    if [[ "$F" -eq 0 ]]; then
        printf 'at=%s\nnode_setup=pass\nvpn_status=%s\npanel_connection=not_verified\n' "$(date -Is)" "$VPN_STATUS" > "$STATE/POSTBOOT_SETUP_PASS"
    else
        printf 'at=%s\n' "$(date -Is)" > "$STATE/POSTBOOT_FAIL"
    fi
fi
if [[ "$F" -ne 0 ]]; then exit 1; fi
if [[ "$MODE" == --require-xray && "$XRAY_COVER_OK" -ne 1 ]]; then
    echo 'STRICT_CHECK=INCOMPLETE: ожидается TCP/443 и локальный REALITY cover.'
    exit 2
fi
exit 0
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
