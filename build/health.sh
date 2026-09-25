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
