#!/usr/bin/env python3
"""VKarmani read-only IPv4, routing, service and bottleneck triage.

No configuration, network interface, daemon, firewall or route is modified.
An optional DNS lookup checks names through the host resolver, not public DNS
consensus. Output excludes configuration secrets and peer/client addresses.
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys


MAX_OUTPUT = 512 * 1024


def run(args, timeout=5):
    if not shutil.which(args[0]):
        return None, 'COMMAND_MISSING'
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           check=False)
        if p.returncode:
            return None, 'COMMAND_FAILED'
        if len(p.stdout) > MAX_OUTPUT:
            return None, 'OUTPUT_TOO_LARGE'
        return p.stdout, None
    except subprocess.TimeoutExpired:
        return None, 'TIMEOUT'
    except (OSError, UnicodeError):
        return None, 'COMMAND_UNAVAILABLE'


def valid_public(address):
    try:
        value = ipaddress.IPv4Address(address)
        return value.is_global and not value.is_reserved and not value.is_multicast
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False


def parse_addresses(raw):
    if raw is None or len(raw) > MAX_OUTPUT:
        raise ValueError('IP_ADDRESSES_UNAVAILABLE')
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ValueError('IP_ADDRESSES_SCHEMA')
    out = []
    used = set()
    for item in rows:
        if not isinstance(item, dict):
            raise ValueError('IP_ADDRESS_ROW_SCHEMA')
        interface = item.get('ifname')
        if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.:@-]{1,64}', interface):
            raise ValueError('IP_INTERFACE_NAME')
        link_up = item.get('operstate') == 'UP'
        mtu = item.get('mtu')
        if not isinstance(mtu, int) or mtu <= 0:
            mtu = None
        for addr in item.get('addr_info', []):
            if not isinstance(addr, dict):
                raise ValueError('IP_ADDRESS_DETAILS')
            ip = addr.get('local')
            if addr.get('family') == 'inet' and valid_public(ip):
                if ip in used:
                    raise ValueError('DUPLICATE_PUBLIC_ADDRESS')
                used.add(ip)
                out.append({'ip': ip, 'interface': interface, 'mtu': mtu,
                            'interface_up': link_up, 'prefixlen': addr.get('prefixlen'),
                            'secondary': addr.get('secondary', False) is True})
    return sorted(out, key=lambda x: (int(ipaddress.IPv4Address(x['ip'])), x['interface']))


def parse_route(raw):
    if raw is None or len(raw) > MAX_OUTPUT:
        raise ValueError('ROUTE_UNAVAILABLE')
    rows = json.loads(raw)
    if not isinstance(rows, list) or not rows:
        raise ValueError('ROUTE_MISSING')
    route = rows[0]
    if not isinstance(route, dict):
        raise ValueError('ROUTE_SCHEMA')
    src = route.get('prefsrc') or route.get('src')
    if not src or not valid_public(src):
        src = None
    return {'interface': route.get('dev') if isinstance(route.get('dev'), str) else None,
            'source_ipv4': src,
            'gateway': route.get('gateway') if isinstance(route.get('gateway'), str) else None}


def check_dns(domain, assigned, resolver=run):
    if not domain:
        return {'status': 'SKIPPED', 'reason': 'DOMAIN_NOT_SUPPLIED'}
    if len(domain) > 253 or not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9.-]+', domain) or '..' in domain or '.' not in domain:
        return {'status': 'UNVERIFIED', 'reason': 'INVALID_DOMAIN'}
    raw, err = resolver(['getent', 'ahostsv4', domain], 5)
    if err:
        return {'status': 'UNVERIFIED', 'reason': 'DNS_' + err}
    addresses = set()
    for line in raw.splitlines():
        fields = line.split()
        if fields and valid_public(fields[0]):
            addresses.add(fields[0])
    ips = sorted(addresses, key=lambda a: int(ipaddress.IPv4Address(a)))
    local = {i['ip'] for i in assigned}
    if len(ips) != 1:
        return {'status': 'REVIEW', 'reason': 'DNS_A_RECORDS_NOT_UNIQUE',
                'domain': domain, 'dns_ipv4': ips}
    if ips[0] not in local:
        return {'status': 'REVIEW', 'reason': 'DNS_IP_NOT_ASSIGNED_TO_HOST',
                'domain': domain, 'dns_ipv4': ips}
    return {'status': 'PASS', 'reason': 'DNS_IP_ASSIGNED_TO_HOST',
            'domain': domain, 'selected_ipv4': ips[0], 'dns_ipv4': ips,
            'note': 'SYSTEM_RESOLVER_ONLY; PUBLIC_DNS_NOT_VERIFIED'}


def network_backends(root=Path('/')):
    """Report config presence, NOT an inferred active network manager."""
    netplan = root / 'etc/netplan'
    ifaces = root / 'etc/network/interfaces'
    ifacedir = root / 'etc/network/interfaces.d'
    try:
        netplan_present = netplan.is_dir() and any(
            p.is_file() and not p.is_symlink() and p.suffix in ('.yaml', '.yml')
            for p in netplan.iterdir())
        ifupdown_present = ifaces.is_file() or (ifacedir.is_dir() and any(p.is_file() for p in ifacedir.iterdir()))
        networkd_present = (root / 'etc/systemd/network').is_dir()
        nm_present = (root / 'etc/NetworkManager/system-connections').is_dir()
        cloudinit_present = (root / 'etc/cloud/cloud.cfg').is_file()
    except OSError:
        return {'status': 'UNVERIFIED', 'reason': 'NETWORK_CONFIG_UNREADABLE'}
    names = []
    if netplan_present: names.append('netplan')
    if ifupdown_present: names.append('ifupdown-config-present')
    if networkd_present: names.append('systemd-networkd-config-dir-present')
    if nm_present: names.append('NetworkManager-config-dir-present')
    if cloudinit_present: names.append('cloud-init-installed')
    return {'status': 'INFO', 'config_sources': names,
            'note': 'PRESENCE_DOES_NOT_PROVE_ACTIVE_BACKEND; NO_FILES_MODIFIED'}


def read_counter(path):
    try:
        raw = Path(path).read_text().strip()
        if not re.fullmatch(r'[0-9]{1,20}', raw):
            return None
        return int(raw)
    except (OSError, ValueError):
        return None


def conntrack(root=Path('/proc/sys/net/netfilter')):
    used = read_counter(root / 'nf_conntrack_count')
    maximum = read_counter(root / 'nf_conntrack_max')
    if used is None or maximum is None or maximum <= 0:
        return {'status': 'UNVERIFIED', 'reason': 'CONNTRACK_COUNTERS_UNAVAILABLE'}
    pct = round(used * 100 / maximum, 1)
    return {'status': 'REVIEW' if pct >= 85 else 'PASS', 'used': used,
            'capacity': maximum, 'utilization_percent': pct,
            'reason': 'CONNTRACK_NEAR_CAPACITY' if pct >= 85 else 'CONNTRACK_BELOW_THRESHOLD'}


def tcp_tuning(root=Path('/proc/sys')):
    settings = {
        'congestion_control': 'net/ipv4/tcp_congestion_control',
        'default_qdisc': 'net/core/default_qdisc',
        'tcp_mtu_probing': 'net/ipv4/tcp_mtu_probing',
        'somaxconn': 'net/core/somaxconn',
    }
    result = {}
    for key, relative in settings.items():
        try:
            value = (root / relative).read_text().strip()
            result[key] = value[:64] if value and len(value) <= 64 else None
        except OSError:
            result[key] = None
    return {'status': 'INFO', 'effective_kernel_values': result,
            'note': 'REPORT_ONLY; NO_SYSCTL_TUNING_RECOMMENDED_WITHOUT_MEASUREMENTS'}


def tcp_listeners(raw):
    """Summarize ports only; do not expose remote/client IP addresses."""
    if raw is None or len(raw) > MAX_OUTPUT:
        return {'status': 'UNVERIFIED', 'reason': 'LISTENERS_UNAVAILABLE'}
    ports = set()
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        endpoint = parts[3]
        try:
            port = int(endpoint.rsplit(':', 1)[-1])
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return {'status': 'INFO', 'expected_tcp_port_80_listening': 80 in ports,
            'expected_tcp_port_443_listening': 443 in ports,
            'note': 'PORT_ONLY; BIND_ADDRESS_PROCESS_AND_EXTERNAL_CONNECTIVITY_NOT_VERIFIED'}


def parse_qdisc(raw):
    if raw is None or len(raw) > MAX_OUTPUT:
        return {'status': 'UNVERIFIED', 'reason': 'QDISC_UNAVAILABLE'}
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError('QDISC_SCHEMA')
        rows = []
        for item in data:
            if not isinstance(item, dict):
                raise ValueError('QDISC_ROW')
            dev, kind = item.get('dev'), item.get('kind')
            if isinstance(dev, str) and re.fullmatch(r'[a-zA-Z0-9_.:@-]{1,64}', dev) and isinstance(kind, str):
                rows.append({'interface': dev, 'kind': kind[:32],
                             'root': item.get('root') is True})
        return {'status': 'INFO', 'qdiscs': rows[:128],
                'note': 'ACTIVE_QDISC_READ_ONLY; NOT_PROOF_OF_REAL_NETWORK_SPEED'}
    except (ValueError, TypeError, json.JSONDecodeError):
        return {'status': 'UNVERIFIED', 'reason': 'QDISC_PARSE_ERROR'}


def docker_node_status(runner=run):
    """Never inspect env, mounts, labels, client IPs or other container names."""
    raw, error = runner(['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}'], 6)
    if error:
        return {'status': 'UNVERIFIED', 'reason': 'DOCKER_' + error}
    for line in raw.splitlines():
        name, sep, state = line.partition('\t')
        if sep and name == 'remnanode':
            return {'status': 'INFO', 'remnanode_running': state.startswith('Up '),
                    'note': 'RUNNING_CONTAINER_DOES_NOT_PROVE_XRAY_CLIENT_CONNECTIONS'}
    return {'status': 'INFO', 'remnanode_running': False,
            'note': 'NOT_LISTED; CONTAINER_MAY_NOT_BE_INSTALLED_YET'}


def run_diagnostics(domain=None, runner=run, root=Path('/')):
    raw, addr_error = runner(['ip', '-j', '-4', 'address', 'show', 'scope', 'global'], 6)
    try:
        assigned = parse_addresses(raw)
        address_info = {'status': 'PASS' if assigned else 'REVIEW', 'public_ipv4': assigned,
                        'reason': 'ASSIGNED_PUBLIC_IPV4' if assigned else 'NO_PUBLIC_IPV4_ASSIGNED'}
    except (ValueError, TypeError, json.JSONDecodeError):
        assigned = []
        address_info = {'status': 'UNVERIFIED', 'reason': addr_error or 'ADDRESS_PARSE_ERROR'}
    raw, route_error = runner(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'], 6)
    try:
        route = {'status': 'PASS', **parse_route(raw)}
    except (ValueError, TypeError, json.JSONDecodeError):
        route = {'status': 'UNVERIFIED', 'reason': route_error or 'ROUTE_PARSE_ERROR'}
    dns = check_dns(domain, assigned, runner) if address_info['status'] != 'UNVERIFIED' else {
        'status': 'UNVERIFIED', 'reason': 'LOCAL_ADDRESS_DATA_UNAVAILABLE'}
    chosen = dns.get('selected_ipv4')
    if chosen and route.get('source_ipv4') and chosen != route['source_ipv4']:
        route['source_differs_from_inbound_ipv4'] = True
        route['note'] = 'NORMAL_FOR_MULTI_IPV4; CHECK_EGRESS_SOURCE_IF_REQUIRED'
    raw, qdisc_error = runner(['tc', '-j', 'qdisc', 'show'], 6)
    qdiscs = parse_qdisc(raw) if not qdisc_error else {
        'status': 'UNVERIFIED', 'reason': 'TC_' + qdisc_error}
    raw, error = runner(['ss', '-H', '-ltn'], 6)
    listeners = tcp_listeners(raw)
    if error:
        listeners = {'status': 'UNVERIFIED', 'reason': error}
    result = {
        'scope': 'READ_ONLY_LOCAL_NODE; NOT_A_LIVE_VPN_THROUGHPUT_OR_FIREWALL_TEST',
        'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'addresses': address_info,
        'domain_alignment': dns,
        'outbound_route': route,
        'network_configuration': network_backends(root),
        'conntrack': conntrack(root / 'proc/sys/net/netfilter'),
        'tcp_kernel': tcp_tuning(root / 'proc/sys'),
        'tcp_listeners': listeners,
        'interface_qdiscs': qdiscs,
        'docker_node': docker_node_status(runner),
        'next_diagnostics': 'bash ./install.sh --diagnose-resources --seconds 15',
        'actions_performed': 'NONE',
    }
    result['review_required'] = any(isinstance(result[k], dict) and
                                    result[k].get('status') in ('REVIEW', 'UNVERIFIED')
                                    for k in ('addresses', 'domain_alignment', 'outbound_route',
                                              'conntrack', 'tcp_listeners'))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only IPv4, DNS, routing and socket audit')
    parser.add_argument('--domain', metavar='NODE_DOMAIN', help='check node DNS A against all local public IPv4s')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run_diagnostics(args.domain), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'UNVERIFIED', 'reason': 'DIAGNOSTIC_ERROR',
                          'error_type': type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
