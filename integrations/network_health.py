#!/usr/bin/env python3
"""Read-only, privacy-limited host network diagnostics for VKarmani nodes.

Never changes sysctl, qdisc, interfaces, routes or firewall. Does not resolve
names, send traffic, print gateways, NIC addresses, peers, MACs or secret data.
Snapshot counters are cumulative; this is NOT a throughput benchmark.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

MAX_OUTPUT = 512 * 1024
IFNAME = re.compile(r'[A-Za-z0-9_.:@-]{1,64}\Z')
PARAMS = {
    'congestion_control': 'net/ipv4/tcp_congestion_control',
    'available_congestion_controls': 'net/ipv4/tcp_available_congestion_control',
    'default_qdisc': 'net/core/default_qdisc',
    'tcp_mtu_probing': 'net/ipv4/tcp_mtu_probing',
    'ip_forward': 'net/ipv4/ip_forward',
    'rp_filter_all': 'net/ipv4/conf/all/rp_filter',
    'somaxconn': 'net/core/somaxconn',
    'tcp_max_syn_backlog': 'net/ipv4/tcp_max_syn_backlog',
    'tcp_rmem': 'net/ipv4/tcp_rmem',
    'tcp_wmem': 'net/ipv4/tcp_wmem',
    'rmem_max': 'net/core/rmem_max',
    'wmem_max': 'net/core/wmem_max',
    'tcp_fastopen': 'net/ipv4/tcp_fastopen',
    'ip_local_port_range': 'net/ipv4/ip_local_port_range',
    'ipv6_disabled': 'net/ipv6/conf/all/disable_ipv6',
}


def run(argv):
    if argv[0] not in ('ip', 'tc') or not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, text=True, capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=5, check=False)
        if p.returncode or len(p.stdout) > MAX_OUTPUT:
            return None
        return p.stdout
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None


def read(path):
    try:
        value = Path(path).read_bytes()
        if len(value) > MAX_OUTPUT:
            return None
        return value.decode('ascii', errors='strict').strip()
    except (OSError, UnicodeError, ValueError):
        return None


def default_interface(payload):
    """Select an unambiguous primary IPv4 route, without emitting gateways."""
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list):
            return None, 'ROUTE_SCHEMA'
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                return None, 'ROUTE_SCHEMA'
            if row.get('dst') not in (None, 'default', '0.0.0.0/0'):
                continue
            dev = row.get('dev')
            metric = row.get('metric', 0)
            if not isinstance(dev, str) or not IFNAME.fullmatch(dev):
                return None, 'ROUTE_INTERFACE_INVALID'
            if isinstance(metric, bool) or not isinstance(metric, int) or metric < 0:
                return None, 'ROUTE_METRIC_INVALID'
            candidates.append((metric, dev))
        if not candidates:
            return None, 'ROUTE_MISSING'
        minmetric = min(item[0] for item in candidates)
        interfaces = {dev for metric, dev in candidates if metric == minmetric}
        if len(interfaces) != 1:
            return None, 'ROUTE_AMBIGUOUS'
        return next(iter(interfaces)), None
    except (ValueError, TypeError, OverflowError):
        return None, 'ROUTE_UNPARSEABLE'


def qdisc_summary(payload):
    """Keep only qdisc types/queue drops, never dump device options or handles."""
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list) or len(rows) > 128:
            raise ValueError('invalid qdisc array')
        kinds, root, drops = [], None, 0
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('invalid qdisc row')
            kind = row.get('kind')
            if not isinstance(kind, str) or not re.fullmatch(r'[a-z0-9_-]{1,32}', kind):
                raise ValueError('bad qdisc type')
            kinds.append(kind)
            if row.get('root') is True or row.get('parent') == 'root':
                root = kind
            stats = row.get('stats')
            if isinstance(stats, dict):
                queue = stats.get('queue') or {}
                if isinstance(queue, dict):
                    n = queue.get('drops', 0)
                    if type(n) is int and n >= 0 and row.get('drops') is None:
                        drops += n
            n = row.get('drops')
            if type(n) is int and n >= 0:
                drops += n
        if not kinds:
            return {'verified': False, 'reason': 'EMPTY_QDISC'}
        # A multiqueue virtio device normally has mq at root; fq may live below it.
        effective_fq = 'fq' in kinds and (root in ('fq', 'mq', None))
        return {'verified': True, 'root_kind': root,
                'kinds': sorted(set(kinds)), 'fq_present': effective_fq,
                'queue_drops_cumulative': drops}
    except (ValueError, TypeError, OverflowError):
        return {'verified': False, 'reason': 'QDISC_UNPARSEABLE'}


def interface_counters(payload, expected):
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError('wrong link array')
        row = rows[0]
        if not isinstance(row, dict) or row.get('ifname') != expected:
            raise ValueError('wrong interface')
        s = row.get('stats64', row.get('stats'))
        if not isinstance(s, dict):
            raise ValueError('statistics unavailable')
        result = {'verified': True, 'mtu': row.get('mtu') if type(row.get('mtu')) is int else None}
        for direction in ('rx', 'tx'):
            entry = s.get(direction)
            if not isinstance(entry, dict):
                raise ValueError('missing counters')
            for key in ('packets', 'bytes', 'dropped', 'errors'):
                val = entry.get(key)
                if type(val) is not int or val < 0:
                    raise ValueError('invalid counter')
                result[direction + '_' + key] = val
        return result
    except (ValueError, TypeError, OverflowError):
        return {'verified': False, 'reason': 'LINK_COUNTERS_UNPARSEABLE'}


def softnet_summary(raw):
    if raw is None:
        return {'verified': False, 'reason': 'SOFTNET_NOT_AVAILABLE'}
    processed = dropped = squeeze = 0
    try:
        for line in raw.splitlines():
            cols = line.split()
            if len(cols) < 3:
                raise ValueError('short row')
            values = [int(col, 16) for col in cols[:3]]
            processed += values[0]
            dropped += values[1]
            squeeze += values[2]
        return {'verified': True, 'processed_cumulative': processed,
                'dropped_cumulative': dropped, 'time_squeeze_cumulative': squeeze}
    except (ValueError, OverflowError):
        return {'verified': False, 'reason': 'SOFTNET_UNPARSEABLE'}


def natural_number(value):
    try:
        if value is None or not re.fullmatch(r'[0-9]{1,18}', value):
            return None
        return int(value)
    except (ValueError, TypeError):
        return None



def _proc_columns(raw, prefix, allowed):
    """Parse aggregate /proc/net/netstat and /proc/net/snmp two-line sections.

    Return only explicitly allowed counters, never connection/peer details.
    """
    if raw is None:
        return {'verified': False, 'reason': 'PROC_COUNTERS_UNAVAILABLE'}
    lines = raw.splitlines()
    for first, second in zip(lines, lines[1:]):
        if not first.startswith(prefix + ':') or not second.startswith(prefix + ':'):
            continue
        names = first.split()[1:]
        values = second.split()[1:]
        if len(names) != len(values) or len(names) > 4096:
            break
        numbers = {}
        for name, value in zip(names, values):
            if name in allowed:
                if not re.fullmatch(r'[0-9]{1,20}', value):
                    return {'verified': False, 'reason': 'COUNTER_INVALID'}
                numbers[name] = int(value)
        return {'verified': bool(numbers), 'counters': numbers} if numbers else {'verified': False, 'reason': 'COUNTER_SET_NOT_FOUND'}
    return {'verified': False, 'reason': 'PROC_COUNTERS_UNPARSEABLE'}


def socket_counters(raw):
    """Aggregate only socket counts; /proc/net/sockstat contains no peer IDs."""
    if raw is None:
        return {'verified': False, 'reason': 'SOCKSTAT_UNAVAILABLE'}
    result = {}
    for line in raw.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ('TCP:', 'UDP:'):
            continue
        if len(parts) % 2 != 1:
            return {'verified': False, 'reason': 'SOCKSTAT_UNPARSEABLE'}
        for key, val in zip(parts[1::2], parts[2::2]):
            if key in ('inuse', 'orphan', 'tw', 'alloc', 'mem'):
                if not val.isascii() or not re.fullmatch(r'[0-9]{1,18}', val):
                    return {'verified': False, 'reason': 'SOCKSTAT_INVALID'}
                result[parts[0][:-1].lower() + '_' + key] = int(val)
    return {'verified': bool(result), 'counts': result}


TCP_COUNTERS = frozenset(('ListenOverflows', 'ListenDrops', 'TCPTimeouts',
                          'TCPLossProbes', 'TCPLossProbeRecovery',
                          'TCPFastOpenActiveFail', 'TCPSynRetrans', 'TCPBacklogDrop'))


def snapshot(command=run, reader=read):
    params = {key: reader('/proc/sys/' + path) for key, path in PARAMS.items()}
    route = command(['ip', '-j', '-4', 'route', 'show', 'default'])
    iface, reason = default_interface(route) if route is not None else (None, 'IP_COMMAND_UNAVAILABLE')
    qdisc = {'verified': False, 'reason': 'ROUTE_UNAVAILABLE'}
    counters = {'verified': False, 'reason': 'ROUTE_UNAVAILABLE'}
    if iface is not None:
        qraw = command(['tc', '-j', '-s', 'qdisc', 'show', 'dev', iface])
        qdisc = qdisc_summary(qraw) if qraw is not None else {'verified': False, 'reason': 'TC_UNAVAILABLE'}
        lraw = command(['ip', '-j', '-s', 'link', 'show', 'dev', iface])
        counters = (interface_counters(lraw, iface) if lraw is not None
                    else {'verified': False, 'reason': 'LINK_UNAVAILABLE'})
    ct_current = natural_number(reader('/proc/sys/net/netfilter/nf_conntrack_count'))
    ct_max = natural_number(reader('/proc/sys/net/netfilter/nf_conntrack_max'))
    conntrack = {'verified': ct_current is not None and ct_max not in (None, 0),
                 'count': ct_current, 'capacity': ct_max,
                 'usage_percent': (round(ct_current / ct_max * 100, 2)
                                   if ct_current is not None and ct_max not in (None, 0) else None)}
    softnet = softnet_summary(reader('/proc/net/softnet_stat'))
    tcp_stats = _proc_columns(reader('/proc/net/netstat'), 'TcpExt', TCP_COUNTERS)
    sock_stats = socket_counters(reader('/proc/net/sockstat'))
    warnings = []
    if params['congestion_control'] != 'bbr':
        warnings.append('BBR_NOT_ACTIVE_OR_UNVERIFIED')
    if params['default_qdisc'] != 'fq':
        warnings.append('FQ_DEFAULT_NOT_ACTIVE_OR_UNVERIFIED')
    if not qdisc.get('verified'):
        warnings.append('ACTIVE_QDISC_NOT_VERIFIED')
    elif not qdisc.get('fq_present'):
        warnings.append('FQ_NOT_FOUND_ON_ACTIVE_INTERFACE')
    if conntrack['usage_percent'] is not None and conntrack['usage_percent'] >= 85:
        warnings.append('CONNTRACK_CAPACITY_HIGH')
    if not counters.get('verified'):
        warnings.append('ACTIVE_INTERFACE_COUNTERS_UNVERIFIED')
    if (tcp_stats['verified'] and (tcp_stats['counters'].get('ListenOverflows', 0) > 0
                                   or tcp_stats['counters'].get('ListenDrops', 0) > 0)):
        warnings.append('LISTEN_OVERFLOW_OR_DROP_SEEN_CUMULATIVE')
    return {'schema': 1, 'status': 'REVIEW' if warnings else 'INFO',
            'network_interface': iface, 'route_status': 'OK' if iface else reason,
            'parameters': params, 'qdisc': qdisc,
            'interface_counters': counters, 'softnet': softnet, 'conntrack': conntrack,
            'tcp_host_counters': tcp_stats, 'socket_counts': sock_stats,
            'observations': warnings,
            'limitations': [
                'All packet/drop counters are cumulative since reset, not measured rates',
                'A default fq sysctl does not prove active qdisc uses fq',
                'BBR affects host TCP, not all internal proxy or UDP traffic',
                'No end-to-end client quality, DPI or congestion attribution is inferred',
                'TCP counters are cumulative and cannot identify affected users',
                'No sysctl, qdisc, MTU or buffer parameter is modified',
            ], 'actions_performed': 'NONE'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true')
    args = parser.parse_args(argv)
    result = snapshot()
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 2 if args.strict and result['status'] != 'INFO' else 0


if __name__ == '__main__':
    sys.exit(main())
