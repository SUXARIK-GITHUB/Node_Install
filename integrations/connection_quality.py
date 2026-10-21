#!/usr/bin/env python3
"""VKARMANI read-only aggregate TCP session-quality diagnostics.

Reports only aggregate metadata from established TCP/443 Xray sockets, never
peer IPs, ports, UUIDs, keys or raw ss output. This does not measure throughput
inside VLESS, UDP quality, TSPU filtering or per-user experience.
"""
import argparse
import json
import math
import re
import shutil
import subprocess
import sys
import time

MAX_SS_BYTES = 2 * 1024 * 1024
ESTABLISHED = re.compile(r'^(?:ESTAB|ESTABLISHED)\s')
RTT = re.compile(r'(?<!\S)rtt:(\d+(?:\.\d+)?)/\d+(?:\.\d+)?')
RETRANS = re.compile(r'(?<!\S)retrans:(\d+)/(\d+)')
BYTES_RETRANS = re.compile(r'(?<!\S)bytes_retrans:(\d+)')
DELIVERY = re.compile(r'(?<!\S)delivery_rate\s+(\d+(?:\.\d+)?)([KMG]?)bps(?:\s|$)')


def parse_ss(raw):
    if not isinstance(raw, str) or len(raw) > MAX_SS_BYTES:
        raise ValueError('SS_OUTPUT_INVALID_OR_TOO_LARGE')
    entries = []
    current = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            if ESTABLISHED.match(line):
                current = {'rtt_ms': None, 'retrans': None, 'delivery_bps': None}
                entries.append(current)
            else:
                # Not an ESTABLISHED connection: refuse to misassociate info.
                current = None
            continue
        if current is None:
            continue
        m = RTT.search(line)
        if m:
            val = float(m[1])
            if math.isfinite(val) and val <= 1e6:
                current['rtt_ms'] = val
        m = RETRANS.search(line)
        if m:
            current['retrans'] = int(m[1]) > 0 or int(m[2]) > 0
        m = BYTES_RETRANS.search(line)
        if m:
            current['retrans'] = bool(current['retrans']) or int(m[1]) > 0
        m = DELIVERY.search(line)
        if m:
            multiplier = {'': 1, 'K': 1000, 'M': 1000000, 'G': 1000000000}[m[2]]
            value = float(m[1]) * multiplier
            if math.isfinite(value) and value <= 1e15:
                current['delivery_bps'] = round(value)
    return entries


def percentile(vals, percent):
    if not vals:
        return None
    data = sorted(vals)
    return round(data[max(0, math.ceil(len(data) * percent / 100) - 1)], 2)


def aggregate(entries):
    rtts = [v['rtt_ms'] for v in entries if v['rtt_ms'] is not None]
    rates = [v['delivery_bps'] for v in entries if v['delivery_bps'] is not None]
    flags = [v['retrans'] for v in entries if v['retrans'] is not None]
    return {'established_tcp_connections': len(entries),
            'rtt_sampled': len(rtts), 'rtt_ms_p50': percentile(rtts, 50),
            'rtt_ms_p90': percentile(rtts, 90), 'rtt_ms_p99': percentile(rtts, 99),
            'retransmission_samples': len(flags),
            'connections_reporting_retransmissions': sum(flags),
            'retransmission_observed_percent': (round(100 * sum(flags) / len(flags), 1)
                                               if flags else None),
            'delivery_rate_sampled': len(rates),
            'delivery_rate_bps_median': percentile(rates, 50)}


def obtain_ss():
    if not shutil.which('ss'):
        return None, 'SS_COMMAND_NOT_FOUND'
    try:
        p = subprocess.run(['ss', '-H', '-t', '-i', '-n', 'state', 'established',
                            '( sport = :443 )'], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=8, check=False)
        if p.returncode:
            return None, 'SS_COMMAND_FAILED'
        if len(p.stdout) > MAX_SS_BYTES:
            return None, 'SS_OUTPUT_TOO_LARGE'
        return p.stdout, None
    except subprocess.TimeoutExpired:
        return None, 'SS_TIMEOUT'
    except (OSError, UnicodeError):
        return None, 'SS_UNAVAILABLE'


def snapshot(reader=obtain_ss):
    raw, err = reader()
    if err:
        return None, err
    try:
        return aggregate(parse_ss(raw)), None
    except (TypeError, ValueError, OverflowError):
        return None, 'SS_METRICS_UNPARSEABLE'


def diagnose(seconds, reader=obtain_ss, sleeper=time.sleep):
    before, error = snapshot(reader)
    if error:
        return {'status': 'NOT_VERIFIED', 'reason': error, 'actions_performed': 'NONE'}
    sleeper(seconds)
    after, error = snapshot(reader)
    if error:
        return {'status': 'NOT_VERIFIED', 'reason': error, 'actions_performed': 'NONE'}
    status, reason = 'INFO', 'OBSERVATION_ONLY'
    if not after['established_tcp_connections']:
        reason = 'NO_ESTABLISHED_TCP_443_CONNECTIONS'
    elif not after['rtt_sampled']:
        status, reason = 'NOT_VERIFIED', 'TCP_RTT_METRICS_UNAVAILABLE'
    elif after['rtt_ms_p90'] > 250 or (after['retransmission_observed_percent'] is not None
                                      and after['retransmission_observed_percent'] > 20):
        status, reason = 'REVIEW', 'HIGH_RTT_OR_RETRANSMISSION_RATE'
    return {'status': status, 'reason': reason, 'sampling_seconds': seconds,
            'before': before, 'after': after,
            'notes': ['TCP/443 only; other listeners, UDP and tunnels are not measured',
                      'RTT is to connected client networks; high RTT does not prove host fault',
                      'Retransmission metrics reflect existing counter history, not an exact interval rate',
                      'Samples are aggregated; connections cannot be correlated across snapshots'],
            'actions_performed': 'NONE'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only aggregate quality on TCP/443')
    parser.add_argument('--seconds', type=int, default=5)
    parser.add_argument('--strict', action='store_true',
                        help='exit nonzero when any measurement is REVIEW/NOT_VERIFIED')
    args = parser.parse_args(argv)
    if not 1 <= args.seconds <= 120:
        parser.error('--seconds must be between 1 and 120')
    result = diagnose(args.seconds)
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 2 if args.strict and result['status'] in ('REVIEW', 'NOT_VERIFIED') else 0


if __name__ == '__main__':
    sys.exit(main())
