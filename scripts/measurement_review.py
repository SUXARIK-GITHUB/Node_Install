#!/usr/bin/env python3
"""Read-only comparison of two EXISTING sanitized staging probe reports.

Accepts only reports from VKarmani direct HTTPS or direct TCP iperf3 probes.
Never guesses that network performance == VPN performance or DPI resistance.
No external connections or system mutations. Outputs numeric changes only,
not a recommendation to switch protocol/congestion control.
"""
import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys

MAX_BYTES = 128 * 1024
SUPPORTED = {'DIRECT_HTTPS_SITE_ONLY', 'DIRECT_TCP_IPERF3_NOT_VPN'}

class ReviewError(Exception):
    pass


def _read(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ReviewError('SYMLINK_PATH_FORBIDDEN')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ReviewError('REPORT_UNREADABLE') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
            raise ReviewError('REPORT_NOT_REGULAR_OR_TOO_LARGE')
        with os.fdopen(fd, 'rb') as f:
            fd = -1
            data = f.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ReviewError('REPORT_TOO_LARGE')
    finally:
        if fd >= 0:
            os.close(fd)
    def unique(pairs):
        out = {}
        for k,v in pairs:
            if k in out: raise ReviewError('DUPLICATE_JSON_KEY')
            out[k]=v
        return out
    try:
        report = json.loads(data.decode('utf-8'),object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ReviewError('NONFINITE_JSON')))
    except (UnicodeError,ValueError) as exc:
        raise ReviewError('REPORT_JSON_INVALID') from exc
    if not isinstance(report,dict) or report.get('schema') != 1 or report.get('measure') not in SUPPORTED:
        raise ReviewError('UNKNOWN_REPORT_SCHEMA_OR_MEASURE')
    return report


def _number(v):
    return type(v) in (int,float) and math.isfinite(v) and 0 <= v < 1e12


def compare(before, after):
    if not all(isinstance(v,dict) and v.get('schema') == 1 and v.get('measure') in SUPPORTED for v in (before,after)):
        raise ReviewError('REPORT_SCHEMA_MISMATCH')
    if before['measure'] != after['measure']:
        raise ReviewError('DIFFERENT_MEASURE_TYPE')
    measure = before['measure']
    observations = ['SOURCE_NETWORK_AND_LOAD_EQUIVALENCE_NOT_PROVEN',
                    'NOT_A_VPN_CLIENT_BENCHMARK', 'DPI_EFFECTIVENESS_NOT_MEASURED']
    if measure == 'DIRECT_TCP_IPERF3_NOT_VPN':
        if before.get('direction') not in ('forward','reverse') or before.get('direction') != after.get('direction'):
            raise ReviewError('DIRECTION_MISMATCH')
        if any(row.get('status') != 'PASS' or
               type(row.get('samples')) is not int or row['samples'] < 2 or
               row.get('completed') != row['samples'] or
               not _number(row.get('mbps_median')) or row['mbps_median'] == 0 or
               type(row.get('retransmits_total')) is not int or row['retransmits_total'] < 0
               for row in (before,after)):
            raise ReviewError('INCOMPLETE_THROUGHPUT_REPORT')
        a, b = before['mbps_median'], after['mbps_median']
        differences = {'mbps_median_before': a, 'mbps_median_after': b,
                       'mbps_median_change': round(b-a,2),
                       'retransmits_before':before['retransmits_total'],
                       'retransmits_after':after['retransmits_total']}
    else:
        for row in (before,after):
            if (row.get('status') != 'PASS' or type(row.get('samples')) is not int or
                    row['samples'] < 3 or row.get('ok') != row['samples'] or
                    row.get('failed') != 0 or not isinstance(row.get('metrics'),dict)):
                raise ReviewError('INCOMPLETE_HTTPS_REPORT')
        differences = {}
        for name in ('tcp_ms','tls_ms','ttfb_ms','total_ms'):
            for pct in ('p50','p95'):
                a = before['metrics'].get(name,{}).get(pct)
                b = after['metrics'].get(name,{}).get(pct)
                if not _number(a) or not _number(b):
                    raise ReviewError('HTTPS_METRIC_MISSING_OR_INVALID')
                differences[name+'_'+pct+'_before']=a
                differences[name+'_'+pct+'_after']=b
                differences[name+'_'+pct+'_change']=round(b-a,2)
    return {'schema':1,'status':'REVIEW','measure':measure,
            'differences':differences,'observations':observations,
            'actions_performed':'NONE',
            'limitations':['No information proves identical host, route, conditions or test duration',
                           'This is NOT a real VPN transport comparison or DPI resistance measurement',
                           'No kernel sysctl, sockets, clients, servers or profiles changed']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('before',type=Path)
    p.add_argument('after',type=Path)
    p.add_argument('--strict',action='store_true')
    args=p.parse_args(argv)
    try:
        result=compare(_read(args.before),_read(args.after))
    except (ReviewError,OSError,ValueError,TypeError,OverflowError):
        print(json.dumps({'schema':1,'status':'FAIL','reason':'INVALID_OR_INCOMPATIBLE_REPORT',
                          'actions_performed':'NONE'}))
        return 1
    print(json.dumps(result,indent=2,sort_keys=True))
    return 2 if args.strict else 0

if __name__=='__main__':
    sys.exit(main())
