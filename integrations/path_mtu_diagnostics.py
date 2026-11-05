#!/usr/bin/env python3
"""Bounded read-only IPv4 route/Path-MTU diagnostic for a user-owned target.

Without --probe, only kernel route/link metadata is read. With --probe up to
four ICMP echo requests are sent to the explicitly specified address; failed
pings are not proof of a Path-MTU black hole (ICMP may simply be filtered).
No sysctl, qdisc, route, NIC, MTU, SSH or firewall change. No peer IP is logged.
"""
import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys

IFNAME = re.compile(r'[a-zA-Z0-9_.:@-]{1,64}\Z')
PROBE_SIZES = (1200, 1360, 1400, 1472)  # IPv4 ICMP payload bytes, max 1500-byte frame


class DiagnosticError(ValueError):
    pass


def validate_target(target, allow_private=False):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise DiagnosticError('INVALID_TARGET_IPV4') from exc
    if ip.version != 4 or ip.is_multicast or ip.is_unspecified:
        raise DiagnosticError('INVALID_TARGET_IPV4')
    if not ip.is_global and not allow_private:
        raise DiagnosticError('PRIVATE_TARGET_REQUIRES_EXPLICIT_ALLOW_PRIVATE')
    return str(ip)


def _command(argv, timeout=5):
    if not shutil.which(argv[0]):
        return None
    try:
        result = subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                                timeout=timeout,check=False)
        if len(result.stdout)>65536 or result.returncode != 0:
            return None
        return result.stdout
    except (subprocess.TimeoutExpired,OSError,UnicodeError):
        return None


def parse_route(data):
    try:
        rows=json.loads(data)
        if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):
            raise ValueError('route schema')
        item=rows[0]
        dev=item.get('dev')
        if not isinstance(dev,str) or not IFNAME.fullmatch(dev):
            raise ValueError('invalid route device')
        mtu=item.get('mtu')
        if mtu is not None and (type(mtu) is not int or not 576<=mtu<=1048576):
            raise ValueError('invalid route mtu')
        return {'interface':dev,'cached_route_mtu':mtu}
    except (ValueError,TypeError,KeyError):
        return None


def parse_link(data, expected_iface):
    try:
        rows=json.loads(data)
        if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):
            raise ValueError('link schema')
        row=rows[0]
        mtu=row.get('mtu')
        if row.get('ifname')!=expected_iface or type(mtu) is not int or not 576<=mtu<=1048576:
            raise ValueError('link invalid')
        return mtu
    except (ValueError,TypeError):
        return None


def inspect(target, *, allow_private=False, probe=False, run=None):
    address=validate_target(target,allow_private)
    execute=run or _command
    route_text=execute(['ip','-4','-j','route','get',address])
    route=parse_route(route_text) if route_text is not None else None
    if route is None:
        return {'schema':1,'status':'REVIEW','route':'UNAVAILABLE_OR_AMBIGUOUS',
                'system_changes':'NONE','probe_sent':False}
    iface=route['interface']
    link_text=execute(['ip','-j','link','show','dev',iface])
    link_mtu=parse_link(link_text,iface) if link_text is not None else None
    result={'schema':1,'status':'PASS' if link_mtu else 'REVIEW',
            'interface':iface,'interface_mtu':link_mtu,
            'cached_route_mtu':route['cached_route_mtu'],
            'probe_sent':False,'system_changes':'NONE',
            'notes':['ICMP may be blocked; packet loss is not proof of an MTU problem',
                     'Destination address, gateway and interface addresses are omitted']}
    if probe:
        if not link_mtu:
            result['probe_status']='SKIPPED_UNKNOWN_LINK_MTU'
            return result
        # For IPv4: ICMP payload + 8B ICMP + 20B IP header.
        upper=min(link_mtu,route['cached_route_mtu'] or link_mtu)-28
        sizes=[size for size in PROBE_SIZES if size<=upper]
        results=[]
        for size in sizes:
            success=execute(['ping','-4','-n','-c','1','-W','1','-M','do','-s',str(size),address],timeout=3)
            results.append({'ip_packet_bytes':size+28,'response':'REPLY' if success is not None else 'NO_REPLY_OR_BLOCKED'})
        result['probe_sent']=bool(sizes)
        result['probes']=results
        result['probe_status']='INCONCLUSIVE' if not results or any(x['response']!='REPLY' for x in results) else 'RESPONDED_AT_TESTED_SIZES'
        if result['probe_status']=='INCONCLUSIVE':
            result['status']='REVIEW'
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',required=True,help='IPv4 of a server you control (not printed in report)')
    p.add_argument('--allow-private',action='store_true')
    p.add_argument('--probe',action='store_true',help='explicitly send at most four ICMP echo requests')
    a=p.parse_args(argv)
    try:
        report=inspect(a.target,allow_private=a.allow_private,probe=a.probe)
    except DiagnosticError as exc:
        print(json.dumps({'status':'STOP','error':str(exc),'system_changes':'NONE'}))
        return 2
    print(json.dumps(report,sort_keys=True,indent=2))
    return 0 if report.get('status')=='PASS' else 1


if __name__=='__main__':
    sys.exit(main())
