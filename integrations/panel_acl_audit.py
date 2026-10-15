#!/usr/bin/env python3
"""Read-only comparison between managed Node API UFW ACL and configured panel IPv4.

Never edits UFW, Panel, RKN or Node configuration. Does NOT independently
prove the provider firewall or whether a panel TCP connection can succeed.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class ACLProblem(Exception):
    pass


def require(ok, marker):
    if not ok:
        raise ACLProblem(marker)


def config(path):
    p = Path(path)
    s = p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'CONFIG_NOT_REGULAR')
    require(stat.S_IMODE(s.st_mode) & 0o077 == 0, 'CONFIG_MUST_BE_PRIVATE')
    if os.geteuid() == 0:
        require(s.st_uid == 0, 'CONFIG_NOT_OWNED_BY_ROOT')
    obj = json.loads(p.read_text(encoding='utf-8'))
    require(isinstance(obj, dict) and obj.get('installation_mode') == 'secret-key-only',
            'CONFIG_UNSUPPORTED')
    port, ips = obj.get('node_port'), obj.get('panel_ipv4')
    require(type(port) is int and 1 <= port <= 65535, 'NODE_PORT_INVALID')
    require(isinstance(ips, list) and 1 <= len(ips) <= 16, 'PANEL_IPS_INVALID')
    valid = set()
    for value in ips:
        require(isinstance(value, str), 'PANEL_IPV4_INVALID')
        try:
            a = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise ACLProblem('PANEL_IPV4_INVALID') from exc
        require(a.is_global and str(a) == value, 'PANEL_IPV4_NOT_PUBLIC')
        valid.add(value)
    return port, valid


def audit(text, port, ips):
    """Inspect human-readable `ufw status`, strictly reject ambiguous lines."""
    lines = text.splitlines()
    require(any(line.strip() == 'Status: active' for line in lines), 'UFW_NOT_ACTIVE')
    matched = set()
    suspicious = []
    # UFW's default English C locale is required to safely parse its format.
    for line in lines:
        # Status: lines are column-aligned, possibly with a bracketed rule ID.
        stripped = re.sub(r'^\s*\[\s*\d+\]\s*', '', line)
        cols = re.split(r'\s{2,}', stripped.strip())
        if len(cols) < 3:
            continue
        target, action, source = cols[:3]
        dest = target.split(' ',1)[0]
        if dest not in (str(port), str(port) + '/tcp', str(port) + '/udp'):
            continue
        # Every rule on this port is reviewed: no ALLOW v6/wildcard or UDP.
        if action != 'ALLOW IN' or dest != str(port) + '/tcp':
            suspicious.append('RULE_NOT_TCP_ALLOW')
            continue
        if source in ('Anywhere', 'Anywhere (v6)') or '(v6)' in target:
            suspicious.append('API_WILDCARD_RULE')
            continue
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+(?:/32)?',source):
            ip = source.removesuffix('/32')
            try:
                ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                suspicious.append('INVALID_UFW_SOURCE')
            else:
                matched.add(ip)
        else:
            suspicious.append('AMBIGUOUS_UFW_SOURCE')
    if suspicious:
        raise ACLProblem('API_UFW_UNEXPECTED_RULE_' + suspicious[0])
    require(matched == ips,
            'API_UFW_PANEL_SET_MISMATCH expected=' + str(len(ips)) + ' actual=' + str(len(matched)))
    return True


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default='/etc/vkarmani-node/config.json')
    p.add_argument('--ufw-status-file', type=Path,
                   help='offline saved output of `LC_ALL=C ufw status`, otherwise read real UFW')
    args = p.parse_args(argv)
    try:
        port, ips = config(args.config)
        if args.ufw_status_file:
            content = args.ufw_status_file.read_text(encoding='utf-8')
        else:
            result = subprocess.run(['ufw','status'], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=15,
                                    check=False, env={'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
            require(result.returncode == 0, 'UFW_STATUS_FAILED')
            content = result.stdout
        audit(content,port,ips)
    except (ACLProblem, OSError, ValueError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        print('PANEL_ACL=FAIL reason=' + (str(exc) if isinstance(exc, ACLProblem)
              else type(exc).__name__), file=sys.stderr)
        return 1
    print('PANEL_ACL=PASS CONFIG_MATCHES_UFW; RKN_AND_PROVIDER_AND_TCP_CONNECTIVITY_NOT_VERIFIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
