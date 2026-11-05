#!/usr/bin/env python3
"""Read-only, secret-free combined Nginx/Unix/TLS selfsteal acceptance probe.

Uses the installed site and its owned local Unix listener; no credentials or
traffic contents are displayed. Does NOT authenticate REALITY and makes no DPI
claims. Optional public HTTPS validation invokes the existing installed checker
but never changes host state or config. Requires real installation for PASS.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

try:
    from selfsteal_health import snapshot as static_snapshot, regular_bytes, SETTINGS
    from selfsteal_runtime_probe import probe, CheckError, DOMAIN
except ImportError:
    from integrations.selfsteal_health import snapshot as static_snapshot, regular_bytes, SETTINGS
    from integrations.selfsteal_runtime_probe import probe, CheckError, DOMAIN

SOCKET = Path('run/vkarmani-selfsteal/nginx.sock')
CHECKER = Path('usr/local/sbin/vkarmani-selfsteal-check')


def _nginx_test(timeout=7):
    if not shutil.which('nginx'):
        return 'UNAVAILABLE'
    try:
        p = subprocess.run(['nginx','-t'],stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
        return 'PASS' if p.returncode == 0 else 'FAIL'
    except (OSError, subprocess.TimeoutExpired):
        return 'UNAVAILABLE'


def _public_check(timeout=30, checker=Path('/usr/local/sbin/vkarmani-selfsteal-check')):
    if checker.is_symlink() or not checker.is_file() or not checker.stat().st_mode & 0o111:
        return 'UNAVAILABLE'
    try:
        p = subprocess.run([str(checker)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
        return 'PASS' if p.returncode == 0 else 'FAIL'
    except (OSError, subprocess.TimeoutExpired):
        return 'UNAVAILABLE'


def verify(root=Path('/'), *, cafile=None, public_check=False,
           tls_probe=None, nginx_test=None, public_run=None):
    """Dependency injection allows tests without probing or modifying the host."""
    root = Path(root)
    static = static_snapshot(root)
    checks = {'static_permissions_and_routes':static['status'],
              'local_unix_tls_https':'NOT_CHECKED',
              'nginx_syntax':'NOT_CHECKED',
              'public_site':'NOT_REQUESTED'}
    observations = list(static['observations'])
    config_bytes = regular_bytes(root/SETTINGS, 16384)
    try:
        config = json.loads(config_bytes) if config_bytes is not None else None
        domain = config.get('domain') if isinstance(config,dict) else None
        if not isinstance(domain,str) or not DOMAIN.fullmatch(domain):
            raise ValueError('INVALID_DOMAIN')
    except (ValueError,UnicodeError,TypeError):
        domain = None
        observations.append('NODE_DOMAIN_UNAVAILABLE')
    if static['status']=='STATIC_CHECKS_OK' and domain is not None:
        try:
            result = (tls_probe or probe)(domain, root/SOCKET, proxy_v1=True, cafile=cafile)
            checks['local_unix_tls_https'] = 'PASS' if result['status']=='PASS' else 'REVIEW'
            # No local socket content, domain, peer address or certificate private key is copied.
            checks['tls_version'] = result.get('tls_version')
            checks['alpn'] = result.get('alpn')
            checks['http_code'] = result.get('http_code')
        except (CheckError,OSError,ValueError,TimeoutError):
            checks['local_unix_tls_https'] = 'FAIL'
            observations.append('SELFSTEAL_LOCAL_TLS_PROBE_FAILED')
    if root == Path('/'):
        checks['nginx_syntax'] = (nginx_test or _nginx_test)()
    else:
        checks['nginx_syntax'] = 'SKIPPED_FIXTURE'
    if public_check:
        checks['public_site'] = (public_run or _public_check)() if root == Path('/') else 'SKIPPED_FIXTURE'
    required = (checks['static_permissions_and_routes']=='STATIC_CHECKS_OK' and
                checks['local_unix_tls_https']=='PASS' and
                checks['nginx_syntax'] in ('PASS','SKIPPED_FIXTURE') and
                (not public_check or checks['public_site']=='PASS'))
    return {'schema':1,'status':'PASS' if required else 'REVIEW',
            'mode':static['mode'], 'checks':checks,
            'observations':sorted(set(observations)),
            'limitations':['No Xray authentication or client traffic is tested',
                           'An HTTPS site alone does not establish DPI resistance',
                           'No network, firewall, key, SSH or service modifications'],
            'actions_performed':'NONE'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--strict',action='store_true')
    p.add_argument('--public-check',action='store_true',help='also invoke installed public HTTPS checker (outbound to your site)')
    a=p.parse_args(argv)
    result=verify(public_check=a.public_check)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
    return 2 if a.strict and result['status']!='PASS' else 0


if __name__=='__main__':
    sys.exit(main())
