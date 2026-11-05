#!/usr/bin/env python3
"""Read-only local selfsteal/Nginx permission audit (not a live TLS probe).

No network connections; no secret, domain, client IP, certificate path or raw
config is printed. Use /usr/local/sbin/vkarmani-selfsteal-check for live TLS and
HTTP/2 verification on an installed node. Never changes files or services.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import re
import stat
import sys

MODES = frozenset(('local', 'max.ru', 'ya.ru', 'rutube.ru', 'mail.ru'))
SOCKET_DIR = 'run/vkarmani-selfsteal'
CONF = 'etc/nginx/conf.d/20-vkarmani-selfsteal.conf'
SETTINGS = 'etc/vkarmani-node/config.json'
INDEX = 'var/www/vkarmani-node/site/index.html'
MAX_FILE = 512 * 1024


def regular_bytes(path, maximum=MAX_FILE):
    try:
        s = path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > maximum:
            return None
        return path.read_bytes()
    except (OSError, ValueError):
        return None


def _stat(path):
    try:
        if path.is_symlink():
            return {'exists': True, 'kind': 'symlink', 'mode': None}
        st = path.lstat()
    except (OSError, ValueError):
        return {'exists': False, 'kind': 'missing', 'mode': None}
    kind = 'directory' if stat.S_ISDIR(st.st_mode) else ('socket' if stat.S_ISSOCK(st.st_mode) else 'other')
    return {'exists': True, 'kind': kind, 'mode': f'{stat.S_IMODE(st.st_mode):04o}',
            'uid': st.st_uid, 'gid': st.st_gid}


def snapshot(root=Path('/')):
    """Only whitelist paths and boolean/static metadata; no private contents."""
    root = Path(root)
    notes = []
    cfg = regular_bytes(root/SETTINGS, 16384)
    mode = 'unknown'
    try:
        config = json.loads(cfg) if cfg is not None else None
        if not isinstance(config, dict):
            raise ValueError('config not found or invalid')
        selected = config.get('reality_mode', 'local')
        if selected not in MODES:
            notes.append('UNKNOWN_REALITY_MODE')
        else:
            mode = 'local' if selected == 'local' else 'hybrid'
    except (ValueError, UnicodeError, TypeError):
        notes.append('CONFIG_NOT_READABLE_OR_INVALID')
    base = root / SOCKET_DIR
    directory = _stat(base)
    try:
        worker_gid = grp.getgrnam('www-data').gr_gid
    except KeyError:
        worker_gid = None
        notes.append('NGINX_WORKER_GROUP_NOT_FOUND')
    if directory.get('kind') != 'directory':
        notes.append('SELFSTEAL_RUNTIME_DIRECTORY_MISSING_OR_UNSAFE')
    elif (directory['uid'] != 0 or directory['gid'] != worker_gid or
          directory['mode'] != '0750'):
        notes.append('SELFSTEAL_DIRECTORY_PERMISSIONS_MISMATCH')
    # Always return only socket type and existence, never the socket contents.
    sock_names = ('nginx.sock', 'cover.sock') if mode == 'hybrid' else ('nginx.sock',)
    sockets = {name: _stat(base/name)['kind'] for name in sock_names}
    for name, kind in sockets.items():
        if kind != 'socket':
            notes.append('REQUIRED_' + name.replace('.','_').upper() + '_MISSING')
    config_bytes = regular_bytes(root/CONF)
    checks = {
        'nginx_config_readable': config_bytes is not None,
        'expected_socket_listener': False,
        'public_root_referenced': False,
        'deny_unknown_routes': False,
        'ssl_certificate_configured': False,
    }
    if config_bytes is None:
        notes.append('NGINX_CONFIG_NOT_READABLE')
    else:
        expected = 'cover.sock' if mode == 'hybrid' else 'nginx.sock'
        checks['expected_socket_listener'] = ('listen unix:/run/vkarmani-selfsteal/'+expected).encode() in config_bytes
        checks['public_root_referenced'] = b'root /var/www/vkarmani-node/site;' in config_bytes
        checks['deny_unknown_routes'] = b'location / { return 404; }' in config_bytes
        checks['ssl_certificate_configured'] = b'ssl_certificate /etc/letsencrypt/live/' in config_bytes
        for key, success in checks.items():
            if not success:
                notes.append(key.upper() + '_UNVERIFIED')
    public_page = regular_bytes(root/INDEX,128*1024)
    checks['public_homepage_readable'] = public_page is not None
    if public_page is None:
        notes.append('PUBLIC_HOMEPAGE_MISSING_OR_UNSAFE')
    # No credential/IP/domain leakage; stable, machine-readable status.
    return {'schema': 1, 'status': 'REVIEW' if notes else 'STATIC_CHECKS_OK',
            'mode': mode, 'runtime_dir': {'exists': directory['exists'], 'kind': directory['kind'],
                                          'permissions_expected': directory.get('mode') == '0750' and
                                          directory.get('uid') == 0 and directory.get('gid') == worker_gid},
            'sockets': sockets, 'checks': checks, 'observations': notes,
            'limitations': ['This is a static permission/config inspection, not a REALITY, TLS or HTTP/2 connection test',
                            'Use the installed selfsteal-check script plus staging client/Panel E2E testing'],
            'actions_performed': 'NONE'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--strict', action='store_true')
    args=p.parse_args(argv)
    result=snapshot()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 2 if args.strict and result['status']!='STATIC_CHECKS_OK' else 0


if __name__=='__main__':sys.exit(main())
