#!/usr/bin/env python3
"""Read-only readiness gate for optional R23 transport bundles.

A generated reference bundle is NEVER a running service. Check private file
integrity, role boundaries, authentication consistency and required external
runtime steps without activating Xray, TUN, UFW, NAT, systemd or Panel.
Use `--strict` in automation: syntactically correct but incomplete bundles
return exit 2 (REVIEW), not a false PASS.
"""
import argparse
import base64
import configparser
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

try:
    from optional_transports import domain, Invalid
except ImportError:
    from integrations.optional_transports import domain, Invalid

FILES = {
    'xhttp-tls': frozenset(('profile-xhttp-tls.json', 'nginx-location.conf', 'REVIEW.txt')),
    'hysteria2': frozenset(('profile-hysteria2.json', 'client-reference.json', 'REVIEW.txt')),
    'awg2': frozenset(('awg0-server.conf', 'client-reference.conf', 'REVIEW.txt')),
}
MAX_FILE = 256 * 1024
KEY = re.compile(r'[A-Za-z0-9+/]{43}=\Z')
HEADER = re.compile(r'([0-9]{1,10})(?:-([0-9]{1,10}))?\Z')


class CheckError(Exception):
    pass


def _private_files(folder, mode):
    """Do not follow symlinks or read credentials outside a private folder."""
    folder = Path(folder).absolute()
    # A symlinked parent could silently redirect access to a different bundle.
    # Do not dereference paths from an unverified root/user-supplied location.
    if any(parent.is_symlink() for parent in (folder, *folder.parents)):
        raise CheckError('PRIVATE_BUNDLE_SYMLINK_COMPONENT')
    if not folder.is_dir():
        raise CheckError('PRIVATE_BUNDLE_DIRECTORY_REQUIRED')
    st = folder.lstat()
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise CheckError('PRIVATE_BUNDLE_PERMISSIONS_INVALID')
    if os.geteuid() == 0 and st.st_uid != 0:
        # Root must not treat an unprivileged user's writable config as trusted.
        raise CheckError('PRIVATE_BUNDLE_OWNER_INVALID')
    files = {p.name for p in folder.iterdir()}
    if files != FILES[mode]:
        raise CheckError('BUNDLE_FILES_MISSING_OR_UNEXPECTED')
    result = {}
    for name in sorted(files):
        path = folder / name
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_size > MAX_FILE or stat.S_IMODE(info.st_mode) & 0o077 or
                    (os.geteuid() == 0 and info.st_uid != 0)):
                raise CheckError('BUNDLE_FILE_TYPE_OR_PERMISSIONS_INVALID')
            with os.fdopen(fd, 'rb') as f:
                fd = -1
                raw = f.read(MAX_FILE + 1)
            if len(raw) > MAX_FILE:
                raise CheckError('BUNDLE_FILE_TOO_LARGE')
            result[name] = raw
        finally:
            if fd >= 0: os.close(fd)
    return result


def _json(raw):
    def reject_duplicates(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise CheckError('DUPLICATE_JSON_KEY')
            obj[k] = v
        return obj
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=reject_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(CheckError('NONFINITE_JSON_VALUE')))
    except (ValueError, UnicodeError) as exc:
        raise CheckError('INVALID_JSON') from exc


def _one_inbound(cfg, protocol):
    if not isinstance(cfg, dict) or not isinstance(cfg.get('inbounds'), list) or len(cfg['inbounds']) != 1:
        raise CheckError('ONE_INBOUND_REQUIRED')
    entry = cfg['inbounds'][0]
    if not isinstance(entry, dict) or entry.get('protocol') != protocol:
        raise CheckError('UNEXPECTED_INBOUND_PROTOCOL')
    return entry


def _xhttp(bundle, expected_domain):
    cfg = _json(bundle['profile-xhttp-tls.json'])
    inbound = _one_inbound(cfg, 'vless')
    stream = inbound.get('streamSettings', {})
    settings = inbound.get('settings', {})
    if (inbound.get('listen') != '127.0.0.1' or
            type(inbound.get('port')) is not int or not 1025 <= inbound['port'] <= 65535 or
            inbound['port'] in (2222, 3000, 443) or
            not isinstance(stream, dict) or stream.get('network') != 'xhttp' or
            stream.get('security') != 'none' or
            not isinstance(settings, dict) or settings.get('decryption') != 'none'):
        raise CheckError('XHTTP_LOCAL_INBOUND_CONTRACT_INVALID')
    transport = stream.get('xhttpSettings')
    path = transport.get('path') if isinstance(transport, dict) else None
    if (not isinstance(path, str) or not re.fullmatch(r'/(?:[A-Za-z0-9_-]{3,32}/){0,2}[A-Za-z0-9_-]{10,96}', path) or
            transport.get('host') != expected_domain or transport.get('mode') not in ('auto', 'stream-up', 'packet-up')):
        raise CheckError('XHTTP_PATH_HOST_OR_MODE_INVALID')
    snippet = bundle['nginx-location.conf'].decode('ascii', errors='strict')
    if (f'location ^~ {path}/ {{' not in snippet or
            f'grpc_pass grpc://127.0.0.1:{inbound["port"]};' not in snippet or
            'listen 443' in snippet or 'proxy_pass' in snippet):
        raise CheckError('NGINX_AND_XHTTP_ROUTE_DIVERGED')
    if not isinstance(settings.get('clients'), list):
        raise CheckError('XHTTP_CLIENTS_LIST_MISSING')
    # Empty users are an intentionally inert reference, never ready to serve.
    return ['XRAY_BINARY_AND_VERSION_UNVERIFIED', 'XRAY_TEST_AND_BACKEND_NOT_VERIFIED',
            'NGINX_GRPC_ROUTE_NOT_APPLIED_OR_TESTED',
            'XRAY_AUTHENTICATION_CLIENTS_NOT_CONFIGURED' if not settings['clients']
            else 'XRAY_USERS_NOT_PROVEN_TO_MATCH_PANEL',
            'HTTPS_H2_AND_REAL_CLIENT_NOT_VERIFIED']


def _hysteria(bundle, expected_domain):
    cfg = _json(bundle['profile-hysteria2.json'])
    client = _json(bundle['client-reference.json'])
    inbound = _one_inbound(cfg, 'hysteria')
    stream = inbound.get('streamSettings')
    settings = inbound.get('settings')
    if (not isinstance(stream, dict) or not isinstance(settings, dict) or
            settings.get('version') != 2 or stream.get('security') != 'tls' or
            stream.get('method', stream.get('network')) != 'hysteria' or
            not isinstance(stream.get('hysteriaSettings'), dict) or
            stream['hysteriaSettings'].get('version') != 2 or
            type(inbound.get('port')) is not int or not 1 <= inbound['port'] <= 65535 or
            inbound['port'] in (53, 80, 2222, 3000)):
        raise CheckError('HYSTERIA2_INBOUND_CONTRACT_INVALID')
    users = settings.get('users')
    if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
        raise CheckError('HYSTERIA2_USERS_INVALID')
    auth = users[0].get('auth')
    if not isinstance(auth, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,96}', auth):
        raise CheckError('HYSTERIA2_AUTH_INVALID')
    certs = stream.get('tlsSettings', {}).get('certificates') if isinstance(stream.get('tlsSettings'), dict) else None
    if (not isinstance(certs, list) or len(certs) != 1 or not isinstance(certs[0], dict) or
            certs[0].get('certificateFile') != f'/etc/letsencrypt/live/{expected_domain}/fullchain.pem' or
            certs[0].get('keyFile') != f'/etc/letsencrypt/live/{expected_domain}/privkey.pem'):
        raise CheckError('HYSTERIA2_CERTIFICATE_CONTRACT_INVALID')
    if (not isinstance(client, dict) or client.get('server') != expected_domain or
            client.get('auth') != auth or client.get('udp_port') != inbound['port'] or
            client.get('tls_server_name') != expected_domain):
        raise CheckError('HYSTERIA2_CLIENT_SERVER_MISMATCH')
    if (not isinstance(cfg.get('outbounds'), list) or any(not isinstance(o, dict) or
            o.get('protocol') != 'freedom' for o in cfg['outbounds'])):
        raise CheckError('HYSTERIA2_OUTBOUND_CONTRACT_INVALID')
    return ['XRAY_BINARY_AND_HYSTERIA_SUPPORT_UNVERIFIED',
            'CERTIFICATE_ACCESS_AND_RENEWAL_UNVERIFIED',
            'UDP_PORT_FIREWALL_AND_SERVICE_UNCONFIGURED',
            'QUIC_HANDSHAKE_AND_REAL_CLIENT_NOT_VERIFIED']


def _sections(raw):
    cfg = configparser.ConfigParser(interpolation=None, strict=True)
    cfg.optionxform = str
    try:
        cfg.read_string(raw.decode('ascii'))
    except (ValueError, UnicodeError, configparser.Error) as exc:
        raise CheckError('AWG2_CONFIG_PARSE_FAILED') from exc
    if set(cfg.sections()) != {'Interface', 'Peer'}:
        raise CheckError('AWG2_SECTIONS_INVALID')
    return cfg


def _public(private):
    if not isinstance(private, str) or not KEY.fullmatch(private):
        raise CheckError('AWG2_PRIVATE_KEY_ENCODING_INVALID')
    try:
        data = base64.b64decode(private, validate=True)
        if len(data) != 32:
            raise ValueError('wrong length')
        der = bytes.fromhex('302e020100300506032b656e04220420') + data
        p = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                           input=der, capture_output=True, timeout=8, check=False)
        prefix = bytes.fromhex('302a300506032b656e032100')
        if p.returncode or not p.stdout.startswith(prefix) or len(p.stdout) != len(prefix) + 32:
            raise CheckError('AWG2_OPENSSL_PUBLIC_KEY_FAILED')
        return base64.b64encode(p.stdout[-32:]).decode('ascii')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise CheckError('AWG2_OPENSSL_KEY_CHECK_UNAVAILABLE') from exc


def _awg(bundle, expected_domain):
    server = _sections(bundle['awg0-server.conf'])
    client = _sections(bundle['client-reference.conf'])
    sp, cp = server['Peer'], client['Peer']
    si, ci = server['Interface'], client['Interface']
    if (sp.get('PublicKey') != _public(ci.get('PrivateKey')) or
            cp.get('PublicKey') != _public(si.get('PrivateKey')) or
            sp.get('PresharedKey') != cp.get('PresharedKey') or
            not KEY.fullmatch(sp.get('PresharedKey', ''))):
        raise CheckError('AWG2_PUBLIC_KEY_OR_PSK_MISMATCH')
    try:
        import ipaddress
        a = ipaddress.ip_interface(si.get('Address'))
        b = ipaddress.ip_interface(ci.get('Address'))
        if (a.version != 4 or b.version != 4 or b.ip not in a.network or
                b.ip == a.ip or sp.get('AllowedIPs') != str(b.ip) + '/32' or
                cp.get('AllowedIPs') != '0.0.0.0/0' or
                cp.get('Endpoint') != f'{expected_domain}:{si["ListenPort"]}' or
                not 1025 <= int(si['ListenPort']) <= 65535):
            raise ValueError('invalid addressing')
        if (not 1280 <= int(si['MTU']) <= 1500 or si['MTU'] != ci.get('MTU')):
            raise ValueError('invalid mtu')
        fields = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4')
        if any(si[k] != ci.get(k) for k in fields):
            raise ValueError('obfuscation differs')
        if not (0 < int(si['Jc']) <= 65535 and 0 <= int(si['Jmin']) < int(si['Jmax']) <= 65535):
            raise ValueError('junk values invalid')
        if any(not 0 <= int(si[k]) <= 65535 for k in ('S1', 'S2', 'S3', 'S4')):
            raise ValueError('padding invalid')
        if int(si['S1']) + 56 == int(si['S2']) or int(si['S3']) == int(si['S2']) + 28:
            raise ValueError('equal packet lengths')
        intervals = []
        for k in ('H1','H2','H3','H4'):
            if si[k] != ci.get(k):
                raise ValueError('H mismatch')
            match = HEADER.fullmatch(si[k])
            if match is None:
                raise ValueError('invalid H range')
            lo = int(match[1]); hi = int(match[2] or match[1])
            if not 1 <= lo <= hi <= 2147483647:
                raise ValueError('H outside range')
            intervals.append((lo, hi))
        for i, (lo, hi) in enumerate(intervals):
            if any(i != j and not (hi < otherlo or otherhi < lo) for j, (otherlo, otherhi) in enumerate(intervals)):
                raise ValueError('overlapping headers')
    except (ValueError, KeyError, TypeError) as exc:
        raise CheckError('AWG2_ADDRESS_MTU_OR_OBFUSCATION_MISMATCH') from exc
    return ['AWG2_RUNTIME_AND_INTERFACE_SUPPORT_UNVERIFIED',
            'TUN_AND_ROUTE_OVERLAP_UNVERIFIED', 'IPV4_FORWARDING_NAT_AND_UFW_NOT_CONFIGURED',
            'MTU_AND_DNS_CLIENT_PATH_NOT_VERIFIED', 'AWG2_REAL_CLIENT_NOT_VERIFIED']


def check(mode, bundle, expected_domain, role='ordinary'):
    if mode not in FILES:
        raise CheckError('UNSUPPORTED_MODE')
    try:
        domain(expected_domain)
    except Invalid as exc:
        raise CheckError('EXPECTED_DOMAIN_INVALID') from exc
    if role != 'ordinary':
        raise CheckError('OPTIONAL_DIRECT_TRANSPORT_NOT_ALLOWED_IN_CASCADE')
    files = _private_files(bundle, mode)
    try:
        if mode == 'xhttp-tls':
            needs = _xhttp(files, expected_domain)
        elif mode == 'hysteria2':
            needs = _hysteria(files, expected_domain)
        else:
            needs = _awg(files, expected_domain)
    except UnicodeError as exc:
        raise CheckError('BUNDLE_ENCODING_INVALID') from exc
    return {'schema': 1, 'status': 'REVIEW', 'mode': mode, 'static_bundle': 'VALID',
            'missing_verification': needs,
            'actions_performed': 'NONE',
            'limitations': ['No running service, firewall, NAT, Panel or client is configured',
                            'Valid JSON/INI alone is not proof the target runtime supports this transport',
                            'Never mark production-ready without independent staging acceptance']}



def xray_config_test(mode, bundle, executable):
    """Explicit, local, read-only Core validation; never activate the service.

    Runtime stdout/stderr are suppressed because Xray may print configuration
    fragments or other sensitive material on failure. No automatic downloads.
    """
    if mode not in ('xhttp-tls', 'hysteria2'):
        raise CheckError('XRAY_RUNTIME_TEST_ONLY_FOR_XRAY_BUNDLES')
    _private_files(bundle, mode)  # validate paths and file ownership first
    executable = Path(executable)
    if not executable.is_absolute() or any(p.is_symlink() for p in (executable, *executable.parents)):
        raise CheckError('XRAY_EXECUTABLE_ABSOLUTE_PATH_REQUIRED')
    try:
        st = executable.stat()
    except OSError as exc:
        raise CheckError('XRAY_EXECUTABLE_NOT_FOUND') from exc
    if (not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or
            st.st_mode & 0o022 or (os.geteuid() == 0 and st.st_uid != 0)):
        raise CheckError('XRAY_EXECUTABLE_UNTRUSTED')
    name = 'profile-xhttp-tls.json' if mode == 'xhttp-tls' else 'profile-hysteria2.json'
    try:
        proc = subprocess.run([str(executable), 'run', '-test', '-config', str(Path(bundle).absolute()/name)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=12, check=False,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent'})
    except subprocess.TimeoutExpired as exc:
        raise CheckError('XRAY_RUNTIME_TEST_TIMEOUT') from exc
    except OSError as exc:
        raise CheckError('XRAY_RUNTIME_TEST_EXEC_FAILED') from exc
    if proc.returncode:
        raise CheckError('XRAY_RUNTIME_CONFIG_REJECTED')
    return 'PASS'  # syntax and local binary compatibility only, NOT a live connection


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=sorted(FILES))
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--expected-domain', required=True)
    parser.add_argument('--role', choices=('ordinary','entry','exit'), default='ordinary')
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--xray-bin', type=Path, help='explicit trusted local Xray binary for read-only run -test; no service changes')
    args = parser.parse_args(argv)
    try:
        report = check(args.mode, args.bundle, args.expected_domain, args.role)
        if args.xray_bin is not None:
            report['xray_runtime_config_test'] = xray_config_test(args.mode, args.bundle, args.xray_bin)
            report['limitations'].append('Xray -test validates config only; runtime listeners and clients remain unverified')
    except (CheckError, OSError, ValueError, TypeError, configparser.Error) as exc:
        code = str(exc) if isinstance(exc, CheckError) else type(exc).__name__
        print(json.dumps({'schema':1, 'status':'FAIL', 'reason':code,
                          'actions_performed':'NONE'}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2 if args.strict else 0


if __name__ == '__main__':
    sys.exit(main())
