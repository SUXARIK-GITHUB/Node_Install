#!/usr/bin/env python3
"""VKarmani XHTTP+REALITY alternative import template, without panel/network mutation.

Consumes the EXISTING RAW import template and REALITY keypair. One inbound per
profile; this script does not install a second listener or alter a running node.
All printed diagnostics are secret-free. Used by both fresh install and explicit
--prepare-xhttp on already completed VKarmani installations.
"""
import argparse
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Invalid(Exception):
    pass


def read_private_json(path):
    """No links/special files; bounds, duplicate JSON keys, private-file ownership."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Invalid('SOURCE_UNREADABLE_OR_SYMLINK') from exc
    try:
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_size > 2 * 1024 * 1024):
                raise Invalid('SOURCE_TYPE_OWNER_PERMISSIONS_OR_SIZE_INVALID')
            content = f.read(2 * 1024 * 1024 + 1)
    except OSError as exc:
        raise Invalid('SOURCE_READ_ERROR') from exc
    if len(content) > 2 * 1024 * 1024:
        raise Invalid('SOURCE_TOO_LARGE')

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise Invalid('DUPLICATE_JSON_FIELD')
            obj[key] = value
        return obj

    def reject_nonfinite(_value):
        raise Invalid('NONFINITE_JSON_NUMBER')

    try:
        value = json.loads(content.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=reject_nonfinite)
    except (UnicodeError, ValueError) as exc:
        raise Invalid('INVALID_SOURCE_JSON') from exc
    if not isinstance(value, dict):
        raise Invalid('SOURCE_NOT_OBJECT')
    return value


def _decode_key(raw):
    if not isinstance(raw, str) or not re.fullmatch(r'[A-Za-z0-9_-]{42,44}', raw):
        raise Invalid('INVALID_REALITY_KEY_ENCODING')
    try:
        result = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True)
    except ValueError as exc:
        raise Invalid('INVALID_REALITY_KEY_ENCODING') from exc
    if len(result) != 32:
        raise Invalid('INVALID_REALITY_KEY_LENGTH')
    return result


def xhttp_path(private_key, domain):
    """Stable path across restarts; no extra secret file and no ShortID disclosure."""
    key = _decode_key(private_key)
    digest = hmac.new(key, b'vkarmani-xhttp-path-v1\x00' + domain.encode('ascii'),
                      hashlib.sha256).hexdigest()
    return '/' + digest[:32]


def build_xhttp(root):
    cfg = read_private_json(root / 'config.json')
    keys = read_private_json(root / 'reality.json')
    raw = read_private_json(root / 'profile.json')

    domain = cfg.get('domain')
    public_ip = cfg.get('public_ipv4')
    if (not isinstance(domain, str) or domain != domain.lower()
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{1,250})[a-z0-9]', domain)
            or '.' not in domain):
        raise Invalid('CONFIG_DOMAIN_INVALID')
    try:
        public = ipaddress.IPv4Address(public_ip)
        if not public.is_global:
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise Invalid('CONFIG_PUBLIC_IPV4_INVALID') from exc
    private = _decode_key(keys.get('private_key'))
    public_key = _decode_key(keys.get('public_key'))
    if X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw) != public_key:
        raise Invalid('REALITY_KEYPAIR_MISMATCH')
    shortid = keys.get('short_id')
    if not isinstance(shortid, str) or not re.fullmatch(r'[0-9a-f]{16}', shortid):
        raise Invalid('REALITY_SHORTID_INVALID')

    inbounds = raw.get('inbounds')
    if not isinstance(inbounds, list) or len(inbounds) != 1 or not isinstance(inbounds[0], dict):
        raise Invalid('RAW_TEMPLATE_MUST_HAVE_ONE_INBOUND')
    inbound = inbounds[0]
    if (inbound.get('protocol') != 'vless' or inbound.get('port') != 443
            or inbound.get('listen') not in ('0.0.0.0', public_ip)
            or not isinstance(inbound.get('tag'), str) or not inbound['tag'].startswith('VK_RAW_REALITY_')):
        raise Invalid('RAW_TEMPLATE_IDENTITY_MISMATCH')
    settings = inbound.get('settings')
    stream = inbound.get('streamSettings')
    if (not isinstance(settings, dict) or settings.get('decryption') != 'none'
            or settings.get('clients') != [] or settings.get('flow') != 'xtls-rprx-vision'
            or settings.get('fallbacks') or not isinstance(stream, dict)):
        raise Invalid('RAW_TEMPLATE_SETTINGS_MISMATCH')
    if (stream.get('network') != 'raw' or stream.get('security') != 'reality'
            or 'xhttpSettings' in stream or stream.get('sockopt', {}).get('acceptProxyProtocol', False) is not False):
        raise Invalid('RAW_TEMPLATE_TRANSPORT_MISMATCH')
    reality = stream.get('realitySettings')
    if (not isinstance(reality, dict) or reality.get('target') != '/dev/shm/nginx.sock'
            or type(reality.get('xver')) is not int or reality['xver'] != 1
            or reality.get('serverNames') != [domain]
            or reality.get('privateKey') != keys['private_key']
            or reality.get('shortIds') != [shortid]
            or reality.get('minClientVer') != '0.0.0'):
        raise Invalid('RAW_TEMPLATE_REALITY_SELFSTEAL_MISMATCH')
    sniff = inbound.get('sniffing')
    if (not isinstance(sniff, dict) or sniff.get('enabled') is not True
            or sniff.get('routeOnly') is not True
            or sorted(sniff.get('destOverride', [])) != ['http', 'quic', 'tls']):
        raise Invalid('RAW_TEMPLATE_SNIFFING_MISMATCH')

    # Preserve exactly the operator-reviewed DNS, routing, security identity,
    # existing tag and all existing other profile data. Do not add a listener.
    xhttp = copy.deepcopy(raw)
    node = xhttp['inbounds'][0]
    node['settings']['flow'] = ''  # Vision is incompatible with XHTTP.
    s = node['streamSettings']
    s['network'] = 'xhttp'
    s['xhttpSettings'] = {'host': domain,
                          'path': xhttp_path(keys['private_key'], domain),
                          'mode': 'auto'}
    return xhttp


def atomic_write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise Invalid('OUTPUT_SYMLINK_REFUSED')
    name = path.with_name(path.name + '.new-' + secrets.token_hex(8))
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if name.exists():
            name.unlink()


def main():
    parser = argparse.ArgumentParser(description='Private XHTTP template generation; no live changes')
    parser.add_argument('action', choices=('render', 'compare'))
    parser.add_argument('--root', type=Path, default=Path('/etc/vkarmani-node'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    desired = build_xhttp(args.root)
    if args.action == 'render':
        atomic_write_json(args.output, desired)
        print('XHTTP_TEMPLATE_RENDER=PASS; LIVE_NODE=UNCHANGED')
    else:
        actual = read_private_json(args.output)
        if desired != actual:
            raise Invalid('EXISTING_XHTTP_TEMPLATE_DIFFERS_REFUSE_OVERWRITE')
        print('XHTTP_TEMPLATE_IDEMPOTENT=PASS')


if __name__ == '__main__':
    try:
        main()
    except Invalid as exc:
        print('XHTTP_TEMPLATE=FAIL ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Never print exception text: it might contain source values or paths.
        print('XHTTP_TEMPLATE=FAIL UNEXPECTED_VALIDATION_OR_IO_FAILURE', file=sys.stderr)
        sys.exit(1)
