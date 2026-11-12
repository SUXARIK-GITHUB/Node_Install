#!/usr/bin/env python3
"""Read-only comparison of an OWN server XHTTP import profile and client export.

Accepts an Xray client JSON or a private file containing ONE vless:// URI.
Never prints credentials, URI, SNI, host, IP, short ID, or private key. Does
not access the Panel, run Xray, modify files or promise a working handshake.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import parse_qsl, urlsplit

from xhttp_profile import Invalid, _decode_key, read_private_json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAX_FILE = 2 * 1024 * 1024
MAX_URI = 8192
MODES = frozenset(('auto', 'stream-up', 'stream-one', 'packet-up'))
FINGERPRINTS_TO_TEST = frozenset(('chrome', 'firefox', 'safari'))


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Invalid('DUPLICATE_CLIENT_FIELD')
        obj[key] = value
    return obj


def _load_private_bytes(path):
    """Refuse linked, readable-by-others and oversized client secret exports."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or
                meta.st_uid != os.geteuid() or meta.st_mode & 0o077 or
                not 0 < meta.st_size <= MAX_FILE):
            raise Invalid('CLIENT_FILE_OWNER_PERMS_OR_SIZE')
        result = os.read(fd, MAX_FILE + 1)
        if len(result) > MAX_FILE:
            raise Invalid('CLIENT_FILE_TOO_LARGE')
        return result
    finally:
        os.close(fd)


def _one_vless_uri(raw):
    if len(raw) > MAX_URI or not raw.startswith('vless://') or any(ord(ch) < 32 for ch in raw):
        raise Invalid('INVALID_VLESS_URI')
    try:
        uri = urlsplit(raw)
        if uri.scheme != 'vless' or uri.password is not None or uri.username is None:
            raise Invalid('INVALID_VLESS_URI')
        if uri.port is None or not 1 <= uri.port <= 65535 or not uri.hostname:
            raise Invalid('INVALID_VLESS_URI')
        items = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, max_num_fields=40)
    except (ValueError, UnicodeError) as exc:
        raise Invalid('INVALID_VLESS_URI') from exc
    values = _unique(items)
    if len(values) != len(items):
        raise Invalid('DUPLICATE_URI_PARAMETER')
    # Never return the user UUID or remote hostname: only the transport contract.
    return {'network': values.get('type'), 'security': values.get('security'),
            'flow': values.get('flow', ''), 'sni': values.get('sni'),
            'public_key': values.get('pbk'), 'short_id': values.get('sid'),
            'fingerprint': values.get('fp'), 'host': values.get('host'),
            'path': values.get('path'), 'mode': values.get('mode', 'auto')}


def _client_json(obj):
    if not isinstance(obj, dict):
        raise Invalid('CLIENT_JSON_NOT_OBJECT')
    choices = obj.get('outbounds')
    if choices is None and obj.get('protocol') == 'vless':
        choices = [obj]
    if not isinstance(choices, list) or len(choices) > 64:
        raise Invalid('CLIENT_OUTBOUNDS_INVALID')
    vless = [o for o in choices if isinstance(o, dict) and o.get('protocol') == 'vless']
    if len(vless) != 1:
        raise Invalid('CLIENT_MUST_HAVE_EXACTLY_ONE_VLESS_OUTBOUND')
    node = vless[0]
    stream = node.get('streamSettings')
    settings = node.get('settings')
    if not isinstance(stream, dict) or not isinstance(settings, dict):
        raise Invalid('CLIENT_SETTINGS_INVALID')
    users = settings.get('vnext')
    if (not isinstance(users, list) or len(users) != 1 or
            not isinstance(users[0], dict) or not isinstance(users[0].get('users'), list) or
            len(users[0]['users']) != 1 or not isinstance(users[0]['users'][0], dict)):
        raise Invalid('CLIENT_USER_STRUCTURE_UNEXPECTED')
    user = users[0]['users'][0]
    direct_tags = {o.get('tag') for o in choices
                   if isinstance(o, dict) and o.get('protocol') == 'freedom' and
                   isinstance(o.get('tag'), str)}
    routing = obj.get('routing')
    rules = routing.get('rules', []) if isinstance(routing, dict) else []
    explicit_direct = isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get('outboundTag') in direct_tags for rule in rules)
    default_direct = bool(choices and isinstance(choices[0], dict) and
                          choices[0].get('protocol') == 'freedom')
    reality = stream.get('realitySettings') or {}
    xhttp = stream.get('xhttpSettings') or {}
    if not isinstance(reality, dict) or not isinstance(xhttp, dict):
        raise Invalid('CLIENT_TRANSPORT_SETTINGS_INVALID')
    return {'network': stream.get('network'), 'security': stream.get('security'),
            'flow': user.get('flow', ''), 'sni': reality.get('serverName'),
            'public_key': reality.get('publicKey') or reality.get('password'),
            'short_id': reality.get('shortId'),
            'fingerprint': reality.get('fingerprint'), 'host': xhttp.get('host'),
            'path': xhttp.get('path'), 'mode': xhttp.get('mode', 'auto'),
            'direct_route_review': explicit_direct, 'direct_default_review': default_direct}


def read_client(path):
    raw = _load_private_bytes(path)
    try:
        text = raw.decode('utf-8').strip()
        if text.startswith('vless://'):
            return _one_vless_uri(text)
        obj = json.loads(text, object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Invalid('NONFINITE_CLIENT_JSON')))
    except (ValueError, UnicodeError) as exc:
        raise Invalid('INVALID_CLIENT_EXPORT') from exc
    return _client_json(obj)


def audit(server, client):
    issues, observations = [], []
    if not isinstance(server, dict) or not isinstance(client, dict):
        raise Invalid('PROFILE_NOT_OBJECT')
    inbounds = server.get('inbounds')
    if not isinstance(inbounds, list) or len(inbounds) != 1 or not isinstance(inbounds[0], dict):
        raise Invalid('SERVER_MUST_HAVE_ONE_INBOUND')
    inbound = inbounds[0]
    stream = inbound.get('streamSettings')
    settings = inbound.get('settings')
    if not isinstance(stream, dict) or not isinstance(settings, dict):
        raise Invalid('SERVER_SETTINGS_INVALID')
    reality = stream.get('realitySettings')
    xhttp = stream.get('xhttpSettings')
    if not isinstance(reality, dict) or not isinstance(xhttp, dict):
        raise Invalid('SERVER_XHTTP_OR_REALITY_MISSING')
    if (inbound.get('protocol') != 'vless' or stream.get('network') != 'xhttp' or
            stream.get('security') != 'reality' or settings.get('flow') != '' or
            xhttp.get('mode') != 'auto'):
        issues.append('SERVER_UNREVIEWED_TRANSPORT')
    if client.get('network') != 'xhttp' or client.get('security') != 'reality':
        issues.append('CLIENT_NOT_XHTTP_REALITY')
    if client.get('flow') not in (None, ''):
        issues.append('CLIENT_MUST_NOT_USE_VISION')
    sni = reality.get('serverNames')
    if not isinstance(sni, list) or len(sni) != 1 or not isinstance(sni[0], str):
        raise Invalid('SERVER_SNI_INVALID')
    if client.get('sni') != sni[0]:
        issues.append('CLIENT_SNI_MISMATCH')
    if xhttp.get('host') != client.get('host') or not isinstance(xhttp.get('host'), str):
        issues.append('CLIENT_XHTTP_HOST_MISMATCH_OR_MISSING')
    if xhttp.get('path') != client.get('path') or not isinstance(xhttp.get('path'), str):
        issues.append('CLIENT_XHTTP_PATH_MISMATCH_OR_MISSING')
    if client.get('mode') not in MODES:
        issues.append('CLIENT_XHTTP_MODE_UNKNOWN')
    elif client.get('mode') != 'auto':
        observations.append('CLIENT_FORCED_XHTTP_MODE_REQUIRES_LIVE_REVIEW')
    ids = reality.get('shortIds')
    if not isinstance(ids, list) or client.get('short_id') not in ids:
        issues.append('CLIENT_SHORT_ID_MISMATCH')
    try:
        private = _decode_key(reality.get('privateKey'))
        public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        user_public = _decode_key(client.get('public_key'))
        if public != user_public:
            issues.append('CLIENT_REALITY_PUBLIC_KEY_MISMATCH')
    except (Invalid, ValueError, TypeError):
        issues.append('INVALID_REALITY_KEYPAIR_OR_CLIENT_PUBLIC_KEY')
    fp = client.get('fingerprint')
    if not isinstance(fp, str) or not fp:
        issues.append('CLIENT_FINGERPRINT_MISSING')
    elif fp not in FINGERPRINTS_TO_TEST:
        observations.append('FINGERPRINT_REQUIRES_HYBRID_TLS_COMPATIBILITY_REVIEW')
    if client.get('direct_route_review') is True:
        observations.append('EXPLICIT_DIRECT_ROUTING_PRESENT_REVIEW_CLIENT_PRIVACY_POLICY')
    if client.get('direct_default_review') is True:
        observations.append('CLIENT_DEFAULT_OUTBOUND_DIRECT_POSSIBLE_FALLBACK')
    observations.extend(('CLIENT_CORE_VERSION_NOT_VERIFIED', 'PANEL_HOST_EXPORT_NOT_LIVE_TESTED',
                         'REALITY_HANDSHAKE_AND_DPI_NOT_TESTED', 'DNS_IPV6_AND_DIRECT_FALLBACK_NOT_TESTED'))
    return {'schema': 1, 'status': 'FAIL' if issues else 'STATIC_MATCH',
            'issues': sorted(set(issues)), 'observations': sorted(set(observations)),
            'live_connectivity': 'UNVERIFIED', 'server_modified': 'NO',
            'secrets_or_addresses_printed': 'NO'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--server', required=True, type=Path, help='private 0600 existing XHTTP server template')
    p.add_argument('--client', required=True, type=Path, help='private 0600 Xray JSON or one vless URI')
    p.add_argument('--strict', action='store_true', help='nonzero on static mismatches')
    opts = p.parse_args(argv)
    try:
        result = audit(read_private_json(opts.server), read_client(opts.client))
    except (Invalid, OSError, ValueError, TypeError, OverflowError):
        result = {'schema': 1, 'status': 'FAIL', 'issues': ['INVALID_OR_UNSAFE_INPUT'],
                  'live_connectivity': 'UNVERIFIED', 'server_modified': 'NO',
                  'secrets_or_addresses_printed': 'NO'}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
