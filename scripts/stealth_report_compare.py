#!/usr/bin/env python3
"""Compare TWO existing redacted r40/r41 HTTPS audit reports without network.

Only compares observable status/protocol metadata. Never attributes changes to
DPI resistance, VPN transport, IP reputation or a specific network condition.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

MAX_SIZE = 128 * 1024
STATES = ('PASS', 'UNVERIFIED', 'REVIEW', 'FAIL')
FIELDS = ('tls', 'alpn', 'cipher', 'http_code', 'http_version', 'reason', 'security_headers',
          'redirect_to_expected_https', 'downloaded_bytes')
KNOWN_CHECKS = frozenset(('dns', 'tls12', 'tls13', 'http_head', 'missing_page',
                           'host_mismatch', 'http2_alpn', 'unknown_sni',
                           'missing_sni', 'http80', 'post_handshake_records',
                           'parallel_tls13', 'http2_request',
                           'node_api_external', 'client_socks_https', 'tcp443',
                           'large_http2_asset'))


class Invalid(ValueError):
    pass


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                st.st_size > MAX_SIZE or st.st_mode & 0o022):
            raise Invalid('UNSAFE_INPUT_FILE')
        content = os.read(fd, MAX_SIZE + 1)
    finally:
        os.close(fd)
    if len(content) > MAX_SIZE:
        raise Invalid('REPORT_TOO_LARGE')
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise Invalid('DUPLICATE_JSON_KEY')
            out[k] = v
        return out
    try:
        obj = json.loads(content, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Invalid('NONFINITE')))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Invalid('INVALID_JSON') from exc
    if (not isinstance(obj, dict) or obj.get('schema') != 1 or
            obj.get('scope') != 'EXPLICIT_OWNED_ENDPOINT_ONLY' or
            obj.get('client_or_dpi_stealth_proven') != 'NO' or
            not isinstance(obj.get('checks'), dict) or not obj['checks']):
        raise Invalid('UNKNOWN_OR_UNTRUSTED_SCHEMA')
    return obj


def compare(before, after):
    for item in (before, after):
        if (item.get('schema') != 1 or item.get('scope') != 'EXPLICIT_OWNED_ENDPOINT_ONLY' or
                item.get('client_or_dpi_stealth_proven') != 'NO' or
                not isinstance(item.get('checks'), dict)):
            raise Invalid('REPORT_SCHEMA_MISMATCH')
    names = sorted(set(before['checks']) | set(after['checks']))
    if set(names) - KNOWN_CHECKS:
        raise Invalid('UNRECOGNIZED_CHECK_NAME')
    changed, added, removed = [], [], []
    for name in names:
        if name not in before['checks']:
            added.append(name)
            continue
        if name not in after['checks']:
            removed.append(name)
            continue
        a, b = before['checks'][name], after['checks'][name]
        if not isinstance(a, dict) or not isinstance(b, dict) or a.get('status') not in STATES or b.get('status') not in STATES:
            raise Invalid('CHECK_SCHEMA_MISMATCH')
        different = [field for field in ('status',) + FIELDS if a.get(field) != b.get(field)]
        if different:
            changed.append({'check': name, 'different_fields': different,
                            'status_before': a['status'], 'status_after': b['status']})
    return {'schema': 1, 'status': 'REVIEW', 'changed': changed, 'added_checks': added,
            'removed_checks': removed,
            'observations': ['NOT_A_DPI_RESISTANCE_MEASUREMENT',
                             'NETWORK_LOCATION_AND_CLIENTHELO_NOT_CONTROLLED',
                             'SAME_HOST_AND_NETWORK_NOT_ATTESTED'],
            'actions_performed': 'NONE', 'secrets_or_addresses_printed': 'NO'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before', type=Path)
    p.add_argument('after', type=Path)
    p.add_argument('--strict', action='store_true', help='exit 2 if a check got worse/was removed')
    args = p.parse_args(argv)
    try:
        report = compare(read(args.before), read(args.after))
    except (Invalid, OSError, TypeError, OverflowError):
        print(json.dumps({'schema': 1, 'status': 'FAIL', 'reason': 'INVALID_OR_UNSAFE_INPUT'}))
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    worsening = any(STATES.index(item['status_after']) > STATES.index(item['status_before'])
                    for item in report['changed'])
    return 2 if args.strict and (worsening or report['removed_checks']) else 0


if __name__ == '__main__':
    sys.exit(main())
