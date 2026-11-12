#!/usr/bin/env python3
"""Offline compatibility matrix for operator-recorded REALITY/XHTTP trials.

The tool accepts ONLY constrained test metadata, never actual Xray profiles,
UUIDs, domains, SNI, IPs or secret key material. Results are NOT independent
verification of network resistance or client egress; no connection is made.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 32768
VERSION = re.compile(r'^(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)$')
APPS = frozenset(('xray', 'v2rayng', 'v2rayn', 'mihomo', 'singbox', 'hiddify', 'other'))
FINGERPRINTS = frozenset(('chrome', 'firefox', 'safari', 'edge', 'ios', 'qq',
                           'randomized', 'randomizednoalpn', 'android', 'other'))
TRANSPORTS = frozenset(('raw', 'xhttp'))
KEY_SHARE = frozenset(('PRESENT', 'ABSENT', 'UNKNOWN'))
EGRESS = frozenset(('EXPECTED_VPN_IP', 'DIRECT_IP_OBSERVED', 'NOT_MEASURED'))
NEW_CORE_HYBRID = (26, 9, 8)


class Invalid(ValueError):
    pass


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise Invalid('INVALID_CORE_VERSION')
    return tuple(int(x) for x in value.split('.'))


def _read(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_BYTES
                or st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise Invalid('UNSAFE_MATRIX_FILE_PERMISSIONS_OR_SIZE')
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_BYTES:
        raise Invalid('MATRIX_TOO_LARGE')
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise Invalid('DUPLICATE_JSON_FIELD')
            result[k] = v
        return result
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('NONFINITE_JSON')))
    except (ValueError, UnicodeError) as exc:
        raise Invalid('INVALID_MATRIX_JSON') from exc


def review(data):
    if not isinstance(data, dict) or set(data) != {'schema', 'server_core', 'trials'} or data.get('schema') != 1:
        raise Invalid('MATRIX_SCHEMA_INVALID')
    server_core = version(data['server_core'])
    trials = data['trials']
    if not isinstance(trials, list) or not 1 <= len(trials) <= 32:
        raise Invalid('TRIAL_COUNT_INVALID')
    results = []
    for index, trial in enumerate(trials, 1):
        keys = {'app', 'client_core', 'fingerprint', 'transport', 'key_share',
                'attempts', 'successes', 'egress'}
        if not isinstance(trial, dict) or set(trial) != keys:
            raise Invalid('TRIAL_FIELDS_INVALID')
        app = trial['app']
        if app not in APPS or not isinstance(app, str):
            raise Invalid('CLIENT_APP_UNKNOWN')
        client = trial['client_core']
        if client is not None:
            version(client)
        fp, transport, key_share, egress = (trial['fingerprint'], trial['transport'],
                                             trial['key_share'], trial['egress'])
        if fp not in FINGERPRINTS or transport not in TRANSPORTS or key_share not in KEY_SHARE or egress not in EGRESS:
            raise Invalid('TRIAL_ENUM_INVALID')
        attempts, successes = trial['attempts'], trial['successes']
        if (type(attempts) is not int or type(successes) is not int or
                not 1 <= attempts <= 100 or not 0 <= successes <= attempts):
            raise Invalid('TRIAL_ATTEMPTS_INVALID')
        notes = []
        if server_core >= NEW_CORE_HYBRID and key_share != 'PRESENT':
            notes.append('SERVER_REQUIRES_VERIFIED_HYBRID_KEY_SHARE_COMPATIBILITY')
        if fp.startswith('randomized'):
            notes.append('RANDOMIZED_CLIENTHELLO_MUST_BE_RETESTED_ACROSS_RESTARTS')
        if client is None:
            notes.append('CLIENT_CORE_VERSION_NOT_RECORDED')
        if attempts < 5:
            notes.append('TOO_FEW_ATTEMPTS_FOR_EVEN_LOCAL_RELIABILITY')
        if successes != attempts:
            notes.append('CONNECTION_FAILURES_OBSERVED')
        if egress == 'DIRECT_IP_OBSERVED':
            notes.append('DIRECT_EGRESS_REPORTED_BLOCK_RELEASE')
        elif egress == 'NOT_MEASURED':
            notes.append('EGRESS_NOT_ATTESTED')
        # Absence of reported failures is not proof against DPI or direct leaks.
        observed = ('OBSERVED_COMPATIBLE_IN_THIS_TEST_ONLY' if not notes else 'REVIEW')
        results.append({'trial': index, 'app': app, 'transport': transport,
                        'fingerprint': fp, 'attempts': attempts, 'successes': successes,
                        'status': observed, 'observations': notes})
    return {'schema': 1, 'status': ('REVIEW' if any(t['status'] == 'REVIEW' for t in results)
                                   else 'OBSERVED_COMPATIBLE_IN_TEST_ONLY'),
            'trials': results, 'server_core': data['server_core'],
            'limitations': ['OPERATOR_SUBMITTED_MEASUREMENTS_NOT_VERIFIED',
                            'RESULT_NOT_TRANSFERABLE_TO_OTHER_ISPS_OR_CLIENT_VERSIONS',
                            'NO_DPI_DETECTION_OR_PRIVACY_GUARANTEE'],
            'server_or_client_modified': 'NO', 'secrets_or_addresses_printed': 'NO'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', type=Path, required=True, help='private 0600 JSON with test metadata only')
    p.add_argument('--strict', action='store_true')
    args = p.parse_args(argv)
    try:
        result = review(_read(args.evidence))
    except (Invalid, ValueError, UnicodeError, TypeError, OSError):
        result = {'schema': 1, 'status': 'FAIL', 'reason': 'UNSAFE_OR_INVALID_MATRIX_EVIDENCE',
                  'server_or_client_modified': 'NO', 'secrets_or_addresses_printed': 'NO'}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result['status'] == 'FAIL' or args.strict and result['status'] == 'REVIEW' else 0


if __name__ == '__main__':
    sys.exit(main())
