#!/usr/bin/env python3
"""Compare TWO redacted owned-endpoint audits from distinct network vantage points.

Offline interpretation only. Evidence can indicate a path-specific failure; it
cannot attribute it to an ISP, DPI device, TSPU, RKN, or a particular cause.
No destination IP, domain, client identifier, secrets or raw headers are printed.
"""
import argparse
import json
from pathlib import Path
import sys

from stealth_report_compare import Invalid, KNOWN_CHECKS, STATES, read


class ReviewError(ValueError):
    pass


def _status(report, name):
    check = report['checks'].get(name)
    if check is None:
        return None
    if not isinstance(check, dict) or check.get('status') not in STATES:
        raise ReviewError('INVALID_CHECK_SCHEMA')
    return check['status']


def _validated(report):
    if (not isinstance(report, dict) or report.get('schema') != 1 or
            report.get('scope') != 'EXPLICIT_OWNED_ENDPOINT_ONLY' or
            report.get('client_or_dpi_stealth_proven') != 'NO' or
            not isinstance(report.get('checks'), dict) or
            not report['checks'] or set(report['checks']) - KNOWN_CHECKS):
        raise ReviewError('UNSUPPORTED_REDACTED_REPORT')
    for name in report['checks']:
        _status(report, name)
    transfer = report['checks'].get('large_http2_asset')
    if transfer is not None and 'downloaded_bytes' in transfer:
        count = transfer['downloaded_bytes']
        if type(count) is not int or not 0 <= count <= 262144:
            raise ReviewError('INVALID_TRANSFER_COUNT')


def review(control, affected):
    """All differential categories require a PASS from a control network.

    If measurements are missing, not comparable, or the control itself failed,
    refuse to turn them into a censorship attribution.
    """
    _validated(control)
    _validated(affected)
    differences, missing = [], []
    observations = []
    signals = (
        ('dns', 'DNS_RESOLUTION_DIFFERS'),
        ('tcp443', 'TCP443_REACHABILITY_DIFFERS'),
        ('tls13', 'TLS13_HANDSHAKE_OR_HTTPS_DIFFERS'),
        ('http2_request', 'HTTP2_APPLICATION_RESPONSE_DIFFERS'),
        ('large_http2_asset', 'LARGE_HTTPS_RESPONSE_DIFFERS'),
    )
    for name, code in signals:
        a, b = _status(control, name), _status(affected, name)
        if a is None or b is None:
            missing.append(name)
        elif a != 'PASS':
            observations.append('CONTROL_NOT_PASS_' + name.upper())
        elif b != 'PASS':
            differences.append({'check': name, 'code': code, 'control': 'PASS',
                                'affected': b})
    if (_status(control, 'large_http2_asset') == 'PASS' and
            _status(affected, 'large_http2_asset') == 'PASS'):
        before = control['checks']['large_http2_asset'].get('downloaded_bytes')
        after = affected['checks']['large_http2_asset'].get('downloaded_bytes')
        if before is not None and after is not None and before != after:
            differences.append({'check': 'large_http2_asset',
                                'code': 'STATIC_ASSET_TRANSFER_SIZE_DIFFERS',
                                'control': 'PASS', 'affected': 'PASS'})
    if _status(control, 'tcp443') != 'PASS' or _status(affected, 'tcp443') != 'PASS':
        observations.append('CANNOT_ISOLATE_TLS_FROM_TCP_CONNECTIVITY')
    if _status(control, 'dns') != 'PASS' or _status(affected, 'dns') != 'PASS':
        observations.append('DNS_DIFFERENCE_MAY_REFLECT_RESOLVER_OR_IPV6_POLICY')
    status = ('REVIEW' if differences else 'INSUFFICIENT' if missing or observations
              else 'NO_DIFFERENCE_OBSERVED')
    return {
        'schema': 1, 'status': status, 'differential_signals': differences,
        'missing_or_incomparable_checks': sorted(set(missing)),
        'observations': sorted(set(observations)),
        'interpretation': 'NETWORK_PATH_DIFFERENCE_NOT_PROOF_OF_CENSORSHIP',
        'source_attribution': 'NOT_POSSIBLE', 'same_endpoint_attested_by_operator': 'YES',
        'data_from_live_tests': 'PROVIDED_BY_OPERATOR_NOT_INDEPENDENTLY_VERIFIED',
        'actions_performed': 'NONE', 'addresses_or_credentials_printed': 'NO',
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--control', type=Path, required=True, help='redacted report from known-good network')
    p.add_argument('--affected', type=Path, required=True, help='redacted report from other network')
    p.add_argument('--confirm-same-owned-endpoint', action='store_true',
                   help='operator confirms same domain, IPv4, site file and versions')
    p.add_argument('--strict', action='store_true', help='nonzero unless no difference and complete evidence')
    args = p.parse_args(argv)
    if not args.confirm_same_owned_endpoint:
        p.error('explicit same-owned-endpoint confirmation required')
    try:
        report = review(read(args.control), read(args.affected))
    except (Invalid, ReviewError, ValueError, OSError, TypeError, OverflowError):
        print(json.dumps({'schema': 1, 'status': 'FAIL', 'reason': 'INVALID_OR_UNSAFE_REPORT'}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if args.strict and report['status'] != 'NO_DIFFERENCE_OBSERVED' else 0


if __name__ == '__main__':
    sys.exit(main())
