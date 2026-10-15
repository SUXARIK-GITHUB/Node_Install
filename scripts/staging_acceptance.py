#!/usr/bin/env python3
"""Offline evidence gate. Never runs installation, live probes, ssh, docker or UFW.

Human-submitted evidence is NOT independently verified by this parser. PASS
means the signed-off checklist has results and artifacts, not a system audit.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys

ORDINARY = (
    'snapshot_restore', 'provider_console', 'ssh_password_reentry', 'ipv4_only_reboot',
    'docker_local_remnanode', 'panel_source_acl_allow_deny', 'nginx_cert_acme_renew',
    'tls_12_13_hsts_http80', 'vpn_raw_vision_client', 'vpn_xhttp_client',
    'dns_ipv4_egress', 'rkn_kernel_fault_reboot', 'night_restart_external_canary',
    'monitoring_and_rollback'
)
CASCADE = ORDINARY + (
    'two_distinct_vps', 'two_distinct_domains_and_keys',
    'panel_nodes_profiles_hosts_and_internal_squads',
    'service_user_only_exit_inbound', 'xray_core_test_both_profiles',
    'client_exit_public_ipv4_verified', 'entry_no_direct_during_exit_outage',
    'entry_no_client_dns_leak', 'peer_invalid_credentials_denied',
    'peer_rotation_and_rollback', 'tcp_udp_dns_double_hop',
    'pair_maintenance_stagger', 'reverse_boot_order', '24h_soak'
)


class EvidenceError(Exception):
    pass


def template(role, sha):
    require(isinstance(sha,str) and re.fullmatch(r'[0-9a-f]{64}',sha), 'INVALID_SHA256')
    return {'schema':1, 'role':role, 'source_zip_sha256':sha,
            'status':'NOT_ACCEPTED',
            'checks': {key:{'result':'BLOCKED', 'tested_at_utc':None,
                            'evidence_reference':None, 'operator':None}
                       for key in (ORDINARY if role == 'ordinary' else CASCADE)}}


def require(value, msg):
    if not value:
        raise EvidenceError(msg)


def evaluate(obj):
    require(isinstance(obj,dict) and set(obj) ==
            {'schema','role','source_zip_sha256','status','checks'},'SCHEMA_FIELDS_INVALID')
    role = obj['role']
    require(role in ('ordinary','cascade'), 'ROLE_INVALID')
    expected = ORDINARY if role == 'ordinary' else CASCADE
    require(obj['schema'] == 1 and type(obj['schema']) is int,'SCHEMA_INVALID')
    require(isinstance(obj['source_zip_sha256'],str) and
            re.fullmatch(r'[0-9a-f]{64}', obj['source_zip_sha256']), 'SHA_INVALID')
    require(isinstance(obj['checks'],dict) and set(obj['checks']) == set(expected),
            'CHECKS_MISSING_OR_UNEXPECTED')
    failed, blocked = [], []
    for key in expected:
        val = obj['checks'][key]
        require(isinstance(val,dict) and set(val) ==
                {'result','tested_at_utc','evidence_reference','operator'},
                'INVALID_EVIDENCE_FIELDS_'+key)
        result = val['result']
        require(result in ('PASS','FAIL','BLOCKED'), 'INVALID_RESULT_'+key)
        if result == 'PASS':
            date = val['tested_at_utc']
            require(isinstance(date,str) and 'T' in date, 'MISSING_TIMESTAMP_'+key)
            try:
                moment = dt.datetime.fromisoformat(date.replace('Z','+00:00'))
            except ValueError as exc:
                raise EvidenceError('INVALID_TIMESTAMP_'+key) from exc
            require(moment.tzinfo is not None and moment.utcoffset() == dt.timedelta(0),
                    'NOT_UTC_'+key)
            require(isinstance(val['evidence_reference'],str) and
                    re.fullmatch(r'[A-Za-z0-9_.:/#-]{3,256}',val['evidence_reference']),
                    'MISSING_EVIDENCE_REFERENCE_'+key)
            require(isinstance(val['operator'],str) and
                    re.fullmatch(r'[A-Za-z0-9_.@-]{2,96}',val['operator']),
                    'MISSING_OPERATOR_'+key)
        elif result == 'FAIL':
            failed.append(key)
        else:
            blocked.append(key)
    require(obj['status'] in ('NOT_ACCEPTED','ACCEPTED'), 'INVALID_STATUS')
    # Claiming ACCEPTED while any checks are not PASS is a hard failure.
    require(obj['status'] != 'ACCEPTED' or not (failed or blocked),
            'FALSE_ACCEPTED_STATUS')
    return {'pass':len(expected)-len(failed)-len(blocked),
            'total':len(expected),'failed':failed,'blocked':blocked,
            'all_checked':not (failed or blocked)}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--create-template',choices=['ordinary','cascade'])
    group.add_argument('--evaluate',type=Path)
    p.add_argument('--zip-sha256',help='required with --create-template; use independent archive digest')
    ns=p.parse_args(argv)
    try:
        if ns.create_template:
            print(json.dumps(template(ns.create_template,ns.zip_sha256), indent=2))
            return 0
        obj=json.loads(ns.evaluate.read_text(encoding='utf-8'))
        result=evaluate(obj)
    except (EvidenceError, OSError, ValueError, TypeError) as exc:
        print('ACCEPTANCE=INVALID '+(str(exc) if isinstance(exc,EvidenceError)
              else type(exc).__name__),file=sys.stderr)
        return 2
    accepted = result['all_checked'] and obj['status'] == 'ACCEPTED'
    print('EVIDENCE_REVIEW='+ ('COMPLETE' if accepted else 'INCOMPLETE') +
          ' PASS='+str(result['pass'])+' TOTAL='+str(result['total']))
    print('FAIL='+','.join(result['failed']))
    print('BLOCKED='+','.join(result['blocked']))
    print('LIVE_EVIDENCE=OPERATOR_SUBMITTED_NOT_AUTOMATICALLY_VERIFIED')
    return 0 if accepted else 1


if __name__ == '__main__':
    sys.exit(main())
