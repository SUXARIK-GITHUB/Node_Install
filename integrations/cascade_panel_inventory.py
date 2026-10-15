#!/usr/bin/env python3
"""Offline, strict normalized *evidence* gate for the Remnawave cascade.

Input is an operator-prepared normalization of API v3.x results, NOT arbitrary
raw Panel JSON. Never calls Panel, changes squads, writes users or prints secrets.
Evidence may be forged; this verifies consistency, not provenance or live traffic.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys

import cascade_deployment as deployment


class InventoryError(Exception):
    pass


def ensure(test, reason):
    if not test:
        raise InventoryError(reason)


def exactly(obj, fields, reason):
    ensure(isinstance(obj, dict) and set(obj) == set(fields), reason)


def unique(items, key, marker):
    values = [item[key] for item in items]
    ensure(len(set(values)) == len(values), marker)
    return {item[key]: item for item in items}


def check(entry, exit_, observed, *, now=None):
    """Checks role profile assignment, access scopes and only-entry public Host."""
    deployment.validate_bundle(entry, 'entry')
    deployment.validate_bundle(exit_, 'exit')
    ensure(entry['pair_id'] == exit_['pair_id'], 'PAIR_IDS_DIFFER')
    ensure(entry['self'] == exit_['peer'] | {'private_key': entry['self']['private_key']},
           'ENTRY_PEER_PUBLIC_MISMATCH')
    ensure(exit_['self'] == entry['peer'] | {'private_key': exit_['self']['private_key']},
           'EXIT_PEER_PUBLIC_MISMATCH')
    ensure(entry['bridge'] == exit_['bridge'], 'BRIDGE_ID_DIFFER')
    exactly(observed, ('schema', 'panel_api_major', 'nodes', 'profiles', 'squads', 'hosts', 'users'),
            'INVENTORY_SCHEMA_INVALID')
    ensure(type(observed['schema']) is int and observed['schema'] == 1,
           'INVENTORY_VERSION_INVALID')
    ensure(type(observed['panel_api_major']) is int and observed['panel_api_major'] == 3,
           'PANEL_API_VERSION_NOT_V3')
    for name in ('nodes', 'profiles', 'squads', 'hosts', 'users'):
        ensure(isinstance(observed[name], list), 'INVENTORY_COLLECTION_INVALID_' + name)
        ensure(len(observed[name]) < 10000, 'INVENTORY_COLLECTION_TOO_LARGE_' + name)
    ensure(len(observed['nodes']) == 2 and len(observed['profiles']) == 2 and
           len(observed['squads']) == 2 and len(observed['hosts']) == 1 and
           len(observed['users']) == 1, 'NOT_ISOLATED_TWO_NODE_TEST_INVENTORY')
    for n in observed['nodes']:
        exactly(n, ('role', 'uuid', 'address', 'port', 'profile_uuid', 'active_inbounds'),
                'NODE_SCHEMA_INVALID')
        ensure(n['role'] in ('entry', 'exit') and isinstance(n['uuid'], str)
               and isinstance(n['profile_uuid'], str), 'NODE_ROLE_INVALID')
        ensure(type(n['port']) is int and 1 <= n['port'] <= 65535, 'NODE_PORT_INVALID')
        ensure(isinstance(n['active_inbounds'], list), 'NODE_INBOUNDS_INVALID')
    nodes = unique(observed['nodes'], 'role', 'NODE_ROLE_DUPLICATE')
    unique(observed['nodes'], 'uuid', 'NODE_UUID_DUPLICATE')
    for p in observed['profiles']:
        exactly(p, ('uuid', 'inbound_tags'), 'PROFILE_SCHEMA_INVALID')
        ensure(isinstance(p['uuid'], str) and isinstance(p['inbound_tags'], list),
               'PROFILE_INVALID')
    profiles = unique(observed['profiles'], 'uuid', 'PROFILE_UUID_DUPLICATE')
    for role, bundle in (('entry', entry), ('exit', exit_)):
        n = nodes.get(role)
        ensure(isinstance(n, dict), 'NODE_ROLE_MISSING')
        ensure(n['address'] in (bundle['self']['ipv4'], bundle['self']['domain']),
               'NODE_ADDRESS_MISMATCH_' + role.upper())
        ensure(n['profile_uuid'] in profiles, 'NODE_PROFILE_MISSING_' + role.upper())
        tag = bundle['self']['inbound_tag']
        ensure(n['active_inbounds'] == [tag], 'NODE_INBOUND_MISMATCH_' + role.upper())
        ensure(profiles[n['profile_uuid']]['inbound_tags'] == [tag],
               'PROFILE_INBOUND_MISMATCH_' + role.upper())
    ensure(nodes['entry']['profile_uuid'] != nodes['exit']['profile_uuid'],
           'ROLES_SHARE_PROFILE')
    for s in observed['squads']:
        exactly(s, ('purpose', 'uuid', 'inbound_tags'), 'SQUAD_SCHEMA_INVALID')
        ensure(s['purpose'] in ('clients', 'bridge') and isinstance(s['uuid'], str)
               and isinstance(s['inbound_tags'], list), 'SQUAD_INVALID')
    squads = unique(observed['squads'], 'purpose', 'SQUAD_PURPOSE_DUPLICATE')
    unique(observed['squads'], 'uuid', 'SQUAD_UUID_DUPLICATE')
    ensure(squads['clients']['inbound_tags'] == [entry['self']['inbound_tag']],
           'CLIENT_SQUAD_SCOPE_INVALID')
    ensure(squads['bridge']['inbound_tags'] == [exit_['self']['inbound_tag']],
           'BRIDGE_SQUAD_SCOPE_INVALID')
    host = observed['hosts'][0]
    exactly(host, ('inbound_tag', 'node_uuid'), 'HOST_SCHEMA_INVALID')
    ensure(host['node_uuid'] == nodes['entry']['uuid'] and
           host['inbound_tag'] == entry['self']['inbound_tag'],
           'HOST_MUST_POINT_ONLY_TO_ENTRY')
    u = observed['users'][0]
    exactly(u, ('purpose', 'vlessUuid', 'status', 'active_internal_squads', 'expireAt'),
            'USER_SCHEMA_INVALID')
    ensure(u['purpose'] == 'bridge' and
           u['vlessUuid'] == entry['bridge']['service_user_uuid'],
           'BRIDGE_VLESS_UUID_NOT_MATCHED')
    ensure(u['status'] == 'ACTIVE', 'BRIDGE_SERVICE_USER_INACTIVE')
    ensure(u['active_internal_squads'] == [squads['bridge']['uuid']],
           'BRIDGE_USER_MUST_ONLY_HAVE_BRIDGE_SQUAD')
    try:
        expiration = dt.datetime.fromisoformat(u['expireAt'].replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError) as exc:
        raise InventoryError('BRIDGE_EXPIRATION_INVALID') from exc
    ensure(expiration.tzinfo is not None, 'BRIDGE_EXPIRATION_NOT_TZ_AWARE')
    moment = now if now is not None else dt.datetime.now(dt.timezone.utc)
    ensure(expiration > moment + dt.timedelta(days=1), 'BRIDGE_EXPIRATION_TOO_SOON')
    return {'status':'PASS', 'pair_id':entry['pair_id'],
            'nodes':len(observed['nodes']), 'profiles':len(profiles),
            'squads':len(squads), 'hosts':1, 'bridge_vless_uuid_matches':True}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--entry-bundle', required=True)
    p.add_argument('--exit-bundle', required=True)
    p.add_argument('--inventory', required=True, help='normalized private JSON, not raw API output')
    ns = p.parse_args(argv)
    try:
        entry=deployment.read_role(ns.entry_bundle, 'entry')
        exit_=deployment.read_role(ns.exit_bundle, 'exit')
        observed=deployment.private_file(ns.inventory)
        result=check(entry, exit_, observed)
    except (InventoryError, OSError, ValueError, KeyError, TypeError,
            deployment.DeploymentError) as exc:
        reason = str(exc) if isinstance(exc, (InventoryError, deployment.DeploymentError)) else type(exc).__name__
        print('CASCADE_PANEL_INVENTORY=FAIL reason='+reason, file=sys.stderr)
        return 1
    print('CASCADE_PANEL_INVENTORY=PASS PAIR_ID='+result['pair_id'])
    print('EVIDENCE=NORMALIZED_OPERATOR_EXPORT; PANEL_NOT_MODIFIED; LIVE_CLIENT_NOT_VERIFIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
