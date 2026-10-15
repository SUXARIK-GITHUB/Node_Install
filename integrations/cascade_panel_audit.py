#!/usr/bin/env python3
"""Read-only audit of ACTUAL Remnawave computed Xray JSON after Panel assignment.

Compares routing, transport, Reality key and outbounds with the protected
role-bundle. Allows only dynamic VLESS `clients` and one reviewed LOCAL API
inbound/route. Does not fetch, edit or apply Panel config; test mode only.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import uuid

import cascade_deployment as cd
import cascade_profiles as cp


class PanelPolicyError(cp.Invalid):
    pass


def require(test, reason):
    if not test:
        raise PanelPolicyError(reason)


def audit(bundle, computed):
    """Strict structural comparison, NOT cryptographic proof of live traffic."""
    cfg = cd.validate_bundle(bundle)
    expected = cd.role_profile(cfg)
    require(isinstance(computed, dict), 'COMPUTED_NOT_OBJECT')
    # Explicitly refuse undocumented arbitrary top-level routes and DNS.
    extra = set(computed) - set(expected)
    require(extra <= {'api', 'stats', 'policy'}, 'COMPUTED_EXTRA_TOP_LEVEL')
    original = copy.deepcopy(computed)
    original.pop('stats', None)
    original.pop('policy', None)
    api = original.pop('api', None)
    inbound_list = original.get('inbounds')
    require(isinstance(inbound_list, list) and inbound_list, 'COMPUTED_INBOUND_MISSING')
    vpn = [x for x in inbound_list if isinstance(x, dict) and x.get('protocol') == 'vless']
    require(len(vpn) == 1 and vpn[0].get('tag') == cfg['self']['inbound_tag'],
            'COMPUTED_UNEXPECTED_VPN_INBOUNDS')
    clients = vpn[0].get('settings', {}).get('clients')
    require(isinstance(clients, list), 'COMPUTED_CLIENT_ARRAY_MISSING')
    require(bool(clients), 'COMPUTED_NO_ASSIGNED_USERS')
    ids = set()
    for item in clients:
        require(isinstance(item, dict) and isinstance(item.get('id'), str),
                'COMPUTED_CLIENT_INVALID')
        try:
            normalized = str(uuid.UUID(item['id']))
        except (ValueError, TypeError, AttributeError) as exc:
            raise PanelPolicyError('COMPUTED_CLIENT_UUID_INVALID') from exc
        require(normalized == item['id'] and normalized not in ids, 'COMPUTED_DUPLICATE_CLIENT')
        require(item.get('flow', 'xtls-rprx-vision') == 'xtls-rprx-vision',
                'COMPUTED_CLIENT_FLOW_INVALID')
        ids.add(normalized)
    bridge_id = cfg['bridge']['service_user_uuid']
    if cfg['role'] == 'cascade-exit':
        require(ids == {bridge_id}, 'EXIT_MUST_HAVE_ONLY_BRIDGE_USER')
    else:
        require(bridge_id not in ids, 'ENTRY_MUST_NOT_ADMIT_BRIDGE_USER')
    # Check all other inbound settings are verbatim equal, only clients dynamic.
    vpn[0]['settings']['clients'] = []
    optional_api = [x for x in inbound_list if x is not vpn[0]]
    require(len(optional_api) <= 1, 'COMPUTED_EXTRA_INBOUND_COUNT')
    api_tag = None
    if optional_api:
        require(isinstance(api, dict) and isinstance(api.get('tag'), str),
                'API_INBOUND_WITHOUT_API_OBJECT')
        require(len(optional_api) == 1 and isinstance(optional_api[0], dict),
                'UNSUPPORTED_API_INBOUND')
        extra_in = optional_api[0]
        require(extra_in.get('tag') == 'REMNAWAVE_API_INBOUND' and
                extra_in.get('protocol') in ('tunnel', 'dokodemo-door'),
                'API_INBOUND_UNEXPECTED_TYPE')
        host, port = extra_in.get('listen'), extra_in.get('port')
        require((host == '127.0.0.1' and type(port) is int and 1024 <= port <= 65535 and port not in (2222, 443)) or
                (isinstance(host,str) and bool(re.fullmatch(r'@xtls-api-[A-Za-z0-9_-]{1,80}',host))),
                'API_INBOUND_MUST_BE_LOCAL_ONLY')
        services = api.get('services')
        require(isinstance(services, list) and services and
                all(isinstance(s, str) and s for s in services),
                'API_SERVICES_INVALID')
        api_tag = api['tag']
        # A user-supplied API tag MUST NOT collide with any actual outbound tag.
        require(api_tag not in [x['tag'] for x in expected['outbounds']], 'API_TAG_COLLISION')
        inbound_list.remove(extra_in)
    else:
        require(api is None, 'API_OBJECT_MISSING_API_INBOUND')

    rules = original.get('routing', {}).get('rules')
    require(isinstance(rules, list), 'COMPUTED_ROUTING_RULES_INVALID')
    if api_tag:
        require(len(rules) == len(expected['routing']['rules']) + 1 and
                rules[0] == {'type':'field', 'inboundTag':['REMNAWAVE_API_INBOUND'],
                             'outboundTag':api_tag}, 'COMPUTED_API_ROUTE_NOT_FIRST_LOCAL')
        rules.pop(0)
    require(original == expected, 'COMPUTED_PROFILE_DRIFT_DENY')
    return {'status':'PASS', 'role':cfg['role'], 'pair_id':cfg['pair_id'],
            'client_count':len(ids), 'bridge_authorized':cfg['role']=='cascade-exit',
            'api_local':bool(api_tag)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role-bundle', required=True)
    p.add_argument('--computed-profile', required=True)
    ns = p.parse_args(argv)
    try:
        b = cd.read_role(ns.role_bundle)
        computed = cd.read_profile(ns.computed_profile)
        result = audit(b, computed)
    except (cp.Invalid, OSError, ValueError, UnicodeError, TypeError, ImportError) as exc:
        reason = str(exc) if isinstance(exc, cp.Invalid) else type(exc).__name__
        print('CASCADE_COMPUTED_PROFILE=FAIL reason=' + reason, file=sys.stderr)
        return 1
    print('CASCADE_COMPUTED_PROFILE=PASS role=' + result['role'] +
          ' users=' + str(result['client_count']) + ' local_api=' + str(result['api_local']).lower())
    print('SCOPE=SUPPLIED_COMPUTED_JSON_ONLY; LIVE_NODE_OR_SESSION_NOT_VERIFIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
