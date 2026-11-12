#!/usr/bin/env python3
"""Offline audit of an OWN private Xray client JSON: potential direct egress.

Only conservative static findings. Never runs client, resolves DNS, queries a
server, or claims that TUN, OS routes, IPv6 or UDP are leak-free. Does not echo
any user identifiers, domains, addresses, routing rules or credentials.
"""
import argparse
import json
from pathlib import Path
import sys

from xhttp_subscription_audit import Invalid, _load_private_bytes, _unique


MAX_OUTBOUNDS = 64
MAX_RULES = 512


def read_config(path):
    data = _load_private_bytes(path)
    try:
        text = data.decode('utf-8')
        obj = json.loads(text, object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Invalid('NONFINITE_JSON')))
    except (ValueError, UnicodeError) as exc:
        raise Invalid('INVALID_XRAY_JSON') from exc
    if not isinstance(obj, dict):
        raise Invalid('CLIENT_JSON_MUST_BE_OBJECT')
    return obj


def audit(config):
    if not isinstance(config, dict):
        raise Invalid('CLIENT_CONFIG_NOT_OBJECT')
    outbounds = config.get('outbounds')
    if not isinstance(outbounds, list) or not 1 <= len(outbounds) <= MAX_OUTBOUNDS:
        raise Invalid('OUTBOUNDS_REQUIRED_OR_TOO_MANY')
    if any(not isinstance(x, dict) or not isinstance(x.get('protocol'), str) for x in outbounds):
        raise Invalid('OUTBOUND_SCHEMA_INVALID')
    tags = [x.get('tag') for x in outbounds if x.get('tag') is not None]
    if (any(not isinstance(tag, str) or not tag or len(tag) > 128 for tag in tags)
            or len(set(tags)) != len(tags)):
        raise Invalid('DUPLICATE_OR_INVALID_TAGS')
    direct = {x.get('tag') for x in outbounds if x.get('protocol') == 'freedom'
              and isinstance(x.get('tag'), str)}
    routing = config.get('routing')
    if routing is not None and not isinstance(routing, dict):
        raise Invalid('ROUTING_SCHEMA_INVALID')
    rules = routing.get('rules', []) if routing is not None else []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise Invalid('ROUTING_RULES_INVALID_OR_TOO_MANY')
    observations = []
    direct_rule_count = 0
    unknown_route_tags = 0
    unverified_balancers = 0
    for rule in rules:
        if not isinstance(rule, dict):
            raise Invalid('ROUTING_RULE_INVALID')
        target = rule.get('outboundTag')
        if target is not None and (not isinstance(target, str) or len(target) > 128):
            raise Invalid('INVALID_ROUTING_OUTBOUND_TAG')
        if target in direct:
            direct_rule_count += 1
        if target is not None and target not in tags:
            unknown_route_tags += 1
        if rule.get('balancerTag') is not None:
            unverified_balancers += 1
    if outbounds[0].get('protocol') == 'freedom':
        observations.append('DEFAULT_OUTBOUND_IS_DIRECT')
    elif outbounds[0].get('protocol') != 'vless':
        observations.append('DEFAULT_OUTBOUND_NOT_ATTESTED_AS_VLESS')
    if direct_rule_count:
        observations.append('EXPLICIT_DIRECT_ROUTING_PRESENT_REVIEW_EACH_EXCEPTION')
    if unverified_balancers:
        observations.append('BALANCER_RULES_REQUIRE_RUNTIME_VERIFICATION')
    if unknown_route_tags:
        observations.append('ROUTING_TARGET_NOT_DEFINED_IN_OUTBOUNDS')
    if any(x.get('protocol') in ('socks', 'http') for x in outbounds):
        observations.append('CHAINED_PROXY_EGRESS_NOT_VERIFIED')
    inbounds = config.get('inbounds', [])
    if not isinstance(inbounds, list) or len(inbounds) > 64:
        raise Invalid('INBOUNDS_SCHEMA_INVALID')
    for node in inbounds:
        if not isinstance(node, dict):
            raise Invalid('INBOUND_SCHEMA_INVALID')
        if node.get('protocol') in ('socks', 'http') and node.get('listen') not in ('127.0.0.1', '::1'):
            observations.append('LOCAL_PROXY_LISTENER_NOT_RESTRICTED_TO_LOOPBACK')
    if not isinstance(config.get('dns', {}), dict):
        raise Invalid('DNS_SCHEMA_INVALID')
    observations.extend((
        'DNS_RESOLVER_ROUTE_NOT_MEASURED', 'IPV6_SYSTEM_ROUTE_NOT_MEASURED',
        'UDP443_QUIC_AND_FAILOVER_NOT_MEASURED', 'CLIENT_PROCESS_IDENTITY_NOT_ATTESTED',
        'OS_KILLSWITCH_OR_TUN_POLICY_NOT_MEASURED',
    ))
    risky = any(x in observations for x in (
        'DEFAULT_OUTBOUND_IS_DIRECT', 'EXPLICIT_DIRECT_ROUTING_PRESENT_REVIEW_EACH_EXCEPTION',
        'DEFAULT_OUTBOUND_NOT_ATTESTED_AS_VLESS',
        'LOCAL_PROXY_LISTENER_NOT_RESTRICTED_TO_LOOPBACK',
        'BALANCER_RULES_REQUIRE_RUNTIME_VERIFICATION',
        'ROUTING_TARGET_NOT_DEFINED_IN_OUTBOUNDS',
        'CHAINED_PROXY_EGRESS_NOT_VERIFIED'))
    return {'schema': 1, 'status': 'REVIEW' if risky else 'STATIC_REVIEW',
            'observations': sorted(set(observations)),
            'direct_rules_count': direct_rule_count,
            'live_egress_privacy': 'UNVERIFIED', 'configuration_modified': 'NO',
            'dns_ipv6_udp_proven_safe': 'NO', 'credentials_or_addresses_printed': 'NO'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client-config', type=Path, required=True,
                   help='own private 0600 JSON; not a subscription URI')
    p.add_argument('--strict', action='store_true',
                   help='nonzero on potential direct routes / externally bound proxy')
    args = p.parse_args(argv)
    try:
        result = audit(read_config(args.client_config))
    except (Invalid, ValueError, TypeError, UnicodeError, OSError):
        result = {'schema': 1, 'status': 'FAIL', 'reason': 'UNSAFE_OR_INVALID_CLIENT_CONFIG',
                  'configuration_modified': 'NO', 'credentials_or_addresses_printed': 'NO'}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result['status'] == 'FAIL' or args.strict and result['status'] == 'REVIEW' else 0


if __name__ == '__main__':
    sys.exit(main())
