#!/usr/bin/env python3
"""Offline, fail-closed TWO-ROLE Xray profile preparation for fresh staging nodes.

Never touches Remnawave, /etc, Docker, Nginx, firewall, network or existing
inbounds. Private input/output permissions are deliberately restrictive.
Existing 2.5.10 ordinary installer is NOT a cascade installer.
"""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

SCHEMA = 1
TAG = re.compile(r'[A-Za-z][A-Za-z0-9_-]{3,63}\Z')
FQDN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PRIVATE_RANGES = [
    '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
    '169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24',
    '192.168.0.0/16','198.18.0.0/15','198.51.100.0/24',
    '203.0.113.0/24','224.0.0.0/4','240.0.0.0/4','::/0'
]


class Invalid(Exception):
    pass


def require(condition, label):
    if not condition:
        raise Invalid(label)


def read_private(path):
    path = Path(path)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'INPUT_NOT_REGULAR_SINGLE_LINK')
    require(stat.S_IMODE(s.st_mode) & 0o077 == 0, 'INPUT_REQUIRES_MODE_0600')
    require(s.st_size <= 16384, 'INPUT_TOO_LARGE')
    if os.geteuid() == 0:
        require(s.st_uid == 0, 'INPUT_OWNER_NOT_ROOT')
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=no_duplicates)


def no_duplicates(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'DUPLICATE_CONFIG_FIELD')
        result[name] = value
    return result


def address(value):
    require(isinstance(value, str), 'INVALID_IPV4')
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise Invalid('INVALID_IPV4') from exc
    require(addr.is_global and value == str(addr), 'IPv4_MUST_BE_CANONICAL_GLOBAL')
    return value


def domain(value):
    require(isinstance(value, str) and 4 <= len(value) <= 253 and '.' in value,
            'INVALID_FQDN')
    require(value == value.lower() and not value.endswith('.') and
            all(FQDN_LABEL.fullmatch(x) for x in value.split('.')),
            'INVALID_FQDN')
    return value


def x25519(value):
    # Key presence/encoding is checked; verifying private/public pairing is an
    # external Xray Core + real handshake requirement, NOT implied here.
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', value),
            'INVALID_REALITY_KEY_ENCODING')
    try:
        raw = base64.urlsafe_b64decode(value + '=')
    except (ValueError, base64.binascii.Error) as exc:
        raise Invalid('INVALID_REALITY_KEY_ENCODING') from exc
    require(len(raw) == 32 and any(raw), 'INVALID_REALITY_KEY_BYTES')
    return value


def short_id(value):
    require(isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{2}){1,8}', value),
            'INVALID_SHORT_ID')
    return value


def node(obj, label):
    require(isinstance(obj, dict) and set(obj) == {'domain', 'ipv4', 'private_key',
                'public_key', 'short_id', 'inbound_tag'}, 'INVALID_' + label + '_FIELDS')
    require(isinstance(obj['inbound_tag'], str) and TAG.fullmatch(obj['inbound_tag']),
            'INVALID_INBOUND_TAG')
    return {'domain': domain(obj['domain']), 'ipv4': address(obj['ipv4']),
            'private_key': x25519(obj['private_key']),
            'public_key': x25519(obj['public_key']),
            'short_id': short_id(obj['short_id']),
            'inbound_tag': obj['inbound_tag']}


def checked_config(cfg):
    require(isinstance(cfg, dict) and set(cfg) == {'schema', 'entry', 'exit', 'bridge'},
            'INVALID_INPUT_FIELDS')
    require(type(cfg['schema']) is int and cfg['schema'] == SCHEMA, 'INVALID_SCHEMA')
    entry, exit_node = node(cfg['entry'], 'ENTRY'), node(cfg['exit'], 'EXIT')
    bridge = cfg['bridge']
    require(isinstance(bridge, dict) and set(bridge) == {'service_user_uuid'},
            'INVALID_BRIDGE_FIELDS')
    try:
        peer_uuid = str(uuid.UUID(bridge['service_user_uuid']))
    except (ValueError, TypeError, AttributeError) as exc:
        raise Invalid('INVALID_BRIDGE_USER_UUID') from exc
    require(peer_uuid == bridge['service_user_uuid'].lower() and uuid.UUID(peer_uuid).int != 0,
            'INVALID_BRIDGE_USER_UUID')
    for name in ('domain', 'ipv4', 'inbound_tag', 'private_key', 'public_key'):
        require(entry[name] != exit_node[name], 'ENTRY_EXIT_MUST_DIFFER_' + name.upper())
    require(entry['inbound_tag'] not in ('DIRECT', 'BLOCK', 'TO_EXIT_VLESS') and
            exit_node['inbound_tag'] not in ('DIRECT', 'BLOCK', 'TO_EXIT_VLESS'),
            'RESERVED_INBOUND_TAG')
    require(entry['ipv4'] != exit_node['ipv4'], 'PAIR_REQUIRES_DISTINCT_IPV4')
    for n in (entry, exit_node):
        require(n['private_key'] != n['public_key'], 'REALITY_PRIVATE_PUBLIC_KEY_IDENTICAL')
    return {'entry': entry, 'exit': exit_node, 'bridge': {'service_user_uuid': peer_uuid}}


def inbound(n):
    return {'tag': n['inbound_tag'], 'port': 443, 'listen': '0.0.0.0',
        'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none', 'flow': 'xtls-rprx-vision'},
        'sniffing': {'enabled': True, 'routeOnly': True,
                     'destOverride': ['http', 'tls', 'quic']},
        'streamSettings': {'network': 'raw', 'security': 'reality',
            'realitySettings': {'show': False, 'target': '/dev/shm/nginx.sock',
                'xver': 1, 'minClientVer': '0.0.0', 'spiderX': '/',
                'serverNames': [n['domain']], 'privateKey': n['private_key'],
                'shortIds': [n['short_id']]}}}


def entry_profile(cfg):
    e, x = cfg['entry'], cfg['exit']
    return {'log': {'loglevel': 'warning'},
        'inbounds': [inbound(e)],
        'outbounds': [
            {'tag': 'BLOCK', 'protocol': 'blackhole'},
            {'tag': 'TO_EXIT_VLESS', 'protocol': 'vless',
                'settings': {'vnext': [{'address': x['ipv4'], 'port': 443,
                    'users': [{'id': cfg['bridge']['service_user_uuid'],
                               'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
                'streamSettings': {'network': 'raw', 'security': 'reality',
                    'realitySettings': {'serverName': x['domain'], 'fingerprint': 'chrome',
                        'publicKey': x['public_key'], 'shortId': x['short_id'],
                        'spiderX': '/'}}}
        ],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'ip': PRIVATE_RANGES.copy(), 'outboundTag': 'BLOCK'},
            {'type': 'field', 'inboundTag': [e['inbound_tag']],
             'outboundTag': 'TO_EXIT_VLESS'}]}}


def exit_profile(cfg):
    n = cfg['exit']
    return {'log': {'loglevel': 'warning'},
        'dns': {'servers': ['1.1.1.1', '1.0.0.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [inbound(n)],
        'outbounds': [
            {'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {
                'domainStrategy': 'UseIPv4',
                'finalRules': [{'ip': PRIVATE_RANGES.copy(), 'action': 'block'}]}},
            {'tag': 'BLOCK', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
            {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'ip': PRIVATE_RANGES.copy(), 'outboundTag': 'BLOCK'},
            {'type': 'field', 'inboundTag': [n['inbound_tag']],
             'outboundTag': 'DIRECT'}]}}


def audit(profile, role):
    """Fail-closed structural check of intended import profile, NOT computed panel config."""
    require(role in ('entry', 'exit'), 'INVALID_ROLE')
    require(isinstance(profile, dict) and set(profile) ==
            ({'log','inbounds','outbounds','routing'} if role == 'entry'
             else {'log','dns','inbounds','outbounds','routing'}),
            'INVALID_PROFILE_FIELDS')
    ins, outs = profile.get('inbounds'), profile.get('outbounds')
    require(isinstance(ins, list) and len(ins) == 1 and isinstance(ins[0], dict),
            'PROFILE_INBOUND_COUNT')
    i = ins[0]
    require(i.get('protocol') == 'vless' and type(i.get('port')) is int and i['port'] == 443
            and i.get('listen') == '0.0.0.0', 'INVALID_VLESS_LISTENER')
    require(isinstance(i.get('tag'), str) and TAG.fullmatch(i['tag']), 'INVALID_TAG')
    require(i.get('settings') == {'clients': [], 'decryption': 'none',
                                  'flow': 'xtls-rprx-vision'}, 'UNEXPECTED_CLIENT_OVERRIDE')
    stream = i.get('streamSettings', {})
    require(stream.get('network') == 'raw' and stream.get('security') == 'reality',
            'UNEXPECTED_TRANSPORT')
    r = stream.get('realitySettings', {})
    require(r.get('target') == '/dev/shm/nginx.sock' and r.get('xver') == 1 and
            r.get('minClientVer') == '0.0.0' and len(r.get('serverNames', [])) == 1,
            'UNEXPECTED_SELFSTEAL')
    require(isinstance(outs, list) and all(isinstance(o, dict) for o in outs),
            'INVALID_OUTBOUNDS')
    tags = [o.get('tag') for o in outs]
    require(len(set(tags)) == len(tags) and all(isinstance(x, str) for x in tags),
            'DUPLICATE_OUTBOUND_TAGS')
    route = profile.get('routing', {})
    rules = route.get('rules')
    require(isinstance(rules, list) and len(rules) == 4 and not route.get('balancers'),
            'UNEXPECTED_ROUTING_RULES')
    require(rules[0] == {'type':'field','protocol':['bittorrent'],'outboundTag':'BLOCK'}
            and rules[1] == {'type':'field','domain':['geosite:private'],'outboundTag':'BLOCK'}
            and rules[2] == {'type':'field','ip':PRIVATE_RANGES,'outboundTag':'BLOCK'},
            'BLOCK_RULES_MISSING_OR_REORDERED')
    if role == 'entry':
        require(outs[0] == {'tag':'BLOCK','protocol':'blackhole'},
                'ENTRY_BLOCK_OUTBOUND_MUTATED')
        require(set(peer_key for peer_key in outs[1]) ==
                {'tag','protocol','settings','streamSettings'},
                'ENTRY_PEER_OUTBOUND_EXTRA_FIELDS')
        require(set(tags) == {'BLOCK', 'TO_EXIT_VLESS'} and tags[0] == 'BLOCK',
                'ENTRY_DIRECT_OR_FALLBACK_FORBIDDEN')
        require(route.get('domainStrategy') == 'AsIs', 'ENTRY_DNS_LEAK_RISK')
        require('dns' not in profile, 'ENTRY_BUILTIN_DNS_FORBIDDEN')
        require(rules[3] == {'type':'field', 'inboundTag':[i['tag']],
                             'outboundTag':'TO_EXIT_VLESS'}, 'ENTRY_ROUTE_MISMATCH')
        peer = outs[1]
        require(peer.get('protocol') == 'vless', 'PEER_PROTOCOL_INVALID')
        vnext = peer.get('settings',{}).get('vnext')
        require(isinstance(vnext, list) and len(vnext) == 1, 'PEER_SETTINGS_INVALID')
        v = vnext[0]
        require(v.get('port') == 443 and address(v.get('address')) and
                isinstance(v.get('users'), list) and len(v['users']) == 1,
                'PEER_SETTINGS_INVALID')
        user = v['users'][0]
        require(user.get('encryption') == 'none' and user.get('flow') == 'xtls-rprx-vision',
                'PEER_USER_FLOW_INVALID')
        try:
            require(uuid.UUID(user['id']).int != 0, 'PEER_USER_INVALID')
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise Invalid('PEER_USER_INVALID') from exc
        s = peer.get('streamSettings', {})
        rr = s.get('realitySettings', {})
        require(s.get('network') == 'raw' and s.get('security') == 'reality' and
                isinstance(rr.get('serverName'),str) and
                domain(rr['serverName']) and x25519(rr.get('publicKey')) and
                short_id(rr.get('shortId')) and rr.get('fingerprint') == 'chrome',
                'PEER_REALITY_INVALID')
    else:
        require(outs[1] == {'tag':'BLOCK','protocol':'blackhole'},
                'EXIT_BLOCK_OUTBOUND_MUTATED')
        require(set(tags) == {'DIRECT','BLOCK'} and tags[0] == 'DIRECT',
                'EXIT_OUTBOUND_POLICY')
        require(rules[3] == {'type':'field', 'inboundTag':[i['tag']],
                             'outboundTag':'DIRECT'}, 'EXIT_ROUTE_MISMATCH')
        require(outs[0].get('protocol') == 'freedom' and
                outs[0].get('settings',{}).get('finalRules') ==
                [{'ip': PRIVATE_RANGES,'action':'block'}], 'EXIT_PRIVATE_EGRESS_NOT_BLOCKED')
    return True


def write_private(path, content):
    # Exclusive creation, no symlinks, no overwrite. Called only in a new 0700 dir.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(path)
        finally:
            raise


def encode(obj):
    return (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def make(cfg, directory):
    cfg = checked_config(cfg)
    e, x = entry_profile(cfg), exit_profile(cfg)
    audit(e, 'entry')
    audit(x, 'exit')
    dest = Path(directory)
    # The command may only create a NEW directory: never overwrite a live path.
    ps = dest.parent.lstat()
    require(stat.S_ISDIR(ps.st_mode) and not (ps.st_mode & 0o022),
            'OUTPUT_PARENT_MUST_NOT_BE_WRITABLE_BY_OTHERS')
    dest.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        os.chmod(dest, 0o700)
        assets = {'entry-profile.json': encode(e), 'exit-profile.json': encode(x)}
        public_manifest = {'schema':1, 'status':'STAGING_IMPORT_ONLY',
            'entry': {'domain':cfg['entry']['domain'], 'ipv4':cfg['entry']['ipv4'],
                      'inbound_tag':cfg['entry']['inbound_tag'],
                      'public_key':cfg['entry']['public_key'],
                      'short_id':cfg['entry']['short_id']},
            'exit': {'domain':cfg['exit']['domain'], 'ipv4':cfg['exit']['ipv4'],
                     'inbound_tag':cfg['exit']['inbound_tag'],
                     'public_key':cfg['exit']['public_key'],
                     'short_id':cfg['exit']['short_id']},
            'panel_required': ['Node for entry', 'Node for exit',
                               'two separate Config Profiles', 'Host for entry',
                               'Internal Squad for clients',
                               'separate service user restricted to exit inbound'],
            'warnings': ['No Panel API changes', 'No Xray Core validation',
                         'No VPS/SSH/UFW/Docker mutation',
                         'Private and public Reality key pairing not verified',
                         'Do not import before staging test']}
        assets['panel-plan.json'] = encode(public_manifest)
        assets['SHA256SUMS'] = ''.join(hashlib.sha256(value).hexdigest() + '  ' + name + '\n'
                                       for name,value in sorted(assets.items())).encode()
        for name, content in assets.items():
            write_private(dest/name,content)
        fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        for name in ('entry-profile.json','exit-profile.json','panel-plan.json','SHA256SUMS'):
            (dest/name).unlink(missing_ok=True)
        dest.rmdir()
        raise
    return dest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True, help='local, private, mode 0600 JSON')
    p.add_argument('--output', type=Path, required=True, help='new directory, must not exist')
    args = p.parse_args(argv)
    os.umask(0o077)
    try:
        dest = make(read_private(args.config), args.output)
    except (Invalid, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        # Never print an exception payload for secrets or filesystem-supplied inputs.
        print('CASCADE_PREPARE=FAIL reason=' + (str(exc) if isinstance(exc, Invalid)
              else type(exc).__name__), file=sys.stderr)
        return 1
    print('CASCADE_PREPARE=PASS OFFLINE_ONLY STAGING_IMPORT_NOT_DEPLOYED')
    print('CREATED=' + str(dest))
    print('CORE_TEST=NOT_RUN PANEL=NOT_CONFIGURED LIVE_CLIENT=NOT_TESTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
