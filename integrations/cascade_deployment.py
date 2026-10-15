#!/usr/bin/env python3
"""Role-separated cascade provisioning for fresh, dedicated RemnaNode VPS.

Offline prepare: read a private pair specification and produce two independent,
root-private single-role bundles. Runtime enroll: stage ONLY that role's bundle
before a host mutation; confirm identity after Node IPv4/DNS is established.

Does NOT contact Panel or install Xray. The installer consumes this module and
requires a real core `run -test`. Never treat an import template as live config.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

import cascade_profiles as cp

SCHEMA = 2
ROLES = {'entry': 'cascade-entry', 'exit': 'cascade-exit'}
ROLE_FILENAME = 'cascade-role.json'
STATE_FILENAME = 'role.json'


class DeploymentError(cp.Invalid):
    pass


def require(test, reason):
    if not test:
        raise DeploymentError(reason)


def public_fields(n):
    return {key: n[key] for key in ('domain', 'ipv4', 'public_key', 'short_id', 'inbound_tag')}


def private_role(n):
    result = public_fields(n)
    result['private_key'] = n['private_key']
    return result


def pairing_id(cfg):
    public = {
        'entry': public_fields(cfg['entry']),
        'exit': public_fields(cfg['exit']),
        'bridge_uuid': cfg['bridge']['service_user_uuid'],
        'schema': SCHEMA,
    }
    return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_reality_pair(n):
    # Fail closed: do not accept well-formed but unrelated keys (r4 allowed that
    # for reference/mock data only). No private key ever appears in an error.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    try:
        private = base64.urlsafe_b64decode(n['private_key'] + '=')
        public = base64.urlsafe_b64decode(n['public_key'] + '=')
        derived = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
    except (ValueError, TypeError) as exc:
        raise DeploymentError('INVALID_REALITY_KEY_MATERIAL') from exc
    require(hmac.compare_digest(derived, public), 'REALITY_PRIVATE_PUBLIC_MISMATCH')


def validated_pair(spec):
    cfg = cp.checked_config(spec)
    for role in ('entry', 'exit'):
        verify_reality_pair(cfg[role])
    require(cfg['entry']['short_id'] != cfg['exit']['short_id'], 'SHORT_IDS_MUST_DIFFER')
    return cfg


def create_pair(entry_domain, entry_ipv4, exit_domain, exit_ipv4, output):
    """Generate cryptographically valid keys and bridge UUID offline, never print secrets."""
    import secrets
    import uuid
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    output = Path(output)
    require(output.is_absolute() and output.parent.is_dir(), 'PAIR_OUTPUT_MUST_BE_ABSOLUTE')
    require(not output.parent.stat().st_mode & 0o022, 'PAIR_PARENT_UNSAFE')
    if os.geteuid() == 0:
        require(output.parent.stat().st_uid == 0, 'PAIR_PARENT_NOT_ROOT_OWNED')
    require(not output.exists() and not output.is_symlink(), 'PAIR_OUTPUT_EXISTS')

    def identity(domain, ipv4, role):
        key = X25519PrivateKey.generate()
        enc = lambda data: base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
        return {'domain': cp.domain(domain), 'ipv4': cp.address(ipv4),
                'private_key': enc(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                'public_key': enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                'short_id': secrets.token_hex(8),
                'inbound_tag': 'VK_CASCADE_' + role.upper() + '_' + secrets.token_hex(6).upper()}

    cfg = {'schema':1, 'entry':identity(entry_domain, entry_ipv4, 'entry'),
           'exit':identity(exit_domain, exit_ipv4, 'exit'),
           'bridge':{'service_user_uuid':str(uuid.uuid4())}}
    validated_pair(cfg)
    atomic_new(output, canonical(cfg))
    fsync_dir(output.parent)
    return output


def bundles(cfg):
    pid = pairing_id(cfg)
    return {
        'entry': {'schema': SCHEMA, 'role': ROLES['entry'], 'pair_id': pid,
                  'self': private_role(cfg['entry']), 'peer': public_fields(cfg['exit']),
                  'bridge': {'service_user_uuid': cfg['bridge']['service_user_uuid']}},
        'exit': {'schema': SCHEMA, 'role': ROLES['exit'], 'pair_id': pid,
                 'self': private_role(cfg['exit']), 'peer': public_fields(cfg['entry']),
                 'bridge': {'service_user_uuid': cfg['bridge']['service_user_uuid']}},
    }


def validate_bundle(obj, expected_role=None, cryptographic=True):
    require(isinstance(obj, dict) and set(obj) ==
            {'schema', 'role', 'pair_id', 'self', 'peer', 'bridge'}, 'BUNDLE_SCHEMA_INVALID')
    require(type(obj['schema']) is int and obj['schema'] == SCHEMA, 'BUNDLE_VERSION_INVALID')
    role = obj['role']
    require(role in ROLES.values(), 'INVALID_CASCADE_ROLE')
    if expected_role:
        require(role == ROLES[expected_role], 'ROLE_MISMATCH')
    own = cp.node(obj['self'], 'SELF')
    peer = obj['peer']
    require(isinstance(peer, dict) and set(peer) ==
            {'domain', 'ipv4', 'public_key', 'short_id', 'inbound_tag'}, 'PEER_FIELDS_INVALID')
    for key in peer:
        require(isinstance(peer[key], str), 'INVALID_PEER_FIELD')
    cp.domain(peer['domain'])
    cp.address(peer['ipv4'])
    cp.x25519(peer['public_key'])
    cp.short_id(peer['short_id'])
    require(cp.TAG.fullmatch(peer['inbound_tag']), 'INVALID_PEER_TAG')
    require(obj['self']['domain'] != peer['domain'] and
            obj['self']['ipv4'] != peer['ipv4'] and
            obj['self']['inbound_tag'] != peer['inbound_tag'] and
            obj['self']['public_key'] != peer['public_key'], 'SAME_ENTRY_EXIT_IDENTITY')
    require(own['short_id'] != peer['short_id'], 'SAME_SHORT_ID')
    bridge = obj['bridge']
    require(isinstance(bridge, dict) and set(bridge) == {'service_user_uuid'},
            'BRIDGE_FIELDS_INVALID')
    # Reuse strict UUID validation from r4.
    import uuid
    try:
        peer_uuid = str(uuid.UUID(bridge['service_user_uuid']))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DeploymentError('INVALID_BRIDGE_UUID') from exc
    require(peer_uuid == bridge['service_user_uuid'] and uuid.UUID(peer_uuid).int != 0,
            'INVALID_BRIDGE_UUID')
    require(isinstance(obj['pair_id'], str) and len(obj['pair_id']) == 64 and
            all(c in '0123456789abcdef' for c in obj['pair_id']), 'PAIR_ID_INVALID')
    roles = {'entry': own, 'exit': peer} if role == 'cascade-entry' else {'entry': peer, 'exit': own}
    expected = pairing_id({**roles, 'bridge': bridge})
    require(hmac.compare_digest(expected, obj['pair_id']), 'BUNDLE_PAIR_ID_MISMATCH')
    if cryptographic:
        verify_reality_pair(own)
    return obj


def private_file(path):
    p = Path(path)
    require(p.is_absolute(), 'BUNDLE_PATH_MUST_BE_ABSOLUTE')
    # Disallow symlinked ancestors, unowned or group/world writable directories.
    cur = p.parent
    while cur != cur.parent:
        s = cur.lstat()
        require(stat.S_ISDIR(s.st_mode), 'UNSAFE_BUNDLE_PARENT')
        # /tmp and /var/tmp sticky directories may be used only when their
        # remaining components are private; an unprotected ordinary writable
        # ancestor is never accepted.
        sticky_root = bool((s.st_mode & stat.S_ISVTX) and s.st_uid == 0)
        require(not s.st_mode & 0o022 or sticky_root, 'UNSAFE_BUNDLE_PARENT')
        if os.geteuid() == 0:
            require(s.st_uid == 0, 'BUNDLE_PARENT_NOT_ROOT_OWNED')
        elif cur != p.parent and not sticky_root:
            # Private workspace may be owned by invoking uid, not by root.
            require(s.st_uid in (0, os.geteuid()), 'BUNDLE_PARENT_NOT_OWNED')
        cur = cur.parent
    require(not p.is_symlink(), 'BUNDLE_SYMLINK_REFUSED')
    # A prior lstat-only check is insufficient: a path can be replaced by a
    # symlink between validation and Path.read_text(). Bind fstat and read to
    # one O_NOFOLLOW fd; never read devices, sockets, pipes or large payloads.
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 16384,
                'BUNDLE_MUST_BE_SMALL_REGULAR_FILE')
        require(stat.S_IMODE(st.st_mode) & 0o077 == 0, 'BUNDLE_REQUIRES_PRIVATE_MODE')
        if os.geteuid() == 0:
            require(st.st_uid == 0, 'BUNDLE_MUST_BE_ROOT_OWNED')
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(16385)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    require(len(data) <= 16384, 'BUNDLE_TOO_LARGE')
    return json.loads(data.decode('utf-8'), object_pairs_hook=cp.no_duplicates,
                      parse_constant=lambda _: require(False, 'BUNDLE_NONFINITE_NUMBER'))


def read_role(path, expected_role=None, cryptographic=True):
    return validate_bundle(private_file(path), expected_role, cryptographic)


def role_profile(bundle):
    bundle = validate_bundle(bundle)
    cfg = {'entry': bundle['self'], 'exit': bundle['peer']} if bundle['role'] == 'cascade-entry' \
          else {'entry': bundle['peer'], 'exit': bundle['self']}
    cfg['bridge'] = bundle['bridge']
    if bundle['role'] == 'cascade-entry':
        result = cp.entry_profile(cfg)
        cp.audit(result, 'entry')
    else:
        result = cp.exit_profile(cfg)
        cp.audit(result, 'exit')
    return result


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def atomic_new(path, data):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(pair, out):
    cfg = validated_pair(private_file(pair))
    dest = Path(out)
    require(dest.is_absolute(), 'OUTPUT_MUST_BE_ABSOLUTE')
    require(not dest.exists() and not dest.is_symlink(), 'OUTPUT_EXISTS')
    require(dest.parent.is_dir() and not dest.parent.stat().st_mode & 0o022,
            'OUTPUT_PARENT_UNSAFE')
    if os.geteuid() == 0:
        require(dest.parent.stat().st_uid == 0, 'OUTPUT_PARENT_NOT_ROOT_OWNED')
    dest.mkdir(mode=0o700)
    try:
        for role, data in bundles(cfg).items():
            directory = dest / role
            directory.mkdir(mode=0o700)
            atomic_new(directory / 'role-bundle.json', canonical(data))
            # Public inventory: NO private keys, service-user UUID or SECRET_KEY.
            plan = {'schema': SCHEMA, 'status': 'STAGING_REQUIRES_REAL_PANEL_ASSIGNMENT',
                    'role': role, 'pair_id': data['pair_id'],
                    'own': public_fields(cfg[role]),
                    'peer': public_fields(cfg['exit' if role == 'entry' else 'entry']),
                    'bridge_access': 'service user restricted ONLY to exit inbound',
                    'panel_automation': 'NONE; isolate 2 nodes + 2 profiles + squads + bridge user'}
            atomic_new(directory / 'panel-plan.json', canonical(plan))
            fsync_dir(directory)
        fsync_dir(dest)
    except BaseException:
        # Directory was exclusively created here; never touch an existing path.
        for role in ('entry', 'exit'):
            directory = dest / role
            if directory.is_dir():
                for name in ('role-bundle.json', 'panel-plan.json'):
                    (directory / name).unlink(missing_ok=True)
                directory.rmdir()
        dest.rmdir()
        raise
    return dest


def enrollment(bundle, installed, state, role, pin):
    """Persist paired identity before APT/SSH/UFW. No overwrite or role switch."""
    obj = read_role(bundle, role, cryptographic=False)
    raw = canonical(obj)
    # Bind to raw source file bytes; the source must stay unchanged after preflight.
    fd = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        bs = os.fstat(fd)
        require(stat.S_ISREG(bs.st_mode) and bs.st_nlink == 1 and bs.st_size <= 16384,
                'BUNDLE_FILE_CHANGED')
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(16385)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    require(hmac.compare_digest(hashlib.sha256(data).hexdigest(), pin), 'BUNDLE_CHANGED_AFTER_PREFLIGHT')
    installed, state = Path(installed), Path(state)
    require(installed.name == ROLE_FILENAME and state.name == STATE_FILENAME, 'UNEXPECTED_INSTALL_PATH')
    for parent in (installed.parent, state.parent):
        ps = parent.lstat()
        require(stat.S_ISDIR(ps.st_mode) and not ps.st_mode & 0o077,
                'INSTALL_PATH_MUST_BE_ROOT_PRIVATE')
    state_obj = {'schema': SCHEMA, 'role': obj['role'], 'pair_id': obj['pair_id']}
    if installed.exists() or installed.is_symlink() or state.exists() or state.is_symlink():
        require(installed.is_file() and state.is_file() and
                not installed.is_symlink() and not state.is_symlink(), 'PARTIAL_CASCADE_ENROLLMENT')
        old = read_role(installed, role, cryptographic=False)
        require(hmac.compare_digest(canonical(old), raw) and
                private_file(state) == state_obj, 'CASCADE_ENROLLMENT_DRIFT')
        return obj
    atomic_new(installed, raw)
    # Crash between writes = intentional fail-closed orphan, not ordinary auto-resume.
    atomic_new(state, canonical(state_obj))
    fsync_dir(installed.parent)
    fsync_dir(state.parent)
    return obj


def installed_role(etc, state, cryptographic=True):
    etc, state = Path(etc), Path(state)
    b = etc / ROLE_FILENAME
    r = state / STATE_FILENAME
    require(b.is_file() and r.is_file(), 'CASCADE_ROLE_STATE_MISSING')
    bundle = read_role(b, cryptographic=cryptographic)
    marker = private_file(r)
    require(marker == {'schema': SCHEMA, 'role': bundle['role'], 'pair_id': bundle['pair_id']},
            'CASCADE_ROLE_MARKER_MISMATCH')
    return bundle


def ensure_local_identity(bundle, domain, ipv4):
    require(bundle['self']['domain'] == domain and bundle['self']['ipv4'] == ipv4,
            'CASCADE_ROLE_LOCAL_DOMAIN_IPV4_MISMATCH')
    return True


def read_profile(path):
    """Verify a local import template without following a symlink or blocking FIFO."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 2 * 1024 * 1024,
                'PROFILE_MUST_BE_SMALL_REGULAR_FILE')
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
            fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    require(len(data) <= 2 * 1024 * 1024, 'PROFILE_TOO_LARGE')
    return json.loads(data.decode('utf-8'), object_pairs_hook=cp.no_duplicates,
                      parse_constant=lambda _: require(False, 'PROFILE_NONFINITE_NUMBER'))


def panel_guidance(bundle, panel_ipv4, port):
    profile = role_profile(bundle)
    own = bundle['self']
    role = bundle['role']
    tag = own['inbound_tag']
    peer = bundle['peer']
    msg = [
        'VKarmani CASCADE ' + role + ' (НЕ применено в Remnawave Panel)',
        'Pair ID: ' + bundle['pair_id'],
        'Node domain/IP: ' + own['domain'] + ' / ' + own['ipv4'],
        'API: ' + str(port) + '/tcp, allow ONLY Panel backend IPv4 ' + ','.join(panel_ipv4),
        'Selfsteal: independent host Nginx + /dev/shm/nginx.sock',
        'Reality publicKey: ' + own['public_key'],
        'Reality shortId: ' + own['short_id'],
        'Inbound tag (must be unique IN PANEL DB): ' + tag,
        '1. In TEST Panel create new dedicated Node, bind THIS node SECRET_KEY.',
        '2. Create a separate Config Profile; import this node profile.json.',
        '3. Assign ONLY new profile to THIS node; verify computed config via actual rw-core.',
        '4. Do not merge inherited DIRECT/snippets or other inbound routes.',
        '5. Create isolated Internal Squads: clients->ENTRY tag, bridge->EXIT tag.',
        '6. Create dedicated bridge service user with UUID from PRIVATE role-bundle.json.',
        '7. Restrict bridge user to ONLY exit inbound. Do NOT grant regular clients EXIT.',
        '8. Check Host only on entry, never create a public client Host for exit.',
        '9. Test real client, UDP/TCP, DNS, peer down and no DIRECT fallback.',
        '10. No panel API token is consumed here. No objects created automatically.',
    ]
    if role == 'cascade-entry':
        msg += ['ENTRY peers to exit ' + peer['domain'] + ' / ' + peer['ipv4'] + ':443',
                'ENTRY outbounds must be EXACTLY BLOCK + TO_EXIT_VLESS, BLOCK FIRST.',
                'ENTRY built-in DNS is disabled and domainStrategy is AsIs.']
    else:
        msg += ['EXIT accepts bridge UUID ONLY after service-user Squad assignment.',
                'EXIT DIRECT must be limited to this inbound; review DNS and external egress.']
    return '\n'.join(msg) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    a = sub.add_parser('create-pair')
    a.add_argument('--entry-domain', required=True)
    a.add_argument('--entry-ipv4', required=True)
    a.add_argument('--exit-domain', required=True)
    a.add_argument('--exit-ipv4', required=True)
    a.add_argument('--output', required=True)
    a = sub.add_parser('prepare')
    a.add_argument('--pair', required=True)
    a.add_argument('--output', required=True)
    a = sub.add_parser('validate')
    a.add_argument('--bundle', required=True)
    a.add_argument('--role', choices=tuple(ROLES), required=True)
    a.add_argument('--structure-only', action='store_true')
    a.add_argument('--domain', help='Expected local FQDN, checked before OS mutation')
    a = sub.add_parser('enroll')
    a.add_argument('--bundle', required=True)
    a.add_argument('--role', choices=tuple(ROLES), required=True)
    a.add_argument('--sha256', required=True)
    a.add_argument('--etc', required=True)
    a.add_argument('--state', required=True)
    a = sub.add_parser('check-installed')
    a.add_argument('--etc', required=True)
    a.add_argument('--state', required=True)
    a.add_argument('--domain')
    a.add_argument('--ipv4')
    a = sub.add_parser('profile-check')
    a.add_argument('--etc', required=True)
    a.add_argument('--state', required=True)
    a.add_argument('--profile', required=True)
    ns = p.parse_args(argv)
    os.umask(0o077)
    try:
        if ns.action == 'create-pair':
            create_pair(ns.entry_domain, ns.entry_ipv4, ns.exit_domain, ns.exit_ipv4, ns.output)
            print('CASCADE_PAIR=CREATED PRIVATE_LOCAL_ONLY KEEP_OFF_SERVERS')
        elif ns.action == 'prepare':
            prepare(ns.pair, ns.output)
            print('CASCADE_BUNDLES=PREPARED SEPARATE_PRIVATE_ROLES PANEL=NOT_CONFIGURED')
        elif ns.action == 'validate':
            obj = read_role(ns.bundle, ns.role, cryptographic=not ns.structure_only)
            if ns.domain is not None:
                require(obj['self']['domain'] == ns.domain, 'CASCADE_DOMAIN_CONFLICT_BEFORE_APT')
            print('CASCADE_BUNDLE=VALID role=' + obj['role'] + ' pair_id=' + obj['pair_id'])
        elif ns.action == 'enroll':
            require(os.geteuid() == 0, 'ROOT_REQUIRED')
            enrollment(ns.bundle, Path(ns.etc) / ROLE_FILENAME,
                       Path(ns.state) / STATE_FILENAME, ns.role, ns.sha256)
            print('CASCADE_ROLE=ENROLLED NON_MUTABLE')
        elif ns.action == 'check-installed':
            obj = installed_role(ns.etc, ns.state)
            if ns.domain is not None and ns.ipv4 is not None:
                ensure_local_identity(obj, ns.domain, ns.ipv4)
            print('CASCADE_ROLE=VALID role=' + obj['role'] + ' pair_id=' + obj['pair_id'])
        elif ns.action == 'profile-check':
            b = installed_role(ns.etc, ns.state)
            # Never assume the Panel computed profile equals this local template.
            actual = read_profile(ns.profile)
            require(actual == role_profile(b), 'CASCADE_LOCAL_PROFILE_DRIFT')
            print('CASCADE_LOCAL_TEMPLATE=PASS PANEL_COMPUTED_CONFIG=NOT_VERIFIED')
    except (cp.Invalid, OSError, ValueError, TypeError, KeyError, ImportError,
            json.JSONDecodeError) as exc:
        # External input and crypto can contain private secrets; never log values.
        reason = str(exc) if isinstance(exc, cp.Invalid) else type(exc).__name__
        print('CASCADE_DEPLOY=FAIL ' + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
