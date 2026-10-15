#!/usr/bin/env python3
"""VKarmani-owned IPv4 scanner-list integration inspired by Flecksis/rkn-guard.

Only upstream *data* is fetched. Never executes downloaded programs or changes
RemnaNode/Panel configuration. UFW owns the inbound firewall. No IPv6 rules.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import hmac
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

SOURCE = ('https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/'
          'refs/heads/main/public/government_networks.list')
UPSTREAM = 'https://github.com/Flecksis/rkn-guard'
ROOT = Path('/var/lib/vkarmani-node/rkn')
CONFIG = Path('/etc/vkarmani-node/config.json')
CASCADE_ROLE = Path('/etc/vkarmani-node/cascade-role.json')
CASCADE_MARKER = Path('/var/lib/vkarmani-node/role.json')
OWNER = Path('/var/lib/vkarmani-node/owned-installation')
UFW_FILE = Path('/etc/ufw/before.rules')
LOCK = Path('/run/lock/vkarmani-rkn-guard.lock')
BLOCK_SET = 'vkarmani_rkn_blk4'
PANEL_SET = 'vkarmani_rkn_pan4'
BLOCK_STAGE = 'vkarmani_rkn_btmp4'
PANEL_STAGE = 'vkarmani_rkn_ptmp4'
CHAIN = 'VKARMANI_RKN'
BEGIN = '# BEGIN VKARMANI-RKN-GUARD IPv4 managed by Node_Install'
END = '# END VKARMANI-RKN-GUARD IPv4 managed by Node_Install'
CACHE = ROOT / 'current-v4.txt'
CHECKED = ROOT / 'last-check.json'
MAX_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 65536
MIN_ENTRIES = 100
# Age affects the *diagnostic readiness*, not the basic UFW service. A
# verified older list remains installed when the network is unavailable.
MAX_CHECKPOINT_AGE = dt.timedelta(hours=72)


class GuardError(Exception):
    pass


def run(*args, data=None, timeout=35):
    try:
        proc = subprocess.run(list(args), input=data, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError('COMMAND_FAILED: ' + args[0]) from exc
    if proc.returncode:
        raise GuardError('COMMAND_FAILED: ' + ' '.join(args[:3]) +
                         ' rc=' + str(proc.returncode) + ' ' + proc.stderr[:250].strip())
    return proc.stdout


def owned_file(path):
    if path.is_symlink() or not path.is_file():
        raise GuardError('UNSAFE_OR_MISSING_FILE: ' + str(path))
    if os.geteuid() == 0 and path.stat().st_uid != 0:
        raise GuardError('UNTRUSTED_OWNER: ' + str(path))
    return path.read_text(encoding='utf-8')


def require_node():
    if os.geteuid() != 0:
        raise GuardError('ROOT_REQUIRED')
    if OWNER.is_symlink() or not OWNER.is_file():
        raise GuardError('NOT_A_MANAGED_NODE')
    if ROOT.is_symlink():
        raise GuardError('UNSAFE_STATE_DIRECTORY')
    if UFW_FILE.is_symlink():
        raise GuardError('UNSAFE_UFW_RULES_FILE')


def panel_ips():
    cfg = json.loads(owned_file(CONFIG))
    if not isinstance(cfg, dict):
        raise GuardError('INVALID_NODE_CONFIG_ROOT')
    if cfg.get('installation_mode') != 'secret-key-only':
        raise GuardError('UNSUPPORTED_NODE_CONFIGURATION')
    raw = cfg.get('panel_ipv4')
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise GuardError('INVALID_PANEL_IP_LIST')
    ips = set()
    for value in raw:
        if not isinstance(value, str):
            raise GuardError('INVALID_PANEL_IP')
        try:
            addr = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise GuardError('INVALID_PANEL_IP') from exc
        if not addr.is_global or str(addr) != value:
            raise GuardError('PANEL_IP_MUST_BE_PUBLIC_IPV4')
        ips.add(str(addr))
    return sorted(ips, key=ipaddress.IPv4Address)



def trusted_exception_ips():
    """Panel backends plus verified Entry peer IP on cascade Exit, and nobody else.

    Read-only discovery; called under existing RKN lock. Refuse a torn role
    enrollment, uncertain schema, symlinks or mutable/foreign-owned secrets.
    Management port UFW ACL STILL references panel_ipv4 alone, never this union.
    """
    ips = set(panel_ips())
    has_role = CASCADE_ROLE.exists() or CASCADE_ROLE.is_symlink()
    has_marker = CASCADE_MARKER.exists() or CASCADE_MARKER.is_symlink()
    if not has_role and not has_marker:
        return sorted(ips, key=ipaddress.IPv4Address)
    if not has_role or not has_marker:
        raise GuardError('CASCADE_ROLE_PARTIAL_NO_RKN_EXCEPTION')
    for file in (CASCADE_ROLE, CASCADE_MARKER):
        st = file.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o077:
            raise GuardError('CASCADE_ROLE_FILE_UNSAFE')
        if os.geteuid() == 0 and st.st_uid != 0:
            raise GuardError('CASCADE_ROLE_FILE_NOT_ROOT')
        if st.st_size > 16384:
            raise GuardError('CASCADE_ROLE_FILE_TOO_LARGE')
    try:
        obj = json.loads(owned_file(CASCADE_ROLE))
        mark = json.loads(owned_file(CASCADE_MARKER))
        if not isinstance(obj, dict) or not isinstance(mark, dict):
            raise ValueError()
        if obj.get('role') != mark.get('role') or obj.get('pair_id') != mark.get('pair_id'):
            raise ValueError()
        if obj.get('role') == 'cascade-entry':
            return sorted(ips, key=ipaddress.IPv4Address)
        if obj.get('role') != 'cascade-exit' or obj.get('schema') != 2 or mark.get('schema') != 2:
            raise ValueError()
        peer = obj['peer']
        if not isinstance(peer, dict) or set(peer) != {'domain','ipv4','public_key','short_id','inbound_tag'}:
            raise ValueError()
        addr = ipaddress.IPv4Address(peer['ipv4'])
        if not addr.is_global or str(addr) != peer['ipv4'] or addr == ipaddress.IPv4Address(obj['self']['ipv4']):
            raise ValueError()
        # Public part of PairID pins this IP and cannot be changed alone.
        public = {'entry':peer, 'exit':{k:obj['self'][k] for k in peer},
                  'bridge_uuid':obj['bridge']['service_user_uuid'], 'schema':2}
        expected = hashlib.sha256(json.dumps(public, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if not hmac.compare_digest(expected, obj['pair_id']):
            raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError, ipaddress.AddressValueError) as exc:
        raise GuardError('CASCADE_EXIT_PEER_IDENTITY_INVALID') from exc
    ips.add(str(addr))
    return sorted(ips, key=ipaddress.IPv4Address)


def parse_networks(contents):
    if len(contents.encode('utf-8')) > MAX_BYTES:
        raise GuardError('LIST_TOO_LARGE')
    networks = set()
    for line_no, raw in enumerate(contents.lstrip('\ufeff').splitlines(), 1):
        value = raw.partition('#')[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise GuardError('INVALID_CIDR_AT_LINE_' + str(line_no)) from exc
        if network.version == 6:
            continue  # The node has a strict IPv4-only policy.
        if network.prefixlen < 16 or not network.is_global:
            raise GuardError('UNSAFE_CIDR_AT_LINE_' + str(line_no))
        networks.add(str(network))
        if len(networks) > MAX_ENTRIES:
            raise GuardError('TOO_MANY_CIDRS')
    if len(networks) < MIN_ENTRIES:
        raise GuardError('LIST_TOO_SMALL')
    return sorted(networks, key=lambda s: (int(ipaddress.IPv4Network(s).network_address),
                                            ipaddress.IPv4Network(s).prefixlen))


def parse_cached(text):
    if not text.strip():
        return []
    return parse_networks(text)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if newurl != SOURCE:
            raise GuardError('UNEXPECTED_REDIRECT')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download():
    request = urllib.request.Request(SOURCE, headers={'User-Agent': 'VKarmani-Node-RKN-Data/2.5.3',
                                                      'Accept': 'text/plain'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=35) as response:
            if response.status != 200 or response.geturl() != SOURCE:
                raise GuardError('UNEXPECTED_HTTP_RESPONSE')
            data = response.read(MAX_BYTES + 1)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise GuardError('UPSTREAM_DATA_UNAVAILABLE') from exc
    if len(data) > MAX_BYTES:
        raise GuardError('LIST_TOO_LARGE')
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise GuardError('INVALID_UTF8') from exc


def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise GuardError('UNSAFE_OUTPUT_SYMLINK')
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        folder_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def restore_record(path, original):
    """Reinstate a previously captured state file, including absence of file.

    A failed atomic() may have *published* its new bytes before raising on the
    directory fsync. Never assume that a failed write left the old file intact.
    """
    if path.is_symlink():
        raise GuardError('UNSAFE_ROLLBACK_SYMLINK')
    if original is None:
        if path.exists():
            if not path.is_file():
                raise GuardError('UNSAFE_ROLLBACK_TARGET')
            path.unlink()
            dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        if path.exists():
            raise GuardError('ROLLBACK_FILE_STILL_EXISTS')
    elif not path.exists() or owned_file(path) != original:
        atomic(path, original)
        if owned_file(path) != original:
            raise GuardError('ROLLBACK_BYTES_MISMATCH')


def restore_ufw_file(original, *, must_be_active):
    """Restore verified UFW bytes and sync runtime policy when it is active."""
    if owned_file(UFW_FILE) != original:
        atomic(UFW_FILE, original, mode=0o644)
    if owned_file(UFW_FILE) != original:
        raise GuardError('UFW_ROLLBACK_BYTES_MISMATCH')
    active = 'Status: active' in run('ufw', 'status').splitlines()
    if must_be_active and not active:
        raise GuardError('UFW_INACTIVE_DURING_ROLLBACK')
    if active:
        run('ufw', 'reload', timeout=50)
        check_ufw_active()


def checked_freshness(meta, now=None):
    """Explicit data-age diagnosis; no filesystem or firewall mutation."""
    if not isinstance(meta, dict):
        return 'INVALID'
    timestamp = meta.get('checked_at_utc')
    if not isinstance(timestamp, str):
        return 'UNKNOWN'
    try:
        when = dt.datetime.fromisoformat(timestamp)
    except ValueError:
        return 'INVALID'
    if when.tzinfo is None:
        return 'INVALID'
    now = now or dt.datetime.now(dt.timezone.utc)
    elapsed = now - when
    if elapsed < -dt.timedelta(minutes=5):
        return 'FUTURE'
    return 'STALE' if elapsed > MAX_CHECKPOINT_AGE else 'PASS'


def ipset_exists(name):
    proc = subprocess.run(['ipset', 'list', name], capture_output=True, text=True, timeout=12)
    if proc.returncode:
        return False
    want = 'hash:net' if name in (BLOCK_SET, BLOCK_STAGE) else 'hash:ip'
    if 'Type: ' + want not in proc.stdout or 'family inet' not in proc.stdout:
        raise GuardError('IPSET_SCHEMA_CONFLICT: ' + name)
    return True


def ipset_create(name):
    typ = 'hash:net' if name in (BLOCK_SET, BLOCK_STAGE) else 'hash:ip'
    run('ipset', 'create', name, typ, 'family', 'inet', 'hashsize', '4096',
        'maxelem', str(MAX_ENTRIES if typ == 'hash:net' else 64), timeout=15)


def ipset_stage(name, addresses):
    if not ipset_exists(name):
        ipset_create(name)
    lines = ['flush ' + name]
    lines.extend('add ' + name + ' ' + addr for addr in addresses)
    run('ipset', 'restore', data='\n'.join(lines) + '\n', timeout=90)


def restore_cached():
    if not CACHE.exists():
        return []
    return parse_cached(owned_file(CACHE))


def panel_refresh():
    ips = trusted_exception_ips()  # Include pinned Entry peer ONLY on Exit.
    ipset_stage(PANEL_STAGE, ips)
    run('ipset', 'swap', PANEL_STAGE, PANEL_SET)
    return ips


def _prepare_degraded(reason):
    """Keep the base UFW service bootable when optional ipset is unavailable.

    Never remove foreign rules. During boot UFW is not active yet; a validated
    owned-block removal prevents it loading rules that reference missing sets.
    Any failure to validate/restore this file remains fatal (manual console).
    """
    original = owned_file(UFW_FILE)
    revised = edit_ufw(original, False)
    if revised != original:
        run('iptables-restore', '--test', data=revised, timeout=20)
        try:
            atomic(UFW_FILE, revised, mode=0o644)
            # At boot UFW is inactive; on a live node we MUST reload to make
            # the in-kernel policy agree with the rewritten file.
            status = run('ufw', 'status')
            if 'Status: active' in status.splitlines():
                run('ufw', 'reload', timeout=50)
        except (GuardError, OSError) as exc:
            try:
                restore_ufw_file(original, must_be_active=False)
            except (GuardError, OSError) as rollback_exc:
                raise GuardError('PREPARE_DEGRADED_UFW_ROLLBACK_UNCONFIRMED') from rollback_exc
            raise
    print('RKN_PREPARE=DEGRADED BASE_UFW_PRESERVED REASON=' + reason, file=sys.stderr)
    return False


def prepare():
    """Prepare all ipsets before UFW or remove our dependent firewall fragment.

    A failed ipset create/restore must not block the base firewall from booting.
    If the owned block cannot be removed safely, fail explicitly rather than
    claiming an operational firewall.
    """
    require_node()
    try:
        ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
        new_block = not ipset_exists(BLOCK_SET)
        if new_block:
            ipset_create(BLOCK_SET)
        if not ipset_exists(PANEL_SET):
            ipset_create(PANEL_SET)
        panel = panel_refresh()
        if new_block:
            saved = restore_cached()
            if saved:
                ipset_stage(BLOCK_STAGE, saved)
                run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
    except (GuardError, OSError, ValueError) as exc:
        # Do not rely on `ipset flush`: the set may not even exist.
        return _prepare_degraded(type(exc).__name__)
    print('RKN_PREPARE=PASS PANEL_IPS=' + str(len(panel)))
    return True

def ufw_fragment():
    return ('\n' + BEGIN + '\n'
            ':VKARMANI_RKN - [0:0]\n'
            '-A ufw-before-input -p tcp -m multiport --dports 80,443 -j VKARMANI_RKN\n'
            '-A VKARMANI_RKN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n'
            '-A VKARMANI_RKN -m set --match-set ' + PANEL_SET + ' src -j RETURN\n'
            '-A VKARMANI_RKN -m set --match-set ' + BLOCK_SET + ' src -j DROP\n'
            '-A VKARMANI_RKN -j RETURN\n'
            + END + '\n')


def edit_ufw(text, enable):
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise GuardError('UFW_MARKER_CORRUPT')
    if 'SCANNERS-BLOCK' in text or 'antiscan' in text:
        raise GuardError('FOREIGN_RKN_GUARD_CONFLICT')
    if BEGIN in text:
        start = text.index(BEGIN)
        end = text.index(END, start) + len(END)
        if text[start:end] != ufw_fragment().strip('\n'):
            raise GuardError('UFW_MANAGED_BLOCK_DRIFT')
        # Reverse our exact leading/trailing newline; preserve unrelated bytes.
        before = start - 1 if start and text[start - 1] == '\n' else start
        after = end + 1 if end < len(text) and text[end] == '\n' else end
        text = text[:before] + text[after:]
    if not enable:
        return text
    rows = text.splitlines(keepends=True)
    filter_open = False
    saw_filter = False
    saw_chain = False
    insertion = None
    byte_pos = 0
    for row in rows:
        token = row.strip()
        if token == '*filter':
            if saw_filter:
                raise GuardError('DUPLICATE_UFW_FILTER')
            filter_open = True
            saw_filter = True
        elif token.startswith('*') or token == 'COMMIT':
            if filter_open and insertion is None:
                insertion = byte_pos
            filter_open = False
        elif filter_open:
            if token.startswith(':'):
                if insertion is not None:
                    raise GuardError('INVALID_UFW_CHAIN_ORDER')
                if token.split()[0] == ':ufw-before-input':
                    saw_chain = True
            elif token and not token.startswith('#') and insertion is None:
                insertion = byte_pos
        byte_pos += len(row)
    if not saw_filter or not saw_chain or insertion is None:
        raise GuardError('UFW_BEFORE_RULES_UNRECOGNIZED')
    return text[:insertion] + ufw_fragment() + text[insertion:]


def check_ufw_jump():
    run('iptables', '-C', 'ufw-before-input', '-p', 'tcp', '-m', 'multiport',
        '--dports', '80,443', '-j', CHAIN)
    run('iptables', '-C', CHAIN, '-m', 'set', '--match-set', PANEL_SET, 'src', '-j', 'RETURN')
    run('iptables', '-C', CHAIN, '-m', 'set', '--match-set', BLOCK_SET, 'src', '-j', 'DROP')


def check_ufw_active():
    status = run('ufw', 'status')
    if 'Status: active' not in status.splitlines():
        raise GuardError('UFW_MUST_ALREADY_BE_ACTIVE')


def apply_ufw(enable):
    check_ufw_active()
    original = owned_file(UFW_FILE)
    revised = edit_ufw(original, enable)
    if original == revised:
        if enable:
            check_ufw_jump()
        return
    # Validate the exact resulting restore input without applying it to kernel.
    run('iptables-restore', '--test', data=revised, timeout=20)
    snapshot = ROOT / ('ufw-before-pre-rkn' if enable else 'ufw-before-pre-disable')
    atomic(snapshot, original)
    try:
        atomic(UFW_FILE, revised, mode=0o644)
        run('ufw', 'reload', timeout=50)
        if enable:
            check_ufw_jump()
        else:
            run('iptables', '-S', 'ufw-before-input')
    except (GuardError, OSError) as exc:
        try:
            restore_ufw_file(original, must_be_active=True)
        except (GuardError, OSError) as rollback_exc:
            raise GuardError('UFW_RELOAD_AND_ROLLBACK_UNCONFIRMED') from rollback_exc
        raise


def update():
    require_node()
    if BEGIN not in owned_file(UFW_FILE):
        raise GuardError('RKN_NOT_ENABLED')
    if not prepare():
        raise GuardError('PANEL_OR_CACHE_INVALID_BLOCKING_DISABLED')
    new = parse_networks(download())
    old = restore_cached()
    if old and (len(new) * 2 < len(old) or len(new) > len(old) * 2):
        raise GuardError('SUSPICIOUS_NETWORK_COUNT_CHANGE')
    # Reconcile the active kernel set daily even when the source contents
    # are unchanged (e.g. a third-party flush or lost ipset membership).
    previous_kernel = live_block_set()
    previous_cache = owned_file(CACHE) if CACHE.exists() else None
    previous_checkpoint = owned_file(CHECKED) if CHECKED.exists() else None
    ipset_stage(BLOCK_STAGE, new)
    swapped = False
    try:
        run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
        swapped = True
        if new != old:
            atomic(CACHE, ''.join(item + '\n' for item in new))
        checked_at = dt.datetime.now(dt.timezone.utc).isoformat()
        # The upstream may not publish updates for months. Last success is not
        # the same thing as last content change; report both independently.
        changed_at = checked_at if new != old else None
        if new == old and previous_checkpoint is not None:
            try:
                old_mark = json.loads(previous_checkpoint)
                prior = old_mark.get('content_changed_at_utc')
                changed_at = prior if isinstance(prior, str) and prior else None
            except (ValueError, AttributeError, TypeError):
                changed_at = None
        stamp = {'checked_at_utc': checked_at,
                 'content_changed_at_utc': changed_at,
                 'source': SOURCE, 'count_ipv4': len(new),
                 'sha256': hashlib.sha256((''.join(s + '\n' for s in new)).encode()).hexdigest(),
                 'changed': new != old, 'code_upstream': UPSTREAM,
                 'code_auto_update': False}
        atomic(CHECKED, json.dumps(stamp, sort_keys=True, ensure_ascii=False, indent=2) + '\n')
        check_ufw_jump()
        active_after = live_block_set()
        if len(active_after) != len(new) or set(active_after) != set(new):
            raise GuardError('RKN_KERNEL_SET_UPDATE_MISMATCH')
    except (GuardError, OSError) as exc:
        # Reverse kernel swap AND both disk records, including a record that
        # atomic() published before reporting a directory fsync failure.
        try:
            if swapped:
                run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
                restored = live_block_set()
                if len(restored) != len(previous_kernel) or set(restored) != set(previous_kernel):
                    raise GuardError('RKN_KERNEL_ROLLBACK_MISMATCH')
            restore_record(CACHE, previous_cache)
            restore_record(CHECKED, previous_checkpoint)
        except (GuardError, OSError) as rollback_exc:
            raise GuardError('RKN_UPDATE_ROLLBACK_UNCONFIRMED') from rollback_exc
        raise
    print('RKN_UPDATE=PASS IPV4_NETWORKS=' + str(len(new)) + ' CHANGED=' + str(new != old))


def enable():
    require_node()
    check_ufw_active()
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not prepare():
        raise GuardError('PANEL_LIST_INVALID_RKN_NOT_ENABLED')
    was_enabled = BEGIN in owned_file(UFW_FILE)
    apply_ufw(True)
    try:
        update()
    except (GuardError, OSError, ValueError) as exc:
        # A valid old list may remain active when GitHub/network is unavailable.
        # Check the actual cached bytes against the recorded successful stamp;
        # a parseable but never-verified list is NOT proof of scanner protection.
        verified = False
        fallback_freshness = 'UNKNOWN'
        try:
            old = restore_cached()
            meta = json.loads(owned_file(CHECKED))
            digest = hashlib.sha256((''.join(x + '\n' for x in old)).encode()).hexdigest()
            verified = bool(old and isinstance(meta, dict) and
                            meta.get('sha256') == digest and
                            meta.get('count_ipv4') == len(old))
            if verified:
                # An existing iptables jump is NOT evidence of populated
                # active kernel sets. Repair from signed-off local data only.
                active = live_block_set()
                if len(active) != len(old) or set(active) != set(old):
                    ipset_stage(BLOCK_STAGE, old)
                    run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
                    active = live_block_set()
                    if len(active) != len(old) or set(active) != set(old):
                        raise GuardError('RKN_KERNEL_CACHE_RESTORE_MISMATCH')
                if set(live_panel_set()) != set(trusted_exception_ips()):
                    raise GuardError('RKN_TRUSTED_SOURCE_EXCLUSION_MISMATCH')
                fallback_freshness = checked_freshness(meta)
        except (GuardError, OSError, ValueError, TypeError, KeyError):
            verified = False
        if not verified:
            # This is safe only when THIS invocation installed the block.
            # For an existing filter, preserve state for operator recovery.
            if not was_enabled:
                apply_ufw(False)
            raise GuardError('RKN_NO_VERIFIED_LIST_INITIAL_ACTIVATION') from exc
        print('RKN_DATA=DEGRADED_USING_VERIFIED_CACHE FRESHNESS=' + fallback_freshness,
              file=sys.stderr)
        if fallback_freshness != 'PASS':
            if not was_enabled:
                apply_ufw(False)
            raise GuardError('RKN_CACHE_FRESHNESS_' + fallback_freshness) from exc
    # Print success only after a fresh update or independently verified cache.
    check_ufw_jump()
    print('RKN_FIREWALL=ENABLED TCP_80_443_ONLY PANEL_AND_PINNED_EXIT_PEER_EXCEPTION=DYNAMIC')


def live_block_set():
    """Read the installed IPv4 set; a matching on-disk cache is not enough."""
    raw = run('ipset', 'save', BLOCK_SET, timeout=20)
    active = []
    for line in raw.splitlines():
        if line.startswith('add '):
            words = line.split()
            if len(words) != 3 or words[1] != BLOCK_SET:
                raise GuardError('ACTIVE_BLOCK_SET_UNEXPECTED_ENTRY')
            try:
                active.append(str(ipaddress.IPv4Network(words[2], strict=False)))
            except ValueError as exc:
                raise GuardError('ACTIVE_BLOCK_SET_MALFORMED_IPV4') from exc
    return active


def live_panel_set():
    """Validate real kernel members, never infer panel bypass from rule text."""
    raw = run('ipset', 'save', PANEL_SET, timeout=20)
    addresses = []
    for line in raw.splitlines():
        if not line.startswith('add '):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[1] != PANEL_SET:
            raise GuardError('ACTIVE_PANEL_SET_UNEXPECTED_ENTRY')
        try:
            ip = ipaddress.IPv4Address(fields[2])
        except ipaddress.AddressValueError as exc:
            raise GuardError('ACTIVE_PANEL_SET_INVALID_IPV4') from exc
        if not ip.is_global or str(ip) != fields[2]:
            raise GuardError('ACTIVE_PANEL_SET_UNSAFE_IPV4')
        addresses.append(str(ip))
    if len(addresses) != len(set(addresses)):
        raise GuardError('ACTIVE_PANEL_SET_DUPLICATES')
    return addresses


def status():
    require_node()
    enabled = BEGIN in owned_file(UFW_FILE)
    print('RKN_ENABLED=' + str(enabled))
    print('RKN_SOURCE=' + SOURCE)
    print('RKN_UPSTREAM=' + UPSTREAM + ' (manual code review per release)')
    panel_valid = True
    expected_panel = None
    try:
        expected_panel = trusted_exception_ips()
        print('RKN_TRUSTED_EXCEPTIONS_COUNT=' + str(len(expected_panel)))
    except (ValueError, GuardError, OSError):
        print('RKN_TRUSTED_EXCEPTIONS=INVALID')
        panel_valid = False
    if CHECKED.exists():
        checkpoint_text = owned_file(CHECKED)
        print('RKN_LAST_CHECK=' + checkpoint_text)
        try:
            checkpoint = json.loads(checkpoint_text)
            changed = checkpoint.get('content_changed_at_utc', 'UNKNOWN')
            print('RKN_LAST_CONTENT_CHANGE=' + changed if isinstance(changed, str) else 'RKN_LAST_CONTENT_CHANGE=UNKNOWN')
        except (ValueError, AttributeError):
            print('RKN_LAST_CONTENT_CHANGE=INVALID')
    else:
        print('RKN_LAST_CHECK=NEVER')
        print('RKN_LAST_CONTENT_CHANGE=UNKNOWN')
    if enabled:
        check_ufw_jump()
        print('RKN_FIREWALL_RULES=PASS')
        try:
            active_panel = live_panel_set()
            if expected_panel is None or set(active_panel) != set(expected_panel):
                raise GuardError('ACTIVE_PANEL_SET_CONFIG_MISMATCH')
            print('RKN_PANEL_SET_MATCH=PASS ACTIVE_IPV4=' + str(len(active_panel)))
        except (GuardError, OSError, ValueError) as exc:
            print('RKN_PANEL_SET_MATCH=FAIL REASON=' + type(exc).__name__)
            panel_valid = False
        try:
            cached = restore_cached()
            if not cached:
                raise GuardError('NO_VALID_CACHE')
            mark = json.loads(owned_file(CHECKED))
            if not isinstance(mark, dict):
                raise GuardError('INVALID_CHECKPOINT_ROOT')
            expected = hashlib.sha256((''.join(x + '\n' for x in cached)).encode()).hexdigest()
            if mark.get('sha256') != expected or mark.get('count_ipv4') != len(cached):
                raise GuardError('CACHE_AND_CHECKPOINT_MISMATCH')
            active = live_block_set()
            if len(active) != len(cached) or set(active) != set(cached):
                raise GuardError('KERNEL_SET_CACHE_MISMATCH')
            print('RKN_DATA_INTEGRITY=PASS ACTIVE_IPV4_NETWORKS=' + str(len(active)))
            fresh = checked_freshness(mark)
            print('RKN_FRESHNESS=' + fresh)
            if fresh != 'PASS':
                print('RKN_DATA=DEGRADED REASON=FRESHNESS_' + fresh)
                return 1
            print('RKN_DATA=PASS ACTIVE_IPV4_NETWORKS=' + str(len(active)))
        except (GuardError, ValueError, OSError, KeyError, TypeError) as exc:
            print('RKN_DATA=DEGRADED REASON=' + type(exc).__name__)
            return 1
    else:
        print('RKN_FIREWALL_RULES=DISABLED')
        print('RKN_PANEL_SET_MATCH=NOT_APPLICABLE')
    return 0 if panel_valid else 1


def disable():
    require_node()
    apply_ufw(False)
    print('RKN_FIREWALL=DISABLED; original UFW SSH/panel/VPN rules preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'sync-panel', 'enable', 'update', 'status', 'disable'])
    args = parser.parse_args()
    os.umask(0o077)
    if args.action != 'status':
        LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        if args.action == 'status':
            return status()
        with open(LOCK, 'a', encoding='utf-8') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'prepare':
                # A corrupt panel config disables RKN filtering, never UFW at boot.
                prepare()
                return 0
            if args.action == 'sync-panel':
                # Unlike the boot service, explicit operator sync reports failure.
                return 0 if prepare() else 1
            if args.action == 'enable':
                enable()
            elif args.action == 'update':
                update()
            else:
                disable()
        return 0
    except (GuardError, OSError, ValueError, json.JSONDecodeError, BlockingIOError) as exc:
        print('RKN_GUARD=FAIL ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
