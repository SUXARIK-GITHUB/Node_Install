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
    ips = panel_ips()  # Re-read every operation; no baked-in panel IP.
    ipset_stage(PANEL_STAGE, ips)
    run('ipset', 'swap', PANEL_STAGE, PANEL_SET)
    return ips


def prepare():
    """Offline, safe before UFW: provision sets even when source is unavailable."""
    require_node()
    ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
    new_block = not ipset_exists(BLOCK_SET)
    if new_block:
        ipset_create(BLOCK_SET)
    if not ipset_exists(PANEL_SET):
        ipset_create(PANEL_SET)
    try:
        panel = panel_refresh()
    except (GuardError, ValueError, OSError) as exc:
        # Safe failure: never enforce an unexempted scanner list on the panel.
        run('ipset', 'flush', BLOCK_SET)
        print('RKN_PREPARE=FAIL_OPEN PANEL_CONFIG: ' + str(exc), file=sys.stderr)
        return False
    if new_block:
        try:
            saved = restore_cached()
            if saved:
                ipset_stage(BLOCK_STAGE, saved)
                run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
        except (GuardError, OSError, ValueError) as exc:
            run('ipset', 'flush', BLOCK_SET)
            print('RKN_PREPARE=FAIL_OPEN CACHE: ' + str(exc), file=sys.stderr)
            return False
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
    if enable:
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
    except GuardError as exc:
        atomic(UFW_FILE, original, mode=0o644)
        try:
            run('ufw', 'reload', timeout=50)
        except GuardError:
            raise GuardError('UFW_RELOAD_AND_ROLLBACK_UNCONFIRMED') from exc
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
    ipset_stage(BLOCK_STAGE, new)
    run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
    try:
        if new != old:
            atomic(CACHE, ''.join(item + '\n' for item in new))
    except (OSError, GuardError):
        run('ipset', 'swap', BLOCK_STAGE, BLOCK_SET)
        raise
    stamp = {'checked_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
             'source': SOURCE, 'count_ipv4': len(new),
             'sha256': hashlib.sha256((''.join(s + '\n' for s in new)).encode()).hexdigest(),
             'changed': new != old, 'code_upstream': UPSTREAM,
             'code_auto_update': False}
    atomic(CHECKED, json.dumps(stamp, sort_keys=True, ensure_ascii=False, indent=2) + '\n')
    check_ufw_jump()
    print('RKN_UPDATE=PASS IPV4_NETWORKS=' + str(len(new)) + ' CHANGED=' + str(new != old))


def enable():
    require_node()
    check_ufw_active()
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not prepare():
        raise GuardError('PANEL_LIST_INVALID_RKN_NOT_ENABLED')
    apply_ufw(True)
    print('RKN_FIREWALL=ENABLED TCP_80_443_ONLY PANEL_EXCEPTION=DYNAMIC')
    try:
        update()
    except (GuardError, OSError, ValueError) as exc:
        # Network outage/invalid source never rolls back the healthy UFW/SSH setup.
        print('RKN_DATA=PENDING_TIMER_RETRY ' + str(exc), file=sys.stderr)


def status():
    require_node()
    print('RKN_ENABLED=' + str(BEGIN in owned_file(UFW_FILE)))
    print('RKN_SOURCE=' + SOURCE)
    print('RKN_UPSTREAM=' + UPSTREAM + ' (manual code review per release)')
    try:
        print('RKN_PANEL_FROM_CONFIG=' + ','.join(panel_ips()))
    except (ValueError, GuardError, OSError):
        print('RKN_PANEL_FROM_CONFIG=INVALID')
    if CHECKED.exists():
        print('RKN_LAST_CHECK=' + owned_file(CHECKED))
    else:
        print('RKN_LAST_CHECK=NEVER')
    if BEGIN in owned_file(UFW_FILE):
        check_ufw_jump()
        print('RKN_FIREWALL=PASS')


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
            status()
            return 0
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
