#!/usr/bin/env python3
"""Opt-in, loopback-only Blocky DNS for Node Install (Ordinary / Cascade Exit).

No modification of Remnawave panel profiles, container settings, /etc/resolv.conf,
Nginx, SSH, firewall or default network routes. DNS filtering is *effective only*
for queries intentionally sent to this resolver; this command never claims all
VPN clients are covered without a genuine panel/client integration test.

The updater is installed on the host as an isolated Python stdlib-only program.
All mutation operations are explicit, locked, and root-only. A failure rolls back
files and service status, without touching the live Xray/Remnawave process.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

VERSION = '0.35.0'
ARCHIVES = {
    'x86_64': ('Linux_x86_64', '97ae4257e4f2ea7ee4e0622fca152019eb92224d81b41b2549f064e4cef5584e'),
    'aarch64': ('Linux_arm64', '9ac70e846f7919632e340607fb73d80a1fe280c9ceb876430d2a7d79743b4aae'),
}
LIST_URL = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi.txt'
INSTALL_DIR = Path('/usr/local/libexec/node-install-adblock')
CONFIG_DIR = Path('/etc/node-install-adblock')
DATA_DIR = Path('/var/lib/node-install-adblock')
UNIT_DIR = Path('/etc/systemd/system')
NODE_STATE = Path('/var/lib/vkarmani-node')
NODE_ETC = Path('/etc/vkarmani-node')
LOCK = Path('/run/lock/node-install-adblock.lock')
SERVICE = 'node-install-adblock.service'
UPDATER_SERVICE = 'node-install-adblock-update.service'
UPDATER_TIMER = 'node-install-adblock-update.timer'
PORT = 15353
LIST_FILE = 'hagezi-normal.txt'
# Reserved documentation hostname with a real A record: a synthetic invalid TLD
# would normally return NXDOMAIN even with filtering switched off.
PROBE_NAME = 'www.example.com'
SENTINEL = '*.www.example.com'
MARKER = 'managed.json'
VERSION_MARK = 'NODE_INSTALL_ADBLOCK_V1'
MAX_BINARY_ARCHIVE = 32 * 1024 * 1024
MAX_BINARY = 48 * 1024 * 1024
MAX_LIST = 24 * 1024 * 1024
MIN_ENTRIES = 30000
MAX_ENTRIES = 600000
DNS_TIMEOUT = 3.0


class AdblockError(RuntimeError):
    pass


def require(test, code):
    if not test:
        raise AdblockError(code)


def run(*argv, timeout=30, must=True):
    result = subprocess.run(list(argv), input=None, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, text=True, check=False,
                            env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                 'LANG': 'C', 'LC_ALL': 'C'})
    if must and result.returncode:
        raise AdblockError('COMMAND_FAILED:' + str(argv[1] if len(argv)>1 else argv[0]))
    return result


def root_only():
    require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'ROOT_LINUX_REQUIRED')


def regular_file(path: Path, *, owner_root=True):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
            not (st.st_mode & 0o022) and
            (not owner_root or st.st_uid == 0), 'UNSAFE_FILE:' + str(path))
    return st


def managed_directory(path: Path):
    if path.is_symlink():
        raise AdblockError('UNSAFE_DIRECTORY:' + str(path))
    if path.exists():
        st = path.stat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'UNSAFE_DIRECTORY:' + str(path))
    else:
        path.mkdir(mode=0o755, parents=False)
    return path


def atomic_write(path: Path, payload: bytes, mode=0o644):
    regular_file(path)
    fd, tmp = tempfile.mkstemp(prefix='.node-adblock-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as dest:
            dest.write(payload)
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def fetched(url, limit, *, opener=urllib.request.urlopen):
    require(url.startswith('https://') and '\n' not in url, 'HTTPS_DOWNLOAD_REQUIRED')
    req = urllib.request.Request(url, headers={'User-Agent': 'NodeInstall-Adblock/1.0'})
    with opener(req, timeout=40) as response:
        final_url = response.geturl()
        require(final_url.startswith('https://'), 'UNSAFE_REDIRECT')
        declared = response.headers.get('Content-Length')
        if declared is not None:
            require(int(declared) <= limit, 'DOWNLOAD_TOO_LARGE')
        data = response.read(limit + 1)
    require(0 < len(data) <= limit, 'DOWNLOAD_INVALID_SIZE')
    return data


def archive_details(machine=None):
    machine = machine or platform.machine()
    require(machine in ARCHIVES, 'UNSUPPORTED_CPU_ARCHITECTURE')
    build, digest = ARCHIVES[machine]
    name = f'blocky_v{VERSION}_{build}.tar.gz'
    return 'https://github.com/0xERR0R/blocky/releases/download/v' + VERSION + '/' + name, digest


def extract_binary(archive: bytes, digest: str):
    require(hashlib.sha256(archive).hexdigest() == digest, 'BLOCKY_ARCHIVE_CHECKSUM_MISMATCH')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name in ('blocky', './blocky')]
        require(len(members) == 1 and members[0].isfile() and
                0 < members[0].size <= MAX_BINARY, 'BLOCKY_ARCHIVE_CONTENT_INVALID')
        source = tar.extractfile(members[0])
        require(source is not None, 'BLOCKY_BINARY_MISSING')
        content = source.read(MAX_BINARY + 1)
    require(0 < len(content) <= MAX_BINARY and content[:4] == b'\x7fELF', 'BLOCKY_BINARY_INVALID')
    return content


def validate_list(data: bytes, previous_count: int = 0):
    require(100_000 <= len(data) <= MAX_LIST, 'LIST_SIZE_UNEXPECTED')
    try:
        text = data.decode('utf-8')
    except UnicodeError as exc:
        raise AdblockError('LIST_NOT_UTF8') from exc
    require("HaGeZi's Multi NORMAL" in text[:512], 'WRONG_LIST_SOURCE')
    lines = []
    for raw in text.splitlines():
        value = raw.strip()
        if not value or value.startswith('#'):
            continue
        require(len(value) <= 253 and re.fullmatch(r'\*\.(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}', value),
                'LIST_ENTRY_INVALID')
        lines.append(value)
    count = len(lines)
    require(MIN_ENTRIES <= count <= MAX_ENTRIES, 'LIST_ENTRY_COUNT_UNEXPECTED')
    if previous_count:
        require(previous_count * 0.70 <= count <= previous_count * 1.30, 'LIST_SUSPICIOUS_CHANGE')
    require(len(set(lines)) >= count * .985, 'LIST_TOO_MANY_DUPLICATES')
    return count


def list_payload(data: bytes):
    return data.rstrip(b'\r\n') + b'\n' + SENTINEL.encode() + b'\n'


def count_stored(data: bytes):
    return sum(bool(x and not x.startswith(b'#') and x != SENTINEL.encode()) for x in data.splitlines())


def runtime_config(filtering=True):
    # Explicit loopback listener; no API, DoT, public DNS or high privileged port.
    body = """# Managed by Node Install. Changes through --adblock, not by editing this file.
upstreams:
  groups:
    default:
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
  strategy: parallel_best
  timeout: 3s
ports:
  dns:
    - '127.0.0.1:15353'
logging: {}
log:
  level: warn
  privacy: true
caching:
  maxTime: 20m
  maxItemsCount: 10000
"""
    if filtering:
        body += """blocking:
  denylists:
    ads:
      - /var/lib/node-install-adblock/hagezi-normal.txt
  clientGroupsBlock:
    default:
      - ads
  blockType: nxDomain
  blockTTL: 1m
  loading:
    refreshPeriod: 5m
    strategy: failOnError
"""
    return body.replace('logging: {}\n', '').encode('utf-8')


def service_unit():
    return """[Unit]
Description=Node Install local Blocky ad-block DNS resolver
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
DynamicUser=yes
WorkingDirectory=/var/lib/node-install-adblock
ExecStart=/usr/local/libexec/node-install-adblock/blocky --config /etc/node-install-adblock/config.yml
Restart=on-failure
RestartSec=4s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
LockPersonality=yes
UMask=0077
[Install]
WantedBy=multi-user.target
""".encode()


def update_unit():
    return """[Unit]
Description=Refresh HaGeZi Normal for Node Install Blocky
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/node-install-adblock/adblock.py update
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/node-install-adblock /run/lock
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
""".encode()


def timer_unit():
    return """[Unit]
Description=Daily HaGeZi update (Node Install)
[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=45m
Persistent=true
Unit=node-install-adblock-update.service
[Install]
WantedBy=timers.target
""".encode()


def profile_example():
    # A real Remnawave configuration is panel-owned and MUST NOT be edited here.
    example = {
        'dns': {'servers': [{'address': '127.0.0.1', 'port': PORT}], 'queryStrategy': 'UseIPv4'},
    }
    return (json.dumps(example, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def required_files(filtering=True):
    here = Path(__file__).resolve()
    return {
        INSTALL_DIR/'adblock.py': (here.read_bytes(), 0o755),
        CONFIG_DIR/'config.yml': (runtime_config(filtering), 0o644),
        CONFIG_DIR/'remnawave-dns-example.json': (profile_example(), 0o600),
        UNIT_DIR/SERVICE: (service_unit(), 0o644),
        UNIT_DIR/UPDATER_SERVICE: (update_unit(), 0o644),
        UNIT_DIR/UPDATER_TIMER: (timer_unit(), 0o644),
    }


def ensure_node():
    complete = NODE_STATE / 'INSTALL_COMPLETE'
    require(regular_file(complete) is not None, 'NODE_NOT_INSTALLED')
    role_file = NODE_STATE / 'role.json'
    if role_file.exists() or role_file.is_symlink():
        require(regular_file(role_file) is not None, 'UNSAFE_ROLE_STATE')
        try:
            role = json.loads(role_file.read_text())['role']
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise AdblockError('INVALID_NODE_ROLE') from exc
    else:
        role = 'ordinary'
    cascade = NODE_ETC/'cascade-role.json'
    require(not cascade.is_symlink(), 'UNSAFE_CASCADE_STATE')
    require((role == 'ordinary' and not cascade.exists()) or
            (role in ('cascade-entry','cascade-exit') and regular_file(cascade) is not None),
            'NODE_ROLE_STATE_MISMATCH')
    require(role in ('ordinary','cascade-exit'), 'ADBLOCK_ONLY_ON_ORDINARY_OR_EXIT')
    return role


def owned_marker():
    path = CONFIG_DIR / MARKER
    if not path.exists() and not path.is_symlink():
        return None
    require(regular_file(path) is not None, 'UNSAFE_MANAGEMENT_MARKER')
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise AdblockError('INVALID_MANAGEMENT_MARKER') from exc
    require(data.get('manager') == VERSION_MARK and data.get('schema') == 1,
            'FOREIGN_INSTALLATION')
    return data


def check_existing(marker):
    for path in (INSTALL_DIR/'blocky', INSTALL_DIR/'adblock.py',
                 CONFIG_DIR/'config.yml', CONFIG_DIR/'remnawave-dns-example.json',
                 DATA_DIR/LIST_FILE, UNIT_DIR/SERVICE, UNIT_DIR/UPDATER_SERVICE,
                 UNIT_DIR/UPDATER_TIMER):
        if path.exists() or path.is_symlink():
            require(marker is not None, 'FOREIGN_BLOCKY_ARTIFACT:' + str(path))
            regular_file(path)
    # Do not overwrite operator edits to the active resolver configuration.
    if marker is not None and (CONFIG_DIR/'config.yml').exists():
        expected = marker.get('config_sha256')
        require(expected == hashlib.sha256((CONFIG_DIR/'config.yml').read_bytes()).hexdigest(),
                'CONFIG_MODIFIED_OUTSIDE_MANAGER')
    if marker is not None and (INSTALL_DIR/'blocky').exists():
        require(marker.get('binary_sha256') == hashlib.sha256((INSTALL_DIR/'blocky').read_bytes()).hexdigest(),
                'BINARY_MODIFIED_OUTSIDE_MANAGER')


def check_port_free():
    for socktype in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        sock = socket.socket(socket.AF_INET, socktype)
        try:
            sock.bind(('127.0.0.1', PORT))
        except OSError as exc:
            raise AdblockError('LOOPBACK_DNS_PORT_OCCUPIED') from exc
        finally:
            sock.close()


def systemd_active(unit):
    try:
        return run('systemctl', 'is-active', '--quiet', unit, must=False, timeout=6).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def dns_query(name, *, port=PORT, timeout=DNS_TIMEOUT):
    # A tiny bounded DNS A-query; never relies on /etc/resolv.conf or external tools.
    encoded = b''.join(bytes((len(label),)) + label.encode('idna') for label in name.split('.')) + b'\x00'
    payload = b'NI\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + encoded + b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, ('127.0.0.1', port))
        answer, sender = sock.recvfrom(4096)
    require(sender[0] == '127.0.0.1' and sender[1] == port and len(answer) >= 12
            and answer[:2] == b'NI' and answer[2] & 0x80, 'INVALID_DNS_RESPONSE')
    return answer[3] & 15


def probe(filtering):
    # The first Blocky boot may need several seconds to parse >100k entries.
    # Verify a REAL, otherwise resolvable domain instead of querying an .invalid
    # name that would be NXDOMAIN even if the blocklist were not loaded.
    deadline = time.monotonic() + 25
    last_error = 'ADBLOCK_DNS_NOT_READY'
    while True:
        try:
            require(systemd_active(SERVICE), 'ADBLOCK_SERVICE_NOT_RUNNING')
            require(dns_query('example.org') == 0, 'ADBLOCK_FORWARDING_FAILED')
            probe_rcode = dns_query(PROBE_NAME)
            if filtering:
                require(probe_rcode == 3, 'ADBLOCK_FILTER_NOT_APPLIED')
            else:
                require(probe_rcode == 0, 'ADBLOCK_BYPASS_NOT_WORKING')
            return
        except (AdblockError, OSError, socket.timeout) as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            raise AdblockError('ADBLOCK_PROBE_TIMEOUT:' + last_error)
        time.sleep(0.5)



@contextlib.contextmanager
def locked():
    # A dedicated lock, separate from the global installer lock. Only adblock
    # actions use this lock; normal installation and panel updates are untouched.
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1, 'UNSAFE_LOCK')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def update_lists():
    root_only()
    with locked():
        marker = owned_marker()
        require(marker is not None, 'ADBLOCK_NOT_INSTALLED')
        check_existing(marker)
        target = DATA_DIR/LIST_FILE
        prev = count_stored(target.read_bytes()) if regular_file(target) else 0
        raw = fetched(LIST_URL, MAX_LIST)
        count = validate_list(raw, prev)
        payload = list_payload(raw)
        if target.exists() and hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(payload).digest():
            print('ADBLOCK_UPDATE=UNCHANGED ENTRIES=' + str(count))
            return
        backup = DATA_DIR/'hagezi-normal.previous.txt'
        if target.exists():
            atomic_write(backup, target.read_bytes())
        atomic_write(target, payload)
        print('ADBLOCK_UPDATE=PASS ENTRIES=' + str(count) + ' PREVIOUS=KEPT')


def status():
    try:
        marker = owned_marker()
        if not marker:
            print('ADBLOCK=NOT_INSTALLED')
            return 0
        check_existing(marker)
        enabled = systemd_active(SERVICE)
        filtering = marker.get('filtering') is True
        print('ADBLOCK=' + ('FILTERING' if filtering and enabled else 'DNS_ONLY' if enabled else 'INACTIVE'))
        print('LIST=' + LIST_URL)
        print('DNS_BIND=127.0.0.1:' + str(PORT))
        print('DNS_ENTRIES=' + str(count_stored((DATA_DIR/LIST_FILE).read_bytes()) if (DATA_DIR/LIST_FILE).exists() else 0))
        print('CLIENT_DNS=NOT_VERIFIED')
        print('PANEL_PROFILE=NOT_CHANGED')
        print('SSH_UFW_DOCKER=NOT_CHANGED')
        return 0
    except (AdblockError, OSError) as exc:
        print('ADBLOCK=REVIEW REASON=' + str(exc), file=sys.stderr)
        return 2


def install(enable_filtering=True):
    root_only()
    ensure_node()
    require(shutil.which('systemctl') is not None, 'SYSTEMD_REQUIRED')
    with locked():
        previous = owned_marker()
        check_existing(previous)
        if previous is not None and previous.get('filtering') is enable_filtering and systemd_active(SERVICE):
            print('ADBLOCK=ALREADY_CONFIGURED CLIENT_DNS=NOT_VERIFIED')
            return
        if not systemd_active(SERVICE):
            check_port_free()
        if previous is None:
            url, expected = archive_details()
            binary = extract_binary(fetched(url, MAX_BINARY_ARCHIVE), expected)
        else:
            require(regular_file(INSTALL_DIR/'blocky') is not None, 'BLOCKY_BINARY_MISSING')
            binary = (INSTALL_DIR/'blocky').read_bytes()
        previous_list = (DATA_DIR/LIST_FILE).read_bytes() if regular_file(DATA_DIR/LIST_FILE) else None
        if previous_list is None:
            fresh = fetched(LIST_URL, MAX_LIST)
            count = validate_list(fresh)
            data = list_payload(fresh)
        else:
            count = count_stored(previous_list)
            require(count >= MIN_ENTRIES, 'INVALID_STORED_LIST')
            data = previous_list
        for dirpath in (INSTALL_DIR.parent, CONFIG_DIR.parent, DATA_DIR.parent,
                        INSTALL_DIR, CONFIG_DIR, DATA_DIR):
            managed_directory(dirpath)
        marker_path = CONFIG_DIR/MARKER
        content = required_files(enable_filtering)
        content[INSTALL_DIR/'blocky'] = (binary, 0o755)
        content[DATA_DIR/LIST_FILE] = (data, 0o644)
        oldfiles = {path: (path.read_bytes() if regular_file(path) else None) for path in content}
        old_marker = marker_path.read_bytes() if regular_file(marker_path) else None
        old_active = systemd_active(SERVICE)
        old_timer = systemd_active(UPDATER_TIMER)
        try:
            for path, (payload, mode) in content.items():
                if oldfiles[path] != payload:
                    atomic_write(path, payload, mode)
            new_marker = {'schema': 1, 'manager': VERSION_MARK,
                          'version': VERSION, 'filtering': enable_filtering,
                          'config_sha256': hashlib.sha256(content[CONFIG_DIR/'config.yml'][0]).hexdigest(),
                          'binary_sha256': hashlib.sha256(binary).hexdigest()}
            atomic_write(marker_path, (json.dumps(new_marker, sort_keys=True) + '\n').encode(), 0o600)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'enable', SERVICE)
            run('systemctl', 'restart', SERVICE)
            probe(enable_filtering)
            run('systemctl', 'enable', '--now', UPDATER_TIMER)
        except (OSError, AdblockError, subprocess.SubprocessError):
            # Restore every managed artifact exactly as it was prior to the call.
            run('systemctl', 'stop', SERVICE, must=False)
            for path, value in oldfiles.items():
                if value is None:
                    if path.exists(): path.unlink()
                else:
                    mode = 0o755 if path in (INSTALL_DIR/'blocky', INSTALL_DIR/'adblock.py') else 0o644
                    if path.name == 'remnawave-dns-example.json': mode = 0o600
                    atomic_write(path, value, mode)
            if old_marker is None:
                if marker_path.exists(): marker_path.unlink()
            else:
                atomic_write(marker_path, old_marker, 0o600)
            if not old_timer: run('systemctl', 'disable', '--now', UPDATER_TIMER, must=False)
            if not old_active: run('systemctl', 'disable', SERVICE, must=False)
            run('systemctl', 'daemon-reload', must=False)
            if old_active:
                run('systemctl', 'restart', SERVICE, must=False)
            raise
        print('ADBLOCK=' + ('FILTERING' if enable_filtering else 'DNS_ONLY'))
        print('BLOCKY_VERSION=' + VERSION + ' LIST_ENTRIES=' + str(count))
        print('DNS=127.0.0.1:' + str(PORT) + ' CLIENT_DNS=NOT_VERIFIED')
        print('REMNAWAVE_PROFILE=UNCHANGED; FILTERING_CLIENTS_REQUIRES_DNS_ROUTING')


def disable():
    # IMPORTANT: never stop a resolver that a panel-owned profile may use!
    if owned_marker() is None:
        print('ADBLOCK=NOT_INSTALLED')
        return
    install(enable_filtering=False)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['enable', 'disable', 'status', 'update', 'probe'])
    args = p.parse_args(argv)
    try:
        if args.command == 'status':
            return status()
        if args.command == 'enable':
            install(True)
        elif args.command == 'disable':
            disable()
        elif args.command == 'update':
            update_lists()
        else:
            marker = owned_marker()
            require(marker is not None, 'ADBLOCK_NOT_INSTALLED')
            probe(marker.get('filtering') is True)
            print('ADBLOCK_DNS_PROBE=PASS CLIENT_DNS=NOT_VERIFIED')
        return 0
    except (AdblockError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ADBLOCK=STOP REASON=' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
