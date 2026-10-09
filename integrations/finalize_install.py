#!/usr/bin/env python3
"""Finish ONLY a recorded 2.5.6 final-acceptance checkpoint, never reinstall the OS.

Caller owns the installer flock. No panel API, package installation, key rotation,
container recreation, SSH editing or reboot. RKN's existing owned rollback is used.
The root argument and injectable runner are for offline tests; CLI has no --root.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

VERSION = '2.5.6'
STATE = 'var/lib/vkarmani-node'
CHECKER = '/usr/local/sbin/vkarmani-node-check'
KEY_HELPER = '/usr/local/lib/vkarmani-node/node_helper.py'
RKN = '/usr/local/sbin/vkarmani-rkn-guard'
UFW = 'etc/ufw/before.rules'
DROPIN = 'etc/systemd/system/ufw.service.d/90-vkarmani-rkn.conf'
RKN_MARKER = '# BEGIN VKARMANI-RKN-GUARD IPv4 managed by Node_Install'
WATCHED = (
    'etc/vkarmani-node/config.json', 'etc/vkarmani-node/reality.json',
    'etc/vkarmani-node/profile.json', 'etc/vkarmani-node/remnanode.env',
    'etc/vkarmani-node/time-provider', 'etc/vkarmani-node/ssh-ports',
    'opt/vkarmani-node/compose.yaml', STATE + '/install-version',
    STATE + '/image-digest', STATE + '/owned-installation',
    'usr/local/lib/vkarmani-node/node_helper.py',
    'usr/local/lib/vkarmani-node/time_helper.py',
    'usr/local/lib/vkarmani-node/node_plugins.py',
    'usr/local/lib/vkarmani-node/ssh_guard.py',
    'usr/local/lib/vkarmani-node/finalize_install.py',
    'usr/local/sbin/vkarmani-node-check',
    'usr/local/sbin/vkarmani-selfsteal-check',
    'usr/local/sbin/vkarmani-node-tls-check',
)
OPTIONAL_WATCHED = ('etc/vkarmani-node/profile-xhttp.json',)
PENDING = ('network-rollback-armed', 'network-rollback-running', 'image-update-pending', 'RESUME_FAILED')
IMAGE = re.compile(r'(?:remnawave/node|ghcr\.io/remnawave/node)@sha256:[0-9a-f]{64}')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LC_ALL': 'C', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1',
       'SYSTEMD_PAGER': 'cat', 'PAGER': 'cat', 'HOME': '/root'}


class Failure(Exception):
    """Only a fixed diagnostic code; never concatenate untrusted/secret output."""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, timeout=30, quiet=False):
    # A new process group lets timeout stop inherited pipes/children, not just bash.
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=ENV, start_new_session=True) as p:
        try:
            out, err = p.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(p.pid, signal.SIGTERM)
                p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
            except ProcessLookupError:
                pass
            raise
        if not quiet:
            # Only invoke reviewed secret-free checker/RKN commands without quiet.
            sys.stdout.write(out.decode('utf-8', 'replace'))
            sys.stderr.write(err.decode('utf-8', 'replace'))
        if p.returncode:
            raise Failure('FINALIZATION_COMMAND_FAILED')
        return out.decode('utf-8', 'strict')


class Finalizer:
    def __init__(self, root=Path('/'), runner=run, owner=0):
        self.root = root
        self.state = root / STATE
        self.tx = self.state / 'finalization'
        self.runner = runner
        self.owner = owner

    def path(self, relative):
        parts = PurePosixPath(relative)
        if parts.is_absolute() or '..' in parts.parts or not parts.parts:
            raise Failure('UNSAFE_RELATIVE_PATH')
        return self.root.joinpath(*parts.parts)

    def safe(self, path, directory=False, private=False):
        # All ancestors below the test/host root are root-owned, not writable by others.
        path.relative_to(self.root)
        for part in reversed([path, *path.parents]):
            if part == self.root or self.root not in part.parents:
                continue
            st = part.lstat()
            last = part == path
            regular = stat.S_ISDIR(st.st_mode) if (not last or directory) else stat.S_ISREG(st.st_mode)
            if not regular or st.st_uid != self.owner or st.st_mode & 0o022:
                raise Failure('UNSAFE_FINALIZATION_PATH')
            if last and private and st.st_mode & 0o077:
                raise Failure('UNSAFE_FINALIZATION_PERMISSIONS')
        return path

    def read(self, path, private=False):
        self.safe(path, private=private)
        if path.stat().st_size > 64 * 1024 * 1024:
            raise Failure('FINALIZATION_FILE_TOO_LARGE')
        return path.read_bytes()

    def absent(self, path):
        if path.exists() or path.is_symlink():
            raise Failure('UNEXPECTED_FINALIZATION_STATE')

    def write(self, path, data, exclusive=False):
        self.safe(path.parent, directory=True)
        if path.exists() or path.is_symlink():
            if exclusive:
                raise Failure('FINALIZATION_TARGET_EXISTS')
            self.safe(path, private=True)
        fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if exclusive:
                os.link(name, path)  # exclusive publish; never overwrite INSTALL_COMPLETE
            else:
                os.replace(name, path)
            self.fsync(path.parent)
        finally:
            Path(name).unlink(missing_ok=True)

    @staticmethod
    def fsync(path):
        fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def checkpoint(self):
        obj = json.loads(self.read(self.tx / 'checkpoint.json', private=True))
        if obj.get('schema') != 1 or obj.get('version') != VERSION:
            raise Failure('UNSUPPORTED_FINALIZATION_CHECKPOINT')
        if obj.get('phase') not in ('ready', 'rkn-started', 'rkn-enabled', 'degraded', 'checked', 'complete'):
            raise Failure('UNKNOWN_FINALIZATION_PHASE')
        expected = set(WATCHED) | set(obj.get('optional_files', []))
        if not set(obj.get('optional_files', [])).issubset(OPTIONAL_WATCHED) or set(obj.get('files', {})) != expected:
            raise Failure('INVALID_FINALIZATION_MANIFEST')
        return obj

    def record(self, obj, phase):
        obj['phase'] = phase
        self.write(self.tx / 'checkpoint.json', (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode())

    def base_checks(self):
        self.safe(self.state, directory=True, private=True)
        if self.read(self.state / 'install-version', private=True).strip() != VERSION.encode():
            raise Failure('FINISH_ONLY_RECORDED_2_5_6_SUPPORTED')
        self.read(self.state / 'owned-installation', private=True)
        for name in PENDING:
            self.absent(self.state / name)
        cfg = json.loads(self.read(self.path('etc/vkarmani-node/config.json'), private=True))
        if cfg.get('installation_mode') != 'secret-key-only':
            raise Failure('WRONG_INSTALLATION_MODE')
        addr = str(ipaddress.IPv4Address(cfg['public_ipv4']))
        rows = json.loads(self.runner(['ip', '-j', '-4', 'address', 'show'], quiet=True))
        actual = {a.get('local') for row in rows for a in row.get('addr_info', []) if a.get('family') == 'inet'}
        if addr not in actual:
            raise Failure('FINALIZATION_WRONG_NODE_IPV4')
        digest = self.read(self.state / 'image-digest', private=True).decode().strip()
        if not IMAGE.fullmatch(digest):
            raise Failure('FINALIZATION_IMAGE_DIGEST_INVALID')
        fmt = '{{.Config.Image}}|{{.State.Running}}|{{.State.Restarting}}'
        current = self.runner(['docker', '--host', 'unix:///var/run/docker.sock',
                               'inspect', 'remnanode', '--format', fmt], quiet=True).strip()
        if current != digest + '|true|false':
            raise Failure('FINALIZATION_IMAGE_OR_CONTAINER_DRIFT')
        return digest

    def verify_backup(self):
        pointer = self.read(self.state / 'latest-backup-path', private=True).decode().strip()
        rel = PurePosixPath(pointer)
        if not rel.is_absolute() or '..' in rel.parts:
            raise Failure('INVALID_BACKUP_POINTER')
        rel = str(rel).lstrip('/')
        if not rel.startswith(STATE + '/backups/'):
            raise Failure('BACKUP_OUTSIDE_PROJECT')
        backup = self.safe(self.path(rel), directory=True, private=True)
        manifest = self.read(backup / 'MANIFEST.sha256').decode().splitlines()
        if not 1 <= len(manifest) <= 20000:
            raise Failure('INVALID_BACKUP_MANIFEST')
        for line in manifest:
            m = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            if not m:
                raise Failure('INVALID_BACKUP_MANIFEST')
            part = PurePosixPath(m[2])
            if part.is_absolute() or '..' in part.parts:
                raise Failure('BACKUP_MANIFEST_PATH_ESCAPE')
            if sha(self.read(backup.joinpath(*part.parts))) != m[1]:
                raise Failure('BACKUP_CHECKSUM_MISMATCH')
        return pointer

    def prepare(self, installer):
        digest = self.base_checks()
        self.absent(self.state / 'INSTALL_COMPLETE')
        self.absent(self.tx)
        if (self.state / 'rkn/owned').exists() or (self.state / 'rkn/owned').is_symlink() or RKN_MARKER in self.read(self.path(UFW)).decode():
            raise Failure('RKN_ALREADY_PRESENT_BEFORE_CHECKPOINT')
        self.absent(self.path(DROPIN))
        backup = self.verify_backup()
        source = self.read(installer, private=True)
        tmp = Path(tempfile.mkdtemp(prefix='.finalization-', dir=self.state))
        tmp.chmod(0o700)
        try:
            watched = {name: sha(self.read(self.path(name))) for name in WATCHED}
            optional = [name for name in OPTIONAL_WATCHED if self.path(name).exists() or self.path(name).is_symlink()]
            watched.update({name: sha(self.read(self.path(name), private=True)) for name in optional})
            snap = tmp / 'snapshot'
            snap.mkdir(mode=0o700)
            # Recovery copy contains secrets: only root can traverse/read it.
            for name in watched:
                target = snap / name
                current = snap
                for part in PurePosixPath(name).parts[:-1]:
                    current = current / part
                    current.mkdir(mode=0o700, exist_ok=True)
                    self.safe(current, directory=True, private=True)
                self.write(target, self.read(self.path(name)), exclusive=True)
                if sha(self.read(target)) != watched[name]:
                    raise Failure('FINALIZATION_SNAPSHOT_MISMATCH')
            self.write(tmp / 'installer.sh', source, exclusive=True)
            ufw = self.read(self.path(UFW))
            self.write(tmp / 'ufw-before.rules', ufw, exclusive=True)
            obj = {'schema': 1, 'version': VERSION, 'phase': 'ready', 'files': watched,
                   'optional_files': optional, 'installer_sha256': sha(source),
                   'ufw_before_sha256': sha(ufw), 'image': digest, 'original_backup': backup,
                   'created_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'rkn': 'NOT_ATTEMPTED'}
            self.write(tmp / 'checkpoint.json', (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode(), exclusive=True)
            os.rename(tmp, self.tx)
            self.fsync(self.state)
        except BaseException:
            if tmp.exists():
                shutil.rmtree(tmp)
            raise
        print('FINALIZATION_CHECKPOINT=READY; BACKUP=VERIFIED; VERSION=' + VERSION)

    def verify(self, obj):
        if self.base_checks() != obj['image']:
            raise Failure('FINALIZATION_IMAGE_CHANGED')
        if sha(self.read(self.tx / 'installer.sh', private=True)) != obj['installer_sha256']:
            raise Failure('FINALIZATION_INSTALLER_CHANGED')
        if sha(self.read(self.tx / 'ufw-before.rules', private=True)) != obj['ufw_before_sha256']:
            raise Failure('FINALIZATION_UFW_BACKUP_CHANGED')
        for name, expected in obj['files'].items():
            if sha(self.read(self.path(name))) != expected or sha(self.read(self.tx / 'snapshot' / name)) != expected:
                raise Failure('FINALIZATION_CONFIG_OR_HELPER_DRIFT')
        for name in set(OPTIONAL_WATCHED) - set(obj['optional_files']):
            self.absent(self.path(name))

    def acceptance(self):
        cmdline = self.read(self.path('proc/cmdline')).decode().split()
        mode = '--normal' if 'ipv6.disable=1' in cmdline else '--preboot'
        self.runner([str(self.path(CHECKER.lstrip('/'))), mode], timeout=610)

    def rkn_function(self, function):
        if function not in ('vk_rkn_activate', 'vk_rkn_abort_setup'):
            raise Failure('INVALID_RKN_ACTION')
        self.runner(['bash', '--noprofile', '--norc', '-c',
                     'set -uo pipefail; set +x; umask 077; VK_RKN_NO_PACKAGE_INSTALL=1; source "$1"; ' + function,
                     'finalization', str(self.tx / 'installer.sh')], timeout=600)

    def rollback_rkn(self, obj):
        self.rkn_function('vk_rkn_abort_setup')
        if sha(self.read(self.path(UFW))) != obj['ufw_before_sha256']:
            raise Failure('RKN_ROLLBACK_BASE_FIREWALL_MISMATCH_CONSOLE_REQUIRED')
        self.absent(self.path(DROPIN))
        print('RKN_ROLLBACK=VERIFIED_BASE_UFW')

    def check_rkn(self):
        self.runner([str(self.path(RKN.lstrip('/'))), 'status'], timeout=45)
        for unit in ('vkarmani-rkn-prepare.service', 'vkarmani-rkn-update.timer'):
            self.runner(['systemctl', 'is-enabled', '--quiet', unit])
        self.runner(['systemctl', 'is-active', '--quiet', 'vkarmani-rkn-update.timer'])

    def complete(self, obj):
        self.record(obj, 'checked')
        data = (f'version={VERSION}\nat={dt.datetime.now().astimezone().isoformat(timespec="seconds")}\n'
                f'image={obj["image"]}\n').encode()
        self.write(self.state / 'INSTALL_COMPLETE', data, exclusive=True)
        self.cleanup(obj)

    def cleanup(self, obj):
        # After a power loss between commit and cleanup, only our checked checkpoint
        # may clear failure markers. An ordinary completed older node is not migrated.
        data = dict(line.split('=', 1) for line in self.read(self.state / 'INSTALL_COMPLETE', private=True).decode().splitlines())
        if obj['phase'] not in ('checked', 'complete') or data.get('version') != VERSION or data.get('image') != obj['image']:
            raise Failure('UNRELATED_INSTALL_COMPLETE')
        for name in ('INSTALL_FAILED', 'FINALIZE_FAILED'):
            p = self.state / name
            if p.exists() or p.is_symlink():
                self.safe(p, private=True)
                p.unlink()
        self.fsync(self.state)
        self.record(obj, 'complete')
        print('FINALIZATION=PASS; INSTALL_COMPLETE=PASS; RKN=' + obj['rkn'])
        print('NO_REINSTALL_NO_KEY_ROTATION=YES; FINALIZER_REBOOT=NOT_SCHEDULED')

    def finish(self):
        obj = self.checkpoint()
        self.verify(obj)
        complete = self.state / 'INSTALL_COMPLETE'
        if complete.exists() or complete.is_symlink():
            self.cleanup(obj)
            return
        self.acceptance()
        self.runner(['python3', '-I', '-B', str(self.path(KEY_HELPER.lstrip('/'))), 'reality-export'], quiet=True)
        self.read(self.path('root/reality-keys.txt'), private=True)
        self.verify(obj)  # export must not regenerate keys, config or profiles
        if obj['phase'] == 'rkn-started':
            self.rollback_rkn(obj)  # safely abandon a previously interrupted owned attempt
            self.acceptance()
        if obj['phase'] in ('ready', 'rkn-started'):
            if sha(self.read(self.path(UFW))) != obj['ufw_before_sha256']:
                raise Failure('BASE_UFW_CHANGED_BEFORE_RKN')
            self.record(obj, 'rkn-started')
            try:
                self.rkn_function('vk_rkn_activate')
                self.check_rkn()
                self.acceptance()
            except (Failure, OSError, subprocess.TimeoutExpired):
                self.rollback_rkn(obj)
                self.acceptance()  # fail-open is allowed ONLY after successful rollback and node check
                obj['rkn'] = 'DEGRADED_ROLLED_BACK'
                self.record(obj, 'degraded')
            else:
                obj['rkn'] = 'ENABLED'
                self.record(obj, 'rkn-enabled')
        elif obj['phase'] in ('rkn-enabled', 'checked') and obj['rkn'] == 'ENABLED':
            self.check_rkn()
        elif obj['phase'] == 'degraded' or obj['rkn'] == 'DEGRADED_ROLLED_BACK':
            if sha(self.read(self.path(UFW))) != obj['ufw_before_sha256']:
                raise Failure('DEGRADED_BASE_FIREWALL_CHANGED')
            self.absent(self.path(DROPIN))
        else:
            raise Failure('FINALIZATION_STATE_INCONSISTENT')
        self.verify(obj)
        self.acceptance()
        self.complete(obj)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'finish'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Failure('ROOT_REQUIRED')
    def interrupted(signum, frame):
        raise Failure('FINALIZATION_INTERRUPTED_SIGNAL_' + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    f = Finalizer()
    if args.action == 'prepare':
        f.prepare(f.state / ('installer-' + VERSION + '.sh'))
    else:
        try:
            f.finish()
        except BaseException as exc:
            # Preserve the old failure and checkpoint. Never delete backup or fake success.
            if f.tx.is_dir() and not f.tx.is_symlink():
                code = str(exc) if isinstance(exc, Failure) else 'FINALIZATION_IO_OR_INTERRUPT'
                f.write(f.state / 'FINALIZE_FAILED', ('code=' + code + '\n').encode())
            raise


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        code = str(exc) if isinstance(exc, Failure) else 'FINALIZATION_LOCAL_IO_OR_DATA_ERROR'
        print('FINALIZATION=FAIL code=' + code + '; CHECKPOINT_PRESERVED; no reboot.', file=sys.stderr)
        sys.exit(1)
