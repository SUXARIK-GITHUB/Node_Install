#!/usr/bin/env python3
"""Explicit staging-only update of the *installed* Selfsteal checker.

Only the reviewed legacy checker SHA-256 is eligible. This does not touch
Nginx, Xray, SSH, certificates, sites, or their configuration. The old checker
is preserved with mode 0600; a failed postcheck restores it atomically.
Never run this against a production node without a tested snapshot and a
separately reviewed maintenance window.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install.sh'
CHECKER = Path('/usr/local/sbin/vkarmani-selfsteal-check')
BACKUPS = Path('/var/lib/vkarmani-node/backups')
LOCK = Path('/run/lock/vkarmani-node-installer.lock')
OLD_SHA256 = '164d9470afb93849f6439bad6dc7672cca667e55477ba7bf009426a6fe86beab'
NEW_SHA256 = '811adb955f7fd7e1853311bb0928ea05e83ea17bdca3f79800e53ba42b7cf321'
OPEN = "cat > '/usr/local/sbin/vkarmani-selfsteal-check' <<'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK'\n"
CLOSE = '\nVK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK'


class RepairError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def regular_file(path, *, mode=None, max_bytes=65536, uid=0):
    if path.is_symlink():
        raise RepairError('SYMLINK_REFUSED')
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != uid:
        raise RepairError('UNTRUSTED_CHECKER_OR_BACKUP')
    if stat.S_IMODE(st.st_mode) & 0o022 or (mode is not None and stat.S_IMODE(st.st_mode) != mode):
        raise RepairError('UNSAFE_CHECKER_OR_BACKUP_PERMISSIONS')
    if st.st_size > max_bytes:
        raise RepairError('CHECKER_OR_BACKUP_TOO_LARGE')
    # Reject symlinks in any parent component (not only the leaf).
    parent = path.parent
    while parent != parent.parent:
        if parent.is_symlink():
            raise RepairError('SYMLINK_ANCESTOR_REFUSED')
        parent = parent.parent
    return path.read_bytes()


def bundled_checker(installer=INSTALLER):
    if installer.is_symlink() or not installer.is_file():
        raise RepairError('UNTRUSTED_RELEASE_INSTALLER')
    text = installer.read_text(encoding='utf-8')
    if text.count(OPEN) != 1 or text.count(CLOSE) != 1:
        raise RepairError('EMBEDDED_CHECKER_NOT_UNIQUE')
    # A shell here-document writes the newline immediately before its delimiter.
    # Pin and install the SAME bytes as `cat <<HEREDOC` (not a trimmed copy).
    data = text.split(OPEN, 1)[1].split(CLOSE, 1)[0].encode('utf-8') + b'\n'
    if sha256(data) != NEW_SHA256:
        raise RepairError('RELEASE_CHECKER_HASH_MISMATCH')
    compile(data, '<reviewed selfsteal checker>', 'exec')
    return data


def status(target=CHECKER):
    data = regular_file(target, mode=0o755)
    digest = sha256(data)
    if digest == OLD_SHA256:
        return 'LEGACY_ASSET_CHECKER_REQUIRES_UPDATE'
    if digest == NEW_SHA256:
        return 'COMPATIBLE_CHECKER_INSTALLED'
    raise RepairError('UNKNOWN_CHECKER_VERSION_REFUSED')


@contextmanager
def installer_lock(path=LOCK):
    if path.is_symlink() or not path.parent.is_dir():
        raise RepairError('INVALID_INSTALLER_LOCK_PATH')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o022:
            raise RepairError('UNSAFE_INSTALLER_LOCK')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise RepairError('NODE_INSTALLER_OR_MAINTENANCE_BUSY') from e
        yield
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_replace(path, data, *, mode=0o755):
    if path.is_symlink():
        raise RepairError('SYMLINK_REFUSED')
    fd, name = tempfile.mkstemp(prefix='.vk-checker-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            os.fchown(f.fileno(), 0, 0)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_backup(data, directory=BACKUPS):
    if directory.is_symlink() or not directory.is_dir():
        raise RepairError('BACKUP_DIRECTORY_MISSING_OR_SYMLINK')
    st = directory.lstat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        raise RepairError('BACKUP_DIRECTORY_NOT_PRIVATE')
    name = 'selfsteal-check-before-' + secrets.token_hex(10) + '.py'
    dest = directory / name
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(directory)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return dest


def probe(target):
    try:
        result = subprocess.run([str(target)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=35, check=False,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'})
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RepairError('SELFSTEAL_PROBE_UNAVAILABLE_OR_TIMEOUT') from e
    if result.returncode:
        raise RepairError('SELFSTEAL_PROBE_FAILED_ON_CURRENT_SITE')


def apply(target=CHECKER, directory=BACKUPS, before_after_probe=probe):
    next_data = bundled_checker()
    data = regular_file(target, mode=0o755)
    if sha256(data) == NEW_SHA256:
        before_after_probe(target)
        return 'ALREADY_UPDATED', None
    if sha256(data) != OLD_SHA256:
        raise RepairError('UNKNOWN_CHECKER_VERSION_REFUSED')
    # This should pass against the original site before touching the checker.
    before_after_probe(target)
    saved = save_backup(data, directory)
    try:
        atomic_replace(target, next_data)
        before_after_probe(target)
    except BaseException:
        try:
            atomic_replace(target, data)
            before_after_probe(target)
        except BaseException as rollback_error:
            raise RepairError('CHECKER_UPDATE_FAILED_ROLLBACK_REQUIRES_REVIEW') from rollback_error
        raise RepairError('CHECKER_UPDATE_FAILED_ORIGINAL_RESTORED')
    return 'UPDATED', saved


def rollback(target, backup, before_after_probe=probe):
    if backup.parent != BACKUPS or not re.fullmatch(r'selfsteal-check-before-[0-9a-f]{20}[.]py', backup.name):
        raise RepairError('UNREVIEWED_CHECKER_BACKUP_PATH')
    restore = regular_file(backup, mode=0o600)
    if sha256(restore) != OLD_SHA256:
        raise RepairError('BACKUP_CHECKER_HASH_MISMATCH')
    current = regular_file(target, mode=0o755)
    if sha256(current) != NEW_SHA256:
        raise RepairError('ROLLBACK_ONLY_FROM_REVIEWED_CHECKER')
    atomic_replace(target, restore)
    try:
        before_after_probe(target)
    except BaseException:
        atomic_replace(target, current)
        raise RepairError('LEGACY_CHECKER_NOT_COMPATIBLE_WITH_CURRENT_SITE_RESTORED_UPDATED_CHECKER')
    return 'LEGACY_CHECKER_RESTORED'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    action = ap.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true', help='read-only checker version check')
    action.add_argument('--apply', action='store_true', help='explicitly replace reviewed legacy checker')
    action.add_argument('--rollback', type=Path, help='restore exact root-owned 0600 backup after site rollback')
    ap.add_argument('--confirm-staging', action='store_true', help='confirm reviewed staging environment')
    args = ap.parse_args()
    if os.geteuid() != 0:
        print('CHECKER_REPAIR=STOP ROOT_REQUIRED',file=sys.stderr)
        return 2
    if not args.check and not args.confirm_staging:
        print('CHECKER_REPAIR=STOP STAGING_CONFIRMATION_REQUIRED',file=sys.stderr)
        return 2
    try:
        if args.check:
            print('CHECKER_REPAIR=' + status())
            return 0
        with installer_lock():
            if args.apply:
                state, backup = apply()
                print('CHECKER_REPAIR=' + state + (' BACKUP=' + str(backup) if backup else ''))
            else:
                print('CHECKER_REPAIR=' + rollback(CHECKER, args.rollback))
        return 0
    except (RepairError, OSError, ValueError, SyntaxError, UnicodeError) as e:
        reason = str(e) if isinstance(e, RepairError) else type(e).__name__
        print('CHECKER_REPAIR=STOP ' + reason, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
