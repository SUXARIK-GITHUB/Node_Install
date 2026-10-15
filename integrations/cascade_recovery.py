#!/usr/bin/env python3
"""Create and VERIFY a limited local, immutable cascade role-state backup.

Does not include host snapshots, Panel DB, Docker volumes, secrets belonging to
other services, or live rollback. Backup contains PRIVATE SECRET_KEY and REALITY
material: keep offline/encrypted at rest. No restoration into live system.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import zipfile

import cascade_deployment as cd

REQUIRED = ('etc/vkarmani-node/cascade-role.json',
            'var/lib/vkarmani-node/role.json',
            'etc/vkarmani-node/config.json')
OPTIONAL = ('etc/vkarmani-node/profile.json',
            'etc/vkarmani-node/profile-xhttp.json')
LIMIT = 2 * 1024 * 1024
MAX_ZIP = 8 * 1024 * 1024
MANIFEST = 'backup-manifest.json'


class RecoveryError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise RecoveryError(reason)


def source_read(source, name):
    """Strict no-follow all source path components, fd-bound read and fstat."""
    cur = Path(source)
    require(cur.is_absolute(), 'SOURCE_ROOT_MUST_BE_ABSOLUTE')
    for piece in name.split('/'):
        cur = cur / piece
        st = cur.lstat()
        require(not stat.S_ISLNK(st.st_mode), 'BACKUP_SOURCE_SYMLINK')
    fd = os.open(cur, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= LIMIT,
                'BACKUP_FILE_TYPE_OR_SIZE')
        require(not stat.S_IMODE(st.st_mode) & 0o022, 'BACKUP_SOURCE_WORLD_OR_GROUP_WRITABLE')
        if os.geteuid() == 0:
            require(st.st_uid == 0, 'BACKUP_SOURCE_NOT_ROOT_OWNED')
        data = os.read(fd, LIMIT + 1)
        require(len(data) <= LIMIT, 'BACKUP_SOURCE_TOO_LARGE')
        return data
    finally:
        os.close(fd)


def verify_contents(files):
    require(set(REQUIRED).issubset(files), 'BACKUP_REQUIRED_FILES_MISSING')
    role = json.loads(files[REQUIRED[0]])
    marker = json.loads(files[REQUIRED[1]])
    cd.validate_bundle(role)
    require(marker == {'schema': 2, 'role': role['role'], 'pair_id':role['pair_id']},
            'BACKUP_ROLE_MARKER_INVALID')
    cfg = json.loads(files[REQUIRED[2]])
    require(isinstance(cfg, dict) and cfg.get('installation_mode') == 'secret-key-only',
            'BACKUP_CONFIG_NOT_A_NODE')
    require(cfg.get('domain') == role['self']['domain'] and
            cfg.get('public_ipv4') == role['self']['ipv4'],
            'BACKUP_NODE_IDENTITY_MISMATCH')
    return role


def manifest_for(files, role):
    return {'schema': 1, 'scope':'LOCAL_NODE_ROLE_AND_CONFIG_ONLY',
            'pair_id':role['pair_id'], 'role':role['role'],
            'files': {n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())}}


def create(root, output):
    require(Path(root).is_absolute() and Path(output).is_absolute(), 'ABSOLUTE_PATHS_REQUIRED')
    dest = Path(output)
    require(dest.parent.is_dir() and not dest.parent.is_symlink(), 'OUTPUT_PARENT_MISSING_OR_SYMLINK')
    require(not dest.parent.stat().st_mode & 0o022, 'OUTPUT_PARENT_WRITABLE')
    require(not dest.exists() and not dest.is_symlink(), 'OUTPUT_EXISTS')
    if os.geteuid() == 0:
        require(dest.parent.stat().st_uid == 0, 'OUTPUT_PARENT_NOT_ROOT')
    files = {n:source_read(root,n) for n in REQUIRED}
    for n in OPTIONAL:
        candidate=Path(root)/n
        if candidate.exists() or candidate.is_symlink():
            files[n]=source_read(root,n)
    role=verify_contents(files)
    manifest=json.dumps(manifest_for(files,role),sort_keys=True,indent=2).encode()+b'\n'
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED,compresslevel=7) as z:
                for name, blob in sorted(files.items()):
                    z.writestr(name, blob)
                z.writestr(MANIFEST, manifest)
            stream.flush(); os.fsync(stream.fileno())
        require(dest.stat().st_size <= MAX_ZIP, 'BACKUP_TOO_LARGE')
        check(dest)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return role['pair_id']


def check(path):
    p=Path(path)
    require(not p.is_symlink() and p.is_file(), 'BACKUP_NOT_REGULAR')
    st=p.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_ZIP,
            'BACKUP_INVALID_SIZE_TYPE')
    require(not st.st_mode & 0o077, 'BACKUP_PERMISSIONS_NOT_PRIVATE')
    if os.geteuid() == 0:
        require(st.st_uid == 0, 'BACKUP_NOT_ROOT_OWNED')
    files={}
    with zipfile.ZipFile(p) as z:
        names=z.namelist()
        require(len(names)==len(set(names)) and len(names)<=len(REQUIRED)+len(OPTIONAL)+1,
                'BACKUP_ARCHIVE_DUPLICATE_OR_TOO_MANY')
        require(set(names)-{MANIFEST} <= set(REQUIRED+OPTIONAL) and MANIFEST in names,
                'BACKUP_ARCHIVE_UNEXPECTED_MEMBER')
        for info in z.infolist():
            require(not info.is_dir() and info.file_size<=LIMIT, 'BACKUP_MEMBER_TOO_BIG')
            data=z.read(info, pwd=None)
            require(len(data)<=LIMIT, 'BACKUP_MEMBER_SIZE')
            files[info.filename]=data
    meta=json.loads(files.pop(MANIFEST))
    role=verify_contents(files)
    require(meta == manifest_for(files,role), 'BACKUP_MANIFEST_OR_HASH_MISMATCH')
    return meta


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('create');a.add_argument('--source-root',default='/');a.add_argument('--output',required=True)
    a=sub.add_parser('verify');a.add_argument('--backup',required=True)
    ns=p.parse_args(argv)
    os.umask(0o077)
    try:
        if ns.cmd=='create':
            pid=create(ns.source_root,ns.output)
            print('CASCADE_LOCAL_BACKUP=PASS PAIR_ID='+pid)
            print('CONTAINS_SECRETS=YES; STORE_OFFLINE_ENCRYPTED; NOT_A_FULL_HOST_OR_PANEL_BACKUP')
        else:
            meta=check(ns.backup)
            print('CASCADE_LOCAL_BACKUP_VERIFY=PASS PAIR_ID='+meta['pair_id']+' FILES='+str(len(meta['files'])))
            print('SCOPE=LOCAL_NODE_STATE_ONLY; NO_RESTORE_PERFORMED')
        return 0
    except (RecoveryError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            cd.DeploymentError, UnicodeError) as exc:
        reason=str(exc) if isinstance(exc,(RecoveryError,cd.DeploymentError)) else type(exc).__name__
        print('CASCADE_LOCAL_BACKUP=FAIL reason='+reason,file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
