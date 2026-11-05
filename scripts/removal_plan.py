#!/usr/bin/env python3
"""Fail-closed recovery and uninstallation assessment.

The installer changes bootloader, SSH, UFW, packages and Docker. No arbitrary
recursive deletion or 'erase traces' command is safe without a verified provider
snapshot. This module inventories provenance and exposes ONLY the existing
narrow emergency SSH/UFW rollback when its trusted marker is armed. Complete
uninstallation requires restoring a tested pre-install VPS snapshot in the
provider's console. Audit logs are never destroyed to hide history.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

STATE = Path('/var/lib/vkarmani-node')
ETC = Path('/etc/vkarmani-node')
LOCK = Path('/run/lock/vkarmani-node-installer.lock')
ALLOWED = ('owned-installation', 'install-version', 'INSTALL_COMPLETE', 'INSTALL_FAILED',
           'network-rollback-armed', 'network-rollback-running', 'network-rollback-done',
           'image-update-pending', 'finalization', 'first-backup-path', 'latest-backup-path',
           'RESUME_FAILED')


def safe_owned_file(path):
    try:
        st=path.lstat()
        return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not (st.st_mode & 0o077)
    except OSError:
        return False


def plan(root=Path('/'), *, expected_uid=0):
    state=root/'var/lib/vkarmani-node'
    etc=root/'etc/vkarmani-node'
    try:
        st=state.lstat()
        valid_state=stat.S_ISDIR(st.st_mode) and st.st_uid==expected_uid and not (st.st_mode & 0o022)
    except OSError:
        valid_state=False
    markers={name:(state/name).exists() or (state/name).is_symlink() for name in ALLOWED}
    symlinks=[name for name in ALLOWED if (state/name).is_symlink()]
    owner=valid_state and markers['owned-installation']
    backup='NOT_VERIFIED'
    if owner and not symlinks:
        pointer=state/'first-backup-path'
        try:
            s=pointer.lstat()
            if not(stat.S_ISREG(s.st_mode) and s.st_uid==expected_uid and s.st_mode & 0o077 == 0):
                raise ValueError()
            path=Path(pointer.read_text().strip())
            path_parent=Path('/var/lib/vkarmani-node/backups')
            if path.parent!=path_parent or not re.fullmatch(r'\d{8}-\d{6}-\d+',path.name):
                raise ValueError()
            folder=root / str(path).lstrip('/')
            manifest=folder/'MANIFEST.sha256'
            st=manifest.lstat()
            if stat.S_ISREG(st.st_mode) and st.st_uid==expected_uid and st.st_size>0 and not(st.st_mode & 0o022):
                backup='MANIFEST_PRESENT_UNVERIFIED'  # No silent claim of restorability.
        except (OSError,ValueError):
            pass
    if not valid_state and any(markers.values()):
        status='STOP_UNSAFE_STATE_DIRECTORY'
    elif symlinks:
        status='STOP_UNSAFE_SYMLINK'
    elif not owner:
        status='NOT_OWNED'
    elif markers['INSTALL_COMPLETE']:
        status='COMPLETE_NODE'
    else:
        status='PARTIAL_INSTALLATION'
    return {'schema':1, 'kind':'REMOVAL_PLAN','status':status,
            'owned':bool(owner), 'backup':backup,
            'markers':[name for name in ALLOWED if markers[name]],
            'system_scope':['SSH','UFW','GRUB','IPv6','Nginx','Docker','APT','systemd','sysctl','ACME','swap'],
            'recovery':('NARROW_SSH_UFW_ROLLBACK_AVAILABLE' if owner and
                        (markers['network-rollback-armed'] or markers['network-rollback-running'])
                        else 'NO_SAFE_GENERAL_AUTOMATIC_ROLLBACK'),
            'full_removal':'REQUIRES_VERIFIED_PROVIDER_SNAPSHOT_RESTORE',
            'limitations':['An installer backup is not a full VPS snapshot',
                           'No guarantee of restoring installed packages/services or external access',
                           'No automatic deletion of logs, unrelated services, user data or secrets',
                           'Full cleanup is blocked until verified external snapshot restore']}


def narrow_network_recovery(*, inspector=plan, runner=subprocess.run):
    p=inspector()
    if os.geteuid()!=0 or p['status']!='PARTIAL_INSTALLATION' or p['recovery']!='NARROW_SSH_UFW_ROLLBACK_AVAILABLE':
        return {'status':'STOP','reason':'UNVERIFIED_PARTIAL_NETWORK_ROLLBACK'}
    rollback=Path('/usr/local/sbin/vkarmani-network-rollback')
    try:
        st=rollback.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            return {'status':'STOP','reason':'UNSAFE_NETWORK_ROLLBACK_HELPER'}
        cp=runner([str(rollback)],capture_output=True,text=True,timeout=120,check=False)
        return {'status':'LOCAL_ROLLBACK_FINISHED_REVIEW_EXTERNAL_SSH' if cp.returncode==0 else 'STOP',
                'reason':'CHECK_PROVIDER_CONSOLE_AND_EXTERNAL_SSH' if cp.returncode==0 else 'ROLLBACK_FAILED'}
    except (OSError,subprocess.TimeoutExpired):
        return {'status':'STOP','reason':'ROLLBACK_UNAVAILABLE_OR_TIMEOUT'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('plan','recover-network','full-removal'))
    p.add_argument('--confirm-network-only',action='store_true')
    args=p.parse_args(argv)
    if args.action=='plan':result=plan();code=0
    elif args.action=='full-removal':
        result={'status':'STOP','reason':'FULL_UNINSTALL_REQUIRES_TESTED_PROVIDER_SNAPSHOT',
                'instruction':'Use provider console to restore verified pre-install VPS snapshot; installer cannot safely reverse host-wide APT/GRUB/SSH changes.'}
        code=2
    elif not args.confirm_network_only:
        result={'status':'STOP','reason':'EXPLICIT_NETWORK_ONLY_CONFIRMATION_REQUIRED'};code=2
    else:
        result=narrow_network_recovery();code=0 if result['status'].startswith('LOCAL_ROLLBACK') else 2
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    return code


if __name__=='__main__':
    sys.exit(main())
