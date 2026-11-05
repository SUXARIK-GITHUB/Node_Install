#!/usr/bin/env python3
"""Conditional low-risk TCP backlog tuning after two host counter snapshots.

READ-ONLY by default. Tunable scope intentionally limited to somaxconn and
max_syn_backlog, only when *new* ListenOverflows/ListenDrops were measured.
Never changes BBR, qdisc, MTU, ip_forward, IPv6, UFW or NIC configuration.
A real apply needs root, explicit staging consent, completed VKarmani state,
current-host readback, an exclusive lock, preserved before-values, and rollback.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_ROOT/'scripts'))
sys.path.insert(0, str(SCRIPT_ROOT/'integrations'))
from network_compare import _read as read_snapshot, compare
from network_health import snapshot as host_snapshot

SYSCTL_FILE = Path('/etc/sysctl.d/98-vkarmani-measured.conf')
STATE = Path('/var/lib/vkarmani-node')
RECEIPT = 'r23-network-tuning.json'
PARAMS = {'somaxconn':'net.core.somaxconn', 'tcp_max_syn_backlog':'net.ipv4.tcp_max_syn_backlog'}
INSTALLER_LOCK = Path('/run/lock/vkarmani-node-installer.lock')
# An existing finalization directory is normal *after* INSTALL_COMPLETE. Its
# checkpoint must say complete; an unfinished checkpoint blocks tuning.
PENDING_MARKERS = ('INSTALL_FAILED', 'FINALIZE_FAILED', 'RESUME_FAILED',
                   'image-update-pending', 'cover-pending',
                   'network-rollback-armed', 'network-rollback-running')


class TuneError(Exception):pass


def _strict_int(value):
    if type(value) is int:
        return value if 0 <= value <= 10**9 else None
    if isinstance(value,str) and re.fullmatch(r'[0-9]{1,9}',value):
        return int(value)
    return None


def suggest(before, after, seconds):
    comparison=compare(before,after,seconds)
    recommendations={}
    reasons=[]
    if comparison.get('status')=='REVIEW' and 'PRIMARY_INTERFACE_CHANGED_OR_UNKNOWN' in comparison['observations']:
        reasons.append('DIFFERENT_INTERFACE: no tuning plan allowed')
    else:
        delta=comparison.get('deltas',{}).get('tcp_host_counters',{})
        overflow=delta.get('ListenOverflows',{})
        dropped=delta.get('ListenDrops',{})
        if (overflow.get('status')=='OK' and dropped.get('status')=='OK' and
            (overflow.get('delta',0)>0 or dropped.get('delta',0)>0)):
            for key in PARAMS:
                current=_strict_int(after.get('parameters',{}).get(key))
                if current is None:
                    reasons.append('UNKNOWN_'+key.upper())
                elif current < 8192:
                    recommendations[PARAMS[key]]={'before':current,'after':8192}
        else:
            reasons.append('NO_VERIFIED_NEW_LISTEN_BACKLOG_DROPS')
    return {'schema':1,'status':'RECOMMENDED' if recommendations else 'NO_CHANGE',
            'interface':after.get('network_interface'), 'recommendations':recommendations,
            'observations':reasons, 'source':'TWO_HOST_SNAPSHOTS',
            'limitations':['A backlog increase cannot fix upstream loss, DPI, or saturated CPU',
                           'Observations must be from the same host without reboot',
                           'Requires snapshot, explicit staging approval and rollback']}


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _atomic(path, data, mode=0o600):
    fd,tmp=tempfile.mkstemp(prefix='.vk-net-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode)
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def _run(command):
    p=subprocess.run(command,capture_output=True,text=True,timeout=8,check=False,
                     stdin=subprocess.DEVNULL)
    if p.returncode:
        raise TuneError('SYSCTL_APPLY_FAILED')


def _read_sysctl(path):
    key=Path('/proc/sys')/path.replace('.','/')
    text=key.read_text(encoding='ascii').strip()
    n=_strict_int(text)
    if n is None:raise TuneError('SYSCTL_READBACK_INVALID')
    return n


def _ready(root):
    state = root / STATE.relative_to('/')
    if state.is_symlink() or not state.is_dir():
        raise TuneError('INSTALL_CHECKPOINT_NOT_VERIFIED')
    if root == Path('/'):
        st = state.lstat()
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
            raise TuneError('INSTALL_CHECKPOINT_PERMISSIONS_INVALID')
    for filename in ('INSTALL_COMPLETE', 'owned-installation'):
        p = state / filename
        if p.is_symlink() or not p.is_file():
            raise TuneError('INSTALL_CHECKPOINT_NOT_VERIFIED')
        if root == Path('/'):
            st = p.lstat()
            if st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) & 0o077:
                raise TuneError('INSTALL_CHECKPOINT_PERMISSIONS_INVALID')
    if not (state / 'INSTALL_COMPLETE').read_text(encoding='utf-8').startswith('version=2.5.18\n'):
        raise TuneError('INSTALL_VERSION_MISMATCH')
    if any((state / name).exists() or (state / name).is_symlink() for name in PENDING_MARKERS):
        raise TuneError('INCOMPLETE_OTHER_TRANSACTION')
    tx = state / 'finalization'
    if tx.exists() or tx.is_symlink():
        checkpoint = tx / 'checkpoint.json'
        if (tx.is_symlink() or not tx.is_dir() or checkpoint.is_symlink() or
                not checkpoint.is_file()):
            raise TuneError('INCOMPLETE_OTHER_TRANSACTION')
        if root == Path('/'):
            for item in (tx, checkpoint):
                st = item.lstat()
                if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
                    raise TuneError('INCOMPLETE_OTHER_TRANSACTION')
        try:
            data = json.loads(checkpoint.read_bytes())
        except (OSError, ValueError):
            raise TuneError('INCOMPLETE_OTHER_TRANSACTION') from None
        if not isinstance(data, dict) or data.get('phase') != 'complete' or data.get('version') != '2.5.18':
            raise TuneError('INCOMPLETE_OTHER_TRANSACTION')


@contextmanager
def _host_locks(root, state):
    """Share the installer flock (same lock order on every host operation)."""
    # The synthetic fixture must never open or alter a real host lock.
    global_lock = INSTALLER_LOCK if root == Path('/') else state / 'fixture-installer.lock'
    local_lock = state / 'r23-network-tuning.lock'
    fds = []
    try:
        for path in (global_lock, local_lock):
            if path.parent.is_symlink() or not path.parent.is_dir() or path.is_symlink():
                raise TuneError('UNSAFE_INSTALLER_LOCK_PATH')
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            fds.append(fd)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (root == Path('/') and
                (st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022)):
                raise TuneError('UNSAFE_INSTALLER_LOCK_OWNER_OR_MODE')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TuneError('NODE_INSTALLER_OR_MAINTENANCE_BUSY') from exc
        yield
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _receipt_data(receipt):
    if receipt.is_symlink() or not receipt.is_file():
        raise TuneError('NO_VERIFIED_TUNING_TO_ROLLBACK')
    if receipt.stat().st_size > 8192:
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
    try:
        data = json.loads(receipt.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED') from exc
    if (not isinstance(data, dict) or data.get('schema') != 1 or
            data.get('status') not in ('pending', 'active', 'rolling_back') or
            not isinstance(data.get('before'), dict) or not data['before'] or
            not set(data['before']) <= set(PARAMS.values()) or
            not isinstance(data.get('after'), dict) or
            set(data['after']) != set(data['before']) or
            any(_strict_int(v) != v or type(v) is not int for v in data['before'].values()) or
            any(v != 8192 or type(v) is not int for v in data['after'].values()) or
            any(data['before'][k] >= data['after'][k] for k in data['before']) or
            not isinstance(data.get('config_sha256'), str) or
            not re.fullmatch('[0-9a-f]{64}', data['config_sha256'])):
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
    expected = ('# VKarmani R23 measured backlog tuning, staging-only.\n' +
                ''.join(f'{key} = 8192\n' for key in sorted(data['before']))).encode('ascii')
    if _sha(expected) != data['config_sha256']:
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
    return data


def _rollback_owned(target, receipt, data, run, get):
    """Crash-resumable rollback: journal BEFORE sysctl, file removal AFTER readback.

    Both active and pending states can be recovered. Each observed kernel value
    must be exactly the approved old or new value; otherwise refuse to trample
    third-party changes. An absent file with an active old receipt is only
    accepted for the known r24 interruption after values were restored.
    """
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
    present = target.exists()
    if present and _sha(target.read_bytes()) != data['config_sha256']:
        raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
    values = {key: get(key) for key in data['before']}
    if any(value not in (data['before'][key], data['after'][key]) for key, value in values.items()):
        raise TuneError('THIRD_PARTY_SYSCTL_CHANGE_REFUSE_ROLLBACK')
    if data['status'] == 'active' and not present:
        # Compatible with interrupted rollback from r24 (removed file, old receipt).
        if values != data['before']:
            raise TuneError('NO_VERIFIED_TUNING_TO_ROLLBACK')
    elif data['status'] == 'active' and values != data['after']:
        raise TuneError('THIRD_PARTY_SYSCTL_CHANGE_REFUSE_ROLLBACK')
    # Atomic intent is persisted before the first mutation.
    if data['status'] != 'rolling_back':
        data = dict(data, status='rolling_back')
        _atomic(receipt, (json.dumps(data, sort_keys=True) + '\n').encode())
    for key, value in values.items():
        if value != data['before'][key]:
            run(['sysctl', '-w', f'{key}={data["before"][key]}'])
    if any(get(key) != old for key, old in data['before'].items()):
        raise TuneError('NETWORK_TUNING_RECOVERY_REQUIRED')
    if target.exists():
        if target.is_symlink() or _sha(target.read_bytes()) != data['config_sha256']:
            raise TuneError('RECEIPT_OR_CONFIGURATION_TAMPERED')
        target.unlink()
        fd = os.open(target.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    data['status'] = 'rolled_back'
    _atomic(receipt, (json.dumps(data, sort_keys=True) + '\n').encode())
    return 'NETWORK_TUNING=ROLLBACK_PASS'


def transact(plan, action, *, root=Path('/'), run=_run, get=_read_sysctl):
    """Transactional apply/rollback. root/run/get can be injected in offline tests."""
    root = Path(root)
    if root == Path('/') and os.geteuid() != 0:
        raise TuneError('ROOT_REQUIRED')
    target = root / SYSCTL_FILE.relative_to('/')
    state = root / STATE.relative_to('/')
    receipt = state / RECEIPT
    if target.parent.is_symlink() or not target.parent.is_dir() or receipt.is_symlink():
        raise TuneError('UNSAFE_TARGET_PATH')
    with _host_locks(root, state):
        _ready(root)  # recheck all checkpoints *after* acquiring installer lock
        if action == 'apply':
            if target.exists() or target.is_symlink() or receipt.exists():
                raise TuneError('ALREADY_OWNED_OR_FOREIGN_SYSCTL_FILE')
            choices = plan.get('recommendations') if isinstance(plan, dict) else None
            if (not isinstance(choices, dict) or not choices or
                    not set(choices) <= set(PARAMS.values())):
                raise TuneError('NO_SAFE_TUNING_RECOMMENDATION')
            verified = {}
            for key, item in choices.items():
                if (type(item) is not dict or _strict_int(item.get('before')) is None or
                        type(item.get('before')) is not int or item.get('after') != 8192 or
                        type(item.get('after')) is not int or item['before'] >= 8192):
                    raise TuneError('INVALID_PLAN_VALUE')
                if get(key) != item['before']:
                    raise TuneError('HOST_CONFIG_DRIFT')
                verified[key] = item['before']
            content = ('# VKarmani R23 measured backlog tuning, staging-only.\n' +
                       ''.join(f'{key} = 8192\n' for key in sorted(verified))).encode('ascii')
            data = {'schema': 1, 'status': 'pending', 'before': verified,
                    'after': {k: 8192 for k in verified}, 'config_sha256': _sha(content)}
            _atomic(receipt, (json.dumps(data, sort_keys=True) + '\n').encode())
            try:
                _atomic(target, content, 0o644)
                run(['sysctl', '-p', str(target)])
                if any(get(key) != 8192 for key in verified):
                    raise TuneError('SYSCTL_READBACK_MISMATCH')
                data['status'] = 'active'
                _atomic(receipt, (json.dumps(data, sort_keys=True) + '\n').encode())
                return 'NETWORK_TUNING=APPLIED_MEASURED_BACKLOG_ONLY'
            except BaseException:
                try:
                    _rollback_owned(target, receipt, _receipt_data(receipt), run, get)
                except BaseException:
                    raise TuneError('NETWORK_TUNING_RECOVERY_REQUIRED')
                raise
        if action == 'rollback':
            return _rollback_owned(target, receipt, _receipt_data(receipt), run, get)
        raise TuneError('UNKNOWN_ACTION')


def main(argv=None):
    a=argparse.ArgumentParser(description=__doc__)
    sub=a.add_subparsers(dest='action',required=True)
    for name in ('plan','apply'):
        p=sub.add_parser(name)
        p.add_argument('before',type=Path);p.add_argument('after',type=Path)
        p.add_argument('--seconds',type=float,required=True)
        if name=='apply':p.add_argument('--confirm-staging',action='store_true')
    p=sub.add_parser('rollback');p.add_argument('--confirm-staging',action='store_true')
    args=a.parse_args(argv)
    try:
        if args.action in ('plan','apply'):
            before,after=read_snapshot(args.before),read_snapshot(args.after)
            plan=suggest(before,after,args.seconds)
            if args.action=='plan':
                print(json.dumps(plan,indent=2,sort_keys=True));return 0
            if not args.confirm_staging:raise TuneError('STAGING_CONFIRMATION_REQUIRED')
            # Snapshot provenance: use live host readback and the same primary
            # interface. The operator is responsible for ensuring no reboot.
            now=host_snapshot()
            if now.get('network_interface') != after.get('network_interface') or not after.get('network_interface'):
                raise TuneError('NETWORK_INTERFACE_NOT_SAME_HOST')
            print(transact(plan,'apply'))
            return 0
        if not args.confirm_staging:raise TuneError('STAGING_CONFIRMATION_REQUIRED')
        print(transact(None,'rollback'))
        return 0
    except (TuneError,ValueError,OSError,TypeError,json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        print('NETWORK_TUNING=STOP '+(str(exc) if isinstance(exc,TuneError) else type(exc).__name__),file=sys.stderr)
        return 1


if __name__=='__main__':sys.exit(main())
