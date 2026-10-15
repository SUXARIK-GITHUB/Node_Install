#!/usr/bin/env python3
"""Local RemnaNode night maintenance only, Europe/Moscow 03:00-03:59.

This is NOT an autorepair loop. At most one planned container restart per
Moscow date. It never starts a container deliberately stopped by its operator.
"""
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from zoneinfo import ZoneInfo

MOSCOW = ZoneInfo('Europe/Moscow')
STATE = Path('/var/lib/vkarmani-node')
ETC = Path('/etc/vkarmani-node')
LOCK = Path('/run/lock/vkarmani-node-installer.lock')
RESULT = STATE / 'maintenance-last.json'
DOCKER = '/usr/local/sbin/vkarmani-docker-local'
EXEC_TIMEOUT = 90


class MaintenanceError(Exception):
    pass


def eligible(when):
    return when.astimezone(MOSCOW).hour == 3


def role():
    """Never guess role from listeners; unknown state is not ordinary."""
    path = STATE / 'role.json'
    if not path.exists():
        return 'ordinary'
    if path.is_symlink():
        raise MaintenanceError('ROLE_STATE_SYMLINK')
    try:
        obj = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise MaintenanceError('ROLE_STATE_INVALID') from exc
    if not isinstance(obj, dict) or obj.get('role') not in ('ordinary', 'cascade-entry', 'cascade-exit'):
        raise MaintenanceError('ROLE_STATE_INVALID')
    return obj['role']


def call(args, timeout=EXEC_TIMEOUT):
    try:
        p = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL,
                           text=True, timeout=timeout, check=False,
                           env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                'LANG':'C', 'LC_ALL':'C', 'HOME':'/root'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MaintenanceError('LOCAL_COMMAND_FAILED_OR_TIMEOUT') from exc
    if p.returncode:
        raise MaintenanceError('LOCAL_COMMAND_FAILED ' + Path(args[0]).name +
                               ' rc=' + str(p.returncode))
    return p.stdout.strip()


def atomic_record(record):
    if STATE.is_symlink() or not STATE.is_dir() or RESULT.is_symlink():
        raise MaintenanceError('UNSAFE_STATE_PATH')
    fd, name = tempfile.mkstemp(prefix='.maintenance-', dir=STATE)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(record, stream, ensure_ascii=False, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, RESULT)
        dfd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def last_result():
    # Absence is the only valid "never run" state. Corruption must fail
    # closed: treating a broken marker as {} permits a second restart today.
    if RESULT.is_symlink():
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_SYMLINK')
    if not RESULT.exists():
        return {}
    if not RESULT.is_file():
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_TYPE')
    try:
        item = json.loads(RESULT.read_text())
    except (OSError, ValueError) as exc:
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_JSON') from exc
    if (not isinstance(item, dict) or not isinstance(item.get('moscow_date'), str)
            or not isinstance(item.get('status'), str)):
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_FIELDS')
    try:
        date = dt.date.fromisoformat(item['moscow_date'])
    except ValueError as exc:
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_DATE') from exc
    if date.isoformat() != item['moscow_date']:
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_DATE')
    if (item['status'] not in ('STARTED', 'LOCAL_CONTAINER_PASS_REMOTE_AND_CLIENT_NOT_VERIFIED')
            and not re.fullmatch(r'FAIL_[A-Z0-9_]{1,80}', item['status'])):
        raise MaintenanceError('MAINTENANCE_RECORD_INVALID_STATUS')
    return item


def local_node_running():
    result = call([DOCKER, 'inspect', 'remnanode',
                   '--format', '{{.State.Running}}|{{.State.Restarting}}|{{.HostConfig.NetworkMode}}'])
    return result == 'true|false|host'


def do_run(now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    now_msk = now.astimezone(MOSCOW)
    if not eligible(now):
        print('MAINTENANCE=SKIPPED OUTSIDE_03_04_MOSCOW')
        return 0
    if not (STATE / 'INSTALL_COMPLETE').is_file():
        print('MAINTENANCE=SKIPPED INSTALL_NOT_COMPLETE')
        return 0
    if LOCK.is_symlink() or (LOCK.exists() and (not LOCK.is_file() or LOCK.stat().st_uid != 0)):
        raise MaintenanceError('UNSAFE_INSTALLER_LOCK')
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with LOCK.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('MAINTENANCE=SKIPPED INSTALLER_OR_UPDATE_BUSY')
            return 0
        previous = last_result()
        day = now_msk.date().isoformat()
        if previous.get('moscow_date') == day:
            print('MAINTENANCE=SKIPPED ALREADY_ATTEMPTED_TODAY')
            return 0
        r = role()
        # Two-hop maintenance is never safe without cross-node ordering/canaries.
        if r != 'ordinary':
            print('MAINTENANCE=SKIPPED CASCADE_REQUIRES_PEER_COORDINATION')
            return 0
        # A container stopped by the operator must never be started by timer.
        if not local_node_running():
            print('MAINTENANCE=SKIPPED NODE_NOT_RUNNING')
            return 0
        call(['nginx', '-t'], timeout=15)
        call(['systemctl', 'is-active', '--quiet', 'ufw.service'], timeout=10)
        tx = {'moscow_date': day, 'role': r, 'started_at_utc': now.isoformat(), 'status': 'STARTED'}
        # At-most-once marker BEFORE the restart; a crash can't cause loop.
        atomic_record(tx)
        try:
            call([DOCKER, 'restart', '--time', '25', 'remnanode'], timeout=65)
            if not local_node_running():
                raise MaintenanceError('NODE_NOT_RUNNING_AFTER_RESTART')
            call(['nginx', '-t'], timeout=15)
            call(['systemctl', 'is-active', '--quiet', 'ufw.service'], timeout=10)
            tx['status'] = 'LOCAL_CONTAINER_PASS_REMOTE_AND_CLIENT_NOT_VERIFIED'
            atomic_record(tx)
            print('MAINTENANCE=PASS LOCAL_NODE_RUNNING; CLIENT_AND_CASCADE=NOT_VERIFIED')
            return 0
        except (MaintenanceError, OSError) as exc:
            tx['status'] = 'FAIL_' + (str(exc).split()[0][:80])
            atomic_record(tx)
            print('MAINTENANCE=FAIL ' + tx['status'], file=sys.stderr)
            return 1


def status():
    now = dt.datetime.now(MOSCOW)
    print('MAINTENANCE_TIMEZONE=Europe/Moscow')
    print('MAINTENANCE_WINDOW=03:00-03:59:59')
    print('MAINTENANCE_ROLE=' + role())
    try:
        record = last_result()
    except MaintenanceError:
        print('MAINTENANCE_LAST_STATUS=INVALID')
        raise
    print('MAINTENANCE_LAST_STATUS=' + str(record.get('status', 'NEVER')))
    print('MAINTENANCE_LAST_MOSCOW_DATE=' + str(record.get('moscow_date', 'NEVER')))
    print('MAINTENANCE_NEXT_PLANNED=systemctl list-timers --all vkarmani-node-nightly.timer')
    print('MAINTENANCE_NOW_MOSCOW=' + now.isoformat())
    print('MAINTENANCE_CHECK_SCOPE=LOCAL; authenticated VPN and remote exit NOT_VERIFIED')


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1 or argv[0] not in ('run', 'status'):
        print('Использование: nightly_maintenance.py run|status', file=sys.stderr)
        return 2
    try:
        if argv[0] == 'status':
            status()
            return 0
        if os.geteuid() != 0:
            raise MaintenanceError('ROOT_REQUIRED')
        return do_run()
    except (MaintenanceError, OSError) as exc:
        print('MAINTENANCE=FAIL ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
