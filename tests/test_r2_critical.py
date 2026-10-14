"""Regressions from the 2026-10-14 audit (all host mutations intercepted).

Mocked systemd/UFW tests are not a replacement for isolated VM acceptance.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, SCRIPT, module, payload


def load_file(relname, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relname)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


class R2ShutdownRegressions(unittest.TestCase):
    def sandbox(self, *, fault='', dropin=True, foreign=False, pending=False):
        with tempfile.TemporaryDirectory(prefix='vk-r2-shutdown-') as tmp:
            root = Path(tmp)
            drop = root / '90-vkarmani-rkn.conf'
            backup = root / '90-vkarmani-rkn.conf.vkarmani-pending-remove'
            unit = '[Unit]\nRequires=vkarmani-rkn-prepare.service\nAfter=vkarmani-rkn-prepare.service\n'
            if dropin:
                drop.write_text('FOREIGN\n' if foreign else unit)
            if pending:
                backup.write_text(unit)
            helper = root / 'vk-rkn-guard'
            helper.write_text('#!/usr/bin/env bash\necho "helper $*" >> "$EVENTS"\nexit 0\n')
            helper.chmod(0o755)
            events = root / 'events'
            body = SCRIPT.split('vk_rkn_safe_shutdown() {', 1)[1].split('\nvk_rkn_abort_setup() {', 1)[0]
            body = 'vk_rkn_safe_shutdown() {' + body
            body = body.replace('/etc/systemd/system/ufw.service.d/90-vkarmani-rkn.conf', str(drop))
            body = body.replace('/usr/local/sbin/vkarmani-rkn-guard', str(helper))
            # run unprivileged tests against temp-owned test files
            body = body.replace("$(stat -c '%u' \"$dropin\") == 0", "$(stat -c '%u' \"$dropin\") == $(id -u)")
            body = body.replace("$(stat -c '%u' \"$backup\") == 0", "$(stat -c '%u' \"$backup\") == $(id -u)")
            shell = '''set -Eeuo pipefail
systemctl() {
  echo "systemctl $*" >> "$EVENTS"
  if [[ "$*" == "$FAULT" ]]; then return 44; fi
  if [[ "$*" == 'is-active --quiet vkarmani-rkn-update.service' ]]; then return 3; fi
  return 0
}
ufw() { echo "ufw $*" >> "$EVENTS"; printf 'Status: active\\n'; }
'''+body+'''
set +e
vk_rkn_safe_shutdown > "$OUTPUT" 2>&1
result=$?
set -e
printf 'exit=%s\\n' "$result"
cat "$OUTPUT"
exit 0
'''
            env = os.environ | {'EVENTS': str(events), 'OUTPUT': str(root/'out'), 'FAULT': fault}
            result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            yield result.stdout, events.read_text().splitlines() if events.exists() else [], drop, backup

    def test_shutdown_order_and_actual_success(self):
        for output, events, drop, backup in self.sandbox():
            self.assertIn('exit=0', output)
            self.assertFalse(drop.exists()); self.assertFalse(backup.exists())
            self.assertLess(events.index('helper disable'), events.index('systemctl daemon-reload'))
            self.assertLess(events.index('systemctl daemon-reload'),
                            events.index('systemctl disable --now vkarmani-rkn-prepare.service'))
            self.assertIn('systemctl is-active --quiet ufw.service', events)

    def test_failed_reload_never_stops_prepare_and_restores_dropin(self):
        for output, events, drop, backup in self.sandbox(fault='daemon-reload'):
            self.assertIn('exit=1', output)
            self.assertTrue(drop.is_file()); self.assertFalse(backup.exists())
            self.assertNotIn('systemctl disable --now vkarmani-rkn-prepare.service', events)
            self.assertNotIn('RKN_DISABLE=PASS', output)

    def test_foreign_dropin_never_mutated(self):
        for output, events, drop, backup in self.sandbox(foreign=True):
            self.assertIn('exit=1', output)
            self.assertEqual(drop.read_text(), 'FOREIGN\n')
            self.assertEqual(events, [])

    def test_interrupted_deletion_resumes_idempotently(self):
        for output, events, drop, backup in self.sandbox(dropin=False, pending=True):
            self.assertIn('exit=0', output)
            self.assertFalse(drop.exists()); self.assertFalse(backup.exists())
        for output, events, drop, backup in self.sandbox(dropin=False):
            self.assertIn('exit=0', output)
            self.assertEqual(events.count('systemctl daemon-reload'), 1)

    def test_failed_prepare_stop_reports_error(self):
        for output, events, drop, backup in self.sandbox(fault='disable --now vkarmani-rkn-prepare.service'):
            self.assertIn('exit=1', output)
            self.assertTrue(backup.exists())
            self.assertNotIn('RKN_DISABLE=PASS', output)

    def test_dynamic_caller_protects_all_mutating_actions_with_lock(self):
        command = SCRIPT.split('vkarmani_rkn_command() {', 1)[1].split('vk_write_xhttp_profile_helper()', 1)[0]
        self.assertLess(command.index('flock -n 9'), command.index('update) /usr/local/sbin'))
        self.assertLess(command.index('flock -n 9'), command.index('disable) vk_rkn_safe_shutdown'))
        abort = SCRIPT.split('vk_rkn_abort_setup() {', 1)[1].split('vk_rkn_activate() {', 1)[0]
        self.assertIn('vk_rkn_safe_shutdown', abort)
        self.assertNotIn('systemctl disable --now vkarmani-rkn-prepare.service', abort)


class R2RKNFailOpen(unittest.TestCase):
    def test_no_ipset_creation_does_not_leave_unbootable_ufw_fragment(self):
        m = module('VK_RKN_GUARD_PY')
        with tempfile.TemporaryDirectory(prefix='vk-r2-ipset-') as tmp:
            base = Path(tmp)
            m.UFW_FILE = base / 'before.rules'
            m.ROOT = base / 'rkn'
            m.CACHE = m.ROOT / 'current-v4.txt'
            m.CHECKED = m.ROOT / 'last-check.json'
            before = '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n'
            with_marker = m.edit_ufw(before, True)
            m.UFW_FILE.write_text(with_marker)
            calls = []
            def fake_run(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('ufw', 'status'):
                    return 'Status: inactive\n'
                return ''
            with (patch.object(m, 'require_node'), patch.object(m, 'ipset_exists', return_value=False),
                  patch.object(m, 'ipset_create', side_effect=m.GuardError('IPSET_UNAVAILABLE')),
                  patch.object(m, 'run', side_effect=fake_run),
                  contextlib.redirect_stderr(io.StringIO())):
                self.assertFalse(m.prepare())
            self.assertEqual(m.UFW_FILE.read_text(), before)
            self.assertIn(('iptables-restore', '--test'), [x[:2] for x in calls])
            self.assertNotIn(('ufw', 'reload'), [x[:2] for x in calls])


    def test_status_does_not_claim_cached_networks_exist_in_kernel(self):
        m = module('VK_RKN_GUARD_PY')
        import hashlib
        with tempfile.TemporaryDirectory(prefix='vk-r2-status-') as tmp:
            root = Path(tmp)
            m.UFW_FILE = root / 'before.rules'
            m.CHECKED = root / 'last-check.json'
            m.UFW_FILE.write_text('*filter\n' + m.BEGIN + '\nCOMMIT\n')
            networks = ['198.51.100.%d/32' % i for i in range(100)]
            fingerprint = hashlib.sha256((''.join(x + '\n' for x in networks)).encode()).hexdigest()
            m.CHECKED.write_text(json.dumps({'sha256':fingerprint,'count_ipv4':100}))
            out=io.StringIO()
            with (patch.object(m, 'require_node'), patch.object(m, 'panel_ips', return_value=['1.1.1.1']),
                  patch.object(m, 'restore_cached', return_value=networks),
                  patch.object(m, 'check_ufw_jump'),
                  patch.object(m, 'run', return_value='create vkarmani_rkn_blk4 hash:net family inet\n'),
                  contextlib.redirect_stdout(out)):
                self.assertEqual(m.status(), 1)
            self.assertIn('RKN_DATA=DEGRADED', out.getvalue())
            self.assertNotIn('RKN_DATA=PASS', out.getvalue())

    def test_failed_first_enable_never_prints_enabled(self):
        m = module('VK_RKN_GUARD_PY')
        with tempfile.TemporaryDirectory(prefix='vk-r2-first-enable-') as tmp:
            m.ROOT = Path(tmp)
            m.UFW_FILE = Path(tmp) / 'before.rules'
            m.UFW_FILE.write_text('*filter\nCOMMIT\n')
            applied = []
            out = io.StringIO()
            with (patch.object(m, 'require_node'), patch.object(m, 'check_ufw_active'),
                  patch.object(m, 'prepare', return_value=True),
                  patch.object(m, 'apply_ufw', side_effect=applied.append),
                  patch.object(m, 'update', side_effect=m.GuardError('UPSTREAM_UNAVAILABLE')),
                  patch.object(m, 'restore_cached', return_value=[]),
                  contextlib.redirect_stdout(out)):
                with self.assertRaisesRegex(m.GuardError, 'RKN_NO_VERIFIED_LIST'):
                    m.enable()
            self.assertEqual(applied, [True, False])
            self.assertNotIn('RKN_FIREWALL=ENABLED', out.getvalue())


class R2SecurityRegression(unittest.TestCase):
    def test_all_security_opt_variants(self):
        heredoc = payload('PY_CAPS')
        base = [['NET_ADMIN'], ['NET_RAW']]
        accepted = ['no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true']
        rejected = ['no-new-privileges:false', 'no-new-privileges=false',
                    'no-new-privileges-INVALID', 'no-new-privileges:other',
                    'no-new-privileges:truee']
        for values, valid in [( [v], True) for v in accepted] + [([v], False) for v in rejected] + [([], False),
                (['no-new-privileges:true','no-new-privileges:false'], False),
                (['no-new-privileges:true','no-new-privileges:true'], False)]:
            with self.subTest(security=values):
                p = subprocess.run(['python3', '-', *map(json.dumps, base+[values])],
                                   input=heredoc, capture_output=True, text=True, timeout=5)
                self.assertEqual(p.returncode == 0, valid, p.stderr)

    def test_alias_method_audit_without_keyerror(self):
        m = module('PY_HELPER')
        with tempfile.TemporaryDirectory(prefix='vk-r2-audit-') as tmp:
            cfg = {'domain':'node.example.test','public_ipv4':'8.8.4.4','panel_ipv4':['1.1.1.1'],'node_port':2222}
            with patch.object(m, 'detect_local_public_ipv4s', return_value={'8.8.4.4':'eth0'}):
                if hasattr(m, 'REALITY_EXPORT'):
                    m.REALITY_EXPORT=Path(tmp)/'keys.txt'
                m.ETC=Path(tmp)
                _, _, obj = m.make_keys_profile(cfg)
            inbound = next(x for x in obj['inbounds'] if x['protocol']=='vless')
            inbound['streamSettings']['method']=inbound['streamSettings'].pop('network')
            path=Path(tmp)/'profile.json'; path.write_text(json.dumps(obj))
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                m.audit_profile(path,cfg)
            self.assertIn('PROFILE_RAW_REALITY_SELFSTEAL_POLICY=PASS', out.getvalue())


class R2LocalDocker(unittest.TestCase):
    def test_wrapper_blocks_missing_local_socket_and_ignores_remote_env(self):
        src=(ROOT/'integrations/docker_local.sh').read_text()
        embedded=payload('VK_DOCKER_LOCAL_SH')
        self.assertEqual(embedded, src)
        self.assertIn('env -i', src)
        self.assertIn('--host unix:///var/run/docker.sock', src)
        with tempfile.TemporaryDirectory(prefix='vk-r2-docker-') as tmp:
            missing=Path(tmp)/'missing.sock'
            isolated=src.replace('/var/run/docker.sock',str(missing))
            wrapper=Path(tmp)/'docker.sh'; wrapper.write_text(isolated)
            wrapper.chmod(0o755)
            env=os.environ | {'DOCKER_HOST':'ssh://root@remote.example',
                              'DOCKER_CONTEXT':'remote-prod','DOCKER_CONFIG':'/tmp/foreign-context'}
            p=subprocess.run([str(wrapper),'ps'],env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('LOCAL_DOCKER_UNAVAILABLE',p.stderr)

    def test_wrapper_effectively_sanitizes_context(self):
        src=(ROOT/'integrations/docker_local.sh').read_text()
        with tempfile.TemporaryDirectory(prefix='vk-r2-docker-') as tmp:
            sock=Path(tmp)/'docker.sock'
            server=socket.socket(socket.AF_UNIX)
            server.bind(str(sock))
            self.addCleanup(server.close)
            fake=Path(tmp)/'docker'
            fake.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*"\nprintenv DOCKER_CONFIG\nprintenv DOCKER_HOST || true\nprintenv DOCKER_CONTEXT || true\n')
            fake.chmod(0o755)
            script=src.replace('/var/run/docker.sock',str(sock)).replace('/usr/bin/docker',str(fake))
            wrapper=Path(tmp)/'wrapper'; wrapper.write_text(script); wrapper.chmod(0o755)
            env=os.environ | {'DOCKER_HOST':'tcp://elsewhere:2376', 'DOCKER_CONTEXT':'remote',
                              'DOCKER_CONFIG':'/tmp/remote-config'}
            p=subprocess.run([str(wrapper),'ps','--all'],env=env,text=True,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--host unix://'+str(sock),p.stdout)
            self.assertNotIn('remote-config',p.stdout)
            self.assertNotIn('tcp://elsewhere',p.stdout)


class R2Nightly(unittest.TestCase):
    def test_window_timezone(self):
        m=load_file('integrations/nightly_maintenance.py','night_maint_r2')
        import datetime as dt
        self.assertFalse(m.eligible(dt.datetime(2026,10,14,23,59,59,tzinfo=dt.timezone.utc)))
        self.assertTrue(m.eligible(dt.datetime(2026,10,15,0,0,0,tzinfo=dt.timezone.utc)))
        self.assertTrue(m.eligible(dt.datetime(2026,10,15,0,59,59,tzinfo=dt.timezone.utc)))
        self.assertFalse(m.eligible(dt.datetime(2026,10,15,1,0,0,tzinfo=dt.timezone.utc)))

    def test_timer_not_persistent_and_does_not_reboot_vps(self):
        t=payload('VK_NIGHT_MAINT_TIMER'); u=payload('VK_NIGHT_MAINT_SERVICE')
        self.assertIn('Europe/Moscow',t)
        self.assertIn('FixedRandomDelay=yes',t)
        self.assertIn('Persistent=false',t)
        self.assertIn('nightly_maintenance.py run',u)
        self.assertNotIn('reboot',u)

    def test_manual_stop_and_at_most_once(self):
        m=load_file('integrations/nightly_maintenance.py','night_maint_r2_case')
        import datetime as dt
        with tempfile.TemporaryDirectory(prefix='vk-r2-night-') as tmp:
            root=Path(tmp)
            m.STATE=root; m.RESULT=root/'maintenance-last.json'; m.LOCK=root/'install.lock'
            (root/'INSTALL_COMPLETE').write_text('done')
            now=dt.datetime(2026,10,15,0,20,tzinfo=dt.timezone.utc)
            events=[]
            def fake(args,timeout=None):
                events.append(list(args))
                if args[1]=='inspect': return 'false|false|host'
                return ''
            with patch.object(m,'call',side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.do_run(now),0)
            self.assertFalse(any('restart' in a for a in events))
            self.assertFalse(m.RESULT.exists())
            def running(args,timeout=None):
                events.append(list(args))
                if len(args)>1 and args[1]=='inspect':return 'true|false|host'
                return ''
            events.clear()
            # do_run is called directly as a root-service mock. A nonroot CI
            # runner cannot create root-owned lock files: reset that mock file
            # between invocations, but keep the persisted at-most-once marker.
            if m.LOCK.exists():
                m.LOCK.unlink()
            with patch.object(m,'call',side_effect=running), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.do_run(now),0)
                m.LOCK.unlink()
                self.assertEqual(m.do_run(now),0)
            self.assertEqual(sum(a[1]=='restart' for a in events if len(a)>1),1)
            self.assertEqual(json.loads(m.RESULT.read_text())['status'],
                             'LOCAL_CONTAINER_PASS_REMOTE_AND_CLIENT_NOT_VERIFIED')

if __name__=='__main__':
    unittest.main()
