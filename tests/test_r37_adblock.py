"""r37 offline tests: Blocky install/updates/rollback, no real host mutation."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml
from common import ROOT
sys.path.insert(0, str(ROOT/'integrations'))
sys.path.insert(0, str(ROOT/'scripts'))
import adblock
import terminal_ui as tui


def synthetic_list(n=40000):
    return ("# Title: HaGeZi's Multi NORMAL - all-round protection\n"+
            ''.join(f'*.ad{idx}.example\n' for idx in range(n))).encode()


def fake_archive():
    payload=b'\x7fELF' + b'NODEINSTALL_BLOCKY_FIXTURE'
    out=io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        ti=tarfile.TarInfo(name='blocky');ti.size=len(payload);ti.mode=0o755
        tar.addfile(ti,io.BytesIO(payload))
    return out.getvalue(),payload


class BlockyPolicies(unittest.TestCase):
    def test_config_is_loopback_only_and_bounded(self):
        filtered=yaml.safe_load(adblock.runtime_config(True))
        bypass=yaml.safe_load(adblock.runtime_config(False))
        self.assertEqual(filtered['ports'],{'dns':['127.0.0.1:15353']})
        self.assertNotIn('http',filtered['ports'])
        self.assertNotIn('tls',filtered['ports'])
        self.assertNotIn('https',filtered['ports'])
        self.assertEqual(filtered['blocking']['blockType'],'nxDomain')
        self.assertEqual(filtered['blocking']['loading']['refreshPeriod'],'5m')
        self.assertNotIn('blocking',bypass)
        self.assertTrue(all(x.startswith('https://') for x in filtered['upstreams']['groups']['default']))
        self.assertLessEqual(filtered['caching']['maxItemsCount'],10000)

    def test_service_is_unprivileged_and_timer_daily(self):
        service=adblock.service_unit().decode()
        self.assertIn('DynamicUser=yes',service)
        self.assertIn('NoNewPrivileges=yes',service)
        self.assertIn('ProtectHome=yes',service)
        self.assertIn('CapabilityBoundingSet=',service)
        self.assertIn('--config /etc/node-install-adblock/config.yml',service)
        timer=adblock.timer_unit().decode()
        self.assertIn('OnCalendar=*-*-*',timer)
        self.assertIn('RandomizedDelaySec=',timer)
        self.assertNotIn('ExecStart=',timer)
        self.assertIn('node-install-adblock/adblock.py update',adblock.update_unit().decode())

    def test_panel_profile_is_never_edited_by_manager(self):
        example=json.loads(adblock.profile_example())
        self.assertEqual(set(example),{'dns'})
        self.assertEqual(example['dns']['servers'],[{'address':'127.0.0.1','port':15353}])
        script=(ROOT/'integrations/adblock.py').read_text()
        self.assertNotIn('iptables -t nat',script)
        self.assertNotIn('ufw --force',script)
        self.assertNotIn('docker compose up',script)

    def test_list_valid_and_guarded_against_truncation_and_invalid_rules(self):
        data=synthetic_list()
        self.assertEqual(adblock.validate_list(data),40000)
        self.assertEqual(adblock.validate_list(data,previous_count=40000),40000)
        with self.assertRaisesRegex(adblock.AdblockError,'LIST_SIZE_UNEXPECTED'):
            adblock.validate_list(b'')
        with self.assertRaisesRegex(adblock.AdblockError,'WRONG_LIST_SOURCE'):
            adblock.validate_list(data.replace(b'HaGeZi',b'Unknown'))
        with self.assertRaisesRegex(adblock.AdblockError,'LIST_ENTRY_INVALID'):
            adblock.validate_list(data+b'malware | curl bash\n')
        with self.assertRaisesRegex(adblock.AdblockError,'LIST_SUSPICIOUS_CHANGE'):
            adblock.validate_list(data,previous_count=80000)
        self.assertTrue(adblock.list_payload(data).endswith(adblock.SENTINEL.encode()+b'\n'))
        self.assertEqual(adblock.count_stored(adblock.list_payload(data)),40000)

    def test_binary_pinned_digest_and_safe_extract(self):
        archive,program=fake_archive();digest=hashlib.sha256(archive).hexdigest()
        self.assertEqual(adblock.extract_binary(archive,digest),program)
        with self.assertRaisesRegex(adblock.AdblockError,'CHECKSUM'):
            adblock.extract_binary(archive,'0'*64)
        self.assertEqual(adblock.archive_details('x86_64')[1],
                         '97ae4257e4f2ea7ee4e0622fca152019eb92224d81b41b2549f064e4cef5584e')
        self.assertEqual(adblock.archive_details('aarch64')[1],
                         '9ac70e846f7919632e340607fb73d80a1fe280c9ceb876430d2a7d79743b4aae')
        with self.assertRaisesRegex(adblock.AdblockError,'UNSUPPORTED'):
            adblock.archive_details('powerpc64')

    def test_archive_path_traversal_not_extracted(self):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w:gz') as tar:
            m=tarfile.TarInfo('../../blocky');m.size=8
            tar.addfile(m,io.BytesIO(b'\x7fELFbad!'))
        data=out.getvalue()
        with self.assertRaisesRegex(adblock.AdblockError,'ARCHIVE_CONTENT'):
            adblock.extract_binary(data,hashlib.sha256(data).hexdigest())

    def test_list_https_only_and_bounded_download(self):
        class FakeResponse:
            headers={'Content-Length':'10'}
            def geturl(self):return 'https://example.org/data'
            def read(self,n):return b'ok'
            def __enter__(self):return self
            def __exit__(self,*exc):return False
        self.assertEqual(adblock.fetched('https://example.org/test',16,opener=lambda *a,**k:FakeResponse()),b'ok')
        with self.assertRaisesRegex(adblock.AdblockError,'HTTPS_DOWNLOAD_REQUIRED'):
            adblock.fetched('http://example.org/evil',16,opener=lambda *a,**k:FakeResponse())
        with self.assertRaisesRegex(adblock.AdblockError,'DOWNLOAD_TOO_LARGE'):
            adblock.fetched('https://example.org/test',4,opener=lambda *a,**k:FakeResponse())


class HostPrerequisitePolicy(unittest.TestCase):
    def test_real_owner_policy_is_not_broadened_by_offline_fixtures(self):
        class Stat:
            def __init__(self,uid):self.st_uid=uid
        self.assertTrue(adblock.root_owned(Stat(0)))
        self.assertFalse(adblock.root_owned(Stat(1001)))
        self.assertFalse(adblock.root_owned(Stat(65534)))

    def test_real_systemctl_preflight_requires_an_executable(self):
        with mock.patch.object(adblock.shutil,'which',return_value=None):
            self.assertFalse(adblock.systemctl_available())
        with mock.patch.object(adblock.shutil,'which',return_value='/usr/bin/systemctl'):
            self.assertTrue(adblock.systemctl_available())

    def test_unsafe_fixture_owner_symlink_and_mode_are_still_rejected(self):
        with tempfile.TemporaryDirectory(prefix='node-adblock-guards-') as temp:
            root=Path(temp)
            good=root/'valid';good.write_text('test')
            if os.geteuid() != 0:
                with self.assertRaisesRegex(adblock.AdblockError,'UNSAFE_FILE'):
                    adblock.regular_file(good)
            link=root/'link';link.symlink_to(good)
            with self.assertRaisesRegex(adblock.AdblockError,'UNSAFE_FILE'):
                adblock.regular_file(link,owner_root=False)
            good.chmod(0o666)
            with self.assertRaisesRegex(adblock.AdblockError,'UNSAFE_FILE'):
                adblock.regular_file(good,owner_root=False)


class FakeHost(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='node-adblock-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.dirpatches=[]
        for name,rel in (('INSTALL_DIR','lib'),('CONFIG_DIR','etc/adblock'),('DATA_DIR','var/adblock'),
                         ('UNIT_DIR','units'),('NODE_STATE','node-state'),('NODE_ETC','node-etc'),
                         ('LOCK','locks/adblock.lock')):
            patch=mock.patch.object(adblock,name,self.root/rel)
            patch.start();self.addCleanup(patch.stop)
        for d in (adblock.UNIT_DIR,adblock.NODE_STATE,adblock.NODE_ETC,adblock.LOCK.parent,
                  adblock.CONFIG_DIR.parent,adblock.DATA_DIR.parent,adblock.INSTALL_DIR.parent):
            d.mkdir(parents=True,exist_ok=True)
        (adblock.NODE_STATE/'INSTALL_COMPLETE').write_text('version=2.5.18\n')
        # The offline host is isolated in TemporaryDirectory. Its files are
        # owned by the test runner (uid 1001 on GitHub VMs, uid 0 as root).
        # Simulate root *ownership* only, while preserving all actual file,
        # symlink, hardlink, and permission validation in adblock.py.
        fixture_uid=os.geteuid()
        for name,stub in (
            ('root_owned',lambda st: st.st_uid == fixture_uid),
            ('systemctl_available',lambda:True),
        ):
            patch=mock.patch.object(adblock,name,stub)
            patch.start();self.addCleanup(patch.stop)
        self.blob=synthetic_list()
        self.arch,self.program=fake_archive()
        self.systemd_calls=[]
        self.is_active=False
        self.timer_active=False
        def command(*cmd, **kw):
            self.systemd_calls.append(cmd)
            return subprocess.CompletedProcess(cmd,0,'','')
        def active(unit):return self.is_active if unit==adblock.SERVICE else self.timer_active
        for name,target in (('root_only',lambda:None),('run',command),
                            ('systemd_active',active),('probe',lambda *args:None),
                            ('archive_details',lambda:('https://fixture.invalid/blocky',hashlib.sha256(self.arch).hexdigest())),
                            ('fetched',lambda url,limit: self.arch if 'blocky' in url else self.blob)):
            patch=mock.patch.object(adblock,name,target)
            patch.start();self.addCleanup(patch.stop)
        # Avoid relying on arbitrary Linux socket availability in offline tests.
        patch=mock.patch.object(adblock,'check_port_free',lambda:None)
        patch.start();self.addCleanup(patch.stop)

    def test_entry_rejected_before_any_mutation(self):
        (adblock.NODE_STATE/'role.json').write_text(json.dumps({'role':'cascade-entry'}))
        (adblock.NODE_ETC/'cascade-role.json').write_text('{}')
        with self.assertRaisesRegex(adblock.AdblockError,'ADBLOCK_ONLY_ON'):
            adblock.install(True)
        self.assertEqual(self.systemd_calls,[])
        self.assertFalse(adblock.CONFIG_DIR.exists())

    def test_exit_accepted_only_with_matching_cascade_marker(self):
        (adblock.NODE_STATE/'role.json').write_text(json.dumps({'role':'cascade-exit'}))
        with self.assertRaisesRegex(adblock.AdblockError,'ROLE_STATE_MISMATCH'):
            adblock.install(True)
        (adblock.NODE_ETC/'cascade-role.json').write_text('{}')
        adblock.install(True)
        self.assertEqual(adblock.owned_marker()['filtering'],True)

    def test_full_first_install_writes_only_managed_files_and_not_node(self):
        before=(adblock.NODE_STATE/'INSTALL_COMPLETE').read_bytes()
        adblock.install(True)
        self.assertEqual((adblock.NODE_STATE/'INSTALL_COMPLETE').read_bytes(),before)
        self.assertEqual((adblock.CONFIG_DIR/'config.yml').read_bytes(),adblock.runtime_config(True))
        self.assertEqual((adblock.INSTALL_DIR/'blocky').read_bytes(),self.program)
        self.assertEqual(adblock.owned_marker()['version'],adblock.VERSION)
        self.assertTrue(any('restart' in cmd for cmd in self.systemd_calls))
        self.assertTrue(any(adblock.UPDATER_TIMER in cmd for cmd in self.systemd_calls))
        self.assertFalse((adblock.NODE_ETC/'config.json').exists())

    def test_enable_idempotent_without_network_redownload(self):
        adblock.install(True)
        self.is_active=True
        with mock.patch.object(adblock,'fetched',side_effect=AssertionError('unexpected network')):
            adblock.install(True)
        self.assertEqual(adblock.owned_marker()['filtering'],True)

    def test_disable_keeps_dns_service_and_enables_bypass(self):
        adblock.install(True)
        self.is_active=True
        adblock.disable()
        self.assertEqual(adblock.owned_marker()['filtering'],False)
        self.assertNotIn('blocking',yaml.safe_load((adblock.CONFIG_DIR/'config.yml').read_text()))
        self.assertFalse(any(cmd[:3]==('systemctl','stop',adblock.SERVICE) for cmd in self.systemd_calls))
        adblock.install(True)
        self.assertEqual(adblock.owned_marker()['filtering'],True)

    def test_initial_failure_restores_files_and_never_touches_node(self):
        original=(adblock.NODE_STATE/'INSTALL_COMPLETE').read_bytes()
        with mock.patch.object(adblock,'probe',side_effect=adblock.AdblockError('DNS_DOWN')):
            with self.assertRaisesRegex(adblock.AdblockError,'DNS_DOWN'):
                adblock.install(True)
        self.assertIsNone(adblock.owned_marker())
        self.assertFalse((adblock.CONFIG_DIR/'config.yml').exists())
        self.assertEqual((adblock.NODE_STATE/'INSTALL_COMPLETE').read_bytes(),original)

    def test_corrupt_update_preserves_previous_list(self):
        adblock.install(True)
        prev=(adblock.DATA_DIR/adblock.LIST_FILE).read_bytes()
        with mock.patch.object(adblock,'fetched',return_value=b'corrupted'):
            with self.assertRaisesRegex(adblock.AdblockError,'LIST_SIZE'):
                adblock.update_lists()
        self.assertEqual((adblock.DATA_DIR/adblock.LIST_FILE).read_bytes(),prev)

    def test_update_creates_rollback_copy_and_is_idempotent(self):
        adblock.install(True)
        old=(adblock.DATA_DIR/adblock.LIST_FILE).read_bytes()
        new=synthetic_list(40200)
        with mock.patch.object(adblock,'fetched',return_value=new):
            adblock.update_lists()
        self.assertEqual((adblock.DATA_DIR/'hagezi-normal.previous.txt').read_bytes(),old)
        self.assertEqual(adblock.count_stored((adblock.DATA_DIR/adblock.LIST_FILE).read_bytes()),40200)
        with mock.patch.object(adblock,'fetched',return_value=new):
            adblock.update_lists()
        self.assertEqual((adblock.DATA_DIR/'hagezi-normal.previous.txt').read_bytes(),old)

    def test_manually_changed_config_never_overwritten(self):
        adblock.install(True)
        path=adblock.CONFIG_DIR/'config.yml';path.write_text(path.read_text()+'# changed\n')
        with self.assertRaisesRegex(adblock.AdblockError,'CONFIG_MODIFIED'):
            adblock.install(False)
        self.assertTrue(path.read_text().endswith('# changed\n'))

    def test_symlink_rejected_without_following(self):
        adblock.CONFIG_DIR.mkdir(parents=True)
        ext=self.root/'innocent';ext.write_text('keep this file')
        (adblock.CONFIG_DIR/'config.yml').symlink_to(ext)
        with self.assertRaisesRegex(adblock.AdblockError,'FOREIGN_BLOCKY_ARTIFACT'):
            adblock.install(True)
        self.assertEqual(ext.read_text(),'keep this file')

    def test_status_does_not_mutate(self):
        adblock.status()
        self.assertEqual(self.systemd_calls,[])
        adblock.install(True)
        self.is_active=True
        with contextlib.redirect_stdout(io.StringIO()) as f:
            self.assertEqual(adblock.status(),0)
        self.assertIn('CLIENT_DNS=NOT_VERIFIED',f.getvalue())


class DNSProbeContracts(unittest.TestCase):
    def test_probe_is_a_real_resolvable_domain_not_dot_invalid(self):
        self.assertEqual(adblock.PROBE_NAME,'www.example.com')
        self.assertEqual(adblock.SENTINEL,'*.www.example.com')
        with mock.patch.object(adblock,'systemd_active',return_value=True), \
             mock.patch.object(adblock,'dns_query',side_effect=lambda host: 3 if host==adblock.PROBE_NAME else 0):
            adblock.probe(True)

    def test_bypass_must_really_resolve_probe_host(self):
        with mock.patch.object(adblock,'systemd_active',return_value=True), \
             mock.patch.object(adblock,'dns_query',side_effect=lambda host: 3 if host==adblock.PROBE_NAME else 0), \
             mock.patch.object(adblock.time,'monotonic',side_effect=[0,30]):
            with self.assertRaisesRegex(adblock.AdblockError,'ADBLOCK_PROBE_TIMEOUT:ADBLOCK_BYPASS_NOT_WORKING'):
                adblock.probe(False)

class RebootCoordination(unittest.TestCase):
    def test_reboot_scheduled_only_after_blocky_success(self):
        ok=subprocess.CompletedProcess([],0,'','')
        with mock.patch.object(tui.subprocess,'run',return_value=ok) as m, \
             mock.patch.object(tui.time,'time',return_value=1234567890):
            self.assertTrue(tui.schedule_postinstall_reboot())
        argv=m.call_args.args[0]
        self.assertEqual(argv[0],'systemd-run')
        self.assertIn('--on-active=45s',argv)
        self.assertEqual(argv[-2:],['/usr/bin/systemctl','reboot'])
        with mock.patch.object(tui.subprocess,'run',side_effect=FileNotFoundError('systemd-run')):
            self.assertFalse(tui.schedule_postinstall_reboot())

    def test_wizard_defers_reboot_until_dns_has_passed(self):
        ui=(ROOT/'scripts/terminal_ui.py').read_text()
        self.assertIn("if options['adblock']:\n                run_settings['no_reboot']=True",ui)
        self.assertIn('if blocky_rc==0 and schedule_postinstall_reboot()',ui)
        self.assertIn('Auto reboot не назначен',ui)

class UIContract(unittest.TestCase):
    def test_cli_route_not_implicit_install(self):
        script=(ROOT/'install.sh').read_text()
        self.assertIn('--adblock) shift; vkarmani_adblock_command "$@"',script)
        self.assertNotIn('curl -fsSL | bash',script)
        r=subprocess.run(['bash','install.sh','--adblock','status'],cwd=ROOT,
                         capture_output=True,text=True,timeout=12)
        self.assertEqual(r.returncode,0,r.stderr)
        # Fixture test runner must never install a Node or manipulate host DNS.
        self.assertIn('ADBLOCK=',r.stdout)

    def test_master_has_opt_in_not_default_on(self):
        script=(ROOT/'scripts/terminal_ui.py').read_text()
        self.assertIn("'adblock':False",script)
        self.assertIn('BLOCKY / УСТАНОВКА DNS-ФИЛЬТРА',script)
        self.assertIn('if rc==0:',script)
        self.assertIn("'--adblock','enable'",script)
        self.assertIn('БЛОКИРОВКА РЕКЛАМЫ · BLOCKY',script)
        self.assertIn('DNS клиентов Remnawave не подтверждён',script)


if __name__ == '__main__':
    unittest.main()
