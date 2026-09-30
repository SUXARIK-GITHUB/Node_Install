"""26.04 feature gates and Chrony preservation; systemd/chronyd are not changed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from common import module, SCRIPT, ROOT


class PlatformTests(unittest.TestCase):
    def call(self,args):
        return subprocess.run(['bash','-c','set -Eeuo pipefail; source "$1"; shift; vk_platform_settings "$@"; printf "%s:%s:%s\\n" "$OS_ID" "$OS_CODENAME" "$MIN_MEMORY_MB"','test',str(ROOT/'install.sh'),*args],text=True,capture_output=True,timeout=10)

    def test_supported_exact_release_arch_matrix(self):
        for distro,version,code in [('ubuntu','22.04','jammy'),('ubuntu','24.04','noble'),('ubuntu','26.04','resolute'),('debian','12','bookworm'),('debian','13','trixie')]:
            for arch in ('amd64','arm64'):
                with self.subTest(os=version,arch=arch):
                    r=self.call([distro,version,code,arch]);self.assertEqual(r.returncode,0,r.stderr)
                    self.assertIn('1536' if version=='26.04' else '900',r.stdout)

    def test_wrong_release_codename_arch_refused(self):
        for args in [('ubuntu','26.04','noble','amd64'),('ubuntu','24.04','resolute','amd64'),('ubuntu','26.04','resolute','i386'),('ubuntu','26.10','sassy','amd64'),('linuxmint','26.04','resolute','arm64')]:
            with self.subTest(args=args):
                r=self.call(args);self.assertNotEqual(r.returncode,0);self.assertIn('STOP:',r.stderr)

    def test_real_tool_options_smoke(self):
        r=subprocess.run(['bash','-c','set -Eeuo pipefail; source "$1"; vk_base_tools_smoke','test',str(ROOT/'install.sh')],text=True,capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn('BASE_TOOLS_SMOKE=PASS',r.stdout)

    def test_tool_probe_failure_stops_even_from_a_conditional(self):
        r=subprocess.run(['bash','-c','source "$1"; cp(){ return 71; }; if vk_base_tools_smoke; then exit 99; else exit 0; fi','test',str(ROOT/'install.sh')],text=True,capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn('BASE_TOOLS_SMOKE=PASS',r.stdout)

    def test_package_plan_precedes_access_changes(self):
        start=SCRIPT.index('DOCKER_PACKAGES=(')
        plan=SCRIPT.index('"${APT[@]}" --simulate install "${NODE_PACKAGES[@]}" "${DOCKER_PACKAGES[@]}"',start)
        self.assertLess(plan,SCRIPT.index("stage 'IPv4-only:"))
        self.assertLess(plan,SCRIPT.index("stage 'MSK,"))
        self.assertIn('Suites: $OS_CODENAME',SCRIPT)
        self.assertNotIn('Suites: noble',SCRIPT)
        self.assertIn('APT::Update::Error-Mode=any',SCRIPT)
        self.assertIn('/sys/fs/cgroup/cgroup.controllers',SCRIPT)


class ChronyTests(unittest.TestCase):
    def setUp(self):
        self.m=module('VK_CHRONY_CONFIG_PY')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.conf=self.root/'etc/chrony/chrony.conf';self.conf.parent.mkdir(parents=True)
        self.defaults=self.root/'etc/default/chrony';self.defaults.parent.mkdir(parents=True)
        self.original='confdir /etc/chrony/conf.d\nsourcedir /etc/chrony/sources.d\nntsdumpdir /var/lib/chrony\nserver ntp.example.test iburst nts\n'
        self.conf.write_text(self.original);self.defaults.write_text('# provider comment\nDAEMON_OPTS="-F 1"\n')
        self.conf.chmod(0o644);self.defaults.chmod(0o644)

    def test_preserves_sources_nts_and_idempotent(self):
        once=self.m.render_config(self.original)
        self.assertTrue(once.startswith(self.original));self.assertIn('ntsdumpdir',once)
        self.assertEqual(once,self.m.render_config(once))
        self.assertEqual(once.count('port 0\n'),2)

    def test_preserves_default_flags_and_ipv4_idempotent(self):
        for value in ('-F 1','-F 2','-4 -F 1',''):
            with self.subTest(value=value):
                raw='# text\nDAEMON_OPTS="'+value+'"\n'
                rendered=self.m.render_defaults(raw)
                self.assertIn('-4',rendered);self.assertTrue(rendered.startswith('# text\n'))
                self.assertEqual(rendered,self.m.render_defaults(rendered))
        self.assertIn('DAEMON_OPTS="-4"',self.m.render_defaults('# no flags\n'))

    def test_custom_or_injected_flags_refused(self):
        for raw in ['DAEMON_OPTS="-6"','DAEMON_OPTS="-f /tmp/custom"','DAEMON_OPTS="$(touch /tmp/bad)"','DAEMON_OPTS="-x"','DAEMON_OPTS="-F 1"\nDAEMON_OPTS="-4"','DAEMON_OPTS=bad unquoted']:
            with self.subTest(raw=raw), self.assertRaises(self.m.Failure):
                self.m.render_defaults(raw)

    def test_modified_managed_block_refused(self):
        for raw in [self.m.BLOCK.replace('port 0','port 123'),self.m.BLOCK+self.m.BLOCK,self.m.BEGIN]:
            with self.subTest(raw=raw),self.assertRaises(self.m.Failure):self.m.render_config(raw)

    def test_configure_validates_twice_and_does_not_touch_included_sources(self):
        sources=self.conf.parent/'sources.d';sources.mkdir();source=sources/'ubuntu.sources';source.write_text('pool example.test nts\n')
        runner=unittest.mock.Mock(return_value=subprocess.CompletedProcess([],0))
        self.m.configure(self.root,runner)
        self.assertEqual(runner.call_count,2)
        self.assertEqual(source.read_text(),'pool example.test nts\n')
        self.assertIn('nts',self.conf.read_text());self.assertIn('-4',self.defaults.read_text())
        self.assertEqual(runner.call_args.args[0][:3],['chronyd','-p','-4'])

    def test_validation_failure_restores_both_files(self):
        original=self.defaults.read_bytes()
        runner=unittest.mock.Mock(side_effect=[subprocess.CompletedProcess([],0),subprocess.CompletedProcess([],1)])
        with self.assertRaises(self.m.Failure):self.m.configure(self.root,runner)
        self.assertEqual(self.conf.read_text(),self.original);self.assertEqual(self.defaults.read_bytes(),original)

    def test_prevalidation_failure_writes_nothing(self):
        with patch.object(self.m,'atomic') as a:
            with self.assertRaises(self.m.Failure):self.m.configure(self.root,lambda *a,**k:subprocess.CompletedProcess([],1))
            a.assert_not_called()

    def test_unsafe_symlink_or_permissions_refused(self):
        self.defaults.chmod(0o666)
        with self.assertRaises(self.m.Failure):self.m.configure(self.root)
        self.defaults.unlink();self.defaults.symlink_to(self.conf)
        with self.assertRaises(self.m.Failure):self.m.configure(self.root)
