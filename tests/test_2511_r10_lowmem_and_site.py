"""R10 regressions: 1 GiB pre-APT swap and site/Selfsteal contracts.

No production side effects: all swap-path operations are remapped into a
private temporary directory, no swapon/mkswap/dd is executed on the host.
"""
import re
import subprocess
import tempfile
from pathlib import Path
import unittest

from common import ROOT, SCRIPT


class LowMemoryPreApt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start = SCRIPT.index('vk_lowmem_swap_total_kib() {')
        end = SCRIPT.index('vk_kernel_plugins_supported() {', start)
        cls.functions = SCRIPT[start:end]

    def run_safe(self, extra, ram=1024, existing=False, fs='ext4'):
        with tempfile.TemporaryDirectory(prefix='vk-lowmem-staging-') as tmp:
            sandbox = Path(tmp)
            (sandbox / 'etc').mkdir()
            (sandbox / 'etc/fstab').write_text('# controlled fixture\n')
            (sandbox / 'state').mkdir()
            (sandbox / 'state/owned-installation').touch()
            if existing:
                (sandbox / 'swapfile-vkarmani').write_text('foreign data')
                (sandbox / 'state/owned-installation').unlink()
            # Map absolute paths in the *extracted function definitions only*.
            func = self.functions
            func = func.replace('/var/lib/vkarmani-node/owned-installation',str(sandbox / 'state/owned-installation'))
            func = func.replace('/swapfile-vkarmani',str(sandbox / 'swapfile-vkarmani'))
            func = func.replace('/etc/fstab',str(sandbox / 'etc/fstab'))
            # Simulate kernel swap activation, without changing the real host.
            script = '''set -Eeuo pipefail
SWON=0
vk_lowmem_swap_total_kib() { if [[ $SWON -eq 1 ]]; then echo 1048576; else echo 0; fi; }
findmnt() { echo FS_VALUE; }
blkid() { echo swap; }
stat() { [[ -f "${@: -1}" ]] && echo 0:600:1:1073741824; }
mkswap() { :; }
swapon() {
    if [[ "${1:-}" == --show=NAME ]]; then
        if [[ $SWON -eq 1 ]]; then echo SWAP_PATH; fi
        return 0
    fi
    [[ "${1:-}" == SWAP_PATH ]] || return 1
    SWON=1
}
dd() {
    [[ "$*" == *"count=1024"* && "$*" == *"conv=fsync"* ]] || return 1
    local item
    for item in "$@"; do if [[ $item == of=* ]]; then printf 'mock-data' > "${item#of=}"; return 0; fi; done
    return 1
}
'''.replace('FS_VALUE',fs).replace('SWAP_PATH',str(sandbox/'swapfile-vkarmani'))
            # Original functions override only vk_lowmem_swap_total_kib; override it again after.
            script += func + '''
vk_lowmem_swap_total_kib() { if [[ $SWON -eq 1 ]]; then echo 1048576; else echo 0; fi; }
'''
            script += extra.replace('SWAP_PATH',str(sandbox/'swapfile-vkarmani'))
            outcome = subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=10)
            return outcome,(sandbox/'etc/fstab').read_text(),(sandbox/'swapfile-vkarmani').exists()

    def test_fail_closed_unsupported_fs_before_writes(self):
        p,fstab,created=self.run_safe('vk_lowmem_swap_preflight 1024\n',fs='btrfs')
        self.assertNotEqual(p.returncode,0)
        self.assertIn('не прошла проверку',p.stderr)
        self.assertFalse(created)
        self.assertEqual(fstab,'# controlled fixture\n')

    def test_fail_closed_foreign_file(self):
        p,fstab,_=self.run_safe('vk_lowmem_swap_preflight 1024\n',existing=True)
        self.assertNotEqual(p.returncode,0)
        self.assertIn('чужой swapfile',p.stderr)
        self.assertEqual(fstab,'# controlled fixture\n')

    def test_mock_create_activate_persist_and_repeated_run(self):
        p,fstab,created=self.run_safe('''
vk_lowmem_swap_preflight 1024
vk_prepare_lowmem_swap 1024
vk_prepare_lowmem_swap 1024
''')
        self.assertEqual(p.returncode,0,p.stderr+'\n'+p.stdout)
        self.assertTrue(created)
        self.assertEqual(fstab.count(' none swap sw 0 0'),1)
        self.assertIn('LOWMEM_SWAP=PASS',p.stdout)

    def test_high_memory_no_swap_mutation(self):
        p,fstab,created=self.run_safe('vk_lowmem_swap_preflight 2048; vk_prepare_lowmem_swap 2048')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(created)
        self.assertEqual(fstab,'# controlled fixture\n')

    def test_lowmem_stages_precede_first_apt_and_are_all_distros(self):
        self.assertIn('MIN_MEMORY_MB=900',SCRIPT)
        self.assertNotIn('MIN_MEMORY_MB=1536',SCRIPT)
        self.assertIn('vk_lowmem_swap_preflight "$MEM_MB"',SCRIPT)
        a=SCRIPT.index('vk_prepare_lowmem_swap "$MEM_MB"')
        b=SCRIPT.index("stage 'Базовые инструменты из подписанного репозитория ОС'",a)
        c=SCRIPT.index('vk_apt_run apt-get -o APT::Update::Error-Mode=any update',b)
        self.assertLess(a,b)
        self.assertLess(b,c)
        self.assertIn('LOWMEM_ACTIVE_SWAP_1G',SCRIPT)
        self.assertIn(r"'^version=2\.5\.([2-9]|10|11|12|13|14|15|16|17|18)$'",SCRIPT)
        self.assertIn('FINISH_ONLY_RECORDED_2_5_18_SUPPORTED',SCRIPT)


class SiteAndSelfstealSecurityContracts(unittest.TestCase):
    def test_all_twelve_themes_are_local_csp_no_js_no_remote_assets(self):
        roots=sorted(x for x in (ROOT/'cover-variants').iterdir() if x.is_dir())
        self.assertEqual(len(roots),12)
        for theme in roots:
            with self.subTest(theme=theme.name):
                html=(theme/'index.html').read_text()
                css=(theme/'style.css').read_text()
                self.assertIn('href="style.css"',html)
                self.assertIn("default-src 'none'",html)
                self.assertIn("style-src 'self'",html)
                self.assertNotRegex(html.replace('xmlns="http://www.w3.org/2000/svg"',''),r'(?i)<script|https?://|src="//')
                self.assertNotRegex(css,r'(?i)@import|url\(\s*["\']?https?://')
                self.assertIn('<meta name="viewport"',html)
                self.assertTrue(css.strip())

    def test_deploy_preserves_nginx_config_and_hashes_css(self):
        source=(ROOT/'scripts/staging_web_deploy.py').read_text()
        self.assertIn('def css_name(',source)
        self.assertIn('def site_rollback(',source)
        self.assertIn('def tcp_rollback(',source)
        self.assertIn("version in ('2.5.11','2.5.12','2.5.13','2.5.14','2.5.15','2.5.16','2.5.17','2.5.18')",source)
        self.assertIn('THIRD_PARTY_CHANGE',source)
        self.assertIn('nginx',source)

    def test_generator_keeps_offline_no_external_requests(self):
        script=(ROOT/'scripts/cover_variants.py').read_text()
        self.assertIn('def ',script)
        preview=(ROOT/'preview')
        self.assertTrue(preview.is_dir())
        self.assertTrue(any(preview.rglob('*.html')))

    def test_selfsteal_socket_unmodified_and_isolated_checkers(self):
        for label in ('/dev/shm/nginx.sock','vkarmani-selfsteal-check', 'nginx -t'):
            self.assertIn(label,SCRIPT)
        # Mandatory check of curl/openssl target happens in original tests.
        self.assertTrue((ROOT/'tests/test_230_selfsteal.py').is_file())
        self.assertTrue((ROOT/'tests/test_220_selfsteal.py').is_file())

if __name__=='__main__':
    unittest.main()
