#!/usr/bin/env python3
"""Real PTY tests of the Bash collector and stdin handoff; no host installation."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import termios
import unittest
from test_helper import bundle, encode

ROOT = Path(__file__).resolve().parents[1]
P1 = '[1/3] SECRET_KEY ноды (скрытый ввод): '
P2 = '[2/3] Публичный IPv4 основного сервера (панели): '
P3 = '[3/3] Домен ноды (например, ee1.example.com): '

@unittest.skipUnless(importlib.util.find_spec('pexpect'), 'pexpect not installed')
class TerminalTests(unittest.TestCase):
    def harness(self, folder):
        folder=Path(folder)
        code=("import sys; from pathlib import Path; "
              f"sys.path.insert(0, {str(ROOT/'build')!r}); import node_helper as h; "
              f"h.ETC=Path({str(folder/'etc')!r}); h.detect_public_ipv4=lambda:'8.8.4.4'; "
              "h.dns_check=lambda c:None; h.init_config()")
        runner=folder/'runner.py';runner.write_text(code)
        script=folder/'harness.sh'
        script.write_text('set -Eeuo pipefail\n'+
            'ETC='+shlex.quote(str(folder/'etc'))+'\n'+
            '. '+shlex.quote(str(ROOT/'build/collect-input.sh'))+'\n'+
            'vk_collect_inputs\n'+
            'printf "AUTOMATION_START\\n"\n'+
            'printf "%s\\n%s\\n%s\\n" "$VK_INPUT_SECRET" "$VK_INPUT_PANEL_IPV4" "$VK_INPUT_DOMAIN" | '+
            shlex.quote(sys.executable)+' '+shlex.quote(str(runner))+'\n')
        return script

    def run_flow(self, long=False, assignment=False):
        import pexpect
        data=bundle()
        if long: data['testPadding']='z'*12000  # accepted unknown payload field, synthetic only
        secret=encode(data)
        with tempfile.TemporaryDirectory(prefix='vkarmani-tty-') as temp:
            script=self.harness(temp)
            child=pexpect.spawn('bash',[str(script)],encoding='utf-8',timeout=12)
            output=''
            child.expect_exact(P1);output+=child.before+child.after
            self.assertTrue(child.waitnoecho(timeout=2))
            self.assertNotIn('AUTOMATION_START',output)
            # Raw/noncanonical input avoids the terminal's canonical 4096-byte ceiling.
            child.sendline('SECRET_KEY="'+secret+'"' if assignment else secret)
            child.expect_exact(P2);output+=child.before+child.after
            child.sendline('1.1.1.1')
            child.expect_exact(P3);output+=child.before+child.after
            self.assertNotIn('AUTOMATION_START',output)
            child.sendline(' EE1.EXAMPLE.COM. ')
            child.expect(pexpect.EOF);output+=child.before
            child.close()
            self.assertEqual(child.exitstatus,0,output[-2000:])
            self.assertNotIn(secret,output)
            self.assertIn('AUTOMATION_START',output)
            etc=Path(temp)/'etc'
            saved=(etc/'remnanode.env').read_text()
            self.assertIn('SECRET_KEY='+secret,saved)
            self.assertEqual((etc/'remnanode.env').stat().st_mode&0o777,0o600)
            cfg=json.loads((etc/'config.json').read_text())
            self.assertEqual(cfg['panel_ipv4'],['1.1.1.1'])
            self.assertEqual(cfg['domain'],'ee1.example.com')
            # Noninteractive resume: no /dev/tty is required, no questions on stdin.
            import subprocess
            done=subprocess.run(['bash',str(script)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertTrue(all(p not in done.stdout for p in (P1,P2,P3)))
            self.assertNotIn(secret,done.stdout+done.stderr)
            self.assertEqual((etc/'remnanode.env').read_text(),saved)

    def test_three_prompts_hidden_secret_and_resume(self):self.run_flow()
    def test_long_secret_not_truncated(self):self.run_flow(long=True)
    def test_assignment_quoted_secret(self):self.run_flow(assignment=True)

    def test_invalid_ip_aborts_before_automation(self):
        import pexpect
        with tempfile.TemporaryDirectory() as temp:
            child=pexpect.spawn('bash',[str(self.harness(temp))],encoding='utf-8',timeout=10)
            child.expect_exact(P1);child.sendline(encode(bundle()))
            child.expect_exact(P2);child.sendline('10.0.0.1')
            child.expect(pexpect.EOF);output=child.before;child.close()
            self.assertNotEqual(child.exitstatus,0)
            self.assertNotIn('AUTOMATION_START',output)
            self.assertNotIn(P3,output)

    def test_ctrl_c_restores_echo(self):
        import pexpect
        with tempfile.TemporaryDirectory() as temp:
            script=self.harness(temp)
            child=pexpect.spawn('bash',['-c','bash '+shlex.quote(str(script))+'; stty -a; echo DONE'],encoding='utf-8',timeout=10)
            child.expect_exact(P1)
            self.assertTrue(child.waitnoecho(timeout=2))
            child.sendcontrol('c')
            child.expect_exact('DONE')
            settings=child.before
            child.expect(pexpect.EOF);child.close()
            self.assertNotIn(' -echo ',settings)
            self.assertNotIn(' -icanon ',settings)

if __name__ == '__main__':unittest.main()
