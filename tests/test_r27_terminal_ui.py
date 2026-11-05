"""R27 terminal UX and protected wizard input tests; never touch a real VPS."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import terminal_ui as ui


class TerminalUITests(unittest.TestCase):
    def test_theme_counts_and_fixed_random(self):
        self.assertEqual(len(ui.THEMES),120)
        self.assertEqual(len(set(ui.THEMES)),120)
        self.assertEqual(ui.choose_random_theme(lambda themes:themes[-1]),ui.THEMES[-1])

    def test_validators(self):
        self.assertEqual(ui.validate_domain('Node.Example.com'),'node.example.com')
        self.assertEqual(ui.validate_panel_ip('8.8.8.8'),'8.8.8.8')
        self.assertEqual(ui.validate_secret('SECRET_KEY='+'A'*64),'A'*64)
        for host in ('https://node.example.com','node.example.com:443','a..b.net','bad_name.net','localhost','192.0.2.2'):
            if host=='192.0.2.2':
                with self.assertRaises(ValueError):ui.validate_panel_ip(host)
            else:
                with self.assertRaises(ValueError):ui.validate_domain(host)
        for ip in ('192.168.1.1','127.0.0.1','169.254.0.1','203.0.113.1','::1'):
            with self.assertRaises(ValueError):ui.validate_panel_ip(ip)
        for secret in ('a'*63,'a'*65537,'a\nb'*40,'a'*64+';'):
            with self.assertRaises(ValueError):ui.validate_secret(secret)

    def test_wizard_args_no_credentials_and_guard_ports(self):
        st=dict(mode='ordinary',site=ui.THEMES[0],reality='local',domain='node.example.com',
                panel_ip='8.8.8.8',node_port=None,no_reboot=True,weekly_reboot=False)
        args=ui.wizard_argv(st,fd=12)
        self.assertIn('--site-theme',args)
        self.assertIn('--no-reboot',args)
        self.assertEqual(args[args.index('--wizard-input-fd')+1],'12')
        self.assertNotIn('SECRET_KEY',repr(args))
        st['site']='made-up'
        with self.assertRaises(ValueError):ui.wizard_argv(st,fd=12)
        st['site']=ui.THEMES[0]
        st['node_port']=61001
        with self.assertRaises(ValueError):ui.wizard_argv(st,fd=12)
        st['node_port']=2222
        self.assertIn('--node-port',ui.wizard_argv(st,fd=12))
        st['mode']='entry';st['bundle']='/root/cascade/role-bundle.json';st['site']=None
        args=ui.wizard_argv(st,fd=12)
        self.assertNotIn('--site-theme',args)
        self.assertNotIn('--node-port',args)
        self.assertIn('--cascade-role',args)

    @unittest.skipUnless(hasattr(os,'memfd_create'),'Linux memfd unavailable')
    def test_private_fd_passed_to_bash_without_argv_secret(self):
        secret='A'*88
        fd=ui.secret_fd(secret,'8.8.8.8','node.example.com')
        try:
            target=os.readlink(f'/proc/self/fd/{fd}')
            self.assertIn('memfd:node-install-input',target)
            cp=subprocess.run(['bash','-c','IFS= read -r -u "$1" a; IFS= read -r -u "$1" b; IFS= read -r -u "$1" c; [[ ${#a} -eq 88 && "$b" == node.example.com && "$c" == 8.8.8.8 ]]',
                         '_',str(fd)],pass_fds=(fd,),capture_output=True,text=True,timeout=3)
            self.assertEqual(cp.returncode,0,cp.stderr)
            self.assertNotIn(secret,repr(cp.args))
            self.assertNotIn(secret,cp.stdout+cp.stderr)
        finally:os.close(fd)

    @unittest.skipUnless(hasattr(os,'memfd_create'),'Linux memfd unavailable')
    def test_actual_bash_wizard_function_reads_memfd(self):
        """Only extract read-only Bash function definitions; never invoke installer."""
        installer=(ROOT/'install.sh').read_text()
        src=installer.split('vk_input_error() {',1)[1].split('# A role is selected before any OS mutation',1)[0]
        defs='vk_input_error() {'+src
        fd=ui.secret_fd('A'*88,'8.8.8.8','node.example.com')
        # Bash receives only the descriptor number, not the secret.
        shell=(defs+'\nETC=/tmp/THIS_PATH_DOES_NOT_EXIST_NODE_INSTALL_TEST\n'
               'VK_WIZARD_INPUT_FD=$1; VK_REALITY_MODE=local;\n'
               'vk_collect_inputs; rc=$?; [[ "$rc" -eq 0 && "${#VK_INPUT_SECRET}" -eq 88 && '
               '"$VK_INPUT_DOMAIN" == node.example.com && "$VK_INPUT_PANEL_IP" == 8.8.8.8 ]]\n')
        try:
            cp=subprocess.run(['bash','-c',shell,'_',str(fd)],pass_fds=(fd,),
                              capture_output=True,text=True,timeout=3)
            self.assertEqual(cp.returncode,0,cp.stderr)
            self.assertIn('WIZARD_INPUT=VALIDATED',cp.stdout)
            self.assertNotIn('A'*64,cp.stdout+cp.stderr)
        finally:
            os.close(fd)

    def test_entrypoint_is_readonly_under_test(self):
        cp=subprocess.run(['bash',str(ROOT/'install.sh'),'--menu','--preview-main'],
                          capture_output=True,text=True,timeout=10)
        self.assertEqual(cp.returncode,0)
        for label in ('ПРОВЕРКА VPS','УСТАНОВКА NODE','ПОЛНОЕ УДАЛЕНИЕ'):
            self.assertIn(label,cp.stdout)
        self.assertEqual(subprocess.run(['bash','-n',str(ROOT/'install.sh')],
                          capture_output=True,timeout=5).returncode,0)

    def test_plain_no_tty_fails_safe(self):
        with mock.patch.object(sys,'stdin',io.StringIO('2\n')):
            self.assertEqual(ui.plain_main(),2)


if __name__=='__main__':unittest.main()
