"""R31 second-phase acceptance: terminal UI, private live logs, safe key picker.

Tests operate in temporary directories with fake terminals; they never invoke
real installer mutations, contact the panel or send an actual clipboard command.
"""
import base64
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import terminal_ui as tui
from test_r29_tui_full_vps import FakeWindow


SAMPLE=(
    '============================================================\n'
    'REALITY KEYS — VKarmani RemnaNode 2.5.18\n'
    '============================================================\n'
    'Domain: node.example.com\n'
    'PrivateKey: TEST_PRIVATE_VALUE_NOT_AN_ACTUAL_KEY\n'
    'PublicKey: TEST_PUBLIC_VALUE\n'
    'ShortID: aabbcc\n'
    'Reality mode: local\n'
    'Reality target: /dev/shm/nginx.sock\n'
    'xver: 1\n'
    'flow: xtls-rprx-vision\n'
    'minClientVer: 0.0.0\n'
    'serverName/SNI: node.example.com\n'
)


def terminal(window=None):
    with mock.patch.object(tui.curses,'has_colors',return_value=False), \
         mock.patch.object(tui.curses,'curs_set'):
        return tui.Terminal(window or FakeWindow())


class PhaseTwoUI(unittest.TestCase):
    def test_main_menu_has_explicit_exit_without_running_command(self):
        instance=terminal()
        items=[]
        def chosen(title,rows,*a,**kwargs):
            items.extend(rows)
            return len(rows)-1
        instance.menu=chosen
        instance.action=lambda *a:self.fail('exit must not execute a system command')
        self.assertEqual(instance.run(),0)
        self.assertEqual(items[-1][0],'ВЫЙТИ ИЗ УСТАНОВЩИКА')
        self.assertIn('SSH',items[-1][1])
        cp=subprocess.run([sys.executable,str(ROOT/'scripts/terminal_ui.py'),'--preview-main'],
                          text=True,capture_output=True,timeout=5)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertIn('ВЫЙТИ ИЗ УСТАНОВЩИКА',cp.stdout)

    def test_layout_fits_normal_and_small_terminals_without_border_overwrite(self):
        for width,height in ((55,17),(58,22),(80,24),(85,29),(132,39)):
            with self.subTest(width=width,height=height):
                window=FakeWindow([27],width=width,height=height)
                instance=terminal(window)
                with mock.patch.object(tui.curses,'doupdate'):
                    self.assertIsNone(instance.menu('ГЛАВНОЕ МЕНЮ',[
                        ('ПРОВЕРКА VPS',''+'а'*250),('УСТАНОВКА NODE','Создание новой ноды')]))
                content=' '.join(x[2] for x in window.contents)
                self.assertIn('NODE INSTALL',content)
                self.assertIn('ГЛАВНОЕ МЕНЮ',content)
                for y,x,value in window.contents:
                    self.assertGreaterEqual(y,0)
                    self.assertLess(y,height)
                    self.assertGreaterEqual(x,0)
                    self.assertLess(x+sum(2 if unicodedata.east_asian_width(c) in ('F','W') else 1 for c in value),width)
                self.assertEqual(window.updates,1)

    def test_log_file_is_private_unique_and_not_truncated_between_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);directory.chmod(0o700)
            names=[]
            for _ in range(2):
                fd,path=tui.new_install_log(directory)
                try:
                    os.write(fd,b'START\n');os.fsync(fd)
                finally:os.close(fd)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                self.assertEqual(path.stat().st_uid,os.geteuid())
                self.assertEqual(path.read_bytes(),b'START\n')
                names.append(path.name)
            self.assertNotEqual(*names)
            self.assertEqual(len(list(directory.glob('node-install-*.log'))),2)

    def test_log_symlink_insecure_directory_and_oversize_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp);d.chmod(0o700)
            protected=d/'keys';protected.write_text('do-not-touch')
            stamp=tui.time.strftime('%Y%m%d-%H%M%S',tui.time.localtime())
            (d/f'node-install-{stamp}-{os.getpid()}-00.log').symlink_to(protected)
            fd,path=tui.new_install_log(d)
            os.close(fd)
            self.assertEqual(protected.read_text(),'do-not-touch')
            self.assertTrue(path.name.endswith('-01.log'))
            d.chmod(0o755)
            with self.assertRaisesRegex(OSError,'UNSAFE_LOG_DIRECTORY'):
                tui.new_install_log(d)
            d.chmod(0o700)
            fd,_=tui.new_install_log(d)
            sink=tui.InstallLogSink(fd)
            with mock.patch.object(tui,'MAX_INSTALL_LOG_BYTES',20):
                sink.write('x'*50)
                self.assertTrue(sink.truncated)
            sink.close()

    def test_disk_log_streams_live_redacted_output_and_return_code(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);path.chmod(0o700)
            fake=FakeWindow([27]*50,width=82,height=29)
            ui=terminal(fake)
            script=('import sys,time; '
                    'print("Get:1 started",flush=True); '
                    'time.sleep(0.05); '
                    'print("PrivateKey: NEVER_WRITE_THIS_SECRET",flush=True); '
                    'print("EXIT_CODE=20",flush=True)')
            make_log=tui.new_install_log
            with mock.patch.object(tui,'new_install_log',side_effect=lambda:make_log(path)), \
                 mock.patch.object(tui.curses,'doupdate'):
                rc=ui.logs('УСТАНОВКА', [sys.executable,'-c',script],persist_install=True)
            self.assertEqual(rc,0)
            self.assertIsNotNone(ui.install_log_path)
            data=ui.install_log_path.read_text()
            self.assertIn('Get:1 started',data)
            self.assertIn('PrivateKey: [REDACTED]',data)
            self.assertNotIn('NEVER_WRITE_THIS_SECRET',data)
            self.assertIn('NODE_INSTALL_LOG=END exit_code=0',data)
            self.assertEqual(stat.S_IMODE(ui.install_log_path.stat().st_mode),0o600)
            self.assertIsNone(ui.install_log_error)

    def test_unwritable_root_dir_stops_before_installer_process(self):
        ui=terminal()
        seen=[]
        ui.message=lambda *a,**kwargs:seen.append(a[0])
        with mock.patch.object(tui,'new_install_log',side_effect=PermissionError('no /root')), \
             mock.patch.object(tui.subprocess,'Popen',side_effect=AssertionError('MUST NOT START')):
            self.assertEqual(ui.logs('INSTALL',[sys.executable,'-c','print(1)'],persist_install=True),2)
        self.assertEqual(seen,['ЖУРНАЛ НЕ СОЗДАН'])

    def test_reality_export_reader_checks_owner_mode_symlink_hardlink_and_format(self):
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp)
            p=d/'reality-keys.txt';p.write_text(SAMPLE);p.chmod(0o600)
            headers,items=tui.read_reality_items(p,owner_uid=os.geteuid())
            self.assertEqual(len(headers),3)
            self.assertEqual(items[0][:2],('Domain','node.example.com'))
            self.assertEqual(items[1],('PrivateKey','TEST_PRIVATE_VALUE_NOT_AN_ACTUAL_KEY',True))
            self.assertEqual(items[-1][0],'serverName/SNI')
            symlink=d/'link';symlink.symlink_to(p)
            with self.assertRaises(OSError):tui.read_reality_items(symlink,owner_uid=os.geteuid())
            p.chmod(0o644)
            with self.assertRaises(OSError):tui.read_reality_items(p,owner_uid=os.geteuid())
            p.chmod(0o600)
            hard=d/'hard';os.link(p,hard)
            with self.assertRaises(OSError):tui.read_reality_items(p,owner_uid=os.geteuid())
            hard.unlink()
            p.write_bytes(b'PrivateKey: BAD\x1b[31m\n')
            with self.assertRaises(ValueError):tui.read_reality_items(p,owner_uid=os.geteuid())

    def test_key_picker_masked_by_default_and_revealed_only_after_v(self):
        private='TEST_PRIVATE_VALUE_NOT_AN_ACTUAL_KEY'
        window=FakeWindow([tui.curses.KEY_DOWN,13,ord('v'),27],width=90,height=29)
        ui=terminal(window)
        with mock.patch.object(tui,'has_root',return_value=True), \
             mock.patch.object(tui,'read_reality_items',return_value=(["REALITY KEYS"],[
                   ('Domain','node.example.com',False),('PrivateKey',private,True)])), \
             mock.patch.object(tui,'copy_to_terminal_clipboard',return_value=True) as copy, \
             mock.patch.object(tui.curses,'doupdate'):
            ui.keys_screen()
        copy.assert_called_once_with(private)
        values=' '.join(x[2] for x in window.contents)
        self.assertIn('[СКРЫТО]',values)
        self.assertIn(private,values)
        self.assertIn('OSC 52',values)

    def test_clipboard_request_is_osc52_and_never_stdout_log(self):
        read_fd,write_fd=os.pipe()
        try:
            with mock.patch.object(tui.os,'open',return_value=write_fd):
                self.assertTrue(tui.copy_to_terminal_clipboard('PUBLIC_TEST'))
            data=os.read(read_fd,4096)
            self.assertEqual(data,b'\x1b]52;c;'+base64.b64encode(b'PUBLIC_TEST')+b'\x07')
        finally:os.close(read_fd)
        with mock.patch.object(tui.os,'open',side_effect=OSError('not supported')):
            self.assertFalse(tui.copy_to_terminal_clipboard('PUBLIC_TEST'))
        for val in ('bad\nkey','\x1b]52;', 'x'*5000):
            with self.assertRaises(ValueError):tui.copy_to_terminal_clipboard(val)

    def test_tui_installer_never_cat_keys_over_the_curses_screen(self):
        shell=(ROOT/'install.sh').read_text(encoding='utf-8')
        self.assertIn('if [[ "${VK_NODE_TUI:-0}" == 1 ]]; then',shell)
        self.assertIn('REALITY_KEYS_DISPLAY=FILE_ONLY',shell)
        self.assertIn("'VK_NODE_TUI':'1'",(ROOT/'scripts/terminal_ui.py').read_text())


if __name__=='__main__':unittest.main()
