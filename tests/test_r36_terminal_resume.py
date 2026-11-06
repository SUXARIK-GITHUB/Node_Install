"""r36 regression: recover SSH curses screens after terminal is hidden/resized.

Tests are offline; no host services, installer actions, DNS, or secrets used.
"""
import curses
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import fcntl
import pty
import unittest
from unittest import mock

from common import ROOT
sys.path.insert(0, str(ROOT/'scripts'))
import terminal_ui as tui
from test_r29_tui_full_vps import FakeWindow


class TimedFakeWindow(FakeWindow):
    def __init__(self, keys=(), *, width=92, height=30):
        super().__init__(keys,width,height)
        self.timeouts=[]
        self.redraws=0
        self.full_clears=[]
        self.modes=[]
    def timeout(self,value):self.timeouts.append(value)
    def nodelay(self,value):self.modes.append(value)
    def redrawwin(self):self.redraws+=1
    def clearok(self,value):self.full_clears.append(value)
    def get_wch(self):
        key=self.getch()
        if key==-1:raise curses.error('timed input')
        return chr(key) if 0<=key<256 else key


class ScreenRecovery(unittest.TestCase):
    def terminal(self,window):
        with mock.patch.object(tui.curses,'has_colors',return_value=False),\
             mock.patch.object(tui.curses,'curs_set'):
            return tui.Terminal(window)

    def test_static_main_menu_resends_full_frame_after_30_second_idle(self):
        window=TimedFakeWindow([-1,ord('0')])
        ui=self.terminal(window)
        ui._last_resync=-100.0
        with mock.patch.object(tui.time,'monotonic',return_value=100.0),\
             mock.patch.object(tui.curses,'doupdate') as update:
            self.assertIsNone(ui.menu('ГЛАВНОЕ МЕНЮ',[('ПРОВЕРКА VPS','авто')]));
        self.assertEqual(window.timeouts,[tui.SCREEN_POLL_MS])
        self.assertEqual(window.redraws,1)
        self.assertEqual(update.call_count,2)  # first render + lost-buffer repair
        self.assertTrue(any('ПРОВЕРКА VPS' in row[2] for row in window.contents))

    def test_ctrl_l_force_clears_screen_without_selecting_menu_option(self):
        window=TimedFakeWindow([12,ord('0')])
        ui=self.terminal(window)
        with mock.patch.object(tui.curses,'doupdate'):
            self.assertIsNone(ui.menu('МЕНЮ',[('Действие','не запущено')]));
        self.assertEqual(window.full_clears,[True]);self.assertEqual(window.redraws,0)

    def test_screen_resize_reflows_menu_and_preserves_selected_option(self):
        window=TimedFakeWindow([curses.KEY_DOWN,curses.KEY_RESIZE,13])
        ui=self.terminal(window)
        with mock.patch.object(tui.curses,'doupdate'):
            self.assertEqual(ui.menu('ТЕСТ',[('ПЕРВЫЙ','a'),('ВТОРОЙ','b')]),1)
        self.assertEqual(window.full_clears,[True])
        self.assertEqual(window.updates,3)

    def test_wide_input_timeout_and_resize_keep_existing_input(self):
        window=TimedFakeWindow([ord('a'),-1,curses.KEY_RESIZE,ord('b'),13])
        ui=self.terminal(window)
        ui._last_resync=-100
        with mock.patch.object(tui.time,'monotonic',return_value=100.0),\
             mock.patch.object(tui.curses,'doupdate'):
            self.assertEqual(ui.field('Домен','FQDN',initial='node.'),'node.ab')
        self.assertGreaterEqual(window.redraws,1)
        self.assertEqual(window.full_clears,[True])

    def test_nonblocking_log_poll_and_timeout_restoration(self):
        window=TimedFakeWindow([-1])
        ui=self.terminal(window)
        with mock.patch.object(tui.curses,'doupdate'):
            ui._last_resync=time.monotonic()-tui.SCREEN_RESYNC_SECONDS-1
            self.assertEqual(ui._read_key(wait=False),-1)
            self.assertEqual(window.redraws,1)
            self.assertEqual(ui._read_key(wait=False),-1)
            ui._restore_input_timeout()
        self.assertEqual(window.modes, [False])
        self.assertEqual(window.timeouts,[tui.SCREEN_POLL_MS,tui.SCREEN_POLL_MS])


class RealPTYRecovery(unittest.TestCase):
    """Exercise real ncurses output, not just a FakeWindow call counter."""
    @unittest.skipUnless(os.name=='posix' and hasattr(termios,'TIOCSWINSZ'), 'POSIX PTY required')
    def test_real_pty_idle_redraw_resize_ctrl_l_and_shell_exit(self):
        master,slave=pty.openpty()
        try:
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,105,0,0))
            script=("import sys;sys.path.insert(0,%r);import terminal_ui as ui;"
                    "ui.SCREEN_RESYNC_SECONDS=.45;raise SystemExit(ui.main())" % str(ROOT/'scripts'))
            env={**os.environ,'TERM':'xterm-256color','LANG':'C.UTF-8'}
            proc=subprocess.Popen([sys.executable,'-c',script],stdin=slave,stdout=slave,stderr=slave,
                                  env=env,cwd=ROOT,start_new_session=True)
            os.close(slave);slave=-1
            def receive(seconds):
                until=time.monotonic()+seconds
                result=bytearray()
                while time.monotonic()<until:
                    ready,_,_=select.select([master],[],[],min(.08,max(0,until-time.monotonic())))
                    if ready:
                        try:chunk=os.read(master,65536)
                        except OSError:break
                        if not chunk:break
                        result.extend(chunk)
                return bytes(result)
            try:
                first=receive(2.2)
                self.assertIn(b'NODE INSTALL',first)
                idle=receive(1.8)
                self.assertIn(b'NODE INSTALL',idle,'no re-render during idle')
                os.write(master,b'\x0c')
                manual=receive(.4)
                self.assertIn(b'NODE INSTALL',manual)
                fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack('HHHH',33,95,0,0))
                os.kill(proc.pid,signal.SIGWINCH)
                resized=receive(.65)
                self.assertIn(b'NODE INSTALL',resized)
                os.write(master,b'q')
                self.assertEqual(proc.wait(timeout=5),0)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
        finally:
            if slave>=0:os.close(slave)
            os.close(master)

    @unittest.skipUnless(os.name=='posix' and hasattr(termios,'TIOCSWINSZ'), 'POSIX PTY required')
    def test_progress_output_survives_idle_redraw_without_restarting_process(self):
        master,slave=pty.openpty()
        try:
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',29,105,0,0))
            script=("import sys;sys.path.insert(0,%r);import terminal_ui as ui;"
                    "ui.SCREEN_RESYNC_SECONDS=.45;"
                    "app=lambda w:ui.Terminal(w).logs('ПРОВЕРКА ЖУРНАЛА',"
                    "[sys.executable,'-u','-c',%r]);"
                    "raise SystemExit(ui.curses.wrapper(app))" % (
                        str(ROOT/'scripts'),
                        "import time;print('STEP_ONE');time.sleep(.9);print('STEP_TWO')"))
            proc=subprocess.Popen([sys.executable,'-c',script],stdin=slave,stdout=slave,stderr=slave,
                                  env={**os.environ,'TERM':'xterm-256color','LANG':'C.UTF-8'},
                                  cwd=ROOT,start_new_session=True)
            os.close(slave);slave=-1
            def recv(seconds):
                until=time.monotonic()+seconds;result=bytearray()
                while time.monotonic()<until:
                    ready,_,_=select.select([master],[],[],min(.08,max(0,until-time.monotonic())))
                    if ready:
                        try:chunk=os.read(master,65536)
                        except OSError:break
                        if not chunk:break
                        result.extend(chunk)
                return bytes(result)
            try:
                out=recv(3.2)
                self.assertIn(b'STEP_ONE',out)
                self.assertIn(b'STEP_TWO',out)
                self.assertGreaterEqual(out.count(b'STEP_ONE'),2,'watchdog did not re-send existing log')
                os.write(master,b'\x1b')  # Esc only after child completion
                self.assertEqual(proc.wait(timeout=5),0)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
        finally:
            if slave>=0:os.close(slave)
            os.close(master)


if __name__=='__main__':unittest.main()
