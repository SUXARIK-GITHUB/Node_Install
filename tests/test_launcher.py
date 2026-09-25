#!/usr/bin/env python3
"""Local HTTP serving verifies bash <(curl ...) without root/system changes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(shutil.which('curl'), 'curl required')
class LauncherTests(unittest.TestCase):
    def request(self, payload, args='--help'):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(payload)
            def log_message(self,*a):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            return subprocess.run(['bash','-c',f'bash <(curl -fsSL http://127.0.0.1:{server.server_port}/install.sh) {args}'],
                                  capture_output=True,text=True,timeout=15)
        finally:server.shutdown();thread.join();server.server_close()
    def test_http_process_substitution_help(self):
        r=self.request((ROOT/'install.sh').read_bytes())
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('1.2.0',r.stdout)
        self.assertIn('Три вопроса',r.stdout)
        self.assertNotIn('[1/3]',r.stdout)
    def test_truncated_stream_never_enters_install(self):
        data=(ROOT/'install.sh').read_bytes()
        for size in (10000,len(data)//2,len(data)-150):
            with self.subTest(size=size):
                r=self.request(data[:size])
                self.assertNotEqual(r.returncode,0)
                self.assertNotIn('VKarmani Remnawave Node Installer',r.stdout)
                self.assertNotIn('[1/3]',r.stdout)
                self.assertNotIn('INSTALL_FAILED',r.stdout)
    def test_unknown_option_fails_without_install(self):
        r=self.request((ROOT/'install.sh').read_bytes(),'--not-a-real-option')
        self.assertEqual(r.returncode,2)
        self.assertNotIn('[1/3]',r.stdout)

if __name__=='__main__':unittest.main()
