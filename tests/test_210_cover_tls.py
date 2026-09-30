"""Generated page over the REAL isolated Nginx TLS+PROXY listener; no public ports."""
import concurrent.futures
from pathlib import Path
import ssl
import unittest
from common import module
import test_tls_integration as fixture

@unittest.skipUnless(fixture.NGINX, 'nginx unavailable: actual cover TLS tests skipped')
class CoverTLSIntegrationTests(unittest.TestCase):
    configure = classmethod(fixture.NginxSelfstealIntegrationTests.configure.__func__)
    start = classmethod(fixture.NginxSelfstealIntegrationTests.start.__func__)
    stop = classmethod(fixture.NginxSelfstealIntegrationTests.stop.__func__)

    @classmethod
    def setUpClass(cls):
        fixture.NginxSelfstealIntegrationTests.setUpClass.__func__(cls)
        cls.cover=module('VK_SITE_TOOL_PY')
        data,cls.assets=cls.cover.render('node.example.test')
        (cls.site/'index.html').write_bytes(data)
        for name,body in cls.assets.items():
            (cls.site/name).parent.mkdir(exist_ok=True)
            (cls.site/name).write_bytes(body)
            (cls.site/name).chmod(0o644)
        # Production distro nginx.conf includes mime.types; mirror that in fixture.
        cls.stop()
        config=cls.root/'nginx.conf'
        config.write_text(config.read_text().replace('http { access_log off;', 'http { types { text/css css; image/svg+xml svg; text/html html; } access_log off;'))
        cls.start()

    def probe(self):
        self.helper.check('node.example.test',path=self.socket_path,
                          site=self.site/'index.html',cafile=self.root/'ca.pem',timeout=4)

    def request(self,path):
        s=self.helper.connect('node.example.test','http/1.1',path=self.socket_path,cafile=self.root/'ca.pem')
        try:
            s.sendall(('GET /'+path+' HTTP/1.1\r\nHost: node.example.test\r\nConnection: close\r\n\r\n').encode())
            chunks=[]
            while True:
                b=s.recv(16384)
                if not b:break
                chunks.append(b)
            return b''.join(chunks).split(b'\r\n\r\n',1)
        finally:s.close()

    def test_generated_cover_h1_h2_and_static_asset_types(self):
        self.probe()
        for path,data in self.assets.items():
            headers,body=self.request(path)
            self.assertIn(b'200 OK',headers);self.assertEqual(body,data)
            self.assertIn(b'text/css' if path.endswith('.css') else b'image/svg+xml',headers)
            self.assertNotIn(b'nginx/1.',headers)

    def test_48_checks_eight_workers_on_generated_page(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _:self.probe(),range(48)))
        self.assertIsNone(self.proc.poll())

    def test_atomic_html_change_and_rollback_need_no_reload(self):
        p=self.site/'index.html';old=p.read_bytes();pid=self.proc.pid
        try:
            self.cover.atomic(p,b'<!doctype html><title>Rollback rehearsal</title>',0o644)
            self.probe()
            self.cover.atomic(p,old,0o644)
            self.probe()
            self.assertEqual(self.proc.pid,pid);self.assertIsNone(self.proc.poll())
        finally:p.write_bytes(old)
