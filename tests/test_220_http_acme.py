"""Actual IPv4 loopback Nginx HTTP-01 and redirect isolation. No public/ACME calls."""
import http.client
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from common import template
import test_tls_integration as fixture


@unittest.skipUnless(fixture.NGINX, 'Nginx unavailable: HTTP/ACME integration not verified')
class HttpAcme220Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='vk-http-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.root.chmod(0o755)
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1]
        cls.acme=cls.root/'acme';cls.challenge=cls.acme/'.well-known/acme-challenge'
        cls.challenge.mkdir(parents=True)
        (cls.challenge/'test-token').write_text('OWN_TOKEN_RESPONSE')
        (cls.challenge/'test-token').chmod(0o644)
        fragment=(template('/etc/nginx/conf.d/10-vkarmani-http.conf')
                  .replace('$PUBLIC_IP:80',f'127.0.0.1:{cls.port}')
                  .replace('$DOMAIN','node.example.test').replace('\\$','$')
                  .replace('/var/www/vkarmani-node/acme',str(cls.acme)))
        (cls.root/'temp').mkdir()
        temporary=''.join(f'{d}_temp_path {cls.root}/temp/{d};' for d in
                          ('client_body','proxy','fastcgi','uwsgi','scgi'))
        conf=f'daemon off; master_process off; pid {cls.root}/pid; error_log {cls.root}/error; events {{worker_connections 64;}} http {{{temporary}{fragment}}}'
        (cls.root/'nginx.conf').write_text(conf)
        subprocess.run([fixture.NGINX,'-t','-p',str(cls.root)+'/', '-c',str(cls.root/'nginx.conf')],capture_output=True,check=True,timeout=5)
        cls.proc=subprocess.Popen([fixture.NGINX,'-p',str(cls.root)+'/', '-c',str(cls.root/'nginx.conf')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls.stop)
        for _ in range(100):
            if cls.proc.poll() is not None:raise AssertionError('private HTTP Nginx failed')
            try:
                with socket.create_connection(('127.0.0.1',cls.port),.1):break
            except OSError:time.sleep(.02)
        else:raise AssertionError('private HTTP readiness timeout')

    @classmethod
    def stop(cls):
        cls.proc.terminate()
        try:cls.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:cls.proc.kill();cls.proc.wait(timeout=3)

    def request(self,path='/',host='node.example.test',method='GET'):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        try:
            c.request(method,path,headers={'Host':host})
            r=c.getresponse();return r.status,dict(r.getheaders()),r.read(65536)
        finally:c.close()

    def test_fixed_https_redirect_keeps_path_and_query(self):
        status,h,_=self.request('/about?x=1')
        self.assertEqual(status,301)
        self.assertEqual(h['Location'],'https://node.example.test/about?x=1')

    def test_wrong_host_no_canonical_domain_disclosure(self):
        status,h,b=self.request(host='wrong.invalid')
        self.assertEqual(status,404)
        self.assertNotIn('Location',h)
        self.assertNotIn(b'node.example.test',b)

    def test_acme_token_and_head_work(self):
        for method in ('GET','HEAD'):
            status,h,b=self.request('/.well-known/acme-challenge/test-token',method=method)
            self.assertEqual(status,200)
            self.assertEqual(h['Content-Type'],'text/plain')
            self.assertEqual(b,b'OWN_TOKEN_RESPONSE' if method=='GET' else b'')

    def test_acme_missing_is_404_without_redirect(self):
        status,h,_=self.request('/.well-known/acme-challenge/missing')
        self.assertEqual(status,404);self.assertNotIn('Location',h)

    def test_acme_symlink_not_served(self):
        target=self.root/'private';target.write_text('PRIVATE_CANARY');target.chmod(0o644)
        link=self.challenge/'unsafe';link.symlink_to(target)
        try:
            status,_,body=self.request('/.well-known/acme-challenge/unsafe')
            self.assertEqual(status,404);self.assertNotIn(b'PRIVATE_CANARY',body)
        finally:link.unlink()

    def test_post_rejected_without_change(self):
        self.assertEqual(self.request('/.well-known/acme-challenge/test-token',method='POST')[0],405)
        self.assertEqual((self.challenge/'test-token').read_text(),'OWN_TOKEN_RESPONSE')
