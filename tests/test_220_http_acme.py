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
                  .replace('$DOMAIN','node.example.test')
                  .replace('$NGINX_HTTP_ROOT_ACTION','return 301 https://node.example.test\\$request_uri;')
                  .replace('\\$','$')
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

    def test_hybrid_mode_redirects_to_own_https_and_acme_still_works(self):
        # Isolated second process checks the new external-SNI HTTP policy.
        with tempfile.TemporaryDirectory(prefix='vk-http-remote-') as tmp:
            base = Path(tmp); base.chmod(0o755)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            acme = base / 'acme'; challenge = acme / '.well-known/acme-challenge'
            challenge.mkdir(parents=True)
            (challenge / 'test-token').write_text('REMOTE_MODE_ACME')
            (challenge / 'test-token').chmod(0o644)
            fragment = (template('/etc/nginx/conf.d/10-vkarmani-http.conf')
                        .replace('$PUBLIC_IP:80', f'127.0.0.1:{port}')
                        .replace('$DOMAIN', 'node.example.test')
                        .replace('$NGINX_HTTP_ROOT_ACTION', r'return 301 https://node.example.test\$request_uri;')
                        .replace('\\$', '$')
                        .replace('/var/www/vkarmani-node/acme', str(acme)))
            (base / 'temp').mkdir()
            temporary = ''.join(f'{d}_temp_path {base}/temp/{d};' for d in
                                 ('client_body','proxy','fastcgi','uwsgi','scgi'))
            conf = (f'daemon off; master_process off; pid {base}/pid; '
                    f'error_log {base}/error; events {{worker_connections 64;}} '
                    f'http {{{temporary}{fragment}}}')
            config = base / 'nginx.conf'; config.write_text(conf)
            args = [fixture.NGINX, '-p', str(base)+'/', '-c', str(config)]
            check = subprocess.run([fixture.NGINX, '-t']+args[1:],
                                   capture_output=True, text=True, timeout=5)
            self.assertEqual(check.returncode, 0, check.stderr)
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    self.assertIsNone(proc.poll(), 'private remote-mode Nginx exited')
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    self.fail('private remote-mode Nginx not ready')
                for path, code in [('/', 301), ('/test?q=1', 301),
                                   ('/.well-known/acme-challenge/test-token', 200)]:
                    client = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                    try:
                        client.request('GET', path, headers={'Host': 'node.example.test'})
                        response = client.getresponse()
                        self.assertEqual(response.status, code, path)
                        headers = dict(response.getheaders())
                        if code == 301:
                            self.assertEqual(headers.get('Location'),
                                             'https://node.example.test' + path)
                        else:
                            self.assertNotIn('Location', headers)
                            self.assertEqual(response.read(), b'REMOTE_MODE_ACME')
                    finally:
                        client.close()
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=3)

    def test_post_rejected_without_change(self):
        self.assertEqual(self.request('/.well-known/acme-challenge/test-token',method='POST')[0],405)
        self.assertEqual((self.challenge/'test-token').read_text(),'OWN_TOKEN_RESPONSE')
