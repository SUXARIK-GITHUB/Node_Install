"""R7 mock client SOCKS5 DNS packets + safe phase gate; no network to VPS."""
import argparse
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from common import ROOT
sys.path.insert(0,str(ROOT/'scripts'))
import cascade_live_probe as live


class LiveProbeTests(unittest.TestCase):
    def arguments(self,phase='baseline',previous=None,evidence=None):
        return argparse.Namespace(phase=phase,socks_port=10801,exit_ipv4='8.8.8.8',
               https_echo_url='https://api.ipify.org/',udp_resolver_ipv4='1.1.1.1',
               dns_name='example.org',udp_echo_ipv4='9.9.9.9',udp_echo_port=9521,
               previous=previous,outage_reference=evidence)

    def test_success_fail_closed_recovery_and_receipt_chain(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)
            a=self.arguments()
            baseline=live.check(a,tcp=lambda p,u:'8.8.8.8',udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                               auth_probe=lambda p:None)
            self.assertEqual(baseline['status'],'PASS')
            first=d/'baseline.json';live.create_receipt(first,baseline)
            self.assertEqual(first.stat().st_mode&0o077,0)
            b=self.arguments('outage',first,'provider-test-exit-terminated-report')
            def deny(*args):raise live.ProbeError('no egress')
            outage=live.check(b,tcp=deny,udp=deny,echo=deny,auth_probe=lambda p:None)
            self.assertEqual(outage['status'],'PASS')
            second=d/'outage.json';live.create_receipt(second,outage)
            c=self.arguments('recovery',second)
            recovery=live.check(c,tcp=lambda p,u:'8.8.8.8',udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                                auth_probe=lambda p:None)
            self.assertEqual(recovery['status'],'PASS')
            self.assertEqual({baseline['session'],outage['session'],recovery['session']},
                             {baseline['session']})

    def test_outage_never_accepts_other_direct_ip_or_live_dns(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t);a=self.arguments()
            baseline=live.check(a,tcp=lambda p,u:'8.8.8.8',udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                                auth_probe=lambda p:None)
            old=d/'baseline.json';live.create_receipt(old,baseline)
            b=self.arguments('outage',old,'operator-event')
            for ip in ('8.8.8.8','9.9.9.9'):
                with self.subTest(ip=ip):
                    result=live.check(b,tcp=lambda p,u:ip,udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                                      auth_probe=lambda p:None)
                    self.assertEqual(result['status'],'FAIL')
                    self.assertNotIn('PASS',result['claim'])

    def test_bad_chain_or_no_local_client_refuses_to_pass(self):
        a=self.arguments('outage',None,'provider-outage')
        with self.assertRaisesRegex(live.ProbeError,'PREVIOUS'):
            live.check(a,tcp=lambda p,u:'8.8.8.8',udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                       auth_probe=lambda p:None)
        a=self.arguments()
        with self.assertRaisesRegex(live.ProbeError,'CLIENT_NOT_RUNNING'):
            live.check(a,tcp=lambda p,u:'8.8.8.8',udp=lambda p,i,n:True,echo=lambda p,i,n:True,
                       auth_probe=lambda p:(_ for _ in ()).throw(OSError('unavailable')))
        a.https_echo_url='http://localhost:80'
        with self.assertRaisesRegex(live.ProbeError,'HTTPS_ECHO_URL_INVALID'):
            live.check(a,auth_probe=lambda p:None)

    def test_receipt_must_not_overwrite_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t);p=d/'test.json'
            live.create_receipt(p,{'phase':'baseline','status':'PASS'})
            with self.assertRaisesRegex(live.ProbeError,'MUST_BE_NEW'):
                live.create_receipt(p,{})
            q=d/'link.json';q.symlink_to(p)
            with self.assertRaisesRegex(live.ProbeError,'MUST_BE_NEW'):
                live.create_receipt(q,{})

    def test_actual_socks5_generic_udp_echo_reply(self):
        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp.bind(('127.0.0.1',0));tcp.listen(1)
        port=tcp.getsockname()[1]
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1',0));udp.settimeout(4)
        udp_port=udp.getsockname()[1]
        errors=[]
        def peer():
            try:
                conn,_=tcp.accept();conn.settimeout(4)
                with conn:
                    self.assertEqual(live.exact(conn,3),b'\x05\x01\x00')
                    conn.sendall(b'\x05\x00')
                    self.assertEqual(live.exact(conn,10)[:4],b'\x05\x03\x00\x01')
                    conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',udp_port))
                    packet,addr=udp.recvfrom(4096)
                    self.assertEqual(packet[:4],b'\x00\x00\x00\x01')
                    self.assertEqual(packet[4:8],b'\x09\x09\x09\x09')
                    self.assertEqual(struct.unpack('!H',packet[8:10])[0],9521)
                    udp.sendto(packet,addr)
            except BaseException as exc:errors.append(exc)
        th=threading.Thread(target=peer,daemon=True);th.start()
        try:
            self.assertTrue(live.udp_echo(port,'9.9.9.9',9521))
        finally:
            th.join(timeout=5);tcp.close();udp.close()
        self.assertEqual(errors,[])

    def test_dns_requires_genuine_public_a_answer_and_rejects_bad_pointers(self):
        import ipaddress
        query,_=live.dns_query('example.org',23)
        question=query[12:]
        header=struct.pack('!HHHHHH',23,0x8180,1,1,0,0)
        def record(kind,content):
            return b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(content))+content
        a=header+question+record(1,ipaddress.IPv4Address('93.184.216.34').packed)
        self.assertTrue(live.validate_dns_a_answer(a,'example.org'))
        cname=b'\x05alias\x07example\x03org\x00'
        with self.assertRaisesRegex(live.ProbeError,'DNS_NO_PUBLIC_A_RECORD'):
            live.validate_dns_a_answer(header+question+record(5,cname),'example.org')
        with self.assertRaisesRegex(live.ProbeError,'DNS_NO_PUBLIC_A_RECORD'):
            live.validate_dns_a_answer(header+question+record(1,ipaddress.IPv4Address('127.0.0.1').packed),'example.org')
        with self.assertRaisesRegex(live.ProbeError,'INVALID_DNS_NAME_POINTER'):
            live.validate_dns_a_answer(header+question+b'\xc0\xff'+struct.pack('!HHIH',1,1,60,4)+b'\x5d\xb8\xd8\x22','example.org')

    def test_actual_socks5_udp_associate_dns_reply(self):
        """A real local TCP SOCKS5 + UDP relay is exercised; no public DNS contacted."""
        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp.bind(('127.0.0.1',0));tcp.listen(1)
        bind=tcp.getsockname()[1]
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1',0));udp.settimeout(4)
        relay=udp.getsockname()[1]
        issues=[]
        def peer():
            try:
                conn,_=tcp.accept();conn.settimeout(4)
                with conn:
                    self.assertEqual(conn.recv(3),b'\x05\x01\x00')
                    conn.sendall(b'\x05\x00')
                    request=live.exact(conn,10)
                    self.assertEqual(request[:4],b'\x05\x03\x00\x01')
                    conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',relay))
                    datagram,addr=udp.recvfrom(4096)
                    self.assertEqual(datagram[:4],b'\x00\x00\x00\x01')
                    self.assertEqual(datagram[4:8],b'\x01\x01\x01\x01')
                    payload=datagram[10:]
                    self.assertEqual(payload[12:13],b'\x07')
                    response=payload[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+payload[12:]
                    response+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22'
                    wrapper=b'\x00\x00\x00\x01'+datagram[4:10]
                    udp.sendto(wrapper+response,addr)
            except BaseException as e:
                issues.append(e)
        th=threading.Thread(target=peer,daemon=True);th.start()
        try:
            self.assertTrue(live.udp_dns(bind,'1.1.1.1','example.org'))
        finally:
            th.join(timeout=5);tcp.close();udp.close()
        self.assertEqual(issues,[])


if __name__=='__main__':unittest.main()
