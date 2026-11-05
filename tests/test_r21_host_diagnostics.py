"""R21 read-only diagnostics do not disclose configuration secrets or change OS."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from common import ROOT, SCRIPT
sys.path.insert(0,str(ROOT/'integrations'))
import network_health as network
import selfsteal_health as selfsteal


class HostDiagnostics(unittest.TestCase):
    def test_selfsteal_embedded_source_matches_maintained_module(self):
        source=(ROOT/'integrations/selfsteal_health.py').read_text()
        self.assertIn("<<'VK_SELFSTEAL_HEALTH_PY'\n"+source+'VK_SELFSTEAL_HEALTH_PY',SCRIPT)
        self.assertIn('--diagnose-selfsteal) shift; vkarmani_selfsteal_health_main "$@"',SCRIPT)
        out=subprocess.run(['bash',str(ROOT/'install.sh'),'--diagnose-selfsteal'],
                           capture_output=True,text=True,timeout=12)
        self.assertEqual(out.returncode,0,out.stderr)
        report=json.loads(out.stdout)
        self.assertEqual(report['actions_performed'],'NONE')
        self.assertEqual(report['status'],'REVIEW')  # no installed node in CI
        self.assertNotIn('SECRET_KEY',out.stdout)

    def test_selfsteal_private_data_never_printed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'etc/vkarmani-node').mkdir(parents=True)
            (root/'etc/nginx/conf.d').mkdir(parents=True)
            (root/'run/vkarmani-selfsteal').mkdir(parents=True)
            (root/'var/www/vkarmani-node/site').mkdir(parents=True)
            private='a-private-secret-PANEL_KEY_DO_NOT_LOG'
            (root/'etc/vkarmani-node/config.json').write_text(json.dumps({
                'installation_mode':'secret-key-only','reality_mode':'local',
                'secret':private,'domain':'private.example.test','public_ipv4':'203.0.113.44'}))
            (root/'etc/nginx/conf.d/20-vkarmani-selfsteal.conf').write_text(
                'listen unix:/run/vkarmani-selfsteal/nginx.sock ssl proxy_protocol;\n'
                'root /var/www/vkarmani-node/site;\n'
                'location / { return 404; }\n'
                'ssl_certificate /etc/letsencrypt/live/private.example.test/fullchain.pem;\n')
            (root/'var/www/vkarmani-node/site/index.html').write_text('<html>site</html>')
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                sock.bind(str(root/'run/vkarmani-selfsteal/nginx.sock'))
                obj=selfsteal.snapshot(root)
            finally:sock.close()
            data=json.dumps(obj)
            self.assertEqual(obj['mode'],'local')
            self.assertEqual(obj['sockets']['nginx.sock'],'socket')
            self.assertTrue(obj['checks']['expected_socket_listener'])
            self.assertTrue(obj['checks']['ssl_certificate_configured'])
            for term in (private,'203.0.113.44','private.example.test','fullchain.pem'):
                self.assertNotIn(term,data)
            self.assertEqual(obj['actions_performed'],'NONE')
            self.assertEqual(obj['status'],'REVIEW')  # fake folder isn't root:www-data 0750

    def test_static_mode_distinguishes_hybrid_cover_socket_and_wrong_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'etc/vkarmani-node').mkdir(parents=True)
            (root/'etc/vkarmani-node/config.json').write_text(json.dumps({'reality_mode':'max.ru'}))
            report=selfsteal.snapshot(root)
            self.assertEqual(report['mode'],'hybrid')
            self.assertIn('cover.sock',report['sockets'])
            self.assertIn('REQUIRED_COVER_SOCK_MISSING',report['observations'])
            (root/'etc/vkarmani-node/config.json').write_text(json.dumps({'reality_mode':'bogus'}))
            report=selfsteal.snapshot(root)
            self.assertIn('UNKNOWN_REALITY_MODE',report['observations'])

    def test_tcp_netstat_and_sockstat_are_strictly_aggregated(self):
        net='TcpExt: ListenOverflows ListenDrops TCPTimeouts Unrelated\nTcpExt: 3 4 11 123\n'
        out=network._proc_columns(net,'TcpExt',network.TCP_COUNTERS)
        self.assertEqual(out['counters']['ListenOverflows'],3)
        self.assertEqual(out['counters']['ListenDrops'],4)
        self.assertNotIn('Unrelated',out['counters'])
        self.assertFalse(network._proc_columns('TcpExt: broken\nTcpExt: no','TcpExt',network.TCP_COUNTERS)['verified'])
        socket_lines='sockets: used 89\nTCP: inuse 12 orphan 0 tw 10 alloc 15 mem 3\nUDP: inuse 2 mem 1\n'
        data=network.socket_counters(socket_lines)
        self.assertEqual(data['counts']['tcp_inuse'],12)
        self.assertEqual(data['counts']['udp_mem'],1)
        self.assertNotIn('address',json.dumps(data))
        self.assertFalse(network.socket_counters('TCP: inuse bad')['verified'])

    def test_network_snapshot_includes_buffer_capabilities_read_only(self):
        def runner(command):return None
        def reader(path):
            return {'/proc/sys/net/ipv4/tcp_rmem':'4096 87380 16777216',
                    '/proc/sys/net/ipv4/tcp_wmem':'4096 65536 16777216',
                    '/proc/net/netstat':'TcpExt: ListenOverflows ListenDrops\nTcpExt: 1 0\n',
                    '/proc/net/sockstat':'TCP: inuse 5 orphan 0 tw 2 alloc 10 mem 1\n'}.get(path)
        snap=network.snapshot(runner,reader)
        self.assertEqual(snap['parameters']['tcp_rmem'],'4096 87380 16777216')
        self.assertTrue(snap['tcp_host_counters']['verified'])
        self.assertEqual(snap['socket_counts']['counts']['tcp_inuse'],5)
        self.assertIn('LISTEN_OVERFLOW_OR_DROP_SEEN_CUMULATIVE',snap['observations'])
        self.assertEqual(snap['actions_performed'],'NONE')

    def test_qdisc_drops_are_not_counted_twice(self):
        data=json.dumps([{'kind':'fq','root':True,'drops':7,
                         'stats':{'queue':{'drops':7}}}])
        self.assertEqual(network.qdisc_summary(data)['queue_drops_cumulative'],7)


if __name__ == '__main__':unittest.main()
