#!/usr/bin/env bash
# VKarmani Node 2.0.2. Read README.md before running as root.
# Source-safe for tests: setup only starts at the final dispatcher.
vk_write_tls_check() {
    install -d -m 0755 "$(dirname '/usr/local/sbin/vkarmani-node-tls-check')"
    cat > '/usr/local/sbin/vkarmani-node-tls-check' <<'VK_PAYLOAD_VK_WRITE_TLS_CHECK'
#!/usr/bin/env python3
"""Local TLS verification of the installed RemnaNode, not panel authentication.
Uses only CA and public certificate from SECRET_KEY; never writes private keys.
A fragmented probe exercises a real >1500-byte ClientHello over several writes.
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

ETC = Path('/etc/vkarmani-node')


def normal_pem(value):
    value = value.replace('\\n', '\n').replace('\r\n', '\n')
    value = re.sub(r'(-----BEGIN [A-Z ]+-----)', r'\1\n', value)
    value = re.sub(r'(-----END [A-Z ]+-----)', r'\n\1', value)
    return re.sub(r'\n+', '\n', value).strip() + '\n'


def derive_sni(ca_pem, jwt_public_pem):
    """Official RemnaNode rw-v1 HKDF-SHA256 derivation, without private keys.

    Source: remnawave/node src/common/utils/decode-node-payload/decode-servername.util.ts.
    Older nodes ignore SNI; newer SNI-gated nodes accept this same derived value.
    """
    def canon(value):
        value = re.sub(r'-----[^-]+-----', '', normal_pem(value))
        return re.sub(r'[^A-Za-z0-9+/=]', '', value).encode('ascii')
    ikm = canon(jwt_public_pem) + canon(ca_pem)
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    okm = hmac.new(prk, b'rw-v1' + bytes([1]), hashlib.sha256).digest()[:22]
    tlds = ('com', 'net', 'org', 'io', 'dev', 'app')
    return okm[:16].hex() + '.' + okm[16:21].hex() + '.' + tlds[okm[21] % len(tlds)]


def load_material(etc=ETC):
    cfg = json.loads((etc / 'config.json').read_text())
    port = cfg['node_port']
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('invalid node port')
    name = cfg['domain']
    if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9.-]{1,253}', name):
        raise ValueError('invalid domain')
    path = etc / 'remnanode.env'
    if path.stat().st_mode & 0o077:
        raise ValueError('remnanode.env permissions must be 0600')
    values = [line.split('=', 1)[1] for line in path.read_text().splitlines()
              if line.startswith('SECRET_KEY=')]
    if len(values) != 1:
        raise ValueError('one SECRET_KEY required')
    value = values[0].strip().strip('"\'')
    payload = json.loads(base64.b64decode(value + '=' * (-len(value) % 4),
                                        altchars=b'-_', validate=True))
    ca = normal_pem(payload['caCertPem'])
    cert = ssl.PEM_cert_to_DER_cert(normal_pem(payload['nodeCertPem']))
    cfg = dict(cfg)
    cfg['_probe_servername'] = derive_sni(payload['caCertPem'], payload['jwtPublicKey'])
    # No nodeKeyPem is used. A derived SNI is NOT panel authentication.
    return cfg, ca, hashlib.sha256(cert).digest()


def context(ca, fragmented):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # RemnaNode certificates use their own identity, not the public cover domain.
    # CA validation stays enabled, and the exact leaf certificate is pinned below.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    protocols = ['http/1.1']
    if fragmented:
        # Legal additional ALPN identifiers enlarge ClientHello without modifying
        # its TLS transcript. No application request or secret is sent.
        protocols += ['vk-local-probe-%02d-' % i + 'x' * 120 for i in range(12)]
    ctx.set_alpn_protocols(protocols)
    return ctx


def probe(host, port, servername, ca, fingerprint, fragmented=False, timeout=7.0):
    stage = 'TCP'
    deadline = time.monotonic() + timeout
    first_size = 0
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            stage = 'TLS'
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = context(ca, fragmented).wrap_bio(
                incoming, outgoing, server_side=False, server_hostname=servername)
            first = True
            received = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                raw.settimeout(remaining)
                done, need_read = False, False
                try:
                    tls.do_handshake()
                    done = True
                except ssl.SSLWantReadError:
                    need_read = True
                except ssl.SSLWantWriteError:
                    pass
                data = outgoing.read()
                if data:
                    if first:
                        first_size = len(data)
                    if first and fragmented:
                        # Include splits inside the TLS record header and body.
                        cuts = (1, 4, 73, 988, 1288)
                        start = 0
                        for stop in cuts:
                            if stop >= len(data):
                                break
                            raw.sendall(data[start:stop])
                            start = stop
                            time.sleep(0.01)
                        raw.sendall(data[start:])
                    else:
                        raw.sendall(data)
                    first = False
                if done:
                    leaf = tls.getpeercert(binary_form=True)
                    if not leaf or hashlib.sha256(leaf).digest() != fingerprint:
                        return False, 'TLS_LEAF_MISMATCH', first_size
                    if tls.version() != 'TLSv1.3':
                        return False, 'TLS_VERSION_MISMATCH', first_size
                    if fragmented and first_size <= 1500:
                        return False, 'TLS_PROBE_TOO_SMALL', first_size
                    # No client certificate exists in this probe. A subsequent
                    # certificate_required alert is expected; never label mTLS OK.
                    return True, 'TLS13_CA_AND_LEAF_OK', first_size
                if need_read:
                    data = raw.recv(65536)
                    if not data:
                        return False, 'TLS_CLOSED_BEFORE_SERVER_FINISHED', first_size
                    received += len(data)
                    if received > 1024 * 1024:
                        return False, 'TLS_RESPONSE_TOO_LARGE', first_size
                    incoming.write(data)
    except (TimeoutError, socket.timeout):
        return False, stage + '_TIMEOUT', first_size
    except ssl.SSLCertVerificationError:
        return False, 'TLS_CERTIFICATE_VERIFY_FAILED', first_size
    except ssl.SSLError as exc:
        return False, 'TLS_ERROR_' + re.sub(r'[^A-Z0-9_]', '_', str(exc.reason)), first_size
    except OSError as exc:
        return False, stage + '_OS_ERROR_' + str(exc.errno), first_size


def local_ips():
    rows = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'address', 'show'], text=True, timeout=5))
    return {a['local'] for row in rows for a in row.get('addr_info', [])
            if a.get('family') == 'inet'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all-local', action='store_true')
    args = parser.parse_args()
    try:
        c, ca, fp = load_material()
        ips = local_ips()
        expected = str(ipaddress.IPv4Address(c['public_ipv4']))
        if expected not in ips:
            print('NODE_TLS_LOCAL=FAIL NODE_IPV4_NOT_ASSIGNED')
            return 1
        targets = ['127.0.0.1', expected]
        if args.all_local:
            targets += sorted(x for x in ips if ipaddress.IPv4Address(x).is_global)
        failures = 0
        for host in dict.fromkeys(targets):
            for fragmented in (False, True):
                ok, detail, length = probe(host, c['node_port'], c['_probe_servername'], ca, fp, fragmented)
                print('LOCAL_TLS address=%s:%d mode=%s status=%s detail=%s hello_bytes=%d' % (
                    host, c['node_port'], 'fragmented' if fragmented else 'normal',
                    'PASS' if ok else 'FAIL', detail, length), flush=True)
                failures += not ok
        print('NODE_TLS_LOCAL=' + ('FAIL' if failures else 'PASS'))
        print('PANEL_MTLS=NOT_VERIFIED; local probes do not traverse the external interface or authenticate the panel')
        return int(bool(failures))
    except Exception:
        print('NODE_TLS_LOCAL=FAIL CONFIG_OR_CERTIFICATE_ERROR (secret not displayed)', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
VK_PAYLOAD_VK_WRITE_TLS_CHECK
    chmod 0755 '/usr/local/sbin/vkarmani-node-tls-check'
}

vk_write_selfsteal_check() {
    install -d -m 0755 "$(dirname '/usr/local/sbin/vkarmani-selfsteal-check')"
    cat > '/usr/local/sbin/vkarmani-selfsteal-check' <<'VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK'
#!/usr/bin/env python3
"""Check PROXY v1, verified TLS 1.3, HTTP/1.1 and actual HTTP/2 data on Selfsteal."""
import hashlib
import json
import socket
import ssl
import sys
import time
from pathlib import Path

SOCKET = '/dev/shm/nginx.sock'  # legacy layout; main() resolves the installed layout
SITE = Path('/var/www/vkarmani-node/site/index.html')


class DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def budget(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SELFSTEAL_DEADLINE_EXCEEDED')
        self.sock.settimeout(min(5, remaining))

    def recv(self, length):
        self.budget()
        return self.sock.recv(length)

    def sendall(self, data):
        self.budget()
        return self.sock.sendall(data)

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def connect(domain, alpn, path=SOCKET, cafile=None, deadline=None, expected_leaf=None):
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = deadline if deadline is not None else time.monotonic() + 20
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raw.close()
        raise TimeoutError('SELFSTEAL_DEADLINE_EXCEEDED')
    raw.settimeout(min(5, remaining))
    try:
        raw.connect(path)
        raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 54321 443\r\n')
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols([alpn])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SELFSTEAL_DEADLINE_EXCEEDED')
        raw.settimeout(min(5, remaining))
        s = ctx.wrap_socket(raw, server_hostname=domain)
        if s.selected_alpn_protocol() != alpn:
            s.close()
            raise ValueError('requested ALPN was not negotiated')
        if expected_leaf is not None and hashlib.sha256(s.getpeercert(binary_form=True)).digest() != expected_leaf:
            s.close()
            raise ValueError('SELFSTEAL_CERTIFICATE_NOT_RELOADED')
        return DeadlineSocket(s, deadline)
    except Exception:
        raw.close()
        raise


def read_exact(s, length):
    out = bytearray()
    while len(out) < length:
        part = s.recv(length - len(out))
        if not part:
            raise ValueError('unexpected TLS EOF')
        out.extend(part)
    return bytes(out)


def h2frame(kind, flags, stream, payload=b''):
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream.to_bytes(4, 'big') + payload


def hpack_string(value):
    b = value.encode('ascii')
    n = len(b)
    if n < 127:
        return bytes([n]) + b
    out = bytearray([127])
    n -= 127
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out) + b


def check(domain, path=SOCKET, site=SITE, cafile=None, timeout=20.0, expected_leaf=None):
    deadline = time.monotonic() + timeout
    if Path(site).stat().st_size > 131072:
        raise ValueError('COVER_PAGE_EXCEEDS_128_KIB_PROBE_LIMIT')
    expected = hashlib.sha256(Path(site).read_bytes()).digest()
    with connect(domain, 'http/1.1', path, cafile, deadline, expected_leaf) as s:
        s.sendall(('GET / HTTP/1.1\r\nHost: ' + domain + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        data = bytearray()
        while len(data) <= 147456:
            part = s.recv(8192)
            if not part:
                break
            data.extend(part)
        header, sep, body = bytes(data).partition(b'\r\n\r\n')
        if not sep or not header.startswith(b'HTTP/1.1 200 ') or hashlib.sha256(body).digest() != expected:
            raise ValueError('HTTP/1.1 did not return the expected cover page')
    with connect(domain, 'h2', path, cafile, deadline, expected_leaf) as s:
        # HPACK static indexes: GET=2, https=7, path /=4, :authority=1.
        headers = b'\x82\x87\x84\x01' + hpack_string(domain)
        s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4, 0, 0) + h2frame(1, 5, 1, headers))
        body = bytearray()
        got_settings = got_headers = finished = False
        for _ in range(100):
            head = read_exact(s, 9)
            size, kind, flags = int.from_bytes(head[:3], 'big'), head[3], head[4]
            stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
            if size > 131072:
                raise ValueError('oversized HTTP/2 frame')
            payload = read_exact(s, size)
            if kind == 4:
                if stream != 0 or (flags & 1 and size) or (not flags & 1 and size % 6):
                    raise ValueError('invalid HTTP/2 SETTINGS')
                if not flags & 1:
                    got_settings = True
                    s.sendall(h2frame(4, 1, 0))
            elif kind == 1 and stream == 1:
                # Own Nginx emits indexed :status=200 (HPACK static index 8).
                # Reject other encodings instead of falsely accepting a 404 body.
                block = payload
                if flags & 8:
                    if not block or block[0] >= len(block):
                        raise ValueError('invalid HTTP/2 header padding')
                    padding = block[0]
                    block = block[1:len(block)-padding] if padding else block[1:]
                if flags & 32:
                    block = block[5:]
                if not flags & 4 or not block or block[0] != 0x88 or got_headers:
                    raise ValueError('HTTP2_STATUS_NOT_NGINX_200_OR_UNEXPECTED_HEADERS')
                got_headers = True
                if flags & 1:
                    finished = True
                    break
            elif kind == 0 and stream == 1:
                if not got_headers:
                    raise ValueError('HTTP2_DATA_BEFORE_HEADERS')
                if flags & 8:
                    if not payload or payload[0] >= len(payload):
                        raise ValueError('invalid HTTP/2 padding')
                    padding = payload[0]
                    payload = payload[1:len(payload)-padding] if padding else payload[1:]
                body.extend(payload)
                if len(body) > 131072:
                    raise ValueError('HTTP/2 response too large')
                if flags & 1:
                    finished = True
                    break
                # Window accounting includes padding. Return consumed credit to
                # both connection and stream; otherwise >65535 bytes deadlocks.
                if size:
                    increment = size.to_bytes(4, 'big')
                    s.sendall(h2frame(8, 0, 0, increment) + h2frame(8, 0, 1, increment))
            elif kind in (3, 7):
                raise ValueError('HTTP/2 stream rejected')
        if not (got_settings and got_headers and finished) or hashlib.sha256(body).digest() != expected:
            raise ValueError('HTTP/2 did not return the expected cover page')


def main():
    try:
        cfg = json.loads(Path('/etc/vkarmani-node/config.json').read_text())
        path = cfg.get('selfsteal_host_socket', SOCKET)
        if path not in (SOCKET, '/run/vkarmani-selfsteal/nginx.sock'):
            raise ValueError('unknown socket layout')
        cert_path = Path('/etc/letsencrypt/live') / cfg['domain'] / 'fullchain.pem'
        cert_text = cert_path.read_text().split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----\n'
        expected_leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_text)).digest()
        check(cfg['domain'], path=path, expected_leaf=expected_leaf)
        print('SELFSTEAL_TLS13_HTTP1_HTTP2=PASS')
        return 0
    except Exception as e:
        # Do not print config, request headers, certificate material or bodies.
        if isinstance(e, ssl.SSLCertVerificationError):
            reason = 'TLS_CERTIFICATE_OR_HOSTNAME_VERIFY_FAILED'
        elif isinstance(e, TimeoutError):
            reason = 'PROBE_TIMEOUT_OR_DEADLINE'
        elif isinstance(e, FileNotFoundError):
            reason = 'SOCKET_SITE_CONFIG_OR_CERTIFICATE_MISSING'
        elif isinstance(e, ConnectionRefusedError):
            reason = 'SOCKET_NOT_ACCEPTING_CONNECTIONS'
        elif isinstance(e, ValueError) and not isinstance(e, json.JSONDecodeError):
            reason = str(e)  # fixed diagnostic messages above, never response bytes
        else:
            reason = type(e).__name__
        print('SELFSTEAL_CHECK=FAIL ' + reason, file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK
    chmod 0755 '/usr/local/sbin/vkarmani-selfsteal-check'
}

vk_write_network_script() {
    install -d -m 0755 "$(dirname '/usr/local/sbin/vkarmani-node-network')"
    local vk_tmp
    vk_tmp=$(mktemp '/usr/local/sbin/vkarmani-node-network.tmp.XXXXXX')
    cat > "$vk_tmp" <<'VK_PAYLOAD_VK_WRITE_NETWORK_SCRIPT'
#!/usr/bin/env python3
"""Apply only this installer's sysctls, including after ipv6.disable=1.

procps 4.0.4 can fail at stat() for a missing key even when the line has '-'.
Do not use a blanket --ignore/||true: skip only the three absent IPv6 controls,
and only after confirming that the IPv6 socket API is disabled by the kernel.
No interfaces, addresses, routes, firewall rules, MTU/MSS or qdiscs are changed.
"""
import errno
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

CONFIG = Path('/etc/sysctl.d/99-vkarmani-node.conf')
PROC_SYS = Path('/proc/sys')
IPV6_KEYS = {
    'net.ipv6.conf.all.disable_ipv6',
    'net.ipv6.conf.default.disable_ipv6',
    'net.ipv6.conf.lo.disable_ipv6',
}
REQUIRED = {
    'net.core.default_qdisc': 'fq',
    'net.ipv4.tcp_congestion_control': 'bbr',
}


class ApplyError(Exception):
    pass


def ipv6_socket_disabled():
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError as exc:
        if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            return True
        raise ApplyError('IPV6_SOCKET_PROBE_FAILED errno=' + str(exc.errno)) from exc
    else:
        sock.close()
        return False


def parse_config(text):
    if len(text) > 65536:
        raise ApplyError('CONFIG_TOO_LARGE')
    entries = []
    seen = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if '=' not in line:
            raise ApplyError('CONFIG_NOT_ASSIGNMENT line=' + str(lineno))
        key, value = (x.strip() for x in line.split('=', 1))
        key = key.removeprefix('-')
        if (not re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+)+', key)
                or not value or '\x00' in value):
            raise ApplyError('CONFIG_INVALID line=' + str(lineno))
        if key in seen:
            raise ApplyError('CONFIG_DUPLICATE key=' + key)
        if key.startswith('net.ipv6.') and (key not in IPV6_KEYS or value != '1'):
            raise ApplyError('CONFIG_UNEXPECTED_IPV6 key=' + key)
        entries.append((key, value))
        seen.add(key)
    values = dict(entries)
    for key, expected in REQUIRED.items():
        if values.get(key) != expected:
            raise ApplyError('CONFIG_REQUIRED_VALUE key=' + key)
    # All three controls must remain declared; a missing declaration is not a skip.
    if not IPV6_KEYS.issubset(values):
        raise ApplyError('CONFIG_MISSING_IPV6_CONTROLS')
    return entries


def select_entries(entries, proc_root, ipv6_off):
    kept, skipped = [], []
    for key, value in entries:
        path = proc_root.joinpath(*key.split('.'))
        if not path.exists():
            if key in IPV6_KEYS and value == '1' and ipv6_off:
                skipped.append(key)
                continue
            raise ApplyError('SYSCTL_KEY_MISSING key=' + key)
        if not path.is_file():
            raise ApplyError('SYSCTL_NOT_FILE key=' + key)
        kept.append((key, value))
    return kept, skipped


def load_modules(run=subprocess.run):
    # A failed modprobe is not proof of missing support: drivers can be built in.
    # The actual sysctl write + readback below is the capability test.
    for module in ('tcp_bbr', 'sch_fq'):
        run(['modprobe', module], text=True, capture_output=True, timeout=10)


def resolve_performance(entries, proc_root, run=subprocess.run):
    effective, notes = [], []
    for key, requested in entries:
        if key not in REQUIRED:
            effective.append((key, requested))
            continue
        path = proc_root.joinpath(*key.split('.'))
        before = path.read_text().strip()
        result = run(['sysctl', '-w', key + '=' + requested],
                     text=True, capture_output=True, timeout=10)
        if result.returncode:
            after = path.read_text().strip()
            if after != before or not re.fullmatch(r'[a-zA-Z0-9_]+', after):
                raise ApplyError('PERFORMANCE_FALLBACK_UNSAFE key=' + key)
            effective.append((key, after))
            notes.append(key + ': requested=' + requested + ', effective=' + after)
        else:
            effective.append((key, requested))
    return effective, notes


def save_effective(entries, notes, path=None):
    import json
    import tempfile
    path = path or Path('/var/lib/vkarmani-node/network-effective.json')
    data = {k: v for k, v in entries if k in REQUIRED}
    data['notes'] = notes
    fd, tmp = tempfile.mkstemp(prefix='.network-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply_entries(entries, run=subprocess.run):
    data = ''.join(key + ' = ' + value + '\n' for key, value in entries)
    result = run(['sysctl', '-p', '-'], input=data,
                 text=True, capture_output=True, timeout=15)
    if result.returncode:
        # This file contains sysctls only, never credentials. Do not suppress errors.
        detail = ' '.join(result.stderr.split())[:1200]
        raise ApplyError('SYSCTL_APPLY_FAILED rc=' + str(result.returncode) + ' ' + detail)


def verify_entries(entries, proc_root):
    for key, expected in entries:
        path = proc_root.joinpath(*key.split('.'))
        try:
            actual = path.read_text().strip()
        except OSError as exc:
            raise ApplyError('SYSCTL_READBACK_FAILED key=' + key) from exc
        if actual.split() != expected.split():
            raise ApplyError('SYSCTL_READBACK_MISMATCH key=' + key)


def main():
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    if len(sys.argv) != 1:
        print('Usage: vkarmani-node-network', file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print('NETWORK_SYSCTL=FAIL root required', file=sys.stderr)
        return 1
    try:
        entries = parse_config(CONFIG.read_text(encoding='utf-8'))
        load_modules()
        kept, skipped = select_entries(entries, PROC_SYS, ipv6_socket_disabled())
        for key in skipped:
            print('IPV6_SYSCTL=SKIP_KERNEL_DISABLED key=' + key, flush=True)
        kept, notes = resolve_performance(kept, PROC_SYS)
        apply_entries(kept)
        verify_entries(kept, PROC_SYS)
        save_effective(kept, notes)
        for note in notes:
            print('NETWORK_ACCELERATION=DEGRADED ' + note)
        print('NETWORK_SYSCTL=PASS; BBR_AND_DEFAULT_FQ=' + ('DEGRADED' if notes else 'PASS')
              + '; applied=' + str(len(kept)) + '; skipped_ipv6=' + str(len(skipped)))
        return 0
    except ApplyError as exc:
        print('NETWORK_SYSCTL=FAIL ' + str(exc), file=sys.stderr)
    except subprocess.TimeoutExpired as exc:
        print('NETWORK_SYSCTL=FAIL command timeout: ' + str(exc.cmd[0]), file=sys.stderr)
    except OSError as exc:
        print('NETWORK_SYSCTL=FAIL ' + type(exc).__name__ + ' errno=' + str(exc.errno), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
VK_PAYLOAD_VK_WRITE_NETWORK_SCRIPT
    chmod 0755 "$vk_tmp"
    mv -f -- "$vk_tmp" '/usr/local/sbin/vkarmani-node-network'
}

vk_write_network_unit() {
    install -d -m 0755 "$(dirname '/etc/systemd/system/vkarmani-node-network.service')"
    local vk_tmp
    vk_tmp=$(mktemp '/etc/systemd/system/vkarmani-node-network.service.tmp.XXXXXX')
    cat > "$vk_tmp" <<'VK_PAYLOAD_VK_WRITE_NETWORK_UNIT'
[Unit]
Description=VKarmani IPv6-aware sysctl application (no route or qdisc replacement)
After=systemd-modules-load.service systemd-sysctl.service network.target docker.service ufw.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-network
TimeoutStartSec=60
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
VK_PAYLOAD_VK_WRITE_NETWORK_UNIT
    chmod 0644 "$vk_tmp"
    mv -f -- "$vk_tmp" '/etc/systemd/system/vkarmani-node-network.service'
}

vk_write_node_unit() {
    install -d -m 0755 "$(dirname '/etc/systemd/system/vkarmani-node.service')"
    cat > '/etc/systemd/system/vkarmani-node.service' <<'VK_PAYLOAD_VK_WRITE_NODE_UNIT'
[Unit]
Description=VKarmani RemnaNode manual Compose controls (Docker owns autostart)
Requires=docker.service
After=docker.service systemd-tmpfiles-setup.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/vkarmani-node
ExecStart=/usr/bin/docker compose -f /opt/vkarmani-node/compose.yaml up -d
ExecStop=/usr/bin/docker compose -f /opt/vkarmani-node/compose.yaml stop
TimeoutStartSec=120
TimeoutStopSec=90
# Intentionally no [Install] / WantedBy. restart: always is the sole boot owner.
# Nginx, ACME, BBR and external DNS must not gate the management API.
VK_PAYLOAD_VK_WRITE_NODE_UNIT
    chmod 0644 '/etc/systemd/system/vkarmani-node.service'
}

vk_write_socket_prepare() {
    local temp
    temp=$(mktemp /usr/local/sbin/vkarmani-selfsteal-socket-prepare.tmp.XXXXXX)
    cat > "$temp" <<'VK_SOCKET_PREPARE'
#!/usr/bin/env python3
"""Remove only a root-owned, refused Selfsteal Unix socket before Nginx start.

Never remove a live socket, a symlink, a non-socket or an inode changed by a race.
Only systemd may start the managed Nginx; parallel unmanaged starts are unsupported.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import sys


class UnsafeSocket(Exception):
    pass


def prepare(path):
    path = Path(path)
    if path.parent.is_symlink():
        raise UnsafeSocket('PARENT_SYMLINK')
    try:
        before = path.lstat()
    except FileNotFoundError:
        return 'ABSENT'
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
        raise UnsafeSocket('NOT_OWNED_SOCKET')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(str(path))
        except OSError as exc:
            if exc.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                raise UnsafeSocket('LIVENESS_NOT_PROVEN errno=' + str(exc.errno)) from exc
        else:
            raise UnsafeSocket('LIVE_SOCKET_UNCHANGED')
    try:
        after = path.lstat()
    except FileNotFoundError:
        return 'DISAPPEARED'
    if (before.st_dev, before.st_ino, before.st_uid, before.st_mode) != (
            after.st_dev, after.st_ino, after.st_uid, after.st_mode):
        raise UnsafeSocket('INODE_CHANGED_UNCHANGED')
    path.unlink()
    return 'STALE_REMOVED'


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        print('SELFSTEAL_SOCKET_PREPARE=FAIL ROOT_NO_ARGUMENTS_REQUIRED', file=sys.stderr)
        return 1
    try:
        c = json.loads(Path('/etc/vkarmani-node/config.json').read_text())
        path = c.get('selfsteal_host_socket', '/dev/shm/nginx.sock')
        if path not in ('/run/vkarmani-selfsteal/nginx.sock', '/dev/shm/nginx.sock'):
            raise UnsafeSocket('UNKNOWN_LAYOUT')
        with open('/run/lock/vkarmani-selfsteal-socket.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print('SELFSTEAL_SOCKET_PREPARE=' + prepare(path))
        return 0
    except UnsafeSocket as exc:
        print('SELFSTEAL_SOCKET_PREPARE=FAIL ' + str(exc), file=sys.stderr)
    except Exception:
        print('SELFSTEAL_SOCKET_PREPARE=FAIL CONFIG_OR_FILESYSTEM_ERROR', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
VK_SOCKET_PREPARE
    chmod 0755 "$temp"
    mv -f "$temp" /usr/local/sbin/vkarmani-selfsteal-socket-prepare
}

vk_write_nginx_dropin() {
    vk_write_socket_prepare
    install -d -m 0755 "$(dirname '/etc/systemd/system/nginx.service.d/90-vkarmani-resilience.conf')"
    cat > '/etc/systemd/system/nginx.service.d/90-vkarmani-resilience.conf' <<'VK_PAYLOAD_VK_WRITE_NGINX_DROPIN'
[Unit]
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
# Keep retrying after a delayed provider address or a corrected configuration.

[Service]
ExecStartPre=/usr/local/sbin/vkarmani-selfsteal-socket-prepare
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
VK_PAYLOAD_VK_WRITE_NGINX_DROPIN
    chmod 0644 '/etc/systemd/system/nginx.service.d/90-vkarmani-resilience.conf'
}

vk_write_acceptance() {
    install -d -m 0755 "$(dirname '/usr/local/sbin/vkarmani-node-check')"
    cat > '/usr/local/sbin/vkarmani-node-check' <<'VK_PAYLOAD_VK_WRITE_ACCEPTANCE'
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
# Local-only checks. Does not establish connectivity from the panel.
set -uo pipefail
set +x
umask 077
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID -eq 0 ]] || { echo 'Run as root: sudo vkarmani-node-check'; exit 1; }
MODE=${1:---normal}
[[ $# -le 1 ]] || { echo 'Too many arguments to node-check' >&2; exit 2; }
case "$MODE" in --normal|--preboot|--postboot|--local|--require-xray) ;; *) echo 'Usage: vkarmani-node-check [--local|--preboot|--postboot|--require-xray]'; exit 2 ;; esac
if [[ ${VK_NODE_CHECK_BOUNDED:-0} != 1 ]]; then
    export VK_NODE_CHECK_BOUNDED=1
    # GNU timeout owns a process group; no --foreground (children must be stopped).
    exec timeout --kill-after=5s 600s "$0" "$@"
fi
ETC=/etc/vkarmani-node
STATE=/var/lib/vkarmani-node
HELPER=/usr/local/lib/vkarmani-node/node_helper.py
F=0
XRAY_PRESENT=0
XRAY_COVER_OK=0
pass(){ printf '%-33s PASS\n' "$1"; }
fail(){ printf '%-33s FAIL %s\n' "$1" "${2:-}"; F=1; }
warn(){ printf '%-33s NOTE %s\n' "$1" "${2:-}"; }
helper(){ python3 "$HELPER" "$@"; }
if [[ "$MODE" == --postboot ]]; then
    touch /var/log/vkarmani-node-postboot.log
    chmod 0600 /var/log/vkarmani-node-postboot.log
    exec > >(tee -a /var/log/vkarmani-node-postboot.log) 2>&1
    rm -f "$STATE/POSTBOOT_SETUP_PASS" "$STATE/POSTBOOT_FAIL"
fi
printf '\n=== VKarmani node acceptance %s mode=%s ===\n' "$(date -Is)" "$MODE"
DOMAIN=$(helper get domain) || exit 1
NODE_PORT=$(helper get node_port) || exit 1
PUBLIC_IP=$(helper get public_ipv4) || exit 1
SELFSTEAL_SOCKET=$(python3 -c 'import json; print(json.load(open("/etc/vkarmani-node/config.json")).get("selfsteal_host_socket", "/dev/shm/nginx.sock"))') || exit 1
if [[ "$MODE" == --postboot ]]; then
    for _ in $(seq 1 30); do
        if ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${NODE_PORT}$"; then break; fi
        sleep 2
    done
fi
helper secret >/dev/null 2>&1 && pass SECRET_KEY_VALID || fail SECRET_KEY_VALID
if [[ -f "$STATE/install-version" && $(cat "$STATE/install-version") == 2.0.2 ]]; then
    helper profile-check && pass IMPORT_PROFILE_POLICY || fail IMPORT_PROFILE_POLICY
    warn LIVE_PROFILE_POLICY 'NOT_VERIFIED: local JSON is not the live node config or Host SNI override'
fi
[[ "$(timedatectl show -p Timezone --value)" == Europe/Moscow ]] && pass TIMEZONE_MOSCOW || fail TIMEZONE_MOSCOW
if [[ "$MODE" == --preboot ]]; then
    if [[ ! -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ]] || [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) == 1 ]]; then
        pass IPV6_RUNTIME_OFF
    else
        fail IPV6_RUNTIME_OFF
    fi
    if _contains -w 'ipv6.disable=1' /proc/cmdline; then pass IPV6_KERNEL_PARAMETER; else warn IPV6_KERNEL_PARAMETER 'requires reboot'; fi
else
    _contains -w 'ipv6.disable=1' /proc/cmdline && pass IPV6_KERNEL_PARAMETER || fail IPV6_KERNEL_PARAMETER 'GRUB change not active'
    if python3 - <<'PY'
import socket,sys,errno
try:
    s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
except OSError as e:
    sys.exit(0 if e.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT) else 1)
else:
    s.close()
    sys.exit(1)
PY
    then pass IPV6_SOCKET_DISABLED; else fail IPV6_SOCKET_DISABLED 'IPv6 sockets can still be created'; fi
    IPV6_LISTENERS=$(ss -H -6 -lntup 2>/dev/null || true)
    [[ -z "$IPV6_LISTENERS" ]] && pass NO_IPV6_LISTENERS || fail NO_IPV6_LISTENERS
fi
if ip -6 address show 2>/dev/null | _contains 'inet6'; then fail NO_IPV6_ADDRESSES; else pass NO_IPV6_ADDRESSES; fi
if ip -6 route show 2>/dev/null | _contains .; then fail NO_IPV6_ROUTES; else pass NO_IPV6_ROUTES; fi
/usr/sbin/sshd -t >/dev/null 2>&1 && pass SSH_CONFIG || fail SSH_CONFIG
/usr/sbin/sshd -T 2>/dev/null | _contains -Fx 'addressfamily inet' && pass SSH_IPV4_ONLY || fail SSH_IPV4_ONLY
while IFS= read -r port; do
    if ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${port}$"; then pass "SSH_TCP_$port"; else fail "SSH_TCP_$port"; fi
done < "$ETC/ssh-ports"
for service in docker containerd nginx fail2ban chrony ufw vkarmani-node-network; do
    if systemctl is-active --quiet "$service"; then
        pass "SERVICE_$service"
    else
        fail "SERVICE_$service"
        systemctl show "$service.service" -p Result -p ExecMainStatus --no-pager 2>/dev/null || true
        if [[ "$service" == vkarmani-node-network ]]; then
            journalctl -b -u "$service.service" -n 12 --no-pager 2>/dev/null || true
        fi
    fi
done
ufw status | _contains -F 'Status: active' && pass UFW_ACTIVE || fail UFW_ACTIVE
if python3 - <<'PY_FIREWALL_CHECK'
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import sys


class PolicyError(ValueError):
    pass


def fields(tokens):
    out = {}
    i = 0
    while i < len(tokens):
        key = tokens[i]
        if key == '-m':
            if i + 1 >= len(tokens) or tokens[i + 1] not in ('tcp', 'multiport', 'comment'):
                raise PolicyError('UNREVIEWED_RULE_MODULE')
            i += 2
            continue
        if key not in ('-s', '-d', '-p', '--dport', '--dports', '-j', '--comment') or i + 1 >= len(tokens):
            raise PolicyError('UNREVIEWED_RULE_OPTION')
        if key in out:
            raise PolicyError('DUPLICATE_RULE_OPTION')
        out[key] = tokens[i + 1]
        i += 2
    return out


def validate_rules(c, ssh_ports, user_text, input_text):
    ports = {str(int(x)) for x in ssh_ports}
    if not ports or len(ports) > 15 or any(not 1 <= int(x) <= 65535 for x in ports):
        raise PolicyError('SSH_PORT_SET_INVALID')
    if ports & {'80', '443', str(c['node_port'])}:
        raise PolicyError('SSH_PORT_COLLISION')
    expected = {('0.0.0.0/0', '0.0.0.0/0', 'tcp', p) for p in ports}
    expected |= {('0.0.0.0/0', c['public_ipv4'] + '/32', 'tcp', p) for p in ('80', '443')}
    expected |= {(p + '/32', '0.0.0.0/0', 'tcp', str(c['node_port'])) for p in c['panel_ipv4']}
    found = set()
    for line in user_text.splitlines():
        w = shlex.split(line)
        if not w or w == ['-N', 'ufw-user-input']:
            continue
        if w[:2] != ['-A', 'ufw-user-input']:
            raise PolicyError('UNEXPECTED_USER_CHAIN_LINE')
        rule = fields(w[2:])
        src = str(ipaddress.IPv4Network(rule.get('-s', '0.0.0.0/0')))
        dst = str(ipaddress.IPv4Network(rule.get('-d', '0.0.0.0/0')))
        proto, action = rule.get('-p'), rule.get('-j')
        port = rule.get('--dport')
        if action == 'ACCEPT':
            key = (src, dst, proto, port)
            if '--dports' in rule or key not in expected or key in found:
                raise PolicyError('UNEXPECTED_OR_DUPLICATE_ACCEPT')
            found.add(key)
        elif action == 'DROP':
            # Only this installer's temporary Fail2ban bans on SSH ports are expected.
            raw_ports = rule.get('--dports', port or '')
            banned = set(raw_ports.split(','))
            if (proto != 'tcp' or dst != '0.0.0.0/0' or ipaddress.IPv4Network(src).prefixlen != 32
                    or not banned or not banned <= ports or ('--dport' in rule and '--dports' in rule)):
                raise PolicyError('UNREVIEWED_DENY_RULE')
        else:
            raise PolicyError('UNREVIEWED_USER_CHAIN_TARGET')
    if found != expected:
        raise PolicyError('MISSING_EXPECTED_SSH_ACME_REALITY_OR_PANEL_RULE')
    jumps = ['ufw-before-logging-input', 'ufw-before-input', 'ufw-after-input',
             'ufw-after-logging-input', 'ufw-reject-input', 'ufw-track-input']
    wanted = [['-P', 'INPUT', 'DROP']] + [['-A', 'INPUT', '-j', name] for name in jumps]
    actual = [shlex.split(line) for line in input_text.splitlines() if line.strip()]
    if actual != wanted:
        raise PolicyError('INPUT_POLICY_OR_UFW_TOPOLOGY_DRIFT')
    return True


def main():
    try:
        c = json.loads(Path('/etc/vkarmani-node/config.json').read_text())
        ssh = Path('/etc/vkarmani-node/ssh-ports').read_text().split()
        texts = []
        for chain in ('ufw-user-input', 'INPUT'):
            result = subprocess.run(['iptables', '-S', chain], capture_output=True, text=True, timeout=8)
            if result.returncode:
                raise PolicyError('CANNOT_READ_ACTIVE_IPTABLES_POLICY')
            texts.append(result.stdout)
        validate_rules(c, ssh, *texts)
        print('UFW_DECLARED_TCP_RULES_AND_INPUT_TOPOLOGY=PASS')
        return 0
    except PolicyError as exc:
        print('UFW_POLICY=FAIL ' + str(exc))
    except Exception:
        print('UFW_POLICY=FAIL CONFIG_OR_RULE_READ_ERROR')
    return 1


if __name__ == '__main__':
    sys.exit(main())
PY_FIREWALL_CHECK
then pass UFW_TCP_POLICY; else fail UFW_TCP_POLICY; fi
if python3 - <<'PY_NETWORK_CHECK'
import json, subprocess, sys
from pathlib import Path
p = Path('/var/lib/vkarmani-node/network-effective.json')
c = json.loads(p.read_text()) if p.exists() else {'net.ipv4.tcp_congestion_control': 'bbr', 'net.core.default_qdisc': 'fq'}
for key in ('net.ipv4.tcp_congestion_control', 'net.core.default_qdisc'):
    if subprocess.check_output(['sysctl', '-n', key], text=True).strip() != c[key]:
        sys.exit(1)
    print('NETWORK_EFFECTIVE ' + key + '=' + c[key])
for note in c.get('notes', []):
    print('NETWORK_ACCELERATION=DEGRADED ' + note)
PY_NETWORK_CHECK
then pass NETWORK_EFFECTIVE; else fail NETWORK_EFFECTIVE; fi
if [[ -f "$STATE/install-version" ]]; then
    [[ $(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null) == 1 ]] && pass TCP_MTU_PROBING || fail TCP_MTU_PROBING
    for expected in 'passwordauthentication yes' 'permitrootlogin yes' 'permitemptypasswords no' 'authenticationmethods any'; do
        /usr/sbin/sshd -T 2>/dev/null | _contains -Fx "$expected" && pass "SSH_${expected// /_}" || fail "SSH_${expected// /_}"
    done
fi
warn INTERFACE_QDISC 'сохранена текущая структура очередей; root qdisc не перезаписывается'
if [[ "$MODE" == --postboot ]]; then
    chronyc waitsync 15 0.1 0.0 2 >/dev/null 2>&1 || true
fi
chronyc tracking 2>/dev/null | _contains -E 'Leap status[[:space:]]*:[[:space:]]*Normal' && pass NTP_SYNC || fail NTP_SYNC
if [[ $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]]; then
    R1=$(docker inspect remnanode --format '{{.RestartCount}}' 2>/dev/null)
    sleep 5
    R2=$(docker inspect remnanode --format '{{.RestartCount}}' 2>/dev/null)
    if [[ "$R1" == "$R2" && $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]]; then
        pass NODE_RUNNING_STABLE
    else fail NODE_RUNNING_STABLE; fi
else fail NODE_RUNNING_STABLE; fi
[[ $(docker inspect remnanode --format '{{.HostConfig.NetworkMode}}' 2>/dev/null) == host ]] && pass NODE_HOST_NETWORK || fail NODE_HOST_NETWORK
[[ $(docker inspect remnanode --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null) == always ]] && pass NODE_RESTART_POLICY || fail NODE_RESTART_POLICY
[[ $(docker network inspect bridge --format '{{.EnableIPv6}}' 2>/dev/null) == false ]] && pass DOCKER_IPV6_OFF || fail DOCKER_IPV6_OFF
if /usr/local/sbin/vkarmani-node-tls-check --all-local; then
    pass NODE_TLS_LOCAL
else
    fail NODE_TLS_LOCAL
fi
warn EXTERNAL_API_REACHABILITY 'NOT_VERIFIED: локальные обращения не проходят путь от панели'
if [[ "$SELFSTEAL_SOCKET" == /run/vkarmani-selfsteal/nginx.sock ]]; then
    CAPS=$(docker inspect remnanode --format '{{json .HostConfig.CapAdd}}') || CAPS='INVALID'
    ALLOWED=$(helper get allow_net_admin) || ALLOWED='INVALID'
    if [[ "$CAPS" != INVALID && "$ALLOWED" == false && "$CAPS" != *NET_ADMIN* ]]; then
        pass NODE_NO_NET_ADMIN
    elif [[ "$ALLOWED" == true && "$CAPS" == *NET_ADMIN* ]]; then
        warn NODE_NET_ADMIN 'explicit opt-in; container can modify host networking'
    else fail NODE_CAPABILITY_POLICY; fi
    if docker inspect remnanode --format '{{json .Mounts}}' | python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin) if x["Destination"]=="/dev/shm"]; sys.exit(0 if len(a)==1 and a[0]["Source"]=="/run/vkarmani-selfsteal" and not a[0]["RW"] else 1)'; then
        pass NODE_ISOLATED_SELFSTEAL_MOUNT
    else fail NODE_ISOLATED_SELFSTEAL_MOUNT; fi
fi


if ss -H -4 -lnt | awk '{print $4}' | _contains -E ':443$'; then
    XRAY_PRESENT=1
    pass XRAY_TCP443
else
    warn XRAY_TCP443 'NOT_LISTENING: причина не установлена; профиль, запуск Xray или канал управления'
fi
[[ -S "$SELFSTEAL_SOCKET" ]] && pass SELFSTEAL_SOCKET || fail SELFSTEAL_SOCKET
nginx -t >/dev/null 2>&1 && pass NGINX_CONFIG || fail NGINX_CONFIG
openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -checkend 604800 >/dev/null 2>&1 && pass TLS_VALID_7DAYS || fail TLS_VALID_7DAYS
timeout 25 /usr/local/sbin/vkarmani-selfsteal-check >/dev/null 2>&1 && pass SELFSTEAL_TLS13_HTTP1_HTTP2 || fail SELFSTEAL_TLS13_HTTP1_HTTP2
if docker exec remnanode test -S /dev/shm/nginx.sock >/dev/null 2>&1; then pass NODE_SELFSTEAL_SOCKET; else fail NODE_SELFSTEAL_SOCKET; fi
if [[ "$XRAY_PRESENT" -eq 1 ]]; then
    BODY=$(mktemp "$STATE/.cover-check.XXXXXX") || exit 1
    CODE=$(curl --noproxy '*' -4 --fail --silent --show-error --http2 --tlsv1.3 --tls-max 1.3 \
        --connect-timeout 5 --max-time 20 --resolve "$DOMAIN:443:$PUBLIC_IP" \
        -o "$BODY" -w '%{http_code}' "https://$DOMAIN/" 2>/dev/null || true)
    if [[ "$CODE" == 200 ]] && cmp -s "$BODY" /var/www/vkarmani-node/site/index.html; then
        pass REALITY_SELFSTEAL_443
        XRAY_COVER_OK=1
    else
        warn REALITY_SELFSTEAL_443 'TCP/443 открыт, но ожидаемый Selfsteal не подтверждён; проверьте назначенный профиль'
    fi
    rm -f "$BODY"
fi
fail2ban-client ping 2>/dev/null | _contains pong && pass FAIL2BAN_PING || fail FAIL2BAN_PING
fail2ban-client status sshd >/dev/null 2>&1 && pass FAIL2BAN_SSHD_JAIL || fail FAIL2BAN_SSHD_JAIL
for timer in certbot vkarmani-node-cleanup; do
    systemctl is-active --quiet "$timer.timer" && pass "TIMER_$timer" || fail "TIMER_$timer"
    systemctl is-enabled --quiet "$timer.timer" && pass "BOOT_$timer" || fail "BOOT_$timer"
done
if [[ -e "$ETC/weekly-reboot-enabled" ]]; then
    systemctl is-active --quiet vkarmani-weekly-reboot.timer && pass WEEKLY_REBOOT_OPT_IN || fail WEEKLY_REBOOT_OPT_IN
    _contains -Fx 'OnCalendar=Mon *-*-* 04:00:00 Europe/Moscow' /etc/systemd/system/vkarmani-weekly-reboot.timer && pass WEEKLY_REBOOT_SCHEDULE || fail WEEKLY_REBOOT_SCHEDULE
else
    if systemctl is-active --quiet vkarmani-weekly-reboot.timer; then fail UNEXPECTED_WEEKLY_REBOOT; else pass NO_WEEKLY_REBOOT; fi
fi
warn PANEL_CONNECTION 'NOT_VERIFIED: API не используется; состояние подключения смотрите в панели'
if [[ "$MODE" != --local ]]; then
    helper dns && pass DOMAIN_IPV4_ONLY || fail DOMAIN_IPV4_ONLY
fi
if [[ "$F" -eq 0 ]]; then
    echo 'NODE_LOCAL_CHECKS=PASS — подключение панели не подтверждено'
else
    echo 'NODE_LOCAL_CHECKS=FAIL — обнаружены локальные ошибки'
fi
if [[ "$XRAY_PRESENT" -eq 0 ]]; then
    VPN_STATUS=XRAY_NOT_LISTENING_REASON_NOT_CONFIRMED
elif [[ "$XRAY_COVER_OK" -eq 1 ]]; then
    VPN_STATUS=LOCAL_XRAY_COVER_OK_CLIENT_NOT_TESTED
else
    VPN_STATUS=PORT443_PRESENT_PROFILE_NOT_CONFIRMED
fi
printf 'VPN_STATUS=%s\nPANEL_CONNECTION=NOT_VERIFIED\n' "$VPN_STATUS"
echo 'Клиентский VPN-трафик, назначение Host и доступ пользователя этой командой не проверяются.'
if [[ "$MODE" == --postboot ]]; then
    if [[ "$F" -eq 0 ]]; then
        printf 'at=%s\nnode_local_checks=pass\nvpn_status=%s\npanel_connection=not_verified\n' "$(date -Is)" "$VPN_STATUS" > "$STATE/POSTBOOT_SETUP_PASS"
    else
        printf 'at=%s\n' "$(date -Is)" > "$STATE/POSTBOOT_FAIL"
    fi
fi
if [[ "$F" -ne 0 ]]; then exit 1; fi
if [[ "$MODE" == --require-xray && "$XRAY_COVER_OK" -ne 1 ]]; then
    echo 'STRICT_CHECK=INCOMPLETE: ожидается Xray TCP/443 и RAW/REALITY Selfsteal через /dev/shm/nginx.sock.'
    exit 2
fi
exit 0
VK_PAYLOAD_VK_WRITE_ACCEPTANCE
    chmod 0755 '/usr/local/sbin/vkarmani-node-check'
}

vk_write_fail2ban_config() {
    local ssh_list
    ssh_list=$(IFS=,; echo "${SSH_PORTS[*]}")
    [[ ${#SSH_PORTS[@]} -gt 0 && ${#SSH_PORTS[@]} -le 15 ]] || return 1
    install -d -m 0755 /etc/fail2ban/action.d /etc/fail2ban/jail.d
    cat > /etc/fail2ban/action.d/vkarmani-ufw-sshd.conf <<'VK_F2B_ACTION'
[Definition]
actionstart =
actionstop =
actioncheck = LC_ALL=C /usr/sbin/ufw status | /usr/bin/grep -q '^Status: active$'
actionban = /usr/sbin/ufw insert 1 deny from <ip> to any port <port> proto tcp comment 'VKarmani Fail2ban SSH'
actionunban = /usr/sbin/ufw --force delete deny from <ip> to any port <port> proto tcp
[Init]
port = 22
VK_F2B_ACTION
    cat > /etc/fail2ban/fail2ban.local <<'VK_F2B_GLOBAL'
[Definition]
allowipv6 = no
VK_F2B_GLOBAL
    cat > /etc/fail2ban/jail.d/99-vkarmani-sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $ssh_list
mode = normal
banaction = vkarmani-ufw-sshd
ignoreip = 127.0.0.1/8
usedns = no
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
bantime.maxtime = 24h
EOF
    chmod 0644 /etc/fail2ban/action.d/vkarmani-ufw-sshd.conf /etc/fail2ban/fail2ban.local /etc/fail2ban/jail.d/99-vkarmani-sshd.local
}

vk_write_maintenance() {
    install -d -m 0755 /usr/local/sbin
    local temp
    temp=$(mktemp /usr/local/sbin/vkarmani-node-maintain.tmp.XXXXXX)
    cat > "$temp" <<'VK_PAYLOAD_VK_WRITE_MAINTENANCE'
#!/usr/bin/env python3
"""Explicit, serialized maintenance for VKarmani 2.0.2; never reconfigure the OS.

Image rollback restores Compose + image only, NOT container writable-layer data,
OS packages, panel objects or user sessions. A working panel must resend its profile.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
OPT = Path('/opt/vkarmani-node')
COMPOSE = OPT / 'compose.yaml'
IMAGE_RE = re.compile(r'(?:remnawave/node|ghcr\.io/remnawave/node)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[a-f0-9]{64})?')
DIGEST_RE = re.compile(r'(?:remnawave/node|ghcr\.io/remnawave/node)@sha256:[a-f0-9]{64}')


class Failure(Exception):
    pass


def stop_command(proc):
    """Stop this command's own process group, never arbitrary host processes."""
    previous = {}
    # A repeated Ctrl-C must not interrupt reaping the command we are cancelling.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[sig] = signal.signal(sig, signal.SIG_IGN)
    try:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        # The leader may have exited while a grandchild still holds the pipes.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run(args, timeout=60):
    """Bounded local process group; captured output may contain secrets.

    Stopping a Docker client cannot cancel work already accepted by dockerd.
    A timeout during Compose apply therefore leaves the transaction pending.
    """
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True, stdin=subprocess.DEVNULL)
    except OSError as exc:
        raise Failure('COMMAND_START_FAILED: ' + Path(args[0]).name + ' errno=' + str(exc.errno)) from exc
    try:
        try:
            stdout, _stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stop_command(proc)
            raise Failure('COMMAND_TIMEOUT: ' + Path(args[0]).name) from exc
        except BaseException:
            stop_command(proc)
            raise
        if proc.returncode:
            raise Failure('COMMAND_FAILED: ' + Path(args[0]).name + ' rc=' + str(proc.returncode))
        return stdout
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()


def atomic(path, text):
    path = Path(path)
    temp = path.with_name('.' + path.name + '-' + secrets.token_hex(6))
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        # Persist the rename as well as the contents before starting Docker.
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def require_private(path):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
        raise Failure('UNSAFE_OWNER_OR_MODE: ' + str(path))


def compose_config(path):
    raw = run(['docker', 'compose', '--project-directory', str(OPT), '-f', str(path),
               'config', '--format', 'json'])
    obj = json.loads(raw)
    if obj.get('name') != 'vkarmani-node' or set(obj.get('services', {})) != {'remnanode'}:
        raise Failure('COMPOSE_PROJECT_OR_SERVICES_DRIFT')
    service = obj['services']['remnanode']
    if (service.get('network_mode') != 'host' or service.get('container_name') != 'remnanode'
            or service.get('restart') != 'always'):
        raise Failure('COMPOSE_POLICY_DRIFT')
    return service


def render_image(text, old, new):
    if not DIGEST_RE.fullmatch(old) or not DIGEST_RE.fullmatch(new):
        raise Failure('INVALID_PINNED_IMAGE')
    pattern = r'^    image: ' + re.escape(old) + r'$'
    text, count = re.subn(pattern, lambda _: '    image: ' + new, text, flags=re.M)
    if count != 1:
        raise Failure('COMPOSE_IMAGE_LINE_DRIFT: inspect local changes before updating')
    return text


def container(timeout=60):
    obj = json.loads(run(['docker', 'inspect', 'remnanode'], timeout))
    if len(obj) != 1:
        raise Failure('CONTAINER_MISSING')
    value = obj[0]
    labels = value['Config'].get('Labels') or {}
    if labels.get('com.docker.compose.project') != 'vkarmani-node' or labels.get('com.docker.compose.service') != 'remnanode':
        raise Failure('FOREIGN_CONTAINER: no change made')
    return value


def compose_up():
    run(['docker', 'compose', '-f', str(COMPOSE), 'up', '-d', '--no-deps', 'remnanode'], 180)


def xray_listens():
    return bool(re.search(r':443\s', run(['ss', '-H', '-4', '-lnt'])))


def cover_check(config, timeout=25):
    import tempfile
    fd, name = tempfile.mkstemp(prefix='.maintenance-cover-', dir=STATE)
    os.close(fd)
    path = Path(name)
    try:
        code = run(['curl', '--noproxy', '*', '-4', '--fail', '--silent', '--show-error',
                    '--http2', '--tlsv1.3', '--tls-max', '1.3', '--connect-timeout', '5',
                    '--max-time', '20', '--resolve', config['domain'] + ':443:' + config['public_ipv4'],
                    '-o', str(path), '-w', '%{http_code}', 'https://' + config['domain'] + '/'], min(25, timeout))
        if code != '200' or sha(path) != sha('/var/www/vkarmani-node/site/index.html'):
            raise Failure('XRAY_SELFSTEAL_BODY_MISMATCH')
    finally:
        path.unlink(missing_ok=True)


def healthy(config, require_xray, expected_digest, wait=180):
    # A single deadline includes image inspect, both container inspections,
    # probes and sleeps. Cancellation may add a bounded process-reaping grace.
    deadline = time.monotonic() + wait

    def remaining(limit):
        value = deadline - time.monotonic()
        if value <= 0:
            raise Failure('LOCAL_HEALTH_DEADLINE_EXCEEDED')
        return min(limit, value)

    expected_id = run(['docker', 'image', 'inspect', expected_digest, '--format', '{{.Id}}'], remaining(60)).strip()
    last = 'not checked'
    while time.monotonic() < deadline:
        try:
            before = container(remaining(30))
            if not before['State']['Running'] or before['Image'] != expected_id:
                raise Failure('NODE_NOT_RUNNING_EXPECTED_IMAGE')
            run(['/usr/local/sbin/vkarmani-node-tls-check'], remaining(40))
            run(['/usr/local/sbin/vkarmani-selfsteal-check'], remaining(25))
            if require_xray:
                cover_check(config, remaining(25))
            if remaining(5) < 5:
                raise Failure('INSUFFICIENT_STABILITY_OBSERVATION_TIME')
            time.sleep(5)
            after = container(remaining(30))
            if (not after['State']['Running'] or before['RestartCount'] != after['RestartCount']
                    or before['Id'] != after['Id']):
                raise Failure('NODE_RESTARTING')
            return
        except Failure as exc:
            last = str(exc)
            pause = min(2, max(0, deadline - time.monotonic()))
            if pause:
                time.sleep(pause)
    raise Failure('NODE_READINESS_FAILED: ' + last)


def write_backup_archive(folder, paths, source_root=Path('/')):
    """Archive the selected paths; alternate root is for isolated fixture tests."""
    listing = folder / 'FILES.txt'
    atomic(listing, '\n'.join(paths) + '\n')
    archive = folder / 'node-config.tar.gz'
    archive.touch(mode=0o600, exist_ok=False)
    # No running Docker data directory, swap contents or recursively nested backups.
    run(['tar', '--acls', '--xattrs', '--numeric-owner', '-C', str(source_root), '-czf', str(archive),
         '--verbatim-files-from', '-T', str(listing)], 180)
    archive.chmod(0o600)
    with archive.open('rb') as stream:
        os.fsync(stream.fileno())
    run(['tar', '-tzf', str(archive)], 120)
    digest = sha(archive)
    atomic(folder / 'SHA256SUMS', digest + '  node-config.tar.gz\n')
    # Check the actual archive a second time, not merely the checksum file format.
    if sha(archive) != digest:
        raise Failure('BACKUP_HASH_MISMATCH')
    return archive


def backup():
    if shutil.disk_usage(STATE).free < 512 * 1024 * 1024:
        raise Failure('BACKUP_REQUIRES_512_MIB_FREE')
    folder = STATE / 'backups' / ('maintenance-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
    folder.mkdir(parents=True, mode=0o700)
    paths = [
        'etc/vkarmani-node', 'opt/vkarmani-node', 'usr/local/lib/vkarmani-node',
        'etc/ssh', 'etc/ufw', 'etc/default/ufw', 'etc/fail2ban', 'etc/nginx',
        'etc/docker', 'etc/letsencrypt', 'etc/default/grub', 'etc/default/grub.d',
        'etc/sysctl.d', 'etc/modules-load.d', 'etc/tmpfiles.d', 'etc/chrony',
        'etc/default/chrony', 'etc/fstab', 'etc/apt/apt.conf.d', 'etc/apt/keyrings',
        'etc/apt/sources.list.d', 'etc/systemd/system', 'etc/systemd/journald.conf.d',
        'etc/logrotate.d', 'var/www/vkarmani-node']
    paths += [str(x.relative_to('/')) for x in Path('/usr/local/sbin').glob('vkarmani-*') if x.is_file()]
    paths += [str(x.relative_to('/')) for x in STATE.iterdir() if x.is_file()]
    paths = sorted(set(x for x in paths if Path('/' + x).exists()))
    write_backup_archive(folder, paths)
    atomic(STATE / 'latest-maintenance-backup-path', str(folder) + '\n')
    print('BACKUP_CONFIG=PASS ' + str(folder), flush=True)
    print('Contains secrets; copy off-host securely. Not a VPS/container/panel snapshot.', flush=True)
    return folder


def read_transaction(pointer):
    require_private(pointer)
    path = Path(pointer.read_text().strip())
    root = STATE / 'image-transactions'
    if path.parent != root or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', path.name):
        raise Failure('INVALID_IMAGE_TRANSACTION_PATH')
    require_private(path)
    require_private(path / 'meta.json')
    meta = json.loads((path / 'meta.json').read_text())
    for key in ('previous', 'candidate'):
        if not isinstance(meta.get(key), str) or not DIGEST_RE.fullmatch(meta[key]):
            raise Failure('INVALID_TRANSACTION_IMAGE')
    if type(meta.get('require_xray')) is not bool:
        raise Failure('INVALID_TRANSACTION_HEALTH_POLICY')
    for name in ('previous.compose.yaml', 'candidate.compose.yaml'):
        require_private(path / name)
        if sha(path / name) != meta.get(name + '.sha256'):
            raise Failure('TRANSACTION_CHECKSUM_MISMATCH')
    if sha(COMPOSE) not in {meta['previous.compose.yaml.sha256'], meta['candidate.compose.yaml.sha256']}:
        raise Failure('COMPOSE_CHANGED_OUTSIDE_TRANSACTION: manual audit required')
    return path, meta


def restore(path, meta, config):
    # Called explicitly or from a failed update, never on a timer.
    previous = path / 'previous.compose.yaml'
    if compose_config(previous).get('image') != meta['previous']:
        raise Failure('ROLLBACK_IMAGE_DRIFT')
    run(['docker', 'image', 'inspect', meta['previous'], '--format', '{{.Id}}'])
    atomic(COMPOSE, previous.read_text())
    compose_up()
    healthy(config, meta['require_xray'], meta['previous'])
    atomic(STATE / 'image-digest', meta['previous'] + '\n')
    (STATE / 'image-update-pending').unlink(missing_ok=True)
    atomic(path / 'ROLLED_BACK', dt.datetime.now(dt.timezone.utc).isoformat() + '\n')
    print('IMAGE_ROLLBACK_LOCAL=PASS; PANEL_MTLS_AND_CLIENT_TRAFFIC=NOT_VERIFIED', flush=True)


def refresh(config, override):
    pending = STATE / 'image-update-pending'
    if pending.exists():
        raise Failure('IMAGE_UPDATE_PENDING: use rollback-image before another update')
    source = override or config['image']
    if not isinstance(source, str) or not IMAGE_RE.fullmatch(source):
        raise Failure('ONLY_OFFICIAL_REMNAWAVE_IMAGE_ALLOWED')
    old = (STATE / 'image-digest').read_text().strip()
    if not DIGEST_RE.fullmatch(old) or compose_config(COMPOSE).get('image') != old:
        raise Failure('COMPOSE_DIGEST_DRIFT')
    current = container()
    image = json.loads(run(['docker', 'image', 'inspect', old]))[0]
    if current['Image'] != image['Id'] or not current['State']['Running']:
        raise Failure('CURRENT_CONTAINER_DRIFT_OR_STOPPED')
    docker_root = run(['docker', 'info', '--format', '{{.DockerRootDir}}']).strip()
    if not docker_root.startswith('/'):
        raise Failure('DOCKER_ROOT_DIRECTORY_INVALID')
    if shutil.disk_usage(docker_root).free < max(2 * 1024**3, 2 * int(image.get('Size', 0))):
        raise Failure('IMAGE_UPDATE_REQUIRES_FREE_DISK: at least 2 GiB and twice current image size')
    require_xray = xray_listens()
    healthy(config, require_xray, old, wait=60)
    bk = backup()
    print('Pulling requested official image; current node remains running.', flush=True)
    run(['docker', 'pull', source], 900)
    repository = source.split('@')[0].split(':')[0]
    digests = json.loads(run(['docker', 'image', 'inspect', source, '--format', '{{json .RepoDigests}}'])) or []
    candidates = [d for d in digests if DIGEST_RE.fullmatch(d) and d.startswith(repository + '@')]
    if '@sha256:' in source:
        requested = repository + '@' + source.split('@', 1)[1]
        candidates = [d for d in candidates if d == requested]
    if len(candidates) != 1:
        raise Failure('CANDIDATE_DIGEST_AMBIGUOUS_OR_MISSING')
    new = candidates[0]
    if new == old:
        print('IMAGE_UNCHANGED; no container recreation.', flush=True)
        return
    candidate = render_image(COMPOSE.read_text(), old, new)
    root = STATE / 'image-transactions'
    root.mkdir(mode=0o700, exist_ok=True)
    path = root / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    path.mkdir(mode=0o700)
    atomic(path / 'previous.compose.yaml', COMPOSE.read_text())
    atomic(path / 'candidate.compose.yaml', candidate)
    if compose_config(path / 'candidate.compose.yaml').get('image') != new:
        raise Failure('CANDIDATE_COMPOSE_INVALID')
    meta = {'previous': old, 'candidate': new, 'require_xray': require_xray, 'backup': str(bk)}
    for name in ('previous.compose.yaml', 'candidate.compose.yaml'):
        meta[name + '.sha256'] = sha(path / name)
    atomic(path / 'meta.json', json.dumps(meta, indent=2) + '\n')
    run(['docker', 'tag', old, 'remnawave/node:vkarmani-rollback'])
    atomic(pending, str(path) + '\n')
    applying = False
    try:
        print('Applying candidate; existing client sessions may disconnect.', flush=True)
        atomic(COMPOSE, candidate)
        applying = True
        compose_up()
        applying = False
        healthy(config, require_xray, new)
        atomic(STATE / 'image-digest', new + '\n')
        atomic(STATE / 'last-image-transaction', str(path) + '\n')
        atomic(path / 'COMMITTED', dt.datetime.now(dt.timezone.utc).isoformat() + '\n')
        pending.unlink()
    except (Exception, KeyboardInterrupt) as exc:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        if applying and (isinstance(exc, KeyboardInterrupt)
                         or str(exc).startswith(('COMMAND_TIMEOUT:', 'INTERRUPTED signal='))):
            print('IMAGE_APPLY=UNKNOWN; Docker may still be applying the request. '
                  'Pending marker retained; inspect Docker before explicit rollback-image.',
                  file=sys.stderr, flush=True)
            raise
        print('IMAGE_UPDATE=FAIL; attempting previous image (not a full data rollback).', file=sys.stderr, flush=True)
        try:
            restore(path, meta, config)
        except Exception:
            print('IMAGE_ROLLBACK=NOT_CONFIRMED; pending marker retained; use provider console.', file=sys.stderr)
        raise
    print('IMAGE_UPDATE_LOCAL=PASS ' + new, flush=True)
    print('PANEL_MTLS_AND_CLIENT_TRAFFIC=NOT_VERIFIED; verify the panel and a real client.', flush=True)


def interrupted(signum, _frame):
    raise Failure('INTERRUPTED signal=' + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backup', 'refresh-image', 'rollback-image'])
    parser.add_argument('--image')
    args = parser.parse_args()
    if args.image and args.action != 'refresh-image':
        parser.error('--image is only valid for refresh-image')
    os.umask(0o077)
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    if os.geteuid() != 0:
        raise Failure('ROOT_REQUIRED')
    for path in (ETC, STATE, OPT, COMPOSE, ETC / 'remnanode.env', ETC / 'config.json'):
        require_private(path)
    if (not (STATE / 'owned-installation').is_file()
            or 'version=2.0.2' not in (STATE / 'INSTALL_COMPLETE').read_text().splitlines()):
        raise Failure('ONLY_COMPLETED_2_0_2_SUPPORTED; legacy installation is not migrated')
    with open('/run/lock/vkarmani-node-installer.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Failure('ANOTHER_INSTALL_OR_MAINTENANCE_IS_RUNNING') from exc
        config = json.loads((ETC / 'config.json').read_text())
        # Let the installed validation helper validate schema, not ad-hoc shell parsing.
        run(['python3', '/usr/local/lib/vkarmani-node/node_helper.py', 'get', 'domain'])
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        if args.action == 'backup':
            backup()
        elif args.action == 'refresh-image':
            refresh(config, args.image)
        else:
            pending = STATE / 'image-update-pending'
            pointer = pending if pending.exists() else STATE / 'last-image-transaction'
            if not pointer.exists():
                raise Failure('NO_PREVIOUS_IMAGE_TRANSACTION')
            path, meta = read_transaction(pointer)
            backup()
            atomic(pending, str(path) + '\n')
            restore(path, meta, config)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Failure as exc:
        print('MAINTENANCE=FAIL ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('MAINTENANCE=FAIL INTERNAL_OR_STATE_ERROR (no secrets displayed)', file=sys.stderr)
        sys.exit(1)
VK_PAYLOAD_VK_WRITE_MAINTENANCE
    chmod 0700 "$temp"
    mv -f "$temp" /usr/local/sbin/vkarmani-node-maintain
}

# Read-only preflight; source-safe and independent of Python/APT/ufw commands.
# Accept only an empty filter skeleton and the exact unreferenced UFW limit helpers.
# A name-only exclusion of ufw-user-limit* would hide edits to those chains.
vk_ufw_saved_rules_pristine() {
    local file=$1 prefix=$2
    case "$prefix" in ufw|ufw6) ;; *) return 2 ;; esac
    [[ -e "$file" || -L "$file" ]] || return 0
    if [[ -L "$file" || ! -f "$file" || ! -r "$file" ]]; then
        printf 'UFW_SAVED_RULES=REFUSE file=%s reason=NOT_READABLE_REGULAR_FILE\n' "$file" >&2
        return 1
    fi
    LC_ALL=C awk -v p="$prefix" '
        function refuse(reason) {
            if (!bad) printf "UFW_SAVED_RULES=REFUSE file=%s line=%d reason=%s\n", FILENAME, FNR, reason > "/dev/stderr"
            bad=1; exit 1
        }
        BEGIN {
            allowed[p "-user-input"]=1; allowed[p "-user-output"]=1; allowed[p "-user-forward"]=1
            allowed[p "-user-limit"]=1; allowed[p "-user-limit-accept"]=1
            stock["-A " p "-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \""]=1
            stock["-A " p "-user-limit -j REJECT"]=1
            stock["-A " p "-user-limit-accept -j ACCEPT"]=1
        }
        {
            line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
            if (line ~ /^###[ \t]+tuple([ \t]|$)/) refuse("USER_RULE_METADATA")
            if (line == "" || line ~ /^#/) next
            if (line == "*filter") {
                if (stage != 0) refuse("DUPLICATE_OR_MISPLACED_FILTER")
                stage=1; next
            }
            if (stage != 1) refuse("OUTSIDE_FILTER")
            if (line == "COMMIT") { stage=2; next }
            if (line ~ /^:/) {
                n=split(line, fields, /[ \t]+/); name=substr(fields[1], 2)
                if (n != 3 || !(name in allowed) || fields[2] != "-" ||
                    fields[3] !~ /^\[[0-9]+:[0-9]+\]$/ || declared[name]++) refuse("NONSTANDARD_CHAIN")
                next
            }
            if (line in stock) {
                if (!declared[p "-user-limit"] || !declared[p "-user-limit-accept"] || seen[line]++) refuse("NONSTANDARD_LIMIT_HELPERS")
                helpers++; next
            }
            refuse("USER_RULE_OR_UNKNOWN_DIRECTIVE")
        }
        END {
            if (bad) exit 1
            if (stage != 2 || !declared[p "-user-input"] || !declared[p "-user-output"] ||
                !declared[p "-user-forward"]) refuse("INCOMPLETE_FILTER")
            if ((declared[p "-user-limit"] || declared[p "-user-limit-accept"]) && helpers != 3) refuse("INCOMPLETE_LIMIT_HELPERS")
        }
    ' "$file"
}

vk_check_saved_ufw_rules() {
    local directory=${1:-/etc/ufw}
    vk_ufw_saved_rules_pristine "$directory/user.rules" ufw &&
        vk_ufw_saved_rules_pristine "$directory/user6.rules" ufw6
}

# Stream-safe entry point: the complete function must parse before any setup runs.
vkarmani_main() {
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
# VKarmani Remnawave Node Installer 2.0.2 — 2026-09-30
# Dedicated fresh Ubuntu 22.04/24.04 or Debian 12/13, systemd + GRUB, amd64/arm64.
# One self-contained file; no remote shell scripts are downloaded/executed.
# WARNING: installs packages, modifies SSH/firewall/boot settings; reboot is opt-in.
# Node-only mode: does not create or edit panel objects. RAW+REALITY Selfsteal uses an Nginx Unix socket.
set -Eeuo pipefail
set +x
set +a
umask 077
export LC_ALL=C LANG=C PYTHONUTF8=1 DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset CDPATH ENV BASH_ENV
INSTALLER_VERSION=2.0.2
ETC=/etc/vkarmani-node
STATE=/var/lib/vkarmani-node
LIB=/usr/local/lib/vkarmani-node
OPT=/opt/vkarmani-node
LOG=/var/log/vkarmani-node-install.log
# The panel IPv4 is entered on first run. The node IPv4 is never asked: it is selected from DNS + local interfaces.
NODE_PORT_DEFAULT=2222
NO_REBOOT=1
WEEKLY_REBOOT=0
ALLOW_NET_ADMIN=0
IMAGE_OVERRIDE=''

usage() {
    cat <<'HELP'
VKarmani Remnawave Node Installer 2.0.2

  sudo bash install.sh                         # установка / безопасный повторный запуск
  sudo bash install.sh --reboot                # явное разрешение одного reboot после проверок
  sudo bash install.sh --weekly-reboot         # необязательно: понедельник 04:00 МСК
  sudo bash install.sh --allow-net-admin       # только при необходимости IP-management plugins
  sudo bash install.sh --backup                # закрытая копия конфигурации с SHA256
  sudo bash install.sh --image remnawave/node@sha256:DIGEST
  sudo bash install.sh --check                 # существующая локальная диагностика
  sudo bash install.sh --refresh-image         # только обновление образа, без настройки ОС
  sudo bash install.sh --rollback-image        # предыдущий образ, без APT/firewall/SSH
  sudo bash install.sh --repair-network        # узкое исправление нашей завершённой 1.3.x
  sudo bash install.sh --repair-node           # узкое исправление нашей завершённой 1.3.x
  bash install.sh --version

Три обязательных значения: SECRET_KEY → домен ноды → исходящий IPv4 технички.
IP самой ноды выбирается по DNS среди публичных IPv4 её интерфейсов.
Чистая выделенная Ubuntu 22.04/24.04 или Debian 12/13; amd64/arm64; systemd + GRUB.
Минимум: 900 MiB RAM, 6 GiB свободно. NAT, LXC/OpenVZ, IPv6 SSH, чужая установка не поддержаны.
SSH: парольный вход, существующие порты, без IP-allowlist. Пароли/аккаунты не создаются.
До запуска нужны снимок VPS, консоль хостера и действующий пароль администратора.
IPv6: runtime sysctl + GRUB; для полного отключения socket API необходим reboot.
Полного обновления ОС, autoremove, prune, смены MTU/маршрутов и автоперезагрузки по умолчанию нет.
Nginx на хосте. Клиентский 443 принадлежит Xray; API 2222 разрешён только с IP технички.
SECRET_KEY не даёт административного API панели: Node/Profile/Host/Squad назначаются в панели.
Let's Encrypt: HTTP-01, порт 80, аккаунт без email; запуск означает согласие с условиями CA.
--no-reboot сохранён как совместимый явный запрет reboot. --image не является четвёртым вопросом.
HELP
}
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --no-reboot) NO_REBOOT=1; shift ;;
        --reboot) NO_REBOOT=0; shift ;;
        --weekly-reboot) WEEKLY_REBOOT=1; shift ;;
        --allow-net-admin) ALLOW_NET_ADMIN=1; shift ;;
        --image)
            [[ $# -ge 2 ]] || { echo '--image requires an official image reference' >&2; exit 2; }
            IMAGE_OVERRIDE=$2; shift 2 ;;
        --version) echo "$INSTALLER_VERSION"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
# Three inputs before any APT/network/boot changes. No Python/curl dependency here.
# This file is embedded in install.sh, not downloaded at run time.
vk_input_error() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
vk_trim() {
    local value=$1
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}
vk_validate_ipv4() {
    local value=$1 octet
    local -a parts=()
    [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for octet in "${parts[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    # Early reject of local/reserved addresses. Python revalidates is_global after APT.
    ((parts[0] > 0 && parts[0] < 224)) || return 1
    case "$value" in
        10.*|127.*|169.254.*|192.168.*|192.0.1.*|192.0.2.*|198.51.100.*|203.0.113.*) return 1 ;;
    esac
    if ((parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31)); then return 1; fi
    if ((parts[0] == 100 && parts[1] >= 64 && parts[1] <= 127)); then return 1; fi
    if ((parts[0] == 198 && (parts[1] == 18 || parts[1] == 19))); then return 1; fi
}
vk_validate_domain() {
    local value=$1 part
    local -a parts=()
    [[ ${#value} -le 253 && "$value" == *.* && "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
    [[ ! "$value" =~ ^[0-9.]+$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for part in "${parts[@]}"; do
        [[ ${#part} -ge 1 && ${#part} -le 63 && "$part" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}
vk_restore_tty() {
    if [[ -n "${VK_TTY_STATE:-}" && -n "${VK_TTY_FD:-}" ]]; then
        stty "$VK_TTY_STATE" <&"$VK_TTY_FD" 2>/dev/null || true
        VK_TTY_STATE=''
    fi
}
vk_collect_inputs() {
    # Never inherit exported attributes or tracing for a credential variable.
    set +x
    set +a
    unset VK_INPUT_SECRET VK_INPUT_PANEL_IP VK_INPUT_DOMAIN
    VK_INPUT_SECRET='' VK_INPUT_PANEL_IP='' VK_INPUT_DOMAIN=''
    if [[ -s "$ETC/config.json" ]]; then
        printf 'Повторный запуск: используются сохранённые параметры; вопросов нет.\n'
        return 0
    fi
    if [[ -f "$ETC/inputs.pending" ]]; then
        [[ ! -L "$ETC/inputs.pending" && $(stat -c '%u:%a' "$ETC/inputs.pending") == 0:600 ]] || {
            vk_input_error 'Небезопасные права inputs.pending; требуется root:0600.'; return 1;
        }
        local -a saved=()
        mapfile -t saved < "$ETC/inputs.pending"
        [[ ${#saved[@]} -eq 3 ]] || { vk_input_error 'Повреждён inputs.pending.'; return 1; }
        VK_INPUT_SECRET=${saved[0]}; VK_INPUT_PANEL_IP=${saved[1]}; VK_INPUT_DOMAIN=${saved[2]}
        [[ "$VK_INPUT_SECRET" =~ ^[A-Za-z0-9_+/=-]{64,65536}$ ]] || return 1
        vk_validate_ipv4 "$VK_INPUT_PANEL_IP" && vk_validate_domain "$VK_INPUT_DOMAIN" || return 1
        unset saved
        printf 'Продолжение: три значения восстановлены из закрытого inputs.pending; вопросов нет.\n'
        return 0
    fi
    command -v stty >/dev/null || { vk_input_error 'Требуется stty (coreutils).'; return 1; }
    exec {VK_TTY_FD}<>/dev/tty || { vk_input_error 'Нужен интерактивный SSH-терминал (при ssh-команде используйте ssh -t).'; return 1; }
    VK_TTY_STATE=$(stty -g <&"$VK_TTY_FD") || return 1
    trap 'vk_restore_tty' EXIT
    trap 'vk_restore_tty; exit 130' INT
    trap 'vk_restore_tty; exit 143' TERM
    trap 'vk_restore_tty; exit 129' HUP
    printf '\nVKarmani: SECRET_KEY → домен ноды → IPv4 технички.\n' >&"$VK_TTY_FD"
    printf 'IPv4 самой ноды НЕ спрашивается: он выбирается автоматически по DNS из адресов VPS.\n' >&"$VK_TTY_FD"
    printf 'После трёх значений — автоматическая установка. Reboot только с --reboot. Нужны снимок VPS и консоль хостера.\n' >&"$VK_TTY_FD"
    printf 'Будут изменены firewall/загрузка, отключён IPv6; условия Let\047s Encrypt принимаются автоматически.\n' >&"$VK_TTY_FD"
    printf 'Если у хостера есть внешний firewall/security group: TCP/2222 должен быть разрешён с IPv4 панели.\n\n' >&"$VK_TTY_FD"
    # Noncanonical mode also permits long (>4096 byte) single-line SECRET_KEY bundles.
    # Disable echo BEFORE displaying the prompt, so immediate paste cannot reveal the key.
    stty -echo -icanon min 1 time 0 <&"$VK_TTY_FD"
    printf '[1/3] SECRET_KEY ноды (скрытый ввод): ' >&"$VK_TTY_FD"
    if ! IFS= read -r -u "$VK_TTY_FD" VK_INPUT_SECRET; then
        vk_restore_tty; vk_input_error 'Ввод SECRET_KEY прерван.'; return 1
    fi
    vk_restore_tty
    printf '\n' >&"$VK_TTY_FD"
    VK_INPUT_SECRET=$(vk_trim "$VK_INPUT_SECRET")
    if [[ "$VK_INPUT_SECRET" == SECRET_KEY=* ]]; then VK_INPUT_SECRET=${VK_INPUT_SECRET#SECRET_KEY=}; fi
    if [[ "$VK_INPUT_SECRET" == \"*\" || "$VK_INPUT_SECRET" == \'*\' ]]; then
        VK_INPUT_SECRET=${VK_INPUT_SECRET:1:${#VK_INPUT_SECRET}-2}
    fi
    [[ ${#VK_INPUT_SECRET} -ge 64 && ${#VK_INPUT_SECRET} -le 65536 && "$VK_INPUT_SECRET" =~ ^[A-Za-z0-9_+/=-]+$ ]] || {
        unset VK_INPUT_SECRET; vk_input_error 'Некорректный формат SECRET_KEY. Вставьте значение из панели одной строкой.'; return 1;
    }
    printf '[2/3] Домен ноды (например, ee1.example.com): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_DOMAIN || { vk_input_error 'Ввод домена прерван.'; return 1; }
    VK_INPUT_DOMAIN=$(vk_trim "$VK_INPUT_DOMAIN")
    VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN,,}; VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN%.}
    vk_validate_domain "$VK_INPUT_DOMAIN" || { vk_input_error 'Некорректный домен: без https://, порта и пути; IDN в punycode.'; return 1; }
    printf '[3/3] Публичный исходящий IPv4 технички (backend панели): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_PANEL_IP || { vk_input_error 'Ввод IPv4 панели прерван.'; return 1; }
    VK_INPUT_PANEL_IP=$(vk_trim "$VK_INPUT_PANEL_IP")
    vk_validate_ipv4 "$VK_INPUT_PANEL_IP" || { vk_input_error 'Некорректный публичный IPv4 панели.'; return 1; }
    exec {VK_TTY_FD}>&-
    unset VK_TTY_FD
    trap - EXIT INT TERM HUP
    printf '\nВсе три значения приняты. IPv4 ноды будет выбран автоматически; SECRET_KEY не выводится.\n'
}
[[ $EUID -eq 0 ]] || { echo 'Запустите через sudo bash или от root.' >&2; exit 1; }
if [[ -s "$STATE/INSTALL_COMPLETE" ]]; then
    echo 'Установка уже завершена. Повторный обычный запуск выполняет только диагностику.'
    echo 'Настройки, образ, ключи, firewall и расписание НЕ меняются. Образ: --refresh-image; 1.3.x: --repair-node.'
    [[ -x /usr/local/sbin/vkarmani-node-check ]] || { echo 'Диагностическая команда отсутствует; требуется разбор состояния.'; exit 1; }
    if [[ -e "$STATE/image-update-pending" ]]; then
        echo 'Есть незавершённая транзакция образа. Сначала выполните --rollback-image.'; exit 1
    fi
    if grep -w 'ipv6.disable=1' /proc/cmdline >/dev/null; then
        /usr/local/sbin/vkarmani-node-check --local
    else
        /usr/local/sbin/vkarmani-node-check --preboot
    fi
    return
fi
if [[ -e "$STATE/network-rollback-armed" || -e "$STATE/network-rollback-running" ]]; then
    echo 'STOP: не завершён сетевой откат. Используйте консоль VPS и /usr/local/sbin/vkarmani-network-rollback; не удаляйте backup.'; exit 1
fi
if [[ -f "$STATE/owned-installation" ]]; then
    [[ -f "$STATE/install-version" && $(cat "$STATE/install-version") == "$INSTALLER_VERSION" ]] || {
        echo 'STOP: незавершённая установка другой версии. Не смешиваю поколения установщика; используйте исходную версию или снимок VPS.'; exit 1;
    }
fi
[[ -z "$IMAGE_OVERRIDE" || "$IMAGE_OVERRIDE" =~ ^(remnawave/node|ghcr\.io/remnawave/node)(:[A-Za-z0-9_.-]+)?(@sha256:[a-f0-9]{64})?$ ]] || {
    echo 'STOP: --image допускает только официальный remnawave/node или ghcr.io/remnawave/node.'; exit 2;
}
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo 'Bash >= 4 required' >&2; exit 1; }
command -v flock >/dev/null || { echo 'util-linux/flock required' >&2; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/vkarmani-node-installer.lock
flock -n 9 || { echo 'Установщик уже запущен.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'Требуется сервер с systemd.' >&2; exit 1; }
if systemd-detect-virt --container --quiet; then
    echo 'LXC/OpenVZ/Docker не поддерживаются: ядро и полное отключение IPv6 контролирует хост.' >&2
    exit 1
fi
[[ -r /etc/os-release ]] || exit 1
# Only distro-owned os-release is sourced. User input is always JSON, never shell.
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) echo "ОС вне поддерживаемого списка: ${PRETTY_NAME:-unknown}. Никаких изменений не выполнено." >&2; exit 1 ;;
esac
OS_ID=$ID
OS_CODENAME=$VERSION_CODENAME
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) echo 'Только amd64/arm64' >&2; exit 1 ;; esac
[[ -f /boot/grub/grub.cfg && -f /etc/default/grub ]] && command -v update-grub >/dev/null || {
    echo 'Нужна загрузка через GRUB: update-grub, /boot/grub/grub.cfg, /etc/default/grub.' >&2; exit 1;
}
if _contains -al 'systemd-boot' /sys/firmware/efi/efivars/LoaderInfo-* 2>/dev/null; then
    echo 'Обнаружен systemd-boot, этот установщик изменяет только GRUB. Остановка.' >&2; exit 1
fi
[[ "${SSH_CONNECTION:-}" != *:* ]] || { echo 'Текущая SSH-сессия использует IPv6. Сначала подключитесь по IPv4.' >&2; exit 1; }
[[ -x /usr/sbin/sshd ]] || { echo 'Требуется установленный OpenSSH server.' >&2; exit 1; }
install -d -o root -g root -m 0755 /run/sshd
/usr/sbin/sshd -t
MEM_MB=$(awk '/MemTotal:/{print int($2/1024)}' /proc/meminfo)
FREE_MB=$(df -Pm / | awk 'NR==2{print $4}')
[[ "$MEM_MB" -ge 900 && "$FREE_MB" -ge 6144 ]] || {
    echo "Нужно >=900 MiB RAM и >=6144 MiB свободного места. Сейчас RAM=$MEM_MB, disk=$FREE_MB MiB." >&2; exit 1;
}
[[ -z "$(dpkg --audit)" ]] || { echo 'dpkg сообщает незавершённые операции. Исправьте пакетную базу прежде установки.' >&2; exit 1; }
# Never overwrite the only pre-change access backup while its guard is pending.
for marker in network-rollback-armed network-rollback-running; do
    if [[ -e "$STATE/$marker" ]]; then
        echo 'STOP: незавершённый SSH/UFW rollback. Проверьте консоль и выполните существующий vkarmani-network-rollback; повторная установка не трогает backup.' >&2
        exit 1
    fi
done
FRESH=1
[[ -f "$STATE/owned-installation" ]] && FRESH=0
if [[ $FRESH -eq 0 && -f "$ETC/config.json" ]] && ! grep -F '"installation_mode": "secret-key-only"' "$ETC/config.json" >/dev/null; then
    echo 'Найдена установка другой версии/режима. Этот вариант не мигрирует API-установку: используйте чистую VPS.' >&2
    exit 1
fi
if [[ $FRESH -eq 1 ]]; then
    for p in "$ETC" "$OPT" /etc/vkarmani /opt/remnanode /opt/remnawave; do
        [[ ! -e "$p" ]] || { echo "Уже существует $p. Автоматическая миграция/удаление не выполняется." >&2; exit 1; }
    done
    if command -v docker >/dev/null; then
        [[ -z "$(docker ps -aq 2>/dev/null)" ]] || { echo 'Найдены чужие Docker containers. Нужна выделенная чистая VPS.' >&2; exit 1; }
    fi
    if command -v ufw >/dev/null && ufw status | _contains -F 'Status: active'; then
        echo 'UFW уже активен. Чужой firewall не перезаписывается: используйте чистую VPS.' >&2; exit 1
    fi
    for service in firewalld nftables netfilter-persistent nginx apache2 caddy; do
        if systemctl is-active --quiet "$service"; then
            echo "Активен $service. Нужна чистая выделенная VPS, без старого web/firewall стека." >&2; exit 1
        fi
    done
    if ss -H -lnt | awk '{print $4}' | _contains -E ':(80|443)$'; then
        echo 'Порты 80/443 уже заняты.' >&2; exit 1
    fi
    # Refuse a separate unmanaged nftables/iptables ruleset, even when its unit is inactive.
    if command -v nft >/dev/null && [[ -n "$(nft list tables 2>/dev/null)" ]]; then
        echo 'Обнаружены существующие nftables tables. Нужен чистый firewall.' >&2; exit 1
    fi
    for save in iptables-save iptables-legacy-save; do
        if command -v "$save" >/dev/null; then
            RULESET=$("$save") || { echo 'STOP: не удалось прочитать firewall.'; exit 1; }
            if printf '%s\n' "$RULESET" | _contains -E '^-A |^:[^ ]+ (DROP|REJECT|-) '; then
                echo 'STOP: найдены чужие iptables rules/chains/policies. Не сбрасываю.'; exit 1
            fi
        fi
    done
    if ! vk_check_saved_ufw_rules; then
        echo 'STOP: UFW содержит сохранённые пользовательские правила или нестандартный user.rules/user6.rules. Не сбрасываю firewall.' >&2; exit 1
    fi
    for p in /etc/docker/daemon.json /etc/nginx/conf.d /etc/nginx/sites-enabled; do
        if [[ -f "$p" ]] || { [[ -d "$p" ]] && find "$p" -mindepth 1 -maxdepth 1 ! -name default -print -quit | _contains .; }; then
            echo "Найдена пользовательская конфигурация $p. Не перезаписываю." >&2; exit 1
        fi
    done
fi
for package in docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | _contains -F 'ok installed'; then
        echo "STOP: конфликтующий пакет $package. Автоматически не удаляю." >&2; exit 1
    fi
done
# Fail closed on customized SSH policy rather than silently removing access restrictions.
LOGIN_USER=${SUDO_USER:-root}
[[ "$LOGIN_USER" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*[$]?$ ]] || { echo 'STOP: нестандартное имя администратора.'; exit 1; }
[[ $(passwd -S "$LOGIN_USER" | awk '{print $2}') == P ]] || {
    echo "STOP: у $LOGIN_USER нет действующего локального пароля. Задайте его через консоль хостера и повторите. Пароль установщик не спрашивает и не меняет."; exit 1;
}
SSH_EFFECTIVE=$(/usr/sbin/sshd -T)
if printf '%s\n' "$SSH_EFFECTIVE" | _contains -E '^(allowusers|denyusers|allowgroups|denygroups) '; then
    echo 'STOP: обнаружены пользовательские ограничения SSH. Они не снимаются вслепую.'; exit 1
fi
# On a clean supported image includes live under /etc/ssh. Refuse Match policies;
# effective sshd -T alone does not prove what all remote addresses will inherit.
SSH_CONFIG_FILES=(/etc/ssh/sshd_config)
for f in /etc/ssh/sshd_config.d/*.conf; do [[ ! -f "$f" ]] || SSH_CONFIG_FILES+=("$f"); done
if grep -Ei '^[[:space:]]*(Match|AllowUsers|DenyUsers|AllowGroups|DenyGroups)[[:space:]]' "${SSH_CONFIG_FILES[@]}" | _contains .; then
    echo 'STOP: SSH Match/Allow/Deny требует ручного аудита. Чужая политика не перезаписывается.'; exit 1
fi
while IFS= read -r line; do
    line=${line%%#*}
    read -r keyword include_path extra <<< "$line"
    [[ ${keyword,,} != include ]] || {
        [[ "$include_path" == /etc/ssh/sshd_config.d/'*.conf' && -z "${extra:-}" ]] || {
            echo 'STOP: нестандартный SSH Include требует ручного аудита.'; exit 1;
        }
    }
done < <(cat "${SSH_CONFIG_FILES[@]}")
if printf '%s\n' "$SSH_EFFECTIVE" | _contains -E '^listenaddress \['; then
    # sshd -T prints [::]:22 even for the default wildcard. Only refuse explicit
    # IPv6 ListenAddress directives, not its synthesized default effective output.
    if grep -Ei '^[[:space:]]*ListenAddress[[:space:]]+[^#]*:' "${SSH_CONFIG_FILES[@]}" | _contains -vE ':[0-9]+([[:space:]]|$)'; then
        echo 'STOP: явный IPv6 ListenAddress несовместим с IPv4-only. Нужен аудит SSH.'; exit 1
    fi
fi
unset SSH_EFFECTIVE
if [[ $FRESH -eq 1 ]]; then
    APT_SOURCE_PATHS=(/etc/apt/sources.list.d)
    [[ ! -f /etc/apt/sources.list ]] || APT_SOURCE_PATHS+=(/etc/apt/sources.list)
    if grep -rF 'download.docker.com' "${APT_SOURCE_PATHS[@]}" 2>/dev/null | _contains .; then
        echo 'STOP: уже настроен чужой Docker APT repository. Не дублирую Signed-By/источники.'; exit 1
    fi
    [[ ! -e /swapfile-vkarmani ]] || { echo 'STOP: /swapfile-vkarmani уже существует без маркера нашей установки.'; exit 1; }
fi
# Input is from /dev/tty, never from the downloaded shell script stream.
vk_collect_inputs
# Package maintainer scripts must not read answers from the operator's terminal.
# All installer questions have been answered; unexpected package prompts fail safely.
exec </dev/null
install -d -m 0700 "$ETC" "$STATE" "$LIB" "$OPT"
if [[ ! -s "$ETC/config.json" ]]; then
    printf '%s\n%s\n%s\n' "$VK_INPUT_SECRET" "$VK_INPUT_PANEL_IP" "$VK_INPUT_DOMAIN" > "$ETC/inputs.pending.tmp"
    chmod 0600 "$ETC/inputs.pending.tmp"
    mv -f "$ETC/inputs.pending.tmp" "$ETC/inputs.pending"
fi
printf '%s\n' "$INSTALLER_VERSION" > "$STATE/install-version"
touch "$STATE/owned-installation"
touch "$LOG"; chmod 0600 "$LOG"
# No xtrace, no printing of SECRET_KEY, private keys or Docker environment.
exec > >(exec 9>&-; tee -a "$LOG") 2>&1
stage() { printf '\n[%s] %s\n' "$(date -Is)" "$*"; }
die() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
ensure_sshd_runtime() { install -d -o root -g root -m 0755 /run/sshd; }
ERROR_HANDLED=0
on_error() {
    local rc=${1:-1} line=${2:-unknown}
    if [[ "$ERROR_HANDLED" == 1 ]]; then
        exit "$rc"
    fi
    ERROR_HANDLED=1
    trap - ERR INT TERM HUP
    set +e
    printf '\nINSTALL_FAILED rc=%s line=%s\nСм. %s. Ребут НЕ запланирован.\n' "$rc" "$line" "$LOG" >&2
    printf 'rc=%s line=%s at=%s\n' "$rc" "$line" "$(date -Is)" > "$STATE/INSTALL_FAILED"
    if [[ -f "$STATE/network-rollback-armed" ]]; then
        /usr/local/sbin/vkarmani-network-rollback || true
    fi
    exit "$rc"
}
trap 'on_error "$?" "$LINENO"' ERR
trap 'on_error 130 "$LINENO"' INT
trap 'on_error 143 "$LINENO"' TERM
trap 'on_error 129 "$LINENO"' HUP
stage "VKarmani installer $INSTALLER_VERSION — проверка и резервная копия"
BK="$STATE/backups/$(date +%Y%m%d-%H%M%S)-$$"
install -d -m 0700 "$BK"
for p in etc/ssh etc/ufw etc/default/ufw etc/default/grub etc/default/grub.d etc/sysctl.d \
         etc/docker etc/nginx etc/fail2ban etc/chrony etc/default/chrony etc/fstab \
         etc/apt/apt.conf.d etc/apt/sources.list.d etc/apt/keyrings etc/modules-load.d \
         etc/systemd/system etc/systemd/journald.conf.d etc/tmpfiles.d etc/logrotate.d \
         etc/letsencrypt etc/vkarmani-node opt/vkarmani-node usr/local/lib/vkarmani-node var/www/vkarmani-node; do
    if [[ -e "/$p" ]]; then cp -a --parents "/$p" "$BK/"; fi
done
(cd "$BK"; find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 -r sha256sum > MANIFEST.sha256
    sha256sum --check --quiet MANIFEST.sha256)
printf '%s\n' "$BK" > "$STATE/latest-backup-path"
# Mark ownership only after all destructive-operation preconditions pass.
touch "$STATE/owned-installation"
[[ -e "$STATE/first-backup-path" ]] || printf '%s\n' "$BK" > "$STATE/first-backup-path"

stage 'Базовые инструменты из подписанного репозитория ОС'
cat > /etc/apt/apt.conf.d/99-vkarmani-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
Acquire::Retries "3";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
DPkg::Lock::Timeout "300";
EOF
APT=(apt-get -y --no-remove --no-install-recommends -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update
"${APT[@]}" install ca-certificates curl gnupg python3 python3-cryptography dnsutils jq iproute2 openssl
cat > "$LIB/node_helper.py" <<'PY_HELPER'
#!/usr/bin/env python3
"""VKarmani 2.0.2: node-only installer. No panel API, credentials or POST requests.
Three inputs are collected by Bash before APT and passed via stdin. Python 3.10+.
"""
import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
MODE = 'secret-key-only'
class Failure(Exception):
    pass

def read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (ValueError, OSError) as e:
        raise Failure('Не удалось прочитать JSON: ' + str(path)) from e


def sync_parent(path):
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        sync_parent(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def domain(value):
    if not isinstance(value, str):
        raise Failure('Домен должен быть строкой.')
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value:
        raise Failure('Нужен полный DNS-домен, без https:// и пути.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
           for p in value.split('.')):
        raise Failure('Некорректный домен. IDN укажите в punycode.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Failure('Вместо IP нужен DNS-домен.')


def public_ipv4(value):
    try:
        ip = ipaddress.IPv4Address(value)
        if not isinstance(value, str) or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError()
        return str(ip)
    except (ValueError, TypeError) as e:
        raise Failure('Нужен глобальный публичный IPv4-адрес, не CIDR.') from e


def _dns_query(domain_name, kind, server):
    cmd = ['dig', '-4', '+time=3', '+tries=1', '+noall', '+comments', '+answer']
    if server:
        cmd.append('@' + server)
    cmd += [domain_name, kind]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode or not re.search(r'status: NOERROR[, ]', r.stdout):
        return None
    return {line.split()[-1] for line in r.stdout.splitlines()
            if len(line.split()) >= 5 and line.split()[-2] == kind}


def detect_local_public_ipv4s():
    """Return every globally routable IPv4 actually assigned to this VPS.

    Do not use the default-route source as the node address: providers commonly
    attach two public IPv4s and the node domain can intentionally point to the
    secondary address.
    """
    try:
        r = subprocess.run(['ip', '-j', '-4', 'address', 'show', 'scope', 'global'],
                           capture_output=True, text=True, timeout=10, check=True)
        rows = json.loads(r.stdout)
    except (subprocess.SubprocessError, ValueError, TypeError) as e:
        raise Failure('Не удалось получить IPv4-адреса интерфейсов VPS.') from e
    found = {}
    for row in rows:
        ifname = row.get('ifname')
        if not isinstance(ifname, str) or not ifname:
            continue
        for info in row.get('addr_info') or []:
            if info.get('family') != 'inet':
                continue
            value = info.get('local')
            try:
                ip = public_ipv4(value)
            except Failure:
                continue
            found.setdefault(ip, ifname)
    if not found:
        raise Failure('На интерфейсах VPS не найден прямой публичный IPv4. NAT/IPv6-only не поддерживаются.')
    return dict(sorted(found.items(), key=lambda x: tuple(int(p) for p in x[0].split('.'))))


def _dns_snapshot(domain_name):
    resolvers = ((None, 'system'), ('1.1.1.1', '1.1.1.1'), ('8.8.8.8', '8.8.8.8'))
    snapshot = {}
    for server, label in resolvers:
        last = None
        for attempt in range(1, 4):
            a = _dns_query(domain_name, 'A', server)
            aaaa = _dns_query(domain_name, 'AAAA', server)
            if a is not None and aaaa is not None:
                last = (a, aaaa)
                break
            if attempt < 3:
                import time
                time.sleep(1)
        snapshot[label] = last
    return snapshot


def _fmt_dns_snapshot(snapshot):
    parts = []
    for label in ('system', '1.1.1.1', '8.8.8.8'):
        item = snapshot.get(label)
        if item is None:
            parts.append(label + ': нет ответа')
            continue
        a, aaaa = item
        parts.append(f'{label}: A={",".join(sorted(a)) if a else "NONE"}, '
                     f'AAAA={",".join(sorted(aaaa)) if aaaa else "NONE"}')
    return '; '.join(parts)


def select_public_ipv4_for_domain(domain_name, wait_seconds=0):
    """Select the node IPv4 by matching public DNS to local VPS addresses.

    If a server has multiple public IPv4s, no default-route guess is made. The
    selected address must be the single A record returned by available public
    resolvers and must be locally assigned. AAAA must be absent.
    """
    import time
    local = detect_local_public_ipv4s()
    local_set = set(local)
    deadline = time.monotonic() + max(0, int(wait_seconds))
    last_notice = 0.0
    while True:
        snap = _dns_snapshot(domain_name)
        public = {k: v for k, v in snap.items() if k != 'system' and v is not None}
        valid = {}
        conflict = False
        for label, (a, aaaa) in public.items():
            if aaaa or len(a) != 1:
                conflict = True
                continue
            ip = next(iter(a))
            if ip not in local_set:
                conflict = True
                continue
            valid[label] = ip
        chosen = set(valid.values())
        ready = bool(valid) and not conflict and len(chosen) == 1 and len(valid) == len(public)
        if ready:
            selected = next(iter(chosen))
            system = snap.get('system')
            if system is None:
                print('WARN: системный DNS недоступен; публичный DNS подтверждён.', file=sys.stderr)
            elif system != ({selected}, set()):
                print('WARN: системный DNS ещё отличается; публичный DNS уже подтверждён. Продолжаю.', file=sys.stderr)
            print('IPv4 ноды выбран автоматически: ' + selected + ' (интерфейс ' + local[selected] + ').')
            if len(local) > 1:
                print('Публичные IPv4 VPS: ' + ', '.join(local) + '; DNS выбрал: ' + selected + '.')
            return selected

        now = time.monotonic()
        if wait_seconds and now < deadline:
            if last_notice == 0.0 or now - last_notice >= 60:
                remaining = max(1, int((deadline - now + 59) // 60))
                print(
                    'WARN: пока нельзя однозначно выбрать IPv4 ноды.\n'
                    f'      Домен: {domain_name}\n'
                    f'      Публичные IPv4 этой VPS: {", ".join(local)}\n'
                    f'      DNS: {_fmt_dns_snapshot(snap)}\n'
                    '      A-запись должна содержать ровно один из IPv4 этой VPS; AAAA/Proxy должны отсутствовать.\n'
                    f'      Ничего вводить повторно не нужно: жду DNS автоматически, осталось до {remaining} мин.',
                    file=sys.stderr,
                    flush=True,
                )
                last_notice = now
            time.sleep(15)
            continue
        raise Failure(
            'Не удалось автоматически выбрать IPv4 ноды. Публичные IPv4 VPS: ' +
            ', '.join(local) + '. DNS: ' + _fmt_dns_snapshot(snap) +
            '. A-запись домена должна указывать ровно на один из этих адресов, без AAAA/CDN Proxy.'
        )


def dns_check(c, wait_seconds=0):
    """Confirm that the persisted node domain still points to its selected IPv4."""
    import time
    deadline = time.monotonic() + max(0, int(wait_seconds))
    last_notice = 0.0
    while True:
        snap = _dns_snapshot(c['domain'])
        public = {k: v for k, v in snap.items() if k != 'system' and v is not None}
        good = {k for k, (a, aaaa) in public.items() if a == {c['public_ipv4']} and not aaaa}
        bad = {k for k in public if k not in good}
        if good and not bad:
            if snap.get('system') is None:
                print('WARN: системный DNS недоступен; публичный DNS подтверждён.', file=sys.stderr)
            elif snap.get('system') != ({c['public_ipv4']}, set()):
                print('WARN: системный DNS ещё отличается; публичный DNS уже подтверждён. Продолжаю.', file=sys.stderr)
            print('DNS: A=' + c['public_ipv4'] + ', AAAA отсутствует; подтверждено через: ' + ', '.join(sorted(good)) + '.')
            return
        now = time.monotonic()
        if wait_seconds and now < deadline:
            if last_notice == 0.0 or now - last_notice >= 60:
                remaining = max(1, int((deadline - now + 59) // 60))
                print(
                    'WARN: DNS домена пока не соответствует сохранённому IPv4 ноды.\n'
                    f'      Домен: {c["domain"]}\n'
                    f'      Ожидаемый IPv4: {c["public_ipv4"]}\n'
                    f'      DNS: {_fmt_dns_snapshot(snap)}\n'
                    f'      Жду DNS автоматически, осталось до {remaining} мин.',
                    file=sys.stderr,
                    flush=True,
                )
                last_notice = now
            time.sleep(15)
            continue
        raise Failure('DNS не соответствует выбранному IPv4 ноды ' + c['public_ipv4'] + ': ' + _fmt_dns_snapshot(snap))

def make_keys_profile(c):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    path = ETC / 'reality.json'
    if path.exists():
        keys = read_json(path)
        required = {'private_key', 'public_key', 'short_id'}
        if not required.issubset(keys) or not all(isinstance(keys.get(k), str) and keys.get(k) for k in required):
            raise Failure('reality.json повреждён: отсутствуют ключи RAW/REALITY.')
        try:
            if not re.fullmatch(r'[0-9a-f]{16}', keys['short_id']):
                raise ValueError()
            for name in ('private_key', 'public_key'):
                if not re.fullmatch(r'[A-Za-z0-9_-]{43}', keys[name]):
                    raise ValueError()
            private = base64.b64decode(keys['private_key'] + '=', altchars=b'-_', validate=True)
            public = base64.b64decode(keys['public_key'] + '=', altchars=b'-_', validate=True)
            actual = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            if actual != public:
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise Failure('reality.json повреждён: неверная пара X25519 или ShortID. Ключи не заменены.') from exc
    else:
        key = X25519PrivateKey.generate()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        keys = {'private_key': enc(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                'public_key': enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                'short_id': secrets.token_hex(8)}
        atomic_json(path, keys)
    suffix = hashlib.sha256(c['domain'].encode()).hexdigest()[:12]
    tag = 'VK_RAW_REALITY_' + suffix.upper()
    # Remnawave fills clients dynamically. Do not force Vision here: RAW+REALITY works
    # without it, and production profiles may choose their own client flow.
    profile = {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': ['1.1.1.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [{'tag': tag, 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                      'settings': {'clients': [], 'decryption': 'none'},
                      'sniffing': {'enabled': True, 'routeOnly': True,
                                   'destOverride': ['http', 'tls', 'quic']},
                      'streamSettings': {
                          'network': 'raw', 'security': 'reality',
                          'realitySettings': {'show': False, 'target': '/dev/shm/nginx.sock',
                                              'xver': 1, 'spiderX': '/',
                                              'serverNames': [c['domain']],
                                              'privateKey': keys['private_key'],
                                              'shortIds': [keys['short_id']]}}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                      {'tag': 'BLOCK', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
            {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                                    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
                                    '224.0.0.0/4', '240.0.0.0/4', c['public_ipv4'] + '/32', '::/0'] +
                                   [ip + '/32' for ip in sorted(set(c['panel_ipv4']) | set(detect_local_public_ipv4s()))],
             'outboundTag': 'BLOCK'}]}}
    validate_profile(profile, c)
    atomic_json(ETC / 'profile.json', profile)
    return 'VK-RAW-' + suffix, tag, profile

def validate_profile(profile, c):
    """Validate THIS node's masking policy, not legal ownership or panel state."""
    if not isinstance(profile, dict):
        raise Failure('PROFILE_NOT_XRAY_OBJECT')
    inbounds = profile.get('inbounds')
    if not isinstance(inbounds, list) or len(inbounds) != 1 or not isinstance(inbounds[0], dict):
        raise Failure('PROFILE_REQUIRES_ONE_VLESS_INBOUND')
    inbound = inbounds[0]
    if inbound.get('protocol') != 'vless' or type(inbound.get('port')) is not int or inbound['port'] != 443:
        raise Failure('PROFILE_REQUIRES_VLESS_TCP443')
    stream = inbound.get('streamSettings') or {}
    if not isinstance(stream, dict) or stream.get('security') != 'reality':
        raise Failure('PROFILE_REQUIRES_RAW_REALITY_NO_OTHER_TRANSPORTS')
    # Newer schemas use method; network is the older compatibility spelling.
    # Never let a second spelling silently select XHTTP/WS behind a raw field.
    methods = [stream[key] for key in ('network', 'method') if key in stream]
    if not methods or any(value not in ('raw', 'tcp') for value in methods):
        raise Failure('PROFILE_REQUIRES_RAW_REALITY_NO_OTHER_TRANSPORTS')
    r = stream.get('realitySettings')
    if not isinstance(r, dict):
        raise Failure('PROFILE_REALITY_SETTINGS_MISSING')
    if r.get('serverNames') != [c['domain']]:
        raise Failure('PROFILE_SNI_MUST_EQUAL_THIS_NODE_DOMAIN')
    # target and the older dest alias cannot override one another silently.
    targets = [r[k] for k in ('target', 'dest') if k in r]
    if not targets or any(value != '/dev/shm/nginx.sock' for value in targets):
        raise Failure('PROFILE_TARGET_MUST_BE_LOCAL_SELFSTEAL_SOCKET')
    if type(r.get('xver')) is not int or r['xver'] != 1:
        raise Failure('PROFILE_SELFSTEAL_REQUIRES_PROXY_V1')
    settings = inbound.get('settings')
    if not isinstance(settings, dict) or settings.get('decryption') != 'none' or settings.get('fallbacks'):
        raise Failure('PROFILE_UNEXPECTED_VLESS_SETTINGS_OR_FALLBACKS')
    outbounds = profile.get('outbounds')
    if not isinstance(outbounds, list) or not outbounds or any(
            not isinstance(o, dict) or o.get('protocol') not in ('freedom', 'blackhole') for o in outbounds):
        raise Failure('PROFILE_UNSUPPORTED_OUTBOUND_REQUIRES_MANUAL_AUDIT')
    return True


def audit_profile(path, c):
    path = Path(path)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise Failure('PROFILE_TOO_LARGE_FOR_LOCAL_POLICY_AUDIT')
    validate_profile(read_json(path), c)
    print('PROFILE_RAW_REALITY_SELFSTEAL_POLICY=PASS')
    print('SCOPE=SUPPLIED_JSON_ONLY; LIVE_NODE_AND_HOST_OVERRIDES=NOT_VERIFIED; DOMAIN_OWNERSHIP=OPERATOR_RESPONSIBILITY')


def docker_config():
    p = Path('/etc/docker/daemon.json')
    cfg = read_json(p) if p.exists() else {}
    if not isinstance(cfg, dict):
        raise Failure('daemon.json не является объектом.')
    cfg.update({'ipv6': False, 'ip6tables': False, 'live-restore': True,
                'log-driver': 'local', 'log-opts': {'max-size': '10m', 'max-file': '3'}})
    atomic_json(p, cfg)
    os.chmod(p, 0o644)


def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
        sync_parent(path)
    finally:
        if temp.exists():
            temp.unlink()


def normalize_config(raw):
    if not isinstance(raw, dict) or raw.get('installation_mode') != MODE:
        raise Failure('Нужна конфигурация secret-key-only. API-установка не мигрируется.')
    allowed = {'installation_mode', 'domain', 'public_ipv4', 'node_port', 'panel_ipv4',
               'image', 'auto_reboot', 'certbot_dry_run', 'create_swap', 'weekly_reboot',
               'selfsteal_host_socket', 'allow_net_admin'}
    if set(raw) - allowed:
        raise Failure('Неизвестные поля конфигурации. API-параметры здесь не используются.')
    c = dict(raw)
    c['domain'] = domain(c.get('domain'))
    c['public_ipv4'] = public_ipv4(c.get('public_ipv4'))
    ips = c.get('panel_ipv4')
    if not isinstance(ips, list) or not 1 <= len(ips) <= 16:
        raise Failure('panel_ipv4: от 1 до 16 публичных IPv4 панели, без CIDR.')
    c['panel_ipv4'] = sorted({public_ipv4(x) for x in ips})
    port = c.get('node_port', 2222)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise Failure('node_port: целое 1024–65535, не конфликтующее с SSH/80/443.')
    c['node_port'] = port
    image = c.get('image', 'remnawave/node:latest')
    if not isinstance(image, str) or not re.fullmatch(
        r'(?:remnawave/node|ghcr\.io/remnawave/node)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?', image):
        raise Failure('Допускается только официальный образ Remnawave Node.')
    c['image'] = image
    for name in ('auto_reboot', 'certbot_dry_run', 'create_swap', 'weekly_reboot', 'allow_net_admin'):
        value = c.get(name, name in ('certbot_dry_run', 'create_swap'))
        if type(value) is not bool:
            raise Failure(name + ': требуется JSON true/false.')
        c[name] = value
    sock = c.get('selfsteal_host_socket', '/dev/shm/nginx.sock')
    if sock not in ('/dev/shm/nginx.sock', '/run/vkarmani-selfsteal/nginx.sock'):
        raise Failure('Неизвестная схема Selfsteal socket.')
    c['selfsteal_host_socket'] = sock
    return c


def normalize_pem(value):
    value = value.replace('\\n', '\n').replace('\r\n', '\n')
    value = re.sub(r'(-----BEGIN [A-Z ]+-----)', r'\1\n', value)
    value = re.sub(r'(-----END [A-Z ]+-----)', r'\n\1', value)
    return re.sub(r'\n+', '\n', value).strip() + '\n'


def normalize_secret(value, check_dates=False):
    """Validate the actual mTLS/JWT bundle, not an arbitrary 16-char password.
    No key, PEM, invalid input, or third-party exception text is put in errors.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, padding
    if not isinstance(value, str):
        raise Failure('SECRET_KEY должен быть строкой.')
    value = value.strip()
    if value.startswith('SECRET_KEY='):
        value = value[len('SECRET_KEY='):].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not re.fullmatch(r'[A-Za-z0-9+/_-]{32,50000}={0,2}', value):
        raise Failure('Некорректный формат SECRET_KEY: вставьте значение из панели одной строкой.')
    try:
        payload = json.loads(base64.b64decode(value + '=' * (-len(value) % 4),
                                             altchars=b'-_', validate=True))
        fields = ('nodeCertPem', 'nodeKeyPem', 'caCertPem', 'jwtPublicKey')
        if not isinstance(payload, dict) or any(not isinstance(payload.get(k), str) for k in fields):
            raise ValueError()
        pem = {k: normalize_pem(payload[k]).encode('ascii') for k in fields}
        cert = x509.load_pem_x509_certificate(pem['nodeCertPem'])
        ca = x509.load_pem_x509_certificate(pem['caCertPem'])
        key = ser.load_pem_private_key(pem['nodeKeyPem'], password=None)
        ser.load_pem_public_key(pem['jwtPublicKey'])
        encode_public = lambda k: k.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        if encode_public(cert.public_key()) != encode_public(key.public_key()):
            raise ValueError()
        if cert.issuer != ca.subject or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError()
        ca_key = ca.public_key()
        if isinstance(ca_key, ec.EllipticCurvePublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(ca_key, rsa.RSAPublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(ca_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            raise ValueError()
    except Exception as e:
        raise Failure('SECRET_KEY не прошёл проверку mTLS/JWT, сертификата или пары ключей. Возьмите новый из панели.') from e
    if check_dates:
        now = dt.datetime.now(dt.timezone.utc)
        for item in (cert, ca):
            if hasattr(item, 'not_valid_before_utc'):
                start, end = item.not_valid_before_utc, item.not_valid_after_utc
            else:
                start = item.not_valid_before.replace(tzinfo=dt.timezone.utc)
                end = item.not_valid_after.replace(tzinfo=dt.timezone.utc)
            if not start <= now <= end:
                raise Failure('Сертификат внутри SECRET_KEY ещё не действителен или истёк. Проверьте время и возьмите новый ключ.')
    return value


def check_secret(c, check_dates=True):
    path = ETC / 'remnanode.env'
    try:
        if path.stat().st_mode & 0o077:
            raise Failure('remnanode.env должен иметь права 0600.')
        lines = path.read_text(encoding='ascii').splitlines()
        if len(lines) != 3 or lines[0] != f'NODE_PORT={c["node_port"]}' or lines[2] != 'TZ=Europe/Moscow':
            raise Failure('remnanode.env не соответствует сохранённой конфигурации.')
        if not lines[1].startswith('SECRET_KEY='):
            raise Failure('В remnanode.env отсутствует SECRET_KEY.')
        normalize_secret(lines[1][len('SECRET_KEY='):], check_dates)
    except OSError as e:
        raise Failure('Не удалось прочитать сохранённый SECRET_KEY. Файл: /etc/vkarmani-node/remnanode.env') from e


def init_config(node_port='2222', inputs=None):
    """No prompts here. Bash collects SECRET_KEY, panel IPv4 and domain before dependencies.

    Node IPv4 is selected automatically by matching the domain's public A record
    against every public IPv4 actually assigned to the VPS. The panel source IPv4
    is user-entered and is used only for the Node Port firewall allowlist.
    """
    if (ETC / 'config.json').exists():
        c = normalize_config(read_json(ETC / 'config.json'))
        local = detect_local_public_ipv4s()
        if c['public_ipv4'] not in local:
            raise Failure('Сохранённый IPv4 ноды больше не назначен этой VPS. Автоматически адрес рабочей установки не меняю.')
        check_secret(c, check_dates=False)
        print('Продолжение установки: домен, IPv4 ноды/панели и SECRET_KEY взяты из сохранённой конфигурации.')
        return
    if not re.fullmatch(r'[0-9]{4,5}', node_port):
        raise Failure('Некорректный NODE_PORT_DEFAULT.')
    if inputs is None:
        text = sys.stdin.read(70001)
        if len(text) > 70000:
            raise Failure('Слишком большой блок входных данных.')
        inputs = text.splitlines()
    if not isinstance(inputs, (tuple, list)) or len(inputs) != 3:
        raise Failure('Нужны три заранее введённых значения: SECRET_KEY, IPv4 панели и домен.')
    secret = normalize_secret(inputs[0])
    panel_ip = public_ipv4(inputs[1])
    name = domain(inputs[2])
    selected = select_public_ipv4_for_domain(name, wait_seconds=300)
    if panel_ip in detect_local_public_ipv4s():
        raise Failure('IPv4 панели назначен этой же ноде. Нужен отдельный сервер ноды или введите другой IPv4 панели.')
    c = normalize_config({'installation_mode': MODE, 'domain': name, 'public_ipv4': selected,
                          'panel_ipv4': [panel_ip], 'node_port': int(node_port),
                          'selfsteal_host_socket': '/run/vkarmani-selfsteal/nginx.sock'})
    # DNS already selected this exact local address; recheck once against config shape.
    dns_check(c)
    atomic_text(ETC / 'remnanode.env', f'NODE_PORT={c["node_port"]}\nSECRET_KEY={secret}\nTZ=Europe/Moscow\n')
    atomic_json(ETC / 'config.json', c)
    print('Параметры проверены. IPv4 ноды=' + selected + '; SECRET_KEY сохранён с правами 0600.')

def write_panel_guide(c):
    name, tag, _ = make_keys_profile(c)
    keys = read_json(ETC / 'reality.json')
    txt = f'''VKarmani RemnaNode 2.0.2 — действия в панели

Сервер: {c['domain']} / {c['public_ipv4']}
Разрешённый исходящий IPv4 панели: {', '.join(c['panel_ipv4'])}
Управляющий порт NODE_PORT: {c['node_port']} / TCP (НЕ клиентский порт!)

1. Config Profiles: создайте профиль {name} и вставьте JSON из
   /etc/vkarmani-node/profile.json
   Этот файл содержит приватный REALITY-ключ: не публикуйте его.
2. Nodes -> Management: создайте/отредактируйте карточку ЭТОЙ ноды.
   Node Port={c['node_port']}. В Address можно использовать домен ноды или любой
   публичный IPv4, реально назначенный этой VPS. Для VPS с несколькими IPv4
   управляющий порт разрешён с IPv4 панели на ВСЕ локальные IPv4 ноды — это
   специально, чтобы адрес Node в панели не был обязан совпадать с IPv4 домена.
   Клиентский/ACME IPv4, выбранный DNS для {c['domain']}: {c['public_ipv4']}.
   Используйте ту же панель, из которой взят введённый SECRET_KEY.
   Выберите профиль {name} и inbound {tag}.
3. Hosts: выберите этот профиль/inbound; Address={c['domain']}, Port=443.
   Advanced Options лучше оставить DEFAULT. SNI унаследуется из inbound.
   Если SNI переопределяется вручную — укажите {c['domain']}.
4. Internal Squads: разрешите inbound {tag} нужной группе пользователей.
   Обновите подписку в клиенте и проверьте соединение извне.

Шаблон: VLESS + RAW + REALITY.
REALITY target: /dev/shm/nginx.sock; xver=1 (PROXY protocol v1).
Selfsteal: Nginx + OpenSSL на Unix socket, порт 443 полностью остаётся за Xray.
serverName/SNI: {c['domain']}
REALITY publicKey: {keys['public_key']}
ShortID: {keys['short_id']}

Скрипт НЕ авторизуется в панели, НЕ создаёт и НЕ меняет её объекты.
Локальный profile.json — шаблон для импорта, НЕ live-конфиг ноды.
Если у вас уже назначен свой RAW+REALITY профиль, он не перезаписывается.
Отсутствие Xray TCP/443 может означать неполученный или ошибочный профиль.
Локальная готовность VPS не доказывает подключение панели.
TCP/2222 сам по себе не доказывает связь с панелью и работу VPN.

Проверка: sudo vkarmani-node-check
Строгая проверка Xray + Selfsteal через :443: sudo vkarmani-node-check --require-xray
Selfsteal socket: /dev/shm/nginx.sock
Лог после reboot: /var/log/vkarmani-node-postboot.log
'''
    atomic_text(ETC / 'PANEL-SETUP.txt', txt)

def control_ready(c):
    r = subprocess.run(['/usr/local/sbin/vkarmani-node-tls-check'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=40)
    if r.returncode:
        raise Failure('Локальная TLS-проверка Node API не пройдена. См. vkarmani-node-tls-check; доступ панели этим не проверяется.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'get', 'dns', 'keys', 'secret', 'docker-config', 'panel-guide', 'control-ready', 'image', 'allow-net-admin', 'weekly-reboot', 'profile-check'])
    parser.add_argument('arg', nargs='?')
    args = parser.parse_args()
    if args.action == 'init':
        init_config(args.arg or '2222')
        return
    if args.action == 'docker-config':
        docker_config()
        return
    c = normalize_config(read_json(ETC / 'config.json'))
    if args.action == 'get':
        if args.arg not in c:
            raise Failure('Поле конфигурации не найдено.')
        v = c[args.arg]
        print('\n'.join(str(x) for x in v) if isinstance(v, list) else
              ('true' if v else 'false') if isinstance(v, bool) else v)
    elif args.action == 'image':
        c['image'] = args.arg
        atomic_json(ETC / 'config.json', normalize_config(c))
    elif args.action in ('allow-net-admin', 'weekly-reboot'):
        if args.arg not in ('true', 'false'):
            raise Failure('Требуется true/false.')
        c[args.action.replace('-', '_')] = args.arg == 'true'
        atomic_json(ETC / 'config.json', normalize_config(c))
    elif args.action == 'dns':
        dns_check(c)
    elif args.action == 'profile-check':
        audit_profile(args.arg or ETC / 'profile.json', c)
    elif args.action == 'keys':
        make_keys_profile(c)
    elif args.action == 'secret':
        check_secret(c)
        print('SECRET_KEY_VALID=PASS')
    elif args.action == 'panel-guide':
        write_panel_guide(c)
    elif args.action == 'control-ready':
        control_ready(c)
        print('NODE_TLS_LOCAL=PASS (не проверка панели)')


if __name__ == '__main__':
    try:
        main()
    except Failure as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('Ввод прерван.', file=sys.stderr)
        sys.exit(130)
    except Exception:
        print('ERROR: ошибка чтения/проверки данных. Секретные значения не выведены.', file=sys.stderr)
        sys.exit(1)
PY_HELPER
chmod 0700 "$LIB/node_helper.py"
helper() { python3 "$LIB/node_helper.py" "$@"; }
# printf is a Bash builtin: SECRET_KEY is not passed as argv/env to an external process.
printf '%s\n%s\n%s\n' "$VK_INPUT_SECRET" "$VK_INPUT_PANEL_IP" "$VK_INPUT_DOMAIN" | helper init "$NODE_PORT_DEFAULT"
unset VK_INPUT_SECRET VK_INPUT_PANEL_IP VK_INPUT_DOMAIN
rm -f "$ETC/inputs.pending"
DOMAIN=$(helper get domain)
PUBLIC_IP=$(helper get public_ipv4)
NODE_PORT=$(helper get node_port)
if [[ -n "$IMAGE_OVERRIDE" ]]; then
    python3 "$LIB/node_helper.py" image "$IMAGE_OVERRIDE"
fi
IMAGE=$(helper get image)
# A resumed invocation retains an explicitly enabled capability/schedule.
if [[ $ALLOW_NET_ADMIN -eq 1 ]]; then helper allow-net-admin true; fi
if [[ $WEEKLY_REBOOT -eq 1 ]]; then helper weekly-reboot true; fi
[[ $(helper get allow_net_admin) != true ]] || ALLOW_NET_ADMIN=1
[[ $(helper get weekly_reboot) != true ]] || WEEKLY_REBOOT=1
PANEL_IP_TEXT=$(helper get panel_ipv4)
mapfile -t PANEL_IPS <<< "$PANEL_IP_TEXT"
[[ ${#PANEL_IPS[@]} -ge 1 && ${#PANEL_IPS[@]} -le 16 ]] || die 'Некорректный список IP технички.'
unset PANEL_IP_TEXT
ensure_sshd_runtime
mapfile -t SSH_PORTS < <({ /usr/sbin/sshd -T | awk '$1=="port"{print $2}';
    if [[ -n "${SSH_CONNECTION:-}" ]]; then awk '{print $4}' <<< "$SSH_CONNECTION"; fi
    if systemctl is-active --quiet ssh.socket; then
        systemctl show ssh.socket -p Listen --value | python3 -c 'import re,sys; print("\n".join(re.findall(r"(?:[:\s]|^)([0-9]+) \(Stream\)", sys.stdin.read())))'
    fi; } | sed '/^$/d' | sort -nu)
[[ ${#SSH_PORTS[@]} -gt 0 && ${#SSH_PORTS[@]} -le 15 ]] || die 'Требуется от 1 до 15 сохранённых SSH-портов.'
for port in "${SSH_PORTS[@]}"; do
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || die 'Некорректный SSH-порт.'
    [[ "$port" != "$NODE_PORT" && "$port" != 80 && "$port" != 443 ]] || die 'SSH-порт конфликтует с портами ноды.'
done
printf '%s\n' "${SSH_PORTS[@]}" > "$ETC/ssh-ports"
if [[ ! -f "$STATE/image-digest" ]] && ss -H -lnt | awk '{print $4}' | _contains -E ":${NODE_PORT}$"; then
    die "Управляющий порт $NODE_PORT занят. Измените NODE_PORT_DEFAULT в начале установщика ДО первой установки."
fi
helper dns
# Selected IPv4 must still be directly assigned to this VPS; NAT-only addresses are refused.
if ! ip -4 -o address show scope global | awk '{print $4}' | cut -d/ -f1 | _contains -Fx "$PUBLIC_IP"; then
    die 'Публичный IPv4 должен быть назначен интерфейсу этой VPS. NAT/проброс портов не поддержан.'
fi
stage 'Компоненты ноды из подписанных репозиториев (без full-upgrade и snap refresh)'
"${APT[@]}" install openssh-server ufw fail2ban nginx certbot chrony logrotate unattended-upgrades \
    ethtool kmod util-linux procps dbus python3-systemd
ensure_sshd_runtime

stage 'MSK, синхронизация времени и ограничение журналов'
timedatectl set-timezone Europe/Moscow
cat > /etc/chrony/chrony.conf <<'EOF'
pool time.cloudflare.com iburst maxsources 2
pool pool.ntp.org iburst maxsources 2
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
leapsectz right/UTC
keyfile /etc/chrony/chrony.keys
logdir /var/log/chrony
cmdport 0
port 0
EOF
printf 'DAEMON_OPTS="-F 1 -4"\n' > /etc/default/chrony
# Both Debian and Ubuntu chrony units use DAEMON_OPTS (verified again locally below).
if ! systemctl cat chrony.service | _contains 'DAEMON_OPTS'; then
    die 'Неизвестный chrony unit: параметр DAEMON_OPTS не поддерживается.'
fi
chronyd -p -f /etc/chrony/chrony.conf >/dev/null
systemctl enable --now chrony
systemctl restart chrony
chronyc waitsync 60 0.1 0.0 2
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/90-vkarmani-limits.conf <<'EOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
MaxRetentionSec=14day
EOF
systemctl restart systemd-journald
cat > /etc/apt/apt.conf.d/90-vkarmani-security-updates <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

stage 'IPv4-only: ядро, GRUB, UFW, SSH; BBR + fq'
cat > /etc/sysctl.d/99-vkarmani-node.conf <<'EOF'
# systemd-sysctl accepts optional '-' entries. Our helper explicitly handles
# absent IPv6 controls; procps 4.0.4 sysctl -p may otherwise exit with ENOENT.
-net.ipv6.conf.all.disable_ipv6 = 1
-net.ipv6.conf.default.disable_ipv6 = 1
-net.ipv6.conf.lo.disable_ipv6 = 1
# Optional only for early systemd-sysctl. Our helper tests support and records fallback.
-net.core.default_qdisc = fq
-net.ipv4.tcp_congestion_control = bbr
# Enable packetization-layer probing only after detecting a TCP MTU black hole.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
vm.swappiness = 10
EOF
# Do not make systemd-modules-load fail on provider kernels without optional modules.
# The boot network helper retries support and validates actual sysctl readback.
: > /etc/modules-load.d/vkarmani-node.conf
for module in tcp_bbr sch_fq; do
    if modprobe --quiet "$module"; then
        printf '%s\n' "$module" >> /etc/modules-load.d/vkarmani-node.conf
    else
        printf 'OPTIONAL_MODULE=%s unavailable; effective network policy is checked below.\n' "$module"
    fi
done
vk_write_network_script
/usr/local/sbin/vkarmani-node-network
for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ ! -f "$f" ]] || printf '1\n' > "$f"
done
# Existing interfaces must also inherit the security policy, not just future ones.
for kind in accept_redirects secure_redirects send_redirects accept_source_route; do
    for f in /proc/sys/net/ipv4/conf/*/"$kind"; do
        [[ ! -f "$f" ]] || printf '0\n' > "$f"
    done
done
install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-vkarmani-ipv4.cfg <<'EOF'
# Applied to all regular/recovery kernel entries, not only GRUB_CMDLINE_LINUX_DEFAULT.
case " ${GRUB_CMDLINE_LINUX:-} " in
    *" ipv6.disable=1 "*) ;;
    *) GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:-} ipv6.disable=1" ;;
esac
EOF
update-grub
_contains -E '^[[:space:]]*linux[^[:space:]]*[[:space:]].*ipv6.disable=1' /boot/grub/grub.cfg || die 'Параметр IPv6 не попал в grub.cfg.'
vk_write_network_script
vk_write_network_unit
systemctl daemon-reload
systemctl enable vkarmani-node-network
systemctl restart vkarmani-node-network

# Enable password SSH without changing accounts/passwords/authorized keys. Convert socket activation to an IPv4
# ssh.service, whose KillMode=process preserves established SSH child sessions.
ensure_sshd_runtime
[[ "$(systemctl show ssh.service -p KillMode --value)" == process ]] || die 'SSH unit KillMode не process; безопасное переключение не подтверждено.'
PUBKEY_BEFORE=$(/usr/sbin/sshd -T | awk '$1=="pubkeyauthentication"{print $2}')
NETBK="$STATE/network-backup"
install -d -m 0700 "$NETBK"
cp -a /etc/ssh/sshd_config "$NETBK/sshd_config"
cp -a /etc/ufw "$NETBK/"
cp -a /etc/default/ufw "$NETBK/default-ufw"
systemctl is-enabled ssh.socket > "$NETBK/socket-enabled" 2>/dev/null || true
systemctl is-active ssh.socket > "$NETBK/socket-active" 2>/dev/null || true
cat > /usr/local/sbin/vkarmani-network-rollback <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
set +x
umask 077
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
S=/var/lib/vkarmani-node
B=$S/network-backup
exec 7>/run/lock/vkarmani-node-network-guard.lock
flock -x 7
[[ -e "$S/network-rollback-armed" || -e "$S/network-rollback-running" ]] || exit 0
if [[ -e "$S/network-rollback-armed" ]]; then
    mv "$S/network-rollback-armed" "$S/network-rollback-running" || exit 1
fi
failed=0
# Only our SSH/UFW phase is restored. This is not an OS/package/GRUB rollback.
cp -a "$B/sshd_config" /etc/ssh/sshd_config || failed=1
ufw --force disable || failed=1
cp -a "$B/ufw/." /etc/ufw/ || failed=1
cp -a "$B/default-ufw" /etc/default/ufw || failed=1
if grep -q '^ENABLED=yes' "$B/ufw/ufw.conf"; then
    ufw --force enable || failed=1
    ufw status | grep '^Status: active$' >/dev/null || failed=1
else
    ufw status | grep '^Status: inactive$' >/dev/null || failed=1
fi
systemctl daemon-reload || failed=1
install -d -o root -g root -m 0755 /run/sshd || failed=1
if /usr/sbin/sshd -t; then
    if grep -qx enabled "$B/socket-enabled"; then systemctl enable ssh.socket || failed=1; fi
    if grep -qx active "$B/socket-active"; then
        systemctl stop ssh.service || failed=1
        systemctl start ssh.socket || failed=1
    else
        systemctl restart ssh.service || failed=1
    fi
else
    failed=1
fi
if [[ $failed -eq 0 ]] && { systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; }; then
    rm -f "$S/network-rollback-running"
    date -Is > "$S/network-rollback-done"
    echo 'SSH_UFW_ROLLBACK_LOCAL=PASS; внешний вход проверьте через консоль хостера'
else
    echo 'SSH_UFW_ROLLBACK_LOCAL=FAIL; marker сохранён, необходима консоль хостера' >&2
    exit 1
fi
EOF
chmod 0700 /usr/local/sbin/vkarmani-network-rollback
rm -f "$STATE/network-rollback-done"
touch "$STATE/network-rollback-armed"
ROLLBACK_UNIT="vkarmani-network-rollback-$$"
systemd-run --collect --unit="$ROLLBACK_UNIT" --on-active=180s /usr/local/sbin/vkarmani-network-rollback
# First-value-wins: add a bounded managed block; preserve the original body.
python3 - <<'PY_SSH_CONFIG'
from pathlib import Path
import re
import subprocess

START = '# BEGIN VKARMANI PASSWORD SSH'
END = '# END VKARMANI PASSWORD SSH'


def render_ssh(text, ports, existing):
    if text.count(START) != text.count(END) or text.count(START) > 1:
        raise ValueError('damaged SSH managed block')
    text = re.sub(r'(?ms)^' + re.escape(START) + r'\n.*?^' + re.escape(END) + r'\n?', '', text)
    text = text.replace('AddressFamily inet # VKarmani IPv4 only\n', '')
    selected = sorted({int(p) for p in ports})
    if not selected or any(not 1 <= p <= 65535 for p in selected):
        raise ValueError('invalid SSH ports')
    # Always declare the full preserved set, including implicit/socket-only ports.
    # sshd permits repeated Port directives; duplicates in distro includes are harmless.
    extra = ''.join('Port ' + str(p) + '\n' for p in selected)
    block = (START + '\nAddressFamily inet\nPasswordAuthentication yes\n'
             'PermitRootLogin yes\nPermitEmptyPasswords no\n'
             'AuthenticationMethods any\nKbdInteractiveAuthentication no\n'
             'LoginGraceTime 30\nMaxAuthTries 5\nMaxStartups 10:30:60\nUseDNS no\n'
             + extra + END + '\n')
    return block + text


def main():
    path = Path('/etc/ssh/sshd_config')
    ports = Path('/etc/vkarmani-node/ssh-ports').read_text().split()
    current = subprocess.check_output(['/usr/sbin/sshd', '-T'], text=True)
    existing = set(re.findall(r'^port ([0-9]+)$', current, re.M))
    result = render_ssh(path.read_text(), ports, existing)
    tmp = path.with_name('.sshd_config.vkarmani.tmp')
    tmp.write_text(result)
    tmp.chmod(0o600)
    tmp.replace(path)


if __name__ == '__main__':
    main()
PY_SSH_CONFIG
ensure_sshd_runtime
/usr/sbin/sshd -t
SSH_EFFECTIVE=$(/usr/sbin/sshd -T)
for expected in 'passwordauthentication yes' 'permitrootlogin yes' 'permitemptypasswords no' 'authenticationmethods any' 'addressfamily inet'; do
    printf '%s\n' "$SSH_EFFECTIVE" | _contains -Fx "$expected" || die "Не применена SSH-политика: $expected"
done
[[ $(awk '$1=="pubkeyauthentication"{print $2}' <<< "$SSH_EFFECTIVE") == "$PUBKEY_BEFORE" ]] || die 'Настройка существующих SSH-ключей неожиданно изменилась.'
unset SSH_EFFECTIVE
if systemctl is-active --quiet ssh.socket; then systemctl stop ssh.socket; fi
systemctl disable ssh.socket 2>/dev/null || true
systemctl enable ssh.service
systemctl restart ssh.service
# UFW is the only managed host firewall. Node uses host networking, never published bridge ports.
systemctl stop fail2ban
ufw --force reset
sed -i -E 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
for port in "${SSH_PORTS[@]}"; do ufw allow "$port/tcp" comment 'VKarmani SSH preserved'; done
ufw allow proto tcp to "$PUBLIC_IP" port 80 comment 'VKarmani ACME HTTP-01'
ufw allow proto tcp to "$PUBLIC_IP" port 443 comment 'VKarmani RAW REALITY'
for panel in "${PANEL_IPS[@]}"; do
    ufw allow proto tcp from "$panel" to any port "$NODE_PORT" comment 'VKarmani panel only'
done
ufw logging low
ufw --force enable
systemctl enable ufw
for port in "${SSH_PORTS[@]}"; do
    ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${port}$" || die "SSH IPv4:$port не слушает."
done
/usr/sbin/sshd -T | _contains -Fx 'addressfamily inet'
ufw status | _contains -F 'Status: active'
systemctl stop "$ROLLBACK_UNIT.timer"
if ! (
    flock -x 7
    [[ -f "$STATE/network-rollback-armed" && ! -e "$STATE/network-rollback-running" ]] || exit 1
    rm -f "$STATE/network-rollback-armed"
) 7>/run/lock/vkarmani-node-network-guard.lock; then
    die 'Сработал таймер сетевого отката; прекращаю установку.'
fi

stage 'Fail2ban: только SSH-порты, без постоянного исключения IP администратора/технички'
ADMIN_IP=$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")
if [[ -n "$ADMIN_IP" ]]; then
    python3 - "$ADMIN_IP" <<'PY'
import ipaddress,sys
ipaddress.IPv4Address(sys.argv[1])
PY
fi
vk_write_fail2ban_config
fail2ban-client -t
systemctl enable fail2ban
systemctl restart fail2ban

stage 'Swap при небольшой памяти (существующий swap сохраняется)'
if [[ $(helper get create_swap) == true && "$MEM_MB" -lt 2048 && -z "$(swapon --show --noheadings)" ]]; then
    FS_TYPE=$(findmnt -n -o FSTYPE /)
    if [[ "$FS_TYPE" != ext4 && "$FS_TYPE" != xfs ]]; then
        echo "SWAP=SKIPPED: $FS_TYPE; не создаю неподдерживаемый swapfile. Следите за RAM/OOM."
    elif [[ $(df -Pm / | awk 'NR==2{print $4}') -lt 1536 ]]; then
        echo 'SWAP=SKIPPED: недостаточно свободного места для 1 GiB swap и запаса.'
    else
        [[ ! -L /swapfile-vkarmani && ! -L /swapfile-vkarmani.tmp ]] || die 'Swap path является symlink; остановка.'
        if [[ ! -e /swapfile-vkarmani ]]; then
            dd if=/dev/zero of=/swapfile-vkarmani.tmp bs=1M count=1024 status=none
            chmod 0600 /swapfile-vkarmani.tmp
            mkswap /swapfile-vkarmani.tmp
            mv /swapfile-vkarmani.tmp /swapfile-vkarmani
        fi
        [[ $(blkid -p -s TYPE -o value /swapfile-vkarmani) == swap ]] || die 'Существующий swapfile имеет неверную сигнатуру; не форматирую его.'
        chmod 0600 /swapfile-vkarmani
        swapon /swapfile-vkarmani
        _contains -F '/swapfile-vkarmani ' /etc/fstab || printf '/swapfile-vkarmani none swap sw 0 0\n' >> /etc/fstab
    fi
fi

stage 'Официальный Docker Engine и Compose plugin'
for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | _contains -F 'ok installed'; then
        die "Установлен конфликтующий пакет $package. Не удаляю его автоматически вместе с чужими данными."
    fi
done
install -d -m 0755 /etc/apt/keyrings
curl -4 --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --retry 3 \
    "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker-vkarmani.asc
# Validate the official Docker CE signing-key fingerprint before trusting the repository.
gpg --show-keys --with-colons /etc/apt/keyrings/docker-vkarmani.asc | \
    awk -F: '$1=="fpr"{print $10}' | _contains -Fx '9DC858229FC7DD38854AE2D88D81803C0EBFCD88' || die 'Неожиданный fingerprint ключа Docker.'
chmod 0644 /etc/apt/keyrings/docker-vkarmani.asc
cat > /etc/apt/sources.list.d/docker-vkarmani.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$OS_ID
Suites: $OS_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker-vkarmani.asc
EOF
apt-get update
"${APT[@]}" install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
helper docker-config
dockerd --validate --config-file=/etc/docker/daemon.json
systemctl enable docker.service containerd.service
systemctl restart docker
[[ $(docker network inspect bridge --format '{{.EnableIPv6}}') == false ]] || die 'Docker bridge IPv6 включён.'
systemctl restart vkarmani-node-network.service

stage "Nginx + Let's Encrypt + изолированный Selfsteal socket для VLESS RAW REALITY"
install -d -m 0750 -o root -g root /run/vkarmani-selfsteal
cat > /etc/tmpfiles.d/vkarmani-selfsteal.conf <<'EOF'
# Created during sysinit before Docker; no dependency on Nginx or external DNS.
d /run/vkarmani-selfsteal 0750 root root -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/vkarmani-selfsteal.conf
install -d -m 0755 /var/www/vkarmani-node/acme /var/www/vkarmani-node/site /var/www/vkarmani-node/site/assets
python3 - <<'PY'
from pathlib import Path
import json, secrets, html
etc=Path('/etc/vkarmani-node'); root=Path('/var/www/vkarmani-node/site'); meta=etc/'selfsteal-site.json'
try: m=json.loads(meta.read_text()) if meta.exists() else {}
except Exception: m={}
if not m:
    choices=[('Workspace','Secure access to your online workspace.'),('Service Portal','Manage services and account settings in one place.'),('Cloud Desk','Simple tools for files, notes and shared work.'),('Account Center','Access your account and connected services.'),('Project Hub','A lightweight workspace for everyday projects.')]
    title, subtitle=secrets.choice(choices)
    m={'title':title,'subtitle':subtitle,'accent':secrets.randbelow(360),'asset':secrets.token_hex(6),'nonce':secrets.token_hex(12)}
    tmp=meta.with_suffix('.tmp'); tmp.write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n'); tmp.chmod(0o600); tmp.replace(meta)
asset='app-'+m['asset']+'.css'; hue=m['accent']
css=f'''*{{box-sizing:border-box}}html{{color-scheme:light dark}}body{{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f1115;color:#e9edf3}}main{{max-width:920px;margin:0 auto;padding:72px 24px}}.mark{{width:48px;height:48px;border-radius:14px;background:hsl({hue} 72% 52%);box-shadow:0 10px 40px hsl({hue} 72% 52% / .24)}}h1{{font-size:clamp(2rem,6vw,4.4rem);line-height:1;margin:28px 0 18px}}p{{max-width:620px;color:#aeb7c5;font-size:1.05rem;line-height:1.7}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-top:42px}}.card{{padding:20px;border:1px solid #252b35;border-radius:16px;background:#151922}}.card b{{display:block;margin-bottom:8px}}footer{{margin-top:56px;color:#6e7887;font-size:.85rem}}@media(prefers-color-scheme:light){{body{{background:#f7f8fa;color:#171a20}}p{{color:#596270}}.card{{background:white;border-color:#e2e6ec}}footer{{color:#7a8492}}}}'''
(root/'assets'/asset).write_text(css); (root/'assets'/asset).chmod(0o644)
title=html.escape(m['title']); subtitle=html.escape(m['subtitle']); nonce=html.escape(m['nonce'])
index=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#111318"><meta name="description" content="{subtitle}"><meta name="x-instance" content="{nonce}"><title>{title}</title><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/assets/{asset}"></head><body><main><div class="mark"></div><h1>{title}</h1><p>{subtitle}</p><div class="grid"><section class="card"><b>Available</b><span>Services are online and ready.</span></section><section class="card"><b>Private by design</b><span>Connections use modern encrypted transport.</span></section><section class="card"><b>Simple access</b><span>Use your usual account to continue.</span></section></div><footer>© 2026 {title}</footer></main></body></html>'''
(root/'index.html').write_text(index); (root/'index.html').chmod(0o644)
(root/'404.html').write_text(f'<!doctype html><html><meta charset="utf-8"><title>Not found</title><body><h1>404</h1><p>Page not found.</p><!-- {nonce} --></body></html>'); (root/'404.html').chmod(0o644)
(root/'robots.txt').write_text('User-agent: *\nDisallow:\n'); (root/'robots.txt').chmod(0o644)
(root/'favicon.svg').write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="hsl({hue},72%,52%)"/><path d="M18 33 28 43 47 22" fill="none" stroke="white" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></svg>'); (root/'favicon.svg').chmod(0o644)
PY
find /var/www/vkarmani-node/site -type d -exec chmod 0755 {} +
find /var/www/vkarmani-node/site -type f -exec chmod 0644 {} +
python3 - <<'PY_NGINX_MAIN'
from pathlib import Path
import re
path = Path('/etc/nginx/nginx.conf')
text = path.read_text()
# Only the dedicated server's already-backed-up distro main config is edited.
text, count = re.subn(r'(?m)^([ \t]*)worker_connections[ \t]+[0-9]+;', r'\1worker_connections 2048;', text)
if count != 1:
    raise SystemExit('STOP: unexpected nginx events/worker_connections; refusing a blind rewrite')
text = re.sub(r'(?m)^worker_rlimit_nofile[^;]*;[ \t]*\n?', '', text)
text = 'worker_rlimit_nofile 65536;\n' + text
path.write_text(text)
PY_NGINX_MAIN
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/00-vkarmani-global.conf <<'EOF'
server_tokens off;
EOF
cat > /etc/nginx/conf.d/10-vkarmani-http.conf <<EOF
server {
    listen $PUBLIC_IP:80;
    server_name $DOMAIN;
    server_tokens off;
    access_log off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/vkarmani-node/acme;
        default_type text/plain;
        try_files \$uri =404;
    }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOF
if [[ ! -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" || ! -s "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]]; then
    rm -f /etc/nginx/conf.d/20-vkarmani-selfsteal.conf /etc/nginx/conf.d/20-vkarmani-reality-cover.conf
fi
nginx -t
vk_write_nginx_dropin
systemctl daemon-reload
systemctl enable nginx
systemctl restart nginx
[[ $(curl --noproxy '*' -4sS --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:80:$PUBLIC_IP" "http://$DOMAIN/") == 301 ]] || die 'Nginx HTTP redirect check failed.'
certbot certonly --webroot --webroot-path /var/www/vkarmani-node/acme \
    --domain "$DOMAIN" --cert-name "$DOMAIN" --register-unsafely-without-email \
    --agree-tos --non-interactive --keep-until-expiring --key-type ecdsa --preferred-challenges http
NGINX_NUM=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')
NGINX_HTTP2_LISTEN='http2'
NGINX_HTTP2_DIRECTIVE=''
if dpkg --compare-versions "$NGINX_NUM" ge 1.25.1; then
    NGINX_HTTP2_LISTEN=''
    NGINX_HTTP2_DIRECTIVE='http2 on;'
fi
cat > /etc/nginx/conf.d/20-vkarmani-selfsteal.conf <<EOF
server {
    listen unix:/run/vkarmani-selfsteal/nginx.sock ssl $NGINX_HTTP2_LISTEN proxy_protocol;
    $NGINX_HTTP2_DIRECTIVE
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_session_cache shared:VKARMANI_SELFSTEAL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    root /var/www/vkarmani-node/site;
    index index.html;
    access_log off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    keepalive_timeout 65s;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    location = /robots.txt { try_files \$uri =404; }
    location = /favicon.svg { try_files \$uri =404; }
    location /assets/ { try_files \$uri =404; expires 1h; }
    location / { try_files \$uri \$uri/ =404; }
}
EOF
rm -f /etc/nginx/conf.d/20-vkarmani-reality-cover.conf
nginx -t
systemctl reload nginx
for _ in $(seq 1 20); do [[ -S /run/vkarmani-selfsteal/nginx.sock ]] && break; sleep 1; done
[[ -S /run/vkarmani-selfsteal/nginx.sock ]] || die 'Selfsteal socket /run/vkarmani-selfsteal/nginx.sock не создан Nginx.'
vk_write_selfsteal_check
timeout 25 /usr/local/sbin/vkarmani-selfsteal-check
cat > /usr/local/sbin/vkarmani-wait-selfsteal <<'WAITSELF'
#!/usr/bin/env bash
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SECONDS=0
while (( SECONDS < 60 )); do
    remaining=$((60 - SECONDS))
    budget=$((remaining < 22 ? remaining : 22))
    if [[ -S /run/vkarmani-selfsteal/nginx.sock ]] && timeout --kill-after=2s "${budget}s" /usr/local/sbin/vkarmani-selfsteal-check >/dev/null 2>&1; then
        exit 0
    fi
    (( SECONDS >= 60 )) || sleep 1
done
echo 'SELFSTEAL_NOT_READY: 60-second budget exhausted; check nginx, socket and loaded certificate.' >&2
exit 1
WAITSELF
chmod 0755 /usr/local/sbin/vkarmani-wait-selfsteal
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx <<'EOF'
#!/bin/sh
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
/usr/local/sbin/vkarmani-wait-selfsteal
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx
systemctl enable --now certbot.timer
if [[ $(helper get certbot_dry_run) == true && ! -f "$STATE/certbot-dry-run-pass" ]]; then
    certbot renew --cert-name "$DOMAIN" --dry-run --non-interactive
    touch "$STATE/certbot-dry-run-pass"
fi

stage 'RemnaNode: проверка введённого SECRET_KEY, образ по digest, автозапуск'
if [[ $FRESH -eq 0 ]]; then systemctl stop vkarmani-node.service || true; fi
helper secret
vk_write_tls_check
if [[ ! -s "$STATE/image-digest" ]]; then
    timeout --foreground 900 docker pull "$IMAGE"
    DIGEST=$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}')
    [[ "$DIGEST" =~ ^(remnawave/node|ghcr.io/remnawave/node)@sha256:[a-f0-9]{64}$ ]] || die 'Не удалось зафиксировать официальный образ по digest.'
    printf '%s\n' "$DIGEST" > "$STATE/image-digest"
fi
DIGEST=$(cat "$STATE/image-digest")
[[ "$DIGEST" =~ ^(remnawave/node|ghcr\.io/remnawave/node)@sha256:[a-f0-9]{64}$ ]] || die 'Повреждён сохранённый image-digest; не применяю Compose.'
NET_ADMIN_YAML=''
if [[ $ALLOW_NET_ADMIN -eq 1 ]]; then
    NET_ADMIN_YAML=$'    cap_add:\n      - NET_ADMIN'
    echo 'WARN: NET_ADMIN разрешён явно. RemnaNode plugins могут менять firewall/соединения хоста.'
fi
cat > "$OPT/compose.yaml" <<EOF
name: vkarmani-node
services:
  remnanode:
    image: $DIGEST
    container_name: remnanode
    hostname: remnanode
    network_mode: host
    restart: always
    stop_grace_period: 30s
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - NET_RAW
$NET_ADMIN_YAML
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    env_file:
      - $ETC/remnanode.env
    volumes:
      - type: bind
        source: /run/vkarmani-selfsteal
        target: /dev/shm
        read_only: true
        bind:
          create_host_path: false
    logging:
      driver: local
      options:
        max-size: "10m"
        max-file: "3"
EOF
# Compose config can expand secrets; never print its output.
docker compose -f "$OPT/compose.yaml" config --quiet
vk_write_node_unit
systemctl daemon-reload
systemctl disable vkarmani-node.service 2>/dev/null || true
# Explicit up also reconciles a resumed run when the oneshot unit already says active.
docker compose -f "$OPT/compose.yaml" up -d
systemctl start vkarmani-node
for attempt in $(seq 1 6); do
    if helper control-ready >/dev/null 2>&1; then break; fi
    sleep 2
 done
helper control-ready
[[ $(docker inspect remnanode --format '{{.State.Running}}') == true ]] || die 'RemnaNode не запущен.'
docker exec remnanode test -S /dev/shm/nginx.sock || die 'RemnaNode container не видит /dev/shm/nginx.sock.'
timeout 25 /usr/local/sbin/vkarmani-selfsteal-check
helper keys
CORE=$(docker exec remnanode sh -c 'command -v rw-core || command -v xray')
[[ "$CORE" == /* && "$CORE" != *$'\n'* ]] || die 'Xray/rw-core не найден в официальном образе.'
# Validate the generated IMPORT template with the bundled Xray; do not inject it as live config.
docker cp "$ETC/profile.json" remnanode:/tmp/vkarmani-profile-test.json >/dev/null
if ! docker exec remnanode "$CORE" run -test -config /tmp/vkarmani-profile-test.json > "$STATE/xray-config-test.log" 2>&1; then
    docker exec remnanode rm -f /tmp/vkarmani-profile-test.json || true
    die "Xray отклонил конфиг. Закрытый журнал: $STATE/xray-config-test.log"
fi
docker exec remnanode rm -f /tmp/vkarmani-profile-test.json

stage 'RAW + REALITY профиль и параметры для панели (без API-токена)'
helper panel-guide
printf 'Профиль: /etc/vkarmani-node/profile.json\nИнструкция: /etc/vkarmani-node/PANEL-SETUP.txt\n'
printf 'Карточка ноды и назначение профиля выполняются в панели. Секрет не является API-токеном.\n' 

stage 'Расписание обслуживания: weekly reboot только по --weekly-reboot'
cat > /etc/systemd/system/vkarmani-weekly-reboot.service <<'EOF'
[Unit]
Description=VKarmani scheduled Monday 04:00 Moscow reboot
ConditionPathExists=/etc/vkarmani-node/weekly-reboot-enabled
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reboot
EOF
cat > /etc/systemd/system/vkarmani-weekly-reboot.timer <<'EOF'
[Unit]
Description=VKarmani reboot every Monday at 04:00 Europe/Moscow
[Timer]
OnCalendar=Mon *-*-* 04:00:00 Europe/Moscow
AccuracySec=1s
RandomizedDelaySec=0
Persistent=false
Unit=vkarmani-weekly-reboot.service
[Install]
WantedBy=timers.target
EOF
if [[ $WEEKLY_REBOOT -eq 1 ]]; then
    touch "$ETC/weekly-reboot-enabled"
else
    rm -f "$ETC/weekly-reboot-enabled"
fi
cat > /usr/local/sbin/vkarmani-node-cleanup <<'EOF'
#!/usr/bin/env bash
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
exec 8>/run/lock/vkarmani-node-installer.lock
flock -n 8 || exit 0
# Only APT download cache and archived journals within the documented retention.
# Serialize with installation/image updates; no package/image/data deletion.
apt-get clean
journalctl --rotate
journalctl --vacuum-time=14d --vacuum-size=200M
# Never autoremove packages, delete backups, prune images, containers or volumes.
# The previous image must remain available for a controlled rollback.
EOF
chmod 0755 /usr/local/sbin/vkarmani-node-cleanup
cat > /etc/systemd/system/vkarmani-node-cleanup.service <<'EOF'
[Unit]
Description=VKarmani bounded cache and old journal cleanup
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-cleanup
TimeoutStartSec=900
EOF
cat > /etc/systemd/system/vkarmani-node-cleanup.timer <<'EOF'
[Unit]
Description=VKarmani weekly safe cleanup
[Timer]
OnCalendar=Sun *-*-* 03:10:00 Europe/Moscow
Persistent=false
[Install]
WantedBy=timers.target
EOF
cat > /etc/logrotate.d/vkarmani-node <<'EOF'
/var/log/vkarmani-node-*.log {
    weekly
    rotate 4
    maxsize 10M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su root root
}
EOF

stage 'Контроль после перезагрузки и диагностическая команда'
vk_write_acceptance
vk_write_maintenance
cat > /etc/systemd/system/vkarmani-node-postboot.service <<'EOF'
[Unit]
Description=VKarmani node post-boot acceptance
Wants=network-online.target docker.service nginx.service chrony.service fail2ban.service vkarmani-node-network.service ufw.service
After=network-online.target docker.service nginx.service chrony.service fail2ban.service vkarmani-node-network.service ufw.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vkarmani-node-check --postboot
TimeoutStartSec=720
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vkarmani-node-postboot
systemctl enable --now vkarmani-node-cleanup.timer
if [[ $WEEKLY_REBOOT -eq 1 ]]; then
    systemctl enable --now vkarmani-weekly-reboot.timer
else
    systemctl disable --now vkarmani-weekly-reboot.timer
fi

stage 'Очистка только APT-кэша и ограниченных журналов'
apt-get clean
/usr/local/sbin/vkarmani-node-check --preboot
printf 'version=%s\nat=%s\nimage=%s\n' "$INSTALLER_VERSION" "$(date -Is)" "$DIGEST" > "$STATE/INSTALL_COMPLETE"
rm -f "$STATE/INSTALL_FAILED" "$STATE/image-update-pending"
stage 'Установка завершена; проверки ДО перезагрузки пройдены'
printf 'Домен: %s\nIPv4: %s\nУправляющий порт: %s (только IP панели)\n' "$DOMAIN" "$PUBLIC_IP" "$NODE_PORT"
printf 'Разрешённые IPv4 панели: %s\n' "${PANEL_IPS[*]}"
printf 'Внешний firewall хостера (если есть): разрешить TCP/%s от %s к Node Address, указанному в панели.\n' "$NODE_PORT" "${PANEL_IPS[*]}"
printf 'Транспорт: VLESS + RAW + REALITY; Selfsteal: /dev/shm/nginx.sock (xver=1)\n'
printf 'Профиль и действия в панели: /etc/vkarmani-node/PANEL-SETUP.txt\n'
printf 'SSH-порты сохранены: %s\n' "${SSH_PORTS[*]}"
printf 'Проверка после входа: sudo vkarmani-node-check\nЖурнал: /var/log/vkarmani-node-postboot.log\n'
printf 'Резервная копия: %s\nПолное отключение IPv6 проверяется ПОСЛЕ загрузки нового ядра.\n' "$BK"
systemctl list-timers --no-pager vkarmani-weekly-reboot.timer
if [[ $NO_REBOOT -eq 0 ]]; then
    # Scheduled by systemd rather than a background shell; survives SSH closure.
    systemd-run --collect --unit="vkarmani-install-reboot-$(date +%s)" --on-active=15s /usr/bin/systemctl reboot
    echo 'AUTO_REBOOT=ARMED. SSH отключится; после загрузки все настроенные службы запустятся автоматически.'
    sync
else
    echo 'REBOOT_REQUIRED: автоматический reboot не запрошен. После проверки нового парольного SSH-входа выполните sudo reboot.'
fi

}
vkarmani_repair_main() {
    set -Eeuo pipefail
    set +x
    umask 077
    export LC_ALL=C LANG=C PYTHONUTF8=1
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    [[ $# -eq 0 ]] || { echo 'Использование: bash install.sh --repair-node'; exit 2; }
    [[ $EUID -eq 0 ]] || { echo 'Запустите на НОДЕ от root.'; exit 1; }
    ETC=/etc/vkarmani-node
    STATE=/var/lib/vkarmani-node
    HELPER=/usr/local/lib/vkarmani-node/node_helper.py
    [[ -f "$STATE/owned-installation" && -s "$STATE/INSTALL_COMPLETE" && -s "$HELPER" && -s /opt/vkarmani-node/compose.yaml ]] || {
        echo 'STOP: завершённая установка нашего скрипта не найдена. Изменений нет. Незавершённую установку продолжайте обычным запуском.'; exit 1;
    }
    grep -Eq '^version=1\.3\.[0-9]+$' "$STATE/INSTALL_COMPLETE" || {
        echo 'STOP: --repair-node поддерживает только завершённые установки 1.3.x.'; exit 1;
    }
    exec 9>/run/lock/vkarmani-node-installer.lock
    flock -n 9 || { echo 'Другой процесс установки или исправления уже работает.'; exit 1; }
    for cmd in python3 docker ufw nginx fail2ban-client systemctl; do command -v "$cmd" >/dev/null; done
    systemctl is-active --quiet docker
    ufw status | grep -F 'Status: active' >/dev/null || { echo 'STOP: ожидался уже активный UFW. Чужую конфигурацию не меняю.'; exit 1; }
    python3 "$HELPER" secret >/dev/null
    DOMAIN=$(python3 "$HELPER" get domain)
    PUBLIC_IP=$(python3 "$HELPER" get public_ipv4)
    NODE_PORT=$(python3 "$HELPER" get node_port)
    mapfile -t PANEL_IPS < <(python3 "$HELPER" get panel_ipv4)
    mapfile -t SSH_PORTS < "$ETC/ssh-ports"
    [[ ${#PANEL_IPS[@]} -gt 0 && ${#SSH_PORTS[@]} -gt 0 ]]
    ADMIN_IP=$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")
    python3 - "$PUBLIC_IP" "$NODE_PORT" "$ADMIN_IP" "${PANEL_IPS[@]}" <<'PY'
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
assert 1024 <= int(sys.argv[2]) <= 65535
for value in sys.argv[3:]:
    if value: ipaddress.IPv4Address(value)
PY
    for port in "${SSH_PORTS[@]}"; do [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; done
    ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fx "$PUBLIC_IP" >/dev/null || {
        echo 'STOP: сохранённый IP не назначен ноде; сетевую конфигурацию автоматически не подменяю.'; exit 1;
    }
    IMAGE_BEFORE=$(docker inspect remnanode --format '{{.Image}}')
    REF=$(docker inspect remnanode --format '{{.Config.Image}}')
    [[ "$REF" =~ ^(remnawave/node|ghcr.io/remnawave/node)(:|@) ]] || { echo 'STOP: неожиданный образ контейнера.'; exit 1; }
    [[ $(docker inspect remnanode --format '{{.HostConfig.NetworkMode}}') == host ]]
    [[ $(docker inspect remnanode --format '{{.HostConfig.RestartPolicy.Name}}') == always ]]
    docker compose -f /opt/vkarmani-node/compose.yaml config --quiet
    # Resolve the declared image without printing the expanded environment.
    COMPOSE_IMAGE=$(docker compose -f /opt/vkarmani-node/compose.yaml config --format json |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["remnanode"]["image"])')
    [[ $(docker image inspect "$COMPOSE_IMAGE" --format '{{.Id}}') == "$IMAGE_BEFORE" ]] || {
        echo 'STOP: Compose и запущенная нода используют разные образы; автоматическая замена запрещена.'; exit 1;
    }
    nginx -t
    BK="$STATE/backups/repair-2.0.2-$(date +%Y%m%d-%H%M%S)-$$"
    install -d -m 0700 "$BK"
    local -a paths=(
        /usr/local/sbin/vkarmani-node-check
        /usr/local/sbin/vkarmani-node-tls-check
        /usr/local/sbin/vkarmani-selfsteal-check
        /usr/local/sbin/vkarmani-selfsteal-socket-prepare
        /usr/local/sbin/vkarmani-node-network
        /etc/systemd/system/vkarmani-node.service
        /etc/systemd/system/vkarmani-node-network.service
        /etc/systemd/system/vkarmani-node-postboot.service
        /etc/systemd/system/nginx.service.d/90-vkarmani-resilience.conf
        /etc/nginx/conf.d/20-vkarmani-selfsteal.conf
        /etc/fail2ban/fail2ban.local
        /etc/fail2ban/action.d/vkarmani-ufw-sshd.conf
        /etc/fail2ban/jail.d/99-vkarmani-sshd.local
        /etc/ufw/applications.d/vkarmani-sshd
    )
    : > "$BK/present"; : > "$BK/absent"
    for f in "${paths[@]}"; do
        if [[ -e "$f" ]]; then cp -a --parents "$f" "$BK/"; printf '%s\n' "$f" >> "$BK/present";
        else printf '%s\n' "$f" >> "$BK/absent"; fi
    done
    WRAPPER_WAS_ENABLED=$(systemctl is-enabled vkarmani-node.service 2>/dev/null || true)
    REPAIR_TRAPPED=0
    repair_error() {
        local rc=${1:-1} line=${2:-unknown}
        [[ $REPAIR_TRAPPED -eq 0 ]] || exit "$rc"
        REPAIR_TRAPPED=1
        trap - ERR INT TERM HUP
        set +e
        echo "REPAIR_FAILED rc=$rc line=$line; возвращаю управляемые файлы из $BK"
        while IFS= read -r f; do cp -a "$BK$f" "$f"; done < "$BK/present"
        while IFS= read -r f; do rm -f -- "$f"; done < "$BK/absent"
        systemctl daemon-reload
        if [[ "$WRAPPER_WAS_ENABLED" == enabled ]]; then systemctl enable vkarmani-node.service; fi
        systemctl restart fail2ban
        if nginx -t; then systemctl reload-or-restart nginx; fi
        docker compose -f /opt/vkarmani-node/compose.yaml up -d --pull never
        echo 'Выполнена попытка отката файлов. Добавленное разрешение UFW только для IP панели сохранено. Общего открытия firewall не было.'
        echo 'Перезагрузка и обновление образа не запрашивались. Проверьте журнал исправления.'
        exit "$rc"
    }
    trap 'repair_error "$?" "$LINENO"' ERR
    trap 'repair_error 130 "$LINENO"' INT
    trap 'repair_error 143 "$LINENO"' TERM
    trap 'repair_error 129 "$LINENO"' HUP
    LOG=/var/log/vkarmani-node-repair.log
    touch "$LOG"; chmod 0600 "$LOG"
    exec > >(exec 9>&-; tee -a "$LOG") 2>&1
    echo 'VKarmani 2.0.2 — исправление только на НОДЕ'
    echo "Резервная копия: $BK"
    echo 'Без APT, перезапуска Docker daemon, изменений SSH, маршрутов/MTU, замены ключей и reboot.'
    echo 'RemnaNode ненадолго остановится для удаления старой зависимости systemd.'
    systemctl stop vkarmani-node.service
    vk_write_tls_check
    vk_write_selfsteal_check
    vk_write_acceptance
    vk_write_network_script
    vk_write_network_unit
    vk_write_node_unit
    vk_write_nginx_dropin
    # Remove only the old dependency from our own postboot unit, never host networking units.
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/systemd/system/vkarmani-node-postboot.service')
if p.exists():
    s=p.read_text().replace('vkarmani-node.service', 'docker.service')
    lines=[]
    for line in s.splitlines():
        if line.startswith(('Wants=', 'After=')):
            for unit in ('vkarmani-node-network.service', 'ufw.service'):
                if unit not in line.split('=', 1)[1].split():
                    line += ' ' + unit
        lines.append(line)
    p.write_text('\n'.join(lines)+'\n')
p=Path('/etc/nginx/conf.d/20-vkarmani-selfsteal.conf')
if p.exists():
    s=p.read_text()
    if 'listen unix:/dev/shm/nginx.sock' not in s:
        raise SystemExit('STOP: неожиданная конфигурация нашего Selfsteal')
    s=s.replace('location / { try_files $uri $uri/ /index.html; }',
                'location / { try_files $uri $uri/ =404; }')
    p.write_text(s)
PY
    # Keep the panel API source restriction, remove the accidental DNS-IP coupling.
    # No flush, reset, broad allow, arbitrary rule deletion or nftables table removal.
    for panel in "${PANEL_IPS[@]}"; do
        ufw allow proto tcp from "$panel" to any port "$NODE_PORT" comment 'VKarmani panel management'
        if fail2ban-client status sshd >/dev/null 2>&1; then
            fail2ban-client set sshd unbanip "$panel" >/dev/null
        fi
    done
    # Stop before changing the action, so old SSH bans are removed using the OLD action.
    systemctl stop fail2ban
    vk_write_fail2ban_config
    fail2ban-client -t
    nginx -t
    systemctl daemon-reload
    systemctl disable vkarmani-node.service
    systemctl restart vkarmani-node-network.service
    systemctl restart fail2ban
    # Independent Nginx reload cannot stop Node anymore.
    systemctl reload-or-restart nginx
    /usr/local/sbin/vkarmani-selfsteal-check
    docker compose -f /opt/vkarmani-node/compose.yaml up -d --pull never
    [[ $(docker inspect remnanode --format '{{.Image}}') == "$IMAGE_BEFORE" ]] || {
        echo 'STOP: образ неожиданно изменился'; false;
    }
    # The manual compatibility wrapper stays disabled. Docker owns boot/restart.
    for attempt in $(seq 1 5); do
        if /usr/local/sbin/vkarmani-node-tls-check >/dev/null 2>&1; then break; fi
        sleep 2
    done
    /usr/local/sbin/vkarmani-node-check --local
    printf 'version=2.0.2\nat=%s\n' "$(date -Is)" > "$STATE/REPAIR_COMPLETE"
    trap - ERR INT TERM HUP
    echo 'REPAIR_LOCAL=PASS; PANEL_CONNECTION=NOT_VERIFIED'
    echo 'Дефекты конфигурации исправлены; это не подтверждение подключения панели.'
    echo 'Reboot не запланирован. Для диагностики таймаута не запускайте полную установку заново.'
}

vkarmani_repair_network_main() {
    set -Eeuo pipefail
    set +x
    umask 077
    export LC_ALL=C LANG=C PYTHONUTF8=1
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    [[ $# -eq 0 ]] || { echo 'Использование: bash install.sh --repair-network'; exit 2; }
    [[ $EUID -eq 0 ]] || { echo 'Запустите на НОДЕ от root.'; exit 1; }
    local state=/var/lib/vkarmani-node
    local conf=/etc/sysctl.d/99-vkarmani-node.conf
    local unit=vkarmani-node-network.service
    local helper=/usr/local/sbin/vkarmani-node-network
    local unit_file=/etc/systemd/system/vkarmani-node-network.service
    [[ -f "$state/owned-installation" && -s "$state/INSTALL_COMPLETE" && -s "$conf" && -f "$helper" && -f "$unit_file" ]] || {
        echo 'STOP: завершённая установка VKarmani Node не найдена. Изменений нет.'; exit 1;
    }
    grep -Eq '^version=1\.3\.[0-9]+$' "$state/INSTALL_COMPLETE" || {
        echo 'STOP: --repair-network рассчитан на завершённую установку 1.3.x.'; exit 1;
    }
    for cmd in python3 sysctl modprobe systemctl journalctl flock; do command -v "$cmd" >/dev/null; done
    [[ -d /run/systemd/system ]] || { echo 'STOP: нужен systemd.'; exit 1; }
    exec 9>/run/lock/vkarmani-node-installer.lock
    flock -n 9 || { echo 'Другой процесс установки/исправления уже работает.'; exit 1; }
    local bk="$state/backups/network-2.0.2-$(date +%Y%m%d-%H%M%S)-$$"
    install -d -m 0700 "$bk"
    cp -a "$helper" "$bk/network-helper.before"
    cp -a "$unit_file" "$bk/network-unit.before"
    cp -a "$conf" "$bk/sysctl.before"
    journalctl -b -u "$unit" -n 60 --no-pager > "$bk/network-journal.before" 2>&1 || true
    local was_enabled
    was_enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    touch /var/log/vkarmani-node-network-repair.log
    chmod 0600 /var/log/vkarmani-node-network-repair.log
    exec > >(exec 9>&-; tee -a /var/log/vkarmani-node-network-repair.log) 2>&1
    echo 'VKarmani 2.0.2 — исправление применения sysctl после отключения IPv6'
    echo "Резервная копия: $bk"
    echo 'Без APT, reboot, рестарта Docker/RemnaNode/Nginx, изменения ключей, firewall, адресов, маршрутов или MTU.'
    echo '===== ЖУРНАЛ NETWORK ДО ИСПРАВЛЕНИЯ ====='
    tail -n 20 "$bk/network-journal.before"
    local trapped=0
    network_repair_error() {
        local rc=${1:-1} line=${2:-unknown}
        [[ $trapped -eq 0 ]] || exit "$rc"
        trapped=1
        trap - ERR INT TERM HUP
        set +e
        echo "NETWORK_REPAIR=FAIL rc=$rc line=$line; возвращаю два изменённых файла."
        cp -a "$bk/network-helper.before" "$helper"
        cp -a "$bk/network-unit.before" "$unit_file"
        systemctl daemon-reload
        [[ "$was_enabled" != disabled ]] || systemctl disable "$unit"
        echo "Старый журнал и резервная копия: $bk"
        echo 'Частично применённые sysctl автоматически не откатываются; исходный sysctl-конфиг не менялся.'
        exit "$rc"
    }
    trap 'network_repair_error "$?" "$LINENO"' ERR
    trap 'network_repair_error 130 "$LINENO"' INT
    trap 'network_repair_error 143 "$LINENO"' TERM
    trap 'network_repair_error 129 "$LINENO"' HUP
    vk_write_network_script
    vk_write_network_unit
    systemctl daemon-reload
    systemctl enable "$unit"
    systemctl reset-failed "$unit" || true
    if ! systemctl restart "$unit"; then
        journalctl -b -u "$unit" -n 30 --no-pager || true
        false
    fi
    systemctl is-active --quiet "$unit"
    [[ $(sysctl -n net.ipv4.tcp_congestion_control) == bbr ]]
    [[ $(sysctl -n net.core.default_qdisc) == fq ]]
    printf 'version=2.0.2\nat=%s\n' "$(date -Is)" > "$state/NETWORK_REPAIR_COMPLETE"
    trap - ERR INT TERM HUP
    echo 'NETWORK_REPAIR=PASS'
    journalctl -b -u "$unit" -n 12 --no-pager || true
    # Re-run the existing diagnostic unit, not the application/container services.
    if [[ -f /etc/systemd/system/vkarmani-node-postboot.service ]]; then
        echo '===== ПОВТОРНАЯ POSTBOOT-ПРОВЕРКА ====='
        systemctl reset-failed vkarmani-node-postboot.service || true
        if systemctl restart vkarmani-node-postboot.service; then
            echo 'POSTBOOT_LOCAL=PASS; это не проверка подключения панели.'
        else
            echo 'POSTBOOT_LOCAL=FAIL; исправление network сохранено, остались другие локальные ошибки.'
            tail -n 70 /var/log/vkarmani-node-postboot.log 2>/dev/null || true
        fi
    fi
    echo '===== СТРОГАЯ ПРОВЕРКА БЕЗ ПЕРЕЗАПУСКА НОДЫ ====='
    local check_rc=0
    if [[ -x /usr/local/sbin/vkarmani-node-check ]]; then
        /usr/local/sbin/vkarmani-node-check --require-xray || check_rc=$?
        echo "CHECK_EXIT_CODE=$check_rc"
    else
        echo 'NODE_CHECK=MISSING'; check_rc=1
    fi
    echo 'PANEL_CONNECTION=NOT_VERIFIED; автоматический reboot не назначен.'
    echo 'NETWORK_REPAIR относится только к применению sysctl, не к авторизации панели или VPN.'
    return "$check_rc"
}

# VKARMANI_COMPLETE_PAYLOAD_2_0_2
# Sourcing definitions is intentionally inert: used by offline regression tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --repair-network) shift; vkarmani_repair_network_main "$@" ;;
        --repair-node) shift; vkarmani_repair_main "$@" ;;
        --check)
            shift
            [[ -x /usr/local/sbin/vkarmani-node-check ]] || { echo 'Сначала установите ноду.'; exit 1; }
            exec /usr/local/sbin/vkarmani-node-check "$@"
            ;;
        --backup|--refresh-image|--rollback-image)
            ACTION=${1#--}; shift
            [[ -x /usr/local/sbin/vkarmani-node-maintain ]] || { echo 'Нужна завершённая установка 2.0.2. Старые ноды автоматически не мигрируются.'; exit 1; }
            exec /usr/local/sbin/vkarmani-node-maintain "$ACTION" "$@"
            ;;
        *) vkarmani_main "$@" ;;
    esac
fi
