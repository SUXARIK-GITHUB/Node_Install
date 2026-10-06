#!/usr/bin/env bash
# VKarmani Node 2.5.2. Read README.md before running as root.
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
import os
import re
import stat
import subprocess
from html.parser import HTMLParser
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


def check(domain, path=SOCKET, site=SITE, cafile=None, timeout=20.0, expected_leaf=None, extended=False, reject_unknown_sni=True):
    deadline = time.monotonic() + timeout
    content = local_bytes(Path(site))
    expected = hashlib.sha256(content).digest()
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

    if extended:
        check_web_contract(domain, path, Path(site), content, cafile, deadline,
                           expected_leaf, reject_unknown_sni)


def local_bytes(path):
    """Bounded, no-follow regular file read; public content only."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError('UNSAFE_COVER_FILE')
        if st.st_size > 131072:
            raise ValueError('COVER_PAGE_EXCEEDS_128_KIB_PROBE_LIMIT')
        data = f.read(131073)
        after = os.fstat(f.fileno())
    if len(data) > 131072 or (st.st_size, st.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('COVER_FILE_CHANGED_OR_TOO_LARGE')
    return data


class Assets(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'link' and attrs.get('rel') in ('stylesheet', 'icon'):
            path = attrs.get('href', '')
            if not re.fullmatch(r'assets/(?:style-[0-9a-f]{20}[.]css|icon-[0-9a-f]{20}[.]svg)', path):
                raise ValueError('COVER_ASSET_REFERENCE_NOT_LOCAL_VERSIONED')
            self.paths.add(path)


def http1_request(domain, path, cafile, deadline, expected_leaf,
                  uri='/', method='GET', host=None, etag=None):
    if (not re.fullmatch(r'/[A-Za-z0-9_./-]*', uri) or method not in ('GET', 'HEAD', 'POST')
            or '\r' in (host or domain) or '\n' in (host or domain)
            or etag is not None and not re.fullmatch(r'"[0-9a-f-]{1,80}"', etag)):
        raise ValueError('UNSAFE_PROBE_REQUEST')
    request = f'{method} {uri} HTTP/1.1\r\nHost: {host or domain}\r\nConnection: close\r\nAccept-Encoding: identity\r\n'
    if etag is not None:
        request += 'If-None-Match: ' + etag + '\r\n'
    if method == 'POST':
        request += 'Content-Length: 0\r\n'
    with connect(domain, 'http/1.1', path, cafile, deadline, expected_leaf) as c:
        c.sendall((request + '\r\n').encode('ascii'))
        data = bytearray()
        while True:
            piece = c.recv(8192)
            if not piece:
                break
            data.extend(piece)
            if len(data) > 147456:
                raise ValueError('COVER_HTTP_RESPONSE_TOO_LARGE')
    head, sep, body = bytes(data).partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    if not sep or not re.fullmatch(rb'HTTP/1[.]1 [1-5][0-9]{2} [^\r\n]*', lines[0]):
        raise ValueError('INVALID_COVER_HTTP_RESPONSE')
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b':')
        if not colon:
            raise ValueError('INVALID_COVER_HTTP_HEADER')
        key, value = key.decode('ascii').lower(), value.decode('ascii').strip()
        if key in headers:
            raise ValueError('DUPLICATE_COVER_HTTP_HEADER')
        headers[key] = value
    if 'transfer-encoding' in headers or headers.get('content-encoding', 'identity') != 'identity':
        raise ValueError('UNEXPECTED_COVER_TRANSFER_ENCODING')
    if method == 'HEAD' or status == 304:
        if body:
            raise ValueError('COVER_HEAD_OR_304_HAS_BODY')
    elif headers.get('content-length') != str(len(body)):
        raise ValueError('COVER_CONTENT_LENGTH_MISMATCH')
    return status, headers, body


def security_headers(headers):
    required = ("default-src 'none'", "style-src 'self'", "img-src 'self'",
                "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'")
    if (headers.get('x-content-type-options') != 'nosniff'
            or headers.get('referrer-policy') != 'strict-origin-when-cross-origin'
            or any(part not in headers.get('content-security-policy', '') for part in required)):
        raise ValueError('COVER_SECURITY_HEADERS_MISSING')
    if re.search(r'nginx/[0-9]', headers.get('server', ''), re.I):
        raise ValueError('COVER_SERVER_VERSION_EXPOSED')


def negative_sni(path, name, deadline):
    """Negative probe: success means the SERVER refuses TLS, not a client CA error.
    CERT_NONE is intentionally used only here, never for acceptance/content.
    A dropped connection or timeout is not sufficient evidence of this policy.
    """
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SELFSTEAL_DEADLINE_EXCEEDED')
        raw.settimeout(min(5, remaining))
        raw.connect(path)
        raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 54321 443\r\n')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        try:
            with ctx.wrap_socket(raw, server_hostname=name):
                raise ValueError('UNEXPECTED_SNI_ACCEPTED')
        except ssl.SSLError as exc:
            if exc.reason not in ('TLSV1_UNRECOGNIZED_NAME', 'SSLV3_ALERT_HANDSHAKE_FAILURE'):
                raise ValueError('SNI_REFUSAL_NOT_CONFIRMED') from None
    finally:
        raw.close()


def check_web_contract(domain, path, site, content, cafile, deadline, expected_leaf, reject_unknown_sni):
    def request(**kw):
        return http1_request(domain, path, cafile, deadline, expected_leaf, **kw)
    status, headers, body = request(method='HEAD')
    if status != 200 or headers.get('content-length') != str(len(content)):
        raise ValueError('COVER_HEAD_CONTRACT_FAILED')
    security_headers(headers)
    if 'no-cache' not in headers.get('cache-control', ''):
        raise ValueError('COVER_HTML_CACHE_POLICY_FAILED')
    parser = Assets()
    parser.feed(content.decode('utf-8'))
    parser.close()
    if not 1 <= len(parser.paths) <= 8 or not any(x.endswith('.css') for x in parser.paths):
        raise ValueError('COVER_VERSIONED_ASSETS_MISSING_OR_TOO_MANY')
    asset_dir = site.parent / 'assets'
    if asset_dir.is_symlink() or not asset_dir.is_dir():
        raise ValueError('UNSAFE_COVER_ASSET_DIRECTORY')
    for rel in sorted(parser.paths):
        expected = local_bytes(site.parent / rel)
        if hashlib.sha256(expected).hexdigest()[:20] not in rel:
            raise ValueError('COVER_ASSET_HASH_NAME_MISMATCH')
        status, headers, body = request(uri='/' + rel)
        mime = 'text/css' if rel.endswith('.css') else 'image/svg+xml'
        if status != 200 or body != expected or headers.get('content-type', '').split(';')[0] != mime:
            raise ValueError('COVER_ASSET_RESPONSE_FAILED')
        security_headers(headers)
        if 'max-age=604800' not in headers.get('cache-control', ''):
            raise ValueError('COVER_ASSET_CACHE_POLICY_FAILED')
        if not headers.get('etag'):
            raise ValueError('COVER_ASSET_ETAG_MISSING')
        status, h304, body = request(uri='/' + rel, etag=headers['etag'])
        if status != 304:
            raise ValueError('COVER_ASSET_REVALIDATION_FAILED')
        security_headers(h304)
    for uri, mime in (('/robots.txt', 'text/plain'), ('/favicon.svg', 'image/svg+xml')):
        expected_file = local_bytes(site.parent / uri[1:])
        status, headers, body = request(uri=uri)
        if status != 200 or body != expected_file or headers.get('content-type', '').split(';')[0] != mime:
            raise ValueError('COVER_AUXILIARY_STATIC_FAILED')
        security_headers(headers)
    expected_404 = local_bytes(site.parent / '404.html')
    for uri in ('/.env', '/config.json', '/vk-unlisted-path', '/assets/unlisted.css'):
        status, headers, not_found = request(uri=uri)
        if status != 404 or not_found != expected_404:
            raise ValueError('COVER_UNLISTED_PATH_NOT_404')
        security_headers(headers)
    if request(method='POST')[0] != 405:
        raise ValueError('COVER_WRITE_METHOD_NOT_REJECTED')
    if request(host='wrong.example.invalid')[0] != 421:
        raise ValueError('COVER_HOST_GUARD_FAILED')
    if reject_unknown_sni:
        negative_sni(path, 'wrong.example.invalid', deadline)
        negative_sni(path, None, deadline)


def nginx_sni_reject_supported():
    p = subprocess.run(['nginx', '-v'], stdin=subprocess.DEVNULL, capture_output=True,
                       timeout=5, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    m = re.search(rb'nginx/([0-9]+)[.]([0-9]+)[.]([0-9]+)', p.stderr)
    if p.returncode or not m:
        raise ValueError('NGINX_VERSION_NOT_VERIFIED')
    return tuple(map(int, m.groups())) >= (1, 19, 4)


def target_tls(domain, path=SOCKET, cafile=None, timeout=15.0, expected_leaf=None):
    """Only verified TLS/ALPN readiness; no dependency on page or asset integrity."""
    if not isinstance(domain, str) or not re.fullmatch(r'[a-z0-9.-]{1,253}', domain):
        raise ValueError('INVALID_TARGET_DOMAIN')
    if not 0 < timeout <= 20:
        raise ValueError('INVALID_PROBE_BUDGET')
    deadline = time.monotonic() + timeout
    for alpn in ('http/1.1', 'h2'):
        with connect(domain, alpn, path, cafile, deadline, expected_leaf):
            pass


def load_target(etc=Path('/etc/vkarmani-node'), cert_root=Path('/etc/letsencrypt/live')):
    """Read bounded local metadata; Certbot certificate symlinks are intentional."""
    fd = os.open(etc / 'config.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('UNSAFE_SELFSTEAL_CONFIG')
        raw = f.read(65537)
    if len(raw) > 65536:
        raise ValueError('SELFSTEAL_CONFIG_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('SELFSTEAL_CONFIG_DUPLICATE_FIELD')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('SELFSTEAL_CONFIG_NONFINITE_VALUE')
    cfg = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    domain = cfg.get('domain') if isinstance(cfg, dict) else None
    if not isinstance(domain, str) or not re.fullmatch(
            r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
        raise ValueError('INVALID_SELFSTEAL_DOMAIN')
    path = cfg.get('selfsteal_host_socket', SOCKET)
    if path not in (SOCKET, '/run/vkarmani-selfsteal/nginx.sock'):
        raise ValueError('UNKNOWN_SELFSTEAL_SOCKET_LAYOUT')
    with (cert_root / domain / 'fullchain.pem').open('rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError('SELFSTEAL_CERTIFICATE_NOT_REGULAR')
        raw = f.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('SELFSTEAL_CERTIFICATE_TOO_LARGE')
    marker = '-----END CERTIFICATE-----'
    text = raw.decode('ascii')
    if marker not in text:
        raise ValueError('SELFSTEAL_CERTIFICATE_PEM_INVALID')
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(text.split(marker, 1)[0] + marker + '\n')).digest()
    return domain, path, fingerprint


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-only', action='store_true', help='TLS/certificate/ALPN only; no web content check')
    args = parser.parse_args()
    try:
        domain, path, expected_leaf = load_target()
        if args.target_only:
            target_tls(domain, path=path, expected_leaf=expected_leaf)
            print('SELFSTEAL_TARGET_TLS=PASS; WEB_CONTENT=NOT_TESTED')
            print('SELFSTEAL_SCOPE=LOCAL_TARGET_ONLY; AUTHENTICATED_VLESS_CLIENT=NOT_TESTED')
            return 0
        reject = nginx_sni_reject_supported()
        check(domain, path=path, expected_leaf=expected_leaf,
              extended=True, reject_unknown_sni=reject)
        print('SELFSTEAL_TLS13_HTTP1_HTTP2=PASS')
        print('SELFSTEAL_STATIC_ASSETS_HEADERS_NEGATIVE_HTTP=PASS')
        print('SELFSTEAL_SNI_REJECT=' + ('PASS' if reject else 'NOT_SUPPORTED_BY_LEGACY_NGINX'))
        print('SELFSTEAL_SCOPE=LOCAL_TARGET_ONLY; AUTHENTICATED_VLESS_CLIENT=NOT_TESTED')
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

vk_write_node_plugins_helper() {
    local destination=${1:-"$LIB/node_plugins.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_NODE_PLUGINS_PY'
#!/usr/bin/env python3
"""Read-only Node Plugins/runtime/public-listener acceptance helpers.

No Panel API, firewall mutation, packet capture, client address inventory or secret output.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
PLUGIN_FLOOR = (26, 3, 27)
SECURITY_FLOOR = (26, 7, 11)
REQUIRED_SETS = {'ingress-filter-ip', 'torrent-blocker', 'egress-filter-ip', 'egress-filter-port'}
REQUIRED_CHAINS = {'input', 'forward', 'output'}


class Unverified(Exception):
    pass


def parse_kernel_version(raw):
    match = re.fullmatch(r'([0-9]+)\.([0-9]+)(?:[.-].*)?', raw.strip())
    if not match:
        raise ValueError('KERNEL_VERSION_MALFORMED')
    return tuple(int(x) for x in match.groups())


def kernel_supported(raw):
    return parse_kernel_version(raw) >= (5, 7)


def parse_xray_version(raw):
    if len(raw) > 65536:
        raise ValueError('XRAY_VERSION_OUTPUT_OVERSIZED')
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    matches = []
    for line in lines:
        match = re.match(r'^Xray\s+v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s|$)', line, re.I)
        if match:
            matches.append(tuple(int(x) for x in match.groups()))
    if len(matches) != 1:
        raise ValueError('XRAY_VERSION_NOT_UNAMBIGUOUS')
    return matches[0]


def xray_floor_status(raw):
    version = parse_xray_version(raw)
    return {
        'version': '.'.join(str(x) for x in version),
        'plugin': version >= PLUGIN_FLOOR,
        'security': version >= SECURITY_FLOOR,
    }


def _run(args, runner=subprocess.run, timeout=8):
    try:
        p = runner(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                   timeout=timeout, env=ENV)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Unverified('COMMAND_TIMEOUT_OR_EXEC_ERROR') from exc
    if p.returncode:
        raise Unverified('COMMAND_NONZERO')
    if len(p.stdout) > 1048576 or len(p.stderr) > 1048576:
        raise Unverified('COMMAND_OUTPUT_OVERSIZED')
    return p.stdout


def xray_runtime_status(runner=subprocess.run):
    raw = _run(DOCKER + ['exec', 'remnanode', 'rw-core', 'version'], runner)
    try:
        return xray_floor_status(raw)
    except ValueError as exc:
        raise Unverified('XRAY_VERSION_INVALID') from exc


def parse_nft_contract(raw):
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('NFT_JSON_OVERSIZED')
    data = json.loads(raw)
    rows = data.get('nftables') if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError('NFT_JSON_SCHEMA_INVALID')
    tables, sets, chains = set(), set(), set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('NFT_JSON_ROW_INVALID')
        table = row.get('table')
        if isinstance(table, dict) and table.get('family') == 'ip' and table.get('name') == 'remnanode':
            tables.add(('ip', 'remnanode'))
        item = row.get('set')
        if isinstance(item, dict) and item.get('family') == 'ip' and item.get('table') == 'remnanode':
            name = item.get('name')
            if isinstance(name, str):
                sets.add(name)
        chain = row.get('chain')
        if isinstance(chain, dict) and chain.get('family') == 'ip' and chain.get('table') == 'remnanode':
            name = chain.get('name')
            if isinstance(name, str):
                chains.add(name)
    if ('ip', 'remnanode') not in tables:
        return False, 'MISSING_TABLE'
    missing_sets = sorted(REQUIRED_SETS - sets)
    if missing_sets:
        return False, 'MISSING_SETS=' + ','.join(missing_sets)
    missing_chains = sorted(REQUIRED_CHAINS - chains)
    if missing_chains:
        return False, 'MISSING_CHAINS=' + ','.join(missing_chains)
    return True, 'STRUCTURE_OK'


def nft_runtime_status(runner=subprocess.run):
    raw = _run(['nft', '-j', 'list', 'table', 'ip', 'remnanode'], runner)
    try:
        return parse_nft_contract(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise Unverified('NFT_JSON_INVALID') from exc


def parse_ss_listeners(raw):
    rows = []
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('SS_OUTPUT_OVERSIZED')
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 5 or fields[0] != 'LISTEN':
            raise ValueError('SS_SCHEMA_UNRECOGNIZED')
        host, sep, port_text = fields[3].rpartition(':')
        if not sep or not port_text.isdigit():
            raise ValueError('SS_LOCAL_ADDRESS_INVALID')
        # iproute2 can render an IPv4 address with an interface scope suffix,
        # e.g. systemd-resolved on Ubuntu 24.04 as 127.0.0.53%lo:53.
        # The scope is display metadata; policy decisions must use the address.
        if '%' in host:
            host, scope = host.split('%', 1)
            if not host or not scope or '%' in scope:
                raise ValueError('SS_LOCAL_ADDRESS_INVALID')
        port = int(port_text)
        if host not in ('*', '0.0.0.0'):
            try:
                addr = ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError as exc:
                raise ValueError('SS_LOCAL_ADDRESS_INVALID') from exc
            if addr.is_loopback:
                continue
        processes = set(re.findall(r'\(\("([^"\\]+)"', line))
        pids = {int(x) for x in re.findall(r'\bpid=([0-9]+)', line)}
        rows.append({'host': host, 'port': port, 'processes': processes, 'pids': pids})
    return rows


def _read_ports(path):
    values = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        raise Unverified('SSH_PORTS_UNREADABLE') from exc
    for line in lines:
        if not re.fullmatch(r'[0-9]+', line) or not 1 <= int(line) <= 65535:
            raise Unverified('SSH_PORTS_INVALID')
        values.append(int(line))
    if not values or len(values) != len(set(values)):
        raise Unverified('SSH_PORTS_INVALID')
    return values


def _config(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise Unverified('CONFIG_UNREADABLE') from exc
    port = data.get('node_port')
    public = data.get('public_ipv4')
    if type(port) is not int or not 1 <= port <= 65535:
        raise Unverified('NODE_PORT_INVALID')
    try:
        public = str(ipaddress.IPv4Address(public))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise Unverified('PUBLIC_IPV4_INVALID') from exc
    return port, public


def public_listener_policy(raw, ssh_ports, node_port, core_pids=None, node_pids=None, require_xray=False, public_ipv4=None):
    rows = parse_ss_listeners(raw)
    expected = {p: {'sshd'} for p in ssh_ports}
    expected[80] = {'nginx'}
    expected[443] = {'rw-core', 'xray'}
    expected[node_port] = {'rw-node', 'node'}
    required = set(ssh_ports) | {80, node_port}
    if require_xray:
        required.add(443)
    present, unexpected, ambiguous, bad_owner, bad_bind = set(), set(), set(), set(), set()
    for row in rows:
        port = row['port']
        if port not in expected:
            unexpected.add(port)
            continue
        present.add(port)
        if public_ipv4 is not None:
            # Nginx/ACME is intentionally bound to the concrete public IPv4.
            if port == 80 and row['host'] != public_ipv4:
                bad_bind.add(port)
                continue
            # The reviewed VLESS profile permits either the concrete public IPv4
            # or the IPv4 wildcard. rw-core normally binds 0.0.0.0:443 after the
            # IPv6-disabled reboot; ownership/PID checks below still prove that
            # the listener belongs to the remnanode core.
            if port == 443 and row['host'] not in (public_ipv4, '0.0.0.0'):
                bad_bind.add(port)
                continue
        if not row['processes'] or not row['pids']:
            ambiguous.add(port)
            continue
        if not row['processes'].issubset(expected[port]):
            bad_owner.add(port)
            continue
        if port == 443 and core_pids is not None and not row['pids'].issubset(core_pids):
            bad_owner.add(port)
        if port == node_port and node_pids is not None and not row['pids'].issubset(node_pids):
            bad_owner.add(port)
    missing = sorted(required - present)
    if unexpected:
        return False, 'UNEXPECTED_PUBLIC_PORTS=' + ','.join(map(str, sorted(unexpected)))
    if ambiguous:
        return False, 'OWNER_NOT_VERIFIED PORTS=' + ','.join(map(str, sorted(ambiguous)))
    if bad_bind:
        return False, 'BIND_ADDRESS_MISMATCH PORTS=' + ','.join(map(str, sorted(bad_bind)))
    if bad_owner:
        return False, 'OWNER_MISMATCH PORTS=' + ','.join(map(str, sorted(bad_owner)))
    if missing:
        return False, 'MISSING_EXPECTED_PORTS=' + ','.join(map(str, missing))
    return True, 'EXPECTED_ONLY'


def docker_process_pids(runner=subprocess.run):
    raw = _run(DOCKER + ['top', 'remnanode', '-eo', 'pid,comm'], runner)
    core, node = set(), set()
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        pid, comm = int(fields[0]), fields[1]
        if comm in ('rw-core', 'xray'):
            core.add(pid)
        if comm in ('rw-node', 'node'):
            node.add(pid)
    if not node:
        raise Unverified('REMNANODE_PROCESS_NOT_VERIFIED')
    return core, node


def _dual_stack_node_listener(raw, node_port, node_pids):
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('SS_OUTPUT_OVERSIZED')
    matches = []
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 5 or fields[0] != 'LISTEN':
            raise ValueError('SS_SCHEMA_UNRECOGNIZED')
        host, sep, port_text = fields[3].rpartition(':')
        if not sep or not port_text.isdigit():
            raise ValueError('SS_LOCAL_ADDRESS_INVALID')
        if int(port_text) != node_port:
            continue
        if host not in ('*', '::', '[::]'):
            continue
        processes = set(re.findall(r'\(\("([^"\\]+)"', line))
        pids = {int(x) for x in re.findall(r'\bpid=([0-9]+)', line)}
        if not processes or not pids:
            raise Unverified('DUAL_STACK_NODE_OWNER_NOT_VERIFIED')
        if not processes.issubset({'rw-node', 'node'}):
            raise Unverified('DUAL_STACK_NODE_OWNER_MISMATCH')
        if not pids.issubset(node_pids):
            raise Unverified('DUAL_STACK_NODE_PID_MISMATCH')
        matches.append((processes, pids))
    if not matches:
        return None
    if len(matches) != 1:
        raise Unverified('DUAL_STACK_NODE_LISTENER_AMBIGUOUS')
    return matches[0]


def _ipv4_connect_ok(host, port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def listener_runtime_status(config_path, ssh_ports_path, require_xray=False, runner=subprocess.run, connect_check=_ipv4_connect_ok):
    node_port, public_ipv4 = _config(config_path)
    ssh_ports = _read_ports(ssh_ports_path)
    raw4 = _run(['ss', '-H', '-4', '-lntp'], runner)
    core, node = docker_process_pids(runner)
    ok, reason = public_listener_policy(raw4, ssh_ports, node_port, core, node,
                                        require_xray=require_xray, public_ipv4=public_ipv4)
    if ok:
        return ok, reason

    # RemnaNode calls app.listen(NODE_PORT) without an explicit host. Before the
    # first reboot fully removes IPv6, Node.js can own one AF_INET6 wildcard
    # socket while net.ipv6.bindv6only=0. Linux then accepts IPv4 through that
    # socket even though `ss -4` omits it. Accept only this exact NODE_PORT
    # exception after ownership and real IPv4-connect proofs; no other missing
    # listener can be hidden by this path.
    prefix = 'MISSING_EXPECTED_PORTS='
    if not reason.startswith(prefix):
        return ok, reason
    try:
        missing = {int(value) for value in reason[len(prefix):].split(',') if value}
    except ValueError as exc:
        raise Unverified('LISTENER_MISSING_PORTS_INVALID') from exc
    if missing != {node_port}:
        return ok, reason

    raw6 = _run(['ss', '-H', '-6', '-lntp'], runner)
    proof = _dual_stack_node_listener(raw6, node_port, node)
    if proof is None:
        return ok, reason
    bindv6only = _run(['sysctl', '-n', 'net.ipv6.bindv6only'], runner).strip()
    if bindv6only != '0':
        return False, 'NODE_PORT_DUAL_STACK_IPV4_DISABLED'
    if not connect_check('127.0.0.1', node_port) or not connect_check(public_ipv4, node_port):
        return False, 'NODE_PORT_DUAL_STACK_IPV4_CONNECT_FAILED'

    processes, pids = proof
    process = sorted(processes)[0]
    pid = min(pids)
    synthetic = f'LISTEN 0 511 *:{node_port} *:* users:(("{process}",pid={pid},fd=0))'
    ok, reason = public_listener_policy(raw4 + ('\n' if raw4 else '') + synthetic + '\n',
                                        ssh_ports, node_port, core, node,
                                        require_xray=require_xray, public_ipv4=public_ipv4)
    if ok:
        return True, f'{reason} DUAL_STACK_NODE_PORT={node_port} IPV4_CONNECT=PASS'
    return ok, reason


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    k = sub.add_parser('kernel')
    k.add_argument('release', nargs='?', default='')
    sub.add_parser('xray')
    sub.add_parser('nft')
    l = sub.add_parser('listeners')
    l.add_argument('--config', default='/etc/vkarmani-node/config.json')
    l.add_argument('--ssh-ports', default='/etc/vkarmani-node/ssh-ports')
    l.add_argument('--require-xray', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'kernel':
            raw = args.release or os.uname().release
            ok = kernel_supported(raw)
            print(('PASS' if ok else 'FAIL') + ' VERSION=' + raw.split()[0])
            return 0 if ok else 1
        if args.action == 'xray':
            status = xray_runtime_status()
            print('PLUGIN={} SECURITY={} VERSION={}'.format(
                'PASS' if status['plugin'] else 'FAIL',
                'PASS' if status['security'] else 'FAIL', status['version']))
            return 0 if status['plugin'] and status['security'] else 1
        if args.action == 'nft':
            ok, reason = nft_runtime_status()
            print(('PASS ' if ok else 'FAIL ') + reason)
            return 0 if ok else 1
        ok, reason = listener_runtime_status(args.config, args.ssh_ports, args.require_xray)
        print(('PASS ' if ok else 'FAIL ') + reason)
        return 0 if ok else 1
    except Unverified:
        print('NOT_VERIFIED LOCAL_STATE_OR_COMMAND_ERROR')
        return 2
    except (ValueError, json.JSONDecodeError):
        print('NOT_VERIFIED INVALID_LOCAL_DATA')
        return 2


if __name__ == '__main__':
    sys.exit(main())
VK_NODE_PLUGINS_PY
    chmod 0700 "$destination"
}

vk_write_acceptance() {
    local destination=${1:-/usr/local/sbin/vkarmani-node-check}
    local plugin_destination=${2:-${LIB:-/usr/local/lib/vkarmani-node}/node_plugins.py}
    local time_destination=${3:-/usr/local/lib/vkarmani-node/time_helper.py}
    vk_write_time_helper "$time_destination"
    vk_write_node_plugins_helper "$plugin_destination"
    install -d -m 0755 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_PAYLOAD_VK_WRITE_ACCEPTANCE'
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
PLUGIN_HELPER=/usr/local/lib/vkarmani-node/node_plugins.py
F=0
TIME_HELPER=/usr/local/lib/vkarmani-node/time_helper.py
XRAY_PRESENT=0
XRAY_COVER_OK=0
NODE_PLUGIN_PREREQ_FAIL=0
NET_ADMIN_OK=0
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
# Centralized reviewed installer contract classification. Future versions stay fail-closed
# until this table and its regression matrix are explicitly reviewed.
installed_contract_class() {
    case "$1" in
        2.3.0|2.4.0|2.4.1|2.4.2|2.4.3|2.5.0|2.5.1|2.5.2) printf 'modern\n' ;;
        1.3.*|2.0.3|2.1.0|2.1.1|2.1.2|2.1.3|2.2.0) printf 'legacy\n' ;;
        *) printf 'unreviewed\n' ;;
    esac
}
INSTALL_VERSION=''
INSTALLED_CONTRACT_CLASS=unreviewed
if [[ ! -s "$STATE/install-version" ]]; then
    fail INSTALLER_CONTRACT 'install-version missing or empty'
elif ! INSTALL_VERSION=$(cat "$STATE/install-version"); then
    fail INSTALLER_CONTRACT 'install-version unreadable'
elif [[ ! "$INSTALL_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail INSTALLER_CONTRACT 'install-version malformed'
else
    INSTALLED_CONTRACT_CLASS=$(installed_contract_class "$INSTALL_VERSION")
    if [[ "$INSTALLED_CONTRACT_CLASS" == unreviewed ]]; then
        fail INSTALLER_CONTRACT 'unreviewed install-version; no automatic compatibility assumption'
    else
        pass "INSTALLER_CONTRACT_${INSTALLED_CONTRACT_CLASS^^}"
    fi
fi

vk_check_import_profile() {
    case "$INSTALLED_CONTRACT_CLASS" in
        modern)
            if helper profile-check; then
                pass IMPORT_PROFILE_POLICY
                pass PROFILE_TORRENT_SNIFFING_POLICY
            else
                fail IMPORT_PROFILE_POLICY
                fail PROFILE_TORRENT_SNIFFING_POLICY 'profile contract validation failed'
            fi ;;
        legacy)
            case "$INSTALL_VERSION" in
                1.3.*|2.0.3)
                    warn IMPORT_PROFILE_POLICY 'NOT_VERIFIED: historical installation requires its matching policy' ;;
                *) helper profile-check && pass IMPORT_PROFILE_POLICY || fail IMPORT_PROFILE_POLICY ;;
            esac ;;
        *) fail IMPORT_PROFILE_POLICY 'unreviewed installer contract' ;;
    esac
    warn LIVE_PROFILE_POLICY 'NOT_VERIFIED: local JSON is not the live node config or Host SNI override'
}
vk_check_import_profile
if [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then
    if KERNEL_PLUGIN_STATUS=$(python3 "$PLUGIN_HELPER" kernel 2>/dev/null); then
        pass NODE_PLUGIN_KERNEL
    else
        fail NODE_PLUGIN_KERNEL "${KERNEL_PLUGIN_STATUS:-NOT_VERIFIED}"; NODE_PLUGIN_PREREQ_FAIL=1
    fi
    if command -v nft >/dev/null 2>&1 && timeout --foreground 5s nft --version >/dev/null 2>&1; then
        pass NFTABLES_CLI
    else
        fail NFTABLES_CLI 'nft command unavailable or unusable'; NODE_PLUGIN_PREREQ_FAIL=1
    fi
else
    warn NODE_PLUGIN_KERNEL 'NOT_VERIFIED: historical installer contract'
    warn NFTABLES_CLI 'NOT_VERIFIED: historical installer contract'
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
    if IPV6_LISTENERS=$(ss -H -6 -lntup 2>/dev/null); then
        [[ -z "$IPV6_LISTENERS" ]] && pass NO_IPV6_LISTENERS || fail NO_IPV6_LISTENERS
    else fail NO_IPV6_LISTENERS 'NOT_VERIFIED: ss failed'; fi
fi
if IPV6_ADDR=$(ip -6 address show 2>/dev/null); then
    if printf '%s\n' "$IPV6_ADDR" | _contains 'inet6'; then fail NO_IPV6_ADDRESSES; else pass NO_IPV6_ADDRESSES; fi
else fail NO_IPV6_ADDRESSES 'NOT_VERIFIED: ip failed'; fi
if IPV6_ROUTES=$(ip -6 route show 2>/dev/null); then
    [[ -z "$IPV6_ROUTES" ]] && pass NO_IPV6_ROUTES || fail NO_IPV6_ROUTES
else fail NO_IPV6_ROUTES 'NOT_VERIFIED: ip failed'; fi
/usr/sbin/sshd -t >/dev/null 2>&1 && pass SSH_CONFIG || fail SSH_CONFIG
/usr/sbin/sshd -T 2>/dev/null | _contains -Fx 'addressfamily inet' && pass SSH_IPV4_ONLY || fail SSH_IPV4_ONLY
while IFS= read -r port; do
    if ss -H -4 -lnt | awk '{print $4}' | _contains -E ":${port}$"; then pass "SSH_TCP_$port"; else fail "SSH_TCP_$port"; fi
done < "$ETC/ssh-ports"
TIME_SERVICE=$(python3 "$TIME_HELPER" provider) || { fail TIME_PROVIDER; exit 1; }
for service in docker containerd nginx fail2ban "$TIME_SERVICE" ufw vkarmani-node-network; do
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
vk_check_ssh_contract() {
    [[ -n "$INSTALL_VERSION" ]] || { fail SSH_PASSWORD_ONLY 'install-version unavailable'; return; }
    [[ $(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null) == 1 ]] && pass TCP_MTU_PROBING || fail TCP_MTU_PROBING
    if [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then
        python3 -I -B -S /usr/local/lib/vkarmani-node/ssh_guard.py check && pass SSH_PASSWORD_ONLY || fail SSH_PASSWORD_ONLY
    elif [[ "$INSTALLED_CONTRACT_CLASS" == legacy ]]; then
        # Historical installed policy: no implicit SSH migration in diagnostics.
        for expected in 'passwordauthentication yes' 'permitrootlogin yes' 'permitemptypasswords no' 'authenticationmethods any'; do
            /usr/sbin/sshd -T 2>/dev/null | _contains -Fx "$expected" && pass "SSH_${expected// /_}" || fail "SSH_${expected// /_}"
        done
    else
        fail SSH_PASSWORD_ONLY 'unreviewed installer contract'
    fi
}
vk_check_ssh_contract
warn INTERFACE_QDISC 'сохранена текущая структура очередей; root qdisc не перезаписывается'
if [[ "$MODE" == --postboot ]]; then
    python3 "$TIME_HELPER" wait --seconds 35 >/dev/null 2>&1 || true
fi
python3 "$TIME_HELPER" check && pass NTP_SYNC || fail NTP_SYNC
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
    CAP_ADD_JSON=$(docker inspect remnanode --format '{{json .HostConfig.CapAdd}}' 2>/dev/null) || CAP_ADD_JSON='INVALID'
    CAP_DROP_JSON=$(docker inspect remnanode --format '{{json .HostConfig.CapDrop}}' 2>/dev/null) || CAP_DROP_JSON='INVALID'
    SECURITY_OPT_JSON=$(docker inspect remnanode --format '{{json .HostConfig.SecurityOpt}}' 2>/dev/null) || SECURITY_OPT_JSON='INVALID'
    ALLOWED=$(helper get allow_net_admin) || ALLOWED='INVALID'
    if [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then
        if [[ "$ALLOWED" == true ]] && python3 - "$CAP_ADD_JSON" "$CAP_DROP_JSON" "$SECURITY_OPT_JSON" <<'PY_CAPS'
import json
import sys
try:
    cap_add, cap_drop, security = (json.loads(x) for x in sys.argv[1:4])
except Exception:
    raise SystemExit(1)

def normalized_caps(value):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise SystemExit(1)
    result = []
    for item in value:
        item = item.strip().upper()
        if item.startswith('CAP_'):
            item = item[4:]
        if not item:
            raise SystemExit(1)
        result.append(item)
    return result

# Docker Engine 29.8+ canonicalizes capability names returned by inspect to
# CAP_NET_ADMIN/CAP_NET_RAW. Older engines commonly return NET_ADMIN/NET_RAW.
# Accept only that representational difference; the effective policy stays exact.
if normalized_caps(cap_add) != ['NET_ADMIN']:
    raise SystemExit(1)
if normalized_caps(cap_drop) != ['NET_RAW']:
    raise SystemExit(1)
if not isinstance(security, list) or not any(isinstance(x, str) and x.startswith('no-new-privileges') for x in security):
    raise SystemExit(1)
PY_CAPS
        then
            pass NODE_NET_ADMIN
            pass NODE_NET_RAW_DROPPED
            pass NODE_NO_NEW_PRIVILEGES
            NET_ADMIN_OK=1
        else
            fail NODE_CAPABILITY_POLICY 'expected exact NET_ADMIN add, NET_RAW drop and no-new-privileges'
            NODE_PLUGIN_PREREQ_FAIL=1
        fi
    elif [[ "$INSTALLED_CONTRACT_CLASS" == legacy ]]; then
        if [[ "$CAP_ADD_JSON" != INVALID && "$ALLOWED" == false && "$CAP_ADD_JSON" != *NET_ADMIN* ]]; then
            pass NODE_NO_NET_ADMIN
        elif [[ "$ALLOWED" == true && "$CAP_ADD_JSON" == *NET_ADMIN* ]]; then
            pass NODE_NET_ADMIN
        else
            fail NODE_CAPABILITY_POLICY 'legacy state/capability mismatch'
        fi
    else
        fail NODE_CAPABILITY_POLICY 'unreviewed installer contract'
    fi
    if docker inspect remnanode --format '{{json .Mounts}}' | python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin) if x["Destination"]=="/dev/shm"]; sys.exit(0 if len(a)==1 and a[0]["Source"]=="/run/vkarmani-selfsteal" and not a[0]["RW"] else 1)'; then
        pass NODE_ISOLATED_SELFSTEAL_MOUNT
    else fail NODE_ISOLATED_SELFSTEAL_MOUNT; fi
fi

if [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then
    XRAY_PLUGIN_RESULT=$(python3 "$PLUGIN_HELPER" xray 2>/dev/null)
    XRAY_PLUGIN_RC=$?
    if [[ "$XRAY_PLUGIN_RESULT" =~ ^PLUGIN=(PASS|FAIL)[[:space:]]SECURITY=(PASS|FAIL)[[:space:]]VERSION=([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        if [[ "${BASH_REMATCH[1]}" == PASS ]]; then pass XRAY_CORE_PLUGIN_MIN; else fail XRAY_CORE_PLUGIN_MIN "version=${BASH_REMATCH[3]} floor=26.3.27"; NODE_PLUGIN_PREREQ_FAIL=1; fi
        if [[ "${BASH_REMATCH[2]}" == PASS ]]; then pass XRAY_CORE_SECURITY_FLOOR; else fail XRAY_CORE_SECURITY_FLOOR "version=${BASH_REMATCH[3]} floor=26.7.11"; NODE_PLUGIN_PREREQ_FAIL=1; fi
    else
        fail XRAY_CORE_PLUGIN_MIN "${XRAY_PLUGIN_RESULT:-NOT_VERIFIED}"
        fail XRAY_CORE_SECURITY_FLOOR "${XRAY_PLUGIN_RESULT:-NOT_VERIFIED}"
        NODE_PLUGIN_PREREQ_FAIL=1
    fi
    : "$XRAY_PLUGIN_RC"

    NFT_RUNTIME_RESULT=$(python3 "$PLUGIN_HELPER" nft 2>/dev/null)
    NFT_RUNTIME_RC=$?
    if [[ "$NFT_RUNTIME_RC" -eq 0 && "$NFT_RUNTIME_RESULT" == PASS* ]]; then
        pass NODE_PLUGIN_NFT_RUNTIME
    elif [[ "$MODE" == --require-xray ]]; then
        fail NODE_PLUGIN_NFT_RUNTIME "${NFT_RUNTIME_RESULT:-NOT_VERIFIED}"
    else
        warn NODE_PLUGIN_NFT_RUNTIME "NOT_VERIFIED: ${NFT_RUNTIME_RESULT:-runtime table may not exist before Panel Plugin Config sync}"
    fi
    if [[ "$NET_ADMIN_OK" -eq 1 && "$NODE_PLUGIN_PREREQ_FAIL" -eq 0 ]]; then
        pass NODE_PLUGINS_PREREQS
    else
        fail NODE_PLUGINS_PREREQS 'one or more local prerequisites are not verified'
    fi
    warn NODE_PLUGINS_PANEL_CONFIG 'NOT_VERIFIED: installer is node-only and does not read or mutate Panel Plugin Config'
    warn TORRENT_DETECTION 'NOT_VERIFIED: local prerequisites do not prove live BitTorrent detection'

    LISTENER_ARGS=(listeners --config "$ETC/config.json" --ssh-ports "$ETC/ssh-ports")
    [[ "$MODE" == --require-xray ]] && LISTENER_ARGS+=(--require-xray)
    PUBLIC_LISTENER_RESULT=$(python3 "$PLUGIN_HELPER" "${LISTENER_ARGS[@]}" 2>/dev/null)
    PUBLIC_LISTENER_RC=$?
    if [[ "$PUBLIC_LISTENER_RC" -eq 0 && "$PUBLIC_LISTENER_RESULT" == PASS* ]]; then
        pass PUBLIC_TCP_LISTENERS_POLICY
    else
        fail PUBLIC_TCP_LISTENERS_POLICY "${PUBLIC_LISTENER_RESULT:-NOT_VERIFIED}"
    fi
else
    warn XRAY_CORE_PLUGIN_MIN 'NOT_VERIFIED: historical installer contract'
    warn XRAY_CORE_SECURITY_FLOOR 'NOT_VERIFIED: historical installer contract'
    warn NODE_PLUGIN_NFT_RUNTIME 'NOT_VERIFIED: historical installer contract'
    warn NODE_PLUGINS_PREREQS 'NOT_VERIFIED: historical installer contract'
    warn NODE_PLUGINS_PANEL_CONFIG 'NOT_VERIFIED: installer is node-only'
    warn TORRENT_DETECTION 'NOT_VERIFIED: historical installer contract'
    warn PUBLIC_TCP_LISTENERS_POLICY 'NOT_VERIFIED: historical installer contract'
fi

# A listening port and a normal HTTPS page alone do not prove Xray ownership.
if python3 -I -B -S - <<'PY_XRAY_LISTENER_OWNER'
import ipaddress
import json
import os
import re
import subprocess
import sys

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


class Unverified(Exception):
    pass


def command(args, runner):
    p = runner(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
               timeout=8, env=ENV)
    if p.returncode or len(p.stdout) > 1048576:
        raise Unverified('LOCAL_COMMAND_FAILED_OR_OVERSIZED')
    return p.stdout


def identity(runner):
    template = '{"id":"{{.Id}}","running":{{.State.Running}},"pid":{{.State.Pid}},"network":"{{.HostConfig.NetworkMode}}"}'
    d = json.loads(command(DOCKER + ['inspect', '--format', template, 'remnanode'], runner))
    if (not isinstance(d, dict) or d.get('running') is not True or d.get('network') != 'host'
            or not re.fullmatch(r'[a-f0-9]{64}', str(d.get('id')))
            or type(d.get('pid')) is not int or d['pid'] < 1):
        raise Unverified('NODE_CONTAINER_NOT_RUNNING_HOST_MODE')
    return d['id'], d['pid']


def core_pids(raw):
    ids = set()
    for line in raw.splitlines():
        p = line.split()
        if len(p) == 2 and p[0].isdigit() and p[1] in ('rw-core', 'xray'):
            ids.add(int(p[0]))
    return ids


def listener_owners(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 5 or fields[0] != 'LISTEN':
            raise Unverified('SS_LISTENER_SCHEMA_UNRECOGNIZED')
        host, sep, port = fields[3].rpartition(':')
        if not sep or port != '443':
            raise Unverified('UNEXPECTED_PUBLIC_PORT')
        if host != '*':
            ipaddress.IPv4Address(host)
        ids = {int(x) for x in re.findall(r'\bpid=([0-9]+)', line)}
        if not ids:
            raise Unverified('LISTENER_PID_UNAVAILABLE')
        rows.append(ids)
    return rows


def verify(runner=subprocess.run):
    # Do not wake a socket-activated Docker daemon merely for this check.
    command(['systemctl', 'is-active', '--quiet', 'docker.service'], runner)
    before = identity(runner)
    pids = core_pids(command(DOCKER + ['top', 'remnanode', '-eo', 'pid,comm'], runner))
    rows = listener_owners(command(['ss', '-H', '-4', '-lntp', 'sport = :443'], runner))
    if not rows:
        return 3, 'XRAY_PUBLIC_LISTENER=NOT_LISTENING'
    if not pids or any(not owners.issubset(pids) for owners in rows):
        return 1, 'XRAY_PUBLIC_LISTENER=FAIL FOREIGN_OR_NON_CORE_OWNER'
    if (identity(runner) != before
            or core_pids(command(DOCKER + ['top', 'remnanode', '-eo', 'pid,comm'], runner)) != pids):
        raise Unverified('NODE_PROCESS_CHANGED_DURING_CHECK')
    return 0, 'XRAY_PUBLIC_LISTENER=PASS OWNED_BY_REMNANODE_CORE; USER_AUTH=NOT_TESTED'


def main():
    if os.geteuid() != 0:
        print('XRAY_PUBLIC_LISTENER=NOT_VERIFIED ROOT_REQUIRED')
        return 2
    try:
        rc, message = verify()
        print(message)
        return rc
    except Exception:
        print('XRAY_PUBLIC_LISTENER=NOT_VERIFIED LOCAL_STATE_OR_COMMAND_ERROR')
        return 2


if __name__ == '__main__':
    sys.exit(main())
PY_XRAY_LISTENER_OWNER
then
    XRAY_PRESENT=1
    pass XRAY_TCP443
else
    OWNER_RC=$?
    if [[ "$OWNER_RC" -eq 3 ]]; then
        warn XRAY_TCP443 'NOT_LISTENING: профиль или запуск core ещё не подтверждён'
    else
        fail XRAY_TCP443 'NOT_VERIFIED_OR_FOREIGN_OWNER: не считаю чужой HTTPS работающим Xray'
    fi
fi
[[ -S "$SELFSTEAL_SOCKET" ]] && pass SELFSTEAL_SOCKET || fail SELFSTEAL_SOCKET
nginx -t >/dev/null 2>&1 && pass NGINX_CONFIG || fail NGINX_CONFIG
openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -checkend 604800 >/dev/null 2>&1 && pass TLS_VALID_7DAYS || fail TLS_VALID_7DAYS
vk_check_selfsteal_target_contract() {
    if [[ "$INSTALLED_CONTRACT_CLASS" == modern ]]; then
        timeout 20 /usr/local/sbin/vkarmani-selfsteal-check --target-only && pass SELFSTEAL_TARGET_TLS || fail SELFSTEAL_TARGET_TLS
    elif [[ "$INSTALLED_CONTRACT_CLASS" == unreviewed ]]; then
        fail SELFSTEAL_TARGET_TLS 'unreviewed installer contract'
    fi
}
vk_check_selfsteal_target_contract
timeout 25 /usr/local/sbin/vkarmani-selfsteal-check && pass SELFSTEAL_WEB_CONTENT || fail SELFSTEAL_WEB_CONTENT
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
    chmod 0755 "$destination"
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
"""Explicit, serialized maintenance for VKarmani reviewed 2.x; never reconfigure the OS.

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
            run(['/usr/local/sbin/vkarmani-selfsteal-check', '--target-only'], remaining(25))
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
        'etc/systemd/timesyncd.conf', 'etc/systemd/timesyncd.conf.d',
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
            or not any(line in ('version=2.1.0', 'version=2.1.1', 'version=2.1.2', 'version=2.1.3', 'version=2.2.0', 'version=2.3.0', 'version=2.4.0', 'version=2.4.1', 'version=2.4.2', 'version=2.4.3', 'version=2.5.0', 'version=2.5.1', 'version=2.5.2') for line in (STATE / 'INSTALL_COMPLETE').read_text().splitlines())):
        raise Failure('ONLY_REVIEWED_COMPLETED_INSTALLATIONS_SUPPORTED; legacy installation is not migrated')
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
vk_write_time_helper() {
    local destination=${1:-/usr/local/lib/vkarmani-node/time_helper.py}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'PY_TIME_HELPER'
#!/usr/bin/env python3
"""Select and verify one NTP client without replacing an installed time daemon.
No external Python dependencies; no control of the system clock in this helper.
"""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
SYNC_MARKER = Path('/run/systemd/timesync/synchronized')
PROVIDERS = ('chrony', 'systemd-timesyncd')


class Failure(Exception):
    pass


def run(args, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise Failure('TIME_CHECK_DEADLINE')
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=min(5.0, left), check=False,
                           env={**os.environ, 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure('TIME_COMMAND_UNAVAILABLE_OR_TIMEOUT: ' + args[0]) from exc
    if p.returncode:
        raise Failure('TIME_COMMAND_FAILED: ' + args[0])
    return p.stdout.rstrip('\n')


def installed_provider(text):
    """Parse the dpkg database, not localized apt progress or service aliases."""
    if not text.strip():
        raise Failure('EMPTY_DPKG_DATABASE_OUTPUT')
    found = []
    known = {*PROVIDERS, 'ntp', 'ntpsec', 'openntpd'}
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) != 3:
            raise Failure('INVALID_DPKG_DATABASE_OUTPUT')
        package, status_text, provides = fields
        name = package.split(':', 1)[0]
        virtual = any(re.fullmatch(r'time-daemon(?:\s+\([^)]*\))?', x.strip())
                      for x in provides.split(','))
        if name not in known and not virtual:
            continue
        if status_text in ('deinstall ok config-files', 'purge ok not-installed',
                           'unknown ok not-installed'):
            continue  # Configuration remnants do not run a daemon.
        if status_text not in ('install ok installed', 'hold ok installed'):
            raise Failure('INCOMPLETE_TIME_DAEMON_PACKAGE: ' + name)
        if name not in PROVIDERS:
            raise Failure('UNSUPPORTED_TIME_DAEMON: ' + name)
        if name in found:
            raise Failure('DUPLICATE_TIME_DAEMON_PACKAGE')
        found.append(name)
    if len(found) > 1:
        raise Failure('MULTIPLE_TIME_DAEMONS')
    return found[0] if found else None


def private_text(path):
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Failure('UNSAFE_TIME_PROVIDER_FILE')
        return path.read_text().strip()
    except OSError as exc:
        raise Failure('TIME_PROVIDER_FILE_UNREADABLE') from exc


def saved_provider(etc=ETC, state=STATE):
    marker = etc / 'time-provider'
    if marker.exists() or marker.is_symlink():
        value = private_text(marker)
        if value not in PROVIDERS:
            raise Failure('INVALID_TIME_PROVIDER')
        return value
    # Explicit compatibility for existing legacy repair/check paths. A reviewed modern installation
    # must have its own marker; absence is NOT interpreted as success.
    version = (state / 'install-version').read_text().strip() if (state / 'install-version').is_file() else ''
    complete = (state / 'INSTALL_COMPLETE').read_text().splitlines() if (state / 'INSTALL_COMPLETE').is_file() else []
    if (version in ('2.0.0', '2.0.1', '2.0.2') or re.fullmatch(r'1\.3\.\d+', version)
            or any(re.fullmatch(r'version=1\.3\.\d+', line) for line in complete)):
        return 'chrony'
    raise Failure('TIME_PROVIDER_NOT_SAVED')


def select_provider(etc=ETC):
    text = run(['dpkg-query', '-W', '-f=${binary:Package}\t${Status}\t${Provides}\n'],
               time.monotonic() + 10)
    installed = installed_provider(text)
    selected = installed or 'chrony'
    marker = etc / 'time-provider'
    if marker.exists() or marker.is_symlink():
        saved = private_text(marker)
        if saved not in PROVIDERS or installed != saved:
            raise Failure('TIME_PROVIDER_DRIFT: saved and installed provider differ')
    return selected


def save_provider(provider, etc=ETC):
    if provider not in PROVIDERS:
        raise Failure('INVALID_TIME_PROVIDER')
    target = etc / 'time-provider'
    fd, name = tempfile.mkstemp(prefix='.time-provider-', dir=etc)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(provider + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory = os.open(etc, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def probe(provider, deadline, sync_marker=SYNC_MARKER):
    if provider not in PROVIDERS:
        raise Failure('INVALID_TIME_PROVIDER')
    run(['systemctl', 'is-active', '--quiet', provider + '.service'], deadline)
    if provider == 'chrony':
        # One observation, bounded by the common deadline. Keep the previous
        # installation threshold: <0.1 seconds remaining system-clock correction.
        run(['chronyc', '-n', 'waitsync', '1', '0.1', '0.0', '1'], deadline)
        tracking = run(['chronyc', '-n', 'tracking'], deadline)
        if not re.search(r'^Leap status\s*:\s*Normal\s*$', tracking, re.M):
            raise Failure('CHRONY_NOT_SYNCHRONIZED')
    else:
        synchronized = run(['timedatectl', 'show', '--property=NTPSynchronized', '--value'], deadline)
        if synchronized != 'yes':
            raise Failure('TIMESYNCD_CLOCK_NOT_SYNCHRONIZED')
        address = run(['timedatectl', 'show-timesync', '--property=ServerAddress', '--value'], deadline)
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise Failure('TIMESYNCD_NO_IPV4_TIME_SOURCE') from exc
        # Service active + a selected server do not prove a successful NTP reply.
        try:
            st = sync_marker.lstat()
        except OSError as exc:
            raise Failure('TIMESYNCD_NO_SUCCESSFUL_SYNC_MARKER') from exc
        if not stat.S_ISREG(st.st_mode):
            raise Failure('TIMESYNCD_INVALID_SYNC_MARKER')


def wait_sync(provider, seconds, sync_marker=SYNC_MARKER):
    if not 1 <= seconds <= 120:
        raise Failure('INVALID_TIME_WAIT_BUDGET')
    deadline = time.monotonic() + seconds
    last = 'not yet checked'
    while time.monotonic() < deadline:
        try:
            probe(provider, deadline, sync_marker)
            return
        except Failure as exc:
            last = str(exc)
        left = deadline - time.monotonic()
        if left > 0:
            time.sleep(min(2.0, left))
    raise Failure('NTP_SYNC_TIMEOUT: ' + last)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('select')
    sub.add_parser('provider')
    save = sub.add_parser('save')
    save.add_argument('provider', choices=PROVIDERS)
    check = sub.add_parser('check')
    check.add_argument('--provider', choices=PROVIDERS)
    wait = sub.add_parser('wait')
    wait.add_argument('--provider', choices=PROVIDERS)
    wait.add_argument('--seconds', type=int, default=120)
    args = parser.parse_args()
    if args.action == 'select':
        print(select_provider())
    elif args.action == 'provider':
        print(saved_provider())
    elif args.action == 'save':
        save_provider(args.provider)
    else:
        provider = args.provider or saved_provider()
        if args.action == 'wait':
            wait_sync(provider, args.seconds)
        else:
            probe(provider, time.monotonic() + 15)
        print('NTP_SYNC=PASS provider=' + provider)


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError) as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, Failure) else 'TIME_HELPER_IO_OR_DATA_ERROR'), file=sys.stderr)
        sys.exit(1)
PY_TIME_HELPER
    chmod 0700 "$destination"
}

vk_check_202_ntp_resume() {
    python3 - <<'PY_RESUME_NTP_CHECK'
#!/usr/bin/env python3
"""Read-only eligibility gate for the precisely identified 2.0.2 package-stage failure.
This is not a general migration or a bypass for incomplete installations.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

OLD_HELPER_SHA256 = 'd12e637c5a91106b2e7df53f65c84c62dcaca64c5d8d3f29f41639b994082c58'
# These are created after the failed component-package transaction in 2.0.2.
LATE_PATHS = (
    'var/lib/vkarmani-node/INSTALL_COMPLETE',
    'var/lib/vkarmani-node/image-digest',
    'var/lib/vkarmani-node/image-update-pending',
    'var/lib/vkarmani-node/network-backup',
    'var/lib/vkarmani-node/network-rollback-armed',
    'var/lib/vkarmani-node/network-rollback-running',
    'var/lib/vkarmani-node/network-rollback-done',
    'etc/vkarmani-node/time-provider',
    'opt/vkarmani-node/compose.yaml',
    'etc/sysctl.d/99-vkarmani-node.conf',
    'etc/default/grub.d/99-vkarmani-ipv4.cfg',
    'etc/systemd/journald.conf.d/90-vkarmani-limits.conf',
    'etc/apt/apt.conf.d/90-vkarmani-security-updates',
    'etc/apt/sources.list.d/docker-vkarmani.sources',
    'etc/nginx/conf.d/00-vkarmani-global.conf',
    'etc/nginx/conf.d/10-vkarmani-http.conf',
    'etc/nginx/conf.d/20-vkarmani-selfsteal.conf',
    'etc/systemd/system/vkarmani-node-postboot.service',
)


class Failure(Exception):
    pass


def check_resume(root=Path('/'), expected_uid=0):
    def private(path, directory=False):
        p = root / path
        st = p.lstat()
        kind_ok = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if not kind_ok or st.st_uid != expected_uid or st.st_mode & 0o077:
            raise Failure('unsafe file or directory: ' + path)
        return p

    for name in ('var/lib/vkarmani-node', 'etc/vkarmani-node', 'usr/local/lib/vkarmani-node', 'opt/vkarmani-node'):
        private(name, directory=True)
    private('var/lib/vkarmani-node/owned-installation')
    if private('var/lib/vkarmani-node/install-version').read_text().strip() != '2.0.2':
        raise Failure('source version is not 2.0.2')
    failure = private('var/lib/vkarmani-node/INSTALL_FAILED').read_text().strip()
    if not re.fullmatch(r'rc=100 line=2761 at=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})', failure):
        raise Failure('failure is not the known 2.0.2 component-package stage')
    for name in LATE_PATHS:
        p = root / name
        if p.exists() or p.is_symlink():
            raise Failure('later installation stage detected: ' + name)
    helper = private('usr/local/lib/vkarmani-node/node_helper.py')
    if hashlib.sha256(helper.read_bytes()).hexdigest() != OLD_HELPER_SHA256:
        raise Failure('2.0.2 helper differs from the known release')
    config = json.loads(private('etc/vkarmani-node/config.json').read_text())
    if (not isinstance(config, dict) or config.get('installation_mode') != 'secret-key-only'
            or not all(config.get(k) for k in ('domain', 'panel_ipv4', 'public_ipv4'))):
        raise Failure('saved node configuration is incomplete or foreign')
    env = private('etc/vkarmani-node/remnanode.env')
    if not env.stat().st_size:
        raise Failure('saved node credential file is empty')
    # The existing init/secret validator revalidates its CONTENT later, without
    # displaying it. This gate neither rewrites nor prints the key.
    backup = private('var/lib/vkarmani-node/first-backup-path').read_text().strip()
    path = Path(backup)
    if path.parent != Path('/var/lib/vkarmani-node/backups') or not re.fullmatch(r'\d{8}-\d{6}-\d+', path.name):
        raise Failure('original backup pointer is invalid')
    private(str(path.relative_to('/')), directory=True)
    manifest = private(str(path.relative_to('/') / 'MANIFEST.sha256'))
    if not manifest.stat().st_size:
        raise Failure('original backup manifest is empty')


if __name__ == '__main__':
    try:
        check_resume()
        print('RESUME_2.0.2_PACKAGE_STAGE=ELIGIBLE; configuration and secret will be reused')
    except (Failure, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, Failure) else 'cannot validate private saved state'
        print('STOP: узкое продолжение 2.0.2 не разрешено: ' + reason, file=sys.stderr)
        sys.exit(1)
PY_RESUME_NTP_CHECK
}

# Package-manager coordination: never delete APT/dpkg locks or kill the holder.
# Fresh cloud images often start apt-daily/unattended-upgrades while provisioning.
APT_LOCK_TOTAL_WAIT=1800
APT_LOCK_REPORT_INTERVAL=30
APT_LOCK_POLL_INTERVAL=5
APT_LOCK_ATTEMPT_WAIT=15

vk_apt_lock_snapshot() {
    command -v lslocks >/dev/null || {
        echo 'STOP: lslocks (util-linux) is required for safe APT coordination.' >&2
        return 1
    }
    lslocks -n -o PID,COMMAND,PATH 2>/dev/null | awk '
        $3=="/var/lib/dpkg/lock-frontend" ||
        $3=="/var/lib/dpkg/lock" ||
        $3=="/var/cache/apt/archives/lock" ||
        $3=="/var/lib/apt/lists/lock" {
            if ($1 ~ /^[0-9]+$/ && $2 ~ /^[A-Za-z0-9_.+-]+$/) print $1 "\t" $2 "\t" $3
        }'
}

vk_wait_apt_idle() {
    local budget=${1:-$APT_LOCK_TOTAL_WAIT}
    local started=$SECONDS elapsed=0 next_report=0 snapshot holders
    [[ "$budget" =~ ^[0-9]+$ && "$budget" -ge 1 && "$budget" -le 7200 ]] || {
        echo 'STOP: invalid APT wait budget.' >&2; return 1;
    }
    while :; do
        snapshot=$(vk_apt_lock_snapshot) || return 1
        [[ -n "$snapshot" ]] || break
        elapsed=$((SECONDS - started))
        if (( elapsed >= budget )); then
            holders=$(awk -F '\t' '{printf "%s%s(pid=%s)", (NR==1?"":","), $2, $1}' <<< "$snapshot")
            printf 'STOP: пакетный менеджер занят более %ss: %s. Ничего не остановлено и lock-файлы не удалены.\n' \
                "$budget" "${holders:-unknown}" >&2
            return 75
        fi
        if (( elapsed >= next_report )); then
            holders=$(awk -F '\t' '{printf "%s%s(pid=%s)", (NR==1?"":","), $2, $1}' <<< "$snapshot")
            printf 'APT_WAIT: Ubuntu/Debian выполняет пакетную операцию: %s; ждём безопасно (%ss/%ss).\n' \
                "${holders:-unknown}" "$elapsed" "$budget"
            next_report=$((elapsed + APT_LOCK_REPORT_INTERVAL))
        fi
        sleep "$APT_LOCK_POLL_INTERVAL"
    done
    elapsed=$((SECONDS - started))
    if (( elapsed > 0 )); then
        printf 'APT_WAIT=PASS waited=%ss\n' "$elapsed"
    fi
}

vk_apt_run() {
    local deadline=$((SECONDS + APT_LOCK_TOTAL_WAIT)) remaining start_size=0 rc
    while :; do
        remaining=$((deadline - SECONDS))
        if (( remaining <= 0 )); then
            echo 'STOP: общий лимит ожидания пакетного менеджера исчерпан; команда APT не запущена повторно.' >&2
            return 75
        fi
        vk_wait_apt_idle "$remaining" || return $?
        if [[ -n "${LOG:-}" && -f "${LOG:-}" ]]; then
            start_size=$(stat -c '%s' "$LOG" 2>/dev/null || printf '0')
        else
            start_size=0
        fi
        if "$@"; then
            return 0
        else
            rc=$?
        fi
        # Close the tiny race between our lock snapshot and APT's own lock acquisition.
        # Retry only a real lock error; repository/network/dpkg failures propagate unchanged.
        if [[ "$rc" -eq 100 && -n "${LOG:-}" && -f "${LOG:-}" ]] &&
           tail -c "+$((start_size + 1))" "$LOG" 2>/dev/null | grep -Eq \
             'Could not get lock |Unable to acquire the dpkg frontend lock|Unable to lock directory '; then
            printf 'APT_LOCK_RACE: другой пакетный процесс успел получить lock; повторяем после безопасного ожидания.\n'
            sleep 2
            continue
        fi
        return "$rc"
    done
}

# Release mappings are exact. Never use noble packages on resolute as a fallback.
vk_platform_settings() {
    local id=$1 version=$2 codename=$3 arch=$4
    case "$id:$version:$codename" in
        ubuntu:22.04:jammy|ubuntu:24.04:noble|ubuntu:26.04:resolute|debian:12:bookworm|debian:13:trixie) ;;
        *) printf 'STOP: unsupported or inconsistent OS release: %s/%s/%s\n' "$id" "$version" "$codename" >&2; return 1 ;;
    esac
    case "$arch" in amd64|arm64) ;; *) echo 'STOP: only amd64/arm64 are supported.' >&2; return 1 ;; esac
    OS_ID=$id
    OS_CODENAME=$codename
    MIN_MEMORY_MB=900
    if [[ "$id:$version" == ubuntu:26.04 ]]; then
        MIN_MEMORY_MB=1536
    fi
}

vk_kernel_plugins_supported() {
    local raw=${1:-}
    [[ "$raw" =~ ^([0-9]+)\.([0-9]+)([.-].*)?$ ]] || return 1
    local major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]}
    (( major > 5 || (major == 5 && minor >= 7) ))
}

vk_base_tools_smoke() (
    # Exercise the exact options used for backups and checks, regardless of the
    # coreutils provider. No essential package replacement, system config or network.
    set -Eeuo pipefail
    local work
    work=$(mktemp -d /tmp/vkarmani-tools.XXXXXXXX) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    cd -- "$work" || exit 1
    install -d -m 0700 src/sub out || exit 1
    printf 'probe\n' > 'src/sub/file with spaces' || exit 1
    ln -s 'sub/file with spaces' src/link || exit 1
    cp -a --parents -- src/sub 'out/' || exit 1
    cp -a -- src/link out/link || exit 1
    [[ -L out/link && $(readlink out/link) == 'sub/file with spaces' ]] || exit 1
    cmp 'src/sub/file with spaces' 'out/src/sub/file with spaces' || exit 1
    find src/sub -type f -print0 | sort -z | xargs -0 -r sha256sum > checksums || exit 1
    sha256sum --check --quiet checksums || exit 1
    install -m 0600 checksums checked || exit 1
    [[ $(stat -c '%a' checked) == 600 ]] || exit 1
    timeout --kill-after=1s 2s bash -c 'exit 0' || exit 1
    timeout --foreground 2s bash -c 'exit 0' || exit 1
    lslocks -n -o PID,COMMAND,PATH >/dev/null || exit 1
    date -Is >/dev/null || exit 1
    mv -- checked moved || exit 1
    [[ -s moved ]] || exit 1
    printf 'BASE_TOOLS_SMOKE=PASS\n'
)

vk_setup_docker_repository() {
    install -d -m 0755 /etc/apt/keyrings
    local keyfile
    keyfile=$(mktemp /etc/apt/keyrings/.docker-vkarmani.XXXXXXXX)
    if ! curl -4 --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --retry 3 \
        "https://download.docker.com/linux/$OS_ID/gpg" -o "$keyfile"; then
        rm -f -- "$keyfile"; return 1
    fi
    if ! gpg --batch --show-keys --with-colons "$keyfile" | \
        awk -F: '$1=="fpr"{print $10}' | grep -Fx '9DC858229FC7DD38854AE2D88D81803C0EBFCD88' >/dev/null; then
        rm -f -- "$keyfile"; echo 'STOP: unexpected Docker signing-key fingerprint.' >&2; return 1
    fi
    chmod 0644 "$keyfile"
    mv -f -- "$keyfile" /etc/apt/keyrings/docker-vkarmani.asc
    cat > /etc/apt/sources.list.d/docker-vkarmani.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$OS_ID
Suites: $OS_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker-vkarmani.asc
EOF
    vk_apt_run apt-get -o APT::Update::Error-Mode=any update
}

vk_write_apt_clean_helper() {
    local destination=${1:-"$LIB/apt_clean.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_APT_CLEAN_PY'
#!/usr/bin/env python3
"""Best-effort cache cleanup; never remove a lock, stop APT, or skip acceptance."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

STATE = Path('/var/lib/vkarmani-node')


def clean(argv=None, timeout=20.0):
    """Only apt-get clean is used in production. argv injection is for isolated tests."""
    argv = ['apt-get', 'clean'] if argv is None else argv
    if not 0 < timeout <= 30:
        raise ValueError('invalid cleanup budget')
    proc = None
    try:
        # A private file prevents pipe back-pressure / unbounded captured output.
        # APT stderr may contain administrator hooks; do not echo it to the terminal.
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=output, start_new_session=True,
                                    env={**os.environ, 'LC_ALL': 'C'})
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_group(proc)
                return {'status': 'WARNING', 'reason': 'TIMEOUT', 'rc': 124}
            output.seek(0)
            text = output.read(16384).decode('utf-8', errors='replace')
            if rc == 0:
                return {'status': 'PASS', 'reason': 'CLEANED', 'rc': 0}
            # Distinguish the known concurrency case from permissions/I/O/hook errors.
            lock = (rc == 100 and 'Could not get lock ' in text
                    and ('It is held by process ' in text or 'Resource temporarily unavailable' in text)
                    and re.search(r'Unable to lock directory .*/archives/?', text))
            if lock:
                return {'status': 'DEFERRED', 'reason': 'LOCK_BUSY', 'rc': rc}
            return {'status': 'WARNING', 'reason': 'COMMAND_FAILED', 'rc': rc}
    except OSError:
        return {'status': 'WARNING', 'reason': 'COMMAND_UNAVAILABLE_OR_IO', 'rc': 127}
    finally:
        if proc is not None and proc.poll() is None:
            stop_group(proc)


def stop_group(proc):
    """Only our clean command's process group; never another APT/dpkg process."""
    for sig, seconds in ((signal.SIGTERM, 1), (signal.SIGKILL, 1)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            pass
    # SIGKILL above also targets descendants that outlive the direct process.


def record(result, state=STATE):
    path = state / 'apt-clean-status.json'
    fd, name = tempfile.mkstemp(prefix='.apt-clean-', dir=state)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({**result, 'at': dt.datetime.now(dt.timezone.utc).isoformat()}, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    result = clean()
    print('APT_CACHE_CLEAN={status} reason={reason} rc={rc}'.format(**result))
    try:
        record(result)
    except OSError:
        print('APT_CACHE_CLEAN_STATUS=NOT_SAVED; check free disk/inodes and filesystem health')
    if result['status'] != 'PASS':
        print('Optional cache cleanup did not complete; node acceptance still runs. No locks/processes from other package operations were changed.')
    # Cleanup is noncritical. Failure of node acceptance is NOT handled here.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
VK_APT_CLEAN_PY
    chmod 0700 "$destination"
}

vk_write_chrony_config_helper() {
    local destination=${1:-"$LIB/chrony_config.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_CHRONY_CONFIG_PY'
#!/usr/bin/env python3
"""Keep distro/provider sources and NTS; only add IPv4 + client-only policy."""
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile

BEGIN = '# BEGIN VKarmani client-only policy'
END = '# END VKarmani client-only policy'
BLOCK = BEGIN + '\nport 0\ncmdport 0\n' + END + '\n'


class Failure(Exception):
    pass


def render_config(text):
    if '\x00' in text or len(text.encode()) > 1024 * 1024:
        raise Failure('invalid chrony configuration')
    if BEGIN in text or END in text:
        pattern = re.escape(BEGIN) + r'\nport 0\ncmdport 0\n' + re.escape(END) + r'\n?'
        if text.count(BEGIN) != 1 or text.count(END) != 1 or not re.search(pattern, text):
            raise Failure('modified managed chrony policy; manual review required')
        # Exact managed block is idempotent. Never rewrite the provider's sources.
        text = re.sub(pattern, '', text)
    return text.rstrip('\n') + '\n\n' + BLOCK


def render_defaults(text):
    """Do NOT source /etc/default/chrony as shell; retain literal package flags."""
    matches = list(re.finditer(r'(?m)^[ \t]*DAEMON_OPTS[ \t]*=(.*)$', text))
    if len(matches) > 1:
        raise Failure('ambiguous DAEMON_OPTS')
    if not matches:
        return text.rstrip('\n') + '\nDAEMON_OPTS="-4"\n'
    match = matches[0]
    literal = match.group(1)
    if any(x in literal for x in ('$', '`', '\\', '\x00', '\r')):
        raise Failure('nonliteral DAEMON_OPTS; manual review required')
    try:
        value = shlex.split(literal, comments=True)
    except ValueError as exc:
        raise Failure('invalid DAEMON_OPTS quoting') from exc
    if len(value) != 1:
        raise Failure('DAEMON_OPTS must be a single quoted value')
    flags = value[0].split()
    # Supported package default is -F 1 (or none). Reject custom modes, especially
    # -6, -x, -f (custom config), -q and positional config directives.
    i = 0
    while i < len(flags):
        if flags[i] == '-4':
            i += 1
        elif flags[i] == '-F' and i + 1 < len(flags) and flags[i + 1] in ('0', '1', '2'):
            i += 2
        else:
            raise Failure('custom chronyd launch flags require manual review')
    if '-4' not in flags:
        flags.append('-4')
    new = 'DAEMON_OPTS="' + ' '.join(flags) + '"'
    return text[:match.start()] + new + text[match.end():]


def read_safe(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o022:
        raise Failure('unsafe chrony file: ' + path.name)
    return path.read_text(), stat.S_IMODE(s.st_mode)


def atomic(path, text, mode):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def configure(root=Path('/'), runner=subprocess.run):
    config = root / 'etc/chrony/chrony.conf'
    defaults = root / 'etc/default/chrony'
    old_config, cmode = read_safe(config)
    old_defaults, dmode = read_safe(defaults)
    new_config, new_defaults = render_config(old_config), render_defaults(old_defaults)
    # Existing syntax must already be valid; service is never stopped here.
    def validate():
        p = runner(['chronyd', '-p', '-4', '-f', str(config)], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
        if p.returncode:
            raise Failure('chronyd configuration validation failed; sources were not printed')
    validate()
    touched = False
    try:
        touched = True
        atomic(config, new_config, cmode)
        atomic(defaults, new_defaults, dmode)
        validate()
    except BaseException:
        if touched:
            # Service has not been restarted. The full installation backup also
            # contains the original files if filesystem failure prevents rollback.
            atomic(config, old_config, cmode)
            atomic(defaults, old_defaults, dmode)
        raise


def main():
    try:
        configure()
        print('CHRONY_SOURCES=PRESERVED; IPV4_ONLY=CONFIGURED; NTP_SERVER_PORTS=DISABLED')
    except (Failure, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print('STOP: ' + (str(exc) if isinstance(exc, Failure) else 'chrony configuration I/O/timeout; inspect backup'))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
VK_CHRONY_CONFIG_PY
    chmod 0700 "$destination"
}

vk_write_site_tool() {
    local destination=${1:-"$LIB/site_tool.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_SITE_TOOL_PY'
#!/usr/bin/env python3
"""Small static site. Updates publish versioned assets before one atomic index swap.
No service reload, package operation, socket change, VPN config or key access.
"""
import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import tempfile

MAX_INDEX = 128 * 1024
BACKUP_NAME = re.compile(r'cover-\d{8}T\d{12}-[0-9a-f]{12}')
DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')


class Failure(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def render(domain, seed=None):
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain) or re.fullmatch(r'[0-9.]+', domain):
        raise Failure('invalid site domain')
    if seed is not None and (not isinstance(seed, str) or not re.fullmatch(r'[0-9a-f]{64}', seed)):
        raise Failure('invalid cover seed')
    identity = hashlib.sha256((domain + ':' + (seed or 'preview')).encode('ascii')).digest()
    variant = identity[2] % 4
    hue = (28, 36, 42, 155, 192, 216)[identity[0] % 6]
    tilt = 16 + identity[1] % 13
    label = html.escape(domain.split('.')[0].replace('-', ' ').upper())
    safe_domain = html.escape(domain)
    css = r'''*{box-sizing:border-box}html{color-scheme:dark;scroll-behavior:smooth}body{margin:0;background:#101211;color:#ebe9e1;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}::selection{background:hsl(HUE 30% 65% / .32)}a{color:inherit;text-decoration:none}a:focus-visible{outline:2px solid hsl(HUE 48% 71%);outline-offset:7px}body:before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(ellipse at 82% 44%,hsl(HUE 24% 23% / .16),transparent 56%)}.shell{max-width:1440px;margin:auto;padding:0 76px}.header{display:flex;align-items:center;justify-content:space-between;gap:28px;min-height:126px;border-bottom:1px solid #ffffff12}.brand{font-size:15px;font-weight:600;letter-spacing:.2em;display:flex;align-items:center;gap:15px;overflow-wrap:anywhere}.emblem{position:relative;width:23px;height:23px;border:1px solid hsl(HUE 39% 70%);transform:rotate(45deg);flex-shrink:0}.emblem:after{content:"";position:absolute;inset:5px;border:1px solid hsl(HUE 28% 66% / .65)}.status{font-size:10px;letter-spacing:.18em;color:#b2b6ac;display:flex;align-items:center;gap:10px;white-space:nowrap}.status:before{content:"";width:5px;height:5px;border-radius:50%;background:hsl(HUE 41% 68%);box-shadow:0 0 12px hsl(HUE 42% 70% / .35)}.hero{position:relative;min-height:650px;display:grid;grid-template-columns:1.08fr 1fr;align-items:center;gap:20px;padding:86px 0 92px}.copy{z-index:1}.eyebrow{display:flex;align-items:center;gap:15px;color:hsl(HUE 29% 69%);font-size:10px;letter-spacing:.22em;text-transform:uppercase;margin:0 0 34px}.eyebrow:before{content:"";width:29px;height:1px;background:currentColor}h1{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-size:clamp(48px,5.45vw,82px);line-height:1.06;letter-spacing:-.055em;margin:0 0 28px}h1 em{display:block;font-weight:400;color:hsl(HUE 27% 69%)}.description{max-width:360px;font-size:14px;line-height:1.95;color:#a0a79d;margin:0}.description strong{font-weight:400;color:#d0d3c9}.quiet-link{display:inline-flex;align-items:center;gap:20px;margin-top:37px;font-size:11px;letter-spacing:.035em;padding:10px 0;border-bottom:1px solid #ffffff28}.quiet-link span{font-size:16px;color:hsl(HUE 30% 72%)}.sculpture{position:relative;width:min(100%,510px);aspect-ratio:1;margin:0 auto;isolation:isolate}.halo{position:absolute;inset:4%;border:1px solid #ffffff0a;border-radius:50%}.halo:before,.halo:after{content:"";position:absolute;border:1px solid #ffffff05;inset:-9%;border-radius:50%}.halo:after{inset:10%}.orb{position:absolute;inset:19%;border-radius:50%;background:radial-gradient(circle at 30% 20%,hsl(HUE 18% 51%) 0%,hsl(HUE 13% 32%) 16%,#222822 39%,#101510 65%,#090d0a 86%);box-shadow:inset 1px 1px 5px #f0e8d03a,inset -16px -12px 35px #0008,26px 32px 60px #0006;transform:rotate(-12deg)}.orb:after{content:"";position:absolute;inset:0;border-radius:inherit;background:repeating-radial-gradient(ellipse at 70% 70%,transparent 0 3px,#ffffff03 3px 4px)}.ring{position:absolute;left:1%;right:1%;top:32%;height:36%;border:1px solid hsl(HUE 28% 61% / .53);border-radius:50%;transform:rotate(-TILTdeg);box-shadow:0 2px 0 hsl(HUE 20% 33% / .28),0 3px 8px #0003;z-index:2}.ring:after{content:"";position:absolute;inset:7px;border:1px solid hsl(HUE 27% 65% / .12);border-radius:50%}.point{position:absolute;right:15%;top:15%;width:4px;height:4px;background:hsl(HUE 40% 74%);border-radius:50%;box-shadow:0 0 14px hsl(HUE 40% 70% / .5)}.art-caption{position:absolute;bottom:4%;left:0;right:0;text-align:center;font-size:8px;letter-spacing:.26em;color:#808b7e}.detail{display:flex;align-items:baseline;justify-content:space-between;gap:28px;border-top:1px solid #ffffff12;padding:33px 0 35px}.detail h2{font-size:11px;font-weight:400;color:#c5c9be;margin:0;letter-spacing:.04em}.detail p{max-width:390px;font-size:12px;line-height:1.85;margin:0;color:#8e9889}.footer{border-top:1px solid #ffffff12;display:flex;align-items:center;justify-content:space-between;gap:20px;padding:23px 0 35px;font-size:10px;color:#7e897a}.domain{overflow-wrap:anywhere}.footer span:last-child{color:#9ba392;font-size:9px;letter-spacing:.15em}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}@media(min-width:1440px){.hero{min-height:700px}}@media(max-width:900px){.shell{padding:0 38px}.hero{min-height:570px;padding:62px 0;gap:0}.sculpture{width:100%;max-width:none;justify-self:center}h1{font-size:59px}.description{font-size:13px}.header{min-height:104px}}@media(max-width:620px){.shell{padding:0 25px}.header{min-height:88px;gap:16px}.brand{font-size:12px;letter-spacing:.13em;gap:12px}.emblem{width:19px;height:19px}.status{font-size:8px;letter-spacing:.1em;gap:7px}.hero{display:flex;flex-direction:column;align-items:stretch;padding:51px 0 21px;min-height:0}.eyebrow{font-size:9px;margin-bottom:26px}h1{font-size:clamp(43px,11.7vw,68px);margin-bottom:22px}.description{font-size:13px;max-width:320px}.quiet-link{margin-top:22px}.sculpture{width:84%;max-width:360px;margin:10px auto 0}.detail{display:block;padding:26px 0}.detail h2{margin-bottom:13px}.detail p{font-size:11px;max-width:320px}.footer{padding:22px 0 28px;font-size:9px}.footer span:last-child{font-size:8px;letter-spacing:.07em}.art-caption{font-size:7px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}'''.replace('HUE', str(hue)).replace('TILT', str(tilt))
    # A finite family of designs, not a claim of resistance to fingerprinting.
    # Only the selected composition is included in the resulting stylesheet.
    variants = (
        '',
        r"""html{color-scheme:light}body{background:#efece5;color:#242922}body:before{background:radial-gradient(ellipse at 82% 44%,#cbbda720,transparent 56%)}.header,.detail,.footer{border-color:#262c241c}.status,.description,.detail p,.footer{color:#515c4c}.description strong,.detail h2,.footer span:last-child{color:#354030}.eyebrow,h1 em,.quiet-link span{color:#586d46}.quiet-link{border-color:#35403050}.emblem,.emblem:after{border-color:#586d46}.orb{inset:17% 25%;border-radius:2px;transform:rotate(-19deg);background:linear-gradient(135deg,#fdfcf8,#b7b89f);box-shadow:12px 20px 28px #28281f30,inset 0 0 0 1px #515c4c25}.orb:after{border-radius:0;background:linear-gradient(40deg,transparent 49.8%,#fff9 50%,transparent 50.3%)}.ring{left:20%;right:19%;top:23%;height:61%;border:1px solid #626b5070;border-radius:2px;transform:rotate(13deg);box-shadow:none;z-index:-1}.ring:after{border-color:#626b5030;border-radius:2px}.halo{inset:8%;border-color:#626b5020}.halo:before,.halo:after{border-color:#626b5014}.point{background:#586d46;box-shadow:none}.art-caption{color:#65745b}.hero{grid-template-columns:1fr 1fr}h1 em{font-style:normal}""",
        r"""body{background:#121923;color:#edf1f4}body:before{background:radial-gradient(ellipse at 82% 44%,#37567525,transparent 56%)}.status,.description,.detail p,.footer{color:#a0b0c0}.description strong,.detail h2,.footer span:last-child{color:#c5d3e0}.eyebrow,h1 em,.quiet-link span{color:#adc9e4}.orb{inset:22%;border-radius:13px;transform:rotate(-28deg);background:repeating-linear-gradient(90deg,#aacbe114 0 1px,transparent 1px 28px),repeating-linear-gradient(0deg,#aacbe114 0 1px,#263e55 1px 28px);box-shadow:18px 28px 55px #0005,inset 0 0 0 1px #c4d9e744}.orb:after{background:linear-gradient(120deg,#d9edff28,transparent);border-radius:13px}.ring{left:15%;right:15%;top:21%;height:58%;border-radius:12px;transform:rotate(13deg);border-color:#94b8d47a}.ring:after{border-radius:8px;border-color:#94b8d433}.halo,.halo:before,.halo:after{border-radius:12%;border-color:#94b8d417}.point{background:#b4d2e9}.art-caption{color:#a0b0c0}h1{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:clamp(44px,5vw,72px);font-weight:400;line-height:1.12}h1 em{font-style:normal;font-weight:300}.emblem,.emblem:after{border-color:#adc9e4}""",
        r"""body{background:#171923;color:#f1edf6}body:before{background:radial-gradient(ellipse at 80% 48%,#65527722,transparent 56%)}.status,.description,.detail p,.footer{color:#b0a8bc}.description strong,.detail h2,.footer span:last-child{color:#d3cadd}.eyebrow,h1 em,.quiet-link span{color:#c0aacd}.orb{inset:12% 25% 19%;border-radius:48% 48% 3% 3%;background:linear-gradient(155deg,#a190ae,#4a435d 45%,#272536);transform:rotate(0);box-shadow:24px 24px 48px #0004,inset 1px 1px 1px #eee5ff66}.orb:after{border-radius:inherit;background:repeating-linear-gradient(90deg,transparent 0 13px,#ffffff07 13px 14px)}.ring{left:18%;right:18%;top:5%;height:76%;border:1px solid #b7a1ce66;border-radius:49% 49% 2% 2%;transform:rotate(-11deg);box-shadow:none;z-index:-1}.ring:after{border-radius:inherit;border-color:#b7a1ce33}.halo{inset:4% 12%;border-radius:49% 49% 3% 3%;border-color:#b7a1ce17}.halo:before,.halo:after{display:none}.point{background:#ccb8d9;box-shadow:none}.art-caption{color:#b0a8bc}.emblem,.emblem:after{border-color:#c0aacd}""",
    )
    css += variants[variant]
    # Long hostnames and intermediate viewports must not stretch grid tracks.
    css += '.hero>*{min-width:0}.copy,.brand,.domain{overflow-wrap:anywhere}.sculpture{overflow:hidden}.quiet-link{max-width:100%}.header>a{min-width:0}.header>.status{flex-shrink:0}'
    headings = (('Новая глава.', 'Скоро здесь.'), ('Место для идей.', 'Скоро откроемся.'),
                ('Всё начинается', 'с первого шага.'), ('Новый взгляд.', 'Скоро на сайте.'))
    heading, subheading = headings[variant]
    theme_color = ('#101211', '#efece5', '#121923', '#171923')[variant]
    icon = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#101211"/><g fill="none" stroke="hsl({hue} 29% 69%)" stroke-width="1.6"><path d="M32 11 53 32 32 53 11 32Z"/><path d="m32 22 10 10-10 10-10-10Z"/></g></svg>'''
    css_bytes, icon_bytes = css.encode(), icon.encode()
    css_name = 'assets/style-' + sha(css_bytes)[:20] + '.css'
    icon_name = 'assets/icon-' + sha(icon_bytes)[:20] + '.svg'
    index = f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="{theme_color}"><meta name="description" content="Сайт в разработке. Мы создаём новое пространство и скоро откроем его для вас."><title>{safe_domain} — скоро открытие</title><link rel="icon" type="image/svg+xml" href="{icon_name}"><link rel="stylesheet" href="{css_name}"></head>
<body><div class="shell"><header class="header"><a class="brand" href="#" aria-label="На главную"><span class="emblem" aria-hidden="true"></span>{label}</a><span class="status">СКОРО ОТКРЫТИЕ</span></header><main><section class="hero" aria-labelledby="title"><div class="copy"><p class="eyebrow">НОВОЕ ПРОСТРАНСТВО</p><h1 id="title">{heading}<em>{subheading}</em></h1><p class="description"><strong>Сайт в разработке.</strong><br>Мы продумываем каждую деталь, чтобы создать нечто особенное. Совсем скоро здесь появится наш новый проект.</p><a class="quiet-link" href="#about">Всё начинается с идеи <span aria-hidden="true">↗</span></a></div><div class="sculpture" aria-hidden="true"><div class="halo"></div><div class="orb"></div><div class="ring"></div><div class="point"></div><div class="art-caption">ФОРМА. СМЫСЛ. ДЕТАЛИ.</div></div></section><section class="detail" id="about" aria-labelledby="about-title"><h2 id="about-title">Хорошие вещи требуют внимания.</h2><p>Сейчас мы работаем над новым сайтом.<br>Спасибо за интерес и до скорой встречи.</p></section></main><footer class="footer"><span class="domain">© {safe_domain}</span><span>СОЗДАЁМ НОВОЕ</span></footer></div></body></html>
'''.encode()
    assert len(index) < MAX_INDEX
    return index, {css_name: css_bytes, icon_name: icon_bytes}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def safe_dir(path, private=False):
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & (0o077 if private else 0o022):
        raise Failure('unsafe directory: ' + path.name)


def safe_read(path, private=False, limit=MAX_INDEX):
    path = Path(path)
    before = path.lstat()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if not stat.S_ISREG(before.st_mode):
        raise Failure('unsafe file: ' + path.name)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as f:
        actual = os.fstat(f.fileno())
        if ((actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.geteuid()
                or actual.st_mode & (0o077 if private else 0o022)):
            raise Failure('unsafe or replaced file: ' + path.name)
        if actual.st_size > limit:
            raise Failure('file exceeds safe size: ' + path.name)
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
    if (actual.st_mtime_ns, actual.st_size) != (after.st_mtime_ns, after.st_size):
        raise Failure('file changed during read: ' + path.name)
    if len(data) > limit:
        raise Failure('file exceeds safe size: ' + path.name)
    return data


def cover_identity(state, domain):
    """Prepare once; do not write until installation/publication is authorized."""
    safe_dir(state, private=True)
    path = state / 'cover-identity.json'
    if path.exists() or path.is_symlink():
        def pairs(entries):
            result = {}
            for k, v in entries:
                if k in result:
                    raise Failure('duplicate cover identity key')
                result[k] = v
            return result
        value = json.loads(safe_read(path, private=True, limit=2048), object_pairs_hook=pairs)
        if (not isinstance(value, dict) or set(value) != {'version', 'domain', 'seed'}
                or type(value['version']) is not int or value['version'] != 1
                or value['domain'] != domain or not isinstance(value['seed'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['seed'])):
            raise Failure('invalid or foreign cover identity; not regenerated')
        return value
    return {'version': 1, 'domain': domain, 'seed': secrets.token_hex(32)}


def store_identity(state, value):
    """Atomic no-clobber creation. A interrupted write never leaves a partial seed."""
    path = state / 'cover-identity.json'
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    if path.exists() or path.is_symlink():
        if cover_identity(state, value['domain']) != value:
            raise Failure('cover identity changed concurrently')
        return
    fd, name = tempfile.mkstemp(prefix='.cover-identity-', dir=state)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.link(name, path, follow_symlinks=False)
        sync_dir(state)
    finally:
        Path(name).unlink(missing_ok=True)


def node_config(root):
    etc = root / 'etc/vkarmani-node'
    safe_dir(etc, private=True)
    c = json.loads(safe_read(etc / 'config.json', private=True))
    if not isinstance(c, dict) or c.get('installation_mode') != 'secret-key-only':
        raise Failure('foreign node configuration')
    if not isinstance(c.get('domain'), str) or not DOMAIN.fullmatch(c['domain']):
        raise Failure('invalid node domain')
    address = ipaddress.ip_address(c.get('public_ipv4', ''))
    if address.version != 4 or not address.is_global:
        raise Failure('invalid node IPv4')
    return c


def sites(root):
    site = root / 'var/www/vkarmani-node/site'
    for p in (site.parent, site, site / 'assets'):
        safe_dir(p)
    return site


def publish_assets(site, assets):
    for name, data in assets.items():
        if not re.fullmatch(r'assets/(?:style-[0-9a-f]{20}\.css|icon-[0-9a-f]{20}\.svg)', name):
            raise Failure('invalid generated asset path')
        dest = site / name
        if dest.exists() or dest.is_symlink():
            if safe_read(dest) != data:
                raise Failure('asset hash collision or changed asset; not overwritten')
        else:
            atomic(dest, data, 0o644)


def install_site(root=Path('/')):
    c, site = node_config(root), sites(root)
    state = root / 'var/lib/vkarmani-node'
    identity = cover_identity(state, c['domain'])
    index, assets = render(c['domain'], identity['seed'])
    path = site / 'index.html'
    if path.exists() or path.is_symlink():
        if safe_read(path) != index:
            raise Failure('existing site differs; full installation will not replace it')
    store_identity(state, identity)
    publish_assets(site, assets)
    atomic(path, index, 0o644)
    # These are only created on new nodes. Site-only update does not overwrite
    # existing robots/favicon/404 files, so older pages remain rollback-ready.
    defaults = {
        'robots.txt': b'User-agent: *\nDisallow:\n',
        '404.html': '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Страница не найдена</title><h1>404</h1><p>Страница не найдена.</p><a href="/">На главную</a></html>\n'.encode(),
        'favicon.svg': next(value for key, value in assets.items() if key.endswith('.svg')),
    }
    for name, data in defaults.items():
        dest = site / name
        if not (dest.exists() or dest.is_symlink()):
            atomic(dest, data, 0o644)
    return 'COVER_INSTALL=PASS'


def ready(root):
    state = root / 'var/lib/vkarmani-node'
    safe_dir(state, private=True)
    safe_read(state / 'owned-installation', private=True)
    complete = safe_read(state / 'INSTALL_COMPLETE', private=True).decode()
    version = safe_read(state / 'install-version', private=True).decode().strip()
    if version not in ('2.0.3', '2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.2.0', '2.3.0', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2') or not re.search(r'^version=' + re.escape(version) + '$', complete, re.M):
        raise Failure('site-only update requires a reviewed completed 2.0.3 / 2.1.x / 2.2.0 / 2.3.0 / 2.4.x / 2.5.x installation')
    for name in ('INSTALL_FAILED', 'image-update-pending', 'network-rollback-armed', 'network-rollback-running'):
        p = state / name
        if p.exists() or p.is_symlink():
            raise Failure('unresolved transaction: ' + name)
    return state, node_config(root), sites(root)


def run_checks(c, site, state):
    commands = [['nginx', '-t'], ['/usr/local/sbin/vkarmani-selfsteal-check']]
    for cmd in commands:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        if p.returncode:
            raise Failure('cover readiness failed: ' + Path(cmd[0]).name)
    # Current working nodes must also serve the expected content on TCP/443.
    # This is a LOCAL path, not a claim of external client reachability.
    fd, name = tempfile.mkstemp(prefix='.cover-http-', dir=state)
    os.close(fd)
    try:
        cmd = ['curl', '-q', '--noproxy', '*', '-4', '--fail', '--silent', '--show-error',
               '--http2', '--tlsv1.3', '--tls-max', '1.3', '--connect-timeout', '5',
               '--max-time', '15', '--max-filesize', str(MAX_INDEX),
               '--resolve', f"{c['domain']}:443:{c['public_ipv4']}", '-o', name,
               '-w', '%{http_code}', f"https://{c['domain']}/"]
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        if p.returncode or p.stdout != b'200' or Path(name).read_bytes() != safe_read(site / 'index.html'):
            raise Failure('TCP/443 does not serve the expected site; nothing is restarted')
    finally:
        Path(name).unlink(missing_ok=True)


def receipt_write(folder, data):
    atomic(folder / 'receipt.json', (json.dumps(data, sort_keys=True, indent=2) + '\n').encode())


def pointer_read(state, filename):
    value = safe_read(state / filename, private=True, limit=256).decode().strip()
    if not BACKUP_NAME.fullmatch(value):
        raise Failure('invalid cover backup pointer')
    folder = state / 'backups' / value
    safe_dir(state / 'backups', private=True)
    safe_dir(folder, private=True)
    r = json.loads(safe_read(folder / 'receipt.json', private=True))
    if (not isinstance(r, dict) or set(r) != {'before', 'after', 'domain', 'state'}
            or any(not isinstance(r.get(x), str) or not re.fullmatch(r'[0-9a-f]{64}', r[x]) for x in ('before', 'after'))
            or r.get('state') not in ('pending', 'active', 'rolled-back')):
        raise Failure('invalid cover receipt')
    old = safe_read(folder / 'index.before', private=True)
    if sha(old) != r['before']:
        raise Failure('cover backup checksum mismatch')
    return folder, r, old


def clear_pending(state):
    (state / 'cover-pending').unlink(missing_ok=True)
    sync_dir(state)


def update(root=Path('/'), checker=run_checks):
    state, c, site = ready(root)
    if (state / 'cover-pending').exists() or (state / 'cover-pending').is_symlink():
        raise Failure('cover update interrupted; use --rollback-cover before another update')
    checker(c, site, state)
    old = safe_read(site / 'index.html')
    identity = cover_identity(state, c['domain'])
    index, assets = render(c['domain'], identity['seed'])
    if old == index:
        # Verify assets too, do not call a damaged page "unchanged and healthy".
        for name, data in assets.items():
            if safe_read(site / name) != data:
                raise Failure('generated site asset changed or missing')
        return 'COVER_UPDATE=UNCHANGED'
    backups = state / 'backups'
    if not backups.exists():
        backups.mkdir(mode=0o700)
    safe_dir(backups, private=True)
    name = 'cover-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f') + '-' + secrets.token_hex(6)
    folder = backups / name
    folder.mkdir(mode=0o700)
    atomic(folder / 'index.before', old)
    receipt = {'before': sha(old), 'after': sha(index), 'domain': c['domain'], 'state': 'pending'}
    receipt_write(folder, receipt)
    # Read back the actual backup bytes before marking or publishing anything.
    if safe_read(folder / 'index.before', private=True) != old:
        raise Failure('cover backup verification failed')
    atomic(state / 'cover-pending', (name + '\n').encode())
    published = False
    try:
        store_identity(state, identity)
        publish_assets(site, assets)
        if safe_read(site / 'index.html') != old:
            raise Failure('site changed concurrently; not overwritten')
        # Set before writing: fsync can fail AFTER the atomic replacement.
        published = True
        atomic(site / 'index.html', index, 0o644)
        checker(c, site, state)
        receipt['state'] = 'active'
        receipt_write(folder, receipt)
        atomic(state / 'cover-last-update', (name + '\n').encode())
        clear_pending(state)
    except BaseException:
        # Crash/SIGKILL may prevent execution here; the persisted pointer enables
        # explicit recovery. Do not overwrite a third party's concurrent edit.
        try:
            current = safe_read(site / 'index.html')
            if current not in (old, index):
                raise Failure('concurrent site edit; automatic rollback refused')
            if published and current == index:
                atomic(site / 'index.html', old, 0o644)
            checker(c, site, state)
            receipt['state'] = 'rolled-back'
            receipt_write(folder, receipt)
            clear_pending(state)
        except BaseException:
            print('COVER_ROLLBACK=INCOMPLETE; backup=' + str(folder))
        raise
    return 'COVER_UPDATE=PASS backup=' + str(folder)


def rollback(root=Path('/'), checker=run_checks):
    state, c, site = ready(root)
    pending = (state / 'cover-pending').exists() or (state / 'cover-pending').is_symlink()
    folder, receipt, old = pointer_read(state, 'cover-pending' if pending else 'cover-last-update')
    if receipt['domain'] != c['domain']:
        raise Failure('backup belongs to a different domain')
    current = safe_read(site / 'index.html')
    if sha(current) not in (receipt['before'], receipt['after']):
        raise Failure('site changed after update; rollback will not overwrite it')
    if sha(current) == receipt['after']:
        atomic(site / 'index.html', old, 0o644)
    checker(c, site, state)
    receipt['state'] = 'rolled-back'
    receipt_write(folder, receipt)
    if pending:
        clear_pending(state)
    return 'COVER_ROLLBACK=PASS; old assets retained, VPN files and services unchanged'


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'update', 'rollback'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on the node')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        print({'install': install_site, 'update': update, 'rollback': rollback}[args.action]())
        return 0
    except (Failure, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print('STOP: ' + (str(exc) if isinstance(exc, Failure) else 'cover operation failed (I/O, timeout or invalid state); no VPN restart'))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
VK_SITE_TOOL_PY
    chmod 0700 "$destination"
}

vk_write_resources_helper() {
    local destination=${1:-"$LIB/resources.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_RESOURCES_PY'
#!/usr/bin/env python3
"""Read-only host resource snapshot; no connection lists, user IDs or secrets."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time


def text(path):
    try:
        return path.read_text()
    except OSError:
        return ''


def cpu_values(raw):
    line = next((x for x in raw.splitlines() if x.startswith('cpu ')), '')
    try:
        values = [int(v) for v in line.split()[1:9]]
        if len(values) != 8 or any(v < 0 for v in values):
            return None
        return values  # Do not double-count guest/guest_nice.
    except ValueError:
        return None


def paired_counters(raw, group, selected):
    rows = raw.splitlines()
    for i in range(len(rows) - 1):
        a, b = rows[i].split(), rows[i + 1].split()
        if not a or not b or a[0] != group + ':' or b[0] != group + ':':
            continue
        try:
            pairs = dict(zip(a[1:], (int(v) for v in b[1:]), strict=True))
        except ValueError:
            return {}
        return {name: pairs[name] for name in selected if name in pairs}
    return {}


def sample(proc=Path('/proc')):
    vm = {}
    for line in text(proc / 'vmstat').splitlines():
        pair = line.split()
        if len(pair) == 2 and pair[0] in ('oom_kill', 'pswpin', 'pswpout') and pair[1].isdigit():
            vm[pair[0]] = int(pair[1])
    return {
        'cpu': cpu_values(text(proc / 'stat')),
        'tcp': paired_counters(text(proc / 'net/snmp'), 'Tcp', ('OutSegs', 'RetransSegs', 'AttemptFails', 'EstabResets')),
        'tcp_ext': paired_counters(text(proc / 'net/netstat'), 'TcpExt', ('ListenOverflows', 'ListenDrops', 'TCPTimeouts')),
        'vm': vm,
    }


def deltas(before, after):
    return {k: (after[k] - before[k] if after[k] >= before[k] else None)
            for k in before.keys() & after.keys()}


def memory_info(raw):
    result = {}
    for line in raw.splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].isdigit():
            result[p[0].rstrip(':')] = int(p[1])
    selected = {k + '_MiB': round(result[k] / 1024, 1)
                for k in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree') if k in result}
    if 'SwapTotal' in result and 'SwapFree' in result:
        selected['SwapUsed_MiB'] = round((result['SwapTotal'] - result['SwapFree']) / 1024, 1)
    return selected


def pressure(raw):
    result = {}
    for line in raw.splitlines():
        p = line.split()
        if p and p[0] in ('some', 'full'):
            parsed = {}
            for item in p[1:]:
                if '=' not in item:
                    continue
                k, v = item.split('=', 1)
                if k not in ('avg10', 'avg60', 'avg300', 'total'):
                    continue
                try:
                    parsed[k] = int(v) if k == 'total' else float(v)
                except ValueError:
                    continue
            result[p[0]] = parsed
    return result or None


def summarize(before, after):
    result = {name + '_delta': deltas(before[name], after[name]) for name in ('tcp', 'tcp_ext', 'vm')}
    cpu = None
    if before['cpu'] is not None and after['cpu'] is not None:
        delta = [b - a for a, b in zip(before['cpu'], after['cpu'])]
        total = sum(delta)
        if total > 0 and all(x >= 0 for x in delta):
            cpu = {'busy_percent': round(100 * (total - delta[3] - delta[4]) / total, 2),
                   'iowait_percent': round(100 * delta[4] / total, 2),
                   'steal_percent': round(100 * delta[7] / total, 2)}
    result['cpu'] = cpu
    # No arbitrary "packet loss %": TCP retransmission counters are host-wide,
    # not end-to-end losses nor traffic for this node only.
    return result


def container_state():
    if not shutil.which('docker'):
        return {'verified': False, 'reason': 'docker_cli_absent'}
    fmt = '{"running":{{.State.Running}},"restarting":{{.State.Restarting}},"oom_killed":{{.State.OOMKilled}},"restarts":{{.RestartCount}}}'
    try:
        p = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'inspect', '--format', fmt, 'remnanode'],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        if p.returncode:
            return {'verified': False, 'reason': 'container_unavailable'}
        data = json.loads(p.stdout)
        if (not isinstance(data, dict) or set(data) != {'running', 'restarting', 'oom_killed', 'restarts'}
                or any(type(data.get(k)) is not bool for k in ('running', 'restarting', 'oom_killed'))
                or type(data.get('restarts')) is not int or data['restarts'] < 0):
            raise ValueError()
        return {'verified': True, **data,
                'status': 'CRITICAL' if data['oom_killed'] else ('WARN' if data['restarting'] else 'OK')}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'verified': False, 'reason': 'timeout_or_invalid_response'}


def process_identity(path):
    raw = (path / 'stat').read_text()
    fields = raw.rsplit(')', 1)[1].split()
    return int(fields[19])  # starttime; pid reuse must not yield a false snapshot


def fd_snapshot(proc=Path('/proc'), limit=64):
    """Only daemon counters, never fd targets, cmdline, environ or peer addresses."""
    result, errors, truncated = [], 0, False
    try:
        with os.scandir(proc) as entries:
            candidates = [Path(x.path) for x in entries if x.name.isdecimal()]
    except OSError:
        return {'verified': False, 'reason': 'proc_unavailable'}
    for path in candidates:
        try:
            comm = (path / 'comm').read_text().strip()
            if comm not in ('nginx', 'rw-core', 'xray', 'rw-node'):
                continue
            if len(result) >= limit:
                truncated = True
                break
            identity = process_identity(path)
            bounds = None
            for line in (path / 'limits').read_text().splitlines():
                if line.startswith('Max open files'):
                    words = line.split()
                    if len(words) != 6:
                        raise ValueError('invalid limit record')
                    bounds = [None if v == 'unlimited' else int(v) for v in words[3:5]]
            if bounds is None:
                raise ValueError('missing limit')
            with os.scandir(path / 'fd') as fds:
                count = sum(1 for _ in fds)
            if process_identity(path) != identity:
                raise ValueError('process changed')
            percent = round(100 * count / bounds[0], 2) if bounds[0] else None
            status = ('NOT_APPLICABLE' if percent is None else
                      'CRITICAL' if percent >= 85 else 'WARN' if percent >= 70 else 'OK')
            result.append({'process': comm, 'pid': int(path.name), 'open_fds': count,
                           'soft_limit': bounds[0], 'hard_limit': bounds[1],
                           'soft_limit_percent': percent, 'status': status})
        except (OSError, ValueError, IndexError):
            errors += 1
    return {'verified': not errors and not truncated, 'processes': result,
            'unreadable_or_changed': errors, 'truncated': truncated,
            'scope': 'POINT_IN_TIME_DAEMON_FD_COUNTS_NOT_A_LEAK_DIAGNOSIS'}


def parse_socket_queue(raw):
    paths = {'/run/vkarmani-selfsteal/nginx.sock', '/dev/shm/nginx.sock'}
    result = []
    for line in raw.splitlines():
        words = line.split()
        if not paths.intersection(words):
            continue
        if len(words) < 5 or words[0] != 'u_str' or words[1] != 'LISTEN':
            raise ValueError('unexpected listener fields')
        pending, backlog = int(words[2]), int(words[3])
        if pending < 0 or backlog < 0:
            raise ValueError('negative listener counters')
        result.append({'pending_connections': pending, 'backlog': backlog})
    return result


def socket_queue(runner=subprocess.run):
    try:
        p = runner(['ss', '-H', '-x', '-l', '-n'], stdin=subprocess.DEVNULL,
                   capture_output=True, text=True, timeout=5,
                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if p.returncode:
            raise ValueError('ss failed')
        queues = parse_socket_queue(p.stdout)
        return {'verified': True, 'listeners': queues, 'present': bool(queues)}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'verified': False, 'reason': 'listener_snapshot_unavailable'}


def conntrack_snapshot(proc=Path('/proc')):
    count_path = proc / 'sys/net/netfilter/nf_conntrack_count'
    max_path = proc / 'sys/net/netfilter/nf_conntrack_max'
    try:
        count_raw, max_raw = count_path.read_text().strip(), max_path.read_text().strip()
    except OSError:
        return {'verified': False, 'reason': 'conntrack_subsystem_unavailable',
                'scope': 'HOST_WIDE_NOT_VPN_ONLY'}
    if not count_raw.isdigit() or not max_raw.isdigit():
        return {'verified': False, 'reason': 'conntrack_counters_invalid',
                'scope': 'HOST_WIDE_NOT_VPN_ONLY'}
    count, maximum = int(count_raw), int(max_raw)
    if maximum <= 0:
        return {'verified': False, 'reason': 'conntrack_max_invalid',
                'scope': 'HOST_WIDE_NOT_VPN_ONLY'}
    percent = round(100 * count / maximum, 2)
    status = 'CRITICAL' if percent >= 85 else 'WARN' if percent >= 70 else 'OK'
    return {'verified': True, 'count': count, 'max': maximum, 'percent': percent,
            'status': status, 'scope': 'HOST_WIDE_NOT_VPN_ONLY'}


def disk_snapshot(path='/', statvfs=os.statvfs):
    try:
        v = statvfs(path)
        total_mib = v.f_blocks * v.f_frsize / 1048576
        available_mib = v.f_bavail * v.f_frsize / 1048576
        available_percent = 100 * v.f_bavail / v.f_blocks if v.f_blocks else None
        inode_percent = 100 * v.f_favail / v.f_files if v.f_files else None
        if available_percent is None:
            disk_status = 'NOT_VERIFIED'
        elif available_percent < 5 or available_mib < 512:
            disk_status = 'CRITICAL'
        elif available_percent < 10 or available_mib < 1024:
            disk_status = 'WARN'
        else:
            disk_status = 'OK'
        if inode_percent is None:
            inode_status = 'NOT_VERIFIED'
        elif inode_percent < 5:
            inode_status = 'CRITICAL'
        elif inode_percent < 10:
            inode_status = 'WARN'
        else:
            inode_status = 'OK'
        return {'total_MiB': round(total_mib, 1), 'available_MiB': round(available_mib, 1),
                'available_percent': round(available_percent, 2) if available_percent is not None else None,
                'status': disk_status, 'total_inodes': v.f_files, 'available_inodes': v.f_favail,
                'available_inodes_percent': round(inode_percent, 2) if inode_percent is not None else None,
                'inode_status': inode_status, 'basis': 'statvfs_f_bavail_and_f_favail'}
    except (OSError, ValueError, ZeroDivisionError):
        return None


def reboot_required(root=Path('/')):
    try:
        return (root / 'var/run/reboot-required').exists()
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=3, choices=range(1, 31), metavar='1..30')
    args = parser.parse_args()
    proc = Path('/proc')
    start = time.monotonic()
    before = sample(proc)
    time.sleep(args.seconds)
    after = sample(proc)
    result = {'scope': 'HOST_LOCAL_ONLY_NOT_A_VPN_SPEED_TEST', 'kernel': platform.release(),
              'sample_seconds': round(time.monotonic() - start, 3), **summarize(before, after),
              'memory': memory_info(text(proc / 'meminfo')),
              'pressure': {kind: pressure(text(proc / 'pressure' / kind)) for kind in ('cpu', 'memory', 'io')},
              'container': container_state(), 'daemon_fds': fd_snapshot(proc),
              'selfsteal_socket_queue': socket_queue(), 'conntrack': conntrack_snapshot(proc),
              'root_disk': disk_snapshot('/'), 'reboot_required': reboot_required()}
    result['interpretation'] = ('Counters are host-wide observations, not a diagnosis of censorship or proof of provider overselling. '
                                'Compare idle/load samples and client-side throughput before changing MTU, queues, buffers or CPU settings. '
                                'Threshold statuses are diagnostic only; this command never tunes conntrack, limits, swap, MTU or firewall state.')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
VK_RESOURCES_PY
    chmod 0700 "$destination"
}

vkarmani_site_main() (
    set -Eeuo pipefail
    set +x
    umask 077
    export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    local action=$1 work
    shift
    [[ $# -eq 0 ]] || { echo 'Usage: bash install.sh --update-cover / --rollback-cover'; exit 2; }
    [[ $EUID -eq 0 && -d /run/systemd/system ]] || { echo 'STOP: run as root on the installed node.'; exit 1; }
    exec 9>/run/lock/vkarmani-node-installer.lock
    flock -n 9 || { echo 'STOP: another installer/maintenance operation is running.'; exit 1; }
    work=$(mktemp -d /root/vkarmani-cover.XXXXXXXX)
    trap 'rm -rf -- "$work"' EXIT
    vk_write_site_tool "$work/site_tool.py"
    python3 "$work/site_tool.py" "$action"
)

vkarmani_resources_main() (
    set -Eeuo pipefail
    set +x
    export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    local work
    work=$(mktemp -d /tmp/vkarmani-resources.XXXXXXXX)
    trap 'rm -rf -- "$work"' EXIT
    vk_write_resources_helper "$work/resources.py"
    python3 "$work/resources.py" "$@"
)

vk_write_ssh_guard() {
    local destination=${1:-"$LIB/ssh_guard.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_SSH_GUARD_PY'
#!/usr/bin/env python3
"""Password-only SSH admission and effective policy; never reads operator input.
No account/password/key changes. Preflight checks local password state, not an
actual login. The operator must verify a second password session before deployment.
"""
import argparse
import datetime as dt
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys

EXPECTED = {
    'addressfamily': 'inet', 'passwordauthentication': 'yes',
    'pubkeyauthentication': 'no', 'authenticationmethods': 'password',
    'kbdinteractiveauthentication': 'no', 'permitemptypasswords': 'no',
    'hostbasedauthentication': 'no', 'gssapiauthentication': 'no',
    'permitrootlogin': 'yes',
}


class Failure(Exception):
    pass


def password_state(row, today):
    """Validate one shadow row in memory. Error codes never contain password data."""
    fields = row.rstrip('\n').split(':')
    if len(fields) != 9:
        raise Failure('SHADOW_RECORD_INVALID')
    password = fields[1]
    if not password or password.startswith(('!', '*')):
        raise Failure('PASSWORD_MISSING_OR_LOCKED')
    # Avoid treating literal placeholders or unsupported records as a usable hash.
    if not (password.startswith('$') or re.fullmatch(r'[./A-Za-z0-9]{13}', password)):
        raise Failure('PASSWORD_HASH_FORMAT_UNRECOGNIZED')
    try:
        last, maximum, inactive, expiry = [int(fields[n]) if fields[n] else -1 for n in (2, 4, 6, 7)]
    except ValueError:
        raise Failure('PASSWORD_AGING_INVALID') from None
    if any(n < -1 for n in (last, maximum, inactive, expiry)):
        raise Failure('PASSWORD_AGING_INVALID')
    if last == 0:
        raise Failure('PASSWORD_CHANGE_REQUIRED')
    if expiry != -1 and today >= expiry:
        raise Failure('ACCOUNT_EXPIRED')
    if last > today:
        raise Failure('PASSWORD_DATE_IN_FUTURE_CHECK_CLOCK')
    if last != -1 and maximum != -1 and today >= last + maximum:
        raise Failure('PASSWORD_EXPIRED')
    return True


def preflight(user, shadow=Path('/etc/shadow'), lookup=pwd.getpwnam, today=None):
    if not isinstance(user, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*[$]?', user):
        raise Failure('ADMIN_NAME_INVALID')
    try:
        account = lookup(user)
    except KeyError:
        raise Failure('LOCAL_ADMIN_ACCOUNT_MISSING') from None
    shell = account.pw_shell
    if (not shell.startswith('/') or Path(shell).name in ('nologin', 'false')
            or not os.access(shell, os.X_OK)):
        raise Failure('ADMIN_LOGIN_SHELL_UNAVAILABLE')
    fd = os.open(shadow, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o027):
            raise Failure('SHADOW_FILE_UNSAFE')
        data = f.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise Failure('SHADOW_FILE_TOO_LARGE')
    rows = [row for row in data.decode('utf-8').splitlines() if row.split(':', 1)[0] == user]
    if len(rows) != 1:
        raise Failure('LOCAL_ADMIN_SHADOW_RECORD_MISSING_OR_DUPLICATE')
    if today is None:
        today = (dt.datetime.now(dt.timezone.utc).date() - dt.date(1970, 1, 1)).days
    password_state(rows[0], today)
    return True


def inspect_policy(main=Path('/etc/ssh/sshd_config')):
    """Refuse conditional/custom include policy rather than silently bypassing it.

    sshd -T without connection context does not resolve all possible Match cases.
    The dedicated-node installer supports the distro root file + its standard
    drop-in directory only. No include, Match or access restriction is deleted.
    """
    dropin = main.parent / 'sshd_config.d'
    files = [main]
    if dropin.exists() or dropin.is_symlink():
        info = dropin.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise Failure('SSH_INCLUDE_DIRECTORY_UNSAFE')
        files += sorted(dropin.glob('*.conf'))
    if len(files) > 129:
        raise Failure('SSH_POLICY_TOO_MANY_FILES')
    for path in files:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise Failure('SSH_POLICY_FILE_UNSAFE')
            raw = f.read(1048577)
        if len(raw) > 1048576:
            raise Failure('SSH_POLICY_FILE_TOO_LARGE')
        for line in raw.decode('utf-8').splitlines():
            # OpenSSH accepts optional '=' after a keyword; do not miss Match=.
            line = re.sub(r'^([ \t]*[A-Za-z]+)[ \t]*=', r'\1 ', line)
            try:
                words = shlex.split(line, comments=True)
            except ValueError:
                raise Failure('SSH_POLICY_SYNTAX_REQUIRES_REVIEW') from None
            if not words:
                continue
            key = words[0].lower()
            if key in ('match', 'allowusers', 'denyusers', 'allowgroups', 'denygroups'):
                raise Failure('SSH_CONDITIONAL_OR_ACCESS_POLICY_REQUIRES_REVIEW')
            if key == 'include':
                if path != main or words[1:] != [str(dropin / '*.conf')]:
                    raise Failure('SSH_CUSTOM_OR_RECURSIVE_INCLUDE_REQUIRES_REVIEW')
    return True


def validate_effective(text):
    values = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in EXPECTED:
            if parts[0] in values:
                raise Failure('SSH_EFFECTIVE_DUPLICATE_FIELD')
            values[parts[0]] = parts[1]
    if any(values.get(k) != v for k, v in EXPECTED.items()):
        raise Failure('SSH_PASSWORD_ONLY_POLICY_MISMATCH')
    return True


def check(runner=subprocess.run):
    result = runner(['/usr/sbin/sshd', '-T'], stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=10,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise Failure('SSHD_EFFECTIVE_CONFIG_UNAVAILABLE')
    validate_effective(result.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('preflight', 'check'))
    p.add_argument('--user')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('root required')
    if (args.action == 'preflight') != bool(args.user):
        p.error('--user is required only for preflight')
    try:
        inspect_policy()
        if args.action == 'preflight':
            preflight(args.user)
            print('SSH_PASSWORD_STATE=PASS; PASSWORD_NOT_REQUESTED_OR_CHANGED; REMOTE_LOGIN=NOT_TESTED')
        else:
            check()
            print('SSH_PASSWORD_ONLY=PASS; PUBLICKEY_LOGIN=DISABLED; AUTHORIZED_KEYS_FILES=PRESERVED')
        return 0
    except Failure as exc:
        print('SSH_GUARD=FAIL ' + str(exc), file=sys.stderr)
    except Exception:
        print('SSH_GUARD=FAIL LOCAL_CHECK_UNAVAILABLE (no credentials displayed)', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
VK_SSH_GUARD_PY
    chmod 0700 "$destination"
}

vk_write_cert_deploy() {
    local destination=${1:-"$LIB/cert_deploy.py"}
    install -d -m 0700 "$(dirname -- "$destination")"
    cat > "$destination" <<'VK_CERT_DEPLOY_PY'
#!/usr/bin/env python3
"""Activate this node's renewed certificate without Xray restarts or port redirects.
A status receipt is evidence of one hook run, not proof of future renewal or WAN
availability. Certbot owns certificate files; this helper never rolls them back.
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
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
CERT_ROOT = Path('/etc/letsencrypt/live')
STATUS = STATE / 'cert-deploy-status.json'
LOCK = Path('/run/lock/vkarmani-cert-deploy.lock')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')


class Failure(Exception):
    pass


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Failure('UNSAFE_PRIVATE_STATE')
        b = f.read(65537)
    if len(b) > 65536:
        raise Failure('STATE_TOO_LARGE')
    return json.loads(b)


def current_domain():
    c = read_private(ETC / 'config.json')
    d = c.get('domain')
    if c.get('installation_mode') != 'secret-key-only' or not isinstance(d, str) or not DOMAIN.fullmatch(d):
        raise Failure('NODE_DOMAIN_OR_OWNERSHIP_INVALID')
    return d


def leaf_fingerprint(domain):
    # Certbot's live/fullchain.pem symlink is intentional, unlike arbitrary state files.
    with (CERT_ROOT / domain / 'fullchain.pem').open('rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Failure('CERTIFICATE_NOT_REGULAR')
        b = f.read(1024 * 1024 + 1)
    if len(b) > 1024 * 1024:
        raise Failure('CERTIFICATE_TOO_LARGE')
    text = b.decode('ascii')
    end = '-----END CERTIFICATE-----'
    if end not in text:
        raise Failure('CERTIFICATE_PEM_INVALID')
    der = ssl.PEM_cert_to_DER_cert(text.split(end, 1)[0] + end + '\n')
    return hashlib.sha256(der).hexdigest()


def record(value):
    parent = STATUS.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise Failure('UNSAFE_STATUS_DIRECTORY')
    if STATUS.exists() or STATUS.is_symlink():
        read_private(STATUS)
    fd, name = tempfile.mkstemp(prefix='.cert-deploy-', dir=STATUS.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, sort_keys=True)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(name, STATUS)
        dfd = os.open(STATUS.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        Path(name).unlink(missing_ok=True)


def generation():
    if not STATUS.exists() and not STATUS.is_symlink():
        return 'absent'
    value = read_private(STATUS).get('generation')
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value):
        raise Failure('DEPLOY_GENERATION_INVALID')
    return value


def verify_new(before):
    if before != 'absent' and not re.fullmatch(r'[a-f0-9]{32}', before):
        raise Failure('PREVIOUS_GENERATION_INVALID')
    after = read_private(STATUS)
    current = after.get('generation') if isinstance(after, dict) else None
    domain = current_domain()
    if (not isinstance(current, str) or not re.fullmatch(r'[a-f0-9]{32}', current)
            or current == before or after.get('result') != 'PASS'
            or after.get('phase') != 'COMPLETE' or after.get('domain') != domain
            or after.get('certificate_sha256') != leaf_fingerprint(domain)):
        raise Failure('NEW_SUCCESSFUL_DEPLOY_NOT_PROVEN')
    print('CERTBOT_DEPLOY_HOOK=PASS; CURRENT_CERTIFICATE_ACTIVATION_VERIFIED')


def execute(args, deadline, runner):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Failure('DEPLOY_DEADLINE_EXHAUSTED')
    try:
        p = runner(args, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=min(20, remaining), env=ENV)
    except subprocess.TimeoutExpired:
        raise Failure('DEPLOY_COMMAND_TIMEOUT') from None
    if p.returncode:
        raise Failure('DEPLOY_COMMAND_FAILED')


def deploy(domain, runner=subprocess.run, budget=75):
    if not 1 <= budget <= 75:
        raise Failure('DEPLOY_BUDGET_INVALID')
    value = {'version': 1, 'generation': secrets.token_hex(16), 'domain': domain,
             'started_at': dt.datetime.now(dt.timezone.utc).isoformat(),
             'result': 'RUNNING', 'phase': 'PRECHECK'}
    deadline = time.monotonic() + budget
    record(value)
    try:
        value['certificate_sha256'] = leaf_fingerprint(domain)
        execute(['/usr/sbin/nginx', '-t'], deadline, runner)
        value['phase'] = 'RELOAD'; record(value)
        execute(['/usr/bin/systemctl', 'reload', 'nginx'], deadline, runner)
        value['phase'] = 'VERIFY_TARGET_TLS'; record(value)
        # systemctl reload is graceful: for a brief interval an old worker can
        # still overlap the new generation. One successful connection is not
        # sufficient evidence that fresh handshakes consistently serve the new
        # certificate. Require several consecutive target-only successes and
        # reset the streak on any transient old-certificate/failure result.
        stable = 0
        while stable < 4:
            try:
                execute(['/usr/local/sbin/vkarmani-selfsteal-check', '--target-only'], deadline, runner)
                stable += 1
                if stable < 4:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.25:
                        raise Failure('DEPLOY_DEADLINE_EXHAUSTED')
                    time.sleep(0.25)
            except Failure as exc:
                if str(exc).startswith('INTERRUPTED_') or deadline - time.monotonic() <= 1:
                    raise
                stable = 0
                time.sleep(min(1, max(0, deadline - time.monotonic())))
        if leaf_fingerprint(domain) != value['certificate_sha256']:
            raise Failure('CERTIFICATE_CHANGED_DURING_DEPLOY')
        value.update(result='PASS', phase='COMPLETE', finished_at=dt.datetime.now(dt.timezone.utc).isoformat())
        record(value)
        print('CERT_DEPLOY=PASS; TARGET_TLS=PASS; WEB_CONTENT=NOT_TESTED; XRAY_RESTART=NOT_PERFORMED')
    except BaseException as exc:
        value['result'] = 'FAIL'
        value['error'] = str(exc) if isinstance(exc, Failure) else 'INTERRUPTED_OR_LOCAL_ERROR'
        try: record(value)
        except Exception: print('CERT_DEPLOY_STATUS=NOT_SAVED', file=sys.stderr)
        raise


def interrupted(signum, _frame):
    raise Failure('INTERRUPTED_' + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('deploy', 'generation', 'verify-new'))
    parser.add_argument('previous', nargs='?')
    a = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required')
    if (a.action == 'verify-new') != (a.previous is not None):
        parser.error('previous generation required only for verify-new')
    os.umask(0o077)
    if a.action == 'generation':
        print(generation()); return 0
    if a.action == 'verify-new':
        verify_new(a.previous); return 0
    d = current_domain()
    lineage = os.environ.get('RENEWED_LINEAGE', '')
    if not lineage:
        raise Failure('CERTBOT_RENEWED_LINEAGE_MISSING')
    if lineage != str(CERT_ROOT / d):
        print('CERT_DEPLOY=SKIPPED_OTHER_LINEAGE'); return 0
    if set(os.environ.get('RENEWED_DOMAINS', '').split()) != {d}:
        raise Failure('CERTBOT_DOMAIN_CONTRACT_MISMATCH')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        st = os.fstat(lock.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise Failure('UNSAFE_DEPLOY_LOCK')
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Failure('ANOTHER_CERT_DEPLOY_RUNNING') from None
        deploy(d)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Failure as exc:
        print('CERT_DEPLOY=FAIL ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print('CERT_DEPLOY=FAIL LOCAL_IO_OR_CONFIG_ERROR (no secrets displayed)', file=sys.stderr)
        raise SystemExit(1)
VK_CERT_DEPLOY_PY
    chmod 0700 "$destination"
}

vkarmani_main() {
_contains() { grep "$@" >/dev/null; } # Consume stdin fully: safe under pipefail.
# VKarmani Remnawave Node Installer 2.5.2 — 2026-10-06
# Dedicated fresh Ubuntu 22.04/24.04/26.04 or Debian 12/13, systemd + GRUB, amd64/arm64.
# One self-contained file; no remote shell scripts are downloaded/executed.
# WARNING: installs packages, modifies SSH/firewall/boot settings; one successful-install reboot is default.
# Node-only mode: does not create or edit panel objects. RAW+REALITY Selfsteal uses an Nginx Unix socket.
set -Eeuo pipefail
set +x
set +a
umask 077
export LC_ALL=C LANG=C PYTHONUTF8=1 DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset CDPATH ENV BASH_ENV
INSTALLER_VERSION=2.5.2
ETC=/etc/vkarmani-node
STATE=/var/lib/vkarmani-node
LIB=/usr/local/lib/vkarmani-node
OPT=/opt/vkarmani-node
LOG=/var/log/vkarmani-node-install.log
REALITY_KEYS_FILE=/root/reality-keys.txt
# The panel IPv4 is entered on first run. The node IPv4 is never asked: it is selected from DNS + local interfaces.
NODE_PORT_DEFAULT=2222
NO_REBOOT=0
WEEKLY_REBOOT=0
ALLOW_NET_ADMIN=1
IMAGE_OVERRIDE=''

usage() {
    cat <<'HELP'
VKarmani Remnawave Node Installer 2.5.2

  sudo bash install.sh                         # установка + один auto-reboot после успешных проверок
  sudo bash install.sh --no-reboot             # явно запретить одноразовый reboot
  sudo bash install.sh --reboot                # совместимо: явно оставить auto-reboot включённым
  sudo bash install.sh --weekly-reboot         # необязательно: понедельник 04:00 МСК
  sudo bash install.sh --allow-net-admin       # совместимость: NET_ADMIN уже включён по умолчанию
  sudo bash install.sh --backup                # закрытая копия конфигурации с SHA256
  sudo bash install.sh --image remnawave/node@sha256:DIGEST
  sudo bash install.sh --check                 # существующая локальная диагностика
  sudo bash install.sh --refresh-image         # только обновление образа, без настройки ОС
  sudo bash install.sh --rollback-image        # предыдущий образ, без APT/firewall/SSH
  sudo bash install.sh --repair-network        # узкое исправление нашей завершённой 1.3.x
  sudo bash install.sh --repair-node           # узкое исправление нашей завершённой 1.3.x
  sudo bash install.sh --repair-acceptance     # только известный final-acceptance failure 2.5.0 -> hotfix checker 2.5.2
  sudo bash install.sh --update-cover          # только сайт поддерживаемой версии, без restart VPN
  sudo bash install.sh --rollback-cover        # проверенный откат только сайта
  sudo bash install.sh --diagnose-resources    # 3-секундный срез ресурсов, без настройки
  bash install.sh --version

Три обязательных значения: SECRET_KEY → домен ноды → исходящий IPv4 технички.
IP самой ноды выбирается по DNS среди публичных IPv4 её интерфейсов.
Чистая выделенная Ubuntu 22.04/24.04/26.04 или Debian 12/13; amd64/arm64; systemd + GRUB.
Минимум: 900 MiB RAM (26.04: 1536 MiB), 6 GiB свободно. NAT, LXC/OpenVZ, IPv6 SSH, чужая установка не поддержаны.
SSH: только логин/пароль; ключевой вход отключается, authorized_keys не удаляются. Существующие порты, без IP-allowlist. Пароли/аккаунты не создаются.
26.04: адаптация по документации; полный цикл на VPS ещё требует приёмки.
До запуска нужны снимок VPS, консоль хостера и действующий пароль администратора.
IPv6: runtime sysctl + GRUB; для полного отключения socket API необходим reboot.
Полного обновления ОС, autoremove, prune и смены MTU/маршрутов нет. После успешной установки один reboot выполняется автоматически.
Nginx на хосте. Клиентский 443 принадлежит Xray; API 2222 разрешён только с IP технички.
SECRET_KEY не даёт административного API панели: Node/Profile/Host/Squad назначаются в панели.
Let's Encrypt: HTTP-01, порт 80, аккаунт без email; запуск означает согласие с условиями CA.
--no-reboot отключает одноразовый reboot; --reboot и --allow-net-admin сохранены для совместимости. NET_ADMIN включён по умолчанию. --image не является четвёртым вопросом.
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
    printf 'После трёх значений — автоматическая установка и один auto-reboot после успешных проверок. Для запрета: --no-reboot. Нужны снимок VPS и консоль хостера.\n' >&"$VK_TTY_FD"
    printf 'SSH-ключи для входа будут отключены; нужен проверенный вход по паролю. Будут изменены firewall/загрузка, отключён IPv6; условия Let\047s Encrypt принимаются автоматически.\n' >&"$VK_TTY_FD"
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
[[ -z "$IMAGE_OVERRIDE" || "$IMAGE_OVERRIDE" =~ ^(remnawave/node|ghcr\.io/remnawave/node)(:[A-Za-z0-9_.-]+)?(@sha256:[a-f0-9]{64})?$ ]] || {
    echo 'STOP: --image допускает только официальный remnawave/node или ghcr.io/remnawave/node.'; exit 2;
}
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo 'Bash >= 4 required' >&2; exit 1; }
command -v flock >/dev/null || { echo 'util-linux/flock required' >&2; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/vkarmani-node-installer.lock
flock -n 9 || { echo 'Установщик уже запущен.' >&2; exit 1; }
# Version/phase eligibility is checked while holding the installer lock.
RESUME_FROM=''
if [[ -f "$STATE/owned-installation" ]]; then
    PREVIOUS_VERSION=$(cat "$STATE/install-version" 2>/dev/null) || { echo 'STOP: не читается версия незавершённой установки.'; exit 1; }
    if [[ "$PREVIOUS_VERSION" != "$INSTALLER_VERSION" ]]; then
        if [[ "$PREVIOUS_VERSION" == 2.0.2 ]] && vk_check_202_ntp_resume; then
            RESUME_FROM=2.0.2
        else
            echo 'STOP: незавершённая установка другой версии/этапа. Маркеры не изменены; нужен разбор или снимок VPS.'; exit 1
        fi
    fi
fi
[[ -d /run/systemd/system ]] || { echo 'Требуется сервер с systemd.' >&2; exit 1; }
if systemd-detect-virt --container --quiet; then
    echo 'LXC/OpenVZ/Docker не поддерживаются: ядро и полное отключение IPv6 контролирует хост.' >&2
    exit 1
fi
[[ -r /etc/os-release ]] || exit 1
# Only distro-owned os-release is sourced. User input is always JSON, never shell.
# shellcheck disable=SC1091
. /etc/os-release
vk_platform_settings "${ID:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "$(dpkg --print-architecture)"
if [[ "$OS_ID:$OS_CODENAME" == ubuntu:resolute && ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    echo 'STOP: Ubuntu 26.04 requires cgroup v2. No boot/kernel conversion is attempted.' >&2; exit 1
fi
vk_base_tools_smoke
KERNEL_RELEASE=$(uname -r 2>/dev/null) || { echo 'STOP: kernel version cannot be read.' >&2; exit 1; }
if vk_kernel_plugins_supported "$KERNEL_RELEASE"; then
    printf 'NODE_PLUGIN_KERNEL_PREFLIGHT=PASS version=%s\n' "$KERNEL_RELEASE"
else
    printf 'STOP: Node Plugins require a reviewed Linux kernel >= 5.7; current/unparseable kernel=%s. No APT/firewall/GRUB/SSH changes were made.\n' "$KERNEL_RELEASE" >&2
    exit 1
fi
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
[[ "$MEM_MB" -ge "$MIN_MEMORY_MB" && "$FREE_MB" -ge 6144 ]] || {
    echo "Нужно >=${MIN_MEMORY_MB} MiB RAM и >=6144 MiB свободного места. Сейчас RAM=$MEM_MB, disk=$FREE_MB MiB." >&2; exit 1;
}
vk_wait_apt_idle "$APT_LOCK_TOTAL_WAIT"
DPKG_AUDIT=$(dpkg --audit) || { echo "STOP: dpkg --audit failed; package state is NOT verified." >&2; exit 1; }
[[ -z "$DPKG_AUDIT" ]] || { echo 'dpkg сообщает незавершённые операции после освобождения package-manager locks. Исправьте пакетную базу прежде установки.' >&2; exit 1; }
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
# Do not overwrite the old version until its state has been backed up and verified.
if [[ -z "$RESUME_FROM" ]]; then printf '%s\n' "$INSTALLER_VERSION" > "$STATE/install-version"; fi
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
    local failure_record="$STATE/INSTALL_FAILED"
    if [[ -n "$RESUME_FROM" && $(cat "$STATE/install-version" 2>/dev/null) == "$RESUME_FROM" ]]; then
        # A failed backup must not destroy the old, recognized failure checkpoint.
        failure_record="$STATE/RESUME_FAILED"
    fi
    printf 'rc=%s line=%s at=%s\n' "$rc" "$line" "$(date -Is)" > "$failure_record"
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
         etc/systemd/system etc/systemd/journald.conf.d etc/systemd/timesyncd.conf etc/systemd/timesyncd.conf.d \
         etc/tmpfiles.d etc/logrotate.d etc/letsencrypt etc/vkarmani-node opt/vkarmani-node \
         usr/local/lib/vkarmani-node var/www/vkarmani-node var/lib/vkarmani-node/install-version \
         var/lib/vkarmani-node/owned-installation var/lib/vkarmani-node/INSTALL_FAILED \
         var/lib/vkarmani-node/first-backup-path var/lib/vkarmani-node/RESUME_FAILED; do
    if [[ -e "/$p" ]]; then cp -a --parents "/$p" "$BK/"; fi
done
(cd "$BK"; find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 -r sha256sum > MANIFEST.sha256
    sha256sum --check --quiet MANIFEST.sha256)
printf '%s\n' "$BK" > "$STATE/latest-backup-path"
# Mark ownership only after all destructive-operation preconditions pass.
touch "$STATE/owned-installation"
[[ -e "$STATE/first-backup-path" ]] || printf '%s\n' "$BK" > "$STATE/first-backup-path"
if [[ -n "$RESUME_FROM" ]]; then
    # Previous version/failure, helper and key files are now in the verified backup.
    printf '%s\n' "$INSTALLER_VERSION" > "$STATE/install-version.tmp"
    chmod 0600 "$STATE/install-version.tmp"
    mv -f -- "$STATE/install-version.tmp" "$STATE/install-version"
    printf 'RESUME_FROM=%s BACKUP=%s\n' "$RESUME_FROM" "$BK"
fi

stage 'Базовые инструменты из подписанного репозитория ОС'
cat > /etc/apt/apt.conf.d/99-vkarmani-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
Acquire::Retries "3";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
DPkg::Lock::Timeout "15";
EOF
APT=(apt-get -y --no-remove --no-install-recommends -o "DPkg::Lock::Timeout=${APT_LOCK_ATTEMPT_WAIT}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
vk_apt_run apt-get -o APT::Update::Error-Mode=any update
vk_apt_run "${APT[@]}" install ca-certificates curl gnupg python3 python3-cryptography dnsutils jq iproute2 openssl
cat > "$LIB/node_helper.py" <<'PY_HELPER'
#!/usr/bin/env python3
"""VKarmani 2.5.2: node-only installer. No panel API, credentials or POST requests.
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
REALITY_EXPORT = Path('/root/reality-keys.txt')
MODE = 'secret-key-only'
PROFILE_MIN_CLIENT_VERSION = '0.0.0'
PROFILE_FLOW = 'xtls-rprx-vision'

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
    # Remnawave fills clients dynamically. New templates use the agreed common
    # Vision flow; this generator never writes a live panel/node configuration.
    profile = {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': ['1.1.1.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [{'tag': tag, 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                      'settings': {'clients': [], 'decryption': 'none', 'flow': PROFILE_FLOW},
                      'sniffing': {'enabled': True, 'routeOnly': True,
                                   'destOverride': ['http', 'tls', 'quic']},
                      'streamSettings': {
                          'network': 'raw', 'security': 'reality',
                          'realitySettings': {'show': False, 'target': '/dev/shm/nginx.sock',
                                              'xver': 1, 'minClientVer': PROFILE_MIN_CLIENT_VERSION, 'spiderX': '/',
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

def _profile_tag(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and all(ord(c) >= 32 for c in value)


def _profile_api(profile, inbounds):
    """Recognize only the local RemnaNode service API, never an extra VPN entry.

    Xray creates the outbound from api.tag; it is not in the ordinary outbounds.
    This checks a supplied JSON snapshot, not a live socket or panel entitlement.
    """
    api = profile.get('api')
    extra = [i for i in inbounds if i.get('protocol') != 'vless']
    if api is None and not extra:
        return None, None
    if not isinstance(api, dict) or not _profile_tag(api.get('tag')):
        raise Failure('PROFILE_SERVICE_API_REQUIRES_VALID_API_TAG')
    if api.get('listen') or len(extra) != 1:
        raise Failure('PROFILE_SERVICE_API_REQUIRES_ONE_LOCAL_INBOUND')
    item = extra[0]
    listen = item.get('listen')
    local = (isinstance(listen, str) and bool(re.fullmatch(r'@xtls-api-[A-Za-z0-9_-]{1,80}', listen)))
    local = local or (listen == '127.0.0.1' and type(item.get('port')) is int
                      and 1 <= item['port'] <= 65535)
    if (item.get('tag') != 'REMNAWAVE_API_INBOUND'
            or item.get('protocol') not in ('tunnel', 'dokodemo-door') or not local):
        raise Failure('PROFILE_UNREVIEWED_EXTRA_INBOUND')
    services = api.get('services')
    if not isinstance(services, list) or not services or not all(_profile_tag(x) for x in services):
        raise Failure('PROFILE_SERVICE_API_SERVICES_INVALID')
    return api['tag'], item['tag']


def _profile_network_policy(profile, api_tag, api_inbound, inbound_tags):
    """Structural IPv4/routing checks, NOT an end-to-end egress security audit."""
    dns = profile.get('dns')
    if not isinstance(dns, dict) or dns.get('queryStrategy') != 'UseIPv4':
        raise Failure('PROFILE_DNS_REQUIRES_USE_IPV4')
    servers = dns.get('servers')
    if not isinstance(servers, list) or not servers:
        raise Failure('PROFILE_DNS_SERVERS_MISSING')
    for server in servers:
        if isinstance(server, str) and server:
            continue
        if (not isinstance(server, dict) or not isinstance(server.get('address'), str)
                or not server['address']):
            raise Failure('PROFILE_DNS_SERVER_INVALID')
        if server.get('queryStrategy', 'UseIPv4') != 'UseIPv4':
            raise Failure('PROFILE_DNS_SERVER_REQUIRES_USE_IPV4')
    for key in ('serveStale', 'disableCache', 'enableParallelQuery'):
        if key in dns and type(dns[key]) is not bool:
            raise Failure('PROFILE_DNS_BOOLEAN_INVALID')
    if 'serveExpiredTTL' in dns and (type(dns['serveExpiredTTL']) is not int or dns['serveExpiredTTL'] < 0):
        raise Failure('PROFILE_DNS_EXPIRED_TTL_INVALID')

    outbounds = profile.get('outbounds')
    if not isinstance(outbounds, list) or not outbounds or any(
            not isinstance(o, dict) or o.get('protocol') not in ('freedom', 'blackhole') for o in outbounds):
        raise Failure('PROFILE_UNSUPPORTED_OUTBOUND_REQUIRES_MANUAL_AUDIT')
    tags = [o.get('tag') for o in outbounds]
    if not all(_profile_tag(x) for x in tags) or len(set(tags)) != len(tags) or api_tag in tags:
        raise Failure('PROFILE_OUTBOUND_TAGS_INVALID_OR_DUPLICATE')
    for outbound in outbounds:
        if outbound['protocol'] == 'freedom':
            settings = outbound.get('settings')
            if not isinstance(settings, dict) or settings.get('domainStrategy') != 'UseIPv4':
                raise Failure('PROFILE_FREEDOM_REQUIRES_USE_IPV4')
    routing = profile.get('routing')
    if not isinstance(routing, dict) or routing.get('domainStrategy') not in ('AsIs', 'IPIfNonMatch', 'IPOnDemand'):
        raise Failure('PROFILE_ROUTING_STRATEGY_INVALID')
    rules = routing.get('rules')
    if not isinstance(rules, list) or not rules or routing.get('balancers'):
        raise Failure('PROFILE_ROUTING_RULES_REQUIRED_NO_BALANCERS')
    api_routes = 0
    for rule in rules:
        if not isinstance(rule, dict) or rule.get('type', 'field') != 'field':
            raise Failure('PROFILE_ROUTING_RULE_TYPE_INVALID')
        target = rule.get('outboundTag')
        if not _profile_tag(target) or rule.get('balancerTag') or target not in tags + ([api_tag] if api_tag else []):
            raise Failure('PROFILE_ROUTING_OUTBOUND_REFERENCE_INVALID')
        if not any(k in rule for k in ('domain', 'ip', 'port', 'sourcePort', 'network',
                                       'source', 'user', 'inboundTag', 'protocol', 'attrs')):
            raise Failure('PROFILE_ROUTING_RULE_WITHOUT_MATCH')
        for key in ('domain', 'ip', 'source', 'user', 'inboundTag', 'protocol'):
            if key in rule and (not isinstance(rule[key], list) or not rule[key]
                                or not all(isinstance(x, str) and x for x in rule[key])):
                raise Failure('PROFILE_ROUTING_MATCH_LIST_INVALID')
        if 'inboundTag' in rule and any(x not in inbound_tags for x in rule['inboundTag']):
            raise Failure('PROFILE_ROUTING_INBOUND_REFERENCE_INVALID')
        if api_tag and target == api_tag:
            if rule.get('inboundTag') != [api_inbound] or set(rule) - {'type', 'inboundTag', 'outboundTag'}:
                raise Failure('PROFILE_SERVICE_API_ROUTE_MUST_BE_LOCAL_ONLY')
            api_routes += 1
        elif api_inbound and api_inbound in rule.get('inboundTag', []):
            raise Failure('PROFILE_SERVICE_API_ROUTE_TARGET_INVALID')
    if api_tag and (api_routes != 1 or rules[0].get('outboundTag') != api_tag):
        raise Failure('PROFILE_SERVICE_API_ROUTE_MISSING_OR_NOT_FIRST')


def validate_profile(profile, c):
    """Validate supplied node JSON structure and Selfsteal contract, without mutation.

    Does not test users, engine version, Host overrides, DNS answers or final
    TCP/UDP enforcement. A correct API service inbound is not a second VPN.
    """
    if not isinstance(profile, dict):
        raise Failure('PROFILE_NOT_XRAY_OBJECT')
    inbounds = profile.get('inbounds')
    if not isinstance(inbounds, list) or not inbounds or any(not isinstance(i, dict) for i in inbounds):
        raise Failure('PROFILE_REQUIRES_ONE_VLESS_INBOUND')
    vpn = [i for i in inbounds if i.get('protocol') == 'vless']
    if len(vpn) != 1:
        raise Failure('PROFILE_REQUIRES_ONE_VLESS_INBOUND')
    inbound_tags = [i.get('tag') for i in inbounds]
    if not all(_profile_tag(x) for x in inbound_tags) or len(set(inbound_tags)) != len(inbound_tags):
        raise Failure('PROFILE_INBOUND_TAGS_INVALID_OR_DUPLICATE')
    api_tag, api_inbound = _profile_api(profile, inbounds)
    inbound = vpn[0]
    if type(inbound.get('port')) is not int or inbound['port'] != 443:
        raise Failure('PROFILE_REQUIRES_VLESS_TCP443')
    if inbound.get('listen') not in ('0.0.0.0', c['public_ipv4']):
        raise Failure('PROFILE_REQUIRES_NODE_IPV4_LISTENER')
    sniffing = inbound.get('sniffing')
    if not isinstance(sniffing, dict) or sniffing.get('enabled') is not True or sniffing.get('routeOnly') is not True:
        raise Failure('PROFILE_TORRENT_SNIFFING_POLICY_INVALID')
    dest_override = sniffing.get('destOverride')
    if (not isinstance(dest_override, list) or any(not isinstance(x, str) for x in dest_override)
            or len(dest_override) != 3 or set(dest_override) != {'http', 'tls', 'quic'}):
        raise Failure('PROFILE_TORRENT_SNIFFING_POLICY_INVALID')
    stream = inbound.get('streamSettings')
    if not isinstance(stream, dict) or stream.get('security') != 'reality':
        raise Failure('PROFILE_REQUIRES_RAW_REALITY_NO_OTHER_TRANSPORTS')
    # Inspect both spellings; never let an alias silently select another transport.
    methods = [stream[key] for key in ('network', 'method') if key in stream]
    if not methods or any(value not in ('raw', 'tcp') for value in methods):
        raise Failure('PROFILE_REQUIRES_RAW_REALITY_NO_OTHER_TRANSPORTS')
    sockopt = stream.get('sockopt', {})
    if not isinstance(sockopt, dict) or sockopt.get('acceptProxyProtocol', False) is not False:
        raise Failure('PROFILE_DIRECT_INBOUND_MUST_NOT_REQUIRE_PROXY_PROTOCOL')
    r = stream.get('realitySettings')
    if not isinstance(r, dict):
        raise Failure('PROFILE_REALITY_SETTINGS_MISSING')
    if r.get('serverNames') != [c['domain']]:
        raise Failure('PROFILE_SNI_MUST_EQUAL_THIS_NODE_DOMAIN')
    targets = [r[k] for k in ('target', 'dest') if k in r]
    if not targets or any(value != '/dev/shm/nginx.sock' for value in targets):
        raise Failure('PROFILE_TARGET_MUST_BE_LOCAL_SELFSTEAL_SOCKET')
    if type(r.get('xver')) is not int or r['xver'] != 1:
        raise Failure('PROFILE_SELFSTEAL_REQUIRES_PROXY_V1')
    if r.get('minClientVer') != PROFILE_MIN_CLIENT_VERSION:
        raise Failure('PROFILE_MIN_CLIENT_VER_MUST_BE_0_0_0')
    settings = inbound.get('settings')
    if not isinstance(settings, dict) or settings.get('decryption') != 'none' or settings.get('fallbacks'):
        raise Failure('PROFILE_UNEXPECTED_VLESS_SETTINGS_OR_FALLBACKS')
    if settings.get('flow', '') not in ('', 'xtls-rprx-vision'):
        raise Failure('PROFILE_VLESS_FLOW_INVALID')
    for key in ('clients', 'users'):
        if key in settings:
            if not isinstance(settings[key], list) or any(not isinstance(x, dict) for x in settings[key]):
                raise Failure('PROFILE_VLESS_USERS_INVALID')
            if any(x.get('flow', '') not in ('', 'xtls-rprx-vision') for x in settings[key]):
                raise Failure('PROFILE_VLESS_CLIENT_FLOW_INVALID')
    _profile_network_policy(profile, api_tag, api_inbound, inbound_tags)
    return True


def _profile_object(pairs):
    """Reject ambiguous duplicate fields without echoing any key or value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise Failure('PROFILE_DUPLICATE_JSON_FIELD')
        result[key] = value
    return result


def _profile_nonfinite(_value):
    raise Failure('PROFILE_NONFINITE_JSON_NUMBER')


def audit_profile(path, c):
    # The JSON may contain private keys/users. Never print its contents or errors.
    # O_NONBLOCK avoids hanging on a FIFO; fstat then rejects non-regular input.
    import stat
    limit = 2 * 1024 * 1024
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Failure('PROFILE_INPUT_MUST_BE_REGULAR_FILE')
            data = f.read(limit + 1)
        if len(data) > limit:
            raise Failure('PROFILE_TOO_LARGE_FOR_LOCAL_POLICY_AUDIT')
        profile = json.loads(data.decode('utf-8'), object_pairs_hook=_profile_object,
                             parse_constant=_profile_nonfinite)
    except (OSError, ValueError, UnicodeError) as exc:
        raise Failure('PROFILE_INPUT_READ_OR_JSON_INVALID') from exc
    validate_profile(profile, c)
    print('PROFILE_RAW_REALITY_SELFSTEAL_POLICY=PASS')
    print('PROFILE_IPV4_ROUTING_STRUCTURE=PASS')
    print('SCOPE=SUPPLIED_JSON_ONLY; LIVE_NODE_AND_HOST_OVERRIDES=NOT_VERIFIED; DOMAIN_OWNERSHIP=OPERATOR_RESPONSIBILITY')
    print('EGRESS_ENFORCEMENT=NOT_VERIFIED; CORE_VALIDATION_AND_CLIENT_TEST=NOT_PERFORMED')


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


def export_reality_keys_file(c):
    # Derived convenience copy for the operator. reality.json remains authoritative.
    make_keys_profile(c)
    keys = read_json(ETC / 'reality.json')
    path = REALITY_EXPORT
    if path.exists() or path.is_symlink():
        st = path.lstat()
        if path.is_symlink() or not path.is_file() or st.st_uid != os.geteuid() or (st.st_mode & 0o777) != 0o600:
            raise Failure('/root/reality-keys.txt существует с небезопасным типом/владельцем/правами; не перезаписываю.')
    text = (
        '============================================================\n'
        'REALITY KEYS — VKarmani RemnaNode 2.5.2\n'
        '============================================================\n'
        f'Domain: {c["domain"]}\n'
        f'PrivateKey: {keys["private_key"]}\n'
        f'PublicKey: {keys["public_key"]}\n'
        f'ShortID: {keys["short_id"]}\n'
        'Reality target: /dev/shm/nginx.sock\n'
        'xver: 1\n'
        f'flow: {PROFILE_FLOW}\n'
        f'minClientVer: {PROFILE_MIN_CLIENT_VERSION}\n'
        f'serverName/SNI: {c["domain"]}\n'
    )
    atomic_text(path, text)
    st = path.stat()
    if st.st_uid != os.geteuid() or (st.st_mode & 0o777) != 0o600:
        raise Failure('Не удалось зафиксировать владельца и 0600 для /root/reality-keys.txt.')
    return path


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
                          'selfsteal_host_socket': '/run/vkarmani-selfsteal/nginx.sock',
                          'allow_net_admin': True})
    # DNS already selected this exact local address; recheck once against config shape.
    dns_check(c)
    atomic_text(ETC / 'remnanode.env', f'NODE_PORT={c["node_port"]}\nSECRET_KEY={secret}\nTZ=Europe/Moscow\n')
    atomic_json(ETC / 'config.json', c)
    print('Параметры проверены. IPv4 ноды=' + selected + '; SECRET_KEY сохранён с правами 0600.')

def write_panel_guide(c):
    name, tag, _ = make_keys_profile(c)
    keys = read_json(ETC / 'reality.json')
    txt = f'''VKarmani RemnaNode 2.5.2 — действия в панели

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
5. Node Plugins настраиваются вручную в Panel; installer не использует Panel API.
   Рекомендуемый baseline: Ingress Filter=enabled, blockedIps=[ext:vkarmani_ingress_blocklist];
   Egress Filter=enabled, blockedIps=[], blockedPorts=[25,137,138,139,445,465,587,2525];
   Torrent Blocker=enabled, ignoreLists.ip=[], blockDuration=3600;
   Connection Drop=enabled, whitelistIps=[].
   Shared List vkarmani_ingress_blocklist: type=ipList, items=[].
   vkarmani_nonpublic_ipv4 — только reference; НЕ подключайте её в Egress blockedIps по умолчанию.

Шаблон: VLESS + RAW + REALITY + Vision (settings.flow=xtls-rprx-vision).
REALITY target: /dev/shm/nginx.sock; xver=1 (PROXY protocol v1); minClientVer={PROFILE_MIN_CLIENT_VERSION}.
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
    parser.add_argument('action', choices=['init', 'get', 'dns', 'keys', 'reality-export', 'secret', 'docker-config', 'panel-guide', 'control-ready', 'image', 'allow-net-admin', 'weekly-reboot', 'profile-check'])
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
    elif args.action == 'reality-export':
        print(export_reality_keys_file(c))
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
# NET_ADMIN is a reviewed modern default/requirement; persist it on new/resumed current installs.
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
vk_write_time_helper
TIME_HELPER="$LIB/time_helper.py"
TIME_SERVICE=$(python3 "$TIME_HELPER" select)
# Preserve an installed supported NTP provider. --no-remove remains active for
# BOTH the simulation and actual transaction; no whitelist/removal exception.
NODE_PACKAGES=(openssh-server ufw fail2ban nginx certbot "$TIME_SERVICE" logrotate unattended-upgrades
    ethtool kmod util-linux procps dbus python3-systemd nftables)
DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
vk_setup_docker_repository
# Fail before changing access/boot if this release has no signed package candidates.
vk_apt_run "${APT[@]}" --simulate install "${NODE_PACKAGES[@]}" "${DOCKER_PACKAGES[@]}"
printf 'TIME_PROVIDER=%s; системные NTP-пакеты не заменяются.\n' "$TIME_SERVICE"
vk_apt_run "${APT[@]}" install "${NODE_PACKAGES[@]}"
command -v nft >/dev/null || die 'Пакет nftables установлен, но команда nft недоступна.'
timeout --foreground 5s nft --version >/dev/null || die 'nftables CLI не проходит локальную проверку версии.'
ensure_sshd_runtime
[[ $(python3 "$TIME_HELPER" select) == "$TIME_SERVICE" ]] || die 'NTP provider изменился во время APT; останавливаюсь.'

vk_write_ssh_guard
python3 -I -B -S "$LIB/ssh_guard.py" preflight --user "$LOGIN_USER"

stage 'MSK, синхронизация времени и ограничение журналов'
timedatectl set-timezone Europe/Moscow
if [[ "$TIME_SERVICE" == chrony ]]; then
# Preserve sources.d/conf.d, NTS bootstrap trust and provider configuration.
# The managed addition disables server/control UDP ports; the daemon uses IPv4.
if ! systemctl cat chrony.service | _contains 'DAEMON_OPTS'; then
    die 'Неизвестный chrony unit: параметр DAEMON_OPTS не поддерживается.'
fi
vk_write_chrony_config_helper
python3 "$LIB/chrony_config.py"
systemctl enable --now chrony
systemctl restart chrony
else
    # Keep the distro/provider's NTP sources. Only restrict the daemon's socket
    # families, without rewriting timesyncd.conf or replacing its package.
    install -d -m 0755 /etc/systemd/system/systemd-timesyncd.service.d
    cat > /etc/systemd/system/systemd-timesyncd.service.d/90-vkarmani-ipv4.conf <<'VK_TIMESYNCD_IPV4'
[Service]
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET
VK_TIMESYNCD_IPV4
    systemctl daemon-reload
    systemctl enable --now systemd-timesyncd.service
    systemctl restart systemd-timesyncd.service
    TIME_FAMILIES=$(systemctl show systemd-timesyncd.service -p RestrictAddressFamilies --value)
    [[ "$TIME_FAMILIES" == 'AF_UNIX AF_INET' || "$TIME_FAMILIES" == 'AF_INET AF_UNIX' ]] || die 'timesyncd IPv4-only policy не применена.'
fi
python3 "$TIME_HELPER" wait --provider "$TIME_SERVICE" --seconds 120
python3 "$TIME_HELPER" save "$TIME_SERVICE"
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

# Enforce password-only SSH without deleting accounts/passwords/authorized_keys files. Convert socket activation to an IPv4
# ssh.service, whose KillMode=process preserves established SSH child sessions.
ensure_sshd_runtime
[[ "$(systemctl show ssh.service -p KillMode --value)" == process ]] || die 'SSH unit KillMode не process; безопасное переключение не подтверждено.'
# Password-only admission has already been checked; do not preserve key login.
python3 -I -B -S "$LIB/ssh_guard.py" preflight --user "$LOGIN_USER"
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
import os
import stat
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
             'AuthenticationMethods password\nPubkeyAuthentication no\n'
             'KbdInteractiveAuthentication no\nHostbasedAuthentication no\nGSSAPIAuthentication no\n'
             'LoginGraceTime 30\nMaxAuthTries 5\nMaxStartups 10:30:60\nUseDNS no\n'
             + extra + END + '\n')
    return block + text


def main():
    path = Path('/etc/ssh/sshd_config')
    ports = Path('/etc/vkarmani-node/ssh-ports').read_text().split()
    current = subprocess.check_output(['/usr/sbin/sshd', '-T'], text=True, timeout=10)
    existing = set(re.findall(r'^port ([0-9]+)$', current, re.M))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as src:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('unsafe sshd_config; not overwritten')
        original = src.read(1048577)
    if len(original) > 1048576:
        raise ValueError('sshd_config too large; not overwritten')
    result = render_ssh(original.decode('utf-8'), ports, existing)
    import tempfile
    fd, name = tempfile.mkstemp(prefix='.sshd_config.vkarmani.', dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(result)
            f.flush()
            os.fsync(f.fileno())
        subprocess.run(['/usr/sbin/sshd', '-t', '-f', str(tmp)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
        actual = subprocess.check_output(['/usr/sbin/sshd', '-T', '-f', str(tmp)], text=True, timeout=10)
        required = ('passwordauthentication yes', 'pubkeyauthentication no',
                    'authenticationmethods password', 'kbdinteractiveauthentication no',
                    'permitemptypasswords no', 'addressfamily inet')
        if not all(x in actual.splitlines() for x in required):
            raise ValueError('candidate SSH password-only policy not effective')
        tmp.replace(path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
PY_SSH_CONFIG
ensure_sshd_runtime
/usr/sbin/sshd -t
SSH_EFFECTIVE=$(/usr/sbin/sshd -T)
for expected in 'passwordauthentication yes' 'permitrootlogin yes' 'permitemptypasswords no' 'authenticationmethods password' 'pubkeyauthentication no' 'kbdinteractiveauthentication no' 'hostbasedauthentication no' 'gssapiauthentication no' 'addressfamily inet'; do
    printf '%s\n' "$SSH_EFFECTIVE" | _contains -Fx "$expected" || die "Не применена SSH-политика: $expected"
done
printf '%s\n' "$SSH_EFFECTIVE" | _contains -Fx 'pubkeyauthentication no' || die 'SSH public-key login must be disabled.'
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
# Repository/candidates were validated before SSH/UFW/GRUB changes.
vk_apt_run "${APT[@]}" install "${DOCKER_PACKAGES[@]}"
helper docker-config
dockerd --validate --config-file=/etc/docker/daemon.json
systemctl enable docker.service containerd.service
systemctl restart docker
[[ $(docker network inspect bridge --format '{{.EnableIPv6}}') == false ]] || die 'Docker bridge IPv6 включён.'
systemctl restart vkarmani-node-network.service

stage "Nginx + Let's Encrypt + изолированный Selfsteal socket для VLESS RAW REALITY"
NGINX_NUM=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')
[[ "$NGINX_NUM" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Не удалось определить версию Nginx.'
NGINX_BUILD=$(nginx -V 2>&1)
[[ "$NGINX_BUILD" == *--with-http_ssl_module* && "$NGINX_BUILD" == *--with-http_v2_module* ]] || die 'Nginx должен поддерживать TLS и HTTP/2.'
NGINX_HTTP2_LISTEN='http2'
NGINX_HTTP2_DIRECTIVE=''
NGINX_REJECT_HANDSHAKE_DIRECTIVE=''
if dpkg --compare-versions "$NGINX_NUM" ge 1.19.4; then
    NGINX_REJECT_HANDSHAKE_DIRECTIVE='ssl_reject_handshake on;'
else
    echo 'SELFSTEAL_SNI_REJECT=UNAVAILABLE_LEGACY_NGINX; HTTP Host guard remains active.'
fi
if dpkg --compare-versions "$NGINX_NUM" ge 1.25.1; then
    NGINX_HTTP2_LISTEN=''
    NGINX_HTTP2_DIRECTIVE='http2 on;'
fi
install -d -m 0750 -o root -g root /run/vkarmani-selfsteal
cat > /etc/tmpfiles.d/vkarmani-selfsteal.conf <<'EOF'
# Created during sysinit before Docker; no dependency on Nginx or external DNS.
d /run/vkarmani-selfsteal 0750 root root -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/vkarmani-selfsteal.conf
install -d -m 0755 /var/www/vkarmani-node/acme /var/www/vkarmani-node/site /var/www/vkarmani-node/site/assets
vk_write_site_tool
python3 "$LIB/site_tool.py" install
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
# Dedicated node only. Unknown Host must not redirect to a user supplied host.
server {
    listen $PUBLIC_IP:80 default_server;
    server_name _;
    access_log off;
    return 404;
}
server {
    listen $PUBLIC_IP:80;
    server_name $DOMAIN;
    server_tokens off;
    access_log off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    send_timeout 15s;
    if (\$host != $DOMAIN) { return 404; }
    if (\$request_method !~ ^(GET|HEAD)\$) { return 405; }
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/vkarmani-node/acme;
        default_type text/plain;
        disable_symlinks on from=\$document_root;
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
cat > /etc/nginx/conf.d/20-vkarmani-selfsteal.conf <<EOF
# Selfsteal is the local REALITY target, not a TLS-terminating VPN frontend.
# On supported Nginx, reject unknown / absent SNI before certificate disclosure.
# Legacy packages retain an explicit HTTP refusal, not equivalent TLS protection.
server {
    listen unix:/run/vkarmani-selfsteal/nginx.sock ssl $NGINX_HTTP2_LISTEN proxy_protocol default_server;
    $NGINX_HTTP2_DIRECTIVE
    server_name _;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    $NGINX_REJECT_HANDSHAKE_DIRECTIVE
    access_log off;
    return 421;
}
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
    send_timeout 15s;
    keepalive_timeout 65s;
    max_ranges 1;
    disable_symlinks on from=\$document_root;
    if (\$host != $DOMAIN) { return 421; }
    if (\$request_method !~ ^(GET|HEAD)\$) { return 405; }
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    # No child add_header: preserve parent security headers on older Nginx.
    location = / { try_files /index.html =404; expires -1; }
    location = /index.html { try_files \$uri =404; expires -1; }
    location = /robots.txt { try_files \$uri =404; expires -1; }
    location = /favicon.svg { try_files \$uri =404; expires -1; }
    location = /404.html { internal; try_files \$uri =404; expires -1; }
    location ~ "^/assets/(style-[0-9a-f]{20}[.]css|icon-[0-9a-f]{20}[.]svg)\$" {
        try_files \$uri =404;
        expires 7d;
    }
    error_page 404 /404.html;
    location / { return 404; }
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
    if [[ -S /run/vkarmani-selfsteal/nginx.sock ]] && timeout --kill-after=2s "${budget}s" /usr/local/sbin/vkarmani-selfsteal-check --target-only >/dev/null 2>&1; then
        exit 0
    fi
    (( SECONDS >= 60 )) || sleep 1
done
echo 'SELFSTEAL_NOT_READY: 60-second budget exhausted; check nginx, socket and loaded certificate.' >&2
exit 1
WAITSELF
chmod 0755 /usr/local/sbin/vkarmani-wait-selfsteal
vk_write_cert_deploy
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx <<'EOF'
#!/bin/sh
set -eu
exec /usr/bin/python3 -I -B -S /usr/local/lib/vkarmani-node/cert_deploy.py deploy
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/30-vkarmani-nginx
systemctl enable --now certbot.timer
if [[ $(helper get certbot_dry_run) == true ]] && ! grep -Fx 'deploy_hook=pass' "$STATE/certbot-dry-run-pass" >/dev/null 2>&1; then
    DEPLOY_BEFORE=$(python3 -I -B -S "$LIB/cert_deploy.py" generation)
    certbot renew --cert-name "$DOMAIN" --dry-run --run-deploy-hooks --non-interactive
    python3 -I -B -S "$LIB/cert_deploy.py" verify-new "$DEPLOY_BEFORE"
    printf 'deploy_hook=pass\nat=%s\n' "$(date -Is)" > "$STATE/certbot-dry-run-pass"
    unset DEPLOY_BEFORE
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
echo 'INFO: NET_ADMIN включён по умолчанию для функций Remnawave, которым нужен доступ к сетевому состоянию хоста.'
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
    cap_add:
      - NET_ADMIN
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
python3 /usr/local/lib/vkarmani-node/apt_clean.py
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
vk_write_apt_clean_helper
vk_write_resources_helper
vk_write_acceptance
vk_write_maintenance
cat > /etc/systemd/system/vkarmani-node-postboot.service <<EOF
[Unit]
Description=VKarmani node post-boot acceptance
Wants=network-online.target docker.service nginx.service ${TIME_SERVICE}.service fail2ban.service vkarmani-node-network.service ufw.service
After=network-online.target docker.service nginx.service ${TIME_SERVICE}.service fail2ban.service vkarmani-node-network.service ufw.service
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
python3 /usr/local/lib/vkarmani-node/apt_clean.py
/usr/local/sbin/vkarmani-node-check --preboot
helper reality-export >/dev/null
[[ -f "$REALITY_KEYS_FILE" && ! -L "$REALITY_KEYS_FILE" && $(stat -c '%a' "$REALITY_KEYS_FILE") == 600 ]] || die 'Файл REALITY-ключей должен быть regular 0600.'
printf 'version=%s\nat=%s\nimage=%s\n' "$INSTALLER_VERSION" "$(date -Is)" "$DIGEST" > "$STATE/INSTALL_COMPLETE"
rm -f "$STATE/INSTALL_FAILED" "$STATE/RESUME_FAILED" "$STATE/image-update-pending"
stage 'Установка завершена; проверки ДО перезагрузки пройдены'
printf 'Домен: %s\nIPv4: %s\nУправляющий порт: %s (только IP панели)\n' "$DOMAIN" "$PUBLIC_IP" "$NODE_PORT"
printf 'Разрешённые IPv4 панели: %s\n' "${PANEL_IPS[*]}"
printf 'Внешний firewall хостера (если есть): разрешить TCP/%s от %s к Node Address, указанному в панели.\n' "$NODE_PORT" "${PANEL_IPS[*]}"
printf 'Транспорт: VLESS + RAW + REALITY + Vision; Selfsteal: /dev/shm/nginx.sock (xver=1)\n'
printf 'Профиль и действия в панели: /etc/vkarmani-node/PANEL-SETUP.txt\n'
printf 'REALITY_KEYS_FILE: %s (root:0600; PrivateKey не записывается в install log)\n' "$REALITY_KEYS_FILE"
printf 'SSH-порты сохранены: %s\n' "${SSH_PORTS[*]}"
printf 'Проверка после входа: sudo vkarmani-node-check\nЖурнал: /var/log/vkarmani-node-postboot.log\n'
printf 'Резервная копия: %s\nПолное отключение IPv6 проверяется ПОСЛЕ загрузки нового ядра.\n' "$BK"
if [[ $WEEKLY_REBOOT -eq 1 ]]; then
    systemctl list-timers --no-pager vkarmani-weekly-reboot.timer
else
    echo 'WEEKLY_REBOOT=DISABLED; timers Certbot and cleanup were checked separately.'
fi

# The operator explicitly requested the three REALITY values at the end. Bypass tee so
# PrivateKey is visible on the interactive terminal but is not duplicated into install.log.
if [[ -r "$REALITY_KEYS_FILE" && -w /dev/tty ]]; then
    {
        printf '\n'
        cat "$REALITY_KEYS_FILE"
        printf 'Saved securely: %s (root:0600)\n\n' "$REALITY_KEYS_FILE"
    } > /dev/tty
else
    echo "REALITY_KEYS_DISPLAY=SKIPPED_NO_TTY; сохранены в $REALITY_KEYS_FILE (root:0600)."
fi

if [[ $NO_REBOOT -eq 0 ]]; then
    # Scheduled by systemd rather than a background shell; survives SSH closure.
    sync
    if systemd-run --collect --unit="vkarmani-install-reboot-$(date +%s)" --on-active=30s /usr/bin/systemctl reboot; then
        echo 'AUTO_REBOOT=ARMED delay=30s. SSH отключится; после загрузки все настроенные службы запустятся автоматически.'
    else
        reboot_rc=$?
        echo "AUTO_REBOOT=FAILED rc=$reboot_rc; установка уже завершена, выполните sudo reboot вручную." >&2
    fi
else
    echo 'AUTO_REBOOT=DISABLED_BY_FLAG. Выполните sudo reboot после проверки второго парольного SSH-входа.'
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
    BK="$STATE/backups/repair-2.5.2-$(date +%Y%m%d-%H%M%S)-$$"
    install -d -m 0700 "$BK"
    local -a paths=(
        /usr/local/lib/vkarmani-node/time_helper.py
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
    echo 'VKarmani 2.5.2 — исправление только на НОДЕ'
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
    printf 'version=2.5.2\nat=%s\n' "$(date -Is)" > "$STATE/REPAIR_COMPLETE"
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
    local bk="$state/backups/network-2.5.2-$(date +%Y%m%d-%H%M%S)-$$"
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
    echo 'VKarmani 2.5.2 — исправление применения sysctl после отключения IPv6'
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
    printf 'version=2.5.2\nat=%s\n' "$(date -Is)" > "$state/NETWORK_REPAIR_COMPLETE"
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


vkarmani_repair_acceptance_main() {
    set -Eeuo pipefail
    set +x
    umask 077
    export LC_ALL=C LANG=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    [[ $# -eq 0 ]] || { echo 'Использование: bash install.sh --repair-acceptance'; return 2; }
    [[ $EUID -eq 0 ]] || { echo 'Запустите --repair-acceptance от root.' >&2; return 1; }

    local state=/var/lib/vkarmani-node
    local lib=/usr/local/lib/vkarmani-node
    local checker=/usr/local/sbin/vkarmani-node-check
    local plugin="$lib/node_plugins.py"
    local time_helper="$lib/time_helper.py"
    local base_version=2.5.0
    local repair_version=2.5.2
    local old_checker_sha=affb9c5b282d09156ad8eaa304606870698eea12c6f1f54c9e7e36e1c71f789e
    local old_plugin_sha=5e7b09208c07e1121370fd69d0c97d2ca37b2a8c86eb3a0ace0376eb63044fe6
    local old_time_sha=2c4ee1fba63649d35f5e0ee164e8598eda05da725c95b7bbcfd7a91697971cbc

    command -v flock >/dev/null || { echo 'STOP: util-linux/flock отсутствует.' >&2; return 1; }
    command -v sha256sum >/dev/null || { echo 'STOP: sha256sum отсутствует.' >&2; return 1; }
    command -v docker >/dev/null || { echo 'STOP: Docker отсутствует.' >&2; return 1; }
    install -d -m 0755 /run/lock
    exec 8>/run/lock/vkarmani-node-installer.lock
    flock -n 8 || { echo 'STOP: installer/repair уже запущен.' >&2; return 1; }

    [[ -d "$state" && ! -L "$state" ]] || { echo 'STOP: state directory отсутствует или небезопасен.' >&2; return 1; }
    [[ -f "$state/owned-installation" && ! -L "$state/owned-installation" ]] || { echo 'STOP: это не project-owned installation.' >&2; return 1; }
    [[ -s "$state/install-version" && $(cat "$state/install-version") == "$base_version" ]] || {
        echo 'STOP: --repair-acceptance разрешён только для известного незавершённого 2.5.0.' >&2; return 1;
    }
    [[ ! -e "$state/INSTALL_COMPLETE" ]] || { echo 'STOP: завершённые установки этим repair не мигрируются.' >&2; return 1; }
    [[ -f "$state/INSTALL_FAILED" && ! -L "$state/INSTALL_FAILED" ]] || { echo 'STOP: INSTALL_FAILED отсутствует.' >&2; return 1; }
    grep -Eq '^rc=1 line=6412 at=[^[:space:]]+$' "$state/INSTALL_FAILED" || {
        echo 'STOP: failure checkpoint не соответствует известному final-acceptance bug 2.5.0.' >&2; return 1;
    }
    for marker in network-rollback-armed network-rollback-running image-update-pending; do
        [[ ! -e "$state/$marker" ]] || { echo "STOP: найден $marker; сначала разберите незавершённую транзакцию." >&2; return 1; }
    done
    [[ ! -e /root/reality-keys.txt ]] || {
        echo 'STOP: /root/reality-keys.txt уже существует; repair не будет перезаписывать операторский/неизвестный файл.' >&2; return 1;
    }
    for path in "$checker" "$plugin" "$time_helper" /usr/local/lib/vkarmani-node/node_helper.py \
                /etc/vkarmani-node/config.json /opt/vkarmani-node/compose.yaml "$state/image-digest"; do
        [[ -f "$path" && ! -L "$path" ]] || { echo "STOP: отсутствует ожидаемый regular file: $path" >&2; return 1; }
        [[ $(stat -c '%u' "$path") -eq 0 ]] || { echo "STOP: неверный owner: $path" >&2; return 1; }
    done
    [[ $(sha256sum "$checker" | awk '{print $1}') == "$old_checker_sha" ]] || {
        echo 'STOP: установленный checker не совпадает с известным 2.5.0; не перезаписываю.' >&2; return 1;
    }
    [[ $(sha256sum "$plugin" | awk '{print $1}') == "$old_plugin_sha" ]] || {
        echo 'STOP: node_plugins.py не совпадает с известным 2.5.0; не перезаписываю.' >&2; return 1;
    }
    [[ $(sha256sum "$time_helper" | awk '{print $1}') == "$old_time_sha" ]] || {
        echo 'STOP: time_helper.py не совпадает с известным 2.5.0; не перезаписываю.' >&2; return 1;
    }
    [[ $(docker inspect remnanode --format '{{.State.Running}}' 2>/dev/null) == true ]] || {
        echo 'STOP: remnanode не запущен; это уже не узкий acceptance-only случай.' >&2; return 1;
    }

    local bk="$state/backups/acceptance-2.5.2-$(date +%Y%m%d-%H%M%S)-$$"
    install -d -m 0700 "$bk"
    cp -a "$checker" "$plugin" "$time_helper" "$bk/"
    (cd "$bk" && sha256sum vkarmani-node-check node_plugins.py time_helper.py > MANIFEST.sha256 && sha256sum --check --quiet MANIFEST.sha256)

    local tmp_checker tmp_plugin tmp_time
    tmp_checker=$(mktemp /usr/local/sbin/.vkarmani-node-check.2.5.2.XXXXXXXX)
    tmp_plugin=$(mktemp "$lib/.node_plugins.py.2.5.2.XXXXXXXX")
    tmp_time=$(mktemp "$lib/.time_helper.py.2.5.2.XXXXXXXX")
    local committed=0 receipt_committed=0
    vk_acceptance_repair_rollback() {
        local rc=${1:-1}
        set +e
        rm -f "$tmp_checker" "$tmp_plugin" "$tmp_time"
        if [[ "$committed" -eq 0 ]]; then
            cp -a "$bk/vkarmani-node-check" "$checker"
            cp -a "$bk/node_plugins.py" "$plugin"
            cp -a "$bk/time_helper.py" "$time_helper"
            rm -f /root/reality-keys.txt
            [[ "$receipt_committed" -eq 0 ]] || rm -f "$state/ACCEPTANCE_REPAIR_2_5_2"
        fi
        return "$rc"
    }
    trap 'rc=$?; trap - ERR INT TERM HUP; vk_acceptance_repair_rollback "$rc"; exit "$rc"' ERR INT TERM HUP

    LIB="$lib" vk_write_acceptance "$tmp_checker" "$tmp_plugin" "$tmp_time"
    bash -n "$tmp_checker"
    python3 - "$tmp_plugin" "$tmp_time" <<'PY_REPAIR_COMPILE'
from pathlib import Path
import sys
for name in sys.argv[1:]:
    compile(Path(name).read_text(), name, 'exec')
PY_REPAIR_COMPILE

    # Helpers first, checker last: there is no instant where a new checker sees an old parser.
    mv -f -- "$tmp_time" "$time_helper"
    mv -f -- "$tmp_plugin" "$plugin"
    mv -f -- "$tmp_checker" "$checker"
    chown root:root "$checker" "$plugin" "$time_helper"
    chmod 0755 "$checker"
    chmod 0700 "$plugin" "$time_helper"

    echo 'ACCEPTANCE_REPAIR_FILES=INSTALLED; running read-only preboot acceptance'
    "$checker" --preboot
    /usr/local/lib/vkarmani-node/node_helper.py reality-export >/dev/null
    [[ -f /root/reality-keys.txt && ! -L /root/reality-keys.txt && $(stat -c '%u:%a' /root/reality-keys.txt) == 0:600 ]] || {
        echo 'STOP: reality export post-check failed.' >&2; return 1;
    }

    local digest
    digest=$(cat "$state/image-digest")
    [[ "$digest" =~ ^(remnawave/node|ghcr\.io/remnawave/node)@sha256:[a-f0-9]{64}$ ]] || {
        echo 'STOP: image-digest повреждён.' >&2; return 1;
    }
    local receipt_tmp complete_tmp
    receipt_tmp=$(mktemp "$state/.ACCEPTANCE_REPAIR_2_5_2.XXXXXXXX")
    complete_tmp=$(mktemp "$state/.INSTALL_COMPLETE.XXXXXXXX")
    printf 'source_version=%s\nrepair_version=%s\nat=%s\nbackup=%s\n' \
        "$base_version" "$repair_version" "$(date -Is)" "$bk" > "$receipt_tmp"
    printf 'version=%s\nat=%s\nimage=%s\n' "$base_version" "$(date -Is)" "$digest" > "$complete_tmp"
    chmod 0600 "$receipt_tmp" "$complete_tmp"
    mv -f -- "$receipt_tmp" "$state/ACCEPTANCE_REPAIR_2_5_2"
    receipt_committed=1
    mv -f -- "$complete_tmp" "$state/INSTALL_COMPLETE"
    committed=1
    rm -f "$state/INSTALL_FAILED" "$state/RESUME_FAILED"
    trap - ERR INT TERM HUP

    echo "ACCEPTANCE_REPAIR=PASS source=$base_version repair=$repair_version backup=$bk"
    echo 'INSTALL_COMPLETE=PASS; исходная install-version сохранена как 2.5.0.'
    echo 'AUTO_REBOOT=NOT_PERFORMED_BY_REPAIR; выполните один обычный reboot после проверки доступа к консоли/SSH.'
}

# VKARMANI_COMPLETE_PAYLOAD_2_1_1
# Sourcing definitions is intentionally inert: used by offline regression tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --update-cover) shift; vkarmani_site_main update "$@" ;;
        --rollback-cover) shift; vkarmani_site_main rollback "$@" ;;
        --diagnose-resources) shift; vkarmani_resources_main "$@" ;;
        --repair-network) shift; vkarmani_repair_network_main "$@" ;;
        --repair-node) shift; vkarmani_repair_main "$@" ;;
        --repair-acceptance) shift; vkarmani_repair_acceptance_main "$@" ;;
        --check)
            shift
            [[ -x /usr/local/sbin/vkarmani-node-check ]] || { echo 'Сначала установите ноду.'; exit 1; }
            exec /usr/local/sbin/vkarmani-node-check "$@"
            ;;
        --backup|--refresh-image|--rollback-image)
            ACTION=${1#--}; shift
            [[ -x /usr/local/sbin/vkarmani-node-maintain ]] || { echo 'Нужна завершённая установка 2.1.x. Старые ноды автоматически не мигрируются.'; exit 1; }
            exec /usr/local/sbin/vkarmani-node-maintain "$ACTION" "$@"
            ;;
        *) vkarmani_main "$@" ;;
    esac
fi
