#!/usr/bin/env python3
"""Bounded, read-only HTTPS cover diagnostics for an explicitly owned endpoint.

No REALITY credentials, active protocol attacks, port enumeration, proxy use,
network tracing or changes to the host. Each run makes a fixed small number of
ordinary HTTP/TLS connections to exactly the supplied public IP and ports.
Observations are NOT proof of resistance to DPI or active fingerprinting.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
import statistics
import re
import socket
import ssl
import subprocess
import sys
import time

DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
STATUS = re.compile(rb'^HTTP/1\.[01] ([1-5][0-9]{2})(?:\s|\r\n)')
MAX_HEADERS = 16384
TIMEOUT = 4
MAX_PARALLEL = 4  # at most four ordinary TLS dials to the operator-owned endpoint
CURL_TIMEOUT = 12
CURL_RESULT = re.compile(rb'^VK_H2:([0123](?:\.[0-9])?):([1-5][0-9]{2})\Z')
CURL_LARGE_RESULT = re.compile(rb'^VK_LARGE:([0123](?:\.[0-9])?):([1-5][0-9]{2}):([0-9]{1,9})(?:\.0+)?\Z')
MAX_STATIC_BYTES = 262144


class AuditError(ValueError):
    pass


def validated_target(domain, address):
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain) or domain.lower() != domain:
        raise AuditError('INVALID_DOMAIN')
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise AuditError('INVALID_IP') from None
    # The test should never be redirected towards internal services, even if
    # the operator mistypes the address or supplies a split-horizon hostname.
    if ip.version != 4 or not ip.is_global:
        raise AuditError('PUBLIC_IPV4_REQUIRED')
    return domain, str(ip)


def dns_snapshot(domain, address):
    try:
        items = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, TimeoutError):
        return {'status': 'UNVERIFIED', 'reason': 'DNS_LOOKUP_UNAVAILABLE'}
    v4 = {entry[4][0] for entry in items if entry[0] == socket.AF_INET}
    v6 = {entry[4][0] for entry in items if entry[0] == socket.AF_INET6}
    return {
        'status': 'PASS' if address in v4 and not v6 else 'REVIEW',
        'ipv4_includes_target': address in v4,
        'ipv6_records_present': bool(v6),
        'reason': ('IPV6_NEEDS_SEPARATE_ROUTING_REVIEW' if v6 else
                   'TARGET_NOT_IN_DNS_A' if address not in v4 else 'NONE'),
    }


def _context(*, verified, version=None, offer_h2=False):
    if verified:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
    else:
        # Negative tests only: inspect whether unrecognized SNI is rejected.
        # Never use this context to declare that a valid hostname is secure.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if version:
        ctx.minimum_version = version
        ctx.maximum_version = version
    ctx.set_alpn_protocols(['h2', 'http/1.1'] if offer_h2 else ['http/1.1'])
    return ctx


def _tls_request(address, domain, *, sni, method=None, path='/', host=None,
                 version=None, offer_h2=False, verified=True, timeout=TIMEOUT):
    """Return redacted TLS/HTTP metadata. No certificate bytes or headers leak."""
    ctx = _context(verified=verified, version=version, offer_h2=offer_h2)
    start = time.monotonic()
    with socket.create_connection((address, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            tls.settimeout(timeout)
            out = {'tls': tls.version(), 'alpn': tls.selected_alpn_protocol(),
                   'cipher': tls.cipher()[0] if tls.cipher() else None,
                   'elapsed_ms': round((time.monotonic() - start) * 1000)}
            if method is None:
                return out
            # Only send HTTP/1.1 when that protocol was offered alone.
            if offer_h2:
                raise AuditError('H2_NEGOTIATED_WITH_HTTP1_REQUEST')
            request = (f'{method} {path} HTTP/1.1\r\nHost: {host or domain}\r\n'
                       'Accept: text/html\r\nConnection: close\r\n\r\n').encode('ascii')
            tls.sendall(request)
            head = b''
            while b'\r\n\r\n' not in head and len(head) < MAX_HEADERS:
                chunk = tls.recv(min(2048, MAX_HEADERS - len(head)))
                if not chunk:
                    break
                head += chunk
            match = STATUS.match(head)
            if not match or b'\r\n\r\n' not in head:
                raise AuditError('INVALID_HTTP_RESPONSE')
            out['http_code'] = int(match.group(1))
            # Do not return header values: Location/Set-Cookie can be sensitive.
            head_names = {line.partition(b':')[0].lower() for line in head.split(b'\r\n')[1:]
                          if b':' in line}
            out['security_headers'] = all(x in head_names for x in
                                           (b'content-security-policy', b'x-content-type-options'))
            return out


def _http_redirect(address, domain, *, timeout=TIMEOUT):
    with socket.create_connection((address, 80), timeout=timeout) as raw:
        raw.settimeout(timeout)
        raw.sendall(f'GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode('ascii'))
        data = b''
        while b'\r\n\r\n' not in data and len(data) < MAX_HEADERS:
            chunk = raw.recv(min(2048, MAX_HEADERS - len(data)))
            if not chunk:
                break
            data += chunk
        match = STATUS.match(data)
        if not match or b'\r\n\r\n' not in data:
            raise AuditError('INVALID_HTTP80_RESPONSE')
        # Exact allowlisted redirect only. Never follow redirects or contacts.
        location = next((line.split(b':', 1)[1].strip() for line in data.split(b'\r\n')
                         if line.lower().startswith(b'location:')), b'')
        return {'http_code': int(match.group(1)),
                'redirect_to_expected_https': location == f'https://{domain}/'.encode('ascii')}



def _port(value, *, excluded=()):
    if type(value) is not int or not 1 <= value <= 65535 or value in excluded:
        raise AuditError('INVALID_EXPLICIT_PORT')
    return value


def http2_request(domain, address, *, socks_port=None, run=subprocess.run):
    """One REAL HTTP/2 GET to the owned HTTPS cover using curl, if available.

    Curl is invoked without a config, shell, proxy environment, redirects, or
    response body. With socks_port it tests an already running loopback client;
    the caller must separately verify it is Xray/REALITY rather than direct.
    """
    domain, address = validated_target(domain, address)
    if socks_port is not None:
        _port(socks_port)
    cmd = ['curl', '-q', '--silent', '--http2', '--tlsv1.3', '--tls-max', '1.3',
           '--proto', '=https', '--max-redirs', '0', '--connect-timeout', '3',
           '--max-time', str(CURL_TIMEOUT), '--max-filesize', '1048576',
           '--output', os.devnull,
           '--write-out', 'VK_H2:%{http_version}:%{http_code}',
           '--resolve', f'{domain}:443:{address}']
    if socks_port is None:
        cmd.extend(['--noproxy', '*'])
    else:
        # socks5:// keeps target resolution local, so --resolve pins own IP.
        # Explicitly disable any proxy bypass and ambient proxy variables.
        cmd.extend(['--proxy', f'socks5://127.0.0.1:{socks_port}', '--noproxy', ''])
    cmd.append(f'https://{domain}/')
    try:
        proc = run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=CURL_TIMEOUT + 2, check=False, env={'PATH': '/usr/bin:/bin',
                   'LC_ALL': 'C', 'HOME': '/nonexistent'})
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {'status': 'UNVERIFIED', 'reason': 'CURL_UNAVAILABLE_OR_TIMEOUT'}
    if proc.returncode:
        return {'status': 'FAIL' if proc.returncode == 60 else 'UNVERIFIED',
                'reason': 'TLS_CERT_VERIFICATION_FAILED' if proc.returncode == 60 else 'H2_REQUEST_FAILED'}
    match = CURL_RESULT.fullmatch(proc.stdout.strip()) if len(proc.stdout) < 256 else None
    if not match:
        return {'status': 'UNVERIFIED', 'reason': 'H2_RESULT_UNRECOGNIZED'}
    version = match.group(1).decode('ascii')
    code = int(match.group(2))
    status = 'PASS' if version == '2' and code == 200 else 'REVIEW'
    return {'status': status, 'http_version': version, 'http_code': code,
            'reason': ('H2_RESPONSE_FROM_OWN_COVER' if status == 'PASS' else
                       'H2_OR_HTTP_STATUS_MISMATCH'),
            'reality_transport_proven': 'NO'}



def tcp443_external(address, *, connect=socket.create_connection):
    """Single TCP connect to own publicly-addressed HTTPS port; no payload."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise AuditError('INVALID_IP') from None
    if ip.version != 4 or not ip.is_global:
        raise AuditError('PUBLIC_IPV4_REQUIRED')
    try:
        with connect((str(ip), 443), timeout=3):
            return {'status': 'PASS', 'reason': 'TCP443_CONNECTED'}
    except ConnectionRefusedError:
        return {'status': 'REVIEW', 'reason': 'TCP443_EXPLICITLY_REFUSED'}
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return {'status': 'UNVERIFIED', 'reason': 'TCP443_TIMEOUT_OR_NETWORK_ERROR'}


def _static_path(path):
    """No queries, fragments, encoding, dot segments or attacker-chosen URL targets."""
    if (not isinstance(path, str) or len(path) > 128 or
            not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/){0,4}[A-Za-z0-9_-]+\.(?:txt|css|js|jpg|jpeg|png|webp|bin)', path)):
        raise AuditError('INVALID_OWN_STATIC_ASSET_PATH')
    return path


def large_http2_asset(domain, address, path, *, run=subprocess.run):
    """Bounded read of a KNOWN 32-256 KiB asset on the owned HTTPS endpoint.

    Reports only transferred byte count; never stores or displays the body,
    headers or URL. Not an affirmative censorship test without a control network.
    """
    domain, address = validated_target(domain, address)
    path = _static_path(path)
    cmd = ['curl', '-q', '--silent', '--http2', '--tlsv1.3', '--tls-max', '1.3',
           '--proto', '=https', '--max-redirs', '0', '--connect-timeout', '3',
           '--max-time', str(CURL_TIMEOUT), '--max-filesize', str(MAX_STATIC_BYTES),
           '--output', os.devnull, '--noproxy', '*',
           '--write-out', 'VK_LARGE:%{http_version}:%{http_code}:%{size_download}',
           '--resolve', f'{domain}:443:{address}', f'https://{domain}{path}']
    try:
        proc = run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=CURL_TIMEOUT + 2, check=False,
                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'})
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {'status': 'UNVERIFIED', 'reason': 'CURL_UNAVAILABLE_OR_TIMEOUT'}
    match = CURL_LARGE_RESULT.fullmatch(proc.stdout.strip()) if len(proc.stdout) < 256 else None
    if proc.returncode == 60:
        return {'status': 'FAIL', 'reason': 'TLS_CERT_VERIFICATION_FAILED'}
    if match is None:
        return {'status': 'UNVERIFIED', 'reason': ('LARGE_ASSET_RESULT_UNRECOGNIZED' if not proc.returncode
                                                 else 'LARGE_ASSET_TRANSFER_INCOMPLETE_OR_LIMITED')}
    version, code, size = match.group(1).decode('ascii'), int(match.group(2)), int(match.group(3))
    if size > MAX_STATIC_BYTES:
        return {'status': 'UNVERIFIED', 'reason': 'LARGE_ASSET_SIZE_EXCEEDS_BOUND'}
    if proc.returncode:
        # curl often emits --write-out metadata even when a connection dies
        # after partial body delivery (e.g. curl exit 18/28/56). Keep the
        # *byte count* for two-vantage review, never error text or response body.
        return {'status': 'REVIEW', 'http_version': version, 'http_code': code,
                'downloaded_bytes': size, 'reason': 'PARTIAL_OR_FAILED_HTTP_TRANSFER',
                'dpi_or_path_filtering_proven': 'NO'}
    status = 'PASS' if version == '2' and code == 200 and 32768 <= size <= MAX_STATIC_BYTES else 'REVIEW'
    return {'status': status, 'http_version': version, 'http_code': code,
            'downloaded_bytes': size,
            'reason': ('OWN_STATIC_ASSET_TRANSFERRED' if status == 'PASS' else
                       'ASSET_TOO_SMALL_OR_HTTP2_STATUS_MISMATCH'),
            'dpi_or_path_filtering_proven': 'NO'}


def node_api_external(address, port, *, connect=socket.create_connection):
    """One TCP dial to a specifically nominated node API port from elsewhere.

    PASS means only a TCP RST observed from THIS vantage. Timeout is
    UNVERIFIED; a connection is REVIEW (may be a deliberately allowlisted IP).
    Never enumerate ports or send an API request.
    """
    _port(port, excluded=(80, 443))
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise AuditError('INVALID_IP') from None
    if ip.version != 4 or not ip.is_global:
        raise AuditError('PUBLIC_IPV4_REQUIRED')
    try:
        with connect((str(ip), port), timeout=2):
            return {'status': 'REVIEW', 'reason': 'NODE_API_TCP_ACCEPTED_FROM_THIS_SOURCE'}
    except ConnectionRefusedError:
        return {'status': 'PASS', 'reason': 'NODE_API_TCP_REFUSED_FROM_THIS_SOURCE'}
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return {'status': 'UNVERIFIED', 'reason': 'NODE_API_UNREACHABLE_OR_FILTERED'}


def _result_check(call, *, expected=None, reject=False, failure_status='FAIL'):
    try:
        observed = call()
    except (socket.timeout, TimeoutError, ConnectionError, OSError, ssl.SSLError, AuditError) as exc:
        if reject:
            # Only an explicit TLS alert is an observed handshake rejection.
            # TCP EOF, timeout, socket errors can equally mean a broken server.
            if isinstance(exc, ssl.SSLError) and any(alert in str(exc).upper() for alert in (
                'ALERT_HANDSHAKE_FAILURE', 'ALERT_UNRECOGNIZED_NAME',
                'ALERT_ACCESS_DENIED')):
                return {'status': 'PASS', 'reason': 'TLS_ALERT_REJECTED_HANDSHAKE'}
            return {'status': 'UNVERIFIED', 'reason': 'REJECTED_OR_UNREACHABLE'}
        if isinstance(exc, ssl.SSLCertVerificationError):
            return {'status': failure_status, 'reason': 'CERT_OR_SNI_MISMATCH'}
        return {'status': failure_status, 'reason': 'CONNECTION_OR_PROTOCOL_FAILURE'}
    if reject:
        return {'status': 'REVIEW', 'reason': 'UNKNOWN_SNI_ACCEPTED',
                'tls': observed.get('tls'), 'alpn': observed.get('alpn')}
    try:
        acceptable = expected is None or expected(observed)
    except (LookupError, TypeError, ValueError):
        acceptable = False
    status = 'PASS' if acceptable else 'REVIEW'
    observed['status'] = status
    return observed


def parallel_tls_sample(domain, address, *, count=4, connect=_tls_request):
    """Small simultaneous, verified TLS1.3 sample; never sends VPN credentials.

    It does NOT simulate large post-quantum ClientHello or prove REALITY
    handshake completeness: those require a real client and packet capture.
    """
    if type(count) is not int or not 2 <= count <= MAX_PARALLEL:
        raise AuditError('PARALLEL_SAMPLE_MUST_BE_2_TO_4')
    domain, address = validated_target(domain, address)

    def one(_):
        return _result_check(
            lambda: connect(address, domain, sni=domain, version=ssl.TLSVersion.TLSv1_3,
                            offer_h2=True),
            expected=lambda o: o.get('tls') == 'TLSv1.3' and o.get('alpn') == 'h2')

    with ThreadPoolExecutor(max_workers=count) as pool:
        observed = list(pool.map(one, range(count)))
    ok = [item for item in observed if item['status'] == 'PASS']
    versions = {(item.get('tls'), item.get('alpn'), item.get('cipher')) for item in ok}
    latency = [item['elapsed_ms'] for item in ok if type(item.get('elapsed_ms')) is int]
    # Disclose only aggregate timing and negotiated protocol, never peer data.
    status = ('PASS' if len(ok) == count and len(versions) == 1 else
              'FAIL' if any(x['status'] == 'FAIL' for x in observed) else 'REVIEW')
    return {'status': status, 'attempts': count, 'success': len(ok),
            'tls_consistent': len(ok) == count and len(versions) == 1,
            'elapsed_ms_min': min(latency) if latency else None,
            'elapsed_ms_max': max(latency) if latency else None,
            'elapsed_ms_median': round(statistics.median(latency)) if latency else None,
            'clienthello_or_dpi_proven': 'NO',
            'reason': ('PARALLEL_NORMAL_TLS_NOT_REALITY' if status == 'PASS' else
                       'PARALLEL_HANDSHAKE_INCOMPLETE_OR_INCONSISTENT')}


def audit(domain, address, *, connect=_tls_request, plain=_http_redirect, resolve=dns_snapshot,
          parallel_count=0, parallel=parallel_tls_sample,
          actual_http2=False, http2=http2_request, node_api_port=None,
          api_check=node_api_external, client_socks_port=None, tcp443=False,
          tcp_check=tcp443_external, large_static_path=None, large_check=large_http2_asset):
    domain, address = validated_target(domain, address)
    if large_static_path is not None:
        _static_path(large_static_path)  # reject all unsafe inputs BEFORE any network activity
    checks = {'dns': resolve(domain, address)}
    if tcp443:
        checks['tcp443'] = tcp_check(address)
    def request(**options):
        return connect(address, domain, **options)
    for label, version in (('tls12', ssl.TLSVersion.TLSv1_2),
                           ('tls13', ssl.TLSVersion.TLSv1_3)):
        checks[label] = _result_check(
            lambda v=version: request(sni=domain, version=v, method='GET'),
            expected=lambda o, t=label: (o.get('http_code') == 200 and
                                         o.get('tls') == ('TLSv1.2' if t == 'tls12' else 'TLSv1.3') and
                                         o.get('security_headers') is True))
    checks['http_head'] = _result_check(
        lambda: request(sni=domain, method='HEAD'),
        expected=lambda o: o['http_code'] == 200)
    checks['missing_page'] = _result_check(
        lambda: request(sni=domain, method='GET', path='/node-install-nonexistent-page'),
        expected=lambda o: o['http_code'] == 404)
    checks['host_mismatch'] = _result_check(
        lambda: request(sni=domain, method='GET', host='unrelated.invalid'),
        expected=lambda o: o['http_code'] in (400, 421))
    checks['http2_alpn'] = _result_check(
        lambda: request(sni=domain, offer_h2=True),
        expected=lambda o: o['alpn'] == 'h2')
    checks['unknown_sni'] = _result_check(
        lambda: request(sni='invalid-probe.invalid', verified=False), reject=True)
    checks['missing_sni'] = _result_check(
        lambda: request(sni=None, verified=False), reject=True)
    checks['http80'] = _result_check(
        lambda: plain(address, domain),
        expected=lambda o: o['http_code'] == 301 and o['redirect_to_expected_https'])
    if parallel_count:
        if type(parallel_count) is not int or not 2 <= parallel_count <= MAX_PARALLEL:
            raise AuditError('PARALLEL_SAMPLE_MUST_BE_2_TO_4')
        checks['parallel_tls13'] = parallel(domain, address, count=parallel_count, connect=connect)
    if actual_http2:
        checks['http2_request'] = http2(domain, address)
    if node_api_port is not None:
        _port(node_api_port, excluded=(80, 443))
        checks['node_api_external'] = api_check(address, node_api_port)
    if large_static_path is not None:
        checks['large_http2_asset'] = large_check(domain, address, large_static_path)
    if client_socks_port is not None:
        _port(client_socks_port)
        checks['client_socks_https'] = http2(domain, address, socks_port=client_socks_port)
        # A SOCKS listener can be configured to route direct. A successful
        # HTTP response alone cannot attest to REALITY or non-leaking routes.
    # Python stdlib cannot inspect encrypted TLS1.3 NewSessionTicket records.
    checks['post_handshake_records'] = {'status': 'UNVERIFIED', 'reason': 'REQUIRES_PCAP_ON_OWN_STAGING'}
    states = {check['status'] for check in checks.values()}
    status = 'FAIL' if 'FAIL' in states else 'REVIEW' if 'REVIEW' in states else 'UNVERIFIED' if 'UNVERIFIED' in states else 'PASS'
    live_states = {value['status'] for key, value in checks.items() if key != 'post_handshake_records'}
    live_status = ('FAIL' if 'FAIL' in live_states else 'REVIEW' if 'REVIEW' in live_states else
                   'UNVERIFIED' if 'UNVERIFIED' in live_states else 'PASS')
    return {'schema': 1, 'status': status, 'live_checks_status': live_status, 'checks': checks,
            'scope': 'EXPLICIT_OWNED_ENDPOINT_ONLY', 'host_or_firewall_changes': 'NONE',
            'client_or_dpi_stealth_proven': 'NO', 'remote_headers_or_secrets_recorded': 'NO'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--domain', required=True, help='own HTTPS cover hostname')
    p.add_argument('--ip', required=True, help='explicit public IPv4 of OWN node')
    p.add_argument('--confirm-owned-endpoint', action='store_true',
                   help='required: attest that this is your own endpoint')
    p.add_argument('--strict', action='store_true', help='nonzero if not all checks PASS')
    p.add_argument('--parallel', type=int, choices=(2, 3, 4), metavar='{2,3,4}',
                   help='opt-in: at most four concurrent ordinary TLS1.3 handshakes to your endpoint')
    p.add_argument('--http2-actual', action='store_true',
                   help='opt-in: make one real HTTPS/2 request with curl to OWN IPv4')
    p.add_argument('--node-api-port', type=int,
                   help='opt-in: one TCP check of the OWN node management port from an untrusted source')
    p.add_argument('--client-socks5-port', type=int,
                   help='opt-in: one HTTPS/2 request through an existing local client SOCKS5 proxy')
    p.add_argument('--tcp443', action='store_true',
                   help='opt-in: one TCP connect to OWN 443, to separate reachability from TLS')
    p.add_argument('--large-static-path',
                   help='opt-in: read a KNOWN own 32-256KiB static asset through HTTP/2 (no body saved)')
    options = p.parse_args(argv)
    if not options.confirm_owned_endpoint:
        p.error('explicit --confirm-owned-endpoint is required; do not scan third parties')
    try:
        data = audit(options.domain, options.ip, parallel_count=options.parallel or 0,
                     actual_http2=options.http2_actual,
                     node_api_port=options.node_api_port,
                     client_socks_port=options.client_socks5_port,
                     tcp443=options.tcp443, large_static_path=options.large_static_path)
    except AuditError as exc:
        print(json.dumps({'status': 'STOP', 'reason': str(exc)}))
        return 2
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
    return 2 if data['status'] == 'FAIL' or options.strict and data['live_checks_status'] != 'PASS' else 0


if __name__ == '__main__':
    sys.exit(main())
