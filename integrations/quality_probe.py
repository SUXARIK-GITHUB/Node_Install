#!/usr/bin/env python3
"""Bounded real IPv4 HTTPS responsiveness/reliability probe (NOT a VPN speedtest).

Operator selects a domain and expected IPv4; no DNS substitution, no redirects,
no credentials/cookies, no client identifiers, no request bodies. TLS certificate
and hostname are verified, with explicit local test-CA support. Read only /
(max 128KiB), sequentially at most 20 samples. Outputs aggregate timing and
success/error categories only. Does not test DPI, REALITY client or throughput.
"""
import argparse
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import statistics
import sys
import time

DNS = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
MAX_BYTES=128*1024


class ProbeError(Exception):pass


def validate(domain, ip, port, samples, loopback=False):
    if not isinstance(domain,str) or not DNS.fullmatch(domain):
        raise ProbeError('INVALID_DOMAIN')
    try:addr=ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError,ValueError,TypeError) as exc:
        raise ProbeError('INVALID_IPV4') from exc
    if not addr.is_global and not (loopback and addr.is_loopback):
        raise ProbeError('PRIVATE_OR_NONPUBLIC_TARGET_REFUSED')
    if type(port) is not int or not (port == 443 or 1025 <= port <= 65535) or type(samples) is not int or samples not in range(1,21):
        raise ProbeError('PORT_OR_SAMPLES_INVALID')
    return str(addr)


def percentile(data, percentile_value):
    if not data:return None
    sorted_data=sorted(data)
    index=(len(data)-1)*(percentile_value/100)
    low=int(math.floor(index));high=int(math.ceil(index))
    return round(sorted_data[low]+(sorted_data[high]-sorted_data[low])*(index-low),2)


def probe_once(domain, ip, port, timeout=4, cafile=None):
    """Return metrics or a stable error code. Must never log exceptions/IPs."""
    ctx=ssl.create_default_context(cafile=str(cafile) if cafile is not None else None)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['http/1.1'])
    started=time.monotonic()
    try:
        sock=socket.create_connection((ip,port),timeout=timeout)
        tcp=(time.monotonic()-started)*1000
        try:
            with ctx.wrap_socket(sock,server_hostname=domain) as tls:
                tls.settimeout(timeout)
                handshake=(time.monotonic()-started)*1000-tcp
                req=(f'GET / HTTP/1.1\r\nHost: {domain}\r\n'
                     'User-Agent: VKarmani-Quality-Probe/1\r\n'
                     'Accept: text/html\r\nConnection: close\r\n\r\n').encode('ascii')
                tls.sendall(req)
                first=tls.recv(16384)
                ttfb=(time.monotonic()-started)*1000
                if not first.startswith(b'HTTP/1.') or b'\r\n' not in first:
                    return {'error':'HTTP_RESPONSE_INVALID'}
                status_line=first.split(b'\r\n',1)[0]
                match=re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]{0,100})?',status_line)
                if not match:return {'error':'HTTP_RESPONSE_INVALID'}
                status=int(match.group(1))
                total=len(first)
                while total <= MAX_BYTES:
                    chunk=tls.recv(min(8192,MAX_BYTES+1-total))
                    if not chunk:break
                    total+=len(chunk)
                if total>MAX_BYTES:return {'error':'HTTP_RESPONSE_EXCEEDS_128K'}
                return {'status':status,'tcp_ms':round(tcp,2),
                        'tls_ms':round(handshake,2),'ttfb_ms':round(ttfb,2),
                        'total_ms':round((time.monotonic()-started)*1000,2),
                        'response_bytes':total,
                        'tls_version':tls.version(),'alpn':tls.selected_alpn_protocol()}
        finally:
            sock.close()
    except ssl.SSLCertVerificationError:
        return {'error':'TLS_CERTIFICATE_OR_HOSTNAME_FAILED'}
    except ssl.SSLError:
        return {'error':'TLS_HANDSHAKE_FAILED'}
    except (socket.timeout,TimeoutError):
        return {'error':'CONNECTION_TIMEOUT'}
    except (ConnectionError,OSError):
        return {'error':'NETWORK_UNAVAILABLE'}


def summarize(results):
    errors={}
    ok=[]
    for row in results:
        if row.get('error'):
            k=row['error'];errors[k]=errors.get(k,0)+1
        elif 200<=row.get('status',0)<400:
            ok.append(row)
        else:
            k='HTTP_NON_SUCCESS';errors[k]=errors.get(k,0)+1
    fields=('tcp_ms','tls_ms','ttfb_ms','total_ms','response_bytes')
    stats={name:{'p50':percentile([row[name] for row in ok],50),
                 'p95':percentile([row[name] for row in ok],95)} for name in fields}
    return {'schema':1,'status':'PASS' if not errors and results else 'REVIEW',
            'samples':len(results),'ok':len(ok),'failed':len(results)-len(ok),
            'error_classes':errors,'metrics':stats,
            'measure':'DIRECT_HTTPS_SITE_ONLY',
            'limitations':['No VPN tunnel or client traffic measured',
                           'Small response bytes do not represent download throughput',
                           'Results represent one source network and cannot prove DPI resilience',
                           'No IPs, headers, bodies or secrets included in report']}


def run(domain,ip,port,samples,*,cafile=None,loopback=False,delay=.15):
    validate(domain,ip,port,samples,loopback)
    if cafile is not None:
        if cafile.is_symlink() or not cafile.is_file():raise ProbeError('CAFILE_NOT_REGULAR')
    results=[]
    for i in range(samples):
        results.append(probe_once(domain,ip,port,cafile=cafile))
        if i+1<samples:time.sleep(delay)
    return summarize(results)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--domain',required=True)
    p.add_argument('--ip',required=True,help='expected IPv4, not printed')
    p.add_argument('--port',type=int,default=443)
    p.add_argument('--samples',type=int,default=8)
    p.add_argument('--cafile',type=Path,help='explicit trust root for staging tests')
    p.add_argument('--allow-loopback',action='store_true',help='test fixture only')
    p.add_argument('--strict',action='store_true')
    args=p.parse_args(argv)
    try:
        report=run(args.domain,args.ip,args.port,args.samples,cafile=args.cafile,
                   loopback=args.allow_loopback)
    except (ProbeError,ValueError,OSError,TypeError) as exc:
        print(json.dumps({'status':'STOP','reason':str(exc) if isinstance(exc,ProbeError)
                          else 'PROBE_UNAVAILABLE'}))
        return 1
    print(json.dumps(report,sort_keys=True,indent=2))
    return 2 if args.strict and report['status']!='PASS' else 0


if __name__=='__main__':sys.exit(main())
