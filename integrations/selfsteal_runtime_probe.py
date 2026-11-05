#!/usr/bin/env python3
"""Read-only local selfsteal TLS handshake probe over a UNIX socket.

Uses certificate verification, SNI and actual HTTPS GET. For selfsteal sockets
configured with xver:1 pass --proxy-v1 to send a minimal PROXY v1 preface.
Does not call the Panel, modify services, read TLS private keys or send data
to the internet. A successful response is NOT a VLESS/REALITY handshake test.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time

DOMAIN=re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
MAX_HEADER=8192


class CheckError(Exception):pass


def probe(domain, path, *, proxy_v1=False, cafile=None, timeout=5):
    if not isinstance(domain,str) or not DOMAIN.fullmatch(domain):
        raise CheckError('INVALID_DOMAIN')
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir():
        raise CheckError('UNSAFE_SOCKET_PATH')
    if not stat.S_ISSOCK(path.lstat().st_mode):
        raise CheckError('SELFSTEAL_SOCKET_UNAVAILABLE')
    if cafile is not None and (Path(cafile).is_symlink() or not Path(cafile).is_file()):
        raise CheckError('INVALID_TRUST_FILE')
    ctx=ssl.create_default_context(cafile=str(cafile) if cafile else None)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['http/1.1'])
    start=time.monotonic()
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect(str(path))
            if proxy_v1:
                raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 12345 443\r\n')
            with ctx.wrap_socket(raw,server_hostname=domain) as tls:
                tls.settimeout(timeout)
                handshake_ms=round((time.monotonic()-start)*1000,2)
                tls.sendall(f'GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode('ascii'))
                out=b''
                while b'\r\n\r\n' not in out and len(out)<MAX_HEADER:
                    more=tls.recv(min(2048,MAX_HEADER-len(out)))
                    if not more: break
                    out+=more
                match=re.match(rb'HTTP/1\.[01] ([0-9]{3})(?: |\r\n)',out)
                if not match:raise CheckError('INVALID_HTTPS_RESPONSE')
                status=int(match.group(1))
                return {'schema':1,'status':'PASS' if status==200 else 'REVIEW',
                        'http_code':status,'tls_version':tls.version(),
                        'alpn':tls.selected_alpn_protocol(),
                        'handshake_ms':handshake_ms,
                        'proxy_protocol':'v1' if proxy_v1 else 'none',
                        'site_only':'YES','vless_or_dpi_verified':'NO',
                        'secrets_or_peer_addresses_logged':'NO'}
    except (socket.timeout,TimeoutError):
        raise CheckError('SOCKET_OR_TLS_TIMEOUT') from None
    except ssl.SSLCertVerificationError:
        raise CheckError('TLS_CERTIFICATE_OR_SNI_MISMATCH') from None
    except ssl.SSLError:
        raise CheckError('TLS_HANDSHAKE_FAILED') from None
    except (ConnectionError,OSError):
        raise CheckError('SELFSTEAL_SOCKET_CONNECTION_FAILED') from None


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--domain',required=True)
    p.add_argument('--socket',required=True,type=Path)
    p.add_argument('--proxy-v1',action='store_true')
    p.add_argument('--cafile',type=Path,help='test trust root only; never use -k')
    p.add_argument('--strict',action='store_true')
    a=p.parse_args(argv)
    try:
        result=probe(a.domain,a.socket,proxy_v1=a.proxy_v1,cafile=a.cafile)
    except (CheckError,OSError,ValueError) as exc:
        print(json.dumps({'status':'STOP','reason':str(exc) if isinstance(exc,CheckError) else 'RUNTIME_CHECK_UNAVAILABLE'}))
        return 2
    print(json.dumps(result,sort_keys=True,indent=2))
    return 2 if a.strict and result['status']!='PASS' else 0

if __name__=='__main__':sys.exit(main())
