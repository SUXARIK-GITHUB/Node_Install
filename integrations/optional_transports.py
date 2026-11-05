#!/usr/bin/env python3
"""Secure OFFLINE optional transport bundles for a reviewed staging node.

Modes:
  xhttp-tls : local-only VLESS/XHTTP H2C backend + nginx grpc_pass location.
  hysteria2 : standalone Xray hysteria/QUIC+TLS inbound (UDP) and client reference.
  awg2      : AmneziaWG 2.0 server/client configs, generated X25519 keys.

Does NOT change Nginx, Compose, Panel, firewall, sysctl or services. A bundle
is NOT evidence of a live functional transport or compatibility with an actual
RemnaNode binary. Secret files are created in a private 0700 directory and are
never printed. Operator approval, certificates, live Xray -test / awg checks,
firewall planning and a snapshot are required before activation on a VPS.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
URI = re.compile(r'/(?:[A-Za-z0-9_-]{3,32}/){0,2}[A-Za-z0-9_-]{10,96}\Z')
FILES = {}


class Invalid(Exception):
    pass


def domain(value):
    if not isinstance(value,str) or not DOMAIN.fullmatch(value) or value.endswith('.local'):
        raise Invalid('INVALID_DOMAIN')
    return value


def port(value, *, forbid_443=False):
    if type(value) is not int or not 1025 <= value <= 65535:
        raise Invalid('INVALID_UNPRIVILEGED_PORT')
    if value in (2222, 3000) or (forbid_443 and value == 443):
        raise Invalid('PORT_CONFLICT_WITH_NODE')
    return value


def xhttp_tls(domain_name, backend_port, path):
    """Reviewable TLS-terminated H2 -> loopback H2C fragment, not a live patch."""
    domain(domain_name)
    port(backend_port,forbid_443=True)
    if not URI.fullmatch(path):
        raise Invalid('UNSAFE_XHTTP_PATH')
    # Xray validates VLESS UUID issued by the Panel; path is not authentication.
    inbound = {
      'log': {'loglevel': 'warning'},
      'inbounds': [{
          'tag': 'VK_XHTTP_TLS_LOOPBACK', 'listen': '127.0.0.1', 'port': backend_port,
          'protocol': 'vless', 'settings': {'decryption':'none','clients':[]},
          'sniffing': {'enabled':True,'destOverride':['http','tls'],'routeOnly':True},
          'streamSettings': {'network':'xhttp','security':'none',
                             'xhttpSettings':{'path':path,'mode':'auto','host':domain_name}},
      }],
      'outbounds':[{'tag':'DIRECT','protocol':'freedom'}]
    }
    # Include INSIDE the certificate-bearing nginx server only, not global http,
    # stream, the rejecting default_server or public :80. Nginx's grpc_pass uses
    # HTTP/2 cleartext to Xray; the client-facing TLS remains on the cover socket.
    location=f'''# VKARMANI_R23_XHTTP_TLS_H2_STAGING - review before inclusion.
# Needs an ACTIVE loopback Xray inbound at 127.0.0.1:{backend_port}.
# Keep all other selfsteal locations, TLS and 443 stream rules unchanged.
location ^~ {path}/ {{
    access_log off;
    client_max_body_size 4m;
    grpc_pass grpc://127.0.0.1:{backend_port};
    grpc_set_header Host $host;
    grpc_set_header X-Real-IP $remote_addr;
    grpc_read_timeout 180s;
    grpc_send_timeout 180s;
    grpc_connect_timeout 5s;
}}
'''
    notes='''XHTTP/TLS/H2 staging bundle (no actions performed).
1) Install the inbound in a TEST Xray/RemnaNode profile and verify Xray -test.
   Never activate alongside an incompatible existing TCP/443 profile blindly.
2) Backend binds only 127.0.0.1:PORT; NO new public TCP port is opened.
3) Ensure Nginx HTTPS virtual host is reached through existing REALITY fallback.
   Add nginx-location.conf inside the EXACT domain HTTPS server, before the
   final location / { return 404; } rule, never in the default rejecting server.
4) nginx -t, reload, verify HTTPS homepage and backend H2 POST/GET with a
   separately configured test account. Preserve prior conf and rollback.
5) The browser website alone is not proof XHTTP works. The path is not a secret
   authentication mechanism; VLESS clients must be configured in the Panel.
6) No upstream credential, UUID, network rules or existing client is changed.
'''.replace('PORT',str(backend_port))
    return {'profile-xhttp-tls.json':(json.dumps(inbound,indent=2)+'\n').encode(),
            'nginx-location.conf':location.encode(), 'REVIEW.txt':notes.encode()}


def hysteria2(domain_name, udp_port, password=None):
    """Hysteria2 Xray inbound profile, standalone UDP/TLS; no daemon install."""
    domain(domain_name)
    if type(udp_port) is not int or not 1 <= udp_port <= 65535 or udp_port in (53,80,2222,3000):
        raise Invalid('INVALID_UDP_PORT')
    auth = password or secrets.token_urlsafe(36)
    if not isinstance(auth,str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,96}',auth):
        raise Invalid('WEAK_AUTH')
    server={
      'log':{'loglevel':'warning'},
      'inbounds':[{ 'tag':'VK_HYSTERIA2_UDP_STAGING', 'listen':'0.0.0.0',
                    'port':udp_port,'protocol':'hysteria',
                    'settings':{'version':2,'users':[{'auth':auth,'level':0}]},
                    'streamSettings':{'method':'hysteria','security':'tls',
                     'hysteriaSettings':{'version':2,'auth':auth,
                                        'masquerade':{'type':'string','content':'<!doctype html><html lang="en"><title>Service</title><p>Service is available.</p></html>','statusCode':200,'headers':{'Content-Type':'text/html; charset=utf-8'}}},
                     'tlsSettings':{'alpn':['h3'],'certificates':[
                        {'certificateFile':f'/etc/letsencrypt/live/{domain_name}/fullchain.pem',
                         'keyFile':f'/etc/letsencrypt/live/{domain_name}/privkey.pem'}]}}}],
      'outbounds':[{'protocol':'freedom','tag':'DIRECT'}]
    }
    client={'mode':'hysteria2','server':domain_name,'udp_port':udp_port,
            'auth':auth,'tls_server_name':domain_name,'alpn':'h3'}
    notes='''Hysteria2 is an INDEPENDENT optional UDP/TLS transport, not VLESS,
not an alternative XHTTP path, and not part of Remnawave management by default.
The Xray core MUST support protocol=hysteria, method=hysteria, TLS and QUIC.
Certificates must be readable by the Xray process using a secure read-only
mount or restricted copy. Never chmod 644 a private key.
UDP PORT must be free; no firewall changes were made. If operator enables it,
allow only the selected UDP port after a snapshot and port-conflict check.
No HTTP/3 public site parity is guaranteed by a string masquerade response.
Never use this direct-exit profile on cascade ENTRY (fail-closed violation).
Use the private client-reference.json for test clients only; do not publish it.
'''.replace('PORT',str(udp_port))
    return {'profile-hysteria2.json':(json.dumps(server,indent=2)+'\n').encode(),
            'client-reference.json':(json.dumps(client,indent=2)+'\n').encode(),
            'REVIEW.txt':notes.encode()}


def _x25519_pair():
    """OpenSSL supplies X25519 (no Python third-party dependency or persisted tmp key)."""
    try:
        a=subprocess.run(['openssl','genpkey','-algorithm','X25519','-outform','DER'],
                         capture_output=True,check=True,timeout=8)
        b=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],
                         input=a.stdout,capture_output=True,check=True,timeout=8)
    except (OSError,subprocess.SubprocessError) as exc:
        raise Invalid('OPENSSL_X25519_NOT_AVAILABLE') from exc
    # Standard PKCS#8 X25519 private wrapper and RFC8410 SPKI public wrapper.
    private_prefix=bytes.fromhex('302e020100300506032b656e04220420')
    public_prefix=bytes.fromhex('302a300506032b656e032100')
    if len(a.stdout)!=len(private_prefix)+32 or not a.stdout.startswith(private_prefix):
        raise Invalid('OPENSSL_UNEXPECTED_PRIVATE_ENCODING')
    if len(b.stdout)!=len(public_prefix)+32 or not b.stdout.startswith(public_prefix):
        raise Invalid('OPENSSL_UNEXPECTED_PUBLIC_ENCODING')
    return (base64.b64encode(a.stdout[-32:]).decode('ascii'),
            base64.b64encode(b.stdout[-32:]).decode('ascii'))


def awg2(server_domain, udp_port, network='10.88.0.0/24'):
    domain(server_domain)
    if type(udp_port) is not int or not 1025<=udp_port<=65535 or udp_port in (2222,3000):
        raise Invalid('INVALID_AWG_PORT')
    try:
        net=ipaddress.IPv4Network(network,strict=True)
    except (ValueError,TypeError) as exc:
        raise Invalid('INVALID_SUBNET') from exc
    if not net.is_private or net.prefixlen != 24 or net.overlaps(ipaddress.ip_network('10.0.0.0/8')) is False:
        raise Invalid('UNSUPPORTED_PRIVATE_VPN_SUBNET')
    # No auto NAT, FORWARD, sysctl, SSH or UFW modifications. Network choice is
    # reserved for an isolated AWG service; operator must check route overlap.
    server_p,server_pub=_x25519_pair()
    client_p,client_pub=_x25519_pair()
    psk=base64.b64encode(secrets.token_bytes(32)).decode('ascii')
    gateway=str(net.network_address+1)
    client_ip=str(net.network_address+2)
    # AWG 2.0 has RANDOM NON-OVERLAPPING H1-H4 ranges, not four fixed magic
    # headers (the latter resemble the older AWG legacy profile). Ranges and
    # padding sizes MUST match on both peers. An extra 40k between starting
    # values prevents any two ranges from overlapping after width selection.
    population=range(10_000_000,1_900_000_000,40_000)
    positions=sorted(secrets.SystemRandom().sample(population,4))
    headers=[f'H{i} = {base}-{base+2000+secrets.randbelow(3000)}'
             for i,base in enumerate(positions,1)]
    # Avoid equal handshake padding + message lengths (148/92/64 bytes),
    # and prefer moderate data padding rather than saturating mobile links.
    obfs='\n'.join(('Jc = 4','Jmin = 40','Jmax = 90',
                    'S1 = 52','S2 = 38','S3 = 16','S4 = 8',*headers))
    server=f'''# AWG2 optional template: validate with awg-quick before using.
[Interface]
PrivateKey = {server_p}
Address = {gateway}/24
ListenPort = {udp_port}
MTU = 1380
{obfs}

[Peer]
PublicKey = {client_pub}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32
'''
    client=f'''[Interface]
PrivateKey = {client_p}
Address = {client_ip}/32

MTU = 1380
{obfs}

[Peer]
PublicKey = {server_pub}
PresharedKey = {psk}
Endpoint = {server_domain}:{udp_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''
    notes='''AmneziaWG2 independent optional WireGuard-compatible VPN bundle.
Requires the verified awg-tools and amneziawg-go OR tested kernel module
installed separately. This generator DOES NOT install a new kernel or DKMS.
Before activation validate AWG2 support, tools, /dev/net/tun, route overlap,
MTU, UFW, FORWARD, NAT/masquerade, client isolation and restart behavior.
Without explicitly configured IPv4 forwarding + NAT, an AWG client will NOT
have Internet access. The client DNS is intentionally unset; select a trusted
resolver and validate DNS leakage before user deployment. This is intentional (no stealth host-wide changes).
Never activate on cascade ENTRY or assume it is managed by Remnawave Panel.
The emitted keys/PSK and client config are PRIVATE. No live test was run.
'''
    return {'awg0-server.conf':server.encode(),
            'client-reference.conf':client.encode(),
            'REVIEW.txt':notes.encode()}


def write_bundle(output, data):
    output=Path(output)
    repo=Path(__file__).resolve().parents[1]
    if output.resolve() == repo or repo in output.resolve().parents:
        raise Invalid('PRIVATE_BUNDLE_MUST_BE_OUTSIDE_REPOSITORY')
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise Invalid('OUTPUT_PATH_MUST_BE_NEW_SAFE_DIRECTORY')
    if not all(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',n) for n in data):
        raise Invalid('OUTPUT_NAMES_INVALID')
    output.mkdir(mode=0o700)
    try:
        for filename, content in data.items():
            p=output/filename
            with p.open('xb') as f:
                os.fchmod(f.fileno(),0o600)
                f.write(content)
                f.flush(); os.fsync(f.fileno())
        fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    except BaseException:
        for name in data:
            (output/name).unlink(missing_ok=True)
        output.rmdir()
        raise


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['xhttp-tls','hysteria2','awg2'])
    p.add_argument('--domain',required=True)
    p.add_argument('--output',required=True,type=Path,help='NEW private directory, not in repo')
    p.add_argument('--backend-port',type=int,default=33643)
    p.add_argument('--udp-port',type=int,default=None)
    p.add_argument('--xhttp-path',default=None)
    p.add_argument('--vpn-subnet',default='10.88.0.0/24')
    args=p.parse_args(argv)
    try:
        if args.mode=='xhttp-tls':
            data=xhttp_tls(args.domain,args.backend_port,args.xhttp_path or '/api/'+secrets.token_hex(16))
        elif args.mode=='hysteria2':
            data=hysteria2(args.domain,args.udp_port if args.udp_port is not None else 443)
        else:
            data=awg2(args.domain,args.udp_port if args.udp_port is not None else 51820,args.vpn_subnet)
        write_bundle(args.output,data)
    except (Invalid,OSError,ValueError) as exc:
        code=str(exc) if isinstance(exc,Invalid) else type(exc).__name__
        print('OPTIONAL_TRANSPORT=STOP '+code,file=sys.stderr)
        return 1
    print('OPTIONAL_TRANSPORT=PREPARED MODE='+args.mode+' LIVE_NODE=UNCHANGED FILES='+str(len(data)))
    return 0


if __name__=='__main__':sys.exit(main())
