#!/usr/bin/env python3
"""Real client-path HTTPS and SOCKS5 UDP DNS probes; NEVER stop a server.

Run against a pre-started, TEST-ONLY local SOCKS5 listener of the actual VPN
client (Xray SOCKS inbound with udp=true). Baseline -> operator-stops-Exit ->
outage -> operator-restores-Exit -> recovery. Reports observations, not proof
of absence of Entry egress leaks; packet capture and provider evidence remain
mandatory for production sign-off.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import sys
from urllib.parse import urlsplit

TIMEOUT=8
MAX_REPLY=32768


class ProbeError(Exception):pass


def require(cond,why):
    if not cond:raise ProbeError(why)


def exact(sock,n):
    data=b''
    while len(data)<n:
        frag=sock.recv(n-len(data))
        if not frag:raise ProbeError('SOCKS_CONNECTION_CLOSED')
        data+=frag
    return data


def auth(sock):
    sock.sendall(b'\x05\x01\x00')
    require(exact(sock,2)==b'\x05\x00','SOCKS5_NOAUTH_NOT_AVAILABLE')


def addr(sock):
    atyp=exact(sock,1)[0]
    if atyp==1:
        a=socket.inet_ntoa(exact(sock,4))
    elif atyp==3:
        size=exact(sock,1)[0];require(0<size<=253,'SOCKS_ADDR_LENGTH');a=exact(sock,size).decode('ascii')
    elif atyp==4:raise ProbeError('SOCKS_RETURNED_IPV6_NOT_SUPPORTED')
    else:raise ProbeError('SOCKS_BAD_ADDR_TYPE')
    port=struct.unpack('!H',exact(sock,2))[0]
    return a,port


def request(sock,cmd,host,port):
    if re.fullmatch(r'[a-zA-Z0-9.-]{1,253}',host) and not re.fullmatch(r'[\d.]+',host):
        data=host.encode('ascii');target=b'\x03'+bytes([len(data)])+data
    else:
        target=b'\x01'+ipaddress.IPv4Address(host).packed
    sock.sendall(b'\x05'+bytes([cmd])+b'\x00'+target+struct.pack('!H',port))
    h=exact(sock,3)
    require(h[:1]==b'\x05' and h[2:]==b'\x00','SOCKS_BAD_REPLY')
    rep=h[1]
    # Always drain BND.ADDR/BND.PORT even for a failed reply.
    address,bindport=addr(sock)
    require(rep==0,'SOCKS_REMOTE_REQUEST_REJECTED')
    return address,bindport


def local_auth(port):
    with socket.create_connection(('127.0.0.1',port),timeout=TIMEOUT) as conn:
        conn.settimeout(TIMEOUT);auth(conn)


def echo_url(value):
    u=urlsplit(value)
    require(u.scheme=='https' and u.hostname and u.username is None and u.password is None
            and u.port in (None,443) and not u.query and not u.fragment,
            'HTTPS_ECHO_URL_INVALID')
    host=u.hostname.lower()
    require(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])?',host) is not None and
            '.' in host and not re.fullmatch(r'[0-9.]+',host) and
            not host.endswith(('.local','.internal','.localhost','.test','.invalid')),
            'HTTPS_ECHO_HOST_INVALID')
    return host,u.path or '/'


def https_exit(port,url):
    host,path=echo_url(url)
    with socket.create_connection(('127.0.0.1',port),timeout=TIMEOUT) as conn:
        conn.settimeout(TIMEOUT);auth(conn);request(conn,1,host,443)
        with ssl.create_default_context().wrap_socket(conn,server_hostname=host) as tls:
            tls.settimeout(TIMEOUT)
            req=(f'GET {path} HTTP/1.0\r\nHost: {host}\r\n'
                 'User-Agent: VKARMANI-staging-probe/1\r\nConnection: close\r\nAccept: text/plain\r\n\r\n')
            tls.sendall(req.encode('ascii'))
            response=b''
            while len(response)<=MAX_REPLY:
                chunk=tls.recv(min(4096,MAX_REPLY+1-len(response)))
                if not chunk:break
                response+=chunk
            require(len(response)<=MAX_REPLY,'HTTPS_RESPONSE_TOO_LARGE')
    header,sep,body=response.partition(b'\r\n\r\n')
    require(sep and re.match(rb'^HTTP/1\.[01] 200 ',header),'HTTPS_NOT_200')
    require(b'transfer-encoding: chunked' not in header.lower(),'HTTPS_CHUNKED_UNSUPPORTED')
    text=body.decode('ascii','strict').strip()
    ip=ipaddress.ip_address(text)
    require(ip.version==4 and ip.is_global,'HTTPS_EGRESS_NOT_PUBLIC_IPV4')
    return str(ip)


def dns_query(name,nonce):
    labels=name.lower().split('.')
    require(1<len(labels)<=20 and all(re.fullmatch(r'[a-z0-9-]{1,63}',x) for x in labels)
            and len(name)<253,'INVALID_DNS_NAME')
    qname=b''.join(bytes((len(x),))+x.encode('ascii') for x in labels)+b'\x00'
    return (struct.pack('!HHHHHH',nonce,0x0100,1,0,0,0) +qname+b'\x00\x01\x00\x01'),qname



def parse_dns_name(payload, offset):
    """Parse bounded RFC 1035 names including pointers; return name and consumed end.

    We follow each pointer only within the response and reject cycles or
    dangling lengths. A syntactically valid ANCOUNT alone is not an A answer.
    """
    parts=[]
    seen=set()
    result_end=None
    while True:
        require(0 <= offset < len(payload) and offset not in seen and len(seen)<64,
                'INVALID_DNS_NAME_POINTER')
        seen.add(offset)
        n=payload[offset]
        if n & 0xc0 == 0xc0:
            require(offset+1<len(payload),'INVALID_DNS_NAME_POINTER')
            pointer=((n&0x3f)<<8)|payload[offset+1]
            require(pointer<offset,'INVALID_DNS_NAME_POINTER')
            if result_end is None:result_end=offset+2
            offset=pointer
            continue
        require((n&0xc0)==0 and n<=63,'INVALID_DNS_NAME_LABEL')
        if n==0:
            return '.'.join(parts), result_end if result_end is not None else offset+1
        require(offset+n+1<=len(payload),'INVALID_DNS_NAME_LENGTH')
        label=payload[offset+1:offset+n+1]
        try:word=label.decode('ascii')
        except UnicodeDecodeError as exc:raise ProbeError('INVALID_DNS_NAME_LABEL') from exc
        require(re.fullmatch(r'[a-zA-Z0-9-]+',word) is not None,
                'INVALID_DNS_NAME_LABEL')
        parts.append(word.lower())
        require(sum(len(p)+1 for p in parts)<=253,'INVALID_DNS_NAME_LENGTH')
        offset+=n+1


def validate_dns_a_answer(payload, qname):
    """Require a complete, public IPv4 IN/A record, not just positive ANCOUNT."""
    require(len(payload)>=12,'SHORT_DNS_REPLY')
    _,flags,qd,an,_,_=struct.unpack('!HHHHHH',payload[:12])
    require(flags&0x8000 and flags&0xF==0 and qd==1 and an>0,
            'DNS_NO_VALID_A_RESPONSE')
    question,offset=parse_dns_name(payload,12)
    require(question==qname,'DNS_QUESTION_MISMATCH')
    require(offset+4<=len(payload) and payload[offset:offset+4]==b'\x00\x01\x00\x01',
            'DNS_QUESTION_MISMATCH')
    offset+=4
    matched=False
    for _ in range(an):
        _,offset=parse_dns_name(payload,offset)
        require(offset+10<=len(payload),'INVALID_DNS_ANSWER_LENGTH')
        kind,rrclass,_,length=struct.unpack('!HHIH',payload[offset:offset+10])
        offset+=10
        require(offset+length<=len(payload),'INVALID_DNS_ANSWER_LENGTH')
        if kind==1 and rrclass==1 and length==4:
            ip=ipaddress.IPv4Address(payload[offset:offset+length])
            if ip.is_global:matched=True
        offset+=length
    require(matched,'DNS_NO_PUBLIC_A_RECORD')
    return True

def udp_dns(port,resolver,dns_name):
    ipaddress.IPv4Address(resolver)
    require(ipaddress.IPv4Address(resolver).is_global,'DNS_RESOLVER_NOT_PUBLIC')
    nonce=secrets.randbelow(65536)
    query,qname=dns_query(dns_name,nonce)
    with socket.create_connection(('127.0.0.1',port),timeout=TIMEOUT) as control:
        control.settimeout(TIMEOUT);auth(control)
        bindaddr,bindport=request(control,3,'0.0.0.0',0)
        require(bindport>0 and bindaddr in ('0.0.0.0','127.0.0.1'),
                'SOCKS_UDP_RELAY_NOT_LOCAL')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(TIMEOUT)
            udp.bind(('127.0.0.1',0))
            req=b'\x00\x00\x00\x01'+ipaddress.IPv4Address(resolver).packed+struct.pack('!H',53)+query
            udp.sendto(req,('127.0.0.1',bindport))
            reply,source=udp.recvfrom(4096)
            require(source==('127.0.0.1',bindport),'UNEXPECTED_UDP_RELAY')
            require(len(reply)>=22 and reply[:4]==b'\x00\x00\x00\x01','INVALID_UDP_WRAPPER')
            require(reply[4:8]==ipaddress.IPv4Address(resolver).packed and
                    struct.unpack('!H',reply[8:10])[0]==53,'DNS_FROM_WRONG_UPSTREAM')
            payload=reply[10:]
            require(len(payload)>=12+len(qname)+4,'SHORT_DNS_REPLY')
            txn=struct.unpack('!H',payload[:2])[0]
            require(txn==nonce,'DNS_TRANSACTION_ID_MISMATCH')
            return validate_dns_a_answer(payload,dns_name.lower())



def udp_echo(port,target_ipv4,target_port):
    target=ipaddress.IPv4Address(target_ipv4)
    require(target.is_global and target.version==4,'ECHO_TARGET_NOT_GLOBAL_IPV4')
    require(type(target_port) is int and 1025<=target_port<=65535 and target_port!=2222,
            'ECHO_PORT_INVALID')
    token=secrets.token_bytes(20)
    with socket.create_connection(('127.0.0.1',port),timeout=TIMEOUT) as control:
        control.settimeout(TIMEOUT);auth(control)
        relay_ip,relay_port=request(control,3,'0.0.0.0',0)
        require(relay_port>0 and relay_ip in ('0.0.0.0','127.0.0.1'),
                'SOCKS_UDP_RELAY_NOT_LOCAL')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(TIMEOUT)
            udp.bind(('127.0.0.1',0))
            body=b'\x00\x00\x00\x01'+target.packed+struct.pack('!H',target_port)+token
            udp.sendto(body,('127.0.0.1',relay_port))
            reply,source=udp.recvfrom(4096)
            require(source==('127.0.0.1',relay_port),'UNEXPECTED_UDP_ECHO_RELAY')
            require(len(reply)==10+len(token) and reply[:4]==b'\x00\x00\x00\x01' and
                    reply[4:8]==target.packed and struct.unpack('!H',reply[8:10])[0]==target_port
                    and reply[10:]==token,'UDP_ECHO_CONTENT_OR_TARGET_MISMATCH')
            return True


def param_fingerprint(args):
    normalized=json.dumps({'socks_port':args.socks_port,'exit_ipv4':args.exit_ipv4,
                           'echo_url':args.https_echo_url,'resolver':args.udp_resolver_ipv4,
                           'dns_name':args.dns_name,
                           'udp_echo_ipv4':args.udp_echo_ipv4,'udp_echo_port':args.udp_echo_port},sort_keys=True,separators=(',',':'))
    return hashlib.sha256(normalized.encode()).hexdigest()


def secure_receipt_read(file):
    p=Path(file)
    require(not p.is_symlink() and p.is_file() and p.stat().st_nlink==1 and
            stat.S_IMODE(p.stat().st_mode)&0o077==0 and p.stat().st_size<=8192,
            'INSECURE_OR_MISSING_PREVIOUS_RECEIPT')
    return json.loads(p.read_bytes())


def create_receipt(path,info):
    p=Path(path)
    require(not p.exists() and not p.is_symlink() and p.parent.is_dir() and
            not p.parent.is_symlink(),'RECEIPT_MUST_BE_NEW')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write((json.dumps(info,sort_keys=True,indent=2)+'\n').encode())
            f.flush();os.fsync(f.fileno())
    except BaseException:
        p.unlink(missing_ok=True)
        raise


def check(args,tcp=https_exit,udp=udp_dns,echo=udp_echo,auth_probe=local_auth):
    require(1<=args.socks_port<=65535,'SOCKS_PORT_INVALID')
    expected=ipaddress.IPv4Address(args.exit_ipv4)
    require(expected.is_global and expected.version==4,'EXIT_IPV4_NOT_GLOBAL')
    host,_=echo_url(args.https_echo_url)
    require(host,'INVALID_ECHO')
    dns_query(args.dns_name,0)
    require(ipaddress.IPv4Address(args.udp_resolver_ipv4).is_global,'RESOLVER_NOT_GLOBAL')
    require(ipaddress.IPv4Address(args.udp_echo_ipv4).is_global and
            1025<=args.udp_echo_port<=65535 and args.udp_echo_port!=2222,
            'UDP_ECHO_ENDPOINT_INVALID')
    fp=param_fingerprint(args)
    prev=None
    if args.phase=='baseline':
        require(not args.previous,'BASELINE_MUST_START_CHAIN')
        session=secrets.token_hex(16)
    else:
        require(args.previous,'PREVIOUS_RECEIPT_REQUIRED')
        prev=secure_receipt_read(args.previous)
        allowed={'outage':'baseline','recovery':'outage'}
        require(prev.get('phase')==allowed[args.phase] and prev.get('fingerprint')==fp and
                prev.get('status')=='PASS' and re.fullmatch('[a-f0-9]{32}',prev.get('session','')),
                'PREVIOUS_RECEIPT_INVALID_OR_DIFFERENT_TEST')
        session=prev['session']
        if args.phase=='outage':
            require(args.outage_reference and len(args.outage_reference)<256 and
                    not any(x in args.outage_reference for x in '\r\n\0'),
                    'OUTAGE_OPERATOR_EVIDENCE_REFERENCE_REQUIRED')
    try:
        auth_probe(args.socks_port)
    except (OSError,ProbeError) as exc:
        raise ProbeError('LOCAL_SOCKS_CLIENT_NOT_RUNNING') from exc
    detail={}
    try:
        ip=tcp(args.socks_port,args.https_echo_url)
        detail['https']='EXPECTED_EXIT' if ip==str(expected) else 'WRONG_EGRESS_IP'
    except (OSError,ssl.SSLError,ValueError,UnicodeError,ProbeError) as exc:
        detail['https']='FAILED'
    try:
        require(udp(args.socks_port,args.udp_resolver_ipv4,args.dns_name) is True,
                'UDP_DNS_NOT_CONFIRMED')
        detail['udp_dns']='REPLIED'
    except (OSError,UnicodeError,ValueError,ProbeError) as exc:
        detail['udp_dns']='FAILED'
    try:
        require(echo(args.socks_port,args.udp_echo_ipv4,args.udp_echo_port) is True,
                'UDP_ECHO_NOT_CONFIRMED')
        detail['udp_echo']='REPLIED'
    except (OSError,UnicodeError,ValueError,ProbeError):
        detail['udp_echo']='FAILED'
    if args.phase in ('baseline','recovery'):
        success=detail=={'https':'EXPECTED_EXIT','udp_dns':'REPLIED','udp_echo':'REPLIED'}
    else:
        # No other public egress address is an acceptable 'outage' fallback.
        success=detail=={'https':'FAILED','udp_dns':'FAILED','udp_echo':'FAILED'}
    return {'schema':1,'phase':args.phase,'session':session,'fingerprint':fp,
            'status':'PASS' if success else 'FAIL',
            'tcp_https':detail['https'],'udp_dns':detail['udp_dns'],
            'udp_echo':detail['udp_echo'],
            'tested_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'outage_operator_reference':args.outage_reference if args.phase=='outage' else None,
            'claim':'OBSERVATION_ONLY_REQUIRES_ENTRY_EGRESS_CAPTURE_AND_REAL_EXIT_STATUS'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',required=True,choices=['baseline','outage','recovery'])
    p.add_argument('--socks-port',required=True,type=int,
                   help='loopback SOCKS5 port of YOUR running real test VPN client (with UDP support)')
    p.add_argument('--exit-ipv4',required=True)
    p.add_argument('--https-echo-url',required=True,
                   help='HTTPS URL responding with plain public IPv4; selected by operator')
    p.add_argument('--udp-resolver-ipv4',required=True)
    p.add_argument('--dns-name',default='example.org')
    p.add_argument('--udp-echo-ipv4',required=True,help='independent TEST UDP echo server public IPv4')
    p.add_argument('--udp-echo-port',required=True,type=int,help='TEST echo service port >1024')
    p.add_argument('--previous',type=Path)
    p.add_argument('--outage-reference',help='external evidence ID of separately stopped TEST Exit')
    p.add_argument('--output',type=Path,required=True,help='new private JSON receipt, no overwrites')
    args=p.parse_args(argv)
    try:
        result=check(args)
        create_receipt(args.output,result)
    except (OSError,ProbeError,ValueError,json.JSONDecodeError) as exc:
        print('LIVE_PROBE=BLOCKED '+(str(exc) if isinstance(exc,ProbeError) else type(exc).__name__),file=sys.stderr)
        return 2
    print('LIVE_PROBE='+result['status']+' PHASE='+args.phase+' RECEIPT_WRITTEN'
          +' ENTRY_EGRESS_CAPTURE=REQUIRED')
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
