#!/usr/bin/env python3
"""Read-only VPS connectivity diagnostics for Node Install.

All remote tests are explicit opt-in. Targets are allowlisted public hostnames or
operator-supplied public IPv4/IDNA names. No redirects, credentials, request bodies,
remote scripts, proxy env, DNS rebinding to private IPs or unbounded downloads.
A reachable HTTP server is NOT proof that a service works for a signed-in user.
"""
import argparse
import secrets
import stat
import datetime as dt
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time

# Only service home/API endpoints; no login or captcha bypass attempts.
SERVICES = (
    ('VK', 'vk.com', '/', 'web'),
    ('Яндекс', 'ya.ru', '/', 'web'),
    ('MAX', 'max.ru', '/', 'web'),
    ('YouTube', 'www.youtube.com', '/', 'web'),
    ('Reddit', 'www.reddit.com', '/', 'web'),
    ('GitHub', 'github.com', '/', 'web'),
    ('X / Twitter', 'x.com', '/', 'web'),
    ('ChatGPT', 'chatgpt.com', '/', 'web'),
    ('DeepSeek', 'chat.deepseek.com', '/', 'web'),
    ('Grok', 'grok.com', '/', 'web'),
    ('Claude', 'claude.ai', '/', 'web'),
    ('OpenAI API', 'api.openai.com', '/v1/models', 'api'),
    ('Claude Code API', 'api.anthropic.com', '/v1/models', 'api'),
    ('DeepSeek API', 'api.deepseek.com', '/v1/models', 'api'),
)
MAX_BYTES = 8192
MAX_DOMAIN = 253
HTTP_STATUS = re.compile(rb'^HTTP/1\.[01] ([1-5][0-9][0-9])(?:\s|\r?$)')
COOKIELESS_HEADERS = b'User-Agent: NodeInstall-NetworkDiagnostics/1\r\nAccept: */*\r\nConnection: close\r\n'


def clean_host(value):
    """Validate name and allow public IPv4 only (no URL/userinfo/IPv6/port)."""
    if type(value) is not str or not value or len(value) > MAX_DOMAIN or any(c in value for c in '/:@?\\\n\r\x00 '):
        raise ValueError('INVALID_HOST')
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
            raise ValueError('NONPUBLIC_IPV4_FORBIDDEN')
        return str(ip)
    try:
        name = value.rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError) as exc:
        raise ValueError('INVALID_DOMAIN') from exc
    if len(name) > MAX_DOMAIN or len(name.split('.')) < 2 or all(x.isdigit() or x == '.' for x in name):
        raise ValueError('INVALID_DOMAIN')
    for part in name.split('.'):
        if not 1 <= len(part) <= 63 or not re.fullmatch('[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', part):
            raise ValueError('INVALID_DOMAIN')
    return name


def global_ipv4s(host, resolver=socket.getaddrinfo):
    """Reject any resolved private/non-global address; never silently follow it."""
    records = resolver(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    ips = sorted({str(ipaddress.IPv4Address(row[4][0])) for row in records})
    if not ips or any(not ipaddress.IPv4Address(ip).is_global for ip in ips):
        raise ValueError('UNSAFE_DNS_RESULT')
    return ips[:3]


def classify(http_code, *, headers=b''):
    """Do not infer geoblocking from a generic 403 or 451 alone."""
    if 200 <= http_code < 400:
        return 'REACHABLE'
    if http_code == 401:
        return 'AUTH_REQUIRED'
    if http_code == 429 or (http_code == 403 and b'x-ratelimit-remaining: 0' in headers.lower()):
        return 'RATE_LIMITED'
    if http_code in (403, 451):
        return 'RESTRICTED_OR_PROTECTED'
    return 'HTTP_RESPONSE'


def https_once(host, *, path='/', port=443, timeout=4.0, resolver=global_ipv4s, connector=socket.create_connection,
               tls_context=None, monotonic=time.monotonic):
    if type(port) is not int or not 1 <= port <= 65535 or not 1 <= timeout <= 10:
        raise ValueError('INVALID_PORT_OR_TIMEOUT')
    host = clean_host(host)
    if not re.fullmatch(r'/[A-Za-z0-9._~!$&\x27()*+,;=:@%/-]{0,256}', path):
        raise ValueError('INVALID_PATH')
    start = monotonic()
    try:
        ips = resolver(host)
        dns_ms = (monotonic() - start) * 1000
    except (OSError, ValueError):
        return {'status': 'DNS_ERROR'}
    context = tls_context or ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    # No redirects are followed. Hostname verification MUST stay enabled.
    for ip in ips:
        try:
            with connector((ip, port), timeout=timeout) as raw:
                tcp_ms = (monotonic() - start) * 1000
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    secure.settimeout(timeout)
                    tls_ms = (monotonic() - start) * 1000
                    request = (f'HEAD {path} HTTP/1.1\r\nHost: {host}\r\n'.encode('ascii') +
                               COOKIELESS_HEADERS + b'\r\n')
                    secure.sendall(request)
                    data = bytearray()
                    while b'\r\n\r\n' not in data and len(data) < MAX_BYTES:
                        chunk = secure.recv(min(2048, MAX_BYTES-len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    first_ms = (monotonic() - start) * 1000
                    headers = bytes(data).split(b'\r\n\r\n', 1)[0]
                    code_match = HTTP_STATUS.match(headers.split(b'\r\n')[0])
                    if not code_match:
                        return {'status': 'HTTP_INVALID', 'dns_ms': round(dns_ms, 1)}
                    http_code = int(code_match.group(1))
                    return {'status': classify(http_code, headers=headers), 'http': http_code,
                            'dns_ms': round(dns_ms, 1), 'tcp_ms': round(tcp_ms-dns_ms, 1),
                            'tls_ms': round(tls_ms-tcp_ms, 1), 'ttfb_ms': round(first_ms, 1)}
        except ssl.SSLCertVerificationError:
            return {'status': 'TLS_CERT_ERROR'}
        except ssl.SSLError:
            return {'status': 'TLS_ERROR'}
        except (TimeoutError, socket.timeout):
            result = {'status': 'TIMEOUT'}
        except OSError:
            result = {'status': 'TCP_ERROR'}
    return result


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered)-1)*pct/100
    low, high = math.floor(rank), math.ceil(rank)
    return round(ordered[low]+(ordered[high]-ordered[low])*(rank-low), 1)


def quality(host, *, samples=5, seconds_between=0.2, probe=https_once, sleep=time.sleep):
    if type(samples) is not int or not 2 <= samples <= 12 or not 0 <= seconds_between <= 2:
        raise ValueError('INVALID_QUALITY_SAMPLES')
    host = clean_host(host)
    results = []
    for i in range(samples):
        results.append(probe(host))
        if i + 1 < samples:
            sleep(seconds_between)
    ok = [row['ttfb_ms'] for row in results if row.get('status') in ('REACHABLE', 'AUTH_REQUIRED', 'RESTRICTED_OR_PROTECTED', 'RATE_LIMITED', 'HTTP_RESPONSE') and 'ttfb_ms' in row]
    jitter = round(statistics.mean(abs(b-a) for a,b in zip(ok, ok[1:])), 1) if len(ok) >= 2 else None
    p50, p95 = percentile(ok,50), percentile(ok,95)
    spike_limit = (p50 * 2 + 50) if p50 is not None else None
    return {'host': host, 'type': 'HTTPS_TTFB', 'attempts': samples, 'answered': len(ok),
            'failure_pct': round(100 * (samples-len(ok)) / samples,1),
            'min_ms': round(min(ok), 1) if ok else None, 'avg_ms': round(statistics.mean(ok),1) if ok else None,
            'max_ms': round(max(ok),1) if ok else None, 'p50_ms': p50, 'p95_ms': p95,
            'jitter_ms': jitter, 'spikes': sum(v > spike_limit for v in ok) if spike_limit is not None else None,
            'limitations': ['HTTPS response time, not ICMP RTT or VPN latency',
                            'Failure percent means failed HTTPS probes, not router packet loss']}


def parse_ping(output, expected):
    """Strictly parse ICMP output in LC_ALL=C; no invented hop/packet values."""
    matched = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', output)
    if not matched:
        return {'status': 'UNVERIFIED'}
    sent, received = (int(x) for x in matched.groups())
    if not 0 <= received <= sent <= expected:
        return {'status': 'UNVERIFIED'}
    out = {'status': 'MEASURED', 'type': 'ICMP', 'sent': sent, 'received': received,
           'loss_pct': round(100*(sent-received)/sent,1) if sent else None}
    times = re.search(r'(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)',output)
    if times:
        try:
            vals = list(map(float,times.groups()))
            if all(math.isfinite(x) and x >= 0 for x in vals):
                out.update(zip(('min_ms','avg_ms','max_ms','jitter_mdev_ms'), [round(x,2) for x in vals]))
        except ValueError:
            pass
    return out


def icmp_probe(host, *, samples=7, executor=subprocess.run, resolver=global_ipv4s):
    if not 2 <= samples <= 12:
        raise ValueError('INVALID_SAMPLES')
    host = clean_host(host)
    try:
        ips = resolver(host)
    except (OSError, ValueError):
        return {'status': 'DNS_ERROR', 'type': 'ICMP'}
    if not shutil.which('ping'):
        return {'status': 'TOOL_NOT_INSTALLED', 'type': 'ICMP'}
    try:
        result = executor(['ping','-4','-n','-c',str(samples),'-W','2','-i','0.3',ips[0]],
                          capture_output=True, text=True, timeout=samples*3+5,
                          env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        return parse_ping(result.stdout[-8192:], samples)
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'TIMEOUT', 'type': 'ICMP'}


def trace(host, *, resolver=global_ipv4s, executor=subprocess.run):
    host = clean_host(host)
    try:
        ips = resolver(host)
    except (OSError, ValueError):
        return {'status': 'DNS_ERROR'}
    if not shutil.which('traceroute'):
        return {'status': 'TOOL_NOT_INSTALLED', 'explanation': 'traceroute is optional; no package installed'}
    try:
        cp = executor(['traceroute','-4','-n','-m','15','-w','1','-q','1', ips[0]],
                      capture_output=True,text=True,timeout=23,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        # Destination may never respond; hops with '*' are not necessarily traffic loss.
        lines = cp.stdout.splitlines()[1:16]
        return {'status': 'MEASURED' if lines else 'UNVERIFIED',
                'hops_visible': len(lines), 'route': [re.sub(r'[^\x20-\x7e]', '?',x)[:180] for x in lines],
                'limitations':['Intermediate ICMP suppression does not prove end-to-end loss']}
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'TIMEOUT'}


def speed(ip, *, port=5201, seconds=5, direction='both', runner=None):
    """Reuse the existing bounded operator-owned iperf3 probe (not speedtest.net)."""
    # Isolated Python execution intentionally ignores untrusted PYTHONPATH.
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from throughput_probe import run
    if not ipaddress.IPv4Address(ip).is_global or direction not in ('both','download','upload'):
        raise ValueError('PUBLIC_OWNED_IPERF_SERVER_REQUIRED')
    options=({'runner':runner} if runner else {})
    results={}
    if direction in ('both','upload'):
        results['upload_to_peer']=run(ip,port,seconds,1,reverse=False,**options)
    if direction in ('both','download'):
        results['download_from_peer']=run(ip,port,seconds,1,reverse=True,**options)
    return {'schema':1,'kind':'IPERF3_SPEED','status':'PASS' if all(r['status']=='PASS' for r in results.values()) else 'REVIEW',
            'measure':'DIRECT_TCP_IPERF3_NOT_VPN',**results,
            'limitations':['Both directions consume bandwidth; only use your authorized server',
                           'Source VPS-to-peer throughput, not VPN client speed']}


def local_snapshot():
    data = {'schema':1, 'kind':'LOCAL_VPS', 'status':'REVIEW', 'os':'UNVERIFIED',
            'architecture': os.uname().machine, 'ram_mib':None, 'disk_free_mib':None,
            'default_route':'UNVERIFIED', 'owned_installation':False,
            'markers':[], 'limitations':['Read-only; does not prove fresh install eligibility']}
    try:
        text = Path('/etc/os-release').read_text(encoding='utf-8')
        data['os'] = re.search(r'^PRETTY_NAME=(.*)$',text,re.M).group(1).strip('"')[:100]
    except (OSError, AttributeError):
        pass
    try:
        mem = re.search(r'^MemTotal:\s+(\d+) kB',Path('/proc/meminfo').read_text(),re.M)
        if mem:
            data['ram_mib'] = round(int(mem.group(1))/1024)
        disk=os.statvfs('/')
        data['disk_free_mib']=round(disk.f_bavail*disk.f_frsize/1048576)
    except OSError:
        pass
    try:
        result=subprocess.run(['ip','-4','route','show','default'],capture_output=True,text=True,
                              timeout=4,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        data['default_route']='PRESENT' if result.returncode==0 and result.stdout.strip() else 'MISSING'
    except (OSError, subprocess.TimeoutExpired):
        pass
    state=Path('/var/lib/vkarmani-node')
    data['owned_installation']=(state/'owned-installation').is_file()
    data['markers']=[name for name in ('INSTALL_COMPLETE','INSTALL_FAILED','network-rollback-armed',
                        'network-rollback-running','image-update-pending','finalization') if (state/name).exists()]
    data['kernel']=os.uname().release
    data['cpu_logical']=os.cpu_count()
    try:
        swap=re.search(r'^SwapTotal:\s+(\d+) kB',Path('/proc/meminfo').read_text(),re.M)
        data['swap_mib']=round(int(swap.group(1))/1024) if swap else None
    except OSError:
        data['swap_mib']=None
    data['tools']={name:shutil.which(name) is not None for name in
                   ('python3','bash','ip','ss','docker','nginx','ufw','systemctl','traceroute','ping','iperf3')}
    services_state={}
    for name in ('ssh','nginx','docker','fail2ban'):
        if shutil.which('systemctl'):
            try:
                cp=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=3,
                                  env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                services_state[name]='ACTIVE' if cp.returncode==0 else 'INACTIVE_OR_UNKNOWN'
            except (OSError,subprocess.TimeoutExpired):
                services_state[name]='UNVERIFIED'
        else:services_state[name]='UNVERIFIED'
    data['services']=services_state
    if shutil.which('ss'):
        try:
            cp=subprocess.run(['ss','-H','-4','-lnt'],capture_output=True,text=True,timeout=4,
                              env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            # Only summarize presence of named ports, never local addresses/peers.
            listeners=set()
            for line in cp.stdout.splitlines():
                fields=line.split()
                if len(fields)>=4:
                    match=re.search(r':(\d+)$',fields[3])
                    if match:listeners.add(int(match.group(1)))
            data['listeners']={str(port):port in listeners for port in (22,80,443,2222)}
        except (OSError,subprocess.TimeoutExpired):
            data['listeners']='UNVERIFIED'
    data['status']='INFO' if data['default_route']=='PRESENT' else 'REVIEW'
    return data


def services(*, only=None, probe=https_once, progress=None):
    chosen = [row for row in SERVICES if only is None or row[0] in only]
    if not chosen or (only is not None and set(only) != {row[0] for row in chosen}):
        raise ValueError('UNKNOWN_SERVICE_NAME')
    report=[]
    for name,host,path,kind in chosen:
        if progress:progress(name)
        row=probe(host,path=path)
        report.append({'service':name,'host':host,'category':kind, **row})
    return {'kind':'SERVICES', 'schema':1, 'results':report,
            'limitations':['HTTPS status is not proof of application login or geographic entitlement',
                           '401 means authentication required; 403/451 may be anti-bot or regional',
                           'No redirects followed, no cookies or tokens sent']}


def cloudflare_edge(*, probe=None):
    """Small explicitly opt-in GET to Cloudflare trace; only display colo/loc, never client IP."""
    import http.client
    # Python's HTTPSConnection verifies the hostname and certificate.
    try:
        if probe is not None:
            raw=probe()
        else:
            conn=http.client.HTTPSConnection('www.cloudflare.com',timeout=5,context=ssl.create_default_context())
            try:
                conn.request('GET','/cdn-cgi/trace',headers={'User-Agent':'NodeInstall-NetworkDiagnostics/1'})
                response=conn.getresponse()
                raw=response.read(1024) if response.status==200 else b''
            finally:
                conn.close()
        text=raw.decode('ascii',errors='strict')
        parsed=dict(x.split('=',1) for x in text.splitlines() if '=' in x)
        colo,location=parsed.get('colo',''),parsed.get('loc','')
        if not re.fullmatch('[A-Z]{3}',colo) or not re.fullmatch('[A-Z]{2}',location):
            return {'status':'UNVERIFIED'}
        return {'status':'INFO','edge_colo':colo,'observed_country':location,
                'limitations':['CDN edge is not necessarily nearest location',
                               'Cloudflare receives the public source IP; no IP retained in output']}
    except (OSError,UnicodeError,ValueError,TimeoutError):
        return {'status':'UNVERIFIED'}


def history_dir(root=None):
    """Private per-user history, never in the repository or system installer state."""
    return Path(root) if root is not None else Path.home()/'.local/state/vkarmani-network-diagnostics'


def trusted_history(root=None, *, create=False):
    directory=history_dir(root)
    if create:
        directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
        raise ValueError('UNSAFE_HISTORY_DIRECTORY')
    return directory


def save_report(record, root=None):
    """Explicit storage only. Strict file permissions and no credential content."""
    if not isinstance(record,dict) or len(json.dumps(record,ensure_ascii=False))>100_000:
        raise ValueError('INVALID_REPORT')
    directory=trusted_history(root,create=True)
    existing=list(directory.glob('*.json'))
    if len(existing)>=100:
        raise ValueError('HISTORY_LIMIT_REACHED')
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name=f'{stamp}-{secrets.token_hex(3)}.json'
    doc={'recorded_utc':dt.datetime.now(dt.timezone.utc).isoformat(), 'report':record}
    payload=(json.dumps(doc,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode('utf-8')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(payload);f.flush();os.fsync(f.fileno())
        dfd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:os.fsync(dfd)
        finally:os.close(dfd)
    except BaseException:
        try:(directory/name).unlink()
        except OSError:pass
        raise
    return name


def reports_list(root=None):
    directory=history_dir(root)
    if not directory.exists():return []
    directory=trusted_history(root)
    return sorted((p.name for p in directory.glob('*.json') if p.is_file() and not p.is_symlink()),reverse=True)[:100]


def load_report(name,root=None):
    if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{6}\.json',str(name)):
        raise ValueError('INVALID_HISTORY_NAME')
    directory=trusted_history(root)
    p=directory/name
    st=p.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>100_000:
        raise ValueError('UNSAFE_HISTORY_FILE')
    return json.loads(p.read_text(encoding='utf-8'))


def compare_reports(first,second,root=None):
    a=load_report(first,root)['report'];b=load_report(second,root)['report']
    if a.get('kind')!=b.get('kind'):
        return {'status':'REVIEW','reason':'REPORT_KINDS_DIFFER'}
    if a.get('kind')=='SERVICES':
        old={row['service']:row for row in a.get('results',[])}
        return {'kind':'SERVICES_DIFF','changes':[
            {'service':row['service'],'before':old[row['service']]['status'],'after':row['status']}
            for row in b.get('results',[]) if row['service'] in old and row['status']!=old[row['service']]['status']]}
    measures=('avg_ms','p95_ms','jitter_ms','failure_pct','loss_pct','mbps_median')
    differences={key:{'before':a[key],'after':b[key]} for key in measures if key in a and key in b}
    return {'kind':'METRIC_DIFF','changes':differences,'note':'Different test times/routes may not be comparable'}



def render_table(report):
    """Readable monochrome terminal tables; JSON remains the default public API.

    No ANSI sequences or remote content; the curses host owns colour and paging.
    Values such as HTTP 401/403 are not labelled as proof of blocking.
    """
    if not isinstance(report, dict):
        raise ValueError('INVALID_REPORT')
    def value(item):
        return '—' if item is None else str(item).replace('\r',' ').replace('\n',' ')[:100]
    def table(headers, rows, widths):
        cells=[]
        limit=shutil.get_terminal_size(fallback=(105,24)).columns
        if limit < 65:
            for row in rows:
                cells.extend(f'{a}: {value(b)}' for a,b in zip(headers,row))
                cells.append('')
            return '\n'.join(cells)
        def fmt(row):
            return '  '.join(value(cell).ljust(w)[:w] for cell,w in zip(row,widths)).rstrip()
        cells=[fmt(headers), '  '.join('─'*w for w in widths)]
        cells.extend(fmt(row) for row in rows)
        return '\n'.join(cells)
    kind=report.get('kind','')
    if kind=='SERVICES':
        rows=[]
        for item in report.get('results',[]):
            rows.append((item.get('service','—'),item.get('status','—'),
                         item.get('http','—'),
                         value(item.get('ttfb_ms'))+' ms' if item.get('ttfb_ms') is not None else '—'))
        return 'ДОСТУПНОСТЬ СЕРВИСОВ · HTTPS с VPS\n'+table(
             ('Сервис','Результат','HTTP','Время'),rows,(21,28,6,12)) + \
             '\nHTTP 401 = нужна авторизация; 403/451 не доказывают блокировку.\n'
    if kind=='LOCAL_VPS':
        selected=('os','architecture','ram_mib','disk_free_mib','default_route','owned_installation')
        rows=[(key,report.get(key,'—')) for key in selected]
        rows.extend((f'service/{key}',val) for key,val in report.get('services',{}).items())
        return 'СОСТОЯНИЕ VPS · только чтение\n'+table(('Проверка','Результат'),rows,(28,42))
    if kind=='CUSTOM':
        row=report.get('result',{})
        return 'HTTPS ПРОВЕРКА · '+value(report.get('host'))+'\n'+table(
            ('Показатель','Результат'),
            [(k, v) for k,v in row.items()],(28,42))
    if kind=='IPERF3_SPEED':
        rows=[]
        for direction,key in (('Upload','upload_to_peer'),('Download','download_from_peer')):
            r=report.get(key)
            if r is not None:
                rows.append((direction,r.get('status'),r.get('mbps_median'),r.get('retransmits_total')))
        return 'СКОРОСТЬ VPS · TCP до своего iperf3 сервера (не VPN)\n'+table(
            ('Направление','Статус','Мбит/с','Retransmits'),rows,(16,15,14,14))
    if report.get('type')=='ICMP':
        return 'ICMP PING · потери и задержка (если узел отвечает)\n'+table(
            ('Показатель','Результат'),
            [(key, report.get(key)) for key in ('status','sent','received','loss_pct','min_ms','avg_ms','max_ms','jitter_mdev_ms')],
            (28,42))
    if report.get('type')=='HTTPS_TTFB':
        return 'HTTPS КАЧЕСТВО · НЕ ICMP / НЕ VPN RTT\n'+table(
            ('Показатель','Результат'),
            [(key, report.get(key)) for key in ('host','answered','attempts','failure_pct','min_ms','avg_ms','max_ms','p50_ms','p95_ms','jitter_ms','spikes')],
            (28,42))
    if 'route' in report:
        return 'МАРШРУТ · промежуточные узлы могут не отвечать\n'+\
               '\n'.join(value(x) for x in report.get('route',[])[:15])
    if kind=='HISTORY':
        return 'ИСТОРИЯ ИЗМЕРЕНИЙ\n'+'\n'.join(map(value,report.get('names',[])))
    # For short status, diff, CDN and error reports a compact properties table.
    return 'РЕЗУЛЬТАТ\n'+table(('Поле','Значение'),[
         (key,json.dumps(val,ensure_ascii=False) if isinstance(val,(dict,list)) else value(val))
         for key,val in report.items() if key not in ('limitations',)],(28,54))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('local')
    sub.add_parser('services')
    one=sub.add_parser('custom');one.add_argument('--host',required=True);one.add_argument('--port',type=int,default=443)
    q=sub.add_parser('quality');q.add_argument('--host',default='cloudflare.com');q.add_argument('--samples',type=int,default=5)
    ping=sub.add_parser('ping');ping.add_argument('--host',default='cloudflare.com');ping.add_argument('--samples',type=int,default=7)
    tr=sub.add_parser('trace');tr.add_argument('--host',default='cloudflare.com')
    sp=sub.add_parser('speed');sp.add_argument('--server',required=True);sp.add_argument('--port',type=int,default=5201);sp.add_argument('--seconds',type=int,default=5);sp.add_argument('--direction',choices=('both','upload','download'),default='both')
    sub.add_parser('edge')
    sub.add_parser('catalog')
    sub.add_parser('history')
    show=sub.add_parser('show');show.add_argument('name')
    compare=sub.add_parser('compare');compare.add_argument('older');compare.add_argument('newer')
    p.add_argument('--save',action='store_true',help='opt-in private local report file, never automatic')
    p.add_argument('--format',choices=('json','table'),default='json',help='table = readable terminal view, json = API output')
    args=p.parse_args(argv)
    try:
        if args.action=='local':result=local_snapshot()
        elif args.action=='services':result=services(progress=lambda name:print('CHECKING '+name,flush=True))
        elif args.action=='catalog':result={'services':[{'name':n,'host':h,'category':c} for n,h,_,c in SERVICES]}
        elif args.action=='history':result={'kind':'HISTORY','names':reports_list()}
        elif args.action=='show':result=load_report(args.name)
        elif args.action=='compare':result=compare_reports(args.older,args.newer)
        elif args.action=='custom':result={'kind':'CUSTOM','host':clean_host(args.host),'port':args.port,'result':https_once(args.host,port=args.port)}
        elif args.action=='quality':result=quality(args.host,samples=args.samples)
        elif args.action=='ping':result=icmp_probe(args.host,samples=args.samples)
        elif args.action=='trace':result=trace(args.host)
        elif args.action=='speed':result=speed(args.server,port=args.port,seconds=args.seconds,direction=args.direction)
        else:result=cloudflare_edge()
    except (ValueError,TypeError,ipaddress.AddressValueError,OSError) as exc:
        print(json.dumps({'status':'STOP','reason':'INVALID_ARGUMENTS_OR_UNSAFE_TARGET'}));return 2
    if args.save:
        if args.action in ('history','show','compare','catalog'):
            print(json.dumps({'status':'STOP','reason':'CANNOT_SAVE_THIS_ACTION'}));return 2
        try:print('SAVED_REPORT='+save_report(result))
        except (ValueError,OSError):
            print(json.dumps({'status':'STOP','reason':'COULD_NOT_SAVE_REPORT'}));return 2
    if args.format=='table':print(render_table(result))
    else:print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    return 0


if __name__=='__main__':
    sys.exit(main())
