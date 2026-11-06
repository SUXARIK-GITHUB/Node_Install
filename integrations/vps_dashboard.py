#!/usr/bin/env python3
"""Read-only, Russian-language VPS dashboard for the Node Install TUI.

No curl|bash, package installations, background daemons or borrowed stress tests.
HTTP checks are intentionally NOT mislabelled as geoblock or account access.
Only explicit bench writes a bounded temporary file; only explicit speed contacts
an operator-owned iperf3 listener. The CLI emits one bounded JSON line per event.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime as dt
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vps_connectivity as net

# Only fixed, public FQDNs. URLs are not read from remote data or terminal input.
ADDITIONAL_SERVICES = (
    ('Google', 'www.google.com'), ('Google Gemini', 'gemini.google.com'),
    ('Netflix', 'www.netflix.com'), ('Spotify', 'www.spotify.com'),
    ('TikTok', 'www.tiktok.com'), ('Twitch', 'www.twitch.tv'),
    ('Apple', 'www.apple.com'), ('Steam', 'store.steampowered.com'),
    ('Amazon', 'www.amazon.com'), ('Bing', 'www.bing.com'),
    ('Cloudflare', 'www.cloudflare.com'), ('Discord', 'discord.com'),
    ('Telegram', 'web.telegram.org'), ('Microsoft Copilot', 'copilot.microsoft.com'),
    ('Pinterest', 'www.pinterest.com'), ('Docker Hub', 'hub.docker.com'),
)
GEO_SOURCES = (('ipapi.co','/json/','ipapi'),('ipinfo.io','/json','ipinfo'),
               ('ipwho.is','/','ipwho'))
MAX_EVENT = 100_000


def _clean(value, maxlen=110):
    """No control/escape sequences ever reach curses or saved reports."""
    if not isinstance(value,(str,int,float)):
        return '—'
    s=str(value)
    s=''.join(x if x.isprintable() else ' ' for x in s)
    return re.sub(r'\s+',' ',s).strip()[:maxlen]


def _status(exc):
    if isinstance(exc,(socket.timeout,TimeoutError,subprocess.TimeoutExpired)):
        return 'TIMEOUT'
    if isinstance(exc,(ssl.SSLError,ssl.SSLCertVerificationError)):
        return 'TLS_ERROR'
    return 'UNVERIFIED'


def bounded_public_https_json(host,path,*,resolve=net.global_ipv4s,timeout=4):
    """Public-IP-only TLS/hostname-verified HTTPS, with 8-KiB response cap.

    Fixed FQDNs, no redirects, proxy environment, cookies, auth or scripts.
    Using an already-validated IP prevents DNS rebinding into internal hosts.
    """
    if host not in {entry[0] for entry in GEO_SOURCES} or path not in ('/','/json/','/json'):
        raise ValueError('NON_ALLOWLISTED_GEO_ENDPOINT')
    ip=resolve(host)[0]
    if not ipaddress.IPv4Address(ip).is_global:
        raise ValueError('NON_PUBLIC_DESTINATION')
    context=ssl.create_default_context()
    with socket.create_connection((ip,443),timeout=timeout) as sock:
        with context.wrap_socket(sock,server_hostname=host) as tls:
            tls.settimeout(timeout)
            tls.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+host+
                         '\r\nUser-Agent: NodeInstall-ReadOnlyDiag/1\r\nAccept: application/json\r\nConnection: close\r\n\r\n').encode('ascii'))
            response=http.client.HTTPResponse(tls)
            response.begin()
            if response.status!=200 or int(response.getheader('Content-Length') or 0)>8192:
                raise ValueError('GEO_UNAVAILABLE')
            data=response.read(8193)
            if len(data)>8192:raise ValueError('GEO_RESPONSE_TOO_LARGE')
    obj=json.loads(data)
    if not isinstance(obj,dict):raise ValueError('INVALID_GEO_JSON')
    return obj


def normalize_geo(source,data):
    """Take only documented fields. A field from a remote server is never a command."""
    if source=='ipapi':
        if data.get('error'):raise ValueError('GEO_API_ERROR')
        ip=data.get('ip'); country=data.get('country_code') or data.get('country')
        asn=data.get('asn'); org=data.get('org'); city=data.get('city')
    elif source=='ipinfo':
        if data.get('error'):raise ValueError('GEO_API_ERROR')
        ip=data.get('ip');country=data.get('country');city=data.get('city')
        org=_clean(data.get('org',''))
        match=re.match(r'AS(\d+)',org)
        asn='AS'+match.group(1) if match else None
    elif source=='ipwho':
        if data.get('success') is not True:raise ValueError('GEO_API_ERROR')
        ip=data.get('ip');country=data.get('country_code');city=data.get('city')
        entry=data.get('connection') if isinstance(data.get('connection'),dict) else {}
        asn=entry.get('asn');org=entry.get('org') or entry.get('isp')
    else:raise ValueError('UNKNOWN_GEO_SOURCE')
    try:
        address=ipaddress.IPv4Address(str(ip))
        if not address.is_global:raise ValueError('NONPUBLIC_RETURNED_IP')
    except ipaddress.AddressValueError as exc:raise ValueError('INVALID_RETURNED_IP') from exc
    country=str(country or '').upper()
    if not re.fullmatch(r'[A-Z]{2}',country):country='—'
    if isinstance(asn,int):asn='AS'+str(asn)
    elif asn is not None:
        match=re.search(r'AS\s*(\d{1,10})',str(asn),re.I)
        asn='AS'+match.group(1) if match else '—'
    return {'status':'INFO','source':source,'ip':str(address),'country':country,
            'city':_clean(city,45),'asn':asn or '—','organization':_clean(org,90)}


def geo_reputation(*,fetch=bounded_public_https_json,progress=None):
    """Independent geo/ASN observations; not a fraud score or VPN classifier."""
    rows=[]
    for host,path,source in GEO_SOURCES:
        if progress:progress("GeoIP: "+source)
        try:rows.append(normalize_geo(source,fetch(host,path)))
        except (ValueError,OSError,TypeError,TimeoutError,UnicodeError,json.JSONDecodeError,ssl.SSLError) as exc:
            rows.append({'status':_status(exc),'source':source,'reason':type(exc).__name__})
    countries={r['country'] for r in rows if r.get('status')=='INFO' and r.get('country')!='—'}
    public_ips={r['ip'] for r in rows if r.get('status')=='INFO'}
    return {'status':'REVIEW' if len(countries)>1 or len(public_ips)>1 or not public_ips else 'INFO',
            'observations':rows,'country_consensus':next(iter(countries)) if len(countries)==1 else 'НЕ ПОДТВЕРЖДЕНО',
            'country_discrepancy':len(countries)>1,
            'ip_discrepancy':len(public_ips)>1,
            'limitations':['Гео-IP и ASN — оценки справочников; не физическое местоположение VPS.',
                           'Hosting/Residential/VPN/Proxy/risk score здесь НЕ определяются.',
                           'Провайдеры видят исходящий публичный IP VPS; данные могут быть устаревшими.']}


def passive_host(*,snapshot=net.local_snapshot):
    record=snapshot()
    try:
        details=Path('/proc/cpuinfo').read_text(encoding='utf-8')[:200_000]
        found=re.search(r'^model name\s*:\s*(.+)$',details,re.M)
        if found:record['cpu_model']=_clean(found.group(1))
    except OSError:pass
    try:
        mem=Path('/proc/meminfo').read_text()
        for key,alias in (('MemAvailable','ram_available_mib'),('MemFree','ram_free_mib'),('SwapFree','swap_free_mib')):
            match=re.search(r'^'+key+r':\s+(\d+)\s+kB',mem,re.M)
            if match:record[alias]=round(int(match.group(1))/1024)
        disk=os.statvfs('/')
        record['disk_total_gib']=round(disk.f_blocks*disk.f_frsize/1024**3,2)
        record['disk_free_gib']=round(disk.f_bavail*disk.f_frsize/1024**3,2)
    except OSError:pass
    try:
        record['uptime_hours']=round(float(Path('/proc/uptime').read_text().split()[0])/3600,1)
        record['load_average']=[round(x,2) for x in os.getloadavg()]
    except (OSError,ValueError):pass
    try:
        record['tcp_congestion']=_clean(Path('/proc/sys/net/ipv4/tcp_congestion_control').read_text())
    except OSError:pass
    try:
        record['virtualization']='KVM' if Path('/sys/class/dmi/id/product_name').read_text().strip().upper().startswith(('KVM','STANDARD PC')) else 'НЕ ОПРЕДЕЛЕНА'
    except OSError:pass
    return record


def dns_snapshot(*,resolver=net.global_ipv4s,monotonic=time.monotonic):
    records=[]
    for host in ('github.com','www.youtube.com','chatgpt.com','cloudflare.com'):
        start=monotonic()
        try:
            ips=resolver(host)
            records.append({'host':host,'status':'PASS','ip':ips[0],
                            'ms':round((monotonic()-start)*1000,1)})
        except (OSError,ValueError) as exc:
            records.append({'host':host,'status':_status(exc),'reason':type(exc).__name__})
    return {'status':'INFO' if all(r['status']=='PASS' for r in records) else 'REVIEW','results':records,
            'limitations':['Используется системный DNS VPS, не проверка DNS клиента.']}


def services_matrix(*,probe=net.https_once, progress=None, workers=4):
    entries=list(net.SERVICES)+[(name,host,'/','web') for name,host in ADDITIONAL_SERVICES]
    if workers not in (1,2,3,4):raise ValueError('INVALID_PARALLELISM')
    def job(row):
        name,host,path,category=row
        try:result=probe(host,path=path,timeout=4)
        except (OSError,ValueError,TypeError,ssl.SSLError) as exc:result={'status':_status(exc)}
        return {'service':name,'host':host,'category':category,**result}
    ordered=[None]*len(entries)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map={pool.submit(job,row):i for i,row in enumerate(entries)}
        for future in as_completed(future_map):
            index=future_map[future]
            try:ordered[index]=future.result()
            except Exception:ordered[index]={'service':entries[index][0],'host':entries[index][1],
                                            'status':'UNVERIFIED'}
            if progress:progress('Сервисы: '+str(sum(x is not None for x in ordered))+'/'+str(len(entries)))
    counts={}
    for row in ordered:counts[row.get('status','UNVERIFIED')]=counts.get(row.get('status','UNVERIFIED'),0)+1
    return {'status':'INFO' if all(r.get('status') in ('REACHABLE','AUTH_REQUIRED') for r in ordered) else 'REVIEW',
            'results':ordered,'counts':counts,
            'limitations':['HTTP 200/3xx: ответ сервера; не подтверждение входа в аккаунт.',
                           'HTTP 401: требуется авторизация. 403/451: ограничение ИЛИ защита от ботов.',
                           'Не определяется Netflix/YouTube Premium/ChatGPT подписка или реальная геоблокировка.']}


def ping_matrix(*,probe=net.icmp_probe):
    results=[]
    for label,host in (('Cloudflare 1.1.1.1','1.1.1.1'),('GitHub','github.com')):
        try:res=probe(host,samples=5)
        except (OSError,ValueError,TypeError) as exc:res={'status':_status(exc)}
        results.append({'target':label,**res})
    return {'status':'INFO' if all(x.get('status')=='MEASURED' for x in results) else 'REVIEW',
            'results':results,
            'limitations':['Неполучение ICMP не означает недоступность HTTPS или VPN.']}


def cpu_disk_benchmark(*,run_seconds=0.6,write_mib=8,temp_dir=None):
    """Opt-in light benchmark, bounded CPU/memory/disk; no fio, sysbench, apt."""
    import hashlib
    if not 0.2<=run_seconds<=1 or write_mib not in (0,8):raise ValueError('INVALID_BENCH_LIMIT')
    start=time.monotonic();cycles=0
    while time.monotonic()-start<run_seconds:
        hashlib.pbkdf2_hmac('sha256',b'node-install-bench',b'vps',25000)
        cycles+=1
    elapsed=max(time.monotonic()-start,1e-6)
    # A bounded single in-memory copy; no physical RAM capacity estimation.
    source=b'\x5A'*(8*1024*1024)
    t0=time.monotonic();copy=bytearray(source);copy[0]=0
    memory_ms=round((time.monotonic()-t0)*1000,2)
    result={'kind':'LIGHT_BENCH','status':'INFO','cpu_iterations_per_sec':round(cycles*25000/elapsed),
            'memory_copy_8mib_ms':memory_ms,'disk_write_mib_s':None,
            'limitations':['Краткий тест Python; НЕ заменяет sysbench/YABS/fio и не сравним с ними.',
                           'Опциональный диск: временно записывается и удаляется 8 MiB.']}
    if write_mib:
        # Never touch a caller-supplied filename. mkstemp creates a 0600 file,
        # and the random file is always removed, even when fsync fails.
        root=Path(temp_dir) if temp_dir is not None else Path('/tmp')
        st=root.lstat()
        if not stat.S_ISDIR(st.st_mode) or root.is_symlink():
            result['disk_status']='UNSAFE_TEMP_DIR';return result
        usage=shutil.disk_usage(root)
        if usage.free<64*1024*1024:
            result['disk_status']='NOT_ENOUGH_FREE_SPACE';return result
        fd,name=tempfile.mkstemp(prefix='node-install-bench-',dir=root)
        try:
            t0=time.monotonic()
            block=b'\x23'*(1024*1024)
            for _ in range(write_mib):
                view=memoryview(block)
                while view:
                    n=os.write(fd,view)
                    if n<=0:raise OSError('INCOMPLETE_BENCH_WRITE')
                    view=view[n:]
            os.fsync(fd)
            seconds=max(time.monotonic()-t0,0.00001)
            result['disk_write_mib_s']=round(write_mib/seconds,1)
            result['disk_status']='TEMP_FSYNC_COMPLETED'
        except OSError as exc:
            result['disk_status']=type(exc).__name__
        finally:
            os.close(fd)
            os.unlink(name)
    return result


def run_full(*,progress=None,probes=None):
    """Independent sections; partial failure never suppresses other measurements."""
    probes=probes or {}
    tasks=[('host','Система и ресурсы',passive_host),
           ('geo','Публичный IP / геолокация / ASN',lambda:geo_reputation(progress=progress)),
           ('dns','DNS-запросы',dns_snapshot),
           ('services','Публичные сайты и API',lambda:services_matrix(progress=progress)),
           ('ping','ICMP-потери и задержка',ping_matrix),
           ('quality','HTTPS-стабильность GitHub',lambda:net.quality('github.com')),
           ('route','Маршрут до GitHub',lambda:net.trace('github.com')),
           ('cdn','Cloudflare CDN',net.cloudflare_edge)]
    report={'schema':2,'kind':'RUSSIAN_VPS_DIAGNOSTICS',
            'created_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'status':'INFO','mode':'SAFE_READ_ONLY',
            'speed':{'status':'SKIPPED','reason':'Свой iperf3 не указан'},
            'benchmark':{'status':'SKIPPED','reason':'Нужно явно включить из экрана результатов'},
            'limitations':['Выполнено на VPS, а не из VPN-клиента.',
                           'IP/геолокация могут отличаться по справочникам; это не балл доверия.',
                           'Скорость, дисковый тест и нагрузка не запускаются автоматически.']}
    for key,title,default in tasks:
        if progress:progress('НАЧАТО: '+title)
        try:
            fn=probes.get(key,default)
            report[key]=fn()
        except (OSError,ValueError,TypeError,subprocess.TimeoutExpired,UnicodeError,RuntimeError) as exc:
            report[key]={'status':_status(exc),'reason':type(exc).__name__}
        if progress:progress('ГОТОВО: '+title)
    if any(isinstance(report.get(key),dict) and report[key].get('status') in ('REVIEW','UNVERIFIED','STOP','TIMEOUT')
           for key,_,_ in tasks):
        report['status']='REVIEW'
    return report


def _safe_emit(item):
    line=json.dumps(item,ensure_ascii=False,separators=(',',':'))
    if len(line.encode('utf-8'))>MAX_EVENT:raise ValueError('EVENT_TOO_LARGE')
    print(line,flush=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('full','bench','speed'),help='full read-only; bench opt-in; speed own iperf3 only')
    parser.add_argument('--server',help='public IPv4 of authorized operator-owned iperf3 service')
    args=parser.parse_args(argv)
    try:
        if args.mode=='full':
            result=run_full(progress=lambda msg:_safe_emit({'type':'progress','message':_clean(msg)}))
        elif args.mode=='bench':
            _safe_emit({'type':'progress','message':'Щадящий CPU/RAM и 8 MiB диск, только по запросу'})
            result=cpu_disk_benchmark()
        else:
            if not args.server:raise ValueError('OWN_IPERF_SERVER_REQUIRED')
            result=net.speed(args.server,seconds=5)
        _safe_emit({'type':'result','report':result})
        return 0
    except (OSError,ValueError,TypeError) as exc:
        _safe_emit({'type':'error','error':type(exc).__name__})
        return 2


if __name__=='__main__':
    raise SystemExit(main())
