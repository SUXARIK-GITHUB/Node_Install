#!/usr/bin/env python3
"""Explicit, bounded TCP throughput/retransmission benchmark against YOUR iperf3 server.

No iperf3 service is installed, started or downloaded by this tool. This is an
optional client-side staging probe; requires an operator-controlled iperf3
server, permission to test, and installed iperf3 on the invoking host.
No credentials, IPs or raw JSON containing peers are logged. A benchmark on
this host's default route is NOT proof of Xray/REALITY or Entry->Exit quality.
"""
import argparse
import ipaddress
import json
import math
import statistics
import subprocess
import sys
import time


class ThroughputError(Exception):pass


def prepare(ip,port,seconds,samples,*,allow_private=False,reverse=False):
    try:addr=ipaddress.IPv4Address(ip)
    except (ValueError,TypeError) as exc:raise ThroughputError('INVALID_IPV4') from exc
    if not addr.is_global:
        if not (allow_private and addr.is_private and not addr.is_multicast and not addr.is_unspecified):
            raise ThroughputError('NONPUBLIC_TARGET_REQUIRES_EXPLICIT_APPROVAL')
    if type(port) is not int or not 1025<=port<=65535 or type(seconds) is not int or not 3<=seconds<=15:
        raise ThroughputError('PORT_OR_DURATION_INVALID')
    if type(samples) is not int or not 1<=samples<=3 or type(reverse) is not bool:
        raise ThroughputError('SAMPLES_OR_DIRECTION_INVALID')
    return ['iperf3','--client',str(addr),'--port',str(port),'--time',str(seconds),
            '--json','--parallel','1','--connect-timeout','3000'] + (['--reverse'] if reverse else [])


def parse(raw):
    try:
        if isinstance(raw,bytes):raw=raw.decode('utf-8',errors='strict')
        if not isinstance(raw,str) or len(raw)>2*1024*1024:raise ValueError()
        record=json.loads(raw)
        if not isinstance(record,dict) or record.get('error') or not isinstance(record.get('end'),dict):
            raise ValueError()
        end=record['end']
        received=end.get('sum_received')
        sent=end.get('sum_sent')
        if not isinstance(received,dict) or not isinstance(sent,dict):raise ValueError()
        speed=received.get('bits_per_second')
        retr=sent.get('retransmits')
        if type(speed) not in (int,float) or not math.isfinite(speed) or speed<=0 or speed>1e12:
            raise ValueError()
        if retr is None:retr=0  # older iperf3 versions may omit retransmits
        if type(retr) is not int or retr<0:raise ValueError()
        return {'mbps':round(speed/1e6,2),'retransmits':retr}
    except (ValueError,TypeError,KeyError,UnicodeError,OverflowError) as exc:
        raise ThroughputError('IPERF3_RESULT_INVALID') from exc


def run(ip,port,seconds,samples,*,allow_private=False,reverse=False,runner=subprocess.run):
    cmd=prepare(ip,port,seconds,samples,allow_private=allow_private,reverse=reverse)
    results=[];errors={}
    for _ in range(samples):
        try:
            cp=runner(cmd,capture_output=True,stdin=subprocess.DEVNULL,
                      text=True,timeout=seconds+10,check=False)
            if cp.returncode!=0:raise ThroughputError('IPERF3_RUN_FAILED')
            results.append(parse(cp.stdout))
        except (OSError,subprocess.TimeoutExpired):
            errors['IPERF3_NOT_INSTALLED_OR_TIMEOUT']=errors.get('IPERF3_NOT_INSTALLED_OR_TIMEOUT',0)+1
        except ThroughputError as e:
            errors[str(e)]=errors.get(str(e),0)+1
    throughputs=[x['mbps'] for x in results]
    return {'schema':1,'status':'PASS' if len(results)==samples else 'REVIEW',
            'measure':'DIRECT_TCP_IPERF3_NOT_VPN', 'direction':'reverse' if reverse else 'forward',
            'samples':samples,'completed':len(results),'errors':errors,
            'mbps_min':min(throughputs) if throughputs else None,
            'mbps_median':round(statistics.median(throughputs),2) if throughputs else None,
            'mbps_max':max(throughputs) if throughputs else None,
            'retransmits_total':sum(x['retransmits'] for x in results),
            'limitations':['Operator-controlled iperf3 peer required; no server provisioned',
                           'No peer IPs/client identities/raw JSON in output',
                           'Not a VPN throughput, DPI resistance, or REALITY test']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--server',required=True,help='IPv4 of an explicitly authorized iperf3 server')
    p.add_argument('--port',type=int,default=5201)
    p.add_argument('--seconds',type=int,default=5)
    p.add_argument('--samples',type=int,default=2)
    p.add_argument('--allow-private',action='store_true')
    p.add_argument('--reverse',action='store_true')
    p.add_argument('--strict',action='store_true')
    a=p.parse_args(argv)
    try:
        result=run(a.server,a.port,a.seconds,a.samples,
                   allow_private=a.allow_private,reverse=a.reverse)
    except (ThroughputError,ValueError,TypeError):
        print('THROUGHPUT_PROBE=STOP INVALID_ARGUMENTS',file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2,sort_keys=True))
    return 2 if a.strict and result['status']!='PASS' else 0

if __name__=='__main__':sys.exit(main())
