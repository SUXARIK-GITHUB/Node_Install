#!/usr/bin/env python3
"""Compare two read-only Network Engine diagnostic snapshots.

No probes/host changes. Calculates counter *deltas* rather than claiming
cumulative counters are instantaneous rates. Does not print peer/client IPs.
"""
import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys

MAX_BYTES=512*1024
ALLOWED_TCP=('ListenOverflows','ListenDrops','TCPTimeouts','TCPSynRetrans','TCPBacklogDrop')


def _read(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>MAX_BYTES:
            raise ValueError('INVALID_SNAPSHOT_FILE')
        with os.fdopen(fd,'rb') as f:
            fd=-1;raw=f.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:raise ValueError('SNAPSHOT_TOO_BIG')
        data=json.loads(raw)
        if not isinstance(data,dict) or data.get('schema')!=1 or data.get('actions_performed')!='NONE':
            raise ValueError('SNAPSHOT_SCHEMA_MISMATCH')
        return data
    finally:
        if fd>=0:os.close(fd)


def _extract(data,group,name):
    sub=data.get(group)
    if not isinstance(sub,dict) or sub.get('verified') is not True:
        return None
    if group=='tcp_host_counters':
        sub=sub.get('counters',{})
    v=sub.get(name)
    return v if type(v)==int and v>=0 else None


def _delta(a,b,seconds):
    if a is None or b is None:
        return {'status':'UNAVAILABLE'}
    if b<a:
        return {'status':'RESET_OR_RESTART'}
    difference=b-a
    return {'status':'OK','delta':difference,'per_second':round(difference/seconds,3)}


def compare(before,after,seconds):
    if isinstance(seconds,bool) or type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds<=0 or seconds>86400*7:
        raise ValueError('INVALID_SNAPSHOT_INTERVAL')
    result={'schema':1,'status':'INFO','seconds':seconds,'deltas':{},
            'observations':[], 'actions_performed':'NONE',
            'limitations':['Snapshots must be collected from the same host without a reboot',
                           'Counter deltas estimate host events, not individual client quality',
                           'No VPN performance or censorship resistance is inferred']}
    a,b=before.get('network_interface'),after.get('network_interface')
    if not a or not b or a!=b:
        result['observations'].append('PRIMARY_INTERFACE_CHANGED_OR_UNKNOWN')
        result['status']='REVIEW'
        return result
    keys=(('interface_counters',('rx_packets','rx_bytes','rx_dropped','rx_errors',
                                 'tx_packets','tx_bytes','tx_dropped','tx_errors')),
          ('softnet',('processed_cumulative','dropped_cumulative','time_squeeze_cumulative')),
          ('qdisc',('queue_drops_cumulative',)),
          ('tcp_host_counters',ALLOWED_TCP))
    for group,fields in keys:
        result['deltas'][group]={}
        for key in fields:
            result['deltas'][group][key]=_delta(_extract(before,group,key),_extract(after,group,key),seconds)
            d=result['deltas'][group][key]
            if d['status']=='RESET_OR_RESTART':result['observations'].append('COUNTER_RESET_'+group+'_'+key)
            if key in ('rx_dropped','tx_dropped','rx_errors','tx_errors','dropped_cumulative',
                       'queue_drops_cumulative','ListenOverflows','ListenDrops','TCPTimeouts',
                       'TCPSynRetrans','TCPBacklogDrop') and d.get('delta',0)>0:
                result['observations'].append('NEW_ERROR_OR_DROP_'+group+'_'+key)
    if before.get('parameters',{}).get('congestion_control')!=after.get('parameters',{}).get('congestion_control'):
        result['observations'].append('TCP_CONGESTION_CONTROL_CHANGED')
    if before.get('qdisc',{}).get('kinds')!=after.get('qdisc',{}).get('kinds'):
        result['observations'].append('QDISC_KINDS_CHANGED')
    result['observations']=sorted(set(result['observations']))
    if result['observations']:result['status']='REVIEW'
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('before',type=Path)
    p.add_argument('after',type=Path)
    p.add_argument('--seconds',required=True,type=float)
    p.add_argument('--strict',action='store_true')
    a=p.parse_args(argv)
    try:
        report=compare(_read(a.before),_read(a.after),a.seconds)
    except (ValueError,OSError,TypeError,UnicodeError):
        print(json.dumps({'status':'FAIL','reason':'SNAPSHOT_INVALID_OR_UNREADABLE','actions_performed':'NONE'}))
        return 1
    print(json.dumps(report,sort_keys=True,indent=2))
    return 2 if a.strict and report['status']!='INFO' else 0


if __name__=='__main__':sys.exit(main())
