#!/usr/bin/env python3
"""Optional, host-interface IPv4 traffic policing and cumulative byte quotas.

No change to qdisc, default firewall, Docker, SSH or routing. Opt-in rules live
in a separate, dedicated nftables table; management/SSH ports are exempt so a
quota can never intentionally lock out the administrator. The limit is for
host input/output on the selected default-route NIC, not traffic forwarded by
an unrelated bridge, or provider billing adjustments.

Rate limits use nft byte-rate *policing* (drop over the rate), not smooth tc
shaping. Counters are snapshotted periodically; a sudden unclean power loss
may under-count the bytes since the last snapshot. Quotas do not auto-reset.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

CONFIG=Path('/etc/vkarmani-node/traffic-limits.json')
USAGE=Path('/var/lib/vkarmani-node/traffic-used.json')
SSH_PORTS=Path('/etc/vkarmani-node/ssh-ports')
NODE_CONFIG=Path('/etc/vkarmani-node/config.json')
INSTALLED=Path('/var/lib/vkarmani-node/INSTALL_COMPLETE')
SCRIPTPATH=Path('/usr/local/lib/vkarmani-node/traffic_limits.py')
UNIT=Path('/etc/systemd/system/vkarmani-traffic-limits.service')
SNAPSHOT_UNIT=Path('/etc/systemd/system/vkarmani-traffic-snapshot.service')
TIMER=Path('/etc/systemd/system/vkarmani-traffic-snapshot.timer')
TABLE='vkarmani_node_traffic'
MARKER='VKARMANI_NODE_TRAFFIC_V1'
MAX_MBPS=20000
MAX_GIB=100000


class SafeStop(Exception):pass


def run(args, *, input_data=None, timeout=12):
    try:
        result=subprocess.run(args,input=input_data,text=True,capture_output=True,
                              timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise SafeStop('REQUIRED_COMMAND_UNAVAILABLE_OR_TIMEOUT') from exc
    if result.returncode:
        raise SafeStop('COMMAND_FAILED_'+Path(args[0]).name.upper())
    return result.stdout


def read_private(path,limit=16384):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or \
           info.st_nlink!=1 or info.st_size>limit:
            raise SafeStop('UNSAFE_PRIVATE_FILE_'+path.name)
        result=os.read(fd,limit+1)
        if len(result)>limit:raise SafeStop('PRIVATE_FILE_TOO_LARGE')
        return result.decode('utf-8')
    finally:os.close(fd)


def atomic_private(path,data):
    if path.exists() or path.is_symlink():
        read_private(path,65536)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as output:
            os.fchmod(output.fileno(),0o600)
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(name,path)
        dfd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if os.path.exists(name):os.unlink(name)


def inputs(mbps_in,mbps_out,gib_in,gib_out):
    values={'in_mbps':mbps_in,'out_mbps':mbps_out,'in_gib':gib_in,'out_gib':gib_out}
    if any(type(n) is not int or not 0<=n<=(MAX_MBPS if 'mbps' in key else MAX_GIB)
           for key,n in values.items()):
        raise SafeStop('INVALID_RATE_OR_QUOTA')
    if not any(values.values()):raise SafeStop('ALL_LIMITS_DISABLED')
    return values


def network_identity():
    route=json.loads(run(['ip','-j','-4','route','show','default']))
    devices={row.get('dev') for row in route if isinstance(row,dict) and row.get('dev')}
    if len(devices)!=1:raise SafeStop('AMBIGUOUS_DEFAULT_ROUTE')
    interface=next(iter(devices))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):raise SafeStop('INVALID_INTERFACE')
    ports=[]
    for raw in read_private(SSH_PORTS,4096).splitlines():
        if raw.strip():
            if not re.fullmatch('[0-9]{1,5}',raw):raise SafeStop('BAD_SSH_PORT')
            port=int(raw)
            if not 1<=port<=65535:raise SafeStop('BAD_SSH_PORT')
            ports.append(port)
    if not ports:raise SafeStop('NO_SSH_PORTS_REFUSE_LIMITS')
    node=json.loads(read_private(NODE_CONFIG))
    api_port=node.get('node_port')
    if type(api_port) is not int or not 1024<=api_port<=65535:
        raise SafeStop('INVALID_NODE_MANAGEMENT_PORT')
    return interface,sorted(set(ports+[api_port]))


def validate_config(config):
    if not isinstance(config,dict) or set(config)!={'schema','interface','exempt_ports','limits'} or config['schema']!=1:
        raise SafeStop('BAD_TRAFFIC_CONFIG')
    interface=config['interface']
    if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):
        raise SafeStop('BAD_INTERFACE')
    ports=config['exempt_ports']
    if not isinstance(ports,list) or not ports or len(ports)>20 or any(type(p) is not int or not 1<=p<=65535 for p in ports):
        raise SafeStop('BAD_EXEMPT_PORTS')
    limits=config['limits']
    if not isinstance(limits,dict) or set(limits)!={'in_mbps','out_mbps','in_gib','out_gib'}:
        raise SafeStop('BAD_LIMIT_KEYS')
    inputs(**{'mbps_in':limits['in_mbps'],'mbps_out':limits['out_mbps'],
              'gib_in':limits['in_gib'],'gib_out':limits['out_gib']})
    return config


def nft_objects():
    """Return named counters/quotas of *our table*; None means not installed."""
    process=subprocess.run(['nft','-j','list','table','inet',TABLE],capture_output=True,text=True,timeout=10)
    if process.returncode:
        if 'No such file' in process.stderr or 'No such file' in process.stdout:
            return None
        raise SafeStop('NFT_TABLE_QUERY_FAILED')
    try:
        records=json.loads(process.stdout)['nftables']
    except (ValueError,KeyError,TypeError) as exc:raise SafeStop('BAD_NFT_JSON') from exc
    objects={}
    for row in records:
        if isinstance(row,dict):
            for key in ('counter','quota','chain'):
                value=row.get(key)
                if isinstance(value,dict) and value.get('table')==TABLE:
                    objects[(key,value.get('name'))]=value
    marker=objects.get(('counter','incoming_count'))
    if not marker or marker.get('comment')!=MARKER or not objects.get(('counter','outgoing_count')) or \
       not objects.get(('chain','incoming')) or not objects.get(('chain','outgoing')):
        raise SafeStop('FOREIGN_OR_MODIFIED_NFT_TABLE')
    return objects


def restore_counts():
    if not USAGE.exists() and not USAGE.is_symlink():return {'in':0,'out':0}
    payload=json.loads(read_private(USAGE,4096))
    if not isinstance(payload,dict) or payload.get('schema')!=1 or set(payload)!= {'schema','in','out'} or \
       any(type(payload[name]) is not int or payload[name]<0 for name in ('in','out')):
        raise SafeStop('BAD_USAGE_SNAPSHOT')
    return {name:payload[name] for name in ('in','out')}


def snapshot():
    obj=nft_objects()
    if obj is None:raise SafeStop('LIMIT_RULESET_NOT_RUNNING')
    previous=restore_counts()
    used={}
    for side in ('in','out'):
        counter=obj[('counter','incoming_count' if side=='in' else 'outgoing_count')]
        total=counter.get('bytes')
        if type(total) is not int or total<0:raise SafeStop('MISSING_NFT_BYTE_COUNTER')
        used[side]=max(previous[side],total)
        quota=obj.get(('quota','incoming_quota' if side=='in' else 'outgoing_quota'))
        if quota is not None:
            count=quota.get('used')
            if type(count) is not int or count<0:raise SafeStop('BAD_NFT_QUOTA')
            used[side]=max(used[side],count)
    atomic_private(USAGE,json.dumps({'schema':1,**used},sort_keys=True)+'\n')
    return used


def rules(config,used):
    validate_config(config)
    iface=config['interface']
    quoted='"'+iface+'"'
    # 'tcp dport' on ingress and 'tcp sport' on egress protects SSH and Node API
    # while preserving their existing UFW allowlist (no broad port openings).
    port_list='{ '+', '.join(str(p) for p in config['exempt_ports'])+' }'
    result=[f'table inet {TABLE} {{',
       f'  counter incoming_count {{ packets 0 bytes {used["in"]}; comment "{MARKER}"; }}',
       f'  counter outgoing_count {{ packets 0 bytes {used["out"]}; comment "{MARKER}"; }}']
    for side in ('in','out'):
        amount=config['limits'][side+'_gib']
        if amount:
            result.append(f'  quota {"incoming" if side=="in" else "outgoing"}_quota '
                          f'{{ over {amount*1024**3} bytes used {used[side]} bytes; }}')
    for side in ('in','out'):
        incoming=side=='in';chain='incoming' if incoming else 'outgoing'
        selector='iifname' if incoming else 'oifname'
        result.extend([f'  chain {chain} {{',
                 f'    type filter hook {"input" if incoming else "output"} priority 10; policy accept;',
                 f'    {selector} {quoted} tcp {"dport" if incoming else "sport"} {port_list} accept',
                 f'    {selector} {quoted} counter name "{chain}_count"'])
        amount=config['limits'][side+'_gib']
        if amount:result.append(f'    {selector} {quoted} quota name "{chain}_quota" drop')
        speed=config['limits'][side+'_mbps']
        if speed:result.append(f'    {selector} {quoted} limit rate over {speed*125000} bytes/second drop')
        result.append('  }')
    result.append('}')
    return '\n'.join(result)+'\n'


def nft_apply(config):
    network_iface,ports=network_identity()
    if network_iface!=config['interface'] or sorted(ports)!=sorted(config['exempt_ports']):
        raise SafeStop('NETWORK_OR_SSH_PORTS_CHANGED_REFUSE')
    previous=nft_objects()
    if previous is not None:
        # Do not reset the running quota/counters on repeated service restarts.
        return 'ALREADY_ACTIVE'
    used=restore_counts()
    payload=rules(config,used)
    run(['nft','-c','-f','-'],input_data=payload)
    run(['nft','-f','-'],input_data=payload)
    if nft_objects() is None:raise SafeStop('NFT_RULES_NOT_INSTALLED')
    return 'ACTIVE'


def reset_quotas(config):
    """Operator-confirmed start of a new billing period, one nft transaction."""
    if nft_objects() is None:raise SafeStop('LIMIT_RULESET_NOT_RUNNING')
    iface,ports=network_identity()
    if iface!=config['interface'] or sorted(ports)!=sorted(config['exempt_ports']):
        raise SafeStop('NETWORK_OR_SSH_PORTS_CHANGED_REFUSE')
    payload=f'delete table inet {TABLE}\n'+rules(config,{'in':0,'out':0})
    run(['nft','-c','-f','-'],input_data=payload)
    run(['nft','-f','-'],input_data=payload)
    atomic_private(USAGE,json.dumps({'schema':1,'in':0,'out':0},sort_keys=True)+'\n')
    return 'RESET_CONFIRMED'


def setup_units():
    units={
        UNIT:'''[Unit]
Description=VKarmani opt-in traffic caps (protected SSH and Node API)
Wants=network-online.target
After=network-online.target ufw.service
ConditionPathExists=/etc/vkarmani-node/traffic-limits.json
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/vkarmani-node/traffic_limits.py apply
ExecStop=/usr/bin/python3 -I -B /usr/local/lib/vkarmani-node/traffic_limits.py snapshot
TimeoutStartSec=40
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
''',
        SNAPSHOT_UNIT:'''[Unit]
Description=VKarmani traffic usage checkpoint
After=vkarmani-traffic-limits.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/vkarmani-node/traffic_limits.py snapshot
TimeoutStartSec=20
''',
        TIMER:'''[Unit]
Description=Checkpoint traffic usage every minute
[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
Unit=vkarmani-traffic-snapshot.service
[Install]
WantedBy=timers.target
'''
    }
    for path,data in units.items():
        if path.exists() or path.is_symlink():
            old=path.read_text()
            if old!=data:raise SafeStop('UNREVIEWED_SYSTEMD_UNIT_'+path.name)
        else:
            # First installation never overwrites a foreign unit or symlink.
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
            with os.fdopen(fd,'w') as f:f.write(data)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now',UNIT.name])
    run(['systemctl','enable','--now',TIMER.name])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('configure','apply','activate','snapshot','status','reset'))
    parser.add_argument('--confirm-new-period',action='store_true')
    for flag in ('in-mbps','out-mbps','in-gib','out-gib'):
        parser.add_argument('--'+flag,type=int,default=0)
    args=parser.parse_args(argv)
    if os.geteuid()!=0:raise SafeStop('ROOT_REQUIRED')
    if args.action=='configure':
        if not INSTALLED.is_file() or INSTALLED.is_symlink():raise SafeStop('INSTALL_NOT_COMPLETE')
        if CONFIG.exists() or CONFIG.is_symlink():raise SafeStop('LIMITS_ALREADY_CONFIGURED')
        if nft_objects() is not None:raise SafeStop('FOREIGN_TRAFFIC_RULES_PRESENT')
        values=inputs(args.in_mbps,args.out_mbps,args.in_gib,args.out_gib)
        iface,ports=network_identity()
        config=validate_config({'schema':1,'interface':iface,'exempt_ports':ports,'limits':values})
        # Check nft syntax BEFORE creating persistent config or units.
        run(['nft','-c','-f','-'],input_data=rules(config,{'in':0,'out':0}))
        atomic_private(CONFIG,json.dumps(config,sort_keys=True,indent=2)+'\n')
        nft_apply(config)
        setup_units()
        print('TRAFFIC_LIMITS=ACTIVE; scope=host_default_interface; ssh_and_node_api=EXEMPT; quota_reset=MANUAL')
        return 0
    config=validate_config(json.loads(read_private(CONFIG)))
    if args.action=='apply':
        print('TRAFFIC_LIMITS='+nft_apply(config))
    elif args.action=='activate':
        nft_apply(config);setup_units()
        print('TRAFFIC_LIMITS=ACTIVE')
    elif args.action=='reset':
        if not args.confirm_new_period:raise SafeStop('EXPLICIT_NEW_BILLING_PERIOD_CONFIRMATION_REQUIRED')
        print('TRAFFIC_LIMITS='+reset_quotas(config))
    elif args.action=='snapshot':
        print('TRAFFIC_USAGE_SNAPSHOT='+json.dumps(snapshot(),sort_keys=True))
    else:
        obj=nft_objects()
        print('TRAFFIC_LIMITS='+('ACTIVE' if obj else 'NOT_ACTIVE'))
        print('TRAFFIC_CONFIG='+json.dumps(config,sort_keys=True))
        print('TRAFFIC_USAGE_SAVED='+json.dumps(restore_counts(),sort_keys=True))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (SafeStop,ValueError,TypeError,KeyError,OSError,subprocess.TimeoutExpired) as exc:
        print('TRAFFIC_LIMITS=STOP '+(str(exc) if isinstance(exc,SafeStop) else 'INVALID_RUNTIME_STATE'),file=sys.stderr)
        raise SystemExit(2)
