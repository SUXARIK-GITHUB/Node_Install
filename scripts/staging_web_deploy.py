#!/usr/bin/env python3
"""Opt-in, rollbackable cover theme and loopback TCP stream deployment.

New completed staging VKARMANI nodes only. No Docker/Panel/UFW/SSH/443 changes,
no apt installation, no automatic execution during the node install. A failed
health check rolls back the exact owned files. A crash leaves a recoverable
root-only journal. Never use this script as a production migration.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile

try:
    from cover_variants import NAMES, SITES, render
    from nginx_proxy_plan import generate, port
except ImportError:
    from scripts.cover_variants import NAMES, SITES, render
    from scripts.nginx_proxy_plan import generate, port

MARKER_BEGIN = '    # VKARMANI_R7_STYLE_BEGIN\n'
MARKER_END = '    # VKARMANI_R7_STYLE_END\n'
STYLE_LOCATION = (MARKER_BEGIN +
                  '    location = /style.css { try_files $uri =404; expires -1; }\n' +
                  MARKER_END)
STREAM_BLOCK = '\n# VKARMANI_R7_STREAM_BEGIN\nstream {\n    include /etc/nginx/vkarmani-stream-r7/servers.conf;\n}\n# VKARMANI_R7_STREAM_END\n'
SENSITIVE = {'INSTALL_FAILED', 'image-update-pending', 'network-rollback-armed',
             'network-rollback-running', 'cover-pending'}
ROOT = Path('/')


class DeployError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def must(test, why):
    if not test:
        raise DeployError(why)


def path_check(path, root=ROOT, missing=False):
    """Reject symlinks in the selected path AND each existing ancestor."""
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise DeployError('PATH_OUTSIDE_ROOT') from exc
    cur = root
    must(not cur.is_symlink(), 'SYMLINK_ROOT')
    for item in relative.parts:
        cur = cur / item
        if cur.is_symlink():
            raise DeployError('SYMLINK_PATH')
    if not missing:
        must(path.exists(), 'REQUIRED_PATH_MISSING')
    return path


def read(path, root=ROOT, limit=512*1024):
    path_check(path, root)
    st = path.lstat()
    must(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit,
         'INVALID_FILE')
    return path.read_bytes()


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic(path, data, root=ROOT, mode=0o644):
    path_check(path, root, missing=True)
    must(path.parent.is_dir(), 'PARENT_MISSING')
    fd, name = tempfile.mkstemp(prefix='.vk-r7-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(name): os.unlink(name)


def remove(path, root=ROOT):
    path_check(path, root, missing=True)
    path.unlink(missing_ok=True)
    sync_dir(path.parent)


class NodeWeb:
    def __init__(self, root=ROOT, run=None, css_check=None):
        self.root = Path(root)
        self.run = run or self._run
        self.css_check = css_check or self._check_css
        self.state = self.root / 'var/lib/vkarmani-node'
        self.journal = self.state / 'r7-web-deploy'
        self.site = self.root / 'var/www/vkarmani-node/site'
        self.webconf = self.root / 'etc/nginx/conf.d/20-vkarmani-selfsteal.conf'
        self.mainconf = self.root / 'etc/nginx/nginx.conf'
        self.streamconf = self.root / 'etc/nginx/vkarmani-stream-r7/servers.conf'

    @staticmethod
    def _run(args):
        try:
            r = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=35, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeployError('COMMAND_UNAVAILABLE_OR_TIMEOUT') from exc
        if r.returncode:
            raise DeployError('SERVICE_CHECK_FAILED_' + Path(args[0]).name.upper().replace('-', '_'))
        return r.stdout

    def _check_css(self, config, expected, css_name='style.css'):
        domain, ip = config['domain'], config['public_ipv4']
        cmd=['curl','-q','--noproxy','*','-4','--fail','--silent','--show-error',
             '--http2','--tlsv1.3','--tls-max','1.3','--connect-timeout','5',
             '--max-time','15','--max-filesize',str(128*1024),
             '--resolve',f'{domain}:443:{ip}',f'https://{domain}/{css_name}']
        actual=self.run(cmd)
        must(actual==expected,'LIVE_CSS_NOT_SERVED')

    def _activate(self, css=None, config=None, css_name='style.css'):
        # Staging changes must be activated, not only syntactically validated.
        self.run(['nginx','-t'])
        self.run(['systemctl','reload','nginx'])
        self.run(['systemctl','is-active','--quiet','nginx'])
        self.run(['/usr/local/sbin/vkarmani-selfsteal-check'])
        if css is not None:
            self.css_check(config,css,css_name)

    def _check(self, full=True):
        self.run(['nginx','-t'])
        self.run(['systemctl','is-active','--quiet','nginx'])
        if full:
            # This existing checker compares served HTTPS / to site/index.html.
            # It also checks real local REALITY selfsteal TLS and its certificate.
            self.run(['/usr/local/sbin/vkarmani-selfsteal-check'])

    def ready(self):
        path_check(self.state, self.root)
        must(self.state.is_dir(), 'STATE_DIR_INVALID')
        if self.root == ROOT:
            for target in (self.state, self.root/'etc/vkarmani-node'):
                st=target.lstat()
                must(st.st_uid==0 and stat.S_ISDIR(st.st_mode) and
                     stat.S_IMODE(st.st_mode)&0o077==0,
                     'UNSAFE_PRIVATE_CONFIG_DIRECTORY')
            for target in (self.state/'owned-installation',self.state/'INSTALL_COMPLETE',
                           self.state/'install-version',self.root/'etc/vkarmani-node/config.json'):
                st=target.lstat()
                must(st.st_uid==0 and stat.S_ISREG(st.st_mode) and
                     stat.S_IMODE(st.st_mode)&0o077==0,'UNSAFE_PRIVATE_STATE_FILE')
        # install.sh creates this ownership marker with `touch` (zero bytes).
        # Existence, regular-file type, single link and private ownership/mode
        # are checked by read() and the root-only checks above, not contents.
        read(self.state/'owned-installation',self.root,256)
        version=read(self.state/'install-version',self.root,32).decode().strip()
        must(version in ('2.5.11','2.5.12','2.5.13','2.5.14'), 'UNSUPPORTED_STAGING_INSTALL_VERSION')
        complete=read(self.state/'INSTALL_COMPLETE',self.root,2048).decode()
        # Refuse an incompatible marker rather than assuming all sites are 2.5.11.
        must(re.search(r'(?m)^version='+re.escape(version)+r'$',complete) is not None,
             'INSTALL_NOT_COMPLETE')
        for marker in SENSITIVE:
            must(not (self.state/marker).exists() and not (self.state/marker).is_symlink(),
                 'OTHER_TRANSACTION_PENDING')
        config=json.loads(read(self.root/'etc/vkarmani-node/config.json',self.root,16384))
        must(config.get('installation_mode')=='secret-key-only', 'FOREIGN_NODE_CONFIGURATION')
        must(re.fullmatch(r'[a-z0-9.-]{4,253}', config.get('domain','')),
             'INVALID_DOMAIN')
        ip=ipaddress.ip_address(config.get('public_ipv4',''))
        must(ip.version==4 and ip.is_global, 'INVALID_IPV4')
        return config

    @contextmanager
    def lock(self):
        if not self.journal.exists():
            path_check(self.journal,self.root,missing=True)
            self.journal.mkdir(mode=0o700)
        path_check(self.journal,self.root)
        must(self.journal.is_dir(), 'INVALID_JOURNAL')
        if self.root == ROOT:
            st=self.journal.lstat()
            must(st.st_uid==0 and stat.S_IMODE(st.st_mode)&0o077==0,
                 'INSECURE_DEPLOYMENT_JOURNAL')
        lock=self.journal/'lock'
        path_check(lock,self.root,missing=True)
        fd=os.open(lock,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        except BlockingIOError as exc:
            raise DeployError('ANOTHER_DEPLOY_IN_PROGRESS') from exc
        finally: os.close(fd)

    def receipt(self, kind):
        p=self.journal/(kind+'.json')
        if not p.exists() and not p.is_symlink(): return None
        data=json.loads(read(p,self.root,32768))
        must(isinstance(data,dict) and data.get('schema')==1 and
             data.get('kind')==kind and data.get('stage') in ('pending','active','rolled_back'),
             'INVALID_RECEIPT')
        return data

    def write_receipt(self,kind,item):
        atomic(self.journal/(kind+'.json'), (json.dumps(item,sort_keys=True,indent=2)+'\n').encode(),self.root,0o600)

    def backup(self,kind,items,metadata):
        must(self.receipt(kind) is None or self.receipt(kind)['stage']=='rolled_back',
             'PREVIOUS_DEPLOY_ACTIVE_OR_PENDING')
        # Never reuse a previous backup directory.
        b=self.journal/(kind+'-'+secrets.token_hex(10))
        path_check(b,self.root,missing=True); b.mkdir(mode=0o700)
        originals={}
        for label,path in items.items():
            old=None if not path.exists() and not path.is_symlink() else read(path,self.root)
            originals[label]=old
            if old is not None:
                atomic(b/(label+'.before'),old,self.root,0o600)
        r={'schema':1,'kind':kind,'stage':'pending','backup':b.name,
           'metadata':metadata,'files':{label:{'was_present':value is not None,
                    'before_sha':digest(value) if value is not None else None,
                    'before_mode':stat.S_IMODE(items[label].lstat().st_mode) if value is not None else None,
                    'after_sha':None}
                    for label,value in originals.items()}}
        self.write_receipt(kind,r)
        return r,originals

    def verify_receipt_backups(self,r,files):
        b=self.journal/r['backup']
        must(b.parent==self.journal and re.fullmatch(r'(site|tcp)-[0-9a-f]{20}',b.name),
             'BACKUP_PATH_INVALID')
        path_check(b,self.root)
        originals={}
        must(set(r['files'])==set(files), 'RECEIPT_FILESET_MISMATCH')
        for label,p in files.items():
            meta=r['files'][label]
            must(set(meta) in ({'was_present','before_sha','after_sha'},
                               {'was_present','before_sha','before_mode','after_sha'}),
                 'INVALID_RECEIPT_FILE')
            if 'before_mode' in meta:
                mode=meta['before_mode']
                must((mode is None and not meta['was_present']) or
                     (type(mode) is int and 0 <= mode <= 0o777 and meta['was_present']),
                     'INVALID_RECEIPT_FILE_MODE')
            if meta['was_present']:
                data=read(b/(label+'.before'),self.root)
                must(digest(data)==meta['before_sha'],'BACKUP_HASH_MISMATCH')
            else: data=None
            originals[label]=data
        return originals

    @staticmethod
    def original_mode(meta):
        # Backwards-compatible with an r7b pending journal; new r7c receipts
        # preserve the exact owner file mode instead of widening permissions.
        mode=meta.get('before_mode')
        return 0o644 if mode is None else mode

    def recovery(self,kind,r,files,checker):
        originals=self.verify_receipt_backups(r,files)
        # Check all paths before touching ANY of them. In pending stage, any path
        # may be original, new or absent if we were interrupted before that write.
        for label,p in files.items():
            current=None if not p.exists() else read(p,self.root)
            allowed={r['files'][label]['before_sha'],r['files'][label]['after_sha']}
            must((digest(current) if current is not None else None) in allowed,
                 'THIRD_PARTY_CHANGE_REFUSE_ROLLBACK')
        for label,p in files.items():
            old=originals[label]
            if old is not None:
                atomic(p,old,self.root,self.original_mode(r['files'][label]))
            else:
                remove(p,self.root)
        checker()
        r['stage']='rolled_back'
        self.write_receipt(kind,r)
        return kind.upper()+'_ROLLBACK=PASS'

    @staticmethod
    def css_name(css):
        # The installed Selfsteal checker and Nginx location accept ONLY local,
        # content-addressed assets: assets/style-<first 20 hex of sha256>.css.
        return 'assets/style-'+digest(css)[:20]+'.css'

    def site_files(self, receipt=None, css_name=None):
        if receipt is not None:
            meta=receipt.get('metadata') or {}
            if 'nginx' in receipt.get('files',{}):
                # r7..r7f journal: unversioned style.css + edited Nginx location.
                return {'index':self.site/'index.html',
                        'css':self.site/'style.css',
                        'nginx':self.webconf}
            css_name=meta.get('css')
        must(isinstance(css_name,str) and
             re.fullmatch(r'assets/style-[0-9a-f]{20}[.]css',css_name) is not None,
             'INVALID_THEME_ASSET_NAME')
        targets={'index':self.site/'index.html','css':self.site/css_name}
        if receipt is None or (receipt.get('metadata') or {}).get('theme_bundle')==2:
            targets['error']=self.site/'404.html'
            targets['favicon']=self.site/'favicon.svg'
        return targets

    def site_install(self,theme,expect_domain):
        must(theme in NAMES,'UNKNOWN_THEME')
        config=self.ready()
        current=self.receipt('site')
        must(current is None or current['stage']=='rolled_back', 'PREVIOUS_DEPLOY_ACTIVE_OR_PENDING')
        must(expect_domain==config['domain'],'DOMAIN_CONFIRMATION_MISMATCH')
        for d in (self.site,self.webconf.parent):
            path_check(d,self.root); must(d.is_dir(),'DIR_INVALID')
        source=SITES/theme
        # Verify reviewed catalog files and symlink absence. Rendering changes
        # only deterministic editorial choices based on the validated domain.
        for filename in ('index.html','style.css','404.html','favicon.svg'):
            read(source/filename,SITES.parent,128*1024)
        try:
            content=render(theme,config['domain'])
        except (OSError,ValueError) as exc:
            raise DeployError('THEME_RENDER_FAILED') from exc
        html,css,error,icon=(content[name] for name in
                              ('index.html','style.css','404.html','favicon.svg'))
        must(html.count(b'href="style.css"')==1 and
             error.count(b'href="style.css"')==1 and
             b'<script' not in html.lower() and b'<script' not in error.lower() and
             b'@import' not in css and b'url(' not in css and
             b'<script' not in icon.lower() and b'<foreignobject' not in icon.lower(),
             'UNREVIEWED_THEME_CONTENT')
        css_name=self.css_name(css)
        for_page=b'href="/'+css_name.encode()+b'"'
        html=html.replace(b'href="style.css"',for_page)
        html=html.replace(b'href="favicon.svg"', b'href="/favicon.svg"')
        error=error.replace(b'href="style.css"',for_page)
        files=self.site_files(css_name=css_name)
        assets=self.site/'assets'
        path_check(assets,self.root); must(assets.is_dir(),'DIR_INVALID')
        # The existing Selfsteal Nginx already serves versioned assets with
        # its security headers and cache policy; it is verified, never edited.
        conf=read(self.webconf,self.root)
        selected = config.get('reality_mode', 'local')
        socket_path = (b'/run/vkarmani-selfsteal/nginx.sock' if selected == 'local' else
                       b'/run/vkarmani-selfsteal/cover.sock')
        must(b'listen unix:' + socket_path in conf and
             b'root /var/www/vkarmani-node/site;' in conf and
             b'style-[0-9a-f]{20}[.]css' in conf,
             'FOREIGN_OR_UNSUPPORTED_SELFSTEAL')
        must(not files['css'].exists() and not files['css'].is_symlink(),
             'THEME_ASSET_ALREADY_PRESENT')
        self._check()
        with self.lock():
            r,old=self.backup('site',files,{'theme':theme,'domain':config['domain'],
                                             'css':css_name,'theme_bundle':2})
            targets={'index':html,'css':css,'error':error,'favicon':icon}
            for label in targets: r['files'][label]['after_sha']=digest(targets[label])
            self.write_receipt('site',r)
            try:
                # Publish independent assets and error page before the atomic
                # homepage swap. All four files are journaled for rollback.
                for label in ('css','favicon','error','index'):
                    expected=old[label]
                    cur=None if not files[label].exists() else read(files[label],self.root)
                    must(cur==expected,'CONCURRENT_SITE_MODIFICATION')
                    atomic(files[label],targets[label],self.root,
                           self.original_mode(r['files'][label]))
                self._activate(css=css,config=config,css_name=css_name)
                r['stage']='active';self.write_receipt('site',r)
                return 'SITE_DEPLOY=PASS theme='+theme+' SELFSTEAL_LOCAL_CHECK=PASS'
            except BaseException:
                try:
                    print(self.recovery('site',r,files,self._activate),file=sys.stderr)
                except BaseException:
                    print('SITE_RECOVERY=PENDING MANUAL_ROLLBACK_REQUIRED',file=sys.stderr)
                raise

    def site_rollback(self):
        self.ready()
        with self.lock():
            r=self.receipt('site')
            must(r is not None and r['stage'] in ('pending','active'), 'NO_SITE_ROLLBACK')
            return self.recovery('site',r,self.site_files(receipt=r),self._activate)

    def tcp_files(self):
        return {'main':self.mainconf,'fragment':self.streamconf}

    @staticmethod
    def preflight_ports(listen,backend):
        l,b=port(listen),port(backend)
        must(l!=b,'PROXY_SELF_LOOP')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as test:
            test.settimeout(2)
            try: test.bind(('127.0.0.1',l))
            except OSError as exc: raise DeployError('LISTEN_PORT_IN_USE') from exc
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as test:
            test.settimeout(2)
            try: test.connect(('127.0.0.1',b))
            except OSError as exc: raise DeployError('BACKEND_UNAVAILABLE') from exc
        return l,b

    def tcp_install(self,listen,backend,portcheck=True):
        self.ready()
        l,b=self.preflight_ports(listen,backend) if portcheck else (port(listen),port(backend))
        must(l!=b,'PROXY_SELF_LOOP')
        self._check()
        original=read(self.mainconf,self.root)
        # Conservative, dedicated-node-only edit: refuse foreign stream setups.
        must(not self.streamconf.exists() and not self.streamconf.is_symlink() and
             b'VKARMANI_R7_STREAM' not in original and
             re.search(rb'(?m)^\s*events\s*{',original) and
             re.search(rb'(?m)^\s*http\s*{',original) and
             not re.search(rb'(?m)^\s*stream\s*{',original),
             'EXISTING_OR_NONSTANDARD_STREAM_CONFIGURATION')
        new_main=original + STREAM_BLOCK.encode()
        # Existing generator emits a *top level stream{}*; our include contains
        # ONLY the server{} content to avoid a nested stream{} syntax error.
        proposed=generate('tcp',l,b)
        lines=proposed.splitlines()
        must('stream {' in lines and '    server {' in lines and lines[-1]=='}',
             'UNEXPECTED_PROXY_PLAN')
        content='\n'.join(lines[lines.index('    server {'): -1])+'\n'
        if not self.streamconf.parent.exists():
            path_check(self.streamconf.parent,self.root,missing=True)
            self.streamconf.parent.mkdir(mode=0o755)
        with self.lock():
            files=self.tcp_files()
            r,old=self.backup('tcp',files,{'listen':l,'backend':b})
            desired={'main':new_main,'fragment':content.encode()}
            for label in desired:r['files'][label]['after_sha']=digest(desired[label])
            self.write_receipt('tcp',r)
            try:
                atomic(self.streamconf,desired['fragment'],self.root)
                must(read(self.mainconf,self.root)==old['main'],'CONCURRENT_NGINX_EDIT')
                atomic(self.mainconf,new_main,self.root,
                       self.original_mode(r['files']['main']))
                self._activate()
                if portcheck:
                    with socket.create_connection(('127.0.0.1',l),timeout=3):pass
                r['stage']='active';self.write_receipt('tcp',r)
                return 'TCP_DEPLOY=PASS LOOPBACK_ONLY CONNECT_TEST=PASS' if portcheck else 'TCP_DEPLOY=PASS OFFLINE_MOCK'
            except BaseException:
                try:
                    print(self.recovery('tcp',r,files,self._activate),file=sys.stderr)
                except BaseException:
                    print('TCP_RECOVERY=PENDING MANUAL_ROLLBACK_REQUIRED',file=sys.stderr)
                raise

    def tcp_rollback(self):
        self.ready()
        with self.lock():
            r=self.receipt('tcp')
            must(r is not None and r['stage'] in ('pending','active'),'NO_TCP_ROLLBACK')
            return self.recovery('tcp',r,self.tcp_files(),self._activate)

    def status(self):
        self.ready()
        return {'site':None if self.receipt('site') is None else self.receipt('site')['stage'],
                'tcp':None if self.receipt('tcp') is None else self.receipt('tcp')['stage']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('site-deploy');a.add_argument('--theme',required=True,choices=NAMES)
    a.add_argument('--expected-domain',required=True);a.add_argument('--confirm-staging',action='store_true')
    b=sub.add_parser('tcp-deploy');b.add_argument('--listen',type=int,required=True)
    b.add_argument('--backend',type=int,required=True);b.add_argument('--confirm-staging',action='store_true')
    for name in ('site-rollback','tcp-rollback'):
        q=sub.add_parser(name);q.add_argument('--confirm-staging',action='store_true')
    sub.add_parser('status')
    args=p.parse_args(argv)
    if os.geteuid()!=0:
        print('DEPLOY=STOP ROOT_REQUIRED',file=sys.stderr);return 2
    if args.action!='status' and not args.confirm_staging:
        print('DEPLOY=STOP EXPLICIT_STAGING_CONFIRMATION_REQUIRED',file=sys.stderr);return 2
    try:
        app=NodeWeb()
        if args.action=='site-deploy': result=app.site_install(args.theme,args.expected_domain)
        elif args.action=='tcp-deploy':result=app.tcp_install(args.listen,args.backend)
        elif args.action=='site-rollback':result=app.site_rollback()
        elif args.action=='tcp-rollback':result=app.tcp_rollback()
        else:result=json.dumps(app.status(),sort_keys=True)
        print(result);return 0
    except (DeployError,ValueError,OSError,subprocess.TimeoutExpired,KeyError,json.JSONDecodeError) as exc:
        print('DEPLOY=STOP '+(str(exc) if isinstance(exc,DeployError) else type(exc).__name__),file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
