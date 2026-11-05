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
    from cover_rich import render_rich, PAGES
    from site_catalog import NAMES as CATALOG_NAMES, THEMES as CATALOG, SITES as CATALOG_SITES
    from site_audit import audit_bundle
    from nginx_proxy_plan import generate, port
except ImportError:
    from scripts.cover_variants import NAMES, SITES, render
    from scripts.cover_rich import render_rich, PAGES
    from scripts.site_catalog import NAMES as CATALOG_NAMES, THEMES as CATALOG, SITES as CATALOG_SITES
    from scripts.site_audit import audit_bundle
    from scripts.nginx_proxy_plan import generate, port

MARKER_BEGIN = '    # VKARMANI_R7_STYLE_BEGIN\n'
MARKER_END = '    # VKARMANI_R7_STYLE_END\n'
STYLE_LOCATION = (MARKER_BEGIN +
                  '    location = /style.css { try_files $uri =404; expires -1; }\n' +
                  MARKER_END)
STREAM_BLOCK = '\n# VKARMANI_R7_STREAM_BEGIN\nstream {\n    include /etc/nginx/vkarmani-stream-r7/servers.conf;\n}\n# VKARMANI_R7_STREAM_END\n'
RICH_MARKER = b'    # VKARMANI_R20_RICH_BEGIN\n'
RICH_LOCATIONS = (RICH_MARKER +
    b'    location = /journal.html { try_files $uri =404; expires -1; }\n'
    b'    location = /about.html { try_files $uri =404; expires -1; }\n'
    b'    location = /questions.html { try_files $uri =404; expires -1; }\n'
    b'    location = /sitemap.xml { default_type application/xml; try_files $uri =404; expires -1; }\n'
    b'    # VKARMANI_R20_RICH_END\n')
RICH_INDEX_LOCATION = b'    location = /index.html { try_files $uri =404; expires -1; }\n'
HYBRID_MARKER = '# VKARMANI_HYBRID_STREAM_V1'
HYBRID_TAIL_R18 = (HYBRID_MARKER + '\nstream {\n'
    '    include /etc/nginx/vkarmani-hybrid-stream.conf;\n'
    '    include /etc/nginx/vkarmani-stream-r7/*.conf;\n}\n')
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

    def _check_rich_live(self, config, content):
        """Compare exact HTTPS bytes of each additional page after reload.

        Uses the node's assigned public IPv4 with the actual hostname and public
        CA verification. Fail the deploy transaction on any wrong/partial page.
        """
        domain, ip = config['domain'], config['public_ipv4']
        for path in (*PAGES, 'robots.txt', 'sitemap.xml'):
            cmd = ['curl', '-q', '--noproxy', '*', '-4', '--fail',
                   '--silent', '--show-error', '--http2', '--tlsv1.3',
                   '--tls-max', '1.3', '--connect-timeout', '5', '--max-time', '15',
                   '--max-filesize', str(128 * 1024),
                   '--resolve', f'{domain}:443:{ip}', f'https://{domain}/{path}']
            must(self.run(cmd) == content[path], 'RICH_LIVE_ROUTE_NOT_VERIFIED_' + path)

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
        must(version in ('2.5.11','2.5.12','2.5.13','2.5.14','2.5.15','2.5.16','2.5.17','2.5.18'), 'UNSUPPORTED_STAGING_INSTALL_VERSION')
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

    def backup(self,kind,items,metadata,allow_active=False):
        existing=self.receipt(kind)
        must(existing is None or existing['stage']=='rolled_back' or
             (allow_active and kind=='site' and existing['stage']=='active'),
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
        must(b.parent==self.journal and re.fullmatch(r'(site|tcp|xhttp)-[0-9a-f]{20}',b.name),
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

    def site_files(self, receipt=None, css_name=None, rich=False):
        if receipt is not None:
            meta = receipt.get('metadata') or {}
            if meta.get('theme_bundle') != 3 and 'nginx' in receipt.get('files', {}):
                # Legacy R7 receipt: unversioned style.css and edited location.
                return {'index': self.site/'index.html',
                        'css': self.site/'style.css', 'nginx': self.webconf}
            css_name = meta.get('css')
            rich = meta.get('theme_bundle') == 3
        must(isinstance(css_name, str) and
             re.fullmatch(r'assets/style-[0-9a-f]{20}[.]css', css_name) is not None,
             'INVALID_THEME_ASSET_NAME')
        targets = {'index': self.site/'index.html', 'css': self.site/css_name}
        if receipt is None or (receipt.get('metadata') or {}).get('theme_bundle') in (2, 3):
            targets['error'] = self.site/'404.html'
            targets['favicon'] = self.site/'favicon.svg'
        if rich:
            targets.update({'journal': self.site/'journal.html',
                            'about': self.site/'about.html',
                            'questions': self.site/'questions.html',
                            'robots': self.site/'robots.txt',
                            'sitemap': self.site/'sitemap.xml',
                            'nginx': self.webconf})
        if receipt is not None:
            stale = (receipt.get('metadata') or {}).get('stale_css')
            if stale is not None:
                must(isinstance(stale,str) and re.fullmatch(r'assets/style-[0-9a-f]{20}[.]css',stale),
                     'INVALID_STALE_CSS_NAME')
                must(stale != css_name,'STALE_AND_NEW_CSS_COLLISION')
                targets['stale_css'] = self.site/stale
        return targets

    def site_install(self, theme, expect_domain, rich_pages=False, switch=False):
        must(theme in NAMES + CATALOG_NAMES, 'UNKNOWN_THEME')
        must(theme not in CATALOG_NAMES or rich_pages, 'CATALOG_REQUIRES_RICH_PAGES')
        config = self.ready()
        current = self.receipt('site')
        if switch:
            must(rich_pages,'SITE_CHANGE_REQUIRES_RICH_PAGES')
            must(current is not None and current['stage'] == 'active',
                 'SITE_CHANGE_REQUIRES_ACTIVE_SITE')
            must(current.get('metadata',{}).get('theme_bundle') == 3,
                 'SITE_CHANGE_REQUIRES_PREVIOUS_RICH_THEME')
        else:
            must(current is None or current['stage'] == 'rolled_back',
                 'PREVIOUS_DEPLOY_ACTIVE_OR_PENDING')
        must(expect_domain == config['domain'], 'DOMAIN_CONFIRMATION_MISMATCH')
        for d in (self.site, self.webconf.parent):
            path_check(d, self.root); must(d.is_dir(), 'DIR_INVALID')
        source = (CATALOG_SITES if theme in CATALOG_NAMES else SITES) / theme
        for filename in ('index.html', 'style.css', '404.html', 'favicon.svg'):
            read(source/filename, source.parent.parent, 128*1024)
        try:
            content = render_rich(theme, config['domain']) if rich_pages else render(theme, config['domain'])
            audit_bundle(content, config['domain'], rich=rich_pages)
        except (OSError, ValueError, TypeError) as exc:
            raise DeployError('THEME_RENDER_OR_AUDIT_FAILED') from exc
        html, css, error, icon = (content[name] for name in
                                  ('index.html', 'style.css', '404.html', 'favicon.svg'))
        must(html.count(b'href="style.css"') == 1 and
             error.count(b'href="style.css"') == 1 and
             b'<script' not in html.lower() and b'<script' not in error.lower() and
             b'@import' not in css and b'url(' not in css and
             b'<script' not in icon.lower() and b'<foreignobject' not in icon.lower(),
             'UNREVIEWED_THEME_CONTENT')
        css_name = self.css_name(css)
        prior_css = (current.get('metadata') or {}).get('css') if switch else None
        if switch:
            must(isinstance(prior_css,str) and
                 re.fullmatch(r'assets/style-[0-9a-f]{20}[.]css',prior_css),
                 'PRIOR_THEME_ASSET_INVALID')
            must(prior_css != css_name,'SITE_CHANGE_ALREADY_INSTALLED_CSS')
        for_page = b'href="/' + css_name.encode() + b'"'
        targets = {'index': html.replace(b'href="style.css"', for_page).replace(
                       b'href="favicon.svg"', b'href="/favicon.svg"'),
                   'css': css,
                   'error': error.replace(b'href="style.css"', for_page),
                   'favicon': icon}
        if rich_pages:
            for label, filename in (('journal','journal.html'), ('about','about.html'),
                                    ('questions','questions.html')):
                targets[label] = content[filename].replace(b'href="/style.css"', for_page).replace(b'href="style.css"', for_page)
            targets['robots'] = content['robots.txt']
            targets['sitemap'] = content['sitemap.xml']
        files = self.site_files(css_name=css_name, rich=rich_pages)
        if switch:
            files['stale_css'] = self.site/prior_css
        assets = self.site/'assets'
        path_check(assets, self.root); must(assets.is_dir(), 'DIR_INVALID')
        conf = read(self.webconf, self.root)
        selected = config.get('reality_mode', 'local')
        socket_path = (b'/run/vkarmani-selfsteal/nginx.sock' if selected == 'local' else
                       b'/run/vkarmani-selfsteal/cover.sock')
        must(b'listen unix:' + socket_path in conf and
             b'root /var/www/vkarmani-node/site;' in conf and
             b'style-[0-9a-f]{20}[.]css' in conf,
             'FOREIGN_OR_UNSUPPORTED_SELFSTEAL')
        if rich_pages:
            # Existing managed Nginx configuration only. No global wildcard,
            # regex route or generic try_files that could expose private files.
            must(conf.count(RICH_INDEX_LOCATION) == 1 and
                 b'location = /robots.txt' in conf and b'location / { return 404; }' in conf,
                 'RICH_REQUIRES_REVIEWED_NGINX_CONFIG')
            if switch:
                must(conf.count(RICH_LOCATIONS) == 1,
                     'SITE_CHANGE_REQUIRES_EXISTING_RICH_NGINX')
                targets['nginx'] = conf  # do not rewrite a working stream/SSL config
                previous_files=self.site_files(receipt=current)
                for label,path in previous_files.items():
                    expected_hash=current['files'][label]['after_sha']
                    if expected_hash is None:
                        must(not path.exists() and not path.is_symlink(),
                             'PRIOR_SITE_STALE_FILE_REAPPEARED_'+label)
                    else:
                        actual_hash=digest(read(path,self.root))
                        must(actual_hash == expected_hash,
                             'PRIOR_SITE_CHANGED_OUTSIDE_MANAGED_DEPLOYMENT_'+label)
                must(files['stale_css'].exists() and not files['stale_css'].is_symlink(),
                     'PRIOR_THEME_CSS_MISSING')
            else:
                must(RICH_MARKER not in conf,'RICH_CONFIGURATION_ALREADY_INSTALLED')
                targets['nginx'] = conf.replace(RICH_INDEX_LOCATION,
                                                 RICH_INDEX_LOCATION + RICH_LOCATIONS, 1)
                for label in ('journal', 'about', 'questions', 'sitemap'):
                    must(not files[label].exists() and not files[label].is_symlink(),
                         'RICH_PATH_ALREADY_OWNED_OR_PRESENT_' + label)
                # Installer-owned robots.txt is replaced only when its bytes match.
                robots = files['robots']
                if robots.exists() or robots.is_symlink():
                    must(read(robots, self.root, 4096) == b'User-agent: *\nDisallow:\n',
                         'UNREVIEWED_EXISTING_ROBOTS')
        must(not files['css'].exists() and not files['css'].is_symlink(),
             'THEME_ASSET_ALREADY_PRESENT')
        self._check()
        with self.lock():
            must(self.receipt('site') == current, 'CONCURRENT_SITE_RECEIPT_CHANGE')
            metadata={'theme': theme, 'domain': config['domain'],
                      'css': css_name, 'theme_bundle': 3 if rich_pages else 2}
            archived_previous = None
            if switch:
                # Preserve the previous active journal before replacing its pointer.
                # This makes a later rollback restore the previous live theme,
                # including its backed-up pre-site version.
                archived_previous = 'site-previous-' + secrets.token_hex(10) + '.json'
                prior_data = (json.dumps(current,sort_keys=True,indent=2)+'\n').encode()
                atomic(self.journal/archived_previous,prior_data,self.root,0o600)
                metadata.update({'previous_receipt':archived_previous,
                                 'previous_receipt_sha':digest(prior_data),
                                 'stale_css':prior_css})
            r, old = self.backup('site', files, metadata, allow_active=switch)
            for label in targets:
                r['files'][label]['after_sha'] = digest(targets[label])
            self.write_receipt('site', r)
            try:
                # Publish assets first. Swap the homepage last so all existing
                # local references are ready before any new link is served.
                order = ('css', 'favicon', 'error')
                if rich_pages:
                    order += ('journal', 'about', 'questions', 'robots', 'sitemap', 'nginx')
                order += ('index',)
                for label in order:
                    expected = old[label]
                    cur = None if not files[label].exists() else read(files[label], self.root)
                    must(cur == expected, 'CONCURRENT_SITE_MODIFICATION')
                    atomic(files[label], targets[label], self.root,
                           self.original_mode(r['files'][label]))
                self._activate(css=css, config=config, css_name=css_name)
                if rich_pages:
                    live = dict(content)
                    for label, filename in (('journal','journal.html'),
                                            ('about','about.html'), ('questions','questions.html'),
                                            ('robots','robots.txt'), ('sitemap','sitemap.xml')):
                        live[filename] = targets[label]
                    self._check_rich_live(config, live)
                if switch:
                    # Do not leave the previous CSS publicly accessible after success;
                    # its content remains in the private receipt backup for rollback.
                    remove(files['stale_css'],self.root)
                r['stage'] = 'active'; self.write_receipt('site', r)
                return ('SITE_DEPLOY=PASS theme=' + theme +
                        (' RICH_PAGES=VERIFIED' if rich_pages else '') +
                        ' SELFSTEAL_LOCAL_CHECK=PASS')
            except BaseException:
                try:
                    print(self.recovery('site', r, files, self._activate), file=sys.stderr)
                    if switch:
                        # Recovery restored the old files: recover the old journal too.
                        self.write_receipt('site', current)
                except BaseException:
                    print('SITE_RECOVERY=PENDING MANUAL_ROLLBACK_REQUIRED', file=sys.stderr)
                raise

    def _previous_site_receipt(self, receipt):
        metadata=receipt.get('metadata') or {}
        name=metadata.get('previous_receipt')
        if name is None:
            return None
        must(isinstance(name,str) and re.fullmatch(r'site-previous-[0-9a-f]{20}[.]json',name),
             'INVALID_PREVIOUS_RECEIPT_NAME')
        content=read(self.journal/name,self.root,32768)
        must(digest(content)==metadata.get('previous_receipt_sha'),
             'PREVIOUS_RECEIPT_HASH_MISMATCH')
        old=json.loads(content)
        must(isinstance(old,dict) and old.get('schema')==1 and
             old.get('kind')=='site' and old.get('stage')=='active' and
             isinstance(old.get('metadata'),dict),
             'PREVIOUS_RECEIPT_INVALID')
        self.verify_receipt_backups(old,self.site_files(receipt=old))
        return old

    def _resume_previous_site(self, switched, previous):
        """Finish a switch rollback interrupted AFTER the files were restored.

        Recovery writes the rolled_back receipt before restoring the previous
        active pointer. That intermediary is deliberate and must be resumable.
        Confirm *every* file matches the previous signed active receipt before
        reactivating it, rather than merely rewriting the journal by assumption.
        """
        must(switched.get('stage') == 'rolled_back' and previous is not None,
             'NO_VERIFIED_PREVIOUS_SITE_RECOVERY')
        files = self.site_files(receipt=previous)
        must(set(files) == set(previous.get('files', {})), 'PREVIOUS_RECEIPT_FILESET_MISMATCH')
        for label, path in files.items():
            expected = previous['files'][label].get('after_sha')
            current = None if not path.exists() and not path.is_symlink() else read(path, self.root)
            must((digest(current) if current is not None else None) == expected,
                 'RESTORED_PREVIOUS_SITE_DRIFT_' + label.upper())
        self._check()  # no new mutations; verify restored services before journal change
        self.write_receipt('site', previous)
        return 'SITE_CHANGE_ROLLBACK=PASS PREVIOUS_THEME_RESTORED'

    def site_rollback(self):
        self.ready()
        with self.lock():
            r = self.receipt('site')
            must(r is not None, 'NO_SITE_ROLLBACK')
            if r['stage'] == 'rolled_back':
                # Interrupted after recovery() committed rolled_back but before
                # the previous receipt was made active. Repeated calls are safe.
                previous = self._previous_site_receipt(r)
                must(previous is not None, 'NO_SITE_ROLLBACK')
                return self._resume_previous_site(r, previous)
            must(r['stage'] in ('pending', 'active'), 'NO_SITE_ROLLBACK')
            previous = self._previous_site_receipt(r)
            result = self.recovery('site', r, self.site_files(receipt=r), self._activate)
            if previous is not None:
                # On a crash/failure at this point the rolled_back receipt is
                # retained and a subsequent call can resume without guessing.
                return self._resume_previous_site(r, previous)
            return result

    def tcp_files(self,hybrid=False,receipt=None):
        if receipt is not None:
            recorded = set(receipt.get('files', {}))
            must(recorded in ({'main', 'fragment'}, {'fragment'}), 'TCP_RECEIPT_FILESET_INVALID')
            hybrid = recorded == {'fragment'}
        return {'fragment':self.streamconf} if hybrid else {
            'main':self.mainconf, 'fragment':self.streamconf}

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
        config=self.ready()
        l,b=self.preflight_ports(listen,backend) if portcheck else (port(listen),port(backend))
        must(l!=b,'PROXY_SELF_LOOP')
        self._check()
        original=read(self.mainconf,self.root)
        must(not self.streamconf.exists() and not self.streamconf.is_symlink() and
             b'VKARMANI_R7_STREAM' not in original and
             re.search(rb'(?m)^\s*events\s*{',original) and
             re.search(rb'(?m)^\s*http\s*{',original),
             'EXISTING_OR_NONSTANDARD_STREAM_CONFIGURATION')
        hybrid = HYBRID_MARKER.encode() in original
        if not hybrid:
            must(config.get('reality_mode', 'local') == 'local',
                 'HYBRID_MARKER_MISSING_REFUSE_STREAM_EDIT')
        if hybrid:
            # Only R18+ installer-owned stream root, exactly as generated.
            # Old hybrid installations require an explicit reviewed migration.
            must(config.get('reality_mode') in ('max.ru','ya.ru','rutube.ru','mail.ru'),
                 'HYBRID_CONFIGURATION_MODE_MISMATCH')
            before, sep, tail = original.partition(HYBRID_MARKER.encode())
            must(sep and tail == HYBRID_TAIL_R18.encode()[len(sep):] and
                 original.count(sep) == 1 and
                 not re.search(rb'(?m)^\s*stream\s*{',before),
                 'HYBRID_STREAM_REQUIRES_R18_INCLUDE')
            # The original top-level stream remains byte-for-byte untouched.
            new_main=original
        else:
            must(not re.search(rb'(?m)^\s*stream\s*{',original),
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
            files=self.tcp_files(hybrid=hybrid)
            r,old=self.backup('tcp',files,{'listen':l,'backend':b,
                                           'hybrid_fragment_only':hybrid,
                                           'main_sha':digest(original) if hybrid else None})
            desired={'fragment':content.encode()}
            if not hybrid: desired['main']=new_main
            for label in desired:r['files'][label]['after_sha']=digest(desired[label])
            self.write_receipt('tcp',r)
            try:
                must(read(self.mainconf,self.root)==original, 'CONCURRENT_NGINX_EDIT')
                atomic(self.streamconf,desired['fragment'],self.root)
                must(read(self.mainconf,self.root)==original, 'CONCURRENT_NGINX_EDIT')
                if not hybrid:
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
            if set(r.get('files', {})) == {'fragment'}:
                must(r.get('metadata', {}).get('hybrid_fragment_only') is True and
                     digest(read(self.mainconf,self.root)) ==
                     r['metadata'].get('main_sha'),
                     'THIRD_PARTY_HYBRID_MAIN_EDIT_REFUSE_ROLLBACK')
            return self.recovery('tcp',r,self.tcp_files(receipt=r),self._activate)

    def xhttp_tls_install(self, expected_domain, path, backend_port, backend_check=True):
        """Stage one H2 grpc_pass route; never touch Xray/Panel or TCP/443.

        A previously deployed rich site must first be rolled back, otherwise
        its signed nginx receipt would no longer match. Later rich site deploys
        can safely coexist because they preserve this reviewed extra location.
        """
        from importlib.util import module_from_spec, spec_from_file_location
        source = Path(__file__).resolve().parents[1] / 'integrations/optional_transports.py'
        spec=spec_from_file_location('vk_optional_transports',source)
        must(spec is not None and spec.loader is not None,'TRANSPORT_HELPER_UNAVAILABLE')
        helper=module_from_spec(spec)
        spec.loader.exec_module(helper)
        config=self.ready()
        must(expected_domain == config['domain'], 'DOMAIN_CONFIRMATION_MISMATCH')
        must(config.get('cascade_role') in (None, '', 'ordinary'),
             'CASCADE_ENTRY_OR_EXIT_NOT_SUPPORTED_FOR_OPTIONAL_H2_ROUTE')
        bundle=helper.xhttp_tls(config['domain'],backend_port,path)
        current_site=self.receipt('site')
        must(current_site is None or current_site['stage']=='rolled_back',
             'ROLLBACK_MANAGED_SITE_BEFORE_OPTIONAL_XHTTP_ROUTE')
        self._check()
        original=read(self.webconf,self.root)
        ending=b'    location / { return 404; }'
        marker=b'    # VKARMANI_R23_XHTTP_TLS_BEGIN\n'
        must(original.count(ending)==1 and marker not in original and
             b'root /var/www/vkarmani-node/site;' in original and
             b'listen unix:/run/vkarmani-selfsteal/' in original and
             b'style-[0-9a-f]{20}[.]css' in original,
             'UNSUPPORTED_OR_FOREIGN_SELFSTEAL_NGINX_CONFIGURATION')
        # On an actual node, the generated server's domain must match exactly.
        if self.root == ROOT:
            must(('server_name ' + expected_domain + ';').encode() in original,
                 'HTTPS_DOMAIN_NOT_PRESENT_IN_NGINX')
        if backend_check:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                try: sock.connect(('127.0.0.1',backend_port))
                except OSError as exc: raise DeployError('XHTTP_BACKEND_NOT_LISTENING') from exc
        snippet=bundle['nginx-location.conf']
        desired=original.replace(ending,marker+snippet+b'    # VKARMANI_R23_XHTTP_TLS_END\n'+ending,1)
        with self.lock():
            must(self.receipt('site')==current_site,'CONCURRENT_MANAGED_SITE_CHANGE')
            r,_=self.backup('xhttp',{'nginx':self.webconf},
                            {'domain':expected_domain,'backend_port':backend_port,
                             'path_sha256':digest(path.encode())})
            r['files']['nginx']['after_sha']=digest(desired)
            self.write_receipt('xhttp',r)
            try:
                must(read(self.webconf,self.root)==original,'CONCURRENT_NGINX_EDIT')
                atomic(self.webconf,desired,self.root,self.original_mode(r['files']['nginx']))
                self._activate()
                r['stage']='active'
                self.write_receipt('xhttp',r)
                return 'XHTTP_TLS_ROUTE_DEPLOY=PASS TLS_SITE_CHECK=PASS VLESS_E2E=NOT_TESTED'
            except BaseException:
                try:
                    print(self.recovery('xhttp',r,{'nginx':self.webconf},self._activate),file=sys.stderr)
                except BaseException:
                    print('XHTTP_ROUTE_RECOVERY=PENDING_MANUAL_ROLLBACK',file=sys.stderr)
                raise

    def xhttp_tls_rollback(self):
        self.ready()
        with self.lock():
            site=self.receipt('site')
            must(site is None or site['stage']=='rolled_back',
                 'ROLLBACK_MANAGED_SITE_BEFORE_XHTTP_ROUTE_REMOVAL')
            r=self.receipt('xhttp')
            must(r is not None and r['stage'] in ('active','pending'),
                 'NO_XHTTP_ROUTE_ROLLBACK')
            must(set(r.get('files',{}))=={'nginx'},'XHTTP_RECEIPT_FILESET_INVALID')
            return self.recovery('xhttp',r,{'nginx':self.webconf},self._activate)

    def status(self):
        self.ready()
        site=self.receipt('site')
        return {'site':None if site is None else site['stage'],
                'site_theme':None if site is None else (site.get('metadata') or {}).get('theme'),
                'tcp':None if self.receipt('tcp') is None else self.receipt('tcp')['stage'],
                'xhttp_tls':None if self.receipt('xhttp') is None else self.receipt('xhttp')['stage']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('site-deploy');a.add_argument('--theme',required=True,choices=NAMES + CATALOG_NAMES)
    a.add_argument('--expected-domain',required=True);a.add_argument('--confirm-staging',action='store_true')
    a.add_argument('--rich-pages',action='store_true',help='stage opt-in three-page site with exact Nginx routes')
    change=sub.add_parser('site-change',help='transactionally replace an already active rich site; restore previous on failure')
    change.add_argument('--theme',required=True,choices=NAMES + CATALOG_NAMES)
    change.add_argument('--expected-domain',required=True)
    change.add_argument('--confirm-staging',action='store_true')
    b=sub.add_parser('tcp-deploy');b.add_argument('--listen',type=int,required=True)
    b.add_argument('--backend',type=int,required=True);b.add_argument('--confirm-staging',action='store_true')
    x=sub.add_parser('xhttp-tls-deploy',help='optional reviewed Nginx H2 route on staging only')
    x.add_argument('--expected-domain',required=True)
    x.add_argument('--path',required=True)
    x.add_argument('--backend-port',required=True,type=int)
    x.add_argument('--confirm-staging',action='store_true')
    for name in ('site-rollback','tcp-rollback','xhttp-tls-rollback'):
        q=sub.add_parser(name);q.add_argument('--confirm-staging',action='store_true')
    sub.add_parser('status')
    sub.add_parser('site-catalog', help='read-only list of available themes, no root or installation')
    preview=sub.add_parser('site-preview', help='generate complete local HTML, no VPS changes')
    preview.add_argument('--theme', choices=NAMES + CATALOG_NAMES, required=True)
    preview.add_argument('--domain', default='preview.example.test')
    preview.add_argument('--output', type=Path, required=True)
    args=p.parse_args(argv)
    if args.action == 'site-catalog':
        try:
            from cover_variants import THEMES as ORIGINAL
        except ImportError:
            from scripts.cover_variants import THEMES as ORIGINAL
        for name in NAMES + CATALOG_NAMES:
            if name in ORIGINAL:
                category = ORIGINAL[name]['label']
                title = ORIGINAL[name]['names'][0]
            else:
                category = CATALOG[name].category
                title = CATALOG[name].title
            print(f'{name}\t{category}\t{title}')
        return 0
    if args.action == 'site-preview':
        try:
            out=args.output
            path_check(out, ROOT, missing=True)
            must(not out.exists() and out.parent.is_dir(), 'PREVIEW_DESTINATION_EXISTS_OR_PARENT_MISSING')
            bundle=render_rich(args.theme, args.domain)
            audit_bundle(bundle, args.domain, rich=True)
            out.mkdir(mode=0o755)
            try:
                for name, content in bundle.items():
                    dest = out / name
                    path_check(dest, ROOT, missing=True)
                    with dest.open('xb') as fp:
                        fp.write(content)
                    dest.chmod(0o644)
            except BaseException:
                for name in bundle:
                    (out / name).unlink(missing_ok=True)
                out.rmdir()
                raise
            print('SITE_PREVIEW=PASS files=' + str(len(bundle)) + ' theme=' + args.theme)
            return 0
        except (DeployError, ValueError, OSError) as exc:
            print('SITE_PREVIEW=STOP ' + str(exc),file=sys.stderr)
            return 1
    if os.geteuid()!=0:
        print('DEPLOY=STOP ROOT_REQUIRED',file=sys.stderr);return 2
    if args.action!='status' and not args.confirm_staging:
        print('DEPLOY=STOP EXPLICIT_STAGING_CONFIRMATION_REQUIRED',file=sys.stderr);return 2
    try:
        app=NodeWeb()
        if args.action=='site-deploy': result=app.site_install(args.theme,args.expected_domain,rich_pages=args.rich_pages)
        elif args.action=='site-change': result=app.site_install(args.theme,args.expected_domain,rich_pages=True,switch=True)
        elif args.action=='tcp-deploy':result=app.tcp_install(args.listen,args.backend)
        elif args.action=='xhttp-tls-deploy':result=app.xhttp_tls_install(args.expected_domain,args.path,args.backend_port)
        elif args.action=='xhttp-tls-rollback':result=app.xhttp_tls_rollback()
        elif args.action=='site-rollback':result=app.site_rollback()
        elif args.action=='tcp-rollback':result=app.tcp_rollback()
        else:result=json.dumps(app.status(),sort_keys=True)
        print(result);return 0
    except (DeployError,ValueError,OSError,subprocess.TimeoutExpired,KeyError,json.JSONDecodeError) as exc:
        print('DEPLOY=STOP '+(str(exc) if isinstance(exc,DeployError) else type(exc).__name__),file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
