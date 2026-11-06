#!/usr/bin/env python3
"""Node Install interactive terminal front-end (stdlib curses; no new services).

The existing Bash installer remains the only authority for system mutations.
This UI never silently alters OS settings, never logs secret input and never
calls an unreviewed uninstall. SSH-friendly arrow/number controls and a separate
scrollable command log; plain fallback for terminals lacking curses capability.
"""
import argparse
import base64
import curses
import fcntl
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time
import unicodedata
from collections import deque

ROOT=Path(__file__).resolve().parents[1]
INSTALLER=ROOT/'install.sh'
STATE=Path('/var/lib/vkarmani-node')
SCRIPTS=ROOT/'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))
from site_catalog import NAMES as GENERATED, THEMES as GENERATED_META
from cover_variants import NAMES as HANDMADE, THEMES as HANDMADE_META
INTEGRATIONS=ROOT/'integrations'
if str(INTEGRATIONS) not in sys.path:
    sys.path.insert(0,str(INTEGRATIONS))
import vps_report
THEMES=tuple(HANDMADE)+tuple(GENERATED)

def theme_meta(theme):
    if theme in GENERATED_META:
        t=GENERATED_META[theme]
        return (t.title,t.category,t.headline,t.language)
    meta=HANDMADE_META[theme]
    return (meta['label'],meta['section'],meta['intro'],'ru')

REALITY=('local','max.ru','ya.ru','rutube.ru','mail.ru')
USAGE_HINT='↑↓/jk выбор · Enter открыть · Esc назад · 0 выход'
MAX_LOG_LINES=2400
INSTALL_LOG_DIR=Path('/root')
REALITY_KEYS_FILE=Path('/root/reality-keys.txt')
MAX_INSTALL_LOG_BYTES=64*1024*1024
ANSI_ESCAPE=re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])')
LOG_SECRET=re.compile(r'(?i)(\b(?:SECRET_KEY|PrivateKey|nodeKeyPem|PASSWORD|API_TOKEN|API_KEY)\s*[:=]\s*)(\S+)')

def release_label():
    # Cosmetic only: never trust this in place of the installer release verifier.
    try:
        data=json.loads((ROOT/'BUILD_MANIFEST.json').read_text(encoding='utf-8'))
        build=data.get('build_id','')
        revision=re.search(r'-r([0-9]{2})-',build)
        return 'v2.5.18 r'+revision.group(1) if revision else 'v2.5.18'
    except (OSError,ValueError,TypeError):
        return 'v2.5.18'



def validate_domain(value):
    if not isinstance(value,str) or not value or len(value)>253 or value.endswith('..'):
        raise ValueError('INVALID_DOMAIN')
    name=value.lower().rstrip('.')
    if (name.count('.')<1 or len(name)>253 or re.fullmatch(r'[0-9.]+',name)):
        raise ValueError('INVALID_DOMAIN')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',x) or len(x)>63 for x in name.split('.')):
        raise ValueError('INVALID_DOMAIN')
    return name


def validate_panel_ip(value):
    try:ip=ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:raise ValueError('INVALID_IPV4') from exc
    if not ip.is_global:
        raise ValueError('PANEL_IPV4_MUST_BE_PUBLIC')
    return str(ip)


def validate_panel_target(value):
    """The panel may be identified by a public IPv4 or a DNS hostname.

    DNS is resolved and pinned by the installer before firewall setup; merely
    accepting a hostname here must not weaken the management port allowlist.
    """
    if not isinstance(value,str):raise ValueError('INVALID_PANEL_TARGET')
    value=value.strip()
    try:
        return validate_panel_ip(value)
    except ValueError:
        if re.fullmatch(r'[0-9.]+',value):
            raise ValueError('INVALID_PANEL_IPV4') from None
    name=validate_domain(value)
    if name.endswith(('.local','.localhost','.internal','.invalid','.test')):
        raise ValueError('PANEL_HOST_MUST_BE_PUBLIC_DNS')
    return name


def validate_secret(value):
    if value.startswith('SECRET_KEY='):
        value=value[len('SECRET_KEY='):]
    if value and value[0] in "\"'" and value[-1]==value[0]:
        value=value[1:-1]
    if not 64<=len(value)<=65536 or not re.fullmatch(r'[A-Za-z0-9_+/=-]+',value):
        raise ValueError('INVALID_SECRET_KEY_FORMAT')
    return value


def choose_random_theme(chooser=secrets.choice):
    # Selection is made once for a wizard run; retries and reloads reuse the ID.
    return chooser(THEMES)


def wizard_argv(settings, *, fd):
    """No private value is ever placed in argv or environment."""
    if settings['mode'] not in ('ordinary','entry','exit'):
        raise ValueError('INVALID_ROLE')
    validate_domain(settings['domain'])
    validate_panel_target(settings['panel_ip'])
    if settings['mode']=='ordinary' and settings['reality'] not in REALITY:
        raise ValueError('INVALID_REALITY')
    args=['bash',str(INSTALLER),'--wizard-input-fd',str(fd),'--no-reboot']
    if settings['mode']=='ordinary':
        if settings.get('site'):
            if settings['site'] not in THEMES:raise ValueError('INVALID_THEME')
            args+=['--site-theme',settings['site']]
        args+=['--reality-mode',settings['reality']]
        port=settings.get('node_port')
        if port is not None:
            if type(port) is not int or port<1024 or port>65535 or port==61001:
                raise ValueError('INVALID_NODE_PORT')
            args+=['--node-port',str(port)]
        if settings.get('weekly_reboot'):
            args+=['--weekly-reboot']
        for key,flag,maximum in (('in_mbps','--traffic-in-mbps',20000),
                                 ('out_mbps','--traffic-out-mbps',20000),
                                 ('in_gib','--traffic-in-gib',100000),
                                 ('out_gib','--traffic-out-gib',100000)):
            value=settings.get(key)
            if value is not None:
                if type(value) is not int or not 1<=value<=maximum:
                    raise ValueError('INVALID_TRAFFIC_LIMIT')
                args.extend((flag,str(value)))
    else:
        bundle=Path(settings['bundle'])
        if not bundle.is_absolute() or '..' in bundle.parts:
            raise ValueError('INVALID_BUNDLE_PATH')
        args+=['--cascade-role',settings['mode'],'--cascade-bundle',str(bundle)]
    if not settings.get('no_reboot',True):
        # Default is NO REBOOT to preserve console access until operator checks.
        args=[x for x in args if x!='--no-reboot']
    return args


def secret_fd(secret, panel_ip, domain):
    """Sealed anonymous Linux memory descriptor; never writes a key to disk."""
    secret=validate_secret(secret)
    domain=validate_domain(domain)
    panel_ip=validate_panel_target(panel_ip)
    if not hasattr(os,'memfd_create'):
        raise RuntimeError('LINUX_MEMFD_REQUIRED')
    fd=os.memfd_create('node-install-input',getattr(os,'MFD_CLOEXEC',1)|getattr(os,'MFD_ALLOW_SEALING',2))
    try:
        os.fchmod(fd,0o600)
        contents=(secret+'\n'+domain+'\n'+panel_ip+'\n').encode('ascii')
        sent=0
        while sent<len(contents):
            written=os.write(fd,contents[sent:])
            if written<=0:raise OSError('MEMFD_WRITE_INCOMPLETE')
            sent+=written
        os.lseek(fd,0,os.SEEK_SET)
        try:
            seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals)
        except (OSError,AttributeError):
            # File is still an anonymous fd and is only given to the child.
            pass
        return fd
    except BaseException:
        os.close(fd)
        raise


def status_brief():
    if (STATE/'INSTALL_COMPLETE').is_file():
        return 'NODE: УСТАНОВЛЕНА (локальный маркер; не проверка клиентов)'
    if (STATE/'owned-installation').exists():
        return 'NODE: НЕЗАВЕРШЕНА · требуется диагностика'
    return 'NODE: НОВАЯ VPS / состояние не подтверждено'


def preinstall_state_guard():
    # Prevent offering a new installation on a host already enrolled.
    return not any((STATE/x).exists() or (STATE/x).is_symlink() for x in
                   ('owned-installation','INSTALL_COMPLETE','finalization','role.json','image-update-pending'))


def has_root():
    return os.geteuid()==0


def linewrap(text,width):
    if width<10:return [text[:max(1,width)]]
    parts=[]
    for line in str(text).splitlines() or ['']:
        while len(line)>width:
            cut=line.rfind(' ',0,width)
            if cut<width//3:cut=width
            parts.append(line[:cut]);line=line[cut:].lstrip()
        parts.append(line)
    return parts


def safe_log_line(value, redactions=()):
    """Remove control sequences and obvious credentials before display/disk.

    The installer deliberately does not print REALITY private keys to stdout.
    This filter is a second line of defense, not a substitute for that rule.
    """
    value=ANSI_ESCAPE.sub('',str(value)).replace('\x00','')
    value=''.join(char if char.isprintable() or char=='\t' else ' ' for char in value)
    for private in redactions:
        if private:value=value.replace(private,'[REDACTED]')
    return LOG_SECRET.sub(r'\1[REDACTED]',value)


def log_color(line):
    value=line.upper()
    if re.search(r'(^|\s)(?:ERROR|ОШИБКА|FAILED|FAIL|STOP|TRACEBACK|FATAL|DENIED)(?:\b|[:=])',value) or 'EXIT_CODE=20' in value:
        return 4
    if any(term in value for term in ('WARNING','WARN','REVIEW','PARTIAL','NOT_TESTED','NOT_LISTENING','SKIPPED','ОСТОРОЖНО')):
        return 3
    if any(term in value for term in ('=PASS',' PASS','=OK',' SUCCESS','COMPLETE','ГОТОВО','УСПЕШНО')):
        return 6
    if line.startswith(('Get:','Hit:','Ign:','Fetched','Reading ','Unpacking ','Setting up ')):
        return 7
    if line.startswith(('[', '●','→')):
        return 5
    return 1


def new_install_log(directory=INSTALL_LOG_DIR):
    """Create one private, uniquely named, append-only installation transcript.

    No shared /root/install.log is overwritten and symlinks are never followed.
    `directory` is injectable only for isolated tests; the application always
    uses the compiled-in /root path. No paths come from terminal input.
    """
    if not directory.is_absolute():
        raise OSError('LOG_DIRECTORY_NOT_ABSOLUTE')
    st=directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077:
        raise OSError('UNSAFE_LOG_DIRECTORY')
    if directory==INSTALL_LOG_DIR and not has_root():
        raise PermissionError('ROOT_REQUIRED_FOR_INSTALL_LOG')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW
    stamp=time.strftime('%Y%m%d-%H%M%S',time.localtime())
    for n in range(10):
        path=directory/f'node-install-{stamp}-{os.getpid()}-{n:02}.log'
        try:fd=os.open(path,flags,0o600)
        except FileExistsError:continue
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or \
               stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
                raise OSError('UNSAFE_INSTALL_LOG')
            return fd,path
        except BaseException:
            os.close(fd)
            raise
    raise FileExistsError('INSTALL_LOG_NAME_COLLISION')


class InstallLogSink:
    """Bounded disk transcript, synced as installation progresses."""
    def __init__(self,fd):
        self.fd=fd
        self.bytes_written=0
        self.last_sync=time.monotonic()
        self.truncated=False
        self.error=None

    def write(self,line):
        if self.fd is None or self.error or self.truncated:return
        content=(str(line)[:65536]+'\n').encode('utf-8','replace')
        if self.bytes_written+len(content)>MAX_INSTALL_LOG_BYTES:
            self.truncated=True
            content=b'[NODE INSTALL] LOG_FILE_SIZE_LIMIT_REACHED; remaining output not saved\n'
        try:
            pending=memoryview(content)
            while pending:
                count=os.write(self.fd,pending)
                if count<=0:raise OSError('INSTALL_LOG_WRITE_INCOMPLETE')
                pending=pending[count:]
            self.bytes_written+=len(content)
            if time.monotonic()-self.last_sync>=3.0:
                os.fsync(self.fd)
                self.last_sync=time.monotonic()
        except OSError as exc:
            self.error='INSTALL_LOG_IO_ERROR: '+type(exc).__name__

    def close(self):
        if self.fd is None:return
        try:
            os.fsync(self.fd)
        except OSError as exc:
            self.error='INSTALL_LOG_FSYNC_ERROR: '+type(exc).__name__
        finally:
            os.close(self.fd)
            self.fd=None


def read_reality_items(path=REALITY_KEYS_FILE,*,owner_uid=0):
    """Read the installed key export once, enforcing a safe root-private file.

    Returns (non-key header lines, ordered key/value fields). The original
    content is never printed to stdout, saved in an installation log or sent
    to a command. No external commands are run by this viewer.
    """
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=owner_uid or \
       stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or \
       not 0<before.st_size<=32768:
        raise OSError('UNSAFE_REALITY_KEYS_FILE')
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
    fd=os.open(path,flags)
    try:
        after=os.fstat(fd)
        if (after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino) or \
           not stat.S_ISREG(after.st_mode) or after.st_uid!=owner_uid or \
           stat.S_IMODE(after.st_mode)!=0o600 or after.st_nlink!=1:
            raise OSError('REALITY_KEYS_FILE_REPLACED')
        raw=os.read(fd,32769)
        if len(raw)>32768:raise OSError('REALITY_KEYS_FILE_TOO_LARGE')
    finally:
        os.close(fd)
    text=raw.decode('utf-8','strict')
    if any(ord(c)<32 and c not in '\n\r\t' or ord(c)==127 for c in text):
        raise ValueError('REALITY_KEYS_CONTROL_CHARACTERS')
    headers=[];items=[]
    for line in text.splitlines():
        if ':' in line:
            key,value=line.split(':',1)
            key=key.strip();value=value.strip()
            if key and value:
                items.append((key,value,key.casefold() in ('privatekey','private key')))
                continue
        headers.append(line)
    if not items:
        raise ValueError('REALITY_KEYS_NO_FIELDS')
    return headers,items


def copy_to_terminal_clipboard(value):
    """Request OSC 52 copy in the SSH client (no promise of client support).

    The operator explicitly selected the field first. No shell command, local
    clipboard utility, stdout print or secret-bearing logfile is involved.
    """
    if not isinstance(value,str) or not value or len(value.encode('utf-8'))>4096 or \
       any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('INVALID_CLIPBOARD_VALUE')
    encoded=base64.b64encode(value.encode('utf-8'))
    request=b'\x1b]52;c;'+encoded+b'\x07'
    flags=os.O_WRONLY|os.O_CLOEXEC|os.O_NOCTTY|os.O_NONBLOCK|os.O_NOFOLLOW
    try:fd=os.open('/dev/tty',flags)
    except OSError:return False
    try:
        view=memoryview(request)
        while view:
            sent=os.write(fd,view)
            if sent<=0:raise OSError('OSC52_INCOMPLETE')
            view=view[sent:]
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


class Terminal:
    """Stable SSH TUI: one physical screen update per user action, no timed erases."""
    def __init__(self,win):
        self.save_reports=False
        self.win=win
        self.colors=False
        self.frame_left=1
        self.frame_right=win.getmaxyx()[1]-3
        self.install_log_path=None
        self.install_log_error=None
        if curses.has_colors() and os.environ.get('NO_COLOR') is None:
            curses.start_color()
            try:curses.use_default_colors()
            except curses.error:pass
            if curses.COLORS>=256:
                # Deep graphite + restrained mint green: the agreed reference
                # expressed with terminal cells, not an HTML mock screen.
                palette=((1,121,234),(2,231,22),(3,221,234),(4,203,234),
                         (5,78,234),(6,157,234),(7,81,234),(8,28,234),
                         (9,121,234),(10,231,22),(11,194,234),(12,157,235),
                         (13,243,234))
            else:
                palette=((1,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (2,curses.COLOR_WHITE,curses.COLOR_GREEN),
                         (3,curses.COLOR_YELLOW,curses.COLOR_BLACK),
                         (4,curses.COLOR_RED,curses.COLOR_BLACK),
                         (5,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (6,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (7,curses.COLOR_CYAN,curses.COLOR_BLACK),
                         (8,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (9,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (10,curses.COLOR_WHITE,curses.COLOR_GREEN),
                         (11,curses.COLOR_WHITE,curses.COLOR_BLACK),
                         (12,curses.COLOR_GREEN,curses.COLOR_BLACK),
                         (13,curses.COLOR_WHITE,curses.COLOR_BLACK))
            for num,fg,bg in palette:
                curses.init_pair(num,fg,bg)
            self.colors=True
        if self.colors and hasattr(win,'bkgd'):
            try:win.bkgd(' ',self.attr(9))
            except curses.error:pass
        try:curses.curs_set(0)
        except curses.error:pass
        win.keypad(True)
        self.note=''

    def attr(self,kind=1,bold=False):
        return (curses.color_pair(kind) if self.colors else 0)|(curses.A_BOLD if bold else 0)

    def put(self,y,x,text,*,kind=1,bold=False,edge=False):
        height,width=self.win.getmaxyx()
        if y<0 or y>=height or x<0 or x>=width-1:return
        # Never touch terminal's last column. Also clip body text to the inner
        # frame edge so long FQDNs and logs cannot destroy the border.
        right=(width-2 if edge else min(width-2,self.frame_right-1))
        limit=max(0,right-x+1)
        if not limit:return
        glyphs=[];occupied=0
        for char in str(text):
            if ord(char)<32 or char=='\x7f':continue
            cells=2 if unicodedata.east_asian_width(char) in ('F','W') else 1
            if occupied+cells>limit:break
            glyphs.append(char);occupied+=cells
        try:self.win.addnstr(y,x,''.join(glyphs),limit,self.attr(kind,bold))
        except curses.error:pass

    def present(self):
        """Let ncurses update only changed cells: prevents SSH blinking/flicker."""
        self.win.noutrefresh()
        curses.doupdate()

    def paint(self,title,subtitle='',footer=USAGE_HINT):
        self.win.erase()
        height,width=self.win.getmaxyx()
        if height<17 or width<55:
            self.frame_left=1;self.frame_right=width-3
            self.put(0,1,'NODE INSTALL | увеличьте окно терминала',kind=3)
            self.put(2,1,'Рекомендуемый размер: 80 x 24',kind=5)
            return
        panel_width=min(width-2,112)
        left=max(1,(width-panel_width)//2)
        right=left+panel_width-1
        self.frame_left=left;self.frame_right=right
        edge='─'*max(0,right-left-1)
        self.put(0,left,'╭'+edge+'╮',kind=8,edge=True)
        for y in range(1,height-2):
            self.put(y,left,'│',kind=8,edge=True)
            self.put(y,right,'│',kind=8,edge=True)
        self.put(height-2,left,'╰'+edge+'╯',kind=8,edge=True)
        brand='NODE INSTALL'
        self.put(1,max(left+3,(left+right-len(brand))//2),brand,kind=11,bold=True)
        caption='VKARMANI   /   SERVER CONTROL'
        self.put(2,max(left+3,(left+right-len(caption))//2),caption,kind=5)
        version=release_label()
        if panel_width>=85:self.put(2,right-2-len(version),version,kind=5)
        self.put(3,left+3,'─'*max(0,panel_width-7),kind=8)
        self.put(4,left+4,title.upper(),kind=11,bold=True)
        if subtitle:self.put(5,left+4,subtitle,kind=5)
        self.put(6,left+3,'─'*max(0,panel_width-7),kind=8)
        self.put(height-5,left+3,'─'*max(0,panel_width-7),kind=8)
        self.put(height-3,left+4,footer,kind=5)
        if self.note:self.put(height-6,left+4,self.note,kind=3)

    def message(self,title,lines,*,wait=True,warning=False):
        """Scrollable modal; never hide the end of a pre-install review."""
        scroll=0
        while True:
            self.paint(title,footer='↑↓ / PgUp/PgDn читать   ENTER принять   ESC назад')
            h,w=self.win.getmaxyx()
            left=self.frame_left
            wrapped=[part for line in lines for part in linewrap(line,max(20,self.frame_right-left-12))]
            slots=max(1,h-16)
            scroll=max(0,min(scroll,max(0,len(wrapped)-slots)))
            for y,line in enumerate(wrapped[scroll:scroll+slots],start=8):
                if y>=h-7:break
                self.put(y,left+5,line,kind=3 if warning else 1)
            if len(wrapped)>slots:
                self.put(h-6,left+5,f'Строки {scroll+1}–{min(len(wrapped),scroll+slots)} из {len(wrapped)}',kind=5)
            self.present()
            if not wait:return None
            key=self.win.getch()
            if key in (10,13,27,curses.KEY_ENTER):return key
            if key in (curses.KEY_DOWN,ord('j'),curses.KEY_NPAGE):
                scroll=min(max(0,len(wrapped)-slots),scroll+(slots if key==curses.KEY_NPAGE else 1))
            elif key in (curses.KEY_UP,ord('k'),curses.KEY_PPAGE):
                scroll=max(0,scroll-(slots if key==curses.KEY_PPAGE else 1))
            elif key==curses.KEY_END:scroll=max(0,len(wrapped)-slots)
            elif key==curses.KEY_HOME:scroll=0

    def menu(self,title,items,subtitle='',*,start=0,footer=USAGE_HINT,auto_zero=False,special_keys=None):
        """Stable menu, arrows/pages and numeric shortcuts; no redraw while idle."""
        if not items:return None
        i=max(0,min(start,len(items)-1))
        while True:
            self.paint(title,subtitle,footer)
            h,w=self.win.getmaxyx()
            left=self.frame_left;right=self.frame_right
            stride=3 if h>=34 else 2
            available=max(1,(h-14)//stride)
            offset=max(0,min(i-available//2,max(0,len(items)-available)))
            for pos in range(offset,min(len(items),offset+available)):
                y=8+stride*(pos-offset)
                label,desc=items[pos]
                selected=pos==i
                prefix='' if auto_zero and pos==0 else '%02d. '%(pos if auto_zero else pos+1)
                marker='❯ ' if selected else '  '
                row=marker+prefix+label
                if selected:
                    # Two-line active card, no overlay from subsequent redraws.
                    self.put(y,left+4,' '*max(0,right-left-9),kind=2)
                    self.put(y+1,left+4,' '*max(0,right-left-9),kind=2)
                self.put(y,left+5,row,kind=2 if selected else 11,bold=selected)
                self.put(y+1,left+8,desc,kind=2 if selected else 5)
                if stride==3 and y+2<h-6:
                    self.put(y+2,left+5,'─'*max(0,right-left-12),kind=8)
            if len(items)>available:
                self.put(h-6,left+5,f'{i+1}/{len(items)} · PgUp/PgDn страницы')
            self.present()
            key=self.win.getch()
            if special_keys and key in special_keys:
                result=special_keys[key]
                return (result,i) if result=='preview' else result
            if key==ord('0') and auto_zero:return 0
            if key in (27,ord('0'),ord('q')):return None
            if key in (curses.KEY_UP,ord('k')):i=(i-1)%len(items)
            elif key in (curses.KEY_DOWN,ord('j')):i=(i+1)%len(items)
            elif key==curses.KEY_PPAGE:i=max(0,i-available)
            elif key==curses.KEY_NPAGE:i=min(len(items)-1,i+available)
            elif key==curses.KEY_HOME:i=0
            elif key==curses.KEY_END:i=len(items)-1
            elif key in (10,13,curses.KEY_ENTER):return i
            elif 49<=key<=57 and not auto_zero:
                n=key-49
                if n<len(items):return n

    def field(self,title,prompt,*,secret=False,maxlen=253,initial=''):
        """Safe UTF-8 keyboard input; hidden secret is never printed or logged."""
        value=list(initial)
        while True:
            self.paint(title,prompt,footer='ENTER — принять · ESC — отменить · Backspace — стереть')
            h,w=self.win.getmaxyx()
            left=self.frame_left;inner=max(8,self.frame_right-left-12)
            masked=('●'*min(len(value),inner)) if secret else ''.join(value)
            if len(masked)>inner:masked='…'+masked[-(inner-1):]
            self.put(8,left+5,'╭'+'─'*inner+'╮',kind=8)
            self.put(9,left+5,'│',kind=8)
            self.put(9,left+7,'> '+masked)
            self.put(9,left+inner+6,'│',kind=8)
            self.put(10,left+5,'╰'+'─'*inner+'╯',kind=8)
            self.present()
            try:key=self.win.get_wch()
            except curses.error:continue
            except KeyboardInterrupt:return None
            if key in ('\n','\r',curses.KEY_ENTER):return ''.join(value)
            if key=='\x1b':return None
            if key in ('\b','\x7f',curses.KEY_BACKSPACE):
                if value:value.pop()
            elif key==curses.KEY_DC: value=[]
            elif isinstance(key,str) and key.isprintable() and len(value)<maxlen:
                value.append(key)

    def confirm_removal(self,title,description):
        """Explicit choices instead of type-to-confirm; only for rollback/removal."""
        return self.menu(title,[
            ('Я осознаю что делаю и согласен',description),
            ('Я ошибся хочу вернуться назад','Отменить, ничего не изменять')],
            'ОПАСНАЯ ОПЕРАЦИЯ: предварительно проверьте backup и консоль VPS')==0

    def logs(self,title,command,*,pass_fd=None,redact=(),persist_install=False):
        """Live bounded terminal journal; installations also stream to /root.

        Only an actual installation enables the persistent transcript. The
        file is created BEFORE starting the installer, and each saved line is
        sanitized, not the raw child output. The subprocess keeps running if
        a later disk error occurs, to avoid interrupting system mutations.
        """
        log=deque(maxlen=MAX_LOG_LINES)
        sink=None
        if persist_install:
            self.install_log_path=None
            self.install_log_error=None
            try:
                log_fd,path=new_install_log()
                sink=InstallLogSink(log_fd)
                self.install_log_path=path
                sink.write('NODE_INSTALL_LOG=START version='+release_label())
                if sink.error:
                    raise OSError('INSTALL_LOG_INITIAL_WRITE_FAILED')
            except OSError as exc:
                if sink is not None:sink.close()
                self.install_log_error=type(exc).__name__
                self.message('ЖУРНАЛ НЕ СОЗДАН',[ 
                    'Установка не запущена: нельзя создать защищённый журнал в /root.',
                    'Проверьте права /root, свободное место и состояние диска.',
                    'Системные изменения не начинались.'],warning=True)
                return 2
        old_sig=signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        self.win.nodelay(True)
        try:
            with subprocess.Popen(command,stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                    env={**os.environ,'PYTHONUTF8':'1','VK_NODE_TUI':'1'},
                    pass_fds=((pass_fd,) if pass_fd is not None else ()),bufsize=0) as proc:
                channel=proc.stdout.fileno()
                os.set_blocking(channel,False)
                remainder=b'';scroll=0;auto=True;eof=False
                previous_state=None;dirty=True;physical=[];last_width=None

                def add_line(raw):
                    nonlocal dirty
                    text=safe_log_line(raw.decode('utf-8','replace'),redact)
                    log.append(text[:8192])
                    if sink is not None:sink.write(text)
                    dirty=True

                while True:
                    if eof:
                        time.sleep(0.08)
                    else:
                        ready,_,_=select.select([channel],[],[],0.15)
                        if ready:
                            try:chunk=os.read(channel,32768)
                            except BlockingIOError:chunk=None
                            if chunk==b'':eof=True
                            elif chunk:
                                remainder+=chunk
                                if len(remainder)>65536 and b'\n' not in remainder:
                                    add_line(remainder[:8192]);remainder=b''
                                    add_line(b'[LONG LOG LINE TRUNCATED]')
                                while b'\n' in remainder or b'\r' in remainder:
                                    row,remainder=re.split(b'\r\n|\n|\r',remainder,maxsplit=1)
                                    add_line(row)
                    done=proc.poll() is not None
                    if eof and remainder:
                        add_line(remainder);remainder=b''
                    state=(done,proc.returncode)
                    if state!=previous_state:dirty=True;previous_state=state
                    key=self.win.getch()
                    h,w=self.win.getmaxyx();slots=max(1,h-16)
                    if w!=last_width:dirty=True;last_width=w
                    if dirty:
                        usable=max(15,min(w-2,112)-15)
                        physical=[(wrapped,log_color(line)) for line in log
                                  for wrapped in linewrap(line,usable)]
                    if key==curses.KEY_PPAGE:auto=False;scroll=max(0,scroll-slots);dirty=True
                    elif key==curses.KEY_NPAGE:auto=False;scroll=min(max(0,len(physical)-slots),scroll+slots);dirty=True
                    elif key==curses.KEY_END:auto=True;dirty=True
                    elif key==curses.KEY_RESIZE:dirty=True
                    if done and eof and key in (27,10,13,ord('q')):break
                    if not dirty:continue
                    self.paint(title, 'Протокол установки / проверки · PgUp/PgDn прокрутка',
                        footer='PgUp/PgDn листать · End к концу · Esc после завершения')
                    if auto:scroll=max(0,len(physical)-slots)
                    left=self.frame_left;right=self.frame_right
                    self.put(7,left+4,('ГОТОВО' if done and proc.returncode==0 else
                                ('ОШИБКА / ПРОВЕРЬ ЖУРНАЛ' if done else 'ВЫПОЛНЯЕТСЯ')),
                             kind=1 if not done or proc.returncode==0 else 4,bold=True)
                    if right-left>=67:
                        self.put(7,right-19,f'Строк: {len(log)}',kind=5)
                    for y,(line,kind) in enumerate(physical[scroll:scroll+slots],start=9):
                        if y>=h-7:break
                        self.put(y,left+5,line,kind=kind)
                    self.put(h-4,left+4,'Код: '+str(proc.returncode) if done else 'Процесс работает',
                             kind=1 if not done or proc.returncode==0 else 3)
                    if sink is not None and (sink.error or sink.truncated):
                        self.put(h-6,left+4,'ВНИМАНИЕ: журнал на диске неполный',kind=4,bold=True)
                    self.present();dirty=False
                if sink is not None:
                    sink.write('NODE_INSTALL_LOG=END exit_code='+str(proc.returncode))
                return proc.returncode
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            if sink is not None:sink.write('NODE_INSTALL_LOG=START_FAILURE '+type(exc).__name__)
            self.message('Команда не запущена',[type(exc).__name__,'Изменения не подтверждены.'],warning=True)
            return 2
        finally:
            if sink is not None:
                sink.close()
                if sink.error:self.install_log_error=sink.error
                elif sink.truncated:self.install_log_error='LOG_FILE_SIZE_LIMIT_REACHED'
            self.win.nodelay(False)
            signal.signal(signal.SIGINT,old_sig)

    def action(self,*args):
        return self.logs('ЖУРНАЛ / РЕЗУЛЬТАТ', ['bash',str(INSTALLER),*args])

    def extra_settings(self,mode,options):
        """One editable settings page, not nested mandatory questionnaires."""
        while True:
            items=[('ПОРТ УПРАВЛЕНИЯ NODE',str(options['node_port'] or 2222)+' / TCP'),
                   ('ВХОДЯЩАЯ СКОРОСТЬ',str(options['in_mbps'] or 'Без ограничения')+' Мбит/с' if options['in_mbps'] else 'Без ограничения'),
                   ('ИСХОДЯЩАЯ СКОРОСТЬ',str(options['out_mbps'] or 'Без ограничения')+' Мбит/с' if options['out_mbps'] else 'Без ограничения'),
                   ('ВХОДЯЩИЙ ОБЪЁМ',str(options['in_gib'])+' GiB' if options['in_gib'] else 'Без ограничения'),
                   ('ИСХОДЯЩИЙ ОБЪЁМ',str(options['out_gib'])+' GiB' if options['out_gib'] else 'Без ограничения'),
                   ('ЕЖЕНЕДЕЛЬНЫЙ REBOOT','Включён' if options['weekly_reboot'] else 'Выключен'),
                   ('REBOOT ПОСЛЕ УСТАНОВКИ','Включён' if not options['no_reboot'] else 'Выключен'),
                   ('ПРОДОЛЖИТЬ','Сохранить настройки этого мастера')]
            if mode!='ordinary':
                items=[items[6],items[7]]
            selection=self.menu('ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ',items,
                'Изменяйте только нужные пункты; 0 = без лимита',
                footer='↑↓ выбор   ENTER изменить   ESC предыдущий шаг')
            if selection is None:return False
            if selection==len(items)-1:return True
            field_names=('node_port','in_mbps','out_mbps','in_gib','out_gib')
            if mode=='ordinary' and selection<5:
                key=field_names[selection]
                caption=('Порт Node API, 1024–65535','Скорость входящих, Мбит/с',
                         'Скорость исходящих, Мбит/с','Входящий объём, GiB','Исходящий объём, GiB')[selection]
                value=self.field('СЕТЕВЫЕ ЛИМИТЫ',caption+'; 0 = без лимита',maxlen=12,
                                 initial=str(options[key] or 0))
                if value is None:continue
                try:
                    number=int(value.strip() or '0')
                    if key=='node_port':
                        if number and not (1024<=number<=65535 and number not in (443,61001)):
                            raise ValueError()
                    elif not 0<=number<=(20000 if key.endswith('mbps') else 100000):
                        raise ValueError()
                    options[key]=number or None
                except ValueError:
                    self.message('НЕВЕРНОЕ ЗНАЧЕНИЕ',['Укажите целое число в допустимых пределах.'],warning=True)
            else:
                key=('weekly_reboot','no_reboot')[(selection-5) if mode=='ordinary' else selection+1]
                options[key]=not options[key]

    def themes(self):
        """Scrollable 120-theme picker, Auto first; search is never an item."""
        terms=THEMES
        while True:
            items=[('00. АВТО (РАНДОМ)','Автоматический выбор одной из проверенных тем')]
            items += [(f'{theme_meta(theme)[0]} — {theme_meta(theme)[1]}',
                       f'{theme_meta(theme)[2][:65]} · {theme}') for theme in terms]
            pos=self.menu('ВЫБОР САЙТА',items,
                f'Доступно: {len(terms)} из 120 · / поиск · C категория · A все',
                footer='↑↓ выбор   ENTER выбрать   P просмотр   / поиск   C категория   ESC назад',
                auto_zero=True,special_keys={ord('/'): 'search',ord('c'):'category',
                                             ord('C'):'category',ord('a'):'all',ord('A'):'all',ord('p'):'preview',ord('P'):'preview'})
            if pos is None:return None
            if pos==0:
                chosen=choose_random_theme()
                return chosen
            if pos=='search':
                term=self.field('ПОИСК САЙТА','Название, ID или тематика')
                if term is None:continue
                terms=tuple(x for x in THEMES if term.casefold() in
                            (' '.join((x,*theme_meta(x)))).casefold())
                if not terms:self.message('Поиск',['Совпадений нет.']);terms=THEMES
            elif pos=='category':
                categories=sorted({theme_meta(x)[1] for x in THEMES},key=str.casefold)
                cat=self.menu('ТЕМАТИКА САЙТА',[(x,f'{sum(theme_meta(t)[1]==x for t in THEMES)} тем')
                                       for x in categories])
                if cat is not None:
                    terms=tuple(x for x in THEMES if theme_meta(x)[1]==categories[cat])
            elif pos=='all':terms=THEMES
            elif isinstance(pos,tuple) and pos[0]=='preview':
                if pos[1]==0:
                    self.message('АВТО САЙТ',['Будет выбрана одна из 120 тем при установке.'])
                else:
                    item=terms[pos[1]-1];title,category,desc,lang=theme_meta(item)
                    self.message('ПРЕДПРОСМОТР САЙТА',[
                       f'ID: {item}',f'Название: {title}',f'Тематика: {category}',
                       f'Язык: {lang}',f'Описание: {desc}',
                       'Галерея: preview/site-gallery/index.html'])
            else:
                # ENTER selects the highlighted theme without an extra
                # confirmation screen. Operators may inspect any theme in the
                # offline gallery before launching the installer.
                return terms[pos-1]


    def wizard(self):
        if not has_root():
            self.message('Права доступа',['Для установки нужен root: sudo bash install.sh --menu'],warning=True)
            return
        if not preinstall_state_guard():
            choice=self.menu('УСТАНОВКА УЖЕ НАЧАТА',[
                ('Проверить состояние','Только чтение: checkpoint и восстановление'),
                ('Продолжить финализацию','Только сохранённый checkpoint, не новая установка'),
                ('Восстановить SSH/UFW','Требует подтверждения удаления/отката'),
                ('Назад','Не менять состояние VPS')],
                'Новая установка поверх существующей запрещена')
            if choice==0:self.action('--removal-plan','plan')
            elif choice==1:self.action('--finish-install')
            elif choice==2:self.remove(full=False)
            return

        data={'mode':'ordinary','site':None,'bundle':None,'secret':'','domain':'',
              'panel_ip':'','reality':'local'}
        options={'node_port':None,'in_mbps':None,'out_mbps':None,
                 'in_gib':None,'out_gib':None,'weekly_reboot':False,'no_reboot':True}
        step=0
        # Each ESC decrements precisely one step. Previously entered data and
        # the chosen random theme remain intact; nothing starts before review.
        while True:
            mode=data['mode']
            sequence=['mode','site' if mode=='ordinary' else 'bundle',
                      'secret','domain','panel']
            if mode=='ordinary':sequence.append('reality')
            sequence.extend(('extra','review'))
            step=max(0,min(step,len(sequence)-1))
            name=sequence[step]
            result=None
            if name=='mode':
                selected=self.menu('ТИП УСТАНОВКИ',[
                    ('Обычная Node','VLESS / RAW / REALITY / Selfsteal'),
                    ('Cascade Entry','Нужен приватный bundle'),
                    ('Cascade Exit','Нужен приватный bundle')])
                if selected is not None:
                    data['mode']=('ordinary','entry','exit')[selected];result=True
            elif name=='site':
                theme=self.themes()
                if theme is not None:
                    data['site']=theme;result=True
            elif name=='bundle':
                value=self.field('РОЛЕВОЙ BUNDLE','Абсолютный путь к root:0600 role-bundle.json',
                                 initial=data['bundle'] or '')
                if value is not None:
                    try:
                        p=Path(value)
                        st=p.lstat()
                        if not p.is_absolute() or p.is_symlink() or not p.is_file() or \
                           st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1:
                            raise ValueError()
                        data['bundle']=value;result=True
                    except (OSError,ValueError):
                        self.message('Небезопасный bundle',['Нужен существующий приватный файл root:0600.'],warning=True)
                        result='retry'
            elif name=='secret':
                value=self.field('SECRET_KEY','Вставьте SECRET_KEY из панели (скрыто)',
                                 secret=True,maxlen=65536,initial=data['secret'])
                if value is not None:
                    try:data['secret']=validate_secret(value);result=True
                    except ValueError:
                        self.message('НЕВЕРНЫЙ SECRET_KEY',['Проверьте формат значения; пароль не выводился.'],warning=True)
                        result='retry'
            elif name=='domain':
                value=self.field('ДОМЕН НОДЫ','FQDN ноды, например node.example.com',initial=data['domain'])
                if value is not None:
                    try:data['domain']=validate_domain(value);result=True
                    except ValueError:
                        self.message('НЕВЕРНЫЙ ДОМЕН',['Укажите доменное имя ноды без схемы и порта.'],warning=True)
                        result='retry'
            elif name=='panel':
                value=self.field('АДРЕС ПАНЕЛИ','Публичный IPv4 или домен панели (без https:// и порта)',
                                 initial=data['panel_ip'])
                if value is not None:
                    try:data['panel_ip']=validate_panel_target(value);result=True
                    except ValueError:
                        self.message('НЕВЕРНЫЙ АДРЕС ПАНЕЛИ',[
                            'Нужен публичный IPv4 или FQDN; DNS и ACL проверит установщик.'],warning=True)
                        result='retry'
            elif name=='reality':
                pos=self.menu('REALITY / SNI',[
                    (x,'Свой HTTPS-сайт' if x=='local' else 'Внешний TLS target') for x in REALITY],
                    start=REALITY.index(data['reality']))
                if pos is not None:data['reality']=REALITY[pos];result=True
            elif name=='extra':
                result=self.extra_settings(mode,options)
            else:
                settings={**data,**options}
                review=['Роль: '+mode,
                        'Сайт: '+(data['site'] if mode=='ordinary' else 'Не применяется'),
                        'Домен ноды: '+data['domain'],
                        'Адрес панели: '+data['panel_ip']+' (IP или FQDN)',
                        'REALITY: '+data['reality'],
                        'Транспорт: RAW + REALITY + Vision (Ordinary)',
                        'Секрет: •••••••• (скрыт)',
                        'Порт Node API: '+str(options['node_port'] or 2222),
                        'Скорость вход/выход: '+str(options['in_mbps'] or '∞')+' / '+str(options['out_mbps'] or '∞')+' Mbps',
                        'Объём вход/выход: '+str(options['in_gib'] or '∞')+' / '+str(options['out_gib'] or '∞')+' GiB',
                        'Авто reboot: '+('нет' if options['no_reboot'] else 'да'),
                        'Изменяются SSH, UFW, Docker, Nginx, GRUB и сеть.',
                        'До установки сохраните snapshot и проверьте консоль хостера.',
                        'ENTER — установить; ESC — изменить настройки.']
                key=self.message('ПЕРЕД УСТАНОВКОЙ',review)
                if key in (10,13,curses.KEY_ENTER):
                    break
                if key==27:
                    step-=1
                continue

            if result=='retry':
                # Invalid input is not an ESC and must not unwind the wizard.
                # Keep prior answers and permit correction on this same screen.
                continue
            if result is None or result is False:
                if name=='mode':return
                step-=1
            else:
                step+=1

        fd=None
        secret=data['secret']
        try:
            fd=secret_fd(secret,data['panel_ip'],data['domain'])
            cmd=wizard_argv({**data,**options},fd=fd)
            data['secret']=''
            rc=self.logs('УСТАНОВКА NODE / ЖИВОЙ ЖУРНАЛ',cmd,pass_fd=fd,
                         redact=(secret,),persist_install=True)
        except (OSError,ValueError,RuntimeError) as exc:
            # A failed memfd/argv preparation must not leave curses or invoke
            # the installer. Show only the exception type, never its secret.
            self.message('НЕ УДАЛОСЬ НАЧАТЬ УСТАНОВКУ',[
                'Системные команды установки не запускались.',
                'Причина: '+type(exc).__name__],warning=True)
            return
        finally:
            data['secret']=''
            secret=''
            if fd is not None:os.close(fd)
        result=[
            f'Код возврата: {rc}',
            '0 — этапы установки завершены; проверка клиентов отдельная.',
            '20 — основная нода установлена, сайт не опубликован.',
            '21 — основная нода установлена, сетевые лимиты не активированы.',
            'Проверьте итог, backup и журнал до перезагрузки.',
            'Ключи доступны только root в /root/reality-keys.txt.',
            'Не публикуйте приватный REALITY-ключ.']
        if self.install_log_path is not None:
            result.append('Живой журнал сохранён: '+str(self.install_log_path))
        if self.install_log_error:
            result.append('ВНИМАНИЕ: файл журнала неполный: '+self.install_log_error)
        self.message('ИТОГ УСТАНОВКИ',result,warning=rc!=0 or bool(self.install_log_error))
        if rc in (0,20,21) and has_root():
            try:show_keys=REALITY_KEYS_FILE.exists()
            except OSError:show_keys=False
            if show_keys:self.keys_screen()

    def keys_screen(self):
        """Show the protected export after installation; copy one chosen value.

        PrivateKey starts masked. V reveals it locally, Enter requests OSC 52
        clipboard delivery over SSH (or the operator can select visible text).
        The viewer never sends data to the log or any external process.
        """
        if not has_root():
            self.message('REALITY / КЛЮЧИ',['Нужен root, файл доступен только администратору.'],warning=True)
            return
        try:headers,items=read_reality_items()
        except (OSError,ValueError,UnicodeError) as exc:
            self.message('REALITY / КЛЮЧИ НЕДОСТУПНЫ',[
                'Файл /root/reality-keys.txt отсутствует либо не прошёл защитную проверку.',
                'Требуется обычный файл root:0600 без ссылок и сторонних владельцев.',
                'Причина: '+type(exc).__name__],warning=True)
            return
        selected=0;offset=0;reveal=False;notice=''
        while True:
            self.paint('REALITY / КЛЮЧИ УСТАНОВКИ',
                'Данные из защищённого /root/reality-keys.txt',
                footer='↑↓ выбор · ENTER копировать · V показать ключ · ESC назад')
            h,w=self.win.getmaxyx();left=self.frame_left;right=self.frame_right
            width=max(12,right-left-14)
            title_line=next((s for s in headers if s.strip() and set(s.strip())!={'='}), '')
            if title_line:self.put(7,left+5,title_line,kind=5)
            detail_y=max(12,h-10)
            slots=max(1,detail_y-9)
            offset=max(0,min(offset,len(items)-slots))
            if selected<offset:offset=selected
            if selected>=offset+slots:offset=selected-slots+1
            for index in range(offset,min(len(items),offset+slots)):
                y=9+index-offset
                label,value,private=items[index]
                show=value if not private or reveal else '••••••••  (V — показать)'
                row=('❯ ' if index==selected else '  ')+label+': '+show
                if index==selected:self.put(y,left+4,' '*max(0,right-left-9),kind=2)
                self.put(y,left+5,row,kind=2 if index==selected else 1,bold=index==selected)
            self.put(detail_y,left+4,'─'*max(0,right-left-9),kind=8)
            label,value,private=items[selected]
            self.put(detail_y+1,left+5,'ВЫБРАНО: '+label,kind=11,bold=True)
            shown=value if not private or reveal else '[СКРЫТО]  V — показать на экране'
            for j,line in enumerate(linewrap(shown,width)[:2]):
                if detail_y+2+j<h-5:self.put(detail_y+2+j,left+5,line,kind=1)
            if notice:self.put(h-6,left+4,notice,kind=3)
            elif len(items)>slots:
                self.put(h-6,left+4,f'{selected+1}/{len(items)} полей · PgUp/PgDn',kind=5)
            self.present()
            key=self.win.getch()
            if key in (27,ord('q'),ord('0')):
                self.note=''
                return
            if key in (ord('v'),ord('V')):
                reveal=not reveal;notice=''
            elif key in (curses.KEY_DOWN,ord('j')):
                selected=(selected+1)%len(items);notice=''
            elif key in (curses.KEY_UP,ord('k')):
                selected=(selected-1)%len(items);notice=''
            elif key==curses.KEY_PPAGE:
                selected=max(0,selected-slots);notice=''
            elif key==curses.KEY_NPAGE:
                selected=min(len(items)-1,selected+slots);notice=''
            elif key==curses.KEY_HOME:
                selected=0;notice=''
            elif key==curses.KEY_END:
                selected=len(items)-1;notice=''
            elif key in (10,13,curses.KEY_ENTER):
                if copy_to_terminal_clipboard(value):
                    notice='Команда копирования передана SSH-клиенту (OSC 52).'
                else:
                    notice='Буфер недоступен: V — открыть, выделить значение мышью.'

    def vps_process(self,mode='full',*,server=None):
        """Stream structured progress into curses without emitting raw child text.

        Diagnostic child has no write authority over the installer and has its
        own process group. Esc cancels only the diagnostic, never SSH or Node.
        """
        if mode not in ('full','bench','speed'):
            raise ValueError('INVALID_VPS_DIAGNOSTIC_MODE')
        command=[sys.executable,'-I',str(INTEGRATIONS/'vps_dashboard.py'),mode]
        if mode=='speed':
            if server is None:raise ValueError('IPERF3_SERVER_REQUIRED')
            command+=['--server',validate_panel_ip(server)]
        progress=deque(maxlen=150)
        report=None;error=None;cancelled=False
        old_sig=signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        self.win.nodelay(True)
        try:
            with subprocess.Popen(command,stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'},
                    start_new_session=True,bufsize=0) as proc:
                channel=proc.stdout.fileno()
                os.set_blocking(channel,False)
                rest=b'';eof=False;dirty=True;last_second=-1
                progress.append('Автоматическая диагностика: ввод параметров не требуется.')
                while True:
                    if not eof:
                        ready,_,_=select.select([channel],[],[],0.15)
                        if ready:
                            try:chunk=os.read(channel,32768)
                            except BlockingIOError:chunk=None
                            if chunk==b'':eof=True
                            elif chunk:
                                rest+=chunk
                                if len(rest)>MAX_LOG_LINES*64:
                                    error='Слишком большой ответ диагностики';eof=True
                                    os.killpg(proc.pid,signal.SIGTERM)
                                while b'\n' in rest:
                                    line,rest=rest.split(b'\n',1)
                                    if len(line)>100_000:
                                        error='Слишком длинное сообщение';continue
                                    try:event=json.loads(line)
                                    except (UnicodeError,ValueError):continue
                                    if not isinstance(event,dict):continue
                                    if event.get('type')=='progress':
                                        value=str(event.get('message',''))[:120]
                                        progress.append(safe_log_line(value))
                                    elif event.get('type')=='result' and isinstance(event.get('report'),dict):
                                        report=event['report']
                                    elif event.get('type')=='error':
                                        error='Диагностика: '+str(event.get('error','ERROR'))[:100]
                                    dirty=True
                    if eof and rest:
                        try:
                            event=json.loads(rest)
                            if event.get('type')=='result':report=event.get('report')
                        except (ValueError,TypeError,AttributeError):pass
                        rest=b''
                    key=self.win.getch()
                    if key==27 and proc.poll() is None and not cancelled:
                        cancelled=True;progress.append('ОТМЕНЕНО: пользователь нажал Esc')
                        try:os.killpg(proc.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                        dirty=True
                    elif key in (curses.KEY_RESIZE,):dirty=True
                    elapsed=int(time.monotonic())
                    if elapsed!=last_second:dirty=True;last_second=elapsed
                    if dirty:
                        self.paint('ПРОВЕРКА VPS · ВЫПОЛНЯЕТСЯ',
                            'Щадящие авто-тесты · без изменения конфигурации VPS, Docker и firewall',
                            footer='ESC отменить диагностику  ·  проверка выполняется поэтапно')
                        h,w=self.win.getmaxyx();left=self.frame_left
                        self.put(8,left+5,'РЕАЛЬНЫЙ ХОД ПРОВЕРКИ',kind=11,bold=True)
                        slots=max(1,h-19)
                        for i,row in enumerate(list(progress)[-slots:]):
                            kind=4 if 'ОТМЕНЕНО' in row else 6 if row.startswith('ГОТОВО') else 7
                            self.put(10+i,left+5,row,kind=kind)
                        self.put(h-7,left+5,'Внешние HTTP-запросы: без авторизации и без обхода блокировок.',kind=5)
                        self.present();dirty=False
                    if eof and proc.poll() is not None:break
                if not cancelled and (proc.returncode!=0 or report is None):
                    error=error or 'Нет полного результата диагностического процесса.'
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            error=type(exc).__name__
        finally:
            self.win.nodelay(False)
            signal.signal(signal.SIGINT,old_sig)
        if cancelled:return None
        if error:
            self.message('ПРОВЕРКА НЕ ЗАВЕРШЕНА',[
                error,'Остальные системные службы и файлы не изменялись.',
                'Повторите диагностику после проверки сети или SSH.'],warning=True)
            return None
        return report

    def vps_export(self,record):
        """Save only on a conscious E choice, then return to current scroll."""
        option=self.menu('СОХРАНИТЬ РЕЗУЛЬТАТЫ VPS',[
            ('ТЕКСТ .TXT','Русский читаемый отчёт для изучения и пересылки'),
            ('КАРТИНКА .PNG','Цветной отчёт в одном длинном изображении'),
            ('СТРУКТУРИРОВАННЫЙ .JSON','Подробные данные для машинного сравнения'),
            ('ВСЕ ФОРМАТЫ','Сохранить TXT, PNG и JSON по отдельности')],
            'Файлы приватные (0600); внешний IP может присутствовать в отчёте')
        if option is None:return
        formats=('txt',) if option==0 else ('png',) if option==1 else ('json',) if option==2 else ('txt','png','json')
        paths=[]
        try:
            for kind in formats:paths.append(str(vps_report.export_report(record,kind)))
        except (OSError,ValueError,TypeError) as exc:
            self.message('ОШИБКА СОХРАНЕНИЯ',[
                'Не удалось записать один из форматов: '+type(exc).__name__,
                'Уже созданные файлы не удалены. Проверьте права и свободное место.',
                *paths],warning=True)
            return
        self.message('РЕЗУЛЬТАТЫ СОХРАНЕНЫ',[
            'Файлы созданы с правами 0600.',
            'Перед публикацией проверьте наличие публичного IP и адресов серверов.',
            *paths])

    def vps_view(self,report):
        """Russian result browser with mouse wheel, pages, hotkeys and export."""
        if not isinstance(report,dict) or report.get('kind')!='RUSSIAN_VPS_DIAGNOSTICS':
            self.message('ОШИБКА ОТЧЁТА',['Получены данные неизвестного формата.'],warning=True)
            return
        section=0;scroll=0
        mask=0
        for name in ('BUTTON4_PRESSED','BUTTON5_PRESSED','BUTTON1_CLICKED'):
            mask |= getattr(curses,name,0)
        try:
            curses.mousemask(mask)
            curses.mouseinterval(0)
        except curses.error:pass
        try:
            while True:
                named=vps_report.sections(report)
                label='ВСЕ РАЗДЕЛЫ' if section==0 else named[section-1][0].upper()
                self.paint('РЕЗУЛЬТАТЫ ПРОВЕРКИ VPS',
                    f'Раздел {section}/{len(named)} · {label}',
                    footer='↑↓ / колесо · PgUp/PgDn · 0 обзор · 1–9 разделы · E сохранить · ESC назад')
                h,w=self.win.getmaxyx();left=self.frame_left
                width=max(18,self.frame_right-left-12)
                rows=[]
                for line,style in vps_report.display_lines(report,section):
                    wrapped=linewrap(line,width)
                    rows.extend((part,vps_report.KINDS.get(style,1)) for part in wrapped)
                slots=max(1,h-17)
                limit=max(0,len(rows)-slots)
                scroll=max(0,min(limit,scroll))
                for y,(line,kind) in enumerate(rows[scroll:scroll+slots],start=8):
                    if y>=h-7:break
                    self.put(y,left+5,line,kind=kind,bold=kind==11)
                self.put(h-6,left+5,f'Строки {scroll+1}–{min(len(rows),scroll+slots)} из {len(rows)}',kind=5)
                self.present()
                key=self.win.getch()
                if key in (27,ord('q')):return
                if key==curses.KEY_MOUSE:
                    try:
                        _,_,_,_,state=curses.getmouse()
                        if state & getattr(curses,'BUTTON4_PRESSED',0):scroll=max(0,scroll-4)
                        elif state & getattr(curses,'BUTTON5_PRESSED',0):scroll=min(limit,scroll+4)
                    except curses.error:pass
                elif key in (curses.KEY_DOWN,ord('j')):scroll=min(limit,scroll+1)
                elif key in (curses.KEY_UP,ord('k')):scroll=max(0,scroll-1)
                elif key==curses.KEY_PPAGE:scroll=max(0,scroll-slots)
                elif key==curses.KEY_NPAGE:scroll=min(limit,scroll+slots)
                elif key==curses.KEY_HOME:scroll=0
                elif key==curses.KEY_END:scroll=limit
                elif key in (ord('0'),ord('\t')):
                    section=0 if key==ord('0') else (section+1)%(len(named)+1);scroll=0
                elif ord('1')<=key<=ord('9'):
                    index=key-ord('0')
                    if index<=len(named):section=index;scroll=0
                elif key in (ord('e'),ord('E')):
                    self.vps_export(report)
        finally:
            try:curses.mousemask(0)
            except curses.error:pass

    def vps(self):
        """The first main-menu item opens the comprehensive Russian dashboard."""
        report=self.vps_process('full')
        if report is not None:self.vps_view(report)

    def remove(self,full=False):
        self.action('--removal-plan','plan')
        if full:
            self.message('ПОЛНАЯ ЗАЧИСТКА — ВАЖНО',[
               'Node Install меняет SSH, UFW, GRUB, Docker, пакеты и загрузчик.',
               'Автоматическая полная зачистка НЕ является безопасной заменой snapshot.',
               'Для возврата VPS в исходное состояние восстановите проверенный snapshot',
               'через консоль провайдера. Действия удаления здесь не выполняются.',
               'Системные журналы и чужие файлы намеренно не уничтожаются.'],warning=True)
            return
        self.message('ВОССТАНОВЛЕНИЕ ПОСЛЕ СБОЯ',[
           'Автоматическое восстановление допустимо только для вооружённого этапа SSH/UFW.',
           'Для GRUB/APT/Docker/SSL общего надёжного отката нет; нужен snapshot.',
           'Если на сервере INSTALL_COMPLETE, сначала выберите узкую диагностику.'],warning=True)
        if self.confirm_removal('ОТКАТ SSH / UFW',
                     'Только проверенный незавершённый этап с rollback marker'):
            self.action('--removal-plan','recover-network','--confirm-network-only')

    def installed(self):
        items=[('Проверка Node','Статус сервиса/контейнера, только чтение'),
               ('Selfsteal и Nginx','Статический аудит сокетов и конфигураций'),
               ('Сайты — каталог','120 доступных ID'),
               ('Сайты — статус','Состояние текущего сайта'),
               ('Сайты — установить','Начальное развёртывание в staging'),
               ('Сайты — сменить','Смена ранее установленной темы в staging'),
               ('Сайты — откат','Только staging, с подтверждением домена'),
               ('FinalMask','Включение/выключение в экспортируемом клиентском JSON'),
               ('Версия Xray','Только информация, без обновления'),
               ('RKN Guard','Текущий статус'),
               ('Обслуживание','Статус timer/maintenance'),
               ('Backup','Создать backup ноды (не snapshot VPS)'),
                   ('Дополнительные транспорты','Генераторы и проверки, не активация служб'),
                   ('Сетевые лимиты','Состояние, активация и новый расчётный период'),
                   ('REALITY — ключи','Приватный просмотр и выборочное копирование полей')]
        while True:
            idx=self.menu('УПРАВЛЕНИЕ NODE',items)
            if idx is None:return
            command={0:['--check'],1:['--diagnose-selfsteal'],2:['--site-manager','list'],
                     3:['--site-manager','status'],8:['--xray-versions'],9:['--rkn-status'],
                     10:['--maintenance-status']}.get(idx)
            if command:
                self.action(*command)
            elif idx in (4,5,6):
                if not has_root():self.message('Нужен root',['Запусти sudo bash install.sh --menu']);continue
                theme=self.themes() if idx in (4,5) else None
                if idx in (4,5) and theme is None:continue
                try:
                    conf=Path('/etc/vkarmani-node/config.json')
                    st=conf.lstat()
                    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1:
                        raise ValueError('UNSAFE_CONFIG')
                    domain=validate_domain(json.loads(conf.read_text())['domain'])
                except (OSError,ValueError,KeyError,TypeError):
                    self.message('КОНФИГУРАЦИЯ',['Не удалось безопасно прочитать текущий FQDN.'],warning=True)
                    continue
                if idx==6 and not self.confirm_removal('ОТКАТ САЙТА',
                    'Возврат предыдущей управляемой версии сайта'):continue
                action={4:'deploy',5:'change',6:'rollback'}[idx]
                args=['--site-manager',action,'--confirm-staging']
                if idx in (4,5):args+=['--theme',theme,'--expected-domain',domain]
                self.action(*args)
            elif idx==7:
                self.message('FinalMask',['FinalMask применяется к клиентскому исходящему Xray JSON.',
                            'Не меняет серверную ноду или подписки Remnawave автоматически.'],warning=True)
                action=self.menu('FINALMASK', [('Статус','Прочитать текущий client.json'),
                      ('Включить','Новый файл; числовые параметры задаёт оператор'),
                      ('Выключить','Новый файл без FinalMask; исходный не меняется')])
                if action is None:continue
                input_path=self.field('FinalMask','Абсолютный путь к приватному client.json')
                if not input_path:continue
                tag=self.field('FinalMask','Outbound tag',initial='proxy')
                if not tag:continue
                if action==0:
                    self.action('--finalmask','status','--input',input_path,'--outbound-tag',tag)
                    continue
                output_path=self.field('FinalMask','НОВЫЙ путь client-variant.json (исходный не изменяется)')
                if not output_path:continue
                cmd=['--finalmask','enable' if action==1 else 'disable','--input',input_path,
                     '--output',output_path,'--outbound-tag',tag]
                if action==1:
                    values=[]
                    for name,prompt,default in [('lengths','Фрагменты TLS, байты','80-160'),
                                                ('delays','Задержка, мс','0-5'),
                                                ('max-split','Число разбиений','2-4')]:
                        value=self.field('FinalMask / '+name,prompt,initial=default)
                        if value is None:break
                        values.extend(['--'+name,value])
                    if len(values)!=6:continue
                    cmd+=values
                self.action(*cmd)
            elif idx==11:
                self.action('--backup')
            elif idx==12:
                self.message('Экспериментальные транспорты',['XHTTP/TLS/H2, Hysteria2 и AWG2 имеют генераторы/аудит.',
                            'Их сервисы не считаются установленными или испытанными.',
                            'Команды: bash install.sh --optional-transport --help',
                            '          bash install.sh --transport-readiness --help'],warning=True)
            elif idx==13:
                task=self.menu('СЕТЕВЫЕ ЛИМИТЫ',[
                    ('Показать настройки и расход','Только чтение; накопительный учёт'),
                    ('Активировать сохранённые лимиты','Восстановление после частичной установки'),
                    ('Начать новый расчётный период','Сброс счётчиков, только по решению оператора')])
                if task==0:self.action('--traffic-limits','status')
                elif task==1:self.action('--traffic-limits','activate')
                elif task==2 and self.confirm_removal('СБРОС РАСХОДА',
                    'Только после реального начала нового периода у провайдера'):
                    self.action('--traffic-limits','reset','--confirm-new-period')
            elif idx==14:
                self.keys_screen()

    def run(self):
        entries=[('ПРОВЕРКА VPS','Автоматически: IP/ASN, сервисы, DNS, ping, скорость, CPU/RAM/диск, экспорт'),
                 ('УСТАНОВКА NODE','Пошаговый мастер, Авто (Рандом) сайт первым'),
                 ('ОТМЕНИТЬ НЕУДАЧНУЮ УСТАНОВКУ','Диагностика checkpoint и доступный ограниченный rollback'),
                 ('ПОЛНОЕ УДАЛЕНИЕ NODE INSTALL','План + безопасный возврат через проверенный snapshot'),
                 ('УПРАВЛЕНИЕ НОДОЙ','Сайт, selfsteal, FinalMask, backup и обслуживание'),
                 ('ВЫЙТИ ИЗ УСТАНОВЩИКА','Вернуться в обычную SSH-консоль без закрытия сеанса')]
        while True:
            selection=self.menu('ГЛАВНОЕ МЕНЮ',entries,status_brief())
            if selection is None:return 0
            if selection==0:self.vps()
            elif selection==1:self.wizard()
            elif selection==2:self.remove(full=False)
            elif selection==3:self.remove(full=True)
            elif selection==4:self.installed()
            elif selection==5:return 0


def plain_main():
    """Deterministic functional fallback for TERM=dumb; no hidden ANSI prompt."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('NODE_MENU=STOP INTERACTIVE_TTY_REQUIRED (ssh -t)',file=sys.stderr)
        return 2
    choices=['Комплексная проверка VPS (только чтение)',
             'Установка Node (требуется полноценный терминал)',
             'План восстановления после сбоя','План полного удаления','Выйти из установщика']
    while True:
        print('\nNODE INSTALL  |  '+status_brief())
        for i,label in enumerate(choices,1):print(f' {i}. {label}')
        try:choice=input('Пункт: ').strip()
        except (EOFError,KeyboardInterrupt):return 0
        if choice in ('0','5','q'):return 0
        if choice=='1':
            cp=subprocess.run([sys.executable,'-I',str(INTEGRATIONS/'vps_dashboard.py'),'full'],
                              capture_output=True,text=True,timeout=180,check=False)
            try:
                record=next(json.loads(row)['report'] for row in cp.stdout.splitlines()
                       if json.loads(row).get('type')=='result')
                print(vps_report.plain_text(record))
                print('Для просмотра страниц и PNG запустите полноценный TERM=xterm-256color интерфейс.')
            except (ValueError,KeyError,StopIteration):
                print('Диагностика не завершена; проверьте сетевые соединения.')
        elif choice in ('3','4'):
            subprocess.run(['bash',str(INSTALLER),'--removal-plan','plan'],check=False)
            if choice=='4':print('Полное удаление безопасно только через snapshot хостера.')
        elif choice=='2':
            print('Для защищённого мастера: TERM=xterm-256color sudo bash install.sh --menu')
        else:print('Неизвестная команда.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plain',action='store_true')
    parser.add_argument('--preview-main',action='store_true',help='read-only deterministic text preview')
    args=parser.parse_args(argv)
    if args.preview_main:
        print('NODE INSTALL / ГЛАВНОЕ МЕНЮ')
        print(status_brief())
        for name in ('ПРОВЕРКА VPS','УСТАНОВКА NODE','ОТМЕНИТЬ НЕУДАЧНУЮ УСТАНОВКУ',
                     'ПОЛНОЕ УДАЛЕНИЕ NODE INSTALL','УПРАВЛЕНИЕ NODE',
                     'ВЫЙТИ ИЗ УСТАНОВЩИКА'):
            print(' • '+name)
        return 0
    if args.plain or not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get('TERM','dumb')=='dumb':
        return plain_main()
    try:
        return curses.wrapper(lambda win:Terminal(win).run())
    except curses.error:
        return plain_main()


if __name__=='__main__':
    raise SystemExit(main())
