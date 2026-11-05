#!/usr/bin/env python3
"""Node Install interactive terminal front-end (stdlib curses; no new services).

The existing Bash installer remains the only authority for system mutations.
This UI never silently alters OS settings, never logs secret input and never
calls an unreviewed uninstall. SSH-friendly arrow/number controls and a separate
scrollable command log; plain fallback for terminals lacking curses capability.
"""
import argparse
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
import subprocess
import sys
import time
from collections import deque

ROOT=Path(__file__).resolve().parents[1]
INSTALLER=ROOT/'install.sh'
STATE=Path('/var/lib/vkarmani-node')
SCRIPTS=ROOT/'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))
from site_catalog import NAMES as GENERATED, THEMES as GENERATED_META
from cover_variants import NAMES as HANDMADE, THEMES as HANDMADE_META
THEMES=tuple(HANDMADE)+tuple(GENERATED)

def theme_meta(theme):
    if theme in GENERATED_META:
        t=GENERATED_META[theme]
        return (t.title,t.category,t.headline,t.language)
    meta=HANDMADE_META[theme]
    return (meta['label'],meta['section'],meta['intro'],'ru')

REALITY=('local','max.ru','ya.ru','rutube.ru','mail.ru')
USAGE_HINT='↑↓/jk выбор · Enter подтвердить · Esc назад · 0 выход'
MAX_LOG_LINES=700


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
    validate_panel_ip(settings['panel_ip'])
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
    panel_ip=validate_panel_ip(panel_ip)
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


class Terminal:
    def __init__(self,win):
        self.save_reports=False
        self.win=win
        self.colors=False
        if curses.has_colors() and os.environ.get('NO_COLOR') is None:
            curses.start_color()
            try:curses.use_default_colors()
            except curses.error:pass
            # black background; green typography, amber warnings, red failures
            for num,fg,bg in ((1,curses.COLOR_GREEN,curses.COLOR_BLACK),
                               (2,curses.COLOR_BLACK,curses.COLOR_GREEN),
                               (3,curses.COLOR_YELLOW,curses.COLOR_BLACK),
                               (4,curses.COLOR_RED,curses.COLOR_BLACK)):
                curses.init_pair(num,fg,bg)
            self.colors=True
        curses.curs_set(0)
        win.keypad(True)
        self.note=''

    def attr(self,kind=1,bold=False):
        return (curses.color_pair(kind) if self.colors else 0)|(curses.A_BOLD if bold else 0)

    def put(self,y,x,text,*,kind=1,bold=False):
        height,width=self.win.getmaxyx()
        if y<0 or y>=height or x<0 or x>=width-1:return
        try:self.win.addnstr(y,x,str(text),max(0,width-x-1),self.attr(kind,bold))
        except curses.error:pass

    def paint(self,title,subtitle='',footer=USAGE_HINT):
        self.win.erase()
        height,width=self.win.getmaxyx()
        self.put(0,2,'NODE INSTALL  /  VKARMANI',bold=True)
        self.put(1,2,'─'*max(0,width-4))
        self.put(2,2,title.upper(),bold=True)
        self.put(3,2,subtitle[:max(0,width-4)])
        self.put(height-3,2,'─'*max(0,width-4))
        self.put(height-2,2,footer)
        if self.note:self.put(height-4,2,self.note,kind=3)
        self.win.refresh()

    def message(self,title,lines,*,wait=True,warning=False):
        self.paint(title,footer='ENTER / ESC — назад')
        h,w=self.win.getmaxyx(); row=5
        for line in lines:
            for sub in linewrap(line,max(20,w-6)):
                if row>=h-5:break
                self.put(row,3,sub,kind=3 if warning else 1)
                row+=1
        self.win.refresh()
        if wait:self.win.getch()

    def menu(self,title,items,subtitle='',*,start=0,footer=USAGE_HINT,auto_zero=False):
        """Items [(label,detail)], returns index or None. Paging is automatic."""
        i=min(start,len(items)-1) if items else 0
        while True:
            self.paint(title,subtitle,footer)
            h,w=self.win.getmaxyx()
            available=max(3,(h-10)//2)
            offset=max(0,min(i-available//2,max(0,len(items)-available)))
            for pos in range(offset,min(len(items),offset+available)):
                y=5+2*(pos-offset)
                label,desc=items[pos]
                selected=pos==i
                prefix='' if auto_zero and pos==0 else '%02d. '%(pos if auto_zero else pos+1)
                text=('❯ ' if selected else '  ')+prefix+label
                self.put(y,3,text,kind=2 if selected else 1,bold=selected)
                self.put(y+1,6,desc[:max(0,w-9)],kind=1)
            self.put(h-5,3,f'{i+1}/{len(items)} · прокрутка' if items else 'Пусто')
            self.win.refresh()
            key=self.win.getch()
            if key==ord('0') and auto_zero:return 0
            if key in (27,ord('0'),ord('q')):return None
            if key in (curses.KEY_UP,ord('k')):i=(i-1)%len(items)
            elif key in (curses.KEY_DOWN,ord('j')):i=(i+1)%len(items)
            elif key in (curses.KEY_PPAGE,):i=max(0,i-available)
            elif key in (curses.KEY_NPAGE,):i=min(len(items)-1,i+available)
            elif key in (curses.KEY_HOME,):i=0
            elif key in (curses.KEY_END,):i=len(items)-1
            elif key in (10,13,curses.KEY_ENTER):return i
            elif 49<=key<=57:
                n=key-49
                if n<len(items):return n

    def field(self,title,prompt,*,secret=False,maxlen=253,initial=''):
        """Safe UTF-8 keyboard input; hidden secret is never printed or logged."""
        value=list(initial)
        while True:
            self.paint(title,prompt,footer='ENTER — принять · ESC — отменить · Backspace — стереть')
            h,w=self.win.getmaxyx()
            masked=('●'*min(len(value), max(1,w-9))) if secret else ''.join(value)
            if len(masked)>w-9:masked='…'+masked[-(w-10):]
            self.put(6,3,'> '+masked)
            self.win.refresh()
            try:key=self.win.get_wch()
            except curses.error:continue
            if key in ('\n','\r',curses.KEY_ENTER):return ''.join(value)
            if key=='\x1b':return None
            if key in ('\b','\x7f',curses.KEY_BACKSPACE):
                if value:value.pop()
            elif key==curses.KEY_DC: value=[]
            elif isinstance(key,str) and key.isprintable() and len(value)<maxlen:
                value.append(key)

    def agree(self,title,text,phrase):
        self.message(title,linewrap(text,max(20,self.win.getmaxyx()[1]-7)),wait=False,warning=True)
        entered=self.field(title,f'Для продолжения напиши точно: {phrase}',maxlen=64)
        return entered==phrase

    def logs(self,title,command,*,pass_fd=None,redact=()):
        """Log pane runs a bounded external command. No credentials in argv."""
        log=deque(maxlen=MAX_LOG_LINES)
        old_sig=signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        self.win.nodelay(True)
        try:
            with subprocess.Popen(command,stdin=subprocess.DEVNULL,
                     stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                     env={**os.environ,'PYTHONUTF8':'1'},
                     pass_fds=((pass_fd,) if pass_fd is not None else ()),bufsize=0) as proc:
                channel=proc.stdout.fileno()
                os.set_blocking(channel,False)
                remainder=b''; scroll=0; auto=True
                while True:
                    ready,_,_=select.select([channel],[],[],0.12)
                    if ready:
                        try:chunk=os.read(channel,32768)
                        except BlockingIOError:chunk=b''
                        if chunk:
                            remainder+=chunk
                            # Bound any untrusted stdout line and never echo live secrets.
                            if len(remainder)>65536 and b'\n' not in remainder:
                                log.append('[TRUNCATED LONG LOG LINE]')
                                remainder=b''
                            while b'\n' in remainder:
                                row,remainder=remainder.split(b'\n',1)
                                text=row.decode('utf-8','replace').replace('\x1b','?')
                                for private in redact:
                                    if private:text=text.replace(private,'[REDACTED]')
                                log.append(text[:1000])
                    self.paint(title,'Команда выполняется · PgUp/PgDn прокрутка; Esc после завершения',
                               footer='PgUp/PgDn — прокрутка · End — к последней строке · Esc — после завершения')
                    h,w=self.win.getmaxyx(); slots=max(1,h-10)
                    if auto:scroll=max(0,len(log)-slots)
                    for y,line in enumerate(list(log)[scroll:scroll+slots],start=5):
                        self.put(y,2,line[:max(0,w-4)],kind=(4 if any(word in line for word in ('DNS_ERROR','TLS_ERROR','TCP_ERROR','STOP:','TIMEOUT','INVALID','UNREACHABLE')) else (3 if 'REVIEW' in line or 'RESTRICTED_OR_PROTECTED' in line or 'AUTH_REQUIRED' in line else 1)))
                    done=proc.poll() is not None
                    self.put(h-5,2,('Завершено; код '+str(proc.returncode) if done else 'Выполняется...'),
                             kind=1 if done and proc.returncode==0 else 3)
                    self.win.refresh()
                    key=self.win.getch()
                    if key==curses.KEY_PPAGE:auto=False;scroll=max(0,scroll-slots)
                    if key==curses.KEY_NPAGE:auto=False;scroll=min(max(0,len(log)-slots),scroll+slots)
                    if key==curses.KEY_END:auto=True
                    if done and key in (27,10,13,ord('q')):
                        break
                    if done and not ready and not remainder:
                        # Remain on result screen until operator acknowledges.
                        pass
                    if done and remainder:
                        text=remainder.decode('utf-8','replace')
                        for private in redact:
                            if private:text=text.replace(private,'[REDACTED]')
                        log.append(text[:1000]);remainder=b''
                return proc.returncode
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            self.message('Команда не запущена',[type(exc).__name__,'Изменения не подтверждены.'],warning=True)
            return 2
        finally:
            self.win.nodelay(False)
            signal.signal(signal.SIGINT,old_sig)

    def action(self,*args):
        return self.logs('ЖУРНАЛ / РЕЗУЛЬТАТ', ['bash',str(INSTALLER),*args])

    def themes(self):
        """Auto first, followed by category/search and genuine catalog descriptions."""
        terms=THEMES
        while True:
            items=[('00. АВТО (РАНДОМ)','Одна случайная проверенная тема, без ротации после установки'),
                   ('ПОИСК','Поиск по ID, названию и тематике'),
                   ('КАТЕГОРИИ','Выбрать сайт по направлению / тематике'),
                   ('ПОКАЗАТЬ ВСЕ','Показать 120 тем')]
            items += [(f'{theme} — {theme_meta(theme)[0]}',
                       f'{theme_meta(theme)[1]} · {theme_meta(theme)[3]}') for theme in terms]
            pos=self.menu('ВЫБОР САЙТА',items,f'120 тем · 0 = Авто (Рандом) · ESC = назад; фильтр: {len(terms)}',auto_zero=True)
            if pos is None:return None
            if pos==0:
                chosen=choose_random_theme()
                self.message('АВТО (РАНДОМ)',[f'Выбран: {chosen}',theme_meta(chosen)[0],
                             'Выбор фиксируется для данного запуска мастера.'])
                return chosen
            if pos==1:
                term=self.field('ПОИСК САЙТА','Название, ID или тематика')
                if term is None:continue
                terms=tuple(x for x in THEMES if term.casefold() in
                            (' '.join((x,*theme_meta(x)))).casefold())
                if not terms:self.message('Поиск',['Совпадений нет.']);terms=THEMES
            elif pos==2:
                categories=sorted({theme_meta(x)[1] for x in THEMES},key=str.casefold)
                cat=self.menu('ТЕМАТИКА САЙТА',[(x,f'{sum(theme_meta(t)[1]==x for t in THEMES)} тем')
                                       for x in categories])
                if cat is not None:
                    terms=tuple(x for x in THEMES if theme_meta(x)[1]==categories[cat])
            elif pos==3:terms=THEMES
            else:
                chosen=terms[pos-4]
                title,category,description,lang=theme_meta(chosen)
                self.message('ПРЕДПРОСМОТР ТЕМЫ',[
                      f'ID: {chosen}',f'Название: {title}',f'Категория: {category}',
                      f'Язык: {lang}',f'Описание: {description}',
                      'Галерея на компьютере: preview/site-gallery/index.html',
                      'В меню можно выбрать другую тему без изменений сервера.'])
                selected=self.menu('ПОДТВЕРДИТЬ ТЕМУ',[
                    ('ВЫБРАТЬ ЭТОТ САЙТ',f'{chosen} · {title}'),
                    ('Вернуться к каталогу','Выбор не сохранён')])
                if selected==0:return chosen


    def wizard(self):
        if not has_root():
            self.message('Права доступа',['Для установки нужен root: sudo bash install.sh --menu'],warning=True)
            return
        if not preinstall_state_guard():
            self.message('Установка запрещена',['На VPS обнаружены следы установки или незавершённые операции.',
                           'Используй диагностику/восстановление. Данные не перезаписаны.'],warning=True)
            return
        mode_id=self.menu('ТИП УСТАНОВКИ',[('Обычная Node','VLESS / RAW / REALITY / Selfsteal'),
                            ('Cascade Entry','Входная нода, нужен закрытый bundle'),
                            ('Cascade Exit','Выходная нода, нужен закрытый bundle')])
        if mode_id is None:return
        mode=('ordinary','entry','exit')[mode_id]
        theme=self.themes() if mode=='ordinary' else None
        if mode=='ordinary' and theme is None:return
        bundle=None
        if mode!='ordinary':
            bundle=self.field('Ролевой bundle','Абсолютный путь к role-bundle.json (root:0600)')
            if not bundle:return
            try:
                st=Path(bundle).lstat()
                if not Path(bundle).is_absolute() or not Path(bundle).is_file() or st.st_uid!=0 or st.st_mode & 0o077:
                    raise ValueError()
            except (OSError,ValueError):
                self.message('Небезопасный bundle',['Нужен существующий обычный файл root:0600.'],warning=True)
                return
        # Collect once, no credentials ever in argv / environment / stdout.
        raw_secret=self.field('ОБЯЗАТЕЛЬНЫЕ ДАННЫЕ','SECRET_KEY из Remnawave (скрыто)',secret=True,maxlen=65536)
        if raw_secret is None:return
        domain=self.field('ДОМЕН НОДЫ','FQDN, например node.example.com')
        if domain is None:return
        panel_ip=self.field('IP ПАНЕЛИ','Публичный IPv4 панели (не IP этой VPS)')
        if panel_ip is None:return
        try:
            secret=validate_secret(raw_secret)
            domain=validate_domain(domain)
            panel_ip=validate_panel_ip(panel_ip)
        except ValueError as exc:
            self.message('Неверные данные',[str(exc),'Никаких изменений не выполнено.'],warning=True)
            return
        reality='local'
        if mode=='ordinary':
            pos=self.menu('REALITY / SNI',[(x,('Свой HTTPS-сайт' if x=='local' else 'Проверяется внешний TLS target')) for x in REALITY])
            if pos is None:return
            reality=REALITY[pos]
            if self.menu('ТРАНСПОРТ', [('RAW + REALITY + Vision','Основной поддерживаемый вариант'),
                        ('XHTTP / Hysteria2 / AWG2','Только отдельные staging-инструменты, не включаются автоматически')])!=0:
                self.message('Транспорт',['В автоматической установке доступен RAW + REALITY + Vision.',
                              'Дополнительные шаблоны доступны в Управлении / Инструментах.'],warning=True)
                return
        extra=self.menu('ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ',[
            ('ПРОПУСТИТЬ','Сохранить штатные безопасные значения (рекомендовано)'),
            ('НАСТРОИТЬ','Необязательные параметры порта и перезагрузки')])
        if extra is None:return
        no_reboot=True;port=None;weekly=False
        if extra==1:
            if mode=='ordinary':
                p=self.field('Node API порт','Пусто = 2222; не TCP/443 и не 61001',initial='')
                if p is None:return
                if p:
                    try:port=int(p)
                    except ValueError:port=-1
                    if not 1024<=port<=65535 or port in (443,61001):
                        self.message('Неверный порт',['Разрешено: 1024–65535 кроме 61001; исключён публичный 443'],warning=True)
                        return
                weekly=self.menu('ПЛАНОВАЯ ПЕРЕЗАГРУЗКА',[
                    ('Выключена','Не делать еженедельный перезапуск (рекомендовано)'),
                    ('Включена','Только Ordinary; прерывает активные соединения')])==1
            reboot=self.menu('ПОСЛЕ УСТАНОВКИ',[
                ('Без автоматического reboot','Проверить результат, перезагрузить вручную'),
                ('Разрешить один reboot','Нужна консоль хостера и snapshot')])
            if reboot is None:return
            no_reboot=reboot==0
        settings=dict(mode=mode,site=theme,domain=domain,panel_ip=panel_ip,reality=reality,
                      bundle=bundle,no_reboot=no_reboot,node_port=port,weekly_reboot=weekly)
        review=['Роль: '+mode,'Сайт: '+(theme or 'Не применяется'),
                'Домен: '+domain,'Панель IPv4: '+panel_ip,
                'REALITY: '+reality,'Транспорт: RAW/REALITY (для Ordinary)',
                'Секрет: ******** (скрыт)','Node API: '+str(port or 2222),
                'Auto reboot: '+('нет' if no_reboot else 'да'),
                'Потребуется snapshot и доступ к консоли хостера.',
                'Будут изменены SSH/UFW/IPv6/GRUB, Docker, Nginx и другие службы.']
        self.message('ПЕРЕД УСТАНОВКОЙ',review)
        if not self.agree('ПОДТВЕРДИТЕ ОПАСНЫЕ ИЗМЕНЕНИЯ',
                          'Подтверждаю, что VPS тестовая/выделенная, snapshot проверен, консоль хостера доступна.',
                          'INSTALL'):
            return
        fd=None
        try:
            fd=secret_fd(secret,panel_ip,domain)
            cmd=wizard_argv(settings,fd=fd)
            # Retain private string only for optional log redaction; never print it.
            raw_secret=''
            rc=self.logs('УСТАНОВКА NODE / ЖИВОЙ ЖУРНАЛ',cmd,pass_fd=fd,redact=(secret,))
        finally:
            if fd is not None:os.close(fd)
        self.message('ИТОГ УСТАНОВКИ', [f'Код возврата: {rc}',
                     '0 — installer reported success; check server after reboot.',
                     '20 — нода завершена, выбранный сайт не опубликован.',
                     'Не удаляйте checkpoint/backup при ошибке; проверьте журнал.'],warning=rc!=0)

    def vps(self):
        choices=[('Быстрая проверка VPS','ОС, RAM, диск, сеть, маркеры; без изменений'),
                 ('Доступность сервисов','VK / Яндекс / MAX / YouTube / Reddit / GitHub / X / GPT / AI'),
                 ('ICMP Ping и потери','Задержка и потери, если сервис разрешает ICMP'),
                 ('HTTPS Jitter и скачки','p50/p95, jitter, failure rate, не ICMP'),
                 ('Прыжки / Traceroute','Маршрут и видимые узлы, если traceroute установлен'),
                 ('Тест скорости Download/Upload','Только к СВОЕМУ iperf3 серверу, расход трафика'),
                 ('GeoIP / Cloudflare Edge','Внешний HTTPS-запрос; Cloudflare увидит IP VPS'),
                 ('Проверить свой домен','Только публичная HTTPS-цель; защита SSRF'),
                 ('Сетевая диагностика ядра','BBR, qdisc, NIC, conntrack, только чтение'),
                 ('Сохранение результатов','ВКЛ/ВЫКЛ · сейчас НЕ сохраняются автоматически'),
                 ('История проверок','Просмотр имён сохранённых отчётов'),
                 ('Посмотреть отчёт','Открыть сохранённый результат по ID'),
                 ('Сравнить отчёты','Сопоставить две проверки одного типа')]
        while True:
            pos=self.menu('ПРОВЕРКА VPS / СЕТЬ',choices,'Выбери проверку; внешние запросы только по явному выбору')
            if pos is None:return
            if pos==9:
                self.save_reports=not self.save_reports
                choices[9]=('Сохранение результатов',
                            'ВКЛ — только явно запущенные пробы' if self.save_reports else 'ВЫКЛ — без записи на диск')
                continue
            if pos==10:
                self.action('--vps-check','history');continue
            if pos==11:
                name=self.field('ИСТОРИЯ','Имя JSON файла отчёта (из раздела История)')
                if name:self.action('--vps-check','show',name)
                continue
            if pos==12:
                first=self.field('СРАВНЕНИЕ','Имя более раннего JSON отчёта')
                second=self.field('СРАВНЕНИЕ','Имя более позднего JSON отчёта') if first else None
                if first and second:self.action('--vps-check','compare',first,second)
                continue
            cmd=['--vps-check']
            if pos==0:cmd+=['local']
            elif pos==1:cmd+=['services']
            elif pos in (2,3,4,7):
                host=self.field('ЦЕЛЬ ПРОВЕРКИ','Публичный домен / IPv4',initial='cloudflare.com' if pos<7 else '')
                if not host:continue
                if pos==2:cmd+=['ping','--host',host]
                elif pos==3:cmd+=['quality','--host',host]
                elif pos==4:cmd+=['trace','--host',host]
                else:
                    port=self.field('HTTPS ПОРТ','Введите TCP порт, Enter = 443',initial='443')
                    if port is None:continue
                    if not port.isdecimal() or not 1<=int(port)<=65535:
                        self.message('Порт HTTPS',['Допустимо число 1..65535.'],warning=True);continue
                    cmd+=['custom','--host',host,'--port',port]
            elif pos==5:
                ip=self.field('Тест скорости','Публичный IPv4 ТВОЕГО iperf3 сервера')
                if not ip:continue
                try:validate_panel_ip(ip)
                except ValueError:self.message('Ошибка',['Требуется публичный IPv4.'],warning=True);continue
                if not self.agree('НАБЛЮДЕНИЕ ЗА НАГРУЗКОЙ',
                       'Тест запускается против указанного тобой iperf3 сервера и расходует трафик. Другая сторона должна быть твоей.', 'SPEED'):
                    continue
                cmd+=['speed','--server',ip,'--seconds','5']
            elif pos==6:
                if not self.agree('GEOIP / CDN',
                   'Cloudflare получит публичный IP VPS. Запрос без токенов и клиентских данных.', 'GEOIP'):
                    continue
                cmd+=['edge']
            elif pos==8:cmd=['--diagnose-network']
            if cmd[0]=='--vps-check':
                cmd[1:1]=['--format','table']+(['--save'] if self.save_reports else [])
            self.action(*cmd)

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
        if self.agree('ТОЛЬКО ЛОКАЛЬНЫЙ SSH/UFW ROLLBACK',
                     'Команда доступна только при проверенном незавершённом этапе и его rollback marker. После проверь SSH из консоли.',
                     'NETWORK ROLLBACK'):
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
               ('Дополнительные транспорты','Генераторы и проверки, не активация служб')]
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
                domain=self.field('Подтверждение','Повтори текущий FQDN ноды')
                if not domain:continue
                if not self.agree('STAGING — ОПАСНАЯ ОПЕРАЦИЯ',
                       'Смена сайта требует завершённой staging-ноды и сохранного backup.', 'STAGING'):
                    continue
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
                if self.agree('BACKUP','Backup содержит секреты. Защити копию и проверь snapshot VPS.', 'BACKUP'):
                    self.action('--backup')
            elif idx==12:
                self.message('Экспериментальные транспорты',['XHTTP/TLS/H2, Hysteria2 и AWG2 имеют генераторы/аудит.',
                            'Их сервисы не считаются установленными или испытанными.',
                            'Команды: bash install.sh --optional-transport --help',
                            '          bash install.sh --transport-readiness --help'],warning=True)

    def run(self):
        entries=[('ПРОВЕРКА VPS','Ресурсы, связь, сервисы, ping, потери, скорость, маршруты'),
                 ('УСТАНОВКА NODE','Пошаговый мастер, Авто (Рандом) сайт первым'),
                 ('ОТМЕНИТЬ НЕУДАЧНУЮ УСТАНОВКУ','Диагностика checkpoint и доступный ограниченный rollback'),
                 ('ПОЛНОЕ УДАЛЕНИЕ NODE INSTALL','План + безопасный возврат через проверенный snapshot'),
                 ('УПРАВЛЕНИЕ НОДОЙ','Сайт, selfsteal, FinalMask, backup и обслуживание')]
        while True:
            selection=self.menu('ГЛАВНОЕ МЕНЮ',entries,status_brief())
            if selection is None:return 0
            if selection==0:self.vps()
            elif selection==1:self.wizard()
            elif selection==2:self.remove(full=False)
            elif selection==3:self.remove(full=True)
            elif selection==4:self.installed()


def plain_main():
    """Deterministic functional fallback for TERM=dumb; no hidden ANSI prompt."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('NODE_MENU=STOP INTERACTIVE_TTY_REQUIRED (ssh -t)',file=sys.stderr)
        return 2
    choices=['Проверка VPS (локально, только чтение)',
             'Установка Node (требуется полноценный терминал)',
             'План восстановления после сбоя','План полного удаления','Выход']
    while True:
        print('\nNODE INSTALL  |  '+status_brief())
        for i,label in enumerate(choices,1):print(f' {i}. {label}')
        try:choice=input('Пункт: ').strip()
        except (EOFError,KeyboardInterrupt):return 0
        if choice in ('0','5','q'):return 0
        if choice=='1':
            subprocess.run(['bash',str(INSTALLER),'--vps-check','local'],check=False)
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
                     'ПОЛНОЕ УДАЛЕНИЕ NODE INSTALL','УПРАВЛЕНИЕ NODE'):
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
