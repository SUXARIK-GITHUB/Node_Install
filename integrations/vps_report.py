#!/usr/bin/env python3
"""Russian sectioned VPS report, safe private TXT/JSON/PNG exports.

PNG is encoded with Python stdlib and a small *hand-drawn* 5x7 alphabet;
no Pillow, system fonts, native converters, HTML viewer, or installation needed.
The export is a diagnostic infographic, not a screenshot of another app.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import textwrap
import zlib

KINDS={'good':6,'warn':3,'bad':4,'info':7,'heading':11,'normal':1,'dim':5}
TRANSLATIONS={
 'REACHABLE':'Доступен','AUTH_REQUIRED':'Нужен вход',
 'RATE_LIMITED':'Лимит запросов','RESTRICTED_OR_PROTECTED':'403/451 · ограничение/защита',
 'HTTP_RESPONSE':'Есть HTTP-ответ','DNS_ERROR':'Ошибка DNS',
 'TLS_ERROR':'Ошибка TLS','TLS_CERT_ERROR':'Недоверенный TLS',
 'TIMEOUT':'Таймаут','TCP_ERROR':'Ошибка TCP','HTTP_INVALID':'Неверный HTTP',
 'MEASURED':'Измерено','PASS':'Успешно','INFO':'Информация','REVIEW':'Проверьте',
 'SKIPPED':'Не запускали','PARTIAL':'Частично измерено','UNVERIFIED':'Не измерено','TOOL_NOT_INSTALLED':'Утилиты нет',
 'TEMP_FSYNC_COMPLETED':'Временная запись завершена'
}


def _value(x,default='—',limit=130):
    if x is None:return default
    if isinstance(x,(tuple,list)):
        x=', '.join(map(str,x[:12]))
    if isinstance(x,dict):return default
    return re.sub(r'\s+',' ',''.join(c for c in str(x) if c.isprintable())).strip()[:limit] or default


def _row(label,value,style='normal'):
    return (f'{label:<24} {_value(value)}',style)


def _title(label):return (label,'heading')


def _explanation(value):return ('  '+value,'dim')


def _state(status):
    return TRANSLATIONS.get(status,_value(status))


def _kind(status):
    if status in ('PASS','REACHABLE','AUTH_REQUIRED','MEASURED','INFO','TEMP_FSYNC_COMPLETED'):
        return 'good'
    if status in ('TIMEOUT','TLS_ERROR','TLS_CERT_ERROR','DNS_ERROR','TCP_ERROR','UNVERIFIED'):
        return 'bad'
    return 'warn'


def _field_status(doc):
    return _state(doc.get('status','UNVERIFIED'))


def sections(record):
    """Each section is a list of (clean text, palette role); no terminal escapes."""
    if not isinstance(record,dict) or record.get('kind')!='RUSSIAN_VPS_DIAGNOSTICS':
        raise ValueError('INVALID_VPS_REPORT_SCHEMA')
    host=record.get('host',{}) or {}
    geo=record.get('geo',{}) or {}
    svc=record.get('services',{}) or {}
    dns=record.get('dns',{}) or {}
    pings=record.get('ping',{}) or {}
    qual=record.get('quality',{}) or {}
    route=record.get('route',{}) or {}
    cdn=record.get('cdn',{}) or {}
    speed=record.get('speed',{}) or {}
    bench=record.get('benchmark',{}) or {}
    providers=[x for x in geo.get('observations',[]) if x.get('status')=='INFO']
    public_ips=sorted({x['ip'] for x in providers})
    items=[]
    overview=[_title('КОМПЛЕКСНАЯ ДИАГНОСТИКА VPS'),
       _row('Дата UTC:',record.get('created_utc')),
       _row('Результат:',_field_status(record),'warn' if record.get('status')=='REVIEW' else 'good'),
       _row('Публичный IPv4:',', '.join(public_ips) if public_ips else 'Не удалось подтвердить'),
       _row('Геолокация / страна:',geo.get('country_consensus')),
       _row('ASN / сеть:',providers[0].get('asn') if providers else 'Нет данных'),
       _row('Операционная система:',host.get('os')),
       _row('Модель CPU:',host.get('cpu_model')),
       _row('Логические CPU:',host.get('cpu_logical')),
       _row('ОЗУ:',str(host.get('ram_mib','—'))+' MiB'),
       _row('Свободно диска:',str(host.get('disk_free_gib',host.get('disk_free_mib','—')))+(' GiB' if host.get('disk_free_gib') else ' MiB')),
       _row('HTTPS-адресов:',str(len(svc.get('results',[])))+' проверено'),
       _row('Проверка скорости:',_field_status(speed)),
       _row('Тест производительности:',_field_status(bench)),
       ('', 'normal'),
       _title('КАК ЧИТАТЬ РЕЗУЛЬТАТЫ'),
       _explanation('ЗЕЛЁНЫЙ — подтверждённый ответ или измерение.'),
       _explanation('ЖЁЛТЫЙ — ограничение, пропуск или необходима проверка.'),
       _explanation('КРАСНЫЙ — ошибка соединения или отсутствие данных.'),
       _explanation('Внешние проверки относятся к самой VPS, НЕ к клиенту VPN.'),
       _explanation('Нельзя вывести IP-репутацию или реальную геоблокировку только по HTTP.'),
    ]
    items.append(('Обзор',overview))
    server=[_title('ПАРАМЕТРЫ СЕРВЕРА'),
       _row('ОС:',host.get('os')),_row('Ядро Linux:',host.get('kernel')),
       _row('Архитектура:',host.get('architecture')),
       _row('Процессор:',host.get('cpu_model')),
       _row('Потоки:',host.get('cpu_logical')),
       _row('Виртуализация:',host.get('virtualization')),
       _row('ОЗУ всего:',str(host.get('ram_mib','—'))+' MiB'),
       _row('ОЗУ доступно:',str(host.get('ram_available_mib','—'))+' MiB'),
       _row('SWAP всего:',str(host.get('swap_mib','—'))+' MiB'),
       _row('SWAP свободно:',str(host.get('swap_free_mib','—'))+' MiB'),
       _row('Диск всего:',str(host.get('disk_total_gib','—'))+' GiB'),
       _row('Диск свободно:',str(host.get('disk_free_gib','—'))+' GiB'),
       _row('Uptime:',str(host.get('uptime_hours','—'))+' ч'),
       _row('Load average:',host.get('load_average')),
       _row('TCP congestion:',host.get('tcp_congestion')),
       _row('Маршрут по умолч.:',host.get('default_route')),
       _title('СЛУЖБЫ (СТАТУС, НЕ РЕВИЗИЯ КОНФИГУРАЦИИ)')]
    for name,state in (host.get('services') or {}).items():
        server.append(_row(name,state,'good' if state=='ACTIVE' else 'warn'))
    server.append(_explanation('Отсутствие установленного ПО не считается ошибкой новой VPS.'))
    items.append(('Сервер',server))
    iprows=[_title('НЕЗАВИСИМЫЕ БАЗЫ GEO-IP / ASN'),
            ('Источник        Публичный IPv4        Страна   ASN          Организация','heading')]
    for row in geo.get('observations',[]):
        status=row.get('status','UNVERIFIED')
        iprows.append((f"{_value(row.get('source'),12):<16} {_value(row.get('ip'),18):<21} "
                       f"{_value(row.get('country'),5):<8} {_value(row.get('asn'),12):<12} "
                       f"{_value(row.get('organization'),40)}" if status=='INFO' else
                       f"{row.get('source','—')}: {_state(status)} ({_value(row.get('reason'))})",
                       _kind(status)))
    iprows.extend([('', 'normal'),
                   _row('Согласованная страна:',geo.get('country_consensus')),
                   _row('Разные страны:', 'ДА' if geo.get('country_discrepancy') else 'не обнаружено',
                        'warn' if geo.get('country_discrepancy') else 'good'),
                   _row('Разные IP:', 'ДА' if geo.get('ip_discrepancy') else 'не обнаружено',
                        'warn' if geo.get('ip_discrepancy') else 'good'),
                   _title('IP QUALITY / РИСКИ'),
                   _explanation('Скоринг VPN/Proxy/Tor/Fraud требует специализированных источников.'),
                   _explanation('Из ASN или страны нельзя делать вывод «чистый IP».'),
                   _explanation('Различие стран — повод уточнить данные у провайдера, не ошибка VPS.'),
                   _explanation('Каждый геосервис узнаёт внешний IP при запросе.')])
    items.append(('IP и репутация',iprows))
    services=[_title('ДОСТУПНОСТЬ ВЕБ-СЕРВИСОВ И API'),
              _explanation('Проверка TLS и HTTP с VPS, без логина, куки и обхода ограничений.'),
              ('Сервис                     HTTPS-статус                        HTTP    Ответ, мс','heading')]
    for row in svc.get('results',[]):
        code=row.get('http')
        ms=row.get('ttfb_ms')
        st=row.get('status','UNVERIFIED')
        services.append((f"{_value(row.get('service'),23):<26} {_state(st):<36} "
                         f"{str(code) if code is not None else '—':<7} {_value(ms)}",_kind(st)))
    services.extend([('', 'normal'),
       _title('ВАЖНО ПО ИНТЕРПРЕТАЦИИ'),
       _explanation('200/3xx — сервер ответил; это не означает доступность подписки.'),
       _explanation('401 — требуется вход; 403/451 — возможно anti-bot, WAF или регион.'),
       _explanation('429 — лимит запросов; timeout — сеть/фильтрация/сервис, причину надо уточнить.')])
    items.append(('Сервисы',services))
    dnsrows=[_title('DNS / IPV4 / CDN')]
    for row in dns.get('results',[]):
        st=row.get('status','UNVERIFIED')
        dnsrows.append((f"{_value(row.get('host'),26):<28} {_state(st):<15} "
                        f"{_value(row.get('ip'),16):<18} {_value(row.get('ms'))} мс",_kind(st)))
    dnsrows.extend([('', 'normal'),_title('CLOUDFLARE EDGE'),
         _row('Точка CDN:',cdn.get('edge_colo')),
         _row('Страна по CDN:',cdn.get('observed_country')),
         _explanation('Edge — маршрут до CDN, а не доказательство физической страны VPS.'),
         _explanation('IPv6 доступность здесь не измеряется; данные IPv4 не приписываются IPv6.')])
    items.append(('DNS и CDN',dnsrows))
    netrows=[_title('PING / ПОТЕРИ ПАКЕТОВ (ICMP)')]
    for row in pings.get('results',[]):
        netrows.append((f"{_value(row.get('target'),23):<25} {_state(row.get('status'))}  "
                        f"Loss: {_value(row.get('loss_pct'))}%  Avg: {_value(row.get('avg_ms'))} мс  "
                        f"Max: {_value(row.get('max_ms'))} мс",_kind(row.get('status'))))
    netrows.extend([('', 'normal'),_title('ЗАДЕРЖКА HTTPS (НЕ ICMP)')])
    for label,key in (('Успешных запросов','answered'),('Всего запросов','attempts'),
                      ('Ошибки HTTPS, %','failure_pct'),('Median p50, мс','p50_ms'),
                      ('p95, мс','p95_ms'),('Разброс jitter, мс','jitter_ms'),
                      ('Скачки','spikes')):
        netrows.append(_row(label+':',qual.get(key)))
    netrows.extend([('', 'normal'),_title('ПРОМЕЖУТОЧНЫЕ УЗЛЫ ДО GITHUB'),
        _row('Traceroute:',_field_status(route))])
    for hop in route.get('route',[])[:15]:netrows.append((_value(hop,100),'dim'))
    netrows.append(_explanation('Звёздочки в traceroute не доказывают потери у пользователей.'))
    items.append(('Задержки и маршрут',netrows))
    srows=[_title('АВТОМАТИЧЕСКАЯ ЭКСПРЕСС-ПРОВЕРКА СКОРОСТИ')]
    if speed.get('kind')=='AUTO_HTTPS_SPEED':
        srows.extend([_row('Тестовый сервер:',speed.get('server')),
                      _row('Статус:',_field_status(speed),_kind(speed.get('status'))),
                      _row('Скачивание / Download:',
                           str(speed['download_mbps'])+' Мбит/с' if speed.get('download_mbps') is not None else 'Не измерено',
                           'good' if speed.get('download_mbps') is not None else 'warn'),
                      _row('Отдача / Upload:',
                           str(speed['upload_mbps'])+' Мбит/с' if speed.get('upload_mbps') is not None else 'Не измерено',
                           'good' if speed.get('upload_mbps') is not None else 'warn')])
        for direction,name in (('download','Скачивание'),('upload','Отдача')):
            if speed.get(direction+'_reason'):
                srows.append(_explanation(name+': причина — '+_value(speed[direction+'_reason'])))
        if speed.get('reason'):srows.append(_explanation('DNS/доступ: '+_value(speed['reason'])))
        srows.extend([_explanation('До 2 MiB в каждом направлении. Это короткий тест одного HTTPS-соединения.'),
                      _explanation('Он не показывает гарантированную скорость порта VPS или VPN-клиента.'),
                      _explanation('Тест полностью автоматический: ничего вводить не требуется.')])
    elif speed.get('status')=='SKIPPED':
        srows.extend([('Скорость не измерена.','warn'),
                      _explanation('Автоматический тест недоступен или используется старый формат отчёта.')])
    else:
        srows.append(_row('Статус:',_field_status(speed),_kind(speed.get('status'))))
        for direction,key in (('Исходящая/Upload','upload_to_peer'),('Входящая/Download','download_from_peer')):
            data=speed.get(key) or {}
            srows.append(_row(direction+':',str(data.get('mbps_median','—'))+' Мбит/с',
                              _kind(data.get('status'))))
            srows.append(_row('  Повторные передачи:',data.get('retransmits_total')))
    items.append(('Скорость сети',srows))
    brows=[_title('КРАТКИЕ ТЕСТЫ CPU, RAM И ДИСКА')]
    if bench.get('status')=='SKIPPED':
        brows.extend([('Тест не выполнен.','warn'),
                      _explanation('Автоматическое измерение недоступно в этом отчёте.')])
    else:
        brows.extend([_row('CPU PBKDF2 итерац./с:',bench.get('cpu_iterations_per_sec')),
                     _row('RAM copy 8 MiB, мс:',bench.get('memory_copy_8mib_ms')),
                     _row('Диск 8 MiB, MiB/с:',bench.get('disk_write_mib_s')),
                     _row('Файл теста:',_state(bench.get('disk_status')))])
    brows.extend([_explanation('В отличие от sysbench/YABS/fio, это лёгкий экспресс-тест.'),
                 _explanation('Результаты разных VPS/версий Python напрямую не сравнивать.'),
                 _explanation('Тест выполняется автоматически: временный файл 8 MiB удаляется.')])
    items.append(('Производительность',brows))
    notes=[_title('ГРАНИЦЫ И ТОЧНОСТЬ ИЗМЕРЕНИЙ')]
    for value in record.get('limitations',[]):notes.append(_explanation(_value(value)))
    for key in ('geo','services','dns','ping'):
        for msg in (record.get(key,{}).get('limitations',[]) if isinstance(record.get(key),dict) else []):
            notes.append(_explanation(_value(msg)))
    notes.extend([('', 'normal'),
                  _title('ЭКСПОРТ'),
                  _explanation('E — сохранить TXT/JSON/PNG, владелец файла только текущий пользователь.'),
                  _explanation('Отчёт содержит публичный IP и информацию о VPS: перед публикацией проверьте.'),
                  _explanation('Файлы не создаются без явного действия пользователя.'),
                  _explanation('Все измерения выполняются без ввода параметров. Результаты могут быть неполными.'),
                  _explanation('Этот отчёт не является актом аудита защищённости или VPN-клиента.')])
    items.append(('Пояснения',notes))
    return items


def display_lines(record,section=0):
    parts=sections(record)
    if section==0:
        out=[]
        for idx,(title,rows) in enumerate(parts,1):
            out.append((f'{idx:02}. {title.upper()}','heading'))
            out.extend(rows)
            out.append(('', 'normal'))
        return out
    if not 1<=section<=len(parts):raise ValueError('UNKNOWN_SECTION')
    return parts[section-1][1]


def plain_text(record):
    return 'NODE INSTALL · РУССКИЙ ОТЧЁТ О VPS\n'+'='*65+'\n'+\
        '\n'.join(line for line,_ in display_lines(record))+'\n'


# Portable original pixel glyphs for export. 5x7 block capitals are intentional:
# this is a generated diagnostic PNG (no copyrighted font binary or native dep).
GLYPHS={
' ':['00000']*7,
'A':['01110','10001','10001','11111','10001','10001','10001'],
'B':['11110','10001','10001','11110','10001','10001','11110'],
'C':['01111','10000','10000','10000','10000','10000','01111'],
'D':['11110','10001','10001','10001','10001','10001','11110'],
'E':['11111','10000','10000','11110','10000','10000','11111'],
'F':['11111','10000','10000','11110','10000','10000','10000'],
'G':['01111','10000','10000','10111','10001','10001','01111'],
'H':['10001','10001','10001','11111','10001','10001','10001'],
'I':['11111','00100','00100','00100','00100','00100','11111'],
'J':['00111','00010','00010','00010','10010','10010','01100'],
'K':['10001','10010','10100','11000','10100','10010','10001'],
'L':['10000','10000','10000','10000','10000','10000','11111'],
'M':['10001','11011','10101','10101','10001','10001','10001'],
'N':['10001','11001','10101','10011','10001','10001','10001'],
'O':['01110','10001','10001','10001','10001','10001','01110'],
'P':['11110','10001','10001','11110','10000','10000','10000'],
'Q':['01110','10001','10001','10001','10101','10010','01101'],
'R':['11110','10001','10001','11110','10100','10010','10001'],
'S':['01111','10000','10000','01110','00001','00001','11110'],
'T':['11111','00100','00100','00100','00100','00100','00100'],
'U':['10001','10001','10001','10001','10001','10001','01110'],
'V':['10001','10001','10001','10001','10001','01010','00100'],
'W':['10001','10001','10001','10101','10101','10101','01010'],
'X':['10001','10001','01010','00100','01010','10001','10001'],
'Y':['10001','10001','01010','00100','00100','00100','00100'],
'Z':['11111','00001','00010','00100','01000','10000','11111'],
'0':['01110','10001','10011','10101','11001','10001','01110'],
'1':['00100','01100','00100','00100','00100','00100','01110'],
'2':['01110','10001','00001','00010','00100','01000','11111'],
'3':['11110','00001','00001','01110','00001','00001','11110'],
'4':['00010','00110','01010','10010','11111','00010','00010'],
'5':['11111','10000','11110','00001','00001','10001','01110'],
'6':['00110','01000','10000','11110','10001','10001','01110'],
'7':['11111','00001','00010','00100','01000','01000','01000'],
'8':['01110','10001','10001','01110','10001','10001','01110'],
'9':['01110','10001','10001','01111','00001','00010','01100'],
'.':['00000','00000','00000','00000','00000','00110','00110'],
':':['00000','00110','00110','00000','00110','00110','00000'],
'-':['00000','00000','00000','11111','00000','00000','00000'],
'/':['00001','00001','00010','00100','01000','10000','10000'],
'+':['00000','00100','00100','11111','00100','00100','00000'],
'=':['00000','11111','00000','11111','00000','00000','00000'],
'?':['01110','10001','00010','00100','00100','00000','00100'],
'!':['00100','00100','00100','00100','00100','00000','00100'],
'%':['11001','11010','00010','00100','01000','01011','10011'],
'_':['00000','00000','00000','00000','00000','00000','11111'],
'(' :['00010','00100','01000','01000','01000','00100','00010'],
')' :['01000','00100','00010','00010','00010','00100','01000'],
'[' :['01110','01000','01000','01000','01000','01000','01110'],
']' :['01110','00010','00010','00010','00010','00010','01110'],
'|' :['00100']*7,
',' :['00000','00000','00000','00000','00110','00110','00100'],
'~' :['00000','00000','01101','10010','00000','00000','00000'],
'#' :['01010','01010','11111','01010','11111','01010','01010'],
'@' :['01110','10001','10111','10101','10111','10000','01110'],
'>' :['10000','01000','00100','00010','00100','01000','10000'],
'<' :['00001','00010','00100','01000','00100','00010','00001'],
'Ё':['10101','00000','11111','10000','11110','10000','11111'],
'Б':['11111','10000','10000','11110','10001','10001','11110'],
'Г':['11111','10000','10000','10000','10000','10000','10000'],
'Д':['00110','01010','01010','01010','10010','11111','10001'],
'Ж':['10101','10101','01110','11111','01110','10101','10101'],
'З':['11110','00001','00001','01110','00001','00001','11110'],
'И':['10001','10011','10101','10101','11001','10001','10001'],
'Й':['01010','00100','10011','10101','10101','11001','10001'],
'Л':['00111','01001','01001','01001','10001','10001','10001'],
'П':['11111','10001','10001','10001','10001','10001','10001'],
'Ф':['00100','01110','10101','10101','10101','01110','00100'],
'Ц':['10010','10010','10010','10010','10010','11111','00001'],
'Ч':['10001','10001','10001','01111','00001','00001','00001'],
'Ш':['10101','10101','10101','10101','10101','10101','11111'],
'Щ':['10101','10101','10101','10101','10101','11111','00001'],
'Ъ':['11000','01000','01110','01001','01001','01001','01110'],
'Ы':['10001','10001','11101','10101','10101','10101','11101'],
'Ь':['10000','10000','11110','10001','10001','10001','11110'],
'Э':['11110','00001','00001','01111','00001','00001','11110'],
'Ю':['10010','10101','10101','11101','10101','10101','10010'],
'Я':['01111','10001','10001','01111','00101','01001','10001'],
}
for ru,en in {'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O','Р':'P','С':'C','Т':'T','У':'Y','Х':'X'}.items():
    GLYPHS[ru]=GLYPHS[en]
# A missing glyph is rendered as '?' rather than silently omitting its value.


def _pillow_png(report,*,max_lines=350):
    """Optional high-fidelity view if PIL + system Cyrillic font already exist.

    The stock-Python bitmap renderer below remains the guaranteed fallback;
    this path never installs packages or bundles a font.
    """
    from PIL import Image, ImageDraw, ImageFont
    from io import BytesIO
    roots=(
      '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
      '/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf',
      '/usr/share/fonts/truetype/freefont/FreeMono.ttf',
    )
    face=next((f for f in roots if Path(f).is_file()),None)
    if face is None:raise OSError('SYSTEM_CYRILLIC_FONT_NOT_INSTALLED')
    boldface=next((f for f in (
      '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
      '/usr/share/fonts/truetype/liberation2/LiberationMono-Bold.ttf') if Path(f).is_file()),face)
    normal=ImageFont.truetype(face,17)
    bold=ImageFont.truetype(boldface,19)
    hero=ImageFont.truetype(boldface,30)
    rows=[]
    for text,role in display_lines(report):
        # keep control characters and oversized HTML/geolocation fields out
        for piece in textwrap.wrap(_value(text,limit=180),width=105,
                                   break_long_words=True,break_on_hyphens=False) or ['']:
            rows.append((piece,role))
    if len(rows)>max_lines:
        rows=rows[:max_lines]+[('Для полного отчёта используйте экспорт TXT (PNG усечён).','warn')]
    width=1340;height=140+sum(37 if role=='heading' else 26 for _,role in rows)+42
    if height>11000:raise ValueError('PNG_TOO_TALL')
    img=Image.new('RGB',(width,height),(14,17,21))
    canvas=ImageDraw.Draw(img)
    canvas.rectangle((0,0,width,104),fill=(19,29,31))
    canvas.rectangle((0,102,width,105),fill=(52,127,92))
    canvas.text((46,27),'NODE INSTALL   /   ДИАГНОСТИКА VPS',font=hero,fill=(225,249,235))
    canvas.text((48,72),'Read-only · IP / ASN · сеть · сервисы · ресурсы · тесты',
                font=normal,fill=(129,179,160))
    shades={'normal':(219,230,225),'heading':(193,250,218),
            'good':(97,223,156),'warn':(247,193,98),
            'bad':(255,107,123),'info':(116,198,248),'dim':(136,152,154)}
    y=121
    for index,(text,role) in enumerate(rows):
        step=37 if role=='heading' else 26
        if role=='heading':
            canvas.rounded_rectangle((30,y-1,width-30,y+33),radius=7,
                                     fill=(29,44,41),outline=(46,67,56),width=1)
            canvas.text((47,y+5),text,font=bold,fill=shades[role])
        else:
            if index%2==0 and text:
                canvas.rectangle((36,y-1,width-36,y+23),fill=(17,22,26))
            canvas.text((47,y+1),text,font=normal,fill=shades.get(role,shades['normal']))
        y+=step
    from io import BytesIO
    buf=BytesIO();img.save(buf,format='PNG',optimize=True)
    return buf.getvalue()


def png_bytes(report,*,max_lines=350):
    """PNG output; improved TTF path optional, pure-stdlib bitmap guaranteed."""
    try:
        return _pillow_png(report,max_lines=max_lines)
    except (ImportError,ModuleNotFoundError,OSError):
        # Stock minimal Ubuntu has no PIL or fonts; still export usable PNG.
        pass
    rawlines=display_lines(report)
    lines=[]
    for line,role in rawlines:
        # No very wide lines, which would be unreadable on a PNG.
        value=_value(line,limit=140)
        wrapped=textwrap.wrap(value,width=103,break_long_words=True,
                             break_on_hyphens=False,replace_whitespace=True) or ['']
        lines.extend((part,role) for part in wrapped)
    if len(lines)>max_lines:
        lines=lines[:max_lines]+[('ОТЧЁТ УСЕЧЁН ДЛЯ PNG. ПОЛНЫЙ ТЕКСТ ДОСТУПЕН В TXT.','warn')]
    width=1340;scale=2;pitch=18
    height=min(7800,125+len(lines)*pitch+45)
    pixels=bytearray(bytes((13,18,24))*(width*height))
    palette={'normal':(221,231,228),'heading':(179,250,204),'good':(95,234,158),
             'warn':(245,197,99),'bad':(247,105,115),'info':(111,190,239),'dim':(134,155,157)}
    def rect(x,y,w,h,color):
        r,g,b=color
        if y>=height or x>=width:return
        for yy in range(max(0,y),min(height,y+h)):
            x0=max(0,x);x1=min(width,x+w)
            if x1>x0:
                p=(yy*width+x0)*3
                pixels[p:p+(x1-x0)*3]=bytes((r,g,b))*(x1-x0)
    def line_text(x,y,value,role):
        color=palette.get(role,palette['normal'])
        for c in _value(value,limit=110).upper():
            glyph=GLYPHS.get(c,GLYPHS['?'])
            for yy,bits in enumerate(glyph):
                for xx,bit in enumerate(bits):
                    if bit=='1':rect(x+xx*scale,y+yy*scale,scale,scale,color)
            x+=6*scale
            if x>width-40:break
    rect(0,0,width,77,(21,33,36))
    rect(0,75,width,2,(50,130,89))
    line_text(38,21,'NODE INSTALL  |  ДИАГНОСТИКА VPS','heading')
    for i,(row,kind) in enumerate(lines):
        y=94+i*pitch
        if y>=height-12:break
        if kind=='heading':
            rect(29,y-3,width-58,18,(25,44,41))
        line_text(40,y,row,kind)
    def chunk(tag,data):
        return struct.pack('>I',len(data))+tag+data+struct.pack('>I',zlib.crc32(tag+data)&0xffffffff)
    raw=b''.join(b'\x00'+pixels[row*width*3:(row+1)*width*3] for row in range(height))
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+
            chunk(b'IDAT',zlib.compress(raw,6))+chunk(b'IEND',b''))


def _private_directory(folder=None):
    if folder is None:
        folder=Path('/root/NodeInstall-Reports') if os.geteuid()==0 else Path.home()/'.local/state/NodeInstall-Reports'
    folder=Path(folder)
    if not folder.is_absolute():raise ValueError('EXPORT_PATH_NOT_ABSOLUTE')
    folder.mkdir(parents=True,mode=0o700,exist_ok=True)
    info=folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or \
       stat.S_IMODE(info.st_mode)!=0o700 or folder.is_symlink():
        raise OSError('UNSAFE_REPORT_DIRECTORY')
    return folder


def export_report(report,format_name,*,folder=None):
    """Exclusive atomic-enough private file; no overwrite/symlink following."""
    if format_name not in ('txt','json','png'):raise ValueError('INVALID_EXPORT_TYPE')
    # Validate before creating anything.
    sections(report)
    blob=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
    if len(blob.encode('utf-8'))>150_000:raise ValueError('REPORT_TOO_LARGE')
    if format_name=='txt':data=plain_text(report).encode('utf-8')
    elif format_name=='json':data=blob.encode('utf-8')
    else:data=png_bytes(report)
    if len(data)>15_000_000:raise ValueError('REPORT_FILE_TOO_LARGE')
    directory=_private_directory(folder)
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path=directory/f'node-vps-{stamp}-{secrets.token_hex(3)}.{format_name}'
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags,0o600)
    try:
        with os.fdopen(fd,'wb') as file:
            view=memoryview(data)
            while view:
                n=file.write(view)
                if n<=0:raise OSError('EXPORT_SHORT_WRITE')
                view=view[n:]
            file.flush();os.fsync(file.fileno())
        dfd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:os.fsync(dfd)
        finally:os.close(dfd)
    except BaseException:
        try:path.unlink()
        except OSError:pass
        raise
    return path
