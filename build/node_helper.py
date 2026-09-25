#!/usr/bin/env python3
"""VKarmani 1.2.0: node-only installer. No panel API, credentials or POST requests.
Three inputs are collected by Bash before APT and passed via stdin. Python 3.10+.
"""
import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys

ETC = Path('/etc/vkarmani-node')
STATE = Path('/var/lib/vkarmani-node')
MODE = 'secret-key-only'
class Failure(Exception):
    pass

def read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (ValueError, OSError) as e:
        raise Failure('Не удалось прочитать JSON: ' + str(path)) from e


def atomic_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink()


def domain(value):
    if not isinstance(value, str):
        raise Failure('Домен должен быть строкой.')
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value:
        raise Failure('Нужен полный DNS-домен, без https:// и пути.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
           for p in value.split('.')):
        raise Failure('Некорректный домен. IDN укажите в punycode.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Failure('Вместо IP нужен DNS-домен.')


def public_ipv4(value):
    try:
        ip = ipaddress.IPv4Address(value)
        if not isinstance(value, str) or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError()
        return str(ip)
    except (ValueError, TypeError) as e:
        raise Failure('Нужен глобальный публичный IPv4-адрес, не CIDR.') from e


def dns_check(c):
    for server in (None, '1.1.1.1', '8.8.8.8'):
        answers = {}
        for kind in ('A', 'AAAA'):
            cmd = ['dig', '-4', '+time=4', '+tries=2', '+noall', '+comments', '+answer']
            if server:
                cmd.append('@' + server)
            cmd += [c['domain'], kind]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.returncode or not re.search(r'status: NOERROR[, ]', r.stdout):
                raise Failure('DNS-запрос не выполнен: ' + (server or 'system resolver'))
            answers[kind] = {line.split()[-1] for line in r.stdout.splitlines()
                             if len(line.split()) >= 5 and line.split()[-2] == kind}
        if answers['A'] != {c['public_ipv4']} or answers['AAAA']:
            raise Failure('DNS: требуется ровно один A на IPv4 ноды и отсутствие AAAA. Проверьте DNS-only, без CDN proxy; resolver=' + (server or 'system'))
    print('DNS: A подтверждён тремя резолверами, AAAA отсутствует.')


def make_keys_profile(c):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    path = ETC / 'reality.json'
    if path.exists():
        keys = read_json(path)
    else:
        key = X25519PrivateKey.generate()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        keys = {'private_key': enc(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                'public_key': enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                'short_id': secrets.token_hex(8), 'xhttp_path': '/' + secrets.token_hex(16) + '/'}
        atomic_json(path, keys)
    suffix = hashlib.sha256(c['domain'].encode()).hexdigest()[:12]
    tag = 'VK_XHTTP_' + suffix.upper()
    # No Vision flow on XHTTP. Clients are filled by Remnawave, never hard-coded here.
    profile = {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': ['1.1.1.1', '8.8.8.8'], 'queryStrategy': 'UseIPv4'},
        'inbounds': [{'tag': tag, 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
                      'settings': {'clients': [], 'decryption': 'none'},
                      'sniffing': {'enabled': True, 'routeOnly': True, 'destOverride': ['http', 'tls']},
                      'streamSettings': {
                          'network': 'xhttp', 'security': 'reality',
                          'xhttpSettings': {'path': keys['xhttp_path'], 'mode': 'auto'},
                          'realitySettings': {'show': False, 'target': '127.0.0.1:8444', 'xver': 0,
                                              'serverNames': [c['domain']], 'privateKey': keys['private_key'],
                                              'shortIds': [keys['short_id']]}}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                      {'tag': 'BLOCK', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
            {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                                    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
                                    '224.0.0.0/4', '240.0.0.0/4', c['public_ipv4'] + '/32', '::/0'],
             'outboundTag': 'BLOCK'}]}}
    atomic_json(ETC / 'profile.json', profile)
    return 'VK-' + suffix, tag, profile


def docker_config():
    p = Path('/etc/docker/daemon.json')
    cfg = read_json(p) if p.exists() else {}
    if not isinstance(cfg, dict):
        raise Failure('daemon.json не является объектом.')
    cfg.update({'ipv6': False, 'ip6tables': False, 'live-restore': True,
                'log-driver': 'local', 'log-opts': {'max-size': '10m', 'max-file': '3'}})
    atomic_json(p, cfg)
    os.chmod(p, 0o644)


def atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
    finally:
        if temp.exists():
            temp.unlink()


def normalize_config(raw):
    if not isinstance(raw, dict) or raw.get('installation_mode') != MODE:
        raise Failure('Нужна конфигурация secret-key-only. API-установка не мигрируется.')
    allowed = {'installation_mode', 'domain', 'public_ipv4', 'node_port', 'panel_ipv4',
               'image', 'auto_reboot', 'certbot_dry_run', 'create_swap'}
    if set(raw) - allowed:
        raise Failure('Неизвестные поля конфигурации. API-параметры здесь не используются.')
    c = dict(raw)
    c['domain'] = domain(c.get('domain'))
    c['public_ipv4'] = public_ipv4(c.get('public_ipv4'))
    ips = c.get('panel_ipv4')
    if not isinstance(ips, list) or not 1 <= len(ips) <= 16:
        raise Failure('panel_ipv4: от 1 до 16 публичных IPv4 панели, без CIDR.')
    c['panel_ipv4'] = sorted({public_ipv4(x) for x in ips})
    port = c.get('node_port', 2222)
    if type(port) is not int or not 1024 <= port <= 65535 or port == 8444:
        raise Failure('node_port: целое 1024–65535, кроме 8444 и SSH-порта.')
    c['node_port'] = port
    image = c.get('image', 'remnawave/node:latest')
    if not isinstance(image, str) or not re.fullmatch(
        r'(?:remnawave/node|ghcr\.io/remnawave/node)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?', image):
        raise Failure('Допускается только официальный образ Remnawave Node.')
    c['image'] = image
    for name in ('auto_reboot', 'certbot_dry_run', 'create_swap'):
        value = c.get(name, True)
        if type(value) is not bool:
            raise Failure(name + ': требуется JSON true/false.')
        c[name] = value
    return c


def detect_public_ipv4():
    try:
        r = subprocess.run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'],
                           capture_output=True, text=True, timeout=10, check=True)
        routes = json.loads(r.stdout)
        # ip route get performs a kernel route lookup, not a request to 1.1.1.1.
        value = routes[0].get('prefsrc') or routes[0].get('src')
        return public_ipv4(value)
    except (subprocess.SubprocessError, ValueError, IndexError, KeyError, TypeError, Failure) as e:
        raise Failure('Не определён прямой публичный IPv4. NAT/IPv6-only VPS не поддерживаются.') from e


def normalize_pem(value):
    value = value.replace('\\n', '\n').replace('\r\n', '\n')
    value = re.sub(r'(-----BEGIN [A-Z ]+-----)', r'\1\n', value)
    value = re.sub(r'(-----END [A-Z ]+-----)', r'\n\1', value)
    return re.sub(r'\n+', '\n', value).strip() + '\n'


def normalize_secret(value, check_dates=False):
    """Validate the actual mTLS/JWT bundle, not an arbitrary 16-char password.
    No key, PEM, invalid input, or third-party exception text is put in errors.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, padding
    if not isinstance(value, str):
        raise Failure('SECRET_KEY должен быть строкой.')
    value = value.strip()
    if value.startswith('SECRET_KEY='):
        value = value[len('SECRET_KEY='):].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not re.fullmatch(r'[A-Za-z0-9+/_-]{32,50000}={0,2}', value):
        raise Failure('Некорректный формат SECRET_KEY: вставьте значение из панели одной строкой.')
    try:
        payload = json.loads(base64.b64decode(value + '=' * (-len(value) % 4),
                                             altchars=b'-_', validate=True))
        fields = ('nodeCertPem', 'nodeKeyPem', 'caCertPem', 'jwtPublicKey')
        if not isinstance(payload, dict) or any(not isinstance(payload.get(k), str) for k in fields):
            raise ValueError()
        pem = {k: normalize_pem(payload[k]).encode('ascii') for k in fields}
        cert = x509.load_pem_x509_certificate(pem['nodeCertPem'])
        ca = x509.load_pem_x509_certificate(pem['caCertPem'])
        key = ser.load_pem_private_key(pem['nodeKeyPem'], password=None)
        ser.load_pem_public_key(pem['jwtPublicKey'])
        encode_public = lambda k: k.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        if encode_public(cert.public_key()) != encode_public(key.public_key()):
            raise ValueError()
        if cert.issuer != ca.subject or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError()
        ca_key = ca.public_key()
        if isinstance(ca_key, ec.EllipticCurvePublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(ca_key, rsa.RSAPublicKey):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(ca_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            raise ValueError()
    except Exception as e:
        raise Failure('SECRET_KEY не прошёл проверку mTLS/JWT, сертификата или пары ключей. Возьмите новый из панели.') from e
    if check_dates:
        now = dt.datetime.now(dt.timezone.utc)
        for item in (cert, ca):
            if hasattr(item, 'not_valid_before_utc'):
                start, end = item.not_valid_before_utc, item.not_valid_after_utc
            else:
                start = item.not_valid_before.replace(tzinfo=dt.timezone.utc)
                end = item.not_valid_after.replace(tzinfo=dt.timezone.utc)
            if not start <= now <= end:
                raise Failure('Сертификат внутри SECRET_KEY ещё не действителен или истёк. Проверьте время и возьмите новый ключ.')
    return value


def check_secret(c, check_dates=True):
    path = ETC / 'remnanode.env'
    try:
        if path.stat().st_mode & 0o077:
            raise Failure('remnanode.env должен иметь права 0600.')
        lines = path.read_text(encoding='ascii').splitlines()
        if len(lines) != 3 or lines[0] != f'NODE_PORT={c["node_port"]}' or lines[2] != 'TZ=Europe/Moscow':
            raise Failure('remnanode.env не соответствует сохранённой конфигурации.')
        if not lines[1].startswith('SECRET_KEY='):
            raise Failure('В remnanode.env отсутствует SECRET_KEY.')
        normalize_secret(lines[1][len('SECRET_KEY='):], check_dates)
    except OSError as e:
        raise Failure('Не удалось прочитать сохранённый SECRET_KEY. Файл: /etc/vkarmani-node/remnanode.env') from e


def init_config(node_port='2222', inputs=None):
    """No prompts here. Bash collects all inputs before dependency installation.

    Fresh install: stdin consists of SECRET_KEY, panel IPv4, domain, each on one line.
    Resume: the persisted root-only configuration wins, and stdin is not consumed.
    """
    if (ETC / 'config.json').exists():
        c = normalize_config(read_json(ETC / 'config.json'))
        if detect_public_ipv4() != c['public_ipv4']:
            raise Failure('IPv4 сервера изменился. Не меняю адрес и ключи существующей установки автоматически.')
        check_secret(c, check_dates=False)
        print('Продолжение установки: домен, IPv4 панели и SECRET_KEY взяты из файлов root.')
        return
    if not re.fullmatch(r'[0-9]{4,5}', node_port):
        raise Failure('Некорректный NODE_PORT_DEFAULT.')
    if inputs is None:
        # Bound untrusted input without echoing it in exceptions.
        text = sys.stdin.read(70001)
        if len(text) > 70000:
            raise Failure('Слишком большой блок входных данных.')
        inputs = text.splitlines()
    if not isinstance(inputs, (tuple, list)) or len(inputs) != 3:
        raise Failure('Нужны три заранее введённых значения: SECRET_KEY, IPv4 панели, домен.')
    secret = normalize_secret(inputs[0])
    panel_ip = public_ipv4(inputs[1])
    name = domain(inputs[2])
    detected = detect_public_ipv4()
    if panel_ip == detected:
        raise Failure('IPv4 панели совпадает с IPv4 этой ноды. Нужен отдельный сервер ноды и исходящий IPv4 панели.')
    c = normalize_config({'installation_mode': MODE, 'domain': name, 'public_ipv4': detected,
                          'panel_ipv4': [panel_ip], 'node_port': int(node_port)})
    # Validate DNS before committing inputs. A typo can be corrected simply by rerunning.
    dns_check(c)
    # Secret first, config last: a crash cannot commit usable config without its key.
    atomic_text(ETC / 'remnanode.env', f'NODE_PORT={c["node_port"]}\nSECRET_KEY={secret}\nTZ=Europe/Moscow\n')
    atomic_json(ETC / 'config.json', c)
    print('Параметры проверены. SECRET_KEY сохранён с правами 0600, без вывода в журнал.')


def write_panel_guide(c):
    name, tag, _ = make_keys_profile(c)
    keys = read_json(ETC / 'reality.json')
    txt = f'''VKarmani RemnaNode 1.2.0 — действия в панели

Сервер: {c['domain']} / {c['public_ipv4']}
Разрешённый исходящий IPv4 панели: {', '.join(c['panel_ipv4'])}
Управляющий порт NODE_PORT: {c['node_port']} / TCP (НЕ клиентский порт!)

1. Config Profiles: создайте профиль {name} и вставьте JSON из
   /etc/vkarmani-node/profile.json
   Этот файл содержит приватный REALITY-ключ: не публикуйте его.
2. Nodes -> Management: создайте/отредактируйте карточку ЭТОЙ ноды:
   адрес {c['public_ipv4']}, Node Port {c['node_port']}.
   Используйте ту же панель, из которой взят введённый SECRET_KEY.
   Выберите профиль {name} и включите inbound {tag}.
3. Hosts: выберите этот профиль/inbound; Address={c['domain']}, Port=443.
   Security=DEFAULT (из профиля), SNI={c['domain']}, Fingerprint=chrome.
   Не задавайте Vision flow. XHTTP path берётся из профиля; при ручном
   переопределении Path должен быть {keys['xhttp_path']}.
4. Internal Squads: разрешите inbound {tag} группе своих пользователей.
   Обновите подписку в клиенте и проверьте соединение извне.

Транспорт шаблона: VLESS + XHTTP + REALITY, xhttp mode=auto.
REALITY target: 127.0.0.1:8444; xver=0; serverName={c['domain']}.
REALITY publicKey: {keys['public_key']}
ShortID: {keys['short_id']}

Скрипт НЕ авторизуется в панели, НЕ создаёт и НЕ меняет её объекты.
Локальный profile.json — шаблон для импорта, НЕ live-конфиг ноды.
Если у вас уже назначен готовый профиль, он не перезаписывается.
При использовании своего профиля согласуйте SNI/target и порт 443
с этим Nginx; приватные ключи и параметры берите из своего профиля.
До получения профиля от панели отсутствие Xray TCP/443 ожидаемо:
NODE_SETUP=PASS может сочетаться с VPN_STATUS=WAITING_FOR_PANEL_PROFILE.
TCP/2222 сам по себе не доказывает связь с панелью и работу VPN.

Проверка: sudo vkarmani-node-check
Строгая локальная проверка Xray/cover: sudo vkarmani-node-check --require-xray
Лог после reboot: /var/log/vkarmani-node-postboot.log
'''
    atomic_text(ETC / 'PANEL-SETUP.txt', txt)


def control_ready(c):
    try:
        with socket.create_connection(('127.0.0.1', c['node_port']), timeout=3):
            pass
    except OSError as e:
        raise Failure('Управляющий IPv4-порт RemnaNode ещё не слушает. Проверьте контейнер и SECRET_KEY.') from e


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'get', 'dns', 'keys', 'secret', 'docker-config', 'panel-guide', 'control-ready'])
    parser.add_argument('arg', nargs='?')
    args = parser.parse_args()
    if args.action == 'init':
        init_config(args.arg or '2222')
        return
    if args.action == 'docker-config':
        docker_config()
        return
    c = normalize_config(read_json(ETC / 'config.json'))
    if args.action == 'get':
        if args.arg not in c:
            raise Failure('Поле конфигурации не найдено.')
        v = c[args.arg]
        print('\n'.join(str(x) for x in v) if isinstance(v, list) else
              ('true' if v else 'false') if isinstance(v, bool) else v)
    elif args.action == 'dns':
        dns_check(c)
    elif args.action == 'keys':
        make_keys_profile(c)
    elif args.action == 'secret':
        check_secret(c)
        print('SECRET_KEY_VALID=PASS')
    elif args.action == 'panel-guide':
        write_panel_guide(c)
    elif args.action == 'control-ready':
        control_ready(c)
        print('NODE_CONTROL_IPV4=PASS')


if __name__ == '__main__':
    try:
        main()
    except Failure as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('Ввод прерван.', file=sys.stderr)
        sys.exit(130)
    except Exception:
        print('ERROR: ошибка чтения/проверки данных. Секретные значения не выведены.', file=sys.stderr)
        sys.exit(1)
