"""Extract the REAL embedded payloads; never execute installation or write /etc."""
from pathlib import Path
import re
import types

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'install.sh').read_text()


def heredocs(text=SCRIPT):
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        match = re.search(r"<<(?P<quote>['\"]?)(?P<tag>[A-Z][A-Z0-9_]*)(?P=quote)(?:\s|$)", lines[i])
        if not match:
            i += 1
            continue
        tag, command = match['tag'], lines[i].rstrip('\n')
        end = i + 1
        while end < len(lines) and lines[end].rstrip('\n') != tag:
            end += 1
        if end == len(lines):
            raise ValueError('unterminated heredoc ' + tag)
        body = ''.join(lines[i + 1:end])
        yield tag, command, body
        yield from heredocs(body)
        i = end + 1


def payload(tag):
    matches = [body for name, _, body in heredocs() if name == tag]
    if len(matches) != 1:
        raise ValueError(f'{tag}: expected one payload, got {len(matches)}')
    return matches[0]


def module(tag):
    value = types.ModuleType('tested_' + tag)
    exec(compile(payload(tag), 'install.sh::' + tag, 'exec'), value.__dict__)
    return value


def template(destination):
    matches = [body for _, command, body in heredocs() if 'cat > ' + destination + ' <<' in command]
    if len(matches) != 1:
        raise ValueError(f'{destination}: expected one template, got {len(matches)}')
    return matches[0]


def certificate_bundle(expired=False):
    """Ephemeral test-only keys. Includes extensions needed by OpenSSL 3 strict CA validation."""
    import base64
    import datetime as dt
    import json
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    now = dt.datetime.now(dt.timezone.utc)
    ca_key, node_key, jwt_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'VKarmani ephemeral TEST CA')])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'node.example.test')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=365)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
            .public_key(node_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=5))
            .not_valid_after(now + dt.timedelta(days=-1 if expired else 100))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('node.example.test')]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    bundle = {
        'nodeCertPem': leaf.public_bytes(ser.Encoding.PEM).decode(),
        'nodeKeyPem': node_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode(),
        'caCertPem': ca.public_bytes(ser.Encoding.PEM).decode(),
        'jwtPublicKey': jwt_key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode(),
    }
    secret = base64.b64encode(json.dumps(bundle).encode()).decode()
    return bundle, secret
