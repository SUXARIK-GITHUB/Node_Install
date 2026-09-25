'use strict';
/* Read-only probe inside an already running official Remnawave backend.
 * Credentials never leave this process except the intended TLS/JWT handshake.
 * No private CA key is read; no panel/node state-changing endpoint is called.
 */
const crypto = require('node:crypto');
const https = require('node:https');
const net = require('node:net');
const { createRequire } = require('node:module');

function pem(value) {
  if (typeof value !== 'string' || !value.includes('-----BEGIN ')) throw new Error('KEY_MATERIAL_INVALID');
  return value.replace(/\\n/g, '\n').replace(/\r\n/g, '\n').trim() + '\n';
}
function deriveSni(ca, jwt) {
  const compact = s => pem(s).replace(/-----[^-]+-----/g, '').replace(/[^A-Za-z0-9+/=]/g, '');
  const secret = Buffer.from(compact(jwt) + compact(ca), 'ascii');
  const bytes = Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(0), Buffer.from('rw-v1'), 22));
  const labels = [bytes.subarray(0, 16).toString('hex'), bytes.subarray(16, 21).toString('hex')];
  labels.push(['com', 'net', 'org', 'io', 'dev', 'app'][bytes[21] % 6]);
  return labels.join('.');
}
function makeToken(privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const encode = object => Buffer.from(JSON.stringify(object)).toString('base64url');
  const data = encode({ alg: 'RS256', typ: 'JWT' }) + '.' + encode({ iat: now, exp: now + 60, diagnostic: true });
  return data + '.' + crypto.sign('RSA-SHA256', Buffer.from(data), pem(privateKey)).toString('base64url');
}
function validateTarget(host, port) {
  const ipv4 = net.isIP(host) === 4;
  const domain = host.length <= 253 && host.split('.').length >= 2 && host.split('.').every(
    label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
  if ((!ipv4 && !domain) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('INVALID_NODE_ADDRESS_OR_PORT');
}
function probe(host, port, keys, options = {}) {
  // Only this GET is used. In RemnaNode some other GET routes mutate state!
  return new Promise(resolve => {
    let stage = 'TCP', finished = false, request, timer;
    const result = (extra) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (request) request.destroy();
      resolve({ ok: false, stage, ...extra });
    };
    const safeCode = value => typeof value === 'string' && /^[A-Z0-9_]{1,100}$/.test(value) ? value : 'UNCLASSIFIED';
    try {
      const settings = {
        hostname: host, port, family: 4, method: 'GET', path: '/node/xray/healthcheck',
        servername: deriveSni(keys.ca_cert, keys.pub_key),
        ca: pem(keys.ca_cert), cert: pem(keys.client_cert), key: pem(keys.client_key),
        rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        // Node leaf names are not the IP/domain. CA/signature/expiry remain verified.
        checkServerIdentity: () => undefined,
        agent: false, headers: { Authorization: 'Bearer ' + makeToken(keys.priv_key), Accept: 'application/json' }
      };
      if (options.curve) settings.ecdhCurve = options.curve;
      request = https.request(settings, response => {
        stage = 'HTTP';
        let count = 0, chunks = [];
        response.on('data', data => {
          count += data.length;
          if (count > 2 * 1024 * 1024) return result({ code: 'RESPONSE_TOO_LARGE', status: response.statusCode });
          chunks.push(data);
        });
        response.on('error', error => result({ code: safeCode(error.code) }));
        response.on('end', () => {
          let body;
          try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { /* report no raw body */ }
          const valid = response.statusCode === 200 && body && typeof body === 'object' && Object.hasOwn(body, 'response');
          result({ ok: Boolean(valid), status: response.statusCode, code: valid ? 'AUTHENTICATED_HEALTHCHECK' : 'UNEXPECTED_HTTP_RESPONSE' });
        });
      });
      request.on('socket', socket => {
        socket.on('connect', () => { stage = 'TLS'; });
        socket.on('secureConnect', () => { stage = 'TLS_SERVER_VERIFIED'; });
      });
      request.on('error', error => result({ code: safeCode(error.code) }));
      timer = setTimeout(() => result({ code: 'DEADLINE_EXCEEDED' }), options.timeout || 12000);
      request.end();
    } catch (_) { result({ code: 'CREDENTIAL_OR_TLS_SETUP_ERROR' }); }
  });
}
function printResult(prefix, result) {
  console.log(prefix + '=' + (result.ok ? 'PASS' : 'FAIL') + ' stage=' + result.stage + ' code=' + result.code + (result.status ? ' HTTP=' + result.status : ''));
}
function getPrisma() {
  const loaders = [require, createRequire('/opt/app/dist/main.js'), createRequire('/opt/app/package.json')];
  for (const loader of loaders) {
    try { return loader('@prisma/client').PrismaClient; } catch (_) { /* try next known official layout */ }
  }
  throw new Error('PRISMA_NOT_AVAILABLE_IN_THIS_CONTAINER');
}
async function readPanel(PrismaClient, address) {
  const db = new PrismaClient({ log: [] });
  try {
    // Explicitly read-only, with no SELECT * and no CA private-key access.
    return await db.$transaction(async tx => {
      await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
      const rows = await tx.$queryRawUnsafe('SELECT ca_cert, pub_key, client_cert, client_key, priv_key FROM keygen LIMIT 2');
      if (rows.length !== 1) throw new Error('KEYGEN_ROW_COUNT_UNEXPECTED');
      const nodes = await tx.$queryRawUnsafe(`SELECT n.port,
        to_jsonb(n)->>'is_disabled' AS disabled,
        to_jsonb(n)->>'is_connected' AS connected,
        to_jsonb(n)->>'active_config_profile_uuid' AS profile,
        (coalesce(to_jsonb(n)->>'proxy_url', '') <> '') AS has_proxy,
        (SELECT count(*)::int FROM config_profile_inbounds_to_nodes b WHERE b.node_uuid=n.uuid) AS inbounds
        FROM nodes n WHERE lower(n.address)=lower($1) LIMIT 2`, address);
      return { keys: rows[0], nodes };
    }, { maxWait: 5000, timeout: 10000 });
  } finally { await db.$disconnect(); }
}
async function main(args) {
  const host = args[0] || '', port = Number(args[1] || '2222');
  validateTarget(host, port);
  const { keys, nodes } = await readPanel(getPrisma(), host);
  for (const value of Object.values(keys)) pem(value);
  const publicDer = crypto.createPublicKey(pem(keys.pub_key)).export({ type: 'spki', format: 'der' });
  const fromPrivate = crypto.createPublicKey(pem(keys.priv_key)).export({ type: 'spki', format: 'der' });
  if (!publicDer.equals(fromPrivate)) throw new Error('PANEL_JWT_KEY_PAIR_MISMATCH');
  console.log('PANEL_DB=READ_ONLY_OK');
  console.log('CA_SHA256=' + crypto.createHash('sha256').update(new crypto.X509Certificate(pem(keys.ca_cert)).raw).digest('hex'));
  console.log('API_SNI=DERIVED_FROM_PANEL_KEYS');
  console.log('NODE_TARGET=' + host + ':' + port);
  if (!nodes.length) console.log('NODE_CARD=NO_EXACT_ADDRESS_MATCH (a card using a DNS alias is not excluded)');
  else for (const node of nodes) {
    console.log('NODE_CARD=FOUND PORT_MATCH=' + (node.port === port ? 'YES' : 'NO'));
    console.log('NODE_DISABLED=' + node.disabled + ' PROFILE_ASSIGNED=' + Boolean(node.profile) + ' ASSIGNED_INBOUNDS=' + node.inbounds);
    console.log('DB_CONNECTED=' + node.connected + ' (stored state, not proof of this probe)');
    if (node.has_proxy) console.log('NODE_PROXY_CONFIGURED=YES; this probe tests DIRECT transport only, not the configured proxy');
  }
  const result = await probe(host, port, keys);
  printResult('PANEL_NODE_API', result);
  if (result.ok) {
    console.log('PANEL_MTLS=PASS PANEL_JWT=PASS');
    console.log('AUTHENTICATED_DIRECT_API=PASS; panel worker state, applied Xray profile and client traffic are not verified.');
    return 0;
  }
  if (result.status === 401 || result.status === 403) console.log('PANEL_MTLS=PASS PANEL_JWT=REJECTED; compare credentials and clocks');
  if (result.stage.startsWith('TLS')) {
    const alternate = await probe(host, port, keys, { curve: 'X25519' });
    printResult('PANEL_NODE_API_X25519_DIAGNOSTIC', alternate);
    if (alternate.ok) console.log('TLS_GROUP_OR_PATH_DIFFERENCE=DETECTED; diagnostic only, runtime was not changed; MTU loss is not proven');
  }
  console.log('PANEL_CONNECTION=NOT_CONFIRMED; compare node/panel CA_SHA256, TCP/TLS stage and panel source allowlist.');
  return 1;
}
module.exports = { pem, deriveSni, makeToken, validateTarget, probe, readPanel, main };
if (require.main === module || process.argv[1] === '-') {
  const watchdog = setTimeout(() => { console.error('PANEL_CHECK=INCOMPLETE TOTAL_DEADLINE_EXCEEDED'); process.exit(2); }, 60000);
  main(process.argv.slice(2)).then(code => { clearTimeout(watchdog); process.exitCode = code; }).catch(error => {
    clearTimeout(watchdog);
    const allowed = ['INVALID_NODE_ADDRESS_OR_PORT', 'PRISMA_NOT_AVAILABLE_IN_THIS_CONTAINER', 'KEYGEN_ROW_COUNT_UNEXPECTED', 'KEY_MATERIAL_INVALID', 'PANEL_JWT_KEY_PAIR_MISMATCH'];
    console.error('PANEL_CHECK=INCOMPLETE ' + (allowed.includes(error.message) ? error.message : 'DB_SCHEMA_OR_CREDENTIAL_ERROR'));
    console.error('No raw exception, connection string, JWT, certificate or private key was printed.');
    process.exitCode = 2;
  });
}
