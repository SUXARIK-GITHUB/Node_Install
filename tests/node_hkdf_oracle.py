"""Test-only independent JS HKDF oracle; no npm packages and no host mutation.

crypto.hkdfSync first appeared in Node 15. Keep that native comparison on newer
runtimes, and exercise the same RFC 5869 semantics on Jammy's distro Node 12
via createHmac. Never catch a native HKDF error and silently switch algorithms.
Both paths are checked with the RFC's fixed SHA-256 vectors in test_hkdf_compat.
This module is NEVER installed on a node; production install.sh is unchanged.
"""

NODE_HKDF_ORACLE = r"""
const crypto = require('crypto');
function hkdfSha256(ikm, salt, info, length) {
    if (!Number.isInteger(length) || length < 0 || length > 255 * 32) {
        throw new RangeError('invalid SHA-256 HKDF length');
    }
    if (typeof crypto.hkdfSync === 'function') {
        return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, length));
    }
    // RFC 5869 sections 2.2/2.3. Empty salt means HashLen zero octets.
    const key = crypto.createHmac('sha256', salt.length ? salt : Buffer.alloc(32))
        .update(ikm).digest();
    const blocks = [];
    let previous = Buffer.alloc(0);
    for (let counter = 1; counter <= Math.ceil(length / 32); counter++) {
        previous = crypto.createHmac('sha256', key).update(previous)
            .update(info).update(Buffer.from([counter])).digest();
        blocks.push(previous);
    }
    return Buffer.concat(blocks).subarray(0, length);
}
function deriveSni(bundle) {
    const canonical = p => p.replace(/-----[^-]+-----/g, '').replace(/[^A-Za-z0-9+/=]/g, '');
    const key = Buffer.concat([Buffer.from(canonical(bundle.jwtPublicKey), 'utf8'),
                               Buffer.from(canonical(bundle.caCertPem), 'utf8')]);
    const out = hkdfSha256(key, Buffer.alloc(0), Buffer.from('rw-v1', 'utf8'), 22);
    return out.subarray(0, 16).toString('hex') + '.' + out.subarray(16, 21).toString('hex')
        + '.' + ['com', 'net', 'org', 'io', 'dev', 'app'][out[21] % 6];
}
"""

NODE_SNI_PROGRAM = NODE_HKDF_ORACLE + r"""
const bundle = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(deriveSni(bundle));
"""
