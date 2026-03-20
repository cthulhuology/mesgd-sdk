import { readFileSync, writeFileSync } from 'fs';

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : '';
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

const PKI = {
  signingAlg:   { name: 'ECDSA', namedCurve: 'P-256' },
  signingParams:{ name: 'ECDSA', hash: { name: 'SHA-256' } },
  rsaGenAlg: {
    name: 'RSA-OAEP', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: { name: 'SHA-256' }
  },
  rsaAlg: { name: 'RSA-OAEP', hash: 'SHA-256' },

  signingPrivateKey:    null,
  signingPublicKey:     null,
  encryptingPrivateKey: null,
  encryptingPublicKey:  null,

  // Load keys from a flat JWK array, identifying each by use + key_ops.
  // Strip key_ops and use before passing to importKey: the reference format
  // labels RSA keys with swapped key_ops (public='decrypt', private='encrypt')
  // which would conflict with WebCrypto's validation.
  async importJWKS(jwks) {
    const find = (use, op) =>
      jwks.find(j => j.use === use && Array.isArray(j.key_ops) && j.key_ops.includes(op));
    const strip = j => { const c = {...j}; delete c.key_ops; delete c.use; return c; };
    const pubSig  = find('sig', 'verify');
    const privSig = find('sig', 'sign');
    const pubEnc  = find('enc', 'decrypt');
    const privEnc = find('enc', 'encrypt');
    this.signingPrivateKey    = await crypto.subtle.importKey('jwk', strip(privSig), this.signingAlg, true, ['sign']);
    this.signingPublicKey     = await crypto.subtle.importKey('jwk', strip(pubSig),  this.signingAlg, true, ['verify']);
    this.encryptingPrivateKey = await crypto.subtle.importKey('jwk', strip(privEnc), this.rsaAlg,     true, ['decrypt']);
    this.encryptingPublicKey  = await crypto.subtle.importKey('jwk', strip(pubEnc),  this.rsaAlg,     true, ['encrypt']);
  },

  async init(path) {
    if (path) {
      const jwks = JSON.parse(readFileSync(path, 'utf8'));
      await this.importJWKS(jwks);
    } else {
      await this.generate();
    }
  },

  async generate(path) {
    const sigPair = await crypto.subtle.generateKey(this.signingAlg, true,
      ['sign', 'verify']);
    const encPair = await crypto.subtle.generateKey(this.rsaGenAlg,  true,
      ['encrypt', 'decrypt']);

    const pubSig  = await crypto.subtle.exportKey('jwk', sigPair.publicKey);
    const privSig = await crypto.subtle.exportKey('jwk', sigPair.privateKey);
    const pubEnc  = await crypto.subtle.exportKey('jwk', encPair.publicKey);
    const privEnc = await crypto.subtle.exportKey('jwk', encPair.privateKey);

    // Annotate with use + key_ops for array-format storage
    pubSig.use  = 'sig'; pubSig.key_ops  = ['verify'];
    privSig.use = 'sig'; privSig.key_ops = ['sign'];
    pubEnc.use  = 'enc'; pubEnc.key_ops  = ['decrypt'];
    privEnc.use = 'enc'; privEnc.key_ops = ['encrypt'];

    const jwks = [pubSig, pubEnc, privSig, privEnc];
    if (path) writeFileSync(path, JSON.stringify(jwks));

    this.signingPrivateKey    = sigPair.privateKey;
    this.signingPublicKey     = sigPair.publicKey;
    this.encryptingPrivateKey = encPair.privateKey;
    this.encryptingPublicKey  = encPair.publicKey;

    return jwks;
  },

  // Returns JSON {"r":"<base64url>","s":"<base64url>"}
  // WebCrypto ECDSA returns P1363 (raw R||S); split at 32 bytes and base64url-encode each
  async sign(message) {
    const data = new TextEncoder().encode(message);
    const p1363 = new Uint8Array(await crypto.subtle.sign(this.signingParams, this.signingPrivateKey, data));
    return JSON.stringify({ r: b64url(p1363.slice(0, 32)), s: b64url(p1363.slice(32)) });
  },

  // Accepts {"r":"<base64url>","s":"<base64url>"}; reconstructs P1363 for WebCrypto
  async verify(message, signatureJson) {
    const { r, s } = JSON.parse(signatureJson);
    const p1363 = new Uint8Array(64);
    const rb = b64urlDecode(r), sb = b64urlDecode(s);
    p1363.set(rb, 32 - rb.length);
    p1363.set(sb, 64 - sb.length);
    const data = new TextEncoder().encode(message);
    return crypto.subtle.verify(this.signingParams, this.signingPublicKey, p1363, data);
  },

  async encrypt(message) {
    const data = new TextEncoder().encode(message);
    const ct = await crypto.subtle.encrypt(this.rsaAlg, this.encryptingPublicKey, data);
    return btoa(String.fromCharCode(...new Uint8Array(ct)));
  },

  async decrypt(ciphertextBase64) {
    const ct = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt(this.rsaAlg, this.encryptingPrivateKey, ct);
    return new TextDecoder().decode(pt);
  }
};

export { PKI };
