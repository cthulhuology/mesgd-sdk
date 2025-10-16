// Helper functions for base64 encoding/decoding Uint8Array
function uint8ToBase64(uint8) {
  let binary = '';
  for (let i = 0; i < uint8.byteLength; i++) {
    binary += String.fromCharCode(uint8[i]);
  }
  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64);
  const uint8 = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    uint8[i] = binary.charCodeAt(i);
  }
  return uint8;
}

const PKI = {
  signingGenAlg: { name: 'ECDSA', namedCurve: 'P-256' },
  signingAlg: { name: 'ECDSA', namedCurve: 'P-256' },
  signingSignParams: { name: 'ECDSA', hash: { name: 'SHA-256' } },
  signingUsagesPrivate: ['sign'],
  signingUsagesPublic: ['verify'],
  rsaGenAlg: {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: { name: 'SHA-256' }
  },
  rsaAlg: { name: 'RSA-OAEP', hash: 'SHA-256' },
  rsaUsagesPrivate: ['decrypt'],
  rsaUsagesPublic: ['encrypt'],
  storageKey: 'pki_keys',
  keys: null,
  signingPrivateKey: null,
  signingPublicKey: null,
  encryptingPrivateKey: null,
  encryptingPublicKey: null,

  async init() {
    let stored = localStorage.getItem(this.storageKey);
    if (!stored) {
      const signingPair = await crypto.subtle.generateKey(
        this.signingGenAlg,
        true,
        [...this.signingUsagesPrivate, ...this.signingUsagesPublic]
      );
      const encryptingPair = await crypto.subtle.generateKey(
        this.rsaGenAlg,
        true,
        [...this.rsaUsagesPrivate, ...this.rsaUsagesPublic]
      );

      const signingPrivateJWK = await crypto.subtle.exportKey('jwk', signingPair.privateKey);
      const signingPublicJWK = await crypto.subtle.exportKey('jwk', signingPair.publicKey);
      const encryptingPrivateJWK = await crypto.subtle.exportKey('jwk', encryptingPair.privateKey);
      const encryptingPublicJWK = await crypto.subtle.exportKey('jwk', encryptingPair.publicKey);

      stored = JSON.stringify({
        signingPrivate: signingPrivateJWK,
        signingPublic: signingPublicJWK,
        encryptingPrivate: encryptingPrivateJWK,
        encryptingPublic: encryptingPublicJWK
      });
      localStorage.setItem(this.storageKey, stored);
    }

    this.keys = JSON.parse(stored);

    this.signingPrivateKey = await crypto.subtle.importKey(
      'jwk',
      this.keys.signingPrivate,
      this.signingAlg,
      true,
      this.signingUsagesPrivate
    );
    this.signingPublicKey = await crypto.subtle.importKey(
      'jwk',
      this.keys.signingPublic,
      this.signingAlg,
      true,
      this.signingUsagesPublic
    );
    this.encryptingPrivateKey = await crypto.subtle.importKey(
      'jwk',
      this.keys.encryptingPrivate,
      this.rsaAlg,
      true,
      this.rsaUsagesPrivate
    );
    this.encryptingPublicKey = await crypto.subtle.importKey(
      'jwk',
      this.keys.encryptingPublic,
      this.rsaAlg,
      true,
      this.rsaUsagesPublic
    );
  },

  async sign(message) {
    const data = new TextEncoder().encode(message);
    const signature = await crypto.subtle.sign(this.signingSignParams, this.signingPrivateKey, data);
    return uint8ToBase64(new Uint8Array(signature));
  },

  async verify(message, signatureBase64) {
    const data = new TextEncoder().encode(message);
    const signature = base64ToUint8(signatureBase64);
    return await crypto.subtle.verify(this.signingSignParams, this.signingPublicKey, signature, data);
  },

  async encrypt(message) {
    const data = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt(this.rsaAlg, this.encryptingPublicKey, data);
    return uint8ToBase64(new Uint8Array(ciphertext));
  },

  async decrypt(ciphertextBase64) {
    const ciphertext = base64ToUint8(ciphertextBase64);
    const plaintext = await crypto.subtle.decrypt(this.rsaAlg, this.encryptingPrivateKey, ciphertext);
    return new TextDecoder().decode(plaintext);
  }
};

export { PKI };

// Usage example:
// await PKI.init();
// const sig = await PKI.sign('Hello World');
// console.log(await PKI.verify('Hello World', sig)); // true
// const enc = await PKI.encrypt('Secret message');
// console.log(await PKI.decrypt(enc)); // 'Secret message'
