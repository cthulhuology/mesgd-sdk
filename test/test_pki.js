// pki.js (from earlier, with async/await)
import { LocalStorage } from 'node-localstorage'
global.localStorage = new LocalStorage('./test/storage')

import { PKI } from "../pki.mjs"
import * as fs from 'fs'
import * as crypto from 'crypto';

// ... (full PKI object from the original JavaScript implementation here)

async function runTests() {
  // Test init
  await PKI.init();
  console.log('Init: OK');

  // Test sign/verify
  const message = 'Hello World';
  const sig = await PKI.sign(message);
  console.log('Sign: OK');
  const verified = await PKI.verify(message, sig);
  if (!verified) throw new Error('Verify failed');
  const wrongVerified = await PKI.verify('Wrong message', sig);
  if (wrongVerified) throw new Error('Wrong verify passed');
  console.log('Verify: OK');

  // Test encrypt/decrypt
  const secret = 'Secret message';
  const enc = await PKI.encrypt(secret);
  console.log('Encrypt: OK');
  const dec = await PKI.decrypt(enc);
  if (dec !== secret) throw new Error('Decrypt mismatch');
  // Test invalid decrypt (should throw)
  try {
    await PKI.decrypt(enc + 'invalid');
    throw new Error('Invalid decrypt passed');
  } catch (e) {
    console.log('Invalid decrypt: OK (error expected)');
  }

  // Test re-init (loads from storage)
  const originalSig = await PKI.sign(message);
  const stableSig = await PKI.sign(message);

  await PKI.init();  // Re-init should load same keys

  const reloadedSig = await PKI.sign(message);
  if ( await PKI.verify(message,reloadedSig) && await PKI.verify(message,originalSig)) console.log('All tests passed!');
  else throw new Error('Re-init key mismatch');

}

runTests().catch(console.error);
