import { LocalStorage } from 'node-localstorage';
import { readFileSync, writeFileSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES   = join(__dirname, '..', 'fixtures');
const JWKS_FILE  = join(FIXTURES, 'jwks.json');
const GEN_FILE   = join(FIXTURES, 'test_javascript.json');
const SIG_OUT    = join(FIXTURES, 'sig_javascript.json');
const CROSS_LANGS = ['erlang', 'python', 'ruby', 'rust', 'go'];

// Use a test-local localStorage so tests don't pollute or consume the shared store
global.localStorage = new LocalStorage(join(FIXTURES, 'ls_javascript'));

import { PKI } from './pki.mjs';

// --- minimal test harness ---
let passed = 0, failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}: ${e.message}`);
    failed++;
  }
}
function assert(val, msg) { if (!val) throw new Error(msg || 'assertion failed'); }
function assertEqual(a, b) { if (a !== b) throw new Error(`expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); }

// --- load PKI from the shared fixture file instead of localStorage ---
async function loadFromFile(path) {
  const jwks = JSON.parse(readFileSync(path, 'utf8'));
  await PKI.importJWKS(jwks);
}


async function runTests() {
  console.log('--- pki.mjs tests ---');

  await loadFromFile(JWKS_FILE);

  await test('sign/verify round-trip', async () => {
    const sig = await PKI.sign('Hello World');
    assert(await PKI.verify('Hello World', sig), 'verify should pass');
    assert(!await PKI.verify('Wrong message', sig), 'wrong message should fail');
  });

  await test('signature is JSON with r and s', async () => {
    const sig = await PKI.sign('Hello World');
    const obj = JSON.parse(sig);
    assert('r' in obj && 's' in obj, 'signature must have r and s');
  });

  await test('encrypt/decrypt round-trip', async () => {
    const enc = await PKI.encrypt('Secret message');
    const dec = await PKI.decrypt(enc);
    assertEqual(dec, 'Secret message');
  });

  await test('generate creates JSON file', async () => {
    if (existsSync(GEN_FILE)) rmSync(GEN_FILE);
    await PKI.generate(GEN_FILE);
    assert(existsSync(GEN_FILE), 'gen file should exist');
    const jwks = JSON.parse(readFileSync(GEN_FILE, 'utf8'));
    assert(Array.isArray(jwks) && jwks.length === 4, 'should be array of 4 JWKs');
    const ops = new Set(jwks.map(j => j.key_ops[0]));
    assert(ops.has('sign') && ops.has('verify') && ops.has('encrypt') && ops.has('decrypt'));
  });

  await test('generated keys work', async () => {
    await loadFromFile(GEN_FILE);
    const sig = await PKI.sign('Hello World');
    assert(await PKI.verify('Hello World', sig));
    const enc = await PKI.encrypt('Secret');
    assertEqual(await PKI.decrypt(enc), 'Secret');
    await loadFromFile(JWKS_FILE); // restore reference keys
  });

  await test('write cross-lang signature', async () => {
    await loadFromFile(JWKS_FILE);
    const sig = await PKI.sign('Hello World');
    writeFileSync(SIG_OUT, JSON.stringify({ lang: 'javascript', message: 'Hello World', signature: sig }));
  });

  await test('verify cross-lang signatures', async () => {
    await loadFromFile(JWKS_FILE);
    for (const lang of CROSS_LANGS) {
      const path = join(FIXTURES, `sig_${lang}.json`);
      if (!existsSync(path)) continue;
      const rec = JSON.parse(readFileSync(path, 'utf8'));
      assert(await PKI.verify(rec.message, rec.signature), `failed to verify ${lang} signature`);
    }
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runTests().catch(e => { console.error(e); process.exit(1); });
