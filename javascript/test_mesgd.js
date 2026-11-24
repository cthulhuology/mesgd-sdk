import { readFileSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { PKI } from './pki.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures');
const JWKS_FILE = join(FIXTURES, 'jwks.json');
const ALICE = join(FIXTURES, 'test_mesgd_alice.json');
const BOB = join(FIXTURES, 'test_mesgd_bob.json');

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

async function loadFromFile(path) {
  const jwks = JSON.parse(readFileSync(path, 'utf8'));
  await PKI.importJWKS(jwks);
}

function cleanup() {
  for (const p of [ALICE, BOB]) {
    if (existsSync(p)) rmSync(p);
  }
}

async function runTests() {
  console.log('--- mesgd protocol tests ---');
  cleanup();

  await test('two-party encrypt_with / decrypt', async () => {
    await PKI.generate(ALICE);
    const alicePub = await PKI.pubJwk();
    await PKI.generate(BOB);
    const ct = await PKI.encryptWith(alicePub, 'secret from bob');
    await loadFromFile(ALICE);
    assertEqual(await PKI.decrypt(ct), 'secret from bob');
  });

  await test('signed encrypted message', async () => {
    await PKI.generate(ALICE);
    const alicePub = await PKI.pubJwk();
    await PKI.generate(BOB);
    const plain = 'ping';
    const sig = await PKI.sign(plain);
    const envelope = JSON.stringify({ payload: plain, signature: sig });
    const ct = await PKI.encryptWith(alicePub, envelope);
    await loadFromFile(ALICE);
    const opened = JSON.parse(await PKI.decrypt(ct));
    assertEqual(opened.payload, plain);
    await loadFromFile(BOB);
    assert(await PKI.check(plain, sig), 'bob signature should verify');
  });

  await test('compact register envelope', async () => {
    await loadFromFile(JWKS_FILE);
    const mesgdPub = await PKI.pubJwk();
    await PKI.generate(ALICE);
    const payload = JSON.stringify({ name: 'alice' });
    const envelope = JSON.stringify({ payload, signature: await PKI.sign(payload) });
    const ct = await PKI.encryptWith(mesgdPub, envelope);
    const alicePub = await PKI.pubJwk();
    await loadFromFile(JWKS_FILE);
    const opened = JSON.parse(await PKI.decrypt(ct));
    assertEqual(JSON.parse(opened.payload).name, 'alice');
    assert(await PKI.checkWithPub(alicePub, opened.payload, opened.signature));
  });

  if (process.env.MESGD_URL) {
    await test('live register/auth/message', async () => {
      throw new Error('mesgd HTTP JWK registration is not wired yet');
    });
  }

  cleanup();
  await loadFromFile(JWKS_FILE);
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runTests().catch((e) => { console.error(e); process.exit(1); });
