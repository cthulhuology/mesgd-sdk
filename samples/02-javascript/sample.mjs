/**
 * mesgd-sdk JavaScript (ESM) Ping/Pong Sample
 * =============================================
 * Demonstrates the full mesgd-sdk lifecycle using Node.js ES Modules:
 *   1. Initialise local PKI keys
 *   2. Register our public keys with the mesgd echo server
 *   3. Open a WebSocket connection
 *   4. Send 3 signed+encrypted "ping" messages
 *   5. Receive and verify the echoed "pong" response each time
 */

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// Resolve SDK root relative to this file so imports work from any cwd
const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = join(__dirname, "..", "..");

// Dynamic imports from the SDK root — works regardless of working directory
const { PKI } = await import(join(sdkRoot, "pki.mjs"));
const { MesgdClient } = await import(join(sdkRoot, "mesgd.mjs"));

// ---------------------------------------------------------------------------
// Configuration (override via environment variables)
// ---------------------------------------------------------------------------
const MESGD_URL     = process.env.MESGD_URL     ?? "wss://echo.mesgd.org/ws";
const MESGD_PUB_JWK = process.env.MESGD_PUB_JWK ?? "mesgd_pub.json";
const ROUNDS        = parseInt(process.env.MESGD_ROUNDS ?? "3", 10);


/**
 * Load the mesgd server's public encryption JWK from a local file.
 * @param {string} path - Path to mesgd_pub.json
 * @returns {object} Parsed JWK object
 */
function loadMesgdPubJwk(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") {
      console.error(`ERROR: mesgd public key file not found: ${path}`);
      console.error("  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json");
    } else {
      console.error(`ERROR reading ${path}: ${err.message}`);
    }
    process.exit(1);
  }
}


async function main() {
  console.log("=== mesgd-sdk JavaScript Ping/Pong Sample ===\n");

  // ------------------------------------------------------------------
  // Step 1: Initialise PKI
  //   Loads pki_keys.json if it exists; otherwise generates fresh
  //   ECDSA P-256 signing and RSA-2048 encryption key pairs using the
  //   Web Crypto API and saves them as JWK to pki_keys.json.
  // ------------------------------------------------------------------
  console.log("Step 1: Initialising PKI …");
  await PKI.init();
  console.log("        Keys ready.\n");

  // ------------------------------------------------------------------
  // Step 2: Load mesgd's public encryption key
  // ------------------------------------------------------------------
  console.log(`Step 2: Loading mesgd public key from '${MESGD_PUB_JWK}' …`);
  const mesgdPubJwk = loadMesgdPubJwk(MESGD_PUB_JWK);
  console.log("        Loaded.\n");

  // ------------------------------------------------------------------
  // Step 3: Register with mesgd
  //   Signs our public keys with signing_priv, encrypts to mesgd's
  //   encrypting_pub, returns a base64 registration ciphertext.
  // ------------------------------------------------------------------
  console.log("Step 3: Registering with mesgd …");
  const registrationCt = await PKI.register(mesgdPubJwk);
  console.log(`        Registration payload (first 40 chars): ${registrationCt.slice(0, 40)}…\n`);

  // ------------------------------------------------------------------
  // Step 4: Connect WebSocket
  // ------------------------------------------------------------------
  console.log(`Step 4: Connecting to ${MESGD_URL} …`);
  const client = new MesgdClient(mesgdPubJwk);
  const ws = await client.connect(MESGD_URL, registrationCt);
  console.log("        Connected.\n");

  // ------------------------------------------------------------------
  // Step 5: Ping / pong loop
  // ------------------------------------------------------------------
  console.log(`Step 5: Starting ${ROUNDS}-round ping/pong …\n`);
  try {
    for (let i = 1; i <= ROUNDS; i++) {
      const message = `Hello from mesgd-sdk! JavaScript ping #${i}`;

      console.log(`  [${i}/${ROUNDS}] Sending  : ${message}`);
      await client.send(ws, mesgdPubJwk, message);

      const response = await client.receive(ws);
      console.log(`  [${i}/${ROUNDS}] Received : ${response}`);

      if (response !== message) {
        throw new Error(`Echo mismatch — expected: ${JSON.stringify(message)}, got: ${JSON.stringify(response)}`);
      }
      console.log(`  [${i}/${ROUNDS}] ✓ Echo verified\n`);
    }
  } finally {
    await client.disconnect(ws);
    console.log("Connection closed.");
  }

  console.log(`\nAll ${ROUNDS} ping/pong rounds passed.`);
}

main().catch((err) => {
  console.error("Fatal error:", err.message);
  process.exit(1);
});
