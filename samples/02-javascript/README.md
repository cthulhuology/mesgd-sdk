# JavaScript mesgd-sdk Ping/Pong Sample

## Overview

This sample is an ES Module (`.mjs`) for Node.js that demonstrates the full
mesgd-sdk workflow: PKI initialisation using the built-in Web Crypto API, signing
and encrypting messages with ECDSA P-256 and RSA-OAEP, and exchanging them over
a WebSocket connection to the mesgd echo server.

The `pki.mjs` module uses the Node.js built-in `crypto.webcrypto` — no external
crypto library is required. The `mesgd.mjs` module wraps the `ws` npm package for
WebSocket transport.

## Prerequisites

| Requirement | Version | Notes                                   |
|-------------|---------|-----------------------------------------|
| Node.js     | 18+     | Web Crypto API and top-level await      |
| npm         | 9+      | Package management                      |
| ws          | 8.17+   | Installed via `npm install`             |

## Configuration

| Environment Variable | Default                   | Description                          |
|----------------------|---------------------------|--------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws` | WebSocket endpoint                   |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`          | Path to mesgd server public JWK file |
| `MESGD_ROUNDS`       | `3`                       | Number of ping/pong iterations       |

Fetch the mesgd server public key before running:

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory:
npm install

# Run with defaults
npm start
# — or —
node sample.mjs

# Run with custom settings
MESGD_URL=wss://echo.mesgd.org/ws MESGD_PUB_JWK=mesgd_pub.json node sample.mjs
```

## Expected Output

```
=== mesgd-sdk JavaScript Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! JavaScript ping #1
  [1/3] Received : Hello from mesgd-sdk! JavaScript ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! JavaScript ping #2
  [2/3] Received : Hello from mesgd-sdk! JavaScript ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! JavaScript ping #3
  [3/3] Received : Hello from mesgd-sdk! JavaScript ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI (`pki.mjs`)

The JavaScript SDK uses the **Web Crypto API** (`crypto.subtle`) available natively
in Node.js 18+. Keys are generated and stored in the JWK format that `crypto.subtle`
natively produces:

- `crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'}, true, ['sign','verify'])` for signing
- `crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,...}, true, ['encrypt','decrypt'])` for encryption

All four keys (`signing_pub`, `signing_priv`, `encrypting_pub`, `encrypting_priv`) are
exported via `crypto.subtle.exportKey('jwk', key)` and persisted to `pki_keys.json`.

### Registration (`PKI.register()`)

1. Exports `signing_pub` and `encrypting_pub` as JWK objects.
2. Signs the JSON-serialised payload using `crypto.subtle.sign('ECDSA', ...)`.
3. Wraps into `{payload, signature}` envelope.
4. Encrypts with mesgd's `encrypting_pub` using `crypto.subtle.encrypt('RSA-OAEP', ...)`.
5. Returns standard base64.

### Message Exchange

**`client.send()`** follows the same sign-then-encrypt pattern as registration.
**`client.receive()`** performs decrypt-then-verify using our `encrypting_priv` and
mesgd's known `signing_pub`.

### ES Module notes

The file uses `import.meta.url` to locate the SDK root directory regardless of
where the process is started from. All imports are dynamic (`await import(...)`)
to resolve absolute paths at runtime.

## Troubleshooting

**`ERR_MODULE_NOT_FOUND` for `pki.mjs` or `mesgd.mjs`**
The sample expects these files in `../../` relative to `sample.mjs`. Run from
`samples/02-javascript/` or adjust the `sdkRoot` path.

**`SyntaxError: Unexpected token 'export'` or similar**
Ensure `"type": "module"` is set in `package.json` and you are running Node.js 18+.

**WebSocket connection refused**
Verify `MESGD_URL` and that outbound port 443 is open. For local testing set
`MESGD_URL=ws://localhost:8080/ws`.

**`Error: Echo mismatch`**
Delete `pki_keys.json` to regenerate keys and re-register with the server.
