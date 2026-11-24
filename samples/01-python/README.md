# Python mesgd-sdk Ping/Pong Sample

## Overview

This sample demonstrates the complete mesgd-sdk workflow in Python: initialising a
local PKI key store, registering with the mesgd echo server, and exchanging three
signed-and-encrypted messages over WebSocket, verifying each echoed response.

The `pki` module uses the `cryptography` library for ECDSA P-256 signing and
RSA-2048-OAEP encryption. The `mesgd` module wraps the `websockets` async library.

## Prerequisites

| Requirement     | Version | Notes                                      |
|-----------------|---------|--------------------------------------------|
| Python          | 3.11+   | `asyncio` and `match` statement required   |
| pip             | 23+     |                                            |
| cryptography    | 42+     | Installed via requirements.txt             |
| websockets      | 12+     | Installed via requirements.txt             |

Install system OpenSSL if not already present:

```sh
# Ubuntu / Debian
sudo apt install libssl-dev

# macOS (Homebrew)
brew install openssl
```

## Configuration

| Environment Variable | Default                    | Description                              |
|----------------------|----------------------------|------------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws`  | WebSocket endpoint                       |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`           | Path to mesgd server public JWK file     |
| `MESGD_ROUNDS`       | `3`                        | Number of ping/pong iterations           |

Fetch the mesgd server public key before running:

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory:
pip install -r requirements.txt

# Run the sample (uses defaults)
python sample.py

# Or with custom settings:
MESGD_URL=wss://echo.mesgd.org/ws \
MESGD_PUB_JWK=/path/to/mesgd_pub.json \
python sample.py
```

## Expected Output

```
=== mesgd-sdk Python Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Python ping #1
  [1/3] Received : Hello from mesgd-sdk! Python ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Python ping #2
  [2/3] Received : Hello from mesgd-sdk! Python ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Python ping #3
  [3/3] Received : Hello from mesgd-sdk! Python ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### Step 1 — PKI initialisation (`PKI.init()`)

`pki.py` checks for `pki_keys.json` in the current directory. If absent, it calls
`PKI.generate()` which creates:

- An ECDSA P-256 key pair for signing/verification
- An RSA-2048 key pair for encryption/decryption

Both pairs are serialised as JWK and written to `pki_keys.json`. On subsequent
runs the existing keys are loaded.

### Step 2 — Load mesgd's public key

`mesgd_pub.json` contains the mesgd server's RSA-2048 public key in JWK format.
This key is used to encrypt payloads so that only the mesgd server can decrypt them.

### Step 3 — Registration (`PKI.register(mesgd_pub_jwk)`)

1. Exports `signing_pub` and `encrypting_pub` as JWK objects.
2. Serialises them into a JSON payload.
3. Signs the payload with `signing_priv` (ECDSA-SHA256).
4. Wraps payload + signature into a JSON envelope.
5. Encrypts the envelope with mesgd's `encrypting_pub` (RSA-OAEP-SHA256).
6. Returns the result as standard base64.

The mesgd server decrypts this during the WebSocket handshake to learn our public
keys, allowing it to verify and encrypt future messages.

### Step 4 — WebSocket connection (`MesgdClient.connect()`)

Opens a TLS WebSocket to `MESGD_URL` and sends the registration ciphertext as
the first message to complete the handshake.

### Step 5 — Ping/pong (`send` + `receive`)

**`client.send(ws, mesgd_pub_jwk, plaintext)`**:
1. Signs `plaintext` with our `signing_priv`.
2. Wraps `{payload, signature}` into a JSON envelope.
3. Encrypts the envelope with mesgd's `encrypting_pub`.
4. Sends the base64 ciphertext over WebSocket.

**`client.receive(ws)`**:
1. Reads the next WebSocket frame.
2. Base64-decodes the ciphertext.
3. Decrypts with our `encrypting_priv`.
4. Parses `{payload, signature}`.
5. Verifies the signature against mesgd's known `signing_pub`.
6. Returns the plaintext payload.

## Troubleshooting

**`FileNotFoundError: mesgd_pub.json`**
Run `curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json` in the
directory where you run `sample.py`.

**`ModuleNotFoundError: No module named 'pki'`**
Make sure you are running from within `samples/01-python/` and that the SDK root
(`../../`) is accessible. The script inserts `../../` into `sys.path` automatically.

**`ConnectionRefusedError` / WebSocket handshake failure**
Check that `MESGD_URL` is correct and that your network allows outbound WSS on
port 443. For local testing, start a mesgd echo server instance and point
`MESGD_URL` to `ws://localhost:8080/ws`.

**`AssertionError: Echo mismatch`**
This indicates the received message did not match what was sent, either due to
a server-side bug or a key mismatch after re-keying. Delete `pki_keys.json` and
re-register.
