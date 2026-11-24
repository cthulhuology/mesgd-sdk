# C mesgd-sdk Ping/Pong Sample

## Overview

This sample uses the C SDK (`pki.c` / `pki.h`) backed by the OpenSSL EVP API for
ECDSA P-256 signing and RSA-2048-OAEP encryption, `libwebsockets` for WebSocket
transport, and `cJSON` for JWK JSON encoding/decoding. It is the lowest-level of
all SDK implementations and makes the cryptographic operations most explicit.

## Prerequisites

| Requirement      | Version | Notes                         |
|------------------|---------|-------------------------------|
| GCC or Clang     | 11+     | C11 standard                  |
| OpenSSL          | 3.x     | libssl + libcrypto             |
| libwebsockets    | 4.3+    | WebSocket client               |
| cJSON            | 1.7+    | Lightweight JSON library       |
| make             | 4+      |                               |

### Install dependencies

**Ubuntu / Debian:**
```sh
sudo apt update
sudo apt install build-essential libssl-dev libwebsockets-dev libcjson-dev
```

**macOS (Homebrew):**
```sh
brew install openssl libwebsockets cjson
# If OpenSSL is not in the default search path:
export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig"
```

**Fedora / RHEL:**
```sh
sudo dnf install gcc openssl-devel libwebsockets-devel cjson-devel
```

## Configuration

| Environment Variable | Default                   | Description                          |
|----------------------|---------------------------|--------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws` | WebSocket endpoint                   |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`          | Path to mesgd server public JWK file |

Fetch the mesgd server public key before running:

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory:
make

# Run with defaults
./sample

# Run with custom settings
MESGD_URL=wss://echo.mesgd.org/ws MESGD_PUB_JWK=mesgd_pub.json ./sample
```

## Expected Output

```
=== mesgd-sdk C Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! C ping #1
  [1/3] Received : Hello from mesgd-sdk! C ping #1
  [1/3] Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! C ping #2
  [2/3] Received : Hello from mesgd-sdk! C ping #2
  [2/3] Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! C ping #3
  [3/3] Received : Hello from mesgd-sdk! C ping #3
  [3/3] Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI (`pki_init`)

`pki_init()` tries to open `pki_keys.json`. If absent, it calls `pki_generate()`:

1. `EC_KEY_generate_key(NID_X9_62_prime256v1)` — ECDSA P-256 signing key pair.
2. `RSA_generate_key_ex(2048, BN_set_word(e, RSA_F4))` — RSA-2048 encryption key pair.
3. Extracts raw key material (EC coordinates via `EC_POINT_get_affine_coordinates`,
   RSA components via `RSA_get0_key`).
4. Encodes all integers as base64url (`-_`, no padding).
5. Serialises to JSON with `cJSON` and writes `pki_keys.json`.

### Registration (`pki_register`)

1. Exports `signing_pub` and `encrypting_pub` as JWK JSON strings.
2. Signs the payload using `EVP_DigestSign` with SHA-256.
3. Wraps `{payload, signature}` as JSON.
4. Encrypts with mesgd's public key using EVP OAEP context:
   ```c
   EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
   EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
   ```
5. Base64-encodes the ciphertext and returns it.

### WebSocket (`libwebsockets`)

`mesgd_connect()` creates an `lws_context` with TLS enabled and connects to the
server. Messages are exchanged using `lws_write()` / the per-session callback
`LWS_CALLBACK_CLIENT_RECEIVE`.  A `MesgdConn` struct holds the context, wsi
handle, and a receive buffer protected by a mutex.

### Memory management

Every function that returns a `char *` (e.g. `pki_sign`, `mesgd_receive`) returns
heap-allocated memory that the caller must `free()`. The sample calls `free()` on
each such pointer immediately after use.

## Troubleshooting

**`fatal error: cjson/cJSON.h: No such file or directory`**
Install cJSON development headers: `sudo apt install libcjson-dev` or
`brew install cjson`. On macOS, add `-I$(brew --prefix cjson)/include` to `CFLAGS`.

**`libwebsockets.so: cannot open shared object file`**
Add the library directory to `LD_LIBRARY_PATH`:
```sh
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

**`ERROR: pki_init() failed`**
OpenSSL error details are printed to stderr via `ERR_print_errors_fp`. Check the
output for specifics (permissions on `pki_keys.json`, corrupt key file, etc.).

**Build fails on macOS with `ld: library not found for -lwebsockets`**
Add Homebrew lib path: `export LIBRARY_PATH="$(brew --prefix libwebsockets)/lib"`.
