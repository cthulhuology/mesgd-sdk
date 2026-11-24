# Rust mesgd-sdk Ping/Pong Sample

## Overview

This sample uses the Rust SDK backed by the `openssl` crate for ECDSA P-256
signing and RSA-2048-OAEP encryption, and `tokio-tungstenite` for async TLS
WebSocket transport. Error handling uses `anyhow` for ergonomic context chaining.
The code is fully async using `tokio`.

## Prerequisites

| Requirement | Version | Notes                                     |
|-------------|---------|-------------------------------------------|
| Rust        | 1.75+   | stable toolchain (`rustup`)               |
| cargo       | 1.75+   | bundled with Rust                         |
| OpenSSL     | 3.x     | development headers                       |

### Install Rust

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Install OpenSSL headers

```sh
# Ubuntu / Debian
sudo apt install libssl-dev pkg-config

# macOS (Homebrew)
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)

# Fedora / RHEL
sudo dnf install openssl-devel
```

## Configuration

| Environment Variable | Default                   | Description                          |
|----------------------|---------------------------|--------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws` | WebSocket endpoint                   |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`          | Path to mesgd server public JWK file |

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory:
cargo run

# Or build first:
cargo build --release
./target/release/mesgd-sample

# Custom settings:
MESGD_URL=ws://localhost:8080/ws cargo run
```

## Expected Output

```
=== mesgd-sdk Rust Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Rust ping #1
  [1/3] Received : Hello from mesgd-sdk! Rust ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Rust ping #2
  [2/3] Received : Hello from mesgd-sdk! Rust ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Rust ping #3
  [3/3] Received : Hello from mesgd-sdk! Rust ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### OAEP SHA-256 (important detail)

The `openssl` crate's `Rsa::public_encrypt()` only accepts a padding constant and
defaults to SHA-1 for MGF1 when `Padding::OAEP` is used. The SDK uses an `EVP`
context directly to set **both** the OAEP digest and MGF1 digest to SHA-256:

```rust
let mut ctx = PkeyCtx::new(&pkey)?;
ctx.encrypt_init()?;
ctx.set_rsa_padding(Padding::OAEP)?;
ctx.set_rsa_oaep_md(MessageDigest::sha256())?;
ctx.set_rsa_mgf1_md(MessageDigest::sha256())?;
```

This ensures ciphertexts are compatible with Python, Java, C#, and all other
language implementations.

### Async runtime

`#[tokio::main]` starts the Tokio multi-thread runtime. The WebSocket stream
implements `SinkExt` (for `send`) and `StreamExt` (for `next`/receive).

### Error handling with `anyhow`

Every fallible call uses the `?` operator. `.context("description")` adds
human-readable context to each error so the final message explains exactly which
step failed.

## Troubleshooting

**`error: failed to run custom build command for 'openssl-sys'`**
Set `OPENSSL_DIR`:
```sh
export OPENSSL_DIR=$(brew --prefix openssl)   # macOS
```
Or install headers: `sudo apt install libssl-dev pkg-config`

**`Error: WebSocket connect failed: ... certificate verify failed`**
The native-tls backend uses the OS trust store. Import the server CA cert if
using a self-signed certificate for local testing.

**`Error: Echo mismatch`**
Delete `pki_keys.json` and re-run to regenerate keys and re-register.

**Slow first build**
Cargo compiles all dependencies from source. Subsequent builds are incremental
and much faster. Use `--release` for maximum performance.
