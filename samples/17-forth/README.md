# Forth mesgd-sdk Local PKI Demo

## Overview

This sample is a **local-only PKI demonstration** for Forth (gforth). It exercises
ECDSA P-256 signing/verification and RSA-2048-OAEP encryption/decryption using
direct OpenSSL FFI calls — without any network connectivity.

> **WebSocket connectivity is intentionally omitted.** Forth has no standard
> libraries for JSON encoding/decoding or base64url — both required by the mesgd
> JWK wire format. Implementing them from scratch in Forth would require hundreds
> of lines of primitive code with no practical benefit. See `plan.md` §19 for the
> full rationale.
>
> For a complete WebSocket ping/pong echo test, use any other language sample,
> e.g. `samples/01-python/`.

## What this demo does

1. Generates an ECDSA P-256 key pair (via `EVP_PKEY_CTX_set_ec_paramgen_curve_nid`)
2. Generates an RSA-2048 key pair (via `EVP_PKEY_CTX_new_from_name("RSA", ...)`)
3. Runs **3 rounds** of:
   - Sign `"Hello from mesgd-sdk! Forth demo"` with the EC signing key
   - Verify the DER-encoded signature
   - Encrypt the test string with the RSA public key (OAEP-SHA256)
   - Decrypt the ciphertext with the RSA private key
   - Assert the decrypted plaintext matches the original

## Prerequisites

| Requirement | Version | Notes                                      |
|-------------|---------|--------------------------------------------|
| gforth      | 0.7.3+  | GNU Forth interpreter                      |
| OpenSSL     | 3.x     | Shared library (`libcrypto.so`)            |
| gforth C FFI| built-in| `lib.fs`, `c-function`, `add-lib`          |

### Install gforth

**Ubuntu / Debian:**
```sh
sudo apt install gforth libssl-dev
```

**macOS (Homebrew):**
```sh
brew install gforth openssl
```

**From source:** https://www.gnu.org/software/gforth/

## Configuration

No environment variables are needed — this demo has no network component.

## Run

```sh
# Make sure OpenSSL is in the library search path:
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH   # Linux
export DYLD_LIBRARY_PATH=$(brew --prefix openssl)/lib:$DYLD_LIBRARY_PATH  # macOS

gforth sample.f
```

## Expected Output

```
=== mesgd-sdk Forth Local PKI Demo ===

NOTE: WebSocket support is out of scope for Forth.
      This demo exercises local cryptographic operations only.

Initialising PKI (generating ECDSA P-256 + RSA-2048 keys) ...
Keys generated.

Round 1 :
 Signed    : OK (DER signature, 71 bytes)
 Verified  : OK
 Encrypted : OK (256 bytes)
 Decrypted : Hello from mesgd-sdk! Forth demo
 Match     : OK

Round 2 :
 Signed    : OK (DER signature, 70 bytes)
 Verified  : OK
 Encrypted : OK (256 bytes)
 Decrypted : Hello from mesgd-sdk! Forth demo
 Match     : OK

Round 3 :
 Signed    : OK (DER signature, 71 bytes)
 Verified  : OK
 Encrypted : OK (256 bytes)
 Decrypted : Hello from mesgd-sdk! Forth demo
 Match     : OK

All 3 rounds completed successfully.

(WebSocket ping/pong not available in Forth - see samples/01-python/ etc.)
```

> **Note**: ECDSA signatures are non-deterministic (they include a random nonce).
> The signature byte count will vary slightly between runs (70–72 bytes for P-256).

## How It Works

### gforth C FFI

gforth's `c-function` word declares a binding to a C function:

```forth
c-function EVP_sha256 EVP_sha256 -- a
```

The type descriptor uses: `n` = 32-bit integer, `a` = pointer, `u` = unsigned,
`void` = no return.  `add-lib "crypto"` loads `libcrypto.so` at runtime.

### Why `c-value` not `c-function` for constants

C preprocessor constants like `RSA_PKCS1_OAEP_PADDING` are integers, not
functions. They are declared as Forth constants using their numeric value directly:

```forth
4 constant RSA_PKCS1_OAEP_PADDING   \ the integer value of the C constant
```

This corrects the original `pki.f` which incorrectly declared them as `c-function`.

### Memory allocation

The sample uses `allocate` (standard Forth ANS word) to heap-allocate output
buffers for signatures and ciphertexts. Callers are responsible for `free`-ing
them, following C conventions.

### Key persistence (not implemented)

JWK-format key persistence would require a JSON emitter and base64url encoder —
neither of which exists in standard Forth. New keys are generated fresh on each
run. See `plan.md` for the Forth scope limitation rationale.

## Troubleshooting

**`undefined word: lib.fs`**
`lib.fs` is a gforth-specific file for the C FFI. Ensure you are using gforth
(not Swiftforth, iForth, or another Forth). Run `gforth --version` to confirm.

**`add-lib: libcrypto not found`**
Add the OpenSSL library directory to `LD_LIBRARY_PATH` before running:
```sh
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
```
On macOS:
```sh
export DYLD_LIBRARY_PATH=$(brew --prefix openssl)/lib:$DYLD_LIBRARY_PATH
```

**`EVP_PKEY_CTX_new_id failed`**
The NID constant `EVP_PKEY_EC_NID` (408 in OpenSSL 3.x) may differ in your
OpenSSL version. Verify with:
```sh
grep EVP_PKEY_EC /usr/include/openssl/evp.h
```

**Signature byte count differs from expected**
ECDSA DER signatures are variable-length (70–72 bytes for P-256) because the
DER encoding of `r` and `s` depends on their high bits. This is correct behaviour.
