# mesgd-sdk Samples

Each directory contains a self-contained ping/pong echo sample that exercises the
full mesgd-sdk lifecycle: key initialisation → registration → WebSocket connect →
sign+encrypt → send → receive → decrypt+verify.

## Language Popularity Ranking

Languages are ordered by combined TIOBE Index, Stack Overflow Developer Survey, and
GitHub repository activity (March 2026 snapshot).

| Rank | Language   | Directory         | WebSocket Sample |
|------|------------|-------------------|-----------------|
| 1    | Python     | `01-python/`      | ✅               |
| 2    | JavaScript | `02-javascript/`  | ✅               |
| 3    | Java       | `03-java/`        | ✅               |
| 4    | C          | `04-c/`           | ✅               |
| 5    | C++        | `05-cpp/`         | ✅               |
| 6    | C#         | `06-csharp/`      | ✅               |
| 7    | Go         | `07-go/`          | ✅               |
| 8    | Rust       | `08-rust/`        | ✅               |
| 9    | PHP        | `09-php/`         | ✅               |
| 10   | Swift      | `10-swift/`       | ✅ (Apple only)  |
| 11   | Ruby       | `11-ruby/`        | ✅               |
| 12   | Erlang     | `12-erlang/`      | ✅               |
| 13   | Perl       | `13-perl/`        | ✅               |
| 14   | Haskell    | `14-haskell/`     | ✅               |
| 15   | Lua        | `15-lua/`         | ✅               |
| 16   | OCaml      | `16-ocaml/`       | ✅               |
| 17   | Forth      | `17-forth/`       | ❌ (local demo)  |

## Quick Start

### 1. Obtain `mesgd_pub.json`

Every sample needs the mesgd server's public encryption key in JWK format.
Fetch it from the well-known endpoint:

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

Place `mesgd_pub.json` in the directory you run the sample from, or set the
`MESGD_PUB_JWK` environment variable to its absolute path.

### 2. Set environment variables (optional)

| Variable        | Default                        | Description                          |
|-----------------|--------------------------------|--------------------------------------|
| `MESGD_URL`     | `wss://echo.mesgd.org/ws`      | WebSocket endpoint for the echo test |
| `MESGD_PUB_JWK` | `mesgd_pub.json`               | Path to mesgd server public JWK file |

### 3. Run the sample for your language

See the `README.md` in the relevant subdirectory for language-specific instructions.

## How the Ping/Pong Flow Works

```
┌────────────────────────────────────────────────────────┐
│                     Sample Application                  │
│                                                        │
│  1. PKI.init()          Load or generate key pairs     │
│  2. PKI.register()      Sign+encrypt our pubkeys       │
│          │                   to mesgd's enc key        │
│          ▼                                             │
│  3. mesgd.connect()     Open WebSocket to echo server  │
│          │                                             │
│  ┌───────┴──────────────────────┐                      │
│  │  for i in 1..3:              │                      │
│  │    msg = "...ping #i"        │                      │
│  │    mesgd.send()              │  sign(msg) with our  │
│  │      │                       │  signing_priv, then  │
│  │      │                       │  encrypt envelope    │
│  │      │                       │  with mesgd's pub   │
│  │      ▼                       │                      │
│  │    mesgd.receive()           │  decrypt with our    │
│  │      │                       │  encrypting_priv,    │
│  │      │                       │  verify mesgd sig    │
│  │      ▼                       │                      │
│  │    assert response == msg ✓  │                      │
│  └──────────────────────────────┘                      │
│  4. mesgd.disconnect()                                 │
└────────────────────────────────────────────────────────┘
```

## Common Configuration

### `mesgd_pub.json` format

This file contains mesgd's RSA-2048 public key in JWK format:

```json
{
  "kty": "RSA",
  "n":   "<base64url-encoded modulus>",
  "e":   "AQAB"
}
```

It is used by `PKI.register()` and `mesgd.send()` to encrypt payloads so that
only the mesgd server can read them.

### `pki_keys.json` (auto-generated)

On first run, each sample calls `PKI.init()` which generates a fresh ECDSA P-256
signing key pair and an RSA-2048 encryption key pair, saving them to `pki_keys.json`
in the current working directory.  Subsequent runs load the same keys.

## Note on Forth

The Forth implementation (`17-forth/`) is a local-only demonstration.  It
exercises key generation, signing, verification, encryption, and decryption using
direct OpenSSL FFI calls, but does not include WebSocket connectivity.  This is
intentional: Forth has no standard library for JSON encoding/decoding or base64url,
which are prerequisites for the JWK wire format used by the mesgd WebSocket protocol.
See `plan.md` for a full rationale.
