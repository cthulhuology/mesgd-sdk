# Haskell mesgd-sdk Ping/Pong Sample

## Overview

This sample uses the `crypton` library (the maintained successor to the deprecated
`cryptonite`) for ECDSA P-256 signing and RSA-2048-OAEP encryption, the `websockets`
library for WebSocket transport, and `aeson` for JWK JSON serialisation. The code
uses `do`-notation, `forM_` for the ping/pong loop, and `catch` for exception handling.

## Prerequisites

| Requirement  | Version | Notes                                         |
|--------------|---------|-----------------------------------------------|
| GHC          | 9.4+    | `ghcup install ghc 9.4.8`                    |
| cabal-install| 3.10+   | `ghcup install cabal`                         |
| crypton      | 0.34+   | Drop-in replacement for cryptonite             |
| websockets   | 0.12+   | WebSocket client/server                       |
| wuss         | 2.0+    | TLS wrapper for websockets (WSS support)      |
| aeson        | 2.1+    | JSON serialisation                            |

Install GHC and cabal via ghcup: https://www.haskell.org/ghcup/

```sh
curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
ghcup install ghc 9.4.8
ghcup install cabal 3.10.3
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
cabal update
cabal build
cabal run pki-sample

# Or with Stack:
stack build
stack run

# Custom settings:
MESGD_URL=ws://localhost:8080/ws cabal run pki-sample
```

## Expected Output

```
=== mesgd-sdk Haskell Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Haskell ping #1
  [1/3] Received : Hello from mesgd-sdk! Haskell ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Haskell ping #2
  [2/3] Received : Hello from mesgd-sdk! Haskell ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Haskell ping #3
  [3/3] Received : Hello from mesgd-sdk! Haskell ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### crypton vs cryptonite

`crypton` is the drop-in replacement for the deprecated `cryptonite`. Only the
package name in the cabal file changes; all module paths and APIs are identical:

```haskell
import Crypto.PubKey.ECC.Generate (generate)  -- crypton
```

### `forM_` for the ping/pong loop

```haskell
forM_ [1..rounds] $ \i -> do
    let message = "Hello from mesgd-sdk! Haskell ping #" ++ show i
    -- ...
```

### WebSocket TLS with `wuss`

The `wuss` library wraps `websockets` to add TLS:

```haskell
WS.runSecureClient host port path action  -- WSS
WS.runClient       host port path action  -- WS (plaintext)
```

`runWsClient` in the sample selects the correct variant based on the URI scheme.

### Aeson JWK serialisation

JWK objects are built using `Data.Aeson.object` with `.=`:

```haskell
object [ "kty" .= ("EC" :: T.Text)
       , "crv" .= ("P-256" :: T.Text)
       , "x"   .= base64urlEncodeInteger x
       , "y"   .= base64urlEncodeInteger y ]
```

## Troubleshooting

**`Ambiguous occurrence 'PrivateKey'` or similar**
Use qualified imports throughout: `import qualified Crypto.PubKey.RSA as RSA`.

**`cabal: Could not resolve dependencies`**
Run `cabal update` to refresh the package index, then retry `cabal build`.

**TLS handshake failure with `wuss`**
`wuss` uses the system certificate store. On minimal Linux installs, install
CA certificates: `sudo apt install ca-certificates`.

**`exitFailure` called from callback**
Check stderr output — the error message before `exitFailure` explains what failed.
