# OCaml mesgd-sdk Ping/Pong Sample

## Overview

This sample uses OCaml 5.1+ with `mirage-crypto` for ECDSA P-256 and RSA-2048-OAEP
cryptography, `websocket-lwt-unix` for TLS WebSocket transport, and `yojson` for JWK
JSON serialisation. The async I/O uses `Lwt` (monadic promises) with `>>=` bind
operators and `Lwt_main.run` to drive the event loop.

## Prerequisites

| Requirement           | Version | Notes                                     |
|-----------------------|---------|-------------------------------------------|
| OCaml                 | 5.1+    | Or 4.14+ with domains disabled            |
| opam                  | 2.1+    | Package manager                           |
| dune                  | 3.0+    | Build system                              |
| mirage-crypto         | 0.11+   | EC + RSA cryptography                     |
| mirage-crypto-ec      | 0.11+   | ECDSA P-256                               |
| mirage-crypto-pk      | 0.11+   | RSA-2048-OAEP                             |
| websocket-lwt-unix    | 2.16+   | WebSocket over Lwt/Unix                   |
| yojson                | 2.1+    | JSON library                              |
| base64                | 3.5+    | base64url encoding                        |

### Install dependencies

```sh
# Install OCaml + opam if needed
bash -c "sh <(curl -fsSL https://opam.ocaml.org/install.sh)"
opam init
eval $(opam env)
opam switch create 5.1.0

# Install library dependencies
opam install dune yojson base64 lwt lwt_ssl \
             mirage-crypto mirage-crypto-ec mirage-crypto-pk \
             websocket websocket-lwt-unix
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
dune build
dune exec ./sample.exe

# Or run the compiled binary:
./_build/default/sample.exe

# Custom settings:
MESGD_URL=ws://localhost:8080/ws dune exec ./sample.exe
```

## Expected Output

```
=== mesgd-sdk OCaml Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! OCaml ping #1
  [1/3] Received : Hello from mesgd-sdk! OCaml ping #1
  [1/3] Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! OCaml ping #2
  [2/3] Received : Hello from mesgd-sdk! OCaml ping #2
  [2/3] Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! OCaml ping #3
  [3/3] Received : Hello from mesgd-sdk! OCaml ping #3
  [3/3] Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### Lwt monadic style

The entire sample runs inside `Lwt_main.run`. Each async operation returns an
`'a Lwt.t` promise, and `>>=` sequences them:

```ocaml
Pki.sign message >>= fun signature ->
Pki.encrypt_with pub_jwk envelope >>= fun ciphertext ->
Mesgd.send client ciphertext >>= fun () ->
Mesgd.receive client >>= fun raw_frame ->
(* ... *)
```

### Recursive loop

OCaml does not have a `for` loop that works naturally with `Lwt.t`. The sample
uses a recursive `loop i` function:

```ocaml
let rec loop i =
  if i > rounds then Lwt.return_unit
  else
    (* ... do round i ... *)
    loop (i + 1)
in loop 1
```

### mirage-crypto ECDSA

```ocaml
let priv, pub = Mirage_crypto_ec.P256.Dsa.generate ~rng:Mirage_crypto_rng.generate ()
let signature = Mirage_crypto_ec.P256.Dsa.sign ~key:priv digest
```

### Yojson JWK

```ocaml
`Assoc [("kty", `String "EC"); ("crv", `String "P-256");
        ("x",   `String (Base64.encode_string x_bytes));
        ("y",   `String (Base64.encode_string y_bytes))]
```

## Troubleshooting

**`Error: Unbound module Pki`**
Ensure `pki` and `mesgd` are listed as libraries in the `dune` file and that
`pki.ml` / `mesgd.ml` are compiled as library stanzas in the SDK root dune file.

**`Lwt_unix: no ssl support`**
Install `lwt_ssl`: `opam install lwt_ssl`. Also ensure `ssl` (openssl binding) is installed.

**`dune: No opam switch`**
Run `eval $(opam env)` to activate the current opam switch.

**TLS certificate errors**
Install `ca-certificates` on Linux: `sudo apt install ca-certificates`.
On macOS, the system keychain is used automatically.
