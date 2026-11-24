# Go mesgd-sdk Ping/Pong Sample

## Overview

This sample demonstrates the mesgd-sdk workflow in idiomatic Go: explicit error
returns, deferred cleanup, and no global mutable state. The `pki` package uses the
standard library `crypto/ecdsa`, `crypto/rsa`, and `crypto/x509` packages; the
`mesgd` package uses `gorilla/websocket` for TLS WebSocket transport.

## Prerequisites

| Requirement | Version | Notes                                  |
|-------------|---------|----------------------------------------|
| Go          | 1.21+   | `go.work` or module-based builds       |

Install Go: https://go.dev/dl

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
go mod tidy       # download gorilla/websocket
go run .          # build and run

# Or build first, then run:
go build -o sample .
./sample

# Custom settings:
MESGD_URL=ws://localhost:8080/ws go run .
```

## Expected Output

```
=== mesgd-sdk Go Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Go ping #1
  [1/3] Received : Hello from mesgd-sdk! Go ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Go ping #2
  [2/3] Received : Hello from mesgd-sdk! Go ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Go ping #3
  [3/3] Received : Hello from mesgd-sdk! Go ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI (`pki.go`)

Go's `crypto/ecdsa` and `crypto/rsa` packages generate keys:

```go
privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
rsaKey,  _ := rsa.GenerateKey(rand.Reader, 2048)
```

Key material is extracted (`privKey.PublicKey.X`, `privKey.PublicKey.Y`,
`privKey.D`, `rsaKey.PublicKey.N`, etc.) and encoded as base64url strings to build
the JWK JSON written to `pki_keys.json`.

### Error handling

Every function returns `(result, error)`. The sample checks every error immediately:

```go
if err := pki.Init(); err != nil {
    log.Fatalf("pki.Init: %v", err)
}
```

### Deferred cleanup

The WebSocket close is registered with `defer` immediately after `Connect()` to
ensure the connection is always closed, even if a later step panics.

### gorilla/websocket

```go
conn, _, err := websocket.DefaultDialer.Dial(url, nil)
conn.WriteMessage(websocket.TextMessage, payload)
_, msg, err := conn.ReadMessage()
```

TLS certificate verification uses the system root CA pool by default.

## Troubleshooting

**`cannot find package "mesgd-sdk/pki"`**
The `go.mod` module path is `mesgd-sdk/samples/go` and it expects `pki` and
`mesgd` as local packages under `../../`. Run `go mod tidy` and ensure the SDK
root contains `pki.go` and `mesgd.go`.

**`dial tcp: connection refused`**
Check `MESGD_URL` and network access. For local testing:
`MESGD_URL=ws://localhost:8080/ws go run .`

**`x509: certificate signed by unknown authority`**
Your system trust store may be missing the server's CA. Export the CA cert and
set `SSL_CERT_FILE=/path/to/ca.crt` before running.
