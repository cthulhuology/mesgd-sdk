# Swift mesgd-sdk Ping/Pong Sample

## Overview

This sample targets **Apple platforms only** (macOS 13+). It uses `CryptoKit`
for ECDSA P-256 signing and the `Security` framework for RSA-2048-OAEP encryption.
WebSocket connectivity uses `URLSessionWebSocketTask` (no external packages needed).

> **Linux limitation**: `CryptoKit` (swift-crypto) has no RSA support on Linux.
> RSA on Linux requires direct OpenSSL C interop via a `COpenSSL` SPM system
> library. See `plan.md` §18 for details and the roadmap.

> **`init()` is a reserved word** in Swift. The SDK function is named `setup()`
> instead of `init()` — this is an intentional deviation from other languages.

## Prerequisites

| Requirement | Version  | Notes                              |
|-------------|----------|------------------------------------|
| macOS       | 13+      | Ventura or newer                   |
| Xcode       | 15+      | Or Swift toolchain 5.9+            |
| Swift       | 5.9+     | `swift build` CLI                  |

Check your Swift version:
```sh
swift --version
```

## Configuration

| Environment Variable | Default                   | Description                          |
|----------------------|---------------------------|--------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws` | WebSocket endpoint                   |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`          | Path to mesgd server public JWK file |
| `MESGD_ROUNDS`       | `3`                       | Number of ping/pong iterations       |

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory:
swift build
swift run

# Or run the compiled binary directly:
.build/debug/PKISample

# Release build (faster crypto):
swift build -c release
.build/release/PKISample

# Custom settings:
MESGD_URL=ws://localhost:8080/ws swift run
```

## Expected Output

```
=== mesgd-sdk Swift Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Swift ping #1
  [1/3] Received : Hello from mesgd-sdk! Swift ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Swift ping #2
  [2/3] Received : Hello from mesgd-sdk! Swift ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Swift ping #3
  [3/3] Received : Hello from mesgd-sdk! Swift ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### ECDSA P-256 (CryptoKit)

```swift
let signingKey = P256.Signing.PrivateKey()
let signature  = try signingKey.signature(for: SHA256.hash(data: data))
```

For JWK export, the x/y coordinates are extracted from the public key's
`x963Representation` (65 bytes: `04 || x[32] || y[32]`):

```swift
let rep = signingKey.publicKey.x963Representation   // 65 bytes
let x   = rep[1..<33]   // bytes 1..32
let y   = rep[33..<65]  // bytes 33..64
```

### RSA-2048 (Security framework)

The `Security` framework's `SecKeyCreateRandomKey` generates RSA keys and
`SecKeyCreateEncryptedData` performs OAEP-SHA256 encryption:

```swift
SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, plaintext, &error)
```

### WebSocket (URLSessionWebSocketTask)

```swift
let task = URLSession.shared.webSocketTask(with: URL(string: url)!)
task.resume()
task.send(.string(text)) { error in ... }
task.receive { result in ... }
```

`DispatchSemaphore` is used to synchronise the async callbacks with the main
thread, keeping the code linear and easy to follow.

### JWK storage

Keys are serialised to `pki_keys.json` in the **current working directory**
(not `.documentDirectory` — that path is iOS/iPadOS-only). On macOS CLI tools,
`FileManager.default.currentDirectoryPath` gives the process working directory.

## Troubleshooting

**`error: 'init' is a keyword and cannot be used as an identifier`**
This is why the SDK uses `PKI.setup()` instead of `PKI.init()`. Do not try to
rename it back.

**`Error: PKI setup failed: OSStatus -25300`**
The Security framework could not access the keychain. Try running outside a
sandboxed environment (Swift Package command-line targets are not sandboxed).

**`error: compiler is unable to type-check this expression in reasonable time`**
Add explicit type annotations where the compiler complains. This is rare in the
sample but can occur with nested closures.

**WebSocket connection refused on macOS Ventura+**
Apple enforces App Transport Security (ATS). For `ws://` (non-TLS), add an ATS
exception in the app's `Info.plist`. For command-line tools, ATS does not apply.
