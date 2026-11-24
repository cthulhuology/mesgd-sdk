# C# mesgd-sdk Ping/Pong Sample

## Overview

This sample targets .NET 8 and uses only built-in BCL types — no external NuGet
packages are required. `System.Security.Cryptography` provides ECDSA P-256 signing
and RSA-2048 OAEP encryption. `System.Net.WebSockets.ClientWebSocket` handles TLS
WebSocket transport. `System.Text.Json` handles JWK serialisation.

> **Important**: C#'s `ECDsa.SignData()` returns signatures in IEEE P1363 format
> (raw `r||s` bytes). The `PKI.Sign()` method converts this to DER-encoded ASN.1
> before base64-encoding, ensuring interoperability with all other language
> implementations. See `plan.md` §9 for details.

## Prerequisites

| Requirement | Version | Notes                                |
|-------------|---------|--------------------------------------|
| .NET SDK    | 8.0+    | `dotnet` CLI                         |

Install the .NET SDK: https://dotnet.microsoft.com/download

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
# From this directory — build and run in one step:
dotnet run

# Build only:
dotnet build

# Run the compiled binary directly:
./bin/Debug/net8.0/PKISample
# or on Windows:
bin\Debug\net8.0\PKISample.exe

# Custom settings:
MESGD_URL=ws://localhost:8080/ws dotnet run
```

## Expected Output

```
=== mesgd-sdk C# Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! C# ping #1
  [1/3] Received : Hello from mesgd-sdk! C# ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! C# ping #2
  [2/3] Received : Hello from mesgd-sdk! C# ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! C# ping #3
  [3/3] Received : Hello from mesgd-sdk! C# ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI key generation

```csharp
// ECDSA P-256 signing key
signingPriv = ECDsa.Create(ECCurve.NamedCurves.nistP256);

// RSA-2048 encryption key
encryptingPriv = RSA.Create(2048);
```

Keys are exported via `ExportParameters(true)` and encoded field-by-field as
base64url to build JWK JSON written to `pki_keys.json`.

### ECDSA signature format (P1363 → DER)

.NET's `ECDsa.SignData()` returns 64 raw bytes (`r[32] || s[32]`). The `PKI.Sign()`
wrapper converts this to the DER SEQUENCE form used by OpenSSL and all other
implementations:

```
30 <len> 02 <rlen> <r-bytes> 02 <slen> <s-bytes>
```

`PKI.Check()` performs the inverse: DER → P1363 before passing to `ECDsa.VerifyData()`.

### OAEP

```csharp
encryptingPub.Encrypt(data, RSAEncryptionPadding.OaepSHA256)
```

`OaepSHA256` uses SHA-256 for both the OAEP hash and MGF1, matching all other
language implementations.

### WebSocket

`System.Net.WebSockets.ClientWebSocket` is part of .NET and requires no external
package. The sample uses top-level `await` (C# 9+ / .NET 6+ top-level statements).
A `CancellationTokenSource` with a 30-second timeout guards all async operations.

## Troubleshooting

**`MSB3030: Could not copy '../../pki.cs'`**
Ensure you run `dotnet run` from `samples/06-csharp/` and that `pki.cs` and
`mesgd.cs` exist in the SDK root.

**`WebSocketException: The remote party closed the WebSocket connection`**
The server rejected the registration payload, likely due to an outdated
`mesgd_pub.json`. Re-fetch the public key and delete `pki_keys.json`.

**`InvalidOperationException: Signature verification failed`**
The mesgd server's signing key may have rotated. Re-fetch `mesgd_pub.json`.

**`PlatformNotSupportedException` on Linux**
Ensure `.NET 8` is installed, not an older runtime. On ARM64 Linux, AES-NI and
PCLMUL instructions may not be available; the code will still work but slower.
