# Java mesgd-sdk Ping/Pong Sample

## Overview

This sample demonstrates the mesgd-sdk workflow using Java's built-in JCA/JCE
cryptography and the JDK 11+ `HttpClient` WebSocket API — no external dependencies
are required beyond the JDK itself. Key material is generated using
`KeyPairGenerator` for ECDSA P-256 and RSA-2048, serialised as JWK, and persisted
to `pki_keys.json`.

## Prerequisites

| Requirement | Version | Notes                                    |
|-------------|---------|------------------------------------------|
| JDK         | 17+     | `HttpClient` WebSocket, `String.isBlank` |

Install the JDK:

```sh
# Ubuntu / Debian
sudo apt install openjdk-17-jdk

# macOS (Homebrew)
brew install openjdk@17

# Windows
winget install Microsoft.OpenJDK.17
```

## Configuration

| Environment Variable | Default                   | Description                          |
|----------------------|---------------------------|--------------------------------------|
| `MESGD_URL`          | `wss://echo.mesgd.org/ws` | WebSocket endpoint                   |
| `MESGD_PUB_JWK`      | `mesgd_pub.json`          | Path to mesgd server public JWK file |
| `MESGD_ROUNDS`       | `3`                       | Number of ping/pong iterations       |

Fetch the mesgd server public key before running:

```sh
curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json
```

## Build & Run

```sh
# From this directory — compile (no external jars needed for JDK 17+)
javac -cp ../../ PKISample.java

# Run
java -cp .:../../ PKISample

# With custom settings
MESGD_URL=wss://echo.mesgd.org/ws java -cp .:../../ PKISample
```

> **Windows note**: use `;` instead of `:` in the classpath:
> `java -cp ".;..\..\." PKISample`

## Expected Output

```
=== mesgd-sdk Java Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Java ping #1
  [1/3] Received : Hello from mesgd-sdk! Java ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Java ping #2
  [2/3] Received : Hello from mesgd-sdk! Java ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Java ping #3
  [3/3] Received : Hello from mesgd-sdk! Java ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI (`PKI.java`)

Java's `java.security` package provides `KeyPairGenerator` for both ECDSA and RSA:

```java
// ECDSA P-256
KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
gen.initialize(new ECGenParameterSpec("secp256r1"));

// RSA-2048
KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
gen.initialize(2048);
```

Keys are exported to JWK format by extracting raw components via
`ECPublicKey.getW()` (x/y coordinates) and `RSAPrivateCrtKey.getPrimeP()`
(CRT components), then encoding them as base64url strings.

### OAEP padding

The `PKI.encrypt()` and `PKI.encryptWith()` methods use `OAEPParameterSpec` with
SHA-256 for both the digest and the MGF1 digest to ensure interoperability with
all other language implementations:

```java
OAEPParameterSpec spec = new OAEPParameterSpec(
    "SHA-256", "MGF1",
    MGF1ParameterSpec.SHA256,
    PSource.PSpecified.DEFAULT);
cipher.init(Cipher.ENCRYPT_MODE, pubKey, spec);
```

### WebSocket (`HttpClient`)

JDK 11+ includes a built-in non-blocking WebSocket client via
`HttpClient.newWebSocketBuilder()`. The `MesgdClient` wrapper class implements
`WebSocket.Listener` to receive frames asynchronously and delivers them to the
main thread via an `AtomicReference`.

## Troubleshooting

**`ClassNotFoundException: PKI`**
Ensure `../../` is in the classpath: `-cp .:../../`

**`PKIX path building failed`** (TLS/SSL error)
The JDK trust store must include the mesgd server's CA. On corporate networks with
custom CAs, import the CA cert:
```sh
keytool -import -alias mesgd -file mesgd-ca.crt \
  -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit
```

**`AssertionError: Echo mismatch`**
Delete `pki_keys.json` and re-run to regenerate keys and re-register.

**Compilation warnings about `@SuppressWarnings("unchecked")`**
These are expected for the raw-type cast in `loadMesgdPubJwk`. They do not affect
correctness.
