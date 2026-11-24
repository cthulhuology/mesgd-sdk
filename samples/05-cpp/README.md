# C++ mesgd-sdk Ping/Pong Sample

## Overview

This sample uses the C++ SDK (`pki.cc` / `pki.hh`) with the OpenSSL EVP API for
ECDSA P-256 and RSA-2048-OAEP, Boost.Beast for TLS WebSocket transport, and
`nlohmann/json` (single-header) for JWK serialisation. It demonstrates RAII
ownership, `std::string` throughout, and exception-based error handling.

## Prerequisites

| Requirement    | Version | Notes                                       |
|----------------|---------|---------------------------------------------|
| GCC or Clang   | 11+     | C++17 support (`-std=c++17`)                |
| Boost          | 1.82+   | `boost::asio`, `boost::beast`, `boost::ssl` |
| OpenSSL        | 3.x     | libssl + libcrypto                          |
| nlohmann/json  | 3.11+   | Header-only, no linking needed              |
| make           | 4+      |                                             |

### Install dependencies

**Ubuntu / Debian:**
```sh
sudo apt update
sudo apt install build-essential libboost-all-dev libssl-dev
# nlohmann/json (or use single-header download):
sudo apt install nlohmann-json3-dev
```

**macOS (Homebrew):**
```sh
brew install boost openssl nlohmann-json
export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig"
```

**Single-header nlohmann/json (alternative):**
```sh
curl -Lo /usr/local/include/nlohmann/json.hpp \
  https://github.com/nlohmann/json/releases/latest/download/json.hpp
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
make
./sample

# Custom endpoint
MESGD_URL=ws://localhost:8080/ws ./sample
```

## Expected Output

```
=== mesgd-sdk C++ Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! C++ ping #1
  [1/3] Received : Hello from mesgd-sdk! C++ ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! C++ ping #2
  [2/3] Received : Hello from mesgd-sdk! C++ ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! C++ ping #3
  [3/3] Received : Hello from mesgd-sdk! C++ ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### RAII key management

The `pki::PKIImpl` class holds four `EVP_PKEY*` members and frees them in its
destructor, ensuring no leaks even when exceptions are thrown. A module-level
`static PKIImpl impl` instance acts as the singleton key store.

### Boost.Beast TLS WebSocket

```cpp
ssl::context ssl_ctx{ssl::context::tlsv12_client};
ssl_ctx.set_default_verify_paths();
websocket::stream<beast::ssl_stream<tcp::socket>> ws{ioc, ssl_ctx};
```

The TLS layer verifies the server certificate against the system trust store.
Frames are sent and received synchronously within the same `io_context`.

### nlohmann/json for JWK

JWK parsing and serialisation use the `nlohmann::json` structured bindings.
base64url encoding is implemented as a helper in `pki.hh` using OpenSSL's BIO
with character substitution (`+`→`-`, `/`→`_`, strip `=`).

## Troubleshooting

**`fatal error: nlohmann/json.hpp: No such file or directory`**
Install via package manager or download the single-header file (see Prerequisites).

**`error: no member named 'websocket' in namespace 'boost::beast'`**
Boost < 1.70 does not include Beast. Upgrade to Boost 1.82+.

**SSL certificate verification failure**
On some systems `set_default_verify_paths()` does not load the CA bundle.  Try:
```cpp
ssl_ctx.load_verify_file("/etc/ssl/certs/ca-certificates.crt");
```

**Link errors with `-lboost_system`**
On header-only Boost builds (1.82+), `boost::system` is header-only and `-lboost_system`
is not needed. Remove it from `LDFLAGS` in the Makefile if you see "library not found".
