# PHP mesgd-sdk Ping/Pong Sample

## Overview

This sample uses PHP 8.1+ with the built-in OpenSSL extension for ECDSA P-256
signing and RSA-2048-OAEP encryption. WebSocket connectivity is provided by
Ratchet/Pawl running on a ReactPHP event loop — PHP's approach to async I/O.

> **PHP 8.0+ required** for `openssl_pkey_encrypt` with explicit SHA-256 MGF1.
> On PHP 7.x, `openssl_public_encrypt` uses SHA-1 for MGF1, producing ciphertexts
> incompatible with other language implementations.

## Prerequisites

| Requirement       | Version | Notes                                      |
|-------------------|---------|--------------------------------------------|
| PHP               | 8.1+    | With `openssl` extension enabled           |
| Composer          | 2.x     | Dependency management                      |
| OpenSSL extension | built-in| Check: `php -m \| grep openssl`            |

Install PHP on Ubuntu:
```sh
sudo apt install php8.1-cli php8.1-openssl
```

Install Composer: https://getcomposer.org/download/

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
composer install

# Run the sample
php sample.php

# Custom settings:
MESGD_URL=ws://localhost:8080/ws php sample.php
```

## Expected Output

```
=== mesgd-sdk PHP Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! PHP ping #1
  [1/3] Received : Hello from mesgd-sdk! PHP ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! PHP ping #2
  [2/3] Received : Hello from mesgd-sdk! PHP ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! PHP ping #3
  [3/3] Received : Hello from mesgd-sdk! PHP ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### Event loop (ReactPHP)

PHP is traditionally synchronous. The sample uses `React\EventLoop\Loop::get()`
to create a ReactPHP event loop, which Ratchet/Pawl uses to multiplex I/O without
blocking. The `$loop->run()` call at the end of the script starts the loop; it
runs until `$loop->stop()` is called (either after all rounds complete or on error).

### Sequential ping/pong

Because WebSocket callbacks are event-driven, the sample uses a `$pending` queue:
- The first message is sent immediately after the connection handshake.
- Each `on('message')` callback processes the echo and sends the next message.
- After the last echo, `$ws->close()` and `$loop->stop()` terminate the loop.

### OAEP SHA-256 (PHP 8.0+)

```php
openssl_pkey_encrypt($plaintext, $encrypted, $pubKey, [
    'padding' => OPENSSL_PKCS1_OAEP_PADDING,
    'oaep_md' => 'sha256',
    'mgf1_md' => 'sha256',
]);
```

The `oaep_md` and `mgf1_md` options require PHP 8.0+.

## Troubleshooting

**`PHP Fatal error: Uncaught Error: Class 'Ratchet\Client\WebSocket' not found`**
Run `composer install` first to download Ratchet/Pawl.

**`openssl extension not found`**
Enable it in `php.ini`: uncomment `extension=openssl` and restart PHP.

**`ERROR connecting: Stream is encrypted`**
SSL certificate verification may be failing. For local testing:
```sh
MESGD_URL=ws://localhost:8080/ws php sample.php
```

**OAEP mismatch with other languages**
Ensure PHP 8.1+ is used. Verify with `php --version`. Older PHP uses SHA-1 for
MGF1 which is incompatible.
