# Ruby mesgd-sdk Ping/Pong Sample

## Overview

This sample uses Ruby 3.x with the built-in `openssl` gem for ECDSA P-256 signing
and RSA-2048-OAEP encryption, and `websocket-client-simple` for WebSocket transport.
Because `websocket-client-simple` uses a callback model on a background thread, a
`Queue` bridges the callback thread with the main thread for clean sequential
send → receive → assert flow.

## Prerequisites

| Requirement            | Version | Notes                                     |
|------------------------|---------|-------------------------------------------|
| Ruby                   | 3.0+    |                                           |
| Bundler                | 2.x     | `gem install bundler`                     |
| websocket-client-simple| 0.7+    | Installed via `bundle install`            |
| openssl gem            | 3.x     | Part of Ruby stdlib                       |

Install Ruby: https://www.ruby-lang.org/en/documentation/installation/

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
bundle install

# Run the sample
ruby sample.rb

# Custom settings:
MESGD_URL=ws://localhost:8080/ws ruby sample.rb
```

## Expected Output

```
=== mesgd-sdk Ruby Ping/Pong Sample ===

Step 1: Initialising PKI …
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' …
        Loaded.

Step 3: Registering with mesgd …
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6…

Step 4: Connecting to wss://echo.mesgd.org/ws …
        Connected.

Step 5: Starting 3-round ping/pong …

  [1/3] Sending  : Hello from mesgd-sdk! Ruby ping #1
  [1/3] Received : Hello from mesgd-sdk! Ruby ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Ruby ping #2
  [2/3] Received : Hello from mesgd-sdk! Ruby ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Ruby ping #3
  [3/3] Received : Hello from mesgd-sdk! Ruby ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI key generation

```ruby
# ECDSA P-256
@signing_priv = OpenSSL::PKey::EC.generate('prime256v1')

# RSA-2048
@encrypting_priv = OpenSSL::PKey::RSA.generate(2048)
```

Ruby's `openssl` gem uses OpenSSL under the hood. Key material is extracted via
`to_der` / `public_numbers` helpers and encoded as base64url for JWK storage.

### OAEP encryption

The sample uses the non-deprecated EVP path (OpenSSL gem 3.0+):

```ruby
encrypting_pub.encrypt(plaintext,
  rsa_padding_mode: 'oaep',
  rsa_oaep_md:      'SHA256',
  rsa_mgf1_md:      'SHA256')
```

### Thread-safe receive with Queue

`websocket-client-simple` fires the `on :message` callback on a background thread.
The main thread calls `receive_queue.pop` (blocking) to wait for the next message:

```ruby
ws.on :message do |msg|
  receive_queue.push(msg.data)          # callback thread
end

raw_response = receive_queue.pop        # main thread — blocks until message arrives
```

This avoids `Mutex` / `ConditionVariable` complexity and keeps the main flow linear.

## Troubleshooting

**`LoadError: cannot load such file -- websocket-client-simple`**
Run `bundle install` from the sample directory.

**`OpenSSL::PKey::EC::Point::Error`**
You may be on Ruby < 3.0 with an old `openssl` gem. Upgrade Ruby or run
`gem update openssl`.

**`ERROR: Signature verification failed`**
The server's signing key may have changed. Re-fetch `mesgd_pub.json`.

**The WebSocket callback never fires**
Check that the `ws` object is kept in scope until `ws.close` — Ruby may GC it
early if only a local variable.
