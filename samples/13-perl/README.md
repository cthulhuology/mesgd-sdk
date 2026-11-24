# Perl mesgd-sdk Ping/Pong Sample

## Overview

This sample uses Perl 5.20+ with `Crypt::Perl::ECDSA` for P-256 signing,
`Crypt::OpenSSL::RSA` for RSA-2048-OAEP encryption, and
`AnyEvent::WebSocket::Client` for non-blocking WebSocket connectivity. The
AnyEvent event loop handles the async I/O while `condvar` objects provide clean
synchronisation between the callback-driven WebSocket and the sequential main flow.

## Prerequisites

| Requirement                    | Version | Notes                           |
|--------------------------------|---------|---------------------------------|
| Perl                           | 5.20+   |                                 |
| cpanm                          | 1.7+    | `curl -L cpanmin.us \| perl -`  |
| AnyEvent                       | 7.17+   | Non-blocking event loop         |
| AnyEvent::WebSocket::Client    | 0.55+   | WebSocket client                |
| JSON::PP                       | 4.10+   | JSON (core module)              |
| Crypt::Perl                    | 0.35+   | ECDSA P-256                     |
| Crypt::OpenSSL::RSA            | 0.33+   | RSA-2048-OAEP                   |

### Install dependencies

```sh
# Install cpanm if needed
curl -L cpanmin.us | perl - App::cpanminus

# Install CPAN modules
cpanm AnyEvent AnyEvent::WebSocket::Client JSON::PP \
      Crypt::Perl Crypt::OpenSSL::RSA MIME::Base64
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
# Install dependencies
cpanm AnyEvent AnyEvent::WebSocket::Client JSON::PP Crypt::Perl Crypt::OpenSSL::RSA

# Run
perl sample.pl

# Custom settings:
MESGD_URL=ws://localhost:8080/ws perl sample.pl
```

## Expected Output

```
=== mesgd-sdk Perl Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! Perl ping #1
  [1/3] Received : Hello from mesgd-sdk! Perl ping #1
  [1/3] ✓ Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Perl ping #2
  [2/3] Received : Hello from mesgd-sdk! Perl ping #2
  [2/3] ✓ Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Perl ping #3
  [3/3] Received : Hello from mesgd-sdk! Perl ping #3
  [3/3] ✓ Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### AnyEvent event loop

`AnyEvent->condvar` creates a semaphore-like object. The main script calls
`$cv->recv` to block until `$cv->send` is called from a callback. This pattern
converts the callback-driven WebSocket API into sequential-looking code.

### ECDSA (Crypt::Perl)

```perl
my $key  = Crypt::Perl::ECDSA::Generate::by_name('prime256v1');
my $sig  = $key->sign($digest);   # returns DER-encoded signature
```

`Crypt::Perl` is used instead of `Crypt::OpenSSL::EC` because its Perl-native API
is consistent and well-maintained. The signature is DER-encoded ASN.1, matching
all other language implementations.

### RSA-OAEP (Crypt::OpenSSL::RSA)

```perl
$rsa->use_pkcs1_oaep_padding();
$rsa->use_sha256_hash();          # SHA-256 for both digest and MGF1
my $ct = $rsa->encrypt($plaintext);
```

## Troubleshooting

**`Can't locate AnyEvent/WebSocket/Client.pm`**
Run `cpanm AnyEvent::WebSocket::Client`.

**`Can't locate Crypt/Perl.pm`**
Run `cpanm Crypt::Perl`.

**TLS/SSL errors connecting**
Try `ssl_no_verify => 1` in `AnyEvent::WebSocket::Client->new(...)` for testing
only. In production, ensure your system CA bundle is up to date.

**`JSON::PP` encode/decode errors**
Make sure the input is a Perl reference (`{}` or `[]`), not a plain string,
when calling `encode_json`.
