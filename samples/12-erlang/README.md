# Erlang mesgd-sdk Ping/Pong Sample

## Overview

This sample demonstrates the mesgd-sdk workflow in Erlang/OTP using idiomatic
patterns: `receive` blocks for synchronous-style WebSocket message handling, atoms
for error tagging, and `io:format` for output. It uses `gun` (an HTTP/WebSocket
client) for connectivity and `jiffy` for JSON (de)serialisation.

## Prerequisites

| Requirement   | Version | Notes                                   |
|---------------|---------|-----------------------------------------|
| Erlang/OTP    | 26+     |                                         |
| rebar3        | 3.22+   | Build tool                              |
| gun           | 2.1+    | HTTP/WebSocket client (via rebar3)      |
| jiffy         | 1.1+    | JSON library (via rebar3)               |
| certifi       | 2.12+   | CA bundle for TLS (via rebar3)          |

Install Erlang/OTP: https://www.erlang.org/downloads

Install rebar3:
```sh
curl -fsSL https://s3.amazonaws.com/rebar3/rebar3 -o rebar3
chmod +x rebar3
sudo mv rebar3 /usr/local/bin/
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
rebar3 compile

# Start an Erlang shell with all apps loaded
rebar3 shell

# In the Erlang shell:
1> sample:main().
```

Alternatively, to run as an escript:
```sh
rebar3 escriptize
./_build/default/bin/sample
```

## Expected Output

```
=== mesgd-sdk Erlang Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! Erlang ping #1
  [1/3] Received : Hello from mesgd-sdk! Erlang ping #1
  [1/3] Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Erlang ping #2
  [2/3] Received : Hello from mesgd-sdk! Erlang ping #2
  [2/3] Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Erlang ping #3
  [3/3] Received : Hello from mesgd-sdk! Erlang ping #3
  [3/3] Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### PKI (`pki.erl`)

`pki:init/0` uses `crypto:generate_key(ecdh, prime256v1)` for ECDSA P-256 and
`public_key:generate_key({rsa, 2048, 65537})` for RSA-2048. Key components are
extracted and encoded as base64url binaries using `base64url:encode/1`. The four
JWK objects are written to `pki_keys.json` using the `jsx` or `jiffy` JSON library.

### Message exchange pattern

Erlang's `receive` block is the natural mechanism for synchronous-style
WebSocket communication:

```erlang
gun:ws_send(ConnPid, StreamRef, {text, Ciphertext}),
receive
    {gun_ws, ConnPid, StreamRef, {text, Frame}} ->
        %% process echo
after 10000 ->
    error(timeout)
end
```

The `gun` library sends `gun_ws` messages to the calling process when frames arrive.

### Error handling

Erlang's "let it crash" philosophy means errors are raised with `error/1` and
propagate up to the shell or supervisor. In a production OTP application, the
`sample` module would be supervised and errors would trigger restarts.

### jiffy for JSON

`jiffy:decode(Bin, [return_maps])` returns a `#{binary() => _}` map.
`jiffy:encode(Map)` serialises a map to a JSON binary.

## Troubleshooting

**`{error, enoent}` when loading mesgd_pub.json**
Run the sample from the directory containing `mesgd_pub.json`, or set
`MESGD_PUB_JWK` to the absolute path.

**`gun` not found after `rebar3 compile`**
Run `rebar3 get-deps` first, then retry `rebar3 compile`.

**`ws_upgrade_timeout` error**
The server did not acknowledge the WebSocket upgrade in 10 seconds. Check
`MESGD_URL` and network connectivity.

**`{error, {tls_alert, ...}}`**
TLS certificate verification failed. Ensure `certifi` is compiled and its CA
bundle is up to date: `rebar3 upgrade certifi`.
