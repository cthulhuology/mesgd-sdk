# Lua mesgd-sdk Ping/Pong Sample

## Overview

This sample uses Lua 5.4 with the `luaossl` binding to OpenSSL for ECDSA P-256
signing and RSA-2048-OAEP encryption, `lua-websockets` for WebSocket transport,
and `lunajson` for JSON serialisation. Error handling follows Lua convention:
functions return `nil, error_message` on failure.

## Prerequisites

| Requirement     | Version | Notes                                   |
|-----------------|---------|-----------------------------------------|
| Lua             | 5.4+    | Or LuaJIT 2.1                           |
| LuaRocks        | 3.9+    | Package manager                         |
| luaossl         | 20220711+ | OpenSSL bindings (ECDSA + RSA)       |
| lua-websockets  | 1.0+    | WebSocket client                        |
| lunajson        | 1.2.3+  | Pure Lua JSON library                   |

### Install dependencies

**Ubuntu / Debian:**
```sh
sudo apt install lua5.4 luarocks libssl-dev
luarocks install luaossl
luarocks install lua-websockets
luarocks install lunajson
```

**macOS (Homebrew):**
```sh
brew install lua luarocks openssl
luarocks --lua-dir=$(brew --prefix lua) install luaossl \
  OPENSSL_DIR=$(brew --prefix openssl)
luarocks install lua-websockets
luarocks install lunajson
```

**LuaJIT (alternative):**
```sh
luarocks --lua-version=5.1 install luaossl
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
# No build step required — Lua is interpreted

# Run:
lua sample.lua

# Custom settings:
MESGD_URL=ws://localhost:8080/ws lua sample.lua
```

## Expected Output

```
=== mesgd-sdk Lua Ping/Pong Sample ===

Step 1: Initialising PKI ...
        Keys ready.

Step 2: Loading mesgd public key from 'mesgd_pub.json' ...
        Loaded.

Step 3: Registering with mesgd ...
        Registration payload (first 40 chars): eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6...

Step 4: Connecting to wss://echo.mesgd.org/ws ...
        Connected.

Step 5: Starting 3-round ping/pong ...

  [1/3] Sending  : Hello from mesgd-sdk! Lua ping #1
  [1/3] Received : Hello from mesgd-sdk! Lua ping #1
  [1/3] Echo verified

  [2/3] Sending  : Hello from mesgd-sdk! Lua ping #2
  [2/3] Received : Hello from mesgd-sdk! Lua ping #2
  [2/3] Echo verified

  [3/3] Sending  : Hello from mesgd-sdk! Lua ping #3
  [3/3] Received : Hello from mesgd-sdk! Lua ping #3
  [3/3] Echo verified

Connection closed.

All 3 ping/pong rounds passed.
```

## How It Works

### luaossl API

The PKI module corrects the API from the original `pki.lua` (which had wrong
function names). The actual `luaossl` API:

```lua
local pkey = require('openssl.pkey')

-- Generate ECDSA P-256
local ec_key = pkey.new({ type = 'EC', curve = 'prime256v1' })

-- Generate RSA-2048
local rsa_key = pkey.new({ type = 'RSA', bits = 2048 })

-- Sign
local sig = ec_key:sign(digest_bytes)

-- Verify
local ok = ec_pub_key:verify(digest_bytes, sig)
```

### base64url encoding

JWK integer fields require base64url encoding (`-_` not `+/`, no `=` padding):

```lua
local function base64url_encode(s)
    return (require('mime').b64(s)):gsub('%+', '-'):gsub('/', '_'):gsub('=', '')
end
```

### Synchronous WebSocket with lua-websockets

`lua-websockets` provides a synchronous client (`websocket.client.sync`):

```lua
local ws = require('websocket').client.sync({ssl = true})
ws:connect(url, 'mesgd')
ws:send(message)
local data, opcode = ws:receive()
ws:close()
```

## Troubleshooting

**`module 'luaossl' not found`**
Run `luarocks install luaossl`. If OpenSSL headers are not in the default path:
```sh
luarocks install luaossl OPENSSL_DIR=/usr/local/opt/openssl
```

**`module 'lunajson' not found`**
Run `luarocks install lunajson`.

**`module 'websocket' not found`**
Run `luarocks install lua-websockets`.

**`package.path` not finding `pki.lua`**
The sample prepends `../../?.lua` to `package.path`. Run the script from
`samples/15-lua/`, or set `LUA_PATH` manually:
```sh
LUA_PATH="../../?.lua;;" lua sample.lua
```
