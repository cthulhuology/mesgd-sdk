#!/usr/bin/env lua
--[[
  mesgd-sdk Lua Ping/Pong Sample
  ================================
  Demonstrates the full mesgd-sdk lifecycle in Lua 5.4:
    1. Initialise local PKI keys (lua-openssl)
    2. Register our public keys with the mesgd echo server
    3. Open a TLS WebSocket connection (lua-websockets)
    4. Send 3 signed+encrypted "ping" messages
    5. Receive and verify the echoed "pong" response each time

  Install deps:
    luarocks install luaossl
    luarocks install lua-websockets
    luarocks install lunajson

  Run: lua sample.lua
--]]

-- Add SDK root to package path
package.path = '../../?.lua;' .. package.path

local pki    = require('pki')
local mesgd  = require('mesgd')
local json   = require('lunajson')

-- ---------------------------------------------------------------------------
-- Configuration (override via environment variables)
-- ---------------------------------------------------------------------------
local MESGD_URL     = os.getenv('MESGD_URL')     or 'wss://echo.mesgd.org/ws'
local MESGD_PUB_JWK = os.getenv('MESGD_PUB_JWK') or 'mesgd_pub.json'
local ROUNDS        = tonumber(os.getenv('MESGD_ROUNDS') or '3')

-- Helper: read a file to string
local function read_file(path)
    local fh, err = io.open(path, 'r')
    if not fh then return nil, err end
    local content = fh:read('*all')
    fh:close()
    return content
end

-- Helper: abort with error message
local function abort(msg)
    io.stderr:write('ERROR: ' .. msg .. '\n')
    os.exit(1)
end

print('=== mesgd-sdk Lua Ping/Pong Sample ===\n')

-- ------------------------------------------------------------------
-- Step 1: Initialise PKI
--   Calls pki.init() which loads pki_keys.json or generates a fresh
--   ECDSA P-256 signing key pair and RSA-2048 encryption key pair
--   using lua-openssl, serialises as JWK, and writes pki_keys.json.
-- ------------------------------------------------------------------
print('Step 1: Initialising PKI ...')
local ok, err = pki.init()
if not ok then abort('pki.init() failed: ' .. tostring(err)) end
print('        Keys ready.\n')

-- ------------------------------------------------------------------
-- Step 2: Load mesgd's public encryption key
-- ------------------------------------------------------------------
print(string.format("Step 2: Loading mesgd public key from '%s' ...", MESGD_PUB_JWK))
local jwk_json, read_err = read_file(MESGD_PUB_JWK)
if not jwk_json then
    abort(string.format(
        "Cannot read '%s': %s\n  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json",
        MESGD_PUB_JWK, tostring(read_err)))
end
local mesgd_pub_jwk = json.decode(jwk_json)
print('        Loaded.\n')

-- ------------------------------------------------------------------
-- Step 3: Register with mesgd
-- ------------------------------------------------------------------
print('Step 3: Registering with mesgd ...')
local registration_ct, reg_err = pki.register(mesgd_pub_jwk)
if not registration_ct then abort('pki.register() failed: ' .. tostring(reg_err)) end
print(string.format('        Registration payload (first 40 chars): %s...', registration_ct:sub(1, 40)))
print('')

-- ------------------------------------------------------------------
-- Step 4: Connect WebSocket
-- ------------------------------------------------------------------
print(string.format('Step 4: Connecting to %s ...', MESGD_URL))
local client, conn_err = mesgd.connect(MESGD_URL, registration_ct, mesgd_pub_jwk)
if not client then abort('mesgd.connect() failed: ' .. tostring(conn_err)) end
print('        Connected.\n')

-- ------------------------------------------------------------------
-- Step 5: Ping / pong loop
-- ------------------------------------------------------------------
print(string.format('Step 5: Starting %d-round ping/pong ...\n', ROUNDS))
local all_passed = true

for i = 1, ROUNDS do
    local message = string.format('Hello from mesgd-sdk! Lua ping #%d', i)

    print(string.format('  [%d/%d] Sending  : %s', i, ROUNDS, message))

    -- Sign + encrypt
    local sig,  sig_err  = pki.sign(message)
    if not sig then abort(string.format('sign() failed round %d: %s', i, tostring(sig_err))) end

    local envelope   = json.encode({ payload = message, signature = sig })
    local ciphertext, enc_err = pki.encrypt_with(mesgd_pub_jwk, envelope)
    if not ciphertext then abort(string.format('encrypt_with() failed round %d: %s', i, tostring(enc_err))) end

    -- Send over WebSocket
    local send_ok, send_err = client.send(ciphertext)
    if not send_ok then abort(string.format('send() failed round %d: %s', i, tostring(send_err))) end

    -- Receive echoed frame
    local raw_response, recv_err = client.receive()
    if not raw_response then abort(string.format('receive() failed round %d: %s', i, tostring(recv_err))) end

    -- Decrypt + verify
    local plain_envelope, dec_err = pki.decrypt(raw_response)
    if not plain_envelope then abort(string.format('decrypt() failed round %d: %s', i, tostring(dec_err))) end

    local data      = json.decode(plain_envelope)
    local response  = data.payload   or ''
    local recv_sig  = data.signature or ''

    local verified, verify_err = pki.check_with_pub(mesgd_pub_jwk, response, recv_sig)
    if not verified then abort(string.format('check_with_pub() failed round %d: %s', i, tostring(verify_err))) end

    print(string.format('  [%d/%d] Received : %s', i, ROUNDS, response))

    if response ~= message then
        abort(string.format("Echo mismatch round %d: expected '%s', got '%s'", i, message, response))
    end
    print(string.format('  [%d/%d] Echo verified\n', i, ROUNDS))
end

client.disconnect()
print('Connection closed.')
print(string.format('\nAll %d ping/pong rounds passed.', ROUNDS))
