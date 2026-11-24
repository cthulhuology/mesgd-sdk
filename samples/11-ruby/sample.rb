#!/usr/bin/env ruby
# frozen_string_literal: true

# mesgd-sdk Ruby Ping/Pong Sample
# =================================
# Demonstrates the full mesgd-sdk lifecycle in Ruby 3.x:
#   1. Initialise local PKI keys (OpenSSL gem)
#   2. Register our public keys with the mesgd echo server
#   3. Open a TLS WebSocket connection (websocket-client-simple)
#   4. Send 3 signed+encrypted "ping" messages
#   5. Receive and verify the echoed "pong" response each time
#
# Run: bundle install && ruby sample.rb

require 'json'
require 'thread'

$LOAD_PATH.unshift File.join(__dir__, '..', '..')
require_relative '../../pki'
require_relative '../../mesgd'

begin
  require 'websocket-client-simple'
rescue LoadError
  abort "Run 'bundle install' first to install websocket-client-simple"
end

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
MESGD_URL     = ENV.fetch('MESGD_URL',     'wss://echo.mesgd.org/ws')
MESGD_PUB_JWK = ENV.fetch('MESGD_PUB_JWK', 'mesgd_pub.json')
ROUNDS        = Integer(ENV.fetch('MESGD_ROUNDS', '3'))

def load_mesgd_pub_jwk(path)
  unless File.exist?(path)
    warn "ERROR: mesgd public key file not found: #{path}"
    warn '  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json'
    exit 1
  end
  JSON.parse(File.read(path))
rescue JSON::ParserError => e
  abort "ERROR: #{path} is not valid JSON: #{e.message}"
end

puts "=== mesgd-sdk Ruby Ping/Pong Sample ===\n\n"

# ------------------------------------------------------------------
# Step 1: Initialise PKI
# ------------------------------------------------------------------
puts 'Step 1: Initialising PKI …'
PKI.init
puts "        Keys ready.\n\n"

# ------------------------------------------------------------------
# Step 2: Load mesgd's public encryption key
# ------------------------------------------------------------------
puts "Step 2: Loading mesgd public key from '#{MESGD_PUB_JWK}' …"
mesgd_pub_jwk = load_mesgd_pub_jwk(MESGD_PUB_JWK)
puts "        Loaded.\n\n"

# ------------------------------------------------------------------
# Step 3: Register with mesgd
# ------------------------------------------------------------------
puts 'Step 3: Registering with mesgd …'
registration_ct = PKI.register(mesgd_pub_jwk)
puts "        Registration payload (first 40 chars): #{registration_ct[0, 40]}…\n\n"

# ------------------------------------------------------------------
# Steps 4 & 5: Connect WebSocket and run ping/pong
#   websocket-client-simple uses callbacks on a background thread.
#   We use a Queue to bridge the callback thread with the main thread,
#   giving us sequential send → receive → assert behaviour.
# ------------------------------------------------------------------
puts "Step 4: Connecting to #{MESGD_URL} …"

# Queue used to hand received messages back to the main thread
receive_queue = Queue.new
error_queue   = Queue.new

ws = WebSocket::Client::Simple.connect(MESGD_URL)

ws.on :open do
  puts "        Connected.\n\n"
  receive_queue.push(:connected)
end

ws.on :message do |msg|
  receive_queue.push(msg.data)
end

ws.on :error do |e|
  error_queue.push(e)
  receive_queue.push(:error)
end

ws.on :close do |_e|
  receive_queue.push(:closed)
end

# Wait for the connection to open
event = receive_queue.pop
abort 'ERROR: WebSocket connection failed' if event == :error

# Send the registration handshake
ws.send(registration_ct)

puts "Step 5: Starting #{ROUNDS}-round ping/pong …\n\n"

ROUNDS.times do |idx|
  i       = idx + 1
  message = "Hello from mesgd-sdk! Ruby ping ##{i}"

  puts "  [#{i}/#{ROUNDS}] Sending  : #{message}"

  # Sign + encrypt
  signature  = PKI.sign(message)
  envelope   = JSON.generate({ payload: message, signature: signature })
  ciphertext = PKI.encrypt_with(mesgd_pub_jwk, envelope)
  ws.send(ciphertext)

  # Wait for the echo (block main thread until the callback fires)
  raw_response = receive_queue.pop
  abort 'ERROR: WebSocket error during receive' if raw_response == :error

  # Decrypt + verify
  plain = PKI.decrypt(raw_response)
  data  = JSON.parse(plain)
  response  = data['payload']
  signature = data['signature']

  unless PKI.check_with_pub(mesgd_pub_jwk, response, signature)
    abort "ERROR: Signature verification failed on round #{i}"
  end

  puts "  [#{i}/#{ROUNDS}] Received : #{response}"
  abort "ERROR: Echo mismatch on round #{i}" unless response == message
  puts "  [#{i}/#{ROUNDS}] ✓ Echo verified\n\n"
end

ws.close
puts 'Connection closed.'
puts "\nAll #{ROUNDS} ping/pong rounds passed."
