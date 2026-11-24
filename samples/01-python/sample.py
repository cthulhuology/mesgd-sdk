#!/usr/bin/env python3
"""
mesgd-sdk Python Ping/Pong Sample
==================================
Demonstrates the full mesgd-sdk lifecycle:
  1. Initialise local PKI keys
  2. Register our public keys with the mesgd echo server
  3. Open a WebSocket connection
  4. Send 3 signed+encrypted "ping" messages
  5. Receive and verify the echoed "pong" response each time
"""

import asyncio
import json
import os
import sys

# Make sure the SDK root is on the path so we can import pki and mesgd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pki import PKI           # noqa: E402 – SDK PKI module
from mesgd import MesgdClient  # noqa: E402 – SDK mesgd WebSocket client

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
MESGD_URL        = os.environ.get("MESGD_URL",        "wss://echo.mesgd.org/ws")
MESGD_PUB_JWK    = os.environ.get("MESGD_PUB_JWK",    "mesgd_pub.json")
ROUNDS           = int(os.environ.get("MESGD_ROUNDS",  "3"))


def load_mesgd_pub_jwk(path: str) -> dict:
    """Load the mesgd server's public encryption JWK from a local file."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: mesgd public key file not found: {path}")
        print("  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: {path} is not valid JSON: {exc}")
        sys.exit(1)


async def main() -> None:
    print("=== mesgd-sdk Python Ping/Pong Sample ===\n")

    # ------------------------------------------------------------------
    # Step 1: Initialise PKI
    #   Loads pki_keys.json if it exists; otherwise generates a fresh
    #   ECDSA P-256 signing key pair and RSA-2048 encryption key pair
    #   and saves them to pki_keys.json.
    # ------------------------------------------------------------------
    print("Step 1: Initialising PKI …")
    PKI.init()
    print("        Keys ready.\n")

    # ------------------------------------------------------------------
    # Step 2: Load mesgd's public encryption key
    #   This RSA-2048 JWK is used to encrypt our registration payload
    #   and every outbound message so only the mesgd server can read it.
    # ------------------------------------------------------------------
    print(f"Step 2: Loading mesgd public key from '{MESGD_PUB_JWK}' …")
    mesgd_pub_jwk = load_mesgd_pub_jwk(MESGD_PUB_JWK)
    print("        Loaded.\n")

    # ------------------------------------------------------------------
    # Step 3: Register with mesgd
    #   Assembles a JSON payload of our signing_pub + encrypting_pub JWKs,
    #   signs it with our signing_priv so mesgd can verify ownership,
    #   then encrypts the envelope with mesgd's public key.
    #   Returns a base64 ciphertext to send during the WebSocket handshake.
    # ------------------------------------------------------------------
    print("Step 3: Registering with mesgd …")
    registration_ct = PKI.register(mesgd_pub_jwk)
    print(f"        Registration payload (first 40 chars): {registration_ct[:40]}…\n")

    # ------------------------------------------------------------------
    # Step 4: Connect WebSocket
    # ------------------------------------------------------------------
    print(f"Step 4: Connecting to {MESGD_URL} …")
    client = MesgdClient(mesgd_pub_jwk)
    ws = await client.connect(MESGD_URL, registration_ct)
    print("        Connected.\n")

    # ------------------------------------------------------------------
    # Step 5: Ping / pong loop
    #   Each iteration:
    #     a. Compose a plaintext message
    #     b. client.send() signs with our signing_priv, encrypts with
    #        mesgd's encrypting_pub, sends over WebSocket
    #     c. client.receive() waits for the echo, decrypts with our
    #        encrypting_priv, verifies mesgd's signature
    #     d. Assert the plaintext round-tripped correctly
    # ------------------------------------------------------------------
    print(f"Step 5: Starting {ROUNDS}-round ping/pong …\n")
    try:
        for i in range(1, ROUNDS + 1):
            message = f"Hello from mesgd-sdk! Python ping #{i}"

            print(f"  [{i}/{ROUNDS}] Sending  : {message}")
            await client.send(ws, mesgd_pub_jwk, message)

            response = await client.receive(ws)
            print(f"  [{i}/{ROUNDS}] Received : {response}")

            if response != message:
                raise AssertionError(
                    f"Echo mismatch — expected: {message!r}, got: {response!r}"
                )
            print(f"  [{i}/{ROUNDS}] ✓ Echo verified\n")

    finally:
        # Always close the connection, even on error
        await client.disconnect(ws)
        print("Connection closed.")

    print(f"\nAll {ROUNDS} ping/pong rounds passed.")


if __name__ == "__main__":
    asyncio.run(main())
