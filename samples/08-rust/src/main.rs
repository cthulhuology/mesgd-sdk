//! mesgd-sdk Rust Ping/Pong Sample
//! =================================
//! Demonstrates the full mesgd-sdk lifecycle in Rust:
//!   1. Initialise local PKI keys (openssl crate)
//!   2. Register our public keys with the mesgd echo server
//!   3. Open a TLS WebSocket connection (tokio-tungstenite)
//!   4. Send 3 signed+encrypted "ping" messages
//!   5. Receive and verify the echoed "pong" response each time
//!
//! Run: cargo run

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{env, fs};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// SDK modules — in a workspace these would be `use mesgd_sdk::{pki, mesgd};`
// Here we reference them as local modules relative to the crate root.
mod pki;
mod mesgd;

const ROUNDS: usize = 3;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== mesgd-sdk Rust Ping/Pong Sample ===\n");

    // Configuration from environment variables
    let mesgd_url    = env::var("MESGD_URL").unwrap_or_else(|_| "wss://echo.mesgd.org/ws".into());
    let pub_jwk_path = env::var("MESGD_PUB_JWK").unwrap_or_else(|_| "mesgd_pub.json".into());

    // ------------------------------------------------------------------
    // Step 1: Initialise PKI
    //   Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 key
    //   pairs, serialises them as JWK, and writes pki_keys.json.
    // ------------------------------------------------------------------
    println!("Step 1: Initialising PKI …");
    let pki = pki::PKI::init().context("PKI initialisation failed")?;
    println!("        Keys ready.\n");

    // ------------------------------------------------------------------
    // Step 2: Load mesgd's public encryption key
    // ------------------------------------------------------------------
    println!("Step 2: Loading mesgd public key from '{pub_jwk_path}' …");
    let mesgd_pub_jwk = load_mesgd_pub_jwk(&pub_jwk_path)?;
    println!("        Loaded.\n");

    // ------------------------------------------------------------------
    // Step 3: Register with mesgd
    // ------------------------------------------------------------------
    println!("Step 3: Registering with mesgd …");
    let registration_ct = pki.register(&mesgd_pub_jwk)
        .context("Registration failed")?;
    println!(
        "        Registration payload (first 40 chars): {}…\n",
        &registration_ct[..registration_ct.len().min(40)]
    );

    // ------------------------------------------------------------------
    // Step 4: Connect WebSocket (tokio-tungstenite with native-tls)
    // ------------------------------------------------------------------
    println!("Step 4: Connecting to {mesgd_url} …");
    let (mut ws_stream, _) = connect_async(&mesgd_url)
        .await
        .context("WebSocket connect failed")?;

    // Send registration ciphertext as the opening handshake frame
    ws_stream
        .send(Message::Text(registration_ct))
        .await
        .context("Sending registration payload failed")?;
    println!("        Connected.\n");

    let client = mesgd::Client::new(mesgd_pub_jwk.clone());

    // ------------------------------------------------------------------
    // Step 5: Ping / pong loop
    // ------------------------------------------------------------------
    println!("Step 5: Starting {ROUNDS}-round ping/pong …\n");
    for i in 1..=ROUNDS {
        let message = format!("Hello from mesgd-sdk! Rust ping #{i}");

        println!("  [{i}/{ROUNDS}] Sending  : {message}");

        // Sign the message with our signing_priv
        let signature = pki.sign(&message).context("Sign failed")?;

        // Build envelope and encrypt with mesgd's encrypting_pub
        let envelope = json!({ "payload": message, "signature": signature }).to_string();
        let ciphertext = pki
            .encrypt_with(&mesgd_pub_jwk, &envelope)
            .context("Encrypt failed")?;

        ws_stream
            .send(Message::Text(ciphertext))
            .await
            .context("WebSocket send failed")?;

        // Receive, decrypt, and verify
        let raw_frame = ws_stream
            .next()
            .await
            .context("WebSocket stream ended unexpectedly")?
            .context("WebSocket receive error")?;

        let raw_text = match raw_frame {
            Message::Text(t) => t,
            other => anyhow::bail!("Unexpected WebSocket frame type: {:?}", other),
        };

        let (response, _sig) = client
            .decrypt_and_verify(&pki, &raw_text)
            .context("Decrypt/verify failed")?;

        println!("  [{i}/{ROUNDS}] Received : {response}");

        if response != message {
            anyhow::bail!("Echo mismatch — expected: {message:?}, got: {response:?}");
        }
        println!("  [{i}/{ROUNDS}] ✓ Echo verified\n");
    }

    // Graceful close
    ws_stream
        .send(Message::Close(None))
        .await
        .ok(); // ignore errors during close
    println!("Connection closed.");

    println!("\nAll {ROUNDS} ping/pong rounds passed.");
    Ok(())
}

/// Load mesgd's RSA-2048 public encryption JWK from a JSON file.
fn load_mesgd_pub_jwk(path: &str) -> Result<Value> {
    let content = fs::read_to_string(path).with_context(|| {
        format!(
            "Cannot read '{path}'.\n  \
             Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json"
        )
    })?;
    serde_json::from_str(&content).with_context(|| format!("Parsing '{path}' as JSON failed"))
}
