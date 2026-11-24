// mesgd-sdk Swift Ping/Pong Sample
// ==================================
// Demonstrates the mesgd-sdk lifecycle on Apple platforms (macOS 13+):
//   1. Initialise local PKI keys (CryptoKit P-256 + Security RSA)
//   2. Register our public keys with the mesgd echo server
//   3. Open a TLS WebSocket connection (URLSessionWebSocketTask)
//   4. Send 3 signed+encrypted "ping" messages
//   5. Receive and verify the echoed "pong" response each time
//
// Note: RSA operations use the Security framework (Apple-only).
//       Linux support requires an OpenSSL C interop module (see plan.md).
//
// Build: swift build
// Run:   swift run   (or .build/debug/PKISample)

import Foundation
import CryptoKit
import Security

// ---------------------------------------------------------------------------
// Configuration (override via environment variables)
// ---------------------------------------------------------------------------
let mesgdURL   = ProcessInfo.processInfo.environment["MESGD_URL"]     ?? "wss://echo.mesgd.org/ws"
let pubJwkPath = ProcessInfo.processInfo.environment["MESGD_PUB_JWK"] ?? "mesgd_pub.json"
let rounds     = Int(ProcessInfo.processInfo.environment["MESGD_ROUNDS"] ?? "3") ?? 3

print("=== mesgd-sdk Swift Ping/Pong Sample ===\n")

// ------------------------------------------------------------------
// Step 1: Initialise PKI
//   setup() replaces the reserved-word init().
//   Loads pki_keys.json or generates P-256 (CryptoKit) + RSA-2048
//   (Security framework) key pairs and saves as JWK JSON.
// ------------------------------------------------------------------
print("Step 1: Initialising PKI …")
do {
    try PKI.setup()
    print("        Keys ready.\n")
} catch {
    fputs("ERROR: PKI setup failed: \(error)\n", stderr)
    exit(1)
}

// ------------------------------------------------------------------
// Step 2: Load mesgd's public encryption key
// ------------------------------------------------------------------
print("Step 2: Loading mesgd public key from '\(pubJwkPath)' …")
guard let pubJwkData = FileManager.default.contents(atPath: pubJwkPath),
      let mesgdPubJwk = try? JSONSerialization.jsonObject(with: pubJwkData) as? [String: Any]
else {
    fputs("ERROR: Cannot read or parse '\(pubJwkPath)'.\n", stderr)
    fputs("  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json\n", stderr)
    exit(1)
}
print("        Loaded.\n")

// ------------------------------------------------------------------
// Step 3: Register with mesgd
// ------------------------------------------------------------------
print("Step 3: Registering with mesgd …")
let registrationCt: String
do {
    registrationCt = try PKI.register(mesgdPubJwk)
    let preview = String(registrationCt.prefix(40))
    print("        Registration payload (first 40 chars): \(preview)…\n")
} catch {
    fputs("ERROR: Registration failed: \(error)\n", stderr)
    exit(1)
}

// ------------------------------------------------------------------
// Step 4: Connect WebSocket (URLSessionWebSocketTask, macOS 13+)
// ------------------------------------------------------------------
print("Step 4: Connecting to \(mesgdURL) …")
guard let wsURL = URL(string: mesgdURL) else {
    fputs("ERROR: Invalid URL: \(mesgdURL)\n", stderr)
    exit(1)
}

let session  = URLSession(configuration: .default)
let wsTask   = session.webSocketTask(with: wsURL)
wsTask.resume()

// Send the registration ciphertext as the opening handshake frame
let sema = DispatchSemaphore(value: 0)
wsTask.send(.string(registrationCt)) { error in
    if let error = error {
        fputs("ERROR: Sending registration payload: \(error)\n", stderr)
        exit(1)
    }
    sema.signal()
}
sema.wait()
print("        Connected.\n")

// ------------------------------------------------------------------
// Step 5: Ping / pong loop (synchronous via DispatchSemaphore)
// ------------------------------------------------------------------
print("Step 5: Starting \(rounds)-round ping/pong …\n")
var allPassed = true

for i in 1...rounds {
    let message = "Hello from mesgd-sdk! Swift ping #\(i)"
    print("  [\(i)/\(rounds)] Sending  : \(message)")

    // Sign + encrypt
    let ciphertext: String
    do {
        let signature = try PKI.sign(message)
        let envelope  = try JSONSerialization.data(
            withJSONObject: ["payload": message, "signature": signature])
        ciphertext = try PKI.encryptWith(mesgdPubJwk,
                                         message: String(data: envelope, encoding: .utf8)!)
    } catch {
        fputs("ERROR: sign/encrypt round \(i): \(error)\n", stderr)
        allPassed = false
        break
    }

    // Send
    let sendSema = DispatchSemaphore(value: 0)
    wsTask.send(.string(ciphertext)) { error in
        if let error = error {
            fputs("ERROR: WebSocket send round \(i): \(error)\n", stderr)
        }
        sendSema.signal()
    }
    sendSema.wait()

    // Receive echo
    let recvSema = DispatchSemaphore(value: 0)
    var receivedPayload: String?

    wsTask.receive { result in
        defer { recvSema.signal() }
        switch result {
        case .failure(let error):
            fputs("ERROR: WebSocket receive round \(i): \(error)\n", stderr)
        case .success(let msg):
            if case .string(let raw) = msg {
                do {
                    // Decrypt envelope
                    let plainEnvelope = try PKI.decrypt(raw)
                    guard let envData = plainEnvelope.data(using: .utf8),
                          let dict = try? JSONSerialization.jsonObject(with: envData) as? [String: String],
                          let payload = dict["payload"],
                          let sig     = dict["signature"] else {
                        fputs("ERROR: Malformed envelope round \(i)\n", stderr)
                        return
                    }
                    // Verify mesgd's signature
                    guard try PKI.checkWithPub(mesgdPubJwk, message: payload, signature: sig) else {
                        fputs("ERROR: Signature verification failed round \(i)\n", stderr)
                        return
                    }
                    receivedPayload = payload
                } catch {
                    fputs("ERROR: Decrypt/verify round \(i): \(error)\n", stderr)
                }
            }
        }
    }
    recvSema.wait()

    guard let response = receivedPayload else {
        allPassed = false
        break
    }

    print("  [\(i)/\(rounds)] Received : \(response)")

    guard response == message else {
        fputs("ERROR: Echo mismatch — expected: \(message), got: \(response)\n", stderr)
        allPassed = false
        break
    }
    print("  [\(i)/\(rounds)] ✓ Echo verified\n")
}

wsTask.cancel(with: .normalClosure, reason: nil)
print("Connection closed.")

if allPassed {
    print("\nAll \(rounds) ping/pong rounds passed.")
} else {
    exit(1)
}
