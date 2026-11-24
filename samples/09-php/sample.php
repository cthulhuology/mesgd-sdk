<?php
declare(strict_types=1);

/**
 * mesgd-sdk PHP Ping/Pong Sample
 * ================================
 * Demonstrates the full mesgd-sdk lifecycle in PHP 8.1+:
 *   1. Initialise local PKI keys (OpenSSL extension)
 *   2. Register our public keys with the mesgd echo server
 *   3. Open a WebSocket connection (Ratchet/Pawl)
 *   4. Send 3 signed+encrypted "ping" messages
 *   5. Receive and verify the echoed "pong" response each time
 *
 * Run: composer install && php sample.php
 */

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/../../pki.php';
require_once __DIR__ . '/../../mesgd.php';

use Ratchet\Client\WebSocket;
use React\EventLoop\Loop;

// ---------------------------------------------------------------------------
// Configuration (override via environment variables)
// ---------------------------------------------------------------------------
$mesgdUrl   = getenv('MESGD_URL')     ?: 'wss://echo.mesgd.org/ws';
$pubJwkPath = getenv('MESGD_PUB_JWK') ?: 'mesgd_pub.json';
$rounds     = (int) (getenv('MESGD_ROUNDS') ?: '3');

echo "=== mesgd-sdk PHP Ping/Pong Sample ===\n\n";

// ------------------------------------------------------------------
// Step 1: Initialise PKI
//   Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 key
//   pairs (via openssl_pkey_new) and saves as JWK JSON.
//   Minimum PHP 8.0 required for SHA-256 MGF1 OAEP support.
// ------------------------------------------------------------------
echo "Step 1: Initialising PKI ...\n";
PKI::init();
echo "        Keys ready.\n\n";

// ------------------------------------------------------------------
// Step 2: Load mesgd's public encryption key
// ------------------------------------------------------------------
echo "Step 2: Loading mesgd public key from '{$pubJwkPath}' ...\n";
if (!file_exists($pubJwkPath)) {
    fwrite(STDERR, "ERROR: mesgd public key file not found: {$pubJwkPath}\n");
    fwrite(STDERR, "  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json\n");
    exit(1);
}
$mesgdPubJwk = json_decode(file_get_contents($pubJwkPath), true);
if ($mesgdPubJwk === null) {
    fwrite(STDERR, "ERROR: {$pubJwkPath} is not valid JSON.\n");
    exit(1);
}
echo "        Loaded.\n\n";

// ------------------------------------------------------------------
// Step 3: Register with mesgd
// ------------------------------------------------------------------
echo "Step 3: Registering with mesgd ...\n";
$registrationCt = PKI::register($mesgdPubJwk);
echo "        Registration payload (first 40 chars): " . substr($registrationCt, 0, 40) . "...\n\n";

// ------------------------------------------------------------------
// Steps 4 & 5: Connect WebSocket and run ping/pong loop
//   PHP's event-loop (ReactPHP) is used; Ratchet/Pawl provides the
//   async WebSocket client.  We use a counter and a completion flag
//   to know when to stop the event loop.
// ------------------------------------------------------------------
echo "Step 4: Connecting to {$mesgdUrl} ...\n";

$loop         = Loop::get();
$roundsDone   = 0;
$hasError     = false;

\Ratchet\Client\connect($mesgdUrl, [], [], $loop)
    ->then(
        function (WebSocket $ws) use ($mesgdUrl, $mesgdPubJwk, $registrationCt, $rounds, $loop, &$roundsDone, &$hasError) {
            echo "        Connected.\n\n";
            echo "Step 5: Starting {$rounds}-round ping/pong ...\n\n";

            // Send registration handshake
            $ws->send($registrationCt);

            // Queue of messages waiting to be sent; we send each one after
            // receiving the previous echo to keep the exchange sequential.
            $pending = [];
            for ($i = 1; $i <= $rounds; $i++) {
                $pending[] = "Hello from mesgd-sdk! PHP ping #{$i}";
            }

            // Send the first message immediately
            $sendNext = function () use (&$sendNext, &$pending, $ws, $mesgdPubJwk, $rounds, &$roundsDone, $loop) {
                if (empty($pending)) {
                    $ws->close();
                    return;
                }
                $message   = array_shift($pending);
                $roundsDone++;
                $i         = $roundsDone;

                // Sign + encrypt
                $signature = PKI::sign($message);
                $envelope  = json_encode(['payload' => $message, 'signature' => $signature]);
                $ciphertext = PKI::encryptWith($mesgdPubJwk, $envelope);

                echo "  [{$i}/{$rounds}] Sending  : {$message}\n";
                $ws->send($ciphertext);

                // Store expected response for the on-message handler
                $ws->expectedMessage = $message;
            };

            // Kick off the first send
            $sendNext();

            // Handle incoming messages (echoed responses)
            $ws->on('message', function ($raw) use ($ws, $mesgdPubJwk, $rounds, $loop, $sendNext, &$roundsDone, &$hasError) {
                try {
                    // Decrypt the incoming envelope
                    $envelope = PKI::decrypt((string)$raw);
                    $data     = json_decode($envelope, true);
                    $payload  = $data['payload']  ?? '';
                    $sig      = $data['signature'] ?? '';

                    // Verify mesgd's signature on the echoed payload
                    if (!PKI::checkWithPub($mesgdPubJwk, $payload, $sig)) {
                        throw new \RuntimeException('Signature verification failed on received message');
                    }

                    $i = $roundsDone;
                    echo "  [{$i}/{$rounds}] Received : {$payload}\n";

                    if ($payload !== $ws->expectedMessage) {
                        throw new \RuntimeException("Echo mismatch: expected '{$ws->expectedMessage}', got '{$payload}'");
                    }
                    echo "  [{$i}/{$rounds}] ✓ Echo verified\n\n";

                    // Send the next message (or close if done)
                    $sendNext();

                } catch (\Throwable $e) {
                    fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
                    $hasError = true;
                    $ws->close();
                    $loop->stop();
                }
            });

            $ws->on('close', function ($code, $reason) use ($loop) {
                echo "Connection closed.\n";
                $loop->stop();
            });
        },
        function (\Throwable $e) use ($loop, &$hasError) {
            fwrite(STDERR, "ERROR connecting: " . $e->getMessage() . "\n");
            $hasError = true;
            $loop->stop();
        }
    );

$loop->run();

if ($hasError) {
    exit(1);
}
echo "\nAll {$rounds} ping/pong rounds passed.\n";
