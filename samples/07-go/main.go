// mesgd-sdk Go Ping/Pong Sample
// ================================
// Demonstrates the full mesgd-sdk lifecycle in Go:
//   1. Initialise local PKI keys
//   2. Register our public keys with the mesgd echo server
//   3. Open a TLS WebSocket connection (gorilla/websocket)
//   4. Send 3 signed+encrypted "ping" messages
//   5. Receive and verify the echoed "pong" response each time
//
// Run: go run .
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gorilla/websocket"

	// SDK packages from the parent module.
	// In a real project these would be: github.com/mesgd/sdk/pki
	//                                   github.com/mesgd/sdk/mesgd
	pki   "mesgd-sdk/pki"
	mesgd "mesgd-sdk/mesgd"
)

const rounds = 3

func main() {
	fmt.Println("=== mesgd-sdk Go Ping/Pong Sample ===\n")

	// Configuration from environment variables with defaults
	mesgdURL   := getenv("MESGD_URL",     "wss://echo.mesgd.org/ws")
	pubJwkPath := getenv("MESGD_PUB_JWK", "mesgd_pub.json")

	// ------------------------------------------------------------------
	// Step 1: Initialise PKI
	//   Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 keys.
	// ------------------------------------------------------------------
	fmt.Println("Step 1: Initialising PKI …")
	if err := pki.Init(); err != nil {
		log.Fatalf("pki.Init: %v", err)
	}
	fmt.Println("        Keys ready.\n")

	// ------------------------------------------------------------------
	// Step 2: Load mesgd's public encryption key
	// ------------------------------------------------------------------
	fmt.Printf("Step 2: Loading mesgd public key from '%s' …\n", pubJwkPath)
	mesgdPubJwk, err := loadMesgdPubJwk(pubJwkPath)
	if err != nil {
		log.Fatalf("loadMesgdPubJwk: %v", err)
	}
	fmt.Println("        Loaded.\n")

	// ------------------------------------------------------------------
	// Step 3: Register with mesgd
	// ------------------------------------------------------------------
	fmt.Println("Step 3: Registering with mesgd …")
	registrationCt, err := pki.Register(mesgdPubJwk)
	if err != nil {
		log.Fatalf("pki.Register: %v", err)
	}
	preview := registrationCt
	if len(preview) > 40 {
		preview = preview[:40]
	}
	fmt.Printf("        Registration payload (first 40 chars): %s…\n\n", preview)

	// ------------------------------------------------------------------
	// Step 4: Connect WebSocket
	// ------------------------------------------------------------------
	fmt.Printf("Step 4: Connecting to %s …\n", mesgdURL)
	client := mesgd.NewClient(mesgdPubJwk)
	conn, err := client.Connect(mesgdURL, registrationCt)
	if err != nil {
		log.Fatalf("mesgd.Connect: %v", err)
	}
	defer func() {
		client.Disconnect(conn)
		fmt.Println("Connection closed.")
	}()
	fmt.Println("        Connected.\n")

	// ------------------------------------------------------------------
	// Step 5: Ping / pong loop
	// ------------------------------------------------------------------
	fmt.Printf("Step 5: Starting %d-round ping/pong …\n\n", rounds)
	for i := 1; i <= rounds; i++ {
		message := fmt.Sprintf("Hello from mesgd-sdk! Go ping #%d", i)

		fmt.Printf("  [%d/%d] Sending  : %s\n", i, rounds, message)
		if err := client.Send(conn, mesgdPubJwk, message); err != nil {
			log.Fatalf("  mesgd.Send round %d: %v", i, err)
		}

		response, err := client.Receive(conn)
		if err != nil {
			log.Fatalf("  mesgd.Receive round %d: %v", i, err)
		}
		fmt.Printf("  [%d/%d] Received : %s\n", i, rounds, response)

		if response != message {
			log.Fatalf("  Echo mismatch on round %d: expected %q, got %q", i, message, response)
		}
		fmt.Printf("  [%d/%d] ✓ Echo verified\n\n", i, rounds)
	}

	fmt.Printf("All %d ping/pong rounds passed.\n", rounds)
}

// loadMesgdPubJwk reads mesgd's RSA-2048 public encryption JWK from a JSON file.
func loadMesgdPubJwk(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"file not found: %s\n  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json",
				path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var jwk map[string]interface{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return jwk, nil
}

// getenv returns the value of the environment variable name, or defaultVal.
func getenv(name, defaultVal string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return defaultVal
}

// Ensure gorilla/websocket is referenced (avoids unused-import error)
var _ = websocket.DefaultDialer
