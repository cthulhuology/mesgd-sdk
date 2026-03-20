package pki_test

import (
	"encoding/json"
	"os"
	"testing"

	pki "mesgd-sdk"
)

const JWKS_FILE = "../fixtures/jwks.json"
const GEN_FILE = "../fixtures/test_go.json"
const SIG_OUT = "../fixtures/sig_go.json"

var CROSS_LANGS = []string{"erlang", "python", "javascript", "ruby", "rust", "c"}

var globalPKI *pki.PKI

func TestMain(m *testing.M) {
	var err error
	globalPKI, err = pki.Init(JWKS_FILE)
	if err != nil {
		panic("TestMain: failed to init PKI from " + JWKS_FILE + ": " + err.Error())
	}
	os.Exit(m.Run())
}

func TestSignVerifyRoundtrip(t *testing.T) {
	sig, err := globalPKI.Sign("Hello World")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	ok, err := globalPKI.Verify("Hello World", sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for valid signature")
	}
	ok2, err := globalPKI.Verify("Wrong message", sig)
	if err != nil {
		t.Fatalf("Verify (wrong msg) failed: %v", err)
	}
	if ok2 {
		t.Fatal("Verify returned true for wrong message")
	}
}

func TestSignatureIsJSON(t *testing.T) {
	sig, err := globalPKI.Sign("Hello World")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(sig), &m); err != nil {
		t.Fatalf("Signature is not valid JSON: %v", err)
	}
	if m["r"] == "" {
		t.Fatal("Signature JSON missing 'r' field")
	}
	if m["s"] == "" {
		t.Fatal("Signature JSON missing 's' field")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	plaintext := "Secret message"
	ciphertext, err := globalPKI.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	recovered, err := globalPKI.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if recovered != plaintext {
		t.Fatalf("Decrypt returned %q, want %q", recovered, plaintext)
	}
}

func TestGenerateCreatesJSONFile(t *testing.T) {
	os.Remove(GEN_FILE)
	p, err := pki.Generate(GEN_FILE)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if p == nil {
		t.Fatal("Generate returned nil PKI")
	}
	data, err := os.ReadFile(GEN_FILE)
	if err != nil {
		t.Fatalf("Generated file not found: %v", err)
	}
	var jwks []map[string]interface{}
	if err := json.Unmarshal(data, &jwks); err != nil {
		t.Fatalf("Generated file is not valid JSON: %v", err)
	}
	if len(jwks) != 4 {
		t.Fatalf("Generated JWKS has %d keys, want 4", len(jwks))
	}
}

func TestGeneratedKeysWork(t *testing.T) {
	p, err := pki.Generate(GEN_FILE)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	jwks := p.ExportJWKS()
	p2, err := pki.ImportJWKS(jwks)
	if err != nil {
		t.Fatalf("ImportJWKS failed: %v", err)
	}

	sig, err := p2.Sign("Hello World")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	ok, err := p2.Verify("Hello World", sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for valid signature on generated keys")
	}

	ciphertext, err := p2.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	plaintext, err := p2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if plaintext != "test" {
		t.Fatalf("Decrypt returned %q, want %q", plaintext, "test")
	}
}

func TestWriteCrossLangSignature(t *testing.T) {
	sig, err := globalPKI.Sign("Hello World")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	out := map[string]string{
		"lang":      "go",
		"message":   "Hello World",
		"signature": sig,
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := os.WriteFile(SIG_OUT, data, 0644); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func TestVerifyCrossLangSignatures(t *testing.T) {
	for _, lang := range CROSS_LANGS {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			path := "../fixtures/sig_" + lang + ".json"
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("Read %s: %v", path, err)
			}
			var rec map[string]string
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("Unmarshal %s: %v", path, err)
			}
			message := rec["message"]
			signature := rec["signature"]
			ok, err := globalPKI.Verify(message, signature)
			if err != nil {
				t.Fatalf("Verify %s: %v", lang, err)
			}
			if !ok {
				t.Fatalf("Verify %s signature failed", lang)
			}
		})
	}
}
