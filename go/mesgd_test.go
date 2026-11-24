package pki_test

import (
	"encoding/json"
	"os"
	"testing"

	pki "mesgd-sdk"
)

const (
	aliceFile = "../fixtures/test_mesgd_alice.json"
	bobFile   = "../fixtures/test_mesgd_bob.json"
)

func cleanupMesgdFiles() {
	os.Remove(aliceFile)
	os.Remove(bobFile)
}

func TestTwoPartyEncrypt(t *testing.T) {
	cleanupMesgdFiles()
	defer cleanupMesgdFiles()

	alice, err := pki.Generate(aliceFile)
	if err != nil {
		t.Fatalf("generate alice: %v", err)
	}
	alicePub := alice.PubJWK()

	if _, err := pki.Generate(bobFile); err != nil {
		t.Fatalf("generate bob: %v", err)
	}
	ct, err := pki.EncryptWith(alicePub, "secret from bob")
	if err != nil {
		t.Fatalf("encrypt_with: %v", err)
	}
	alice2, err := pki.Init(aliceFile)
	if err != nil {
		t.Fatalf("init alice: %v", err)
	}
	pt, err := alice2.Decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != "secret from bob" {
		t.Fatalf("got %q", pt)
	}
}

func TestSignedEncryptedMessage(t *testing.T) {
	cleanupMesgdFiles()
	defer cleanupMesgdFiles()

	alice, err := pki.Generate(aliceFile)
	if err != nil {
		t.Fatalf("generate alice: %v", err)
	}
	alicePub := alice.PubJWK()
	bob, err := pki.Generate(bobFile)
	if err != nil {
		t.Fatalf("generate bob: %v", err)
	}
	plain := "ping"
	sig, err := bob.Sign(plain)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope, err := json.Marshal(map[string]string{"payload": plain, "signature": sig})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := pki.EncryptWith(alicePub, string(envelope))
	if err != nil {
		t.Fatalf("encrypt_with: %v", err)
	}
	alice2, err := pki.Init(aliceFile)
	if err != nil {
		t.Fatal(err)
	}
	openedRaw, err := alice2.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	var opened map[string]string
	if err := json.Unmarshal([]byte(openedRaw), &opened); err != nil {
		t.Fatal(err)
	}
	if opened["payload"] != plain {
		t.Fatalf("payload %q", opened["payload"])
	}
	ok, err := pki.CheckWithPub(alicePub, opened["payload"], opened["signature"])
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("alice pub should not verify bob signature")
	}
	ok, err = bob.Check(plain, sig)
	if err != nil || !ok {
		t.Fatal("bob should verify own signature")
	}
}

func TestCompactRegisterEnvelope(t *testing.T) {
	cleanupMesgdFiles()
	defer cleanupMesgdFiles()

	mesgd, err := pki.Init(JWKS_FILE)
	if err != nil {
		t.Fatal(err)
	}
	mesgdPub := mesgd.PubJWK()
	alice, err := pki.Generate(aliceFile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"name": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := alice.Sign(string(payload))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]string{
		"payload":   string(payload),
		"signature": sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := pki.EncryptWith(mesgdPub, string(envelope))
	if err != nil {
		t.Fatal(err)
	}
	alicePub := alice.PubJWK()
	openedRaw, err := mesgd.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	var opened map[string]string
	if err := json.Unmarshal([]byte(openedRaw), &opened); err != nil {
		t.Fatal(err)
	}
	var inner map[string]string
	if err := json.Unmarshal([]byte(opened["payload"]), &inner); err != nil {
		t.Fatal(err)
	}
	if inner["name"] != "alice" {
		t.Fatalf("name %q", inner["name"])
	}
	ok, err := pki.CheckWithPub(alicePub, opened["payload"], opened["signature"])
	if err != nil || !ok {
		t.Fatal("mesgd should verify alice registration signature")
	}
}

func TestLiveRegisterAuthMessage(t *testing.T) {
	if os.Getenv("MESGD_URL") == "" {
		t.Skip("set MESGD_URL for live mesgd")
	}
	t.Skip("mesgd HTTP JWK registration is not wired yet")
}
