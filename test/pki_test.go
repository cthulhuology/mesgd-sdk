// pki_test.go
package main

import (
    "testing"
)

func TestPKI(t *testing.T) {
    pki := PKI{}
    if err := pki.Init(); err != nil {
        t.Fatalf("Init failed: %v", err)
    }
    t.Log("Init: OK")

    // Test sign/verify
    msg := "Hello World"
    sig, err := pki.Sign(msg)
    if err != nil {
        t.Fatalf("Sign failed: %v", err)
    }
    t.Log("Sign: OK")
    verified, err := pki.Verify(msg, sig)
    if err != nil || !verified {
        t.Fatalf("Verify failed: %v (err: %v)", verified, err)
    }
    wrongVerified, _ := pki.Verify("Wrong", sig)
    if wrongVerified {
        t.Fatal("Wrong verify passed")
    }
    t.Log("Verify: OK")

    // Test encrypt/decrypt
    secret := "Secret message"
    enc, err := pki.Encrypt(secret)
    if err != nil {
        t.Fatalf("Encrypt failed: %v", err)
    }
    t.Log("Encrypt: OK")
    dec, err := pki.Decrypt(enc)
    if err != nil || dec != secret {
        t.Fatalf("Decrypt failed: %v (got: %s)", err, dec)
    }
    // Test invalid
    _, err = pki.Decrypt(enc + "invalid")
    if err == nil {
        t.Fatal("Invalid decrypt passed")
    }
    t.Log("Invalid decrypt: OK")

    // Test re-init
    originalSig, _ := pki.Sign(msg)
    pki = PKI{}  // Reset
    if err := pki.Init(); err != nil {
        t.Fatal(err)
    }
    reloadedSig, _ := pki.Sign(msg)
    if originalSig != reloadedSig {
        t.Fatal("Re-init mismatch")
    }
    t.Log("All tests passed")
}
