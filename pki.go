package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/asn1"
    "encoding/base64"
    "encoding/gob"
    "fmt"
    "io"
    "math/big"
    "os"
)

type PKI struct {
    signingPriv *ecdsa.PrivateKey
    encryptingPriv *rsa.PrivateKey
}

func (p *PKI) Init() error {
    file := "pki_keys.gob"
    if _, err := os.Stat(file); err == nil {
        f, err := os.Open(file)
        if err != nil {
            return err
        }
        defer f.Close()
        dec := gob.NewDecoder(f)
        var keys struct {
            SigningPriv []byte
            EncryptingPriv []byte
        }
        if err := dec.Decode(&keys); err != nil {
            return err
        }
        signingPrivBlock, _ := pem.Decode(keys.SigningPriv)
        p.signingPriv, err = x509.ParseECPrivateKey(signingPrivBlock.Bytes)
        if err != nil {
            return err
        }
        encryptingPrivBlock, _ := pem.Decode(keys.EncryptingPriv)
        p.encryptingPriv, err = x509.ParsePKCS1PrivateKey(encryptingPrivBlock.Bytes)
        if err != nil {
            return err
        }
        return nil
    }

    // Generate keys
    var err error
    p.signingPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return err
    }
    p.encryptingPriv, err = rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

    // Encode to PEM
    signingPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509.MarshalECPrivateKey(p.signingPriv)})
    encryptingPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.encryptingPriv)})

    keys := struct {
        SigningPriv    []byte
        EncryptingPriv []byte
    }{
        SigningPriv:    signingPrivPEM,
        EncryptingPriv: encryptingPrivPEM,
    }

    f, err := os.Create(file)
    if err != nil {
        return err
    }
    defer f.Close()
    enc := gob.NewEncoder(f)
    if err := enc.Encode(keys); err != nil {
        return err
    }
    return nil
}

func (p *PKI) Sign(message string) (string, error) {
    if p.signingPriv == nil {
        return "", fmt.Errorf("keys not initialized")
    }
    h := sha256.Sum256([]byte(message))
    r, s, err := ecdsa.Sign(rand.Reader, p.signingPriv, h[:])
    if err != nil {
        return "", err
    }
    type ecdsaSignature struct {
        R, S *big.Int
    }
    sigBytes, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(sigBytes), nil
}

func (p *PKI) Verify(message, signatureB64 string) (bool, error) {
    if p.signingPriv == nil {
        return false, fmt.Errorf("keys not initialized")
    }
    sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
    if err != nil {
        return false, err
    }
    h := sha256.Sum256([]byte(message))
    type ecdsaSignature struct {
        R, S *big.Int
    }
    var sig ecdsaSignature
    if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
        return false, err
    }
    return ecdsa.Verify(asn1SignatureToPublicKey(p.signingPriv.PublicKey), h[:], sig.R, sig.S), nil
}

func asn1SignatureToPublicKey(pub ecdsa.PublicKey) *ecdsa.PublicKey {
    return &pub
}

func (p *PKI) Encrypt(message string) (string, error) {
    if p.encryptingPriv == nil {
        return "", fmt.Errorf("keys not initialized")
    }
    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &p.encryptingPriv.PublicKey, []byte(message), nil)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (p *PKI) Decrypt(ciphertextB64 string) (string, error) {
    if p.encryptingPriv == nil {
        return "", fmt.Errorf("keys not initialized")
    }
    ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
    if err != nil {
        return "", err
    }
    plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.encryptingPriv, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

func main() {
    var pki PKI
    if err := pki.Init(); err != nil {
        fmt.Println("Error:", err)
        return
    }
    sig, _ := pki.Sign("Hello World")
    fmt.Println("Signature:", sig)
    verified, _ := pki.Verify("Hello World", sig)
    fmt.Println("Verify:", verified)
    enc, _ := pki.Encrypt("Secret message")
    fmt.Println("Encrypted:", enc)
    dec, _ := pki.Decrypt(enc)
    fmt.Println("Decrypted:", dec)
}
