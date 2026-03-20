package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// PKI holds the signing (EC) and encrypting (RSA) private keys.
// Public keys are derived from the private keys.
type PKI struct {
	signingPriv    *ecdsa.PrivateKey
	encryptingPriv *rsa.PrivateKey
}

// b64url encodes bytes as base64url with no padding.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64urlDec decodes a base64url string (with or without padding).
func b64urlDec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// padTo32 left-pads a byte slice to exactly 32 bytes with zeros.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// bnBytes returns the big-endian byte representation of a *big.Int.
func bnBytes(n *big.Int) []byte {
	return n.Bytes()
}

// Init loads a PKI from a jwks.json file at the given path.
func Init(path string) (*PKI, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Init: read file: %w", err)
	}
	var jwks []map[string]interface{}
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("Init: unmarshal: %w", err)
	}
	return ImportJWKS(jwks)
}

// Generate creates new EC+RSA keys, writes them to path as a JWK array, and returns a PKI.
func Generate(path string) (*PKI, error) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Generate: EC keygen: %w", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("Generate: RSA keygen: %w", err)
	}
	rsaPriv.Precompute()

	p := &PKI{
		signingPriv:    ecPriv,
		encryptingPriv: rsaPriv,
	}

	jwks := p.ExportJWKS()
	data, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("Generate: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, fmt.Errorf("Generate: write file: %w", err)
	}
	return p, nil
}

// Sign signs message with the EC private key and returns JSON {"r":"...","s":"..."}.
func (p *PKI) Sign(message string) (string, error) {
	if p.signingPriv == nil {
		return "", fmt.Errorf("Sign: no signing key")
	}
	h := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, p.signingPriv, h[:])
	if err != nil {
		return "", fmt.Errorf("Sign: %w", err)
	}
	sig := map[string]string{
		"r": b64url(padTo32(bnBytes(r))),
		"s": b64url(padTo32(bnBytes(s))),
	}
	out, err := json.Marshal(sig)
	if err != nil {
		return "", fmt.Errorf("Sign: marshal: %w", err)
	}
	return string(out), nil
}

// Verify verifies signatureJSON ({"r":"...","s":"..."}) against message using the EC public key.
func (p *PKI) Verify(message, signatureJSON string) (bool, error) {
	if p.signingPriv == nil {
		return false, fmt.Errorf("Verify: no signing key")
	}
	var sig map[string]string
	if err := json.Unmarshal([]byte(signatureJSON), &sig); err != nil {
		return false, fmt.Errorf("Verify: unmarshal signature: %w", err)
	}
	rBytes, err := b64urlDec(sig["r"])
	if err != nil {
		return false, fmt.Errorf("Verify: decode r: %w", err)
	}
	sBytes, err := b64urlDec(sig["s"])
	if err != nil {
		return false, fmt.Errorf("Verify: decode s: %w", err)
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	h := sha256.Sum256([]byte(message))
	return ecdsa.Verify(&p.signingPriv.PublicKey, h[:], r, s), nil
}

// Encrypt encrypts message with the RSA public key using OAEP/SHA-256 and returns standard base64.
func (p *PKI) Encrypt(message string) (string, error) {
	if p.encryptingPriv == nil {
		return "", fmt.Errorf("Encrypt: no encrypting key")
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &p.encryptingPriv.PublicKey, []byte(message), nil)
	if err != nil {
		return "", fmt.Errorf("Encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a standard-base64-encoded ciphertext with the RSA private key.
func (p *PKI) Decrypt(ciphertextB64 string) (string, error) {
	if p.encryptingPriv == nil {
		return "", fmt.Errorf("Decrypt: no encrypting key")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("Decrypt: base64 decode: %w", err)
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.encryptingPriv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("Decrypt: %w", err)
	}
	return string(plaintext), nil
}

// ExportJWKS returns the flat 4-element JWK array for this PKI.
func (p *PKI) ExportJWKS() []map[string]interface{} {
	p.encryptingPriv.Precompute()

	x := padTo32(bnBytes(p.signingPriv.PublicKey.X))
	y := padTo32(bnBytes(p.signingPriv.PublicKey.Y))
	d := padTo32(bnBytes(p.signingPriv.D))

	ecPub := map[string]interface{}{
		"kty":     "EC",
		"crv":     "P-256",
		"use":     "sig",
		"key_ops": []string{"verify"},
		"x":       b64url(x),
		"y":       b64url(y),
	}
	ecPriv := map[string]interface{}{
		"kty":     "EC",
		"crv":     "P-256",
		"use":     "sig",
		"key_ops": []string{"sign"},
		"x":       b64url(x),
		"y":       b64url(y),
		"d":       b64url(d),
	}

	rPub := p.encryptingPriv.PublicKey
	rsaPub := map[string]interface{}{
		"kty":     "RSA",
		"use":     "enc",
		"key_ops": []string{"decrypt"},
		"n":       b64url(bnBytes(rPub.N)),
		"e":       b64url(bnBytes(big.NewInt(int64(rPub.E)))),
	}
	rsaPriv := map[string]interface{}{
		"kty":     "RSA",
		"use":     "enc",
		"key_ops": []string{"encrypt"},
		"n":       b64url(bnBytes(p.encryptingPriv.PublicKey.N)),
		"e":       b64url(bnBytes(big.NewInt(int64(p.encryptingPriv.PublicKey.E)))),
		"d":       b64url(bnBytes(p.encryptingPriv.D)),
		"p":       b64url(bnBytes(p.encryptingPriv.Primes[0])),
		"q":       b64url(bnBytes(p.encryptingPriv.Primes[1])),
		"dp":      b64url(bnBytes(p.encryptingPriv.Precomputed.Dp)),
		"dq":      b64url(bnBytes(p.encryptingPriv.Precomputed.Dq)),
		"qi":      b64url(bnBytes(p.encryptingPriv.Precomputed.Qinv)),
	}

	return []map[string]interface{}{ecPub, rsaPub, ecPriv, rsaPriv}
}

// ImportJWKS constructs a PKI from a flat JWK array.
func ImportJWKS(jwks []map[string]interface{}) (*PKI, error) {
	p := &PKI{}

	for _, jwk := range jwks {
		kty, _ := jwk["kty"].(string)
		use, _ := jwk["use"].(string)
		hasOp := func(op string) bool {
			switch v := jwk["key_ops"].(type) {
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && s == op {
						return true
					}
				}
			case []string:
				for _, s := range v {
					if s == op {
						return true
					}
				}
			}
			return false
		}

		switch {
		case kty == "EC" && use == "sig" && hasOp("sign"):
			// EC private key
			xB, err := b64urlDec(jwk["x"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: EC x: %w", err)
			}
			yB, err := b64urlDec(jwk["y"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: EC y: %w", err)
			}
			dB, err := b64urlDec(jwk["d"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: EC d: %w", err)
			}
			priv := &ecdsa.PrivateKey{
				D: new(big.Int).SetBytes(dB),
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     new(big.Int).SetBytes(xB),
					Y:     new(big.Int).SetBytes(yB),
				},
			}
			p.signingPriv = priv

		case kty == "RSA" && use == "enc" && hasOp("encrypt"):
			// RSA private key
			nB, err := b64urlDec(jwk["n"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA n: %w", err)
			}
			eB, err := b64urlDec(jwk["e"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA e: %w", err)
			}
			dB, err := b64urlDec(jwk["d"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA d: %w", err)
			}
			pB, err := b64urlDec(jwk["p"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA p: %w", err)
			}
			qB, err := b64urlDec(jwk["q"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA q: %w", err)
			}
			dpB, err := b64urlDec(jwk["dp"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA dp: %w", err)
			}
			dqB, err := b64urlDec(jwk["dq"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA dq: %w", err)
			}
			qiB, err := b64urlDec(jwk["qi"].(string))
			if err != nil {
				return nil, fmt.Errorf("ImportJWKS: RSA qi: %w", err)
			}
			eInt := int(new(big.Int).SetBytes(eB).Int64())
			rsaKey := &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: new(big.Int).SetBytes(nB),
					E: eInt,
				},
				D:      new(big.Int).SetBytes(dB),
				Primes: []*big.Int{new(big.Int).SetBytes(pB), new(big.Int).SetBytes(qB)},
				Precomputed: rsa.PrecomputedValues{
					Dp:   new(big.Int).SetBytes(dpB),
					Dq:   new(big.Int).SetBytes(dqB),
					Qinv: new(big.Int).SetBytes(qiB),
				},
			}
			rsaKey.Precompute()
			p.encryptingPriv = rsaKey
		}
	}

	if p.signingPriv == nil {
		return nil, fmt.Errorf("ImportJWKS: no EC signing key found")
	}
	if p.encryptingPriv == nil {
		return nil, fmt.Errorf("ImportJWKS: no RSA encrypting key found")
	}
	return p, nil
}
