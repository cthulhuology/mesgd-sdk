use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::bn::{BigNum, BigNumContext};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use openssl::rsa::Padding;
use openssl::md::Md;
use openssl::pkey_ctx::PkeyCtx;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;

use base64::{Engine as _, engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}};

fn b64url_enc(b: &[u8]) -> String { URL_SAFE_NO_PAD.encode(b) }
fn b64url_dec(s: &str) -> Vec<u8> { URL_SAFE_NO_PAD.decode(s).unwrap() }
fn b64_std_enc(b: &[u8]) -> String { STANDARD.encode(b) }
fn b64_std_dec(s: &str) -> Vec<u8> { STANDARD.decode(s).unwrap() }

fn pad32(v: Vec<u8>) -> Vec<u8> {
    if v.len() >= 32 {
        return v;
    }
    let mut padded = vec![0u8; 32 - v.len()];
    padded.extend_from_slice(&v);
    padded
}

pub struct PKI {
    signing_priv: PKey<Private>,
    signing_pub: PKey<Public>,
    encrypting_priv: PKey<Private>,
    encrypting_pub: PKey<Public>,
}

impl PKI {
    pub fn generate(path: &str) -> Result<Self, Box<dyn Error>> {
        // Generate ECDSA P-256
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let signing_priv = PKey::from_ec_key(ec_key)?;
        let signing_pub = PKey::public_key_from_der(&signing_priv.public_key_to_der()?)?;

        // Generate RSA 2048
        let rsa = Rsa::generate(2048)?;
        let encrypting_priv = PKey::from_rsa(rsa)?;
        let encrypting_pub = PKey::public_key_from_der(&encrypting_priv.public_key_to_der()?)?;

        let pki = PKI { signing_priv, signing_pub, encrypting_priv, encrypting_pub };
        let jwks = pki.export_jwks()?;
        let json_str = serde_json::to_string(&jwks)?;

        // Create parent directories if needed
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json_str)?;

        Ok(pki)
    }

    pub fn init(path: &str) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let jwks: Vec<Value> = serde_json::from_str(&contents)?;
        Self::import_jwks(&jwks)
    }

    pub fn import_jwks(jwks: &[Value]) -> Result<Self, Box<dyn Error>> {
        // Find the four keys by use + key_ops
        let pub_sig = jwks.iter().find(|k| {
            k["use"] == "sig" && k["key_ops"].as_array().map(|a| a.iter().any(|v| v == "verify")).unwrap_or(false)
        }).ok_or("missing EC public (verify) key")?;

        let priv_sig = jwks.iter().find(|k| {
            k["use"] == "sig" && k["key_ops"].as_array().map(|a| a.iter().any(|v| v == "sign")).unwrap_or(false)
        }).ok_or("missing EC private (sign) key")?;

        let pub_enc = jwks.iter().find(|k| {
            k["use"] == "enc" && k["key_ops"].as_array().map(|a| a.iter().any(|v| v == "decrypt")).unwrap_or(false)
        }).ok_or("missing RSA public (decrypt) key")?;

        let priv_enc = jwks.iter().find(|k| {
            k["use"] == "enc" && k["key_ops"].as_array().map(|a| a.iter().any(|v| v == "encrypt")).unwrap_or(false)
        }).ok_or("missing RSA private (encrypt) key")?;

        // Import EC keys
        let x_bytes = b64url_dec(pub_sig["x"].as_str().unwrap());
        let y_bytes = b64url_dec(pub_sig["y"].as_str().unwrap());
        let d_bytes = b64url_dec(priv_sig["d"].as_str().unwrap());

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;

        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        let point = EcPoint::from_bytes(&group, &point_bytes, &mut ctx)?;

        let d = BigNum::from_slice(&d_bytes)?;
        let ec_key = EcKey::from_private_components(&group, &d, &point)?;
        let signing_priv = PKey::from_ec_key(ec_key)?;
        let signing_pub = PKey::public_key_from_der(&signing_priv.public_key_to_der()?)?;

        // Import RSA keys
        let n = BigNum::from_slice(&b64url_dec(priv_enc["n"].as_str().unwrap()))?;
        let e = BigNum::from_slice(&b64url_dec(priv_enc["e"].as_str().unwrap()))?;
        let d = BigNum::from_slice(&b64url_dec(priv_enc["d"].as_str().unwrap()))?;
        let p = BigNum::from_slice(&b64url_dec(priv_enc["p"].as_str().unwrap()))?;
        let q = BigNum::from_slice(&b64url_dec(priv_enc["q"].as_str().unwrap()))?;
        let dp = BigNum::from_slice(&b64url_dec(priv_enc["dp"].as_str().unwrap()))?;
        let dq = BigNum::from_slice(&b64url_dec(priv_enc["dq"].as_str().unwrap()))?;
        let qi = BigNum::from_slice(&b64url_dec(priv_enc["qi"].as_str().unwrap()))?;

        // Also extract n and e from pub_enc for consistency (using priv_enc which has all components)
        let _ = pub_enc; // pub_enc used for finding key; priv_enc has n and e too

        let rsa = Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?;
        let encrypting_priv = PKey::from_rsa(rsa)?;
        let encrypting_pub = PKey::public_key_from_der(&encrypting_priv.public_key_to_der()?)?;

        Ok(PKI { signing_priv, signing_pub, encrypting_priv, encrypting_pub })
    }

    pub fn export_jwks(&self) -> Result<Vec<Value>, Box<dyn Error>> {
        // Export EC keys
        let ec_key = self.signing_priv.ec_key()?;
        let group = ec_key.group();
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        ec_key.public_key().affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
        let d = ec_key.private_key();

        let x_enc = b64url_enc(&pad32(x.to_vec()));
        let y_enc = b64url_enc(&pad32(y.to_vec()));
        let d_enc = b64url_enc(&pad32(d.to_vec()));

        let ec_pub = json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "key_ops": ["verify"],
            "x": x_enc,
            "y": y_enc
        });

        let ec_priv = json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "key_ops": ["sign"],
            "x": x_enc,
            "y": y_enc,
            "d": d_enc
        });

        // Export RSA keys
        let rsa = self.encrypting_priv.rsa()?;
        let n_enc = b64url_enc(&rsa.n().to_vec());
        let e_enc = b64url_enc(&rsa.e().to_vec());
        let d_enc_rsa = b64url_enc(&rsa.d().to_vec());
        let p_enc = b64url_enc(&rsa.p().unwrap().to_vec());
        let q_enc = b64url_enc(&rsa.q().unwrap().to_vec());
        let dp_enc = b64url_enc(&rsa.dmp1().unwrap().to_vec());
        let dq_enc = b64url_enc(&rsa.dmq1().unwrap().to_vec());
        let qi_enc = b64url_enc(&rsa.iqmp().unwrap().to_vec());

        let rsa_pub = json!({
            "kty": "RSA",
            "use": "enc",
            "key_ops": ["decrypt"],
            "n": n_enc,
            "e": e_enc
        });

        let rsa_priv = json!({
            "kty": "RSA",
            "use": "enc",
            "key_ops": ["encrypt"],
            "n": n_enc,
            "e": e_enc,
            "d": d_enc_rsa,
            "p": p_enc,
            "q": q_enc,
            "dp": dp_enc,
            "dq": dq_enc,
            "qi": qi_enc
        });

        Ok(vec![ec_pub, rsa_pub, ec_priv, rsa_priv])
    }

    pub fn sign(&self, message: &str) -> Result<String, Box<dyn Error>> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.signing_priv)?;
        signer.update(message.as_bytes())?;
        let der = signer.sign_to_vec()?;
        let sig = EcdsaSig::from_der(&der)?;
        let r = pad32(sig.r().to_vec());
        let s = pad32(sig.s().to_vec());
        Ok(format!("{{\"r\":\"{}\",\"s\":\"{}\"}}", b64url_enc(&r), b64url_enc(&s)))
    }

    pub fn check(&self, message: &str, sig_json: &str) -> Result<bool, Box<dyn Error>> {
        let v: Value = serde_json::from_str(sig_json)?;
        let r_bytes = b64url_dec(v["r"].as_str().unwrap());
        let s_bytes = b64url_dec(v["s"].as_str().unwrap());
        let r = BigNum::from_slice(&r_bytes)?;
        let s = BigNum::from_slice(&s_bytes)?;
        let sig = EcdsaSig::from_private_components(r, s)?;
        let der = sig.to_der()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.signing_pub)?;
        verifier.update(message.as_bytes())?;
        Ok(verifier.verify(&der)?)
    }

    pub fn encrypt(&self, message: &str) -> Result<String, Box<dyn Error>> {
        let data = message.as_bytes();
        let mut ctx = PkeyCtx::new(&self.encrypting_pub)?;
        ctx.encrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        let len = ctx.encrypt(data, None)?;
        let mut out = vec![0u8; len];
        let written = ctx.encrypt(data, Some(&mut out))?;
        out.truncate(written);
        Ok(b64_std_enc(&out))
    }

    pub fn decrypt(&self, ct_b64: &str) -> Result<String, Box<dyn Error>> {
        let ciphertext = b64_std_dec(ct_b64);
        let mut ctx = PkeyCtx::new(&self.encrypting_priv)?;
        ctx.decrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        let len = ctx.decrypt(&ciphertext, None)?;
        let mut plaintext = vec![0u8; len];
        let written = ctx.decrypt(&ciphertext, Some(&mut plaintext))?;
        plaintext.truncate(written);
        Ok(String::from_utf8(plaintext)?)
    }

    pub fn pub_jwk(&self) -> Result<Value, Box<dyn Error>> {
        let jwks = self.export_jwks()?;
        Ok(json!({
            "signing_pub": jwks[0],
            "encrypting_pub": jwks[1]
        }))
    }

    fn unwrap_jwk<'a>(jwk: &'a Value, inner: &str) -> &'a Value {
        if jwk.get(inner).map(|v| v.is_object()).unwrap_or(false) {
            &jwk[inner]
        } else {
            jwk
        }
    }

    pub fn encrypt_with(pub_jwk: &Value, message: &str) -> Result<String, Box<dyn Error>> {
        let jwk = Self::unwrap_jwk(pub_jwk, "encrypting_pub");
        let n = BigNum::from_slice(&b64url_dec(jwk["n"].as_str().ok_or("missing n")?))?;
        let e = BigNum::from_slice(&b64url_dec(jwk["e"].as_str().ok_or("missing e")?))?;
        let rsa = Rsa::from_public_components(n, e)?;
        let key = PKey::from_rsa(rsa)?;
        let data = message.as_bytes();
        let mut ctx = PkeyCtx::new(&key)?;
        ctx.encrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        let len = ctx.encrypt(data, None)?;
        let mut out = vec![0u8; len];
        let written = ctx.encrypt(data, Some(&mut out))?;
        out.truncate(written);
        Ok(b64_std_enc(&out))
    }

    pub fn check_with_pub(pub_jwk: &Value, message: &str, sig_json: &str) -> Result<bool, Box<dyn Error>> {
        let jwk = Self::unwrap_jwk(pub_jwk, "signing_pub");
        let x_bytes = b64url_dec(jwk["x"].as_str().ok_or("missing x")?);
        let y_bytes = b64url_dec(jwk["y"].as_str().ok_or("missing y")?);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&pad32(x_bytes));
        point_bytes.extend_from_slice(&pad32(y_bytes));
        let point = EcPoint::from_bytes(&group, &point_bytes, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;
        let key = PKey::from_ec_key(ec_key)?;
        let v: Value = serde_json::from_str(sig_json)?;
        let r = BigNum::from_slice(&b64url_dec(v["r"].as_str().ok_or("missing r")?))?;
        let s = BigNum::from_slice(&b64url_dec(v["s"].as_str().ok_or("missing s")?))?;
        let sig = EcdsaSig::from_private_components(r, s)?;
        let der = sig.to_der()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(message.as_bytes())?;
        Ok(verifier.verify(&der)?)
    }

    /// Hybrid seal matching the reference wire format {alg,k,iv,ct,tag}: a random
    /// AES-256-GCM key wrapped with RSA-OAEP-SHA256, so payloads exceed OAEP's cap.
    pub fn seal(pub_jwk: &Value, plain: &str) -> Result<String, Box<dyn Error>> {
        let jwk = Self::unwrap_jwk(pub_jwk, "encrypting_pub");
        let n = BigNum::from_slice(&b64url_dec(jwk["n"].as_str().ok_or("missing n")?))?;
        let e = BigNum::from_slice(&b64url_dec(jwk["e"].as_str().ok_or("missing e")?))?;
        let key = PKey::from_rsa(Rsa::from_public_components(n, e)?)?;

        let mut aes_key = [0u8; 32];
        let mut iv = [0u8; 12];
        openssl::rand::rand_bytes(&mut aes_key)?;
        openssl::rand::rand_bytes(&mut iv)?;
        let mut tag = [0u8; 16];
        let ct = openssl::symm::encrypt_aead(openssl::symm::Cipher::aes_256_gcm(),
            &aes_key, Some(&iv), &[], plain.as_bytes(), &mut tag)?;

        let mut ctx = PkeyCtx::new(&key)?;
        ctx.encrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        let len = ctx.encrypt(&aes_key, None)?;
        let mut wrapped = vec![0u8; len];
        let written = ctx.encrypt(&aes_key, Some(&mut wrapped))?;
        wrapped.truncate(written);

        Ok(serde_json::to_string(&json!({
            "alg": "RSA-OAEP+A256GCM",
            "k": b64_std_enc(&wrapped),
            "iv": b64_std_enc(&iv),
            "ct": b64_std_enc(&ct),
            "tag": b64_std_enc(&tag),
        }))?)
    }

    pub fn open(&self, sealed_json: &str) -> Result<String, Box<dyn Error>> {
        let m: Value = serde_json::from_str(sealed_json)?;
        let wrapped = b64_std_dec(m["k"].as_str().ok_or("missing k")?);
        let iv = b64_std_dec(m["iv"].as_str().ok_or("missing iv")?);
        let ct = b64_std_dec(m["ct"].as_str().ok_or("missing ct")?);
        let tag = b64_std_dec(m["tag"].as_str().ok_or("missing tag")?);

        let mut ctx = PkeyCtx::new(&self.encrypting_priv)?;
        ctx.decrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(Md::sha256())?;
        ctx.set_rsa_mgf1_md(Md::sha256())?;
        let len = ctx.decrypt(&wrapped, None)?;
        let mut aes_key = vec![0u8; len];
        let written = ctx.decrypt(&wrapped, Some(&mut aes_key))?;
        aes_key.truncate(written);

        let plain = openssl::symm::decrypt_aead(openssl::symm::Cipher::aes_256_gcm(),
            &aes_key, Some(&iv), &[], &ct, &tag)?;
        Ok(String::from_utf8(plain)?)
    }
}

/// Password + authenticator authentication clients.
pub mod auth;

/// mesgd transport client.
pub mod mesgd;
