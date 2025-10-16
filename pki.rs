use openssl::pkey::{PKey, Private};
use openssl::pkey::Public;
use openssl::ec::{EcKey, EcGroup};
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use base64::{encode, decode};

#[derive(Serialize, Deserialize)]
struct Keys {
    signing_priv_pem: String,
    signing_pub_pem: String,
    encrypting_priv_pem: String,
    encrypting_pub_pem: String,
}

pub struct PKI {
    signing_priv: PKey<Private>,
    signing_pub: PKey<Public>,
    encrypting_priv: PKey<Private>,
    encrypting_pub: PKey<Public>,
}

impl PKI {
    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        let file = "pki_keys.json";
        let keys: Keys;
        if Path::new(file).exists() {
            let mut f = File::open(file)?;
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            keys = serde_json::from_str(&contents)?;
        } else {
            // Generate ECDSA P-256
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            let signing_priv = PKey::from_ec_key(ec_key.clone())?;
            let signing_pub = PKey::public_key_from_pem(ec_key.public_key_to_pem()?.as_slice())?;

            // Generate RSA 2048
            let rsa = Rsa::generate(2048)?;
            let encrypting_priv = PKey::from_rsa(rsa.clone())?;
            let encrypting_pub = PKey::public_key_from_pem(rsa.public_key_to_pem()?.as_slice())?;

            keys = Keys {
                signing_priv_pem: String::from_utf8(signing_priv.private_key_to_pem_pkcs8()?)?,
                signing_pub_pem: String::from_utf8(signing_pub.public_key_to_pem()?)?,
                encrypting_priv_pem: String::from_utf8(encrypting_priv.private_key_to_pem_pkcs8()?)?,
                encrypting_pub_pem: String::from_utf8(encrypting_pub.public_key_to_pem()?)?,
            };

            let serialized = serde_json::to_string(&keys)?;
            let mut f = File::create(file)?;
            f.write_all(serialized.as_bytes())?;
        }

        let signing_priv = PKey::private_key_from_pem(keys.signing_priv_pem.as_bytes())?;
        let signing_pub = PKey::public_key_from_pem(keys.signing_pub_pem.as_bytes())?;
        let encrypting_priv = PKey::private_key_from_pem(keys.encrypting_priv_pem.as_bytes())?;
        let encrypting_pub = PKey::public_key_from_pem(keys.encrypting_pub_pem.as_bytes())?;

        Ok(PKI {
            signing_priv,
            signing_pub,
            encrypting_priv,
            encrypting_pub,
        })
    }

    pub fn sign(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.signing_priv)?;
        signer.update(message.as_bytes())?;
        let signature = signer.sign_to_vec()?;
        Ok(encode(signature))
    }

    pub fn verify(&self, message: &str, signature_b64: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let signature = decode(signature_b64)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.signing_pub)?;
        verifier.update(message.as_bytes())?;
        Ok(verifier.verify(&signature)?)
    }

    pub fn encrypt(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        let rsa_pub = self.encrypting_pub.rsa()?;
        let ciphertext = rsa_pub.public_encrypt(message.as_bytes(), Padding::OAEP, MessageDigest::sha256())?;
        Ok(encode(ciphertext))
    }

    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
        let ciphertext = decode(ciphertext_b64)?;
        let rsa_priv = self.encrypting_priv.rsa()?;
        let plaintext = rsa_priv.private_decrypt(&ciphertext, Padding::OAEP, MessageDigest::sha256())?;
        Ok(String::from_utf8(plaintext)?)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pki = PKI::init()?;
    let sig = pki.sign("Hello World")?;
    println!("Signature: {}", sig);
    println!("Verify: {}", pki.verify("Hello World", &sig)?);
    let enc = pki.encrypt("Secret message")?;
    println!("Encrypted: {}", enc);
    println!("Decrypted: {}", pki.decrypt(&enc)?);
    Ok(())
}
