use mesgd_pki::PKI;
use std::fs;

const JWKS_FILE: &str = "../fixtures/jwks.json";
const GEN_FILE: &str  = "../fixtures/test_rust.json";
const SIG_OUT: &str   = "../fixtures/sig_rust.json";
const CROSS_LANGS: &[&str] = &["erlang", "python", "javascript", "ruby", "go", "c", "java"];

#[test]
fn test_sign_verify_roundtrip() {
    let pki = PKI::init(JWKS_FILE).expect("init failed");
    let sig = pki.sign("Hello World").expect("sign failed");
    assert!(pki.verify("Hello World", &sig).expect("verify failed"), "valid signature should verify");
    assert!(!pki.verify("Wrong", &sig).expect("verify failed"), "wrong message should not verify");
}

#[test]
fn test_signature_is_json() {
    let pki = PKI::init(JWKS_FILE).expect("init failed");
    let sig = pki.sign("Hello World").expect("sign failed");
    let v: serde_json::Value = serde_json::from_str(&sig).expect("signature should be valid JSON");
    assert!(v["r"].is_string(), "signature should have 'r' field");
    assert!(v["s"].is_string(), "signature should have 's' field");
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let pki = PKI::init(JWKS_FILE).expect("init failed");
    let ct = pki.encrypt("Secret message").expect("encrypt failed");
    let pt = pki.decrypt(&ct).expect("decrypt failed");
    assert_eq!(pt, "Secret message");
}

#[test]
fn test_generate_creates_json_file() {
    let _ = fs::remove_file(GEN_FILE);
    let _pki = PKI::generate(GEN_FILE).expect("generate failed");
    assert!(std::path::Path::new(GEN_FILE).exists(), "jwks file should be created");

    let contents = fs::read_to_string(GEN_FILE).expect("read failed");
    let jwks: serde_json::Value = serde_json::from_str(&contents).expect("should be valid JSON");
    let arr = jwks.as_array().expect("should be array");
    assert_eq!(arr.len(), 4, "should have 4 keys");

    let ops: Vec<&str> = arr.iter()
        .flat_map(|k| k["key_ops"].as_array().into_iter().flatten())
        .filter_map(|v| v.as_str())
        .collect();
    assert!(ops.contains(&"sign"), "should have sign key");
    assert!(ops.contains(&"verify"), "should have verify key");
    assert!(ops.contains(&"encrypt"), "should have encrypt key");
    assert!(ops.contains(&"decrypt"), "should have decrypt key");
}

#[test]
fn test_generated_keys_work() {
    let pki = PKI::generate(GEN_FILE).expect("generate failed");
    let jwks_json = fs::read_to_string(GEN_FILE).expect("read failed");
    let jwks: Vec<serde_json::Value> = serde_json::from_str(&jwks_json).expect("parse failed");
    let pki2 = PKI::import_jwks(&jwks).expect("import failed");
    let sig = pki2.sign("Hello World").expect("sign failed");
    assert!(pki2.verify("Hello World", &sig).expect("verify failed"));
    // Also verify with original pki
    assert!(pki.verify("Hello World", &sig).expect("verify cross failed"));
}

#[test]
fn test_write_cross_lang_signature() {
    let pki = PKI::init(JWKS_FILE).expect("init failed");
    let sig = pki.sign("Hello World").expect("sign failed");
    let out = serde_json::json!({
        "lang": "rust",
        "message": "Hello World",
        "signature": sig
    });
    fs::write(SIG_OUT, serde_json::to_string(&out).unwrap()).expect("write failed");
    assert!(std::path::Path::new(SIG_OUT).exists());
}

#[test]
fn test_verify_cross_lang_signatures() {
    let pki = PKI::init(JWKS_FILE).expect("init failed");
    for lang in CROSS_LANGS {
        let path = format!("../fixtures/sig_{}.json", lang);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping {}: file not found", path);
            continue;
        }
        let contents = fs::read_to_string(&path).expect("read failed");
        let v: serde_json::Value = serde_json::from_str(&contents).expect("parse failed");
        let message = v["message"].as_str().expect("message field");
        let sig = v["signature"].as_str().expect("signature field");
        let result = pki.verify(message, sig).expect(&format!("verify failed for {}", lang));
        assert!(result, "cross-lang verification failed for {}", lang);
    }
}
