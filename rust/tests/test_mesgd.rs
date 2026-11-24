use mesgd_pki::PKI;
use serde_json::{json, Value};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

const JWKS_FILE: &str = "../fixtures/jwks.json";
static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp(tag: &str) -> String {
    format!(
        "../fixtures/test_mesgd_{}_{}.json",
        tag,
        SEQ.fetch_add(1, Ordering::SeqCst)
    )
}

#[test]
fn test_two_party_encrypt() {
    let alice_path = tmp("alice");
    let bob_path = tmp("bob");
    let alice = PKI::generate(&alice_path).expect("alice");
    let alice_pub = alice.pub_jwk().expect("pub");
    let _bob = PKI::generate(&bob_path).expect("bob");
    let ct = PKI::encrypt_with(&alice_pub, "secret from bob").expect("encrypt_with");
    let alice2 = PKI::init(&alice_path).expect("init alice");
    assert_eq!(alice2.decrypt(&ct).expect("decrypt"), "secret from bob");
    let _ = fs::remove_file(&alice_path);
    let _ = fs::remove_file(&bob_path);
}

#[test]
fn test_signed_encrypted_message() {
    let alice_path = tmp("alice");
    let bob_path = tmp("bob");
    let alice = PKI::generate(&alice_path).expect("alice");
    let alice_pub = alice.pub_jwk().expect("pub");
    let bob = PKI::generate(&bob_path).expect("bob");
    let plain = "ping";
    let sig = bob.sign(plain).expect("sign");
    let envelope = json!({"payload": plain, "signature": sig}).to_string();
    let ct = PKI::encrypt_with(&alice_pub, &envelope).expect("encrypt_with");
    let alice2 = PKI::init(&alice_path).expect("init");
    let opened: Value = serde_json::from_str(&alice2.decrypt(&ct).expect("decrypt")).unwrap();
    assert_eq!(opened["payload"].as_str().unwrap(), plain);
    let ok = PKI::check_with_pub(&alice_pub, opened["payload"].as_str().unwrap(), opened["signature"].as_str().unwrap()).expect("vwp");
    assert!(!ok, "alice pub should not verify bob signature");
    assert!(bob.check(plain, &sig).expect("bob verify"));
    let _ = fs::remove_file(&alice_path);
    let _ = fs::remove_file(&bob_path);
}

#[test]
fn test_compact_register_envelope() {
    let alice_path = tmp("alice");
    let mesgd = PKI::init(JWKS_FILE).expect("mesgd");
    let mesgd_pub = mesgd.pub_jwk().expect("mesgd pub");
    let alice = PKI::generate(&alice_path).expect("alice");
    let payload = json!({"name": "alice"}).to_string();
    let sig = alice.sign(&payload).expect("sign");
    let envelope = json!({"payload": payload, "signature": sig}).to_string();
    let ct = PKI::encrypt_with(&mesgd_pub, &envelope).expect("encrypt_with");
    let alice_pub = alice.pub_jwk().expect("alice pub");
    let opened: Value = serde_json::from_str(&mesgd.decrypt(&ct).expect("decrypt")).unwrap();
    let inner: Value = serde_json::from_str(opened["payload"].as_str().unwrap()).unwrap();
    assert_eq!(inner["name"].as_str().unwrap(), "alice");
    assert!(PKI::check_with_pub(&alice_pub, opened["payload"].as_str().unwrap(), opened["signature"].as_str().unwrap()).expect("vwp"));
    let _ = fs::remove_file(&alice_path);
}

#[test]
fn test_live_register_auth_message() {
    if std::env::var("MESGD_URL").is_err() {
        return;
    }
    panic!("mesgd HTTP JWK registration is not wired yet");
}
