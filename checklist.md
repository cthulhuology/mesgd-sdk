# mesgd-sdk Implementation Checklist

This checklist tracks every required change and test for all language
implementations.  Check off each item as it is completed.  Items are grouped
by file; within each file, implementation tasks come before test tasks.

---

## Legend

- **[IMPL]** – implementation change required in the source file
- **[TEST]** – test case required in the corresponding test file
- **[COMPAT]** – cross-language interoperability fix
- **[NEW]** – new function / file that does not yet exist

---

## Infrastructure ✓ COMPLETE

- [x] Per-language directories: `erlang/`, `go/`, `python/`, `javascript/`, `ruby/`, `rust/`, `c/`, `cpp/`, `csharp/`, `haskell/`, `java/`, `lua/`, `ocaml/`, `perl/`, `swift/`, `forth/`, `php/`
- [x] Shared fixture directory `fixtures/` with `jwks.json` (stable) and `storage/` (JS LocalStorage)
- [x] `sig_*.json` and `test_*.json` excluded from git (regenerated each test run)
- [x] `.gitignore` covering beams, `__pycache__`, `node_modules/`, `rust/target/`, generated fixtures
- [x] `Makefile` with `deps`, `tests`, `clean` targets; `make clean && make tests` works from scratch
- [x] `deps-python` (pip + requirements.txt), `deps-javascript` (bun install + bun.lock), `deps-rust` (cargo fetch)
- [x] Cross-language interop verified: all 7 working languages sign and verify each other's fixtures (C added)

## Algorithm Constraints

All implementations must conform to algorithms that are natively available in the
browser **`crypto.subtle`** WebCrypto API, as that is the lowest common denominator
across the full language matrix:

| Operation | Algorithm | Parameters |
|-----------|-----------|------------|
| Sign / Verify | ECDSA | Curve P-256, digest SHA-256 |
| Encrypt / Decrypt | RSA-OAEP | 2048-bit key, hash SHA-256, MGF1 hash SHA-256 |
| Key format | JWK flat array | `use` + `key_ops` for key identification |
| Signature wire format | JSON `{"r":"<b64url>","s":"<b64url>"}` | 32-byte big-endian r and s |

WebCrypto RSA-OAEP uses SHA-256 for **both** the OAEP label hash and the MGF1 hash.
Every implementation must match this exactly to achieve cross-language interoperability.

## Cross-Language Interoperability (resolve before or alongside per-file work)

- [x] [COMPAT] Canonicalise ECDSA signature wire format to JWK-style JSON
      (`{"r":"<base64url>","s":"<base64url>"}`) across all implementations;
      done for Erlang, Python, JavaScript, Ruby, Rust, Go, C; others pending
- [x] [COMPAT] Verify that every implementation uses SHA-256 for both the OAEP
      digest **and** the MGF1 digest; done for Erlang, Python, JavaScript, Ruby, Rust, Go, C;
      PHP will use phpseclib 3.0 (native `OPENSSL_PKCS1_OAEP_PADDING` is hardwired to
      SHA-1 MGF1 and cannot interoperate)
- [x] [COMPAT] Verify that all JWK component values (x, y, d, n, e, p, q, dp, dq,
      qi) are encoded as base64url (no padding, `-` and `_` not `+` and `/`);
      done for Erlang, Python, JavaScript, Ruby, Rust, Go, C
- [x] [COMPAT] Verify that all implementations store keys as a flat JWK array
      (not a named dict); keys are identified by `use` (`"sig"` / `"enc"`) and
      `key_ops` (`["sign"]` / `["verify"]` / `["encrypt"]` / `["decrypt"]`);
      done for Erlang, Python, JavaScript, Ruby, Rust, Go, C

---

## Previously Planned (from original plan.md — included here for unified tracking)

### `pki.erl`
- [x] [IMPL] Add `generate/1` function
- [x] [IMPL] Fix typo in generate: `PrivS` → `PrivE` in returned tuple
- [x] [IMPL] Update `-export` list to include `generate/1`
- [x] [IMPL] Refactor `init/1` to call `generate(KeyFile)` instead of inlining key-gen
- [ ] [IMPL] Add MIT No Attribution license header

### `pki.go` ✓ COMPLETE
- [x] [IMPL] JWK JSON serialisation (no PEM, no gob); flat 4-key array
- [x] [IMPL] `ExportJWKS() []map[string]interface{}`
- [x] [IMPL] `ImportJWKS([]map[string]interface{}) (*PKI, error)` — handles both `[]string` and `[]interface{}` key_ops
- [x] [IMPL] `Generate(path string) (*PKI, error)`
- [x] [IMPL] `package pki`; `Sign` returns `{"r":"b64url","s":"b64url"}` JSON
- [x] [IMPL] `Verify` accepts that JSON
- [ ] [NEW]  Add `EncryptWith(pubJwk map[string]interface{}, msg string) (string, error)`
- [ ] [NEW]  Add `Register(mesgdPubJwk map[string]interface{}) (string, error)`

### `pki.py`
- [x] [IMPL] Replace `pickle` with `json` for storage
- [x] [IMPL] Replace PEM serialisation with JWK serialisation (all four keys)
- [x] [IMPL] Add `@classmethod export(cls)` returning JWK array
- [x] [IMPL] Add `@classmethod import_jwks(cls, jwks)`
- [x] [IMPL] Add `@classmethod generate(cls, path)`
- [x] [IMPL] Fix `CURVE = ec.SECP256R1` → `CURVE = ec.SECP256R1()`
- [x] [IMPL] Rename storage file to `pki_keys.json`
- [ ] [NEW]  Add `@classmethod encrypt_with(cls, pub_jwk, msg)`
- [ ] [NEW]  Add `@classmethod register(cls, mesgd_pub_jwk)`

### `pki.mjs`
- [x] [IMPL] Replace camelCase dict storage with a flat JWK array; add `use` field
      (`"sig"` / `"enc"`) to each exported JWK before saving
- [x] [IMPL] Replace named-key load with array scan: find each key by matching
      `use` + `key_ops` attributes (same discovery logic as the Erlang reference)
- [x] [IMPL] Update `sign()` to return `{"r":"<base64url>","s":"<base64url>"}` JSON
      (WebCrypto ECDSA returns P1363; split at 32 bytes, base64url-encode each half)
- [x] [IMPL] Update `verify()` to accept that JSON, reconstruct P1363, then verify
- [ ] [NEW]  Add `encryptWith(pubJwk, msg)`
- [ ] [NEW]  Add `register(mesgdPubJwk)`

### `erlang/test_pki.erl` ✓ COMPLETE
- [x] [IMPL] Change `?KEY_FILE` to `"test/fixtures/jwks.json"` (shared fixture)
- [x] [TEST] Add test for `generate/1` – file created, array of 4 JWKs with correct ops
- [x] [TEST] Add test for `export/4` – round-trip generate → import → sign → verify
- [x] [TEST] Cross-language signature write and verify tests

### `python/test_pki.py` ✓ COMPLETE
- [x] [IMPL] Remove duplicated inline `PKI` class; add `from pki import PKI`
- [x] [TEST] Round-trip sign/verify, encrypt/decrypt
- [x] [TEST] test_generate_creates_json_file – structural JSON check, array of 4
- [x] [TEST] test_generated_keys_work – import round-trip → sign → verify
- [x] [TEST] Cross-language signature write and verify

### `go/pki_test.go` ✓ COMPLETE — 7/7 passing
- [x] [IMPL] Uses shared fixture `../fixtures/jwks.json`; cross-lang tests included
- [x] [IMPL] `package pki_test`; imports `mesgd-sdk`
- [x] [TEST] Full 7-test suite: sign/verify roundtrip, signature JSON, encrypt/decrypt, generate, import roundtrip, write cross-lang sig, verify cross-lang sigs (erlang, python, javascript, ruby, rust)

---

## `pki.c` / `c/test_pki.c` ✓ COMPLETE

### Dependencies (resolved)
- **cJSON** — vendored into `3rd-party/cJSON/` (cJSON.c + cJSON.h)
- **Unity** — vendored into `3rd-party/unity/` (unity.c + unity.h + unity_internals.h)
- **OpenSSL 3.5.5** — system package; modern EVP API (`EVP_EC_gen`, `EVP_RSA_gen`,
  `OSSL_PARAM_BLD`, `EVP_PKEY_fromdata`); no deprecated EC_KEY/RSA direct APIs
- libwebsockets / libev deferred to mesgd WebSocket module (not needed for PKI)

### Implementation
- [x] [IMPL] Vendor cJSON into `3rd-party/cJSON/`; Unity into `3rd-party/unity/`
- [x] [IMPL] `b64url_enc` / `b64url_dec` helpers (BIO-based, URL-safe no padding)
- [x] [IMPL] `b64std_enc` / `b64std_dec` helpers (standard base64 for ciphertext)
- [x] [IMPL] JWK export: `jwk_ec_pub`, `jwk_ec_priv`, `jwk_rsa_pub`, `jwk_rsa_priv` via cJSON
- [x] [IMPL] JWK import: `import_ec_priv`, `import_rsa_priv` via `OSSL_PARAM_BLD` + `EVP_PKEY_fromdata`
- [x] [IMPL] `pki_generate` — `EVP_EC_gen("P-256")` + `EVP_RSA_gen(2048)`; writes JWK JSON
- [x] [IMPL] `pki_init` — loads from file or calls `pki_generate`
- [x] [IMPL] `pki_export` — serialises 4-key JWK array via cJSON
- [x] [IMPL] `pki_import` — parses JWK array; imports EC priv + RSA priv; derives pub keys
- [x] [IMPL] `pki_sign` — EVP_DigestSign → DER → ECDSA_SIG → r,s → base64url JSON
- [x] [IMPL] `pki_verify` — JSON → r,s → ECDSA_SIG_set0 → DER → EVP_DigestVerify
- [x] [IMPL] `pki_encrypt` / `pki_decrypt` — RSA-OAEP SHA-256/MGF1-SHA-256 via EVP_PKEY_CTX
- [x] [IMPL] `main()` guarded under `#ifdef PKI_DEMO`
- [x] [IMPL] `c/Makefile` — gcc, `-I../3rd-party/cJSON -I../3rd-party/unity`, `-lssl -lcrypto`

### Tests (`c/test_pki.c`) — 13 tests, 0 failures, 1 ignored (Go fixture absent at run time)
- [x] [TEST] `test_init_loads_shared_keys` — all four key pointers non-NULL
- [x] [TEST] `test_sign_verify_roundtrip` — sign "Hello World"; verify returns 1
- [x] [TEST] `test_verify_wrong_message_fails` — verify with wrong message returns 0
- [x] [TEST] `test_encrypt_decrypt_roundtrip` — plaintext recovered
- [x] [TEST] `test_generate_creates_file` — file written; non-empty JSON
- [x] [TEST] `test_export_import_roundtrip` — export → free → import → sign → verify
- [x] [TEST] `test_write_cross_lang_fixture` — writes `../fixtures/sig_c.json` with wrapper format
- [x] [TEST] `test_verify_erlang` / `test_verify_python` / `test_verify_javascript` / `test_verify_ruby` / `test_verify_rust` — all PASS
- [x] [TEST] `test_verify_go` — IGNORED (Go fixture written later in test order; will pass in full `make tests` run)

---

## `pki.cc` / `cpp/test_pki.cc`

### Dependencies
Shares all dependencies with the C implementation — libwebsockets, LibreSSL/OpenSSL, libev, cJSON.
Additionally:
- **nlohmann/json** — single-header C++ JSON library; vendor `nlohmann/json.hpp` into `cpp/`
- **Unity** — same Unity test framework as C (or Google Test if preferred; Unity is simpler to vendor)

### Implementation
- [ ] [IMPL] Vendor `nlohmann/json.hpp` into `cpp/`
- [ ] [IMPL] Fix EC public-key extraction (same fix as `pki.c`)
- [ ] [IMPL] Fix RSA key generation exponent (same fix as `pki.c`)
- [ ] [IMPL] Add `base64url_encode` / `base64url_decode` helpers (port directly from `pki.c`)
- [ ] [IMPL] Replace PEM-file storage with `pki_keys.json` using nlohmann/json + canonical JWK structure
- [ ] [IMPL] Add `PKI::generate(const std::string& path)`
- [ ] [IMPL] Add `PKI::exportJWK() -> nlohmann::json`
- [ ] [IMPL] Add `PKI::importJWK(const nlohmann::json&)`
- [ ] [NEW]  Add `PKI::encrypt_with(const nlohmann::json& pub_jwk, const std::string& msg)`
- [ ] [NEW]  Add `PKI::reg(const nlohmann::json& mesgd_pub_jwk)` (avoids reserved word)
- [ ] [IMPL] Wrap `main()` under `#ifdef PKI_DEMO`
- [ ] [IMPL] Add `Makefile` in `cpp/` sharing link flags with `c/Makefile`

### Tests (`cpp/test_pki.cc`)
- [ ] [NEW]  Create test file using Unity (consistent with C) or Google Test
- [ ] [TEST] `InitLoadsOrGeneratesKeys` – `pki.init()` leaves all four keys non-null
- [ ] [TEST] `SignVerifyRoundtrip` – sign/verify succeeds for same message
- [ ] [TEST] `VerifyWrongMessageFails` – verify with mutated message returns false
- [ ] [TEST] `EncryptDecryptRoundtrip` – plaintext recovered correctly
- [ ] [TEST] `ReInitPreservesKeys` – sign before init, reload from file, verify still passes
- [ ] [TEST] `ExportJWKStructure` – `exportJWK()` has four JWKs with correct `kty`
- [ ] [TEST] `ImportRoundtrip` – export → import into new instance → sign → verify
- [ ] [TEST] `GenerateCreatesFile` – `generate(path)` writes file; file parses as valid JSON
- [ ] [TEST] `WriteCrossLangSig` – write `../fixtures/sig_cpp.json`
- [ ] [TEST] `VerifyCrossLangSigs` – verify all passing language fixtures
- [ ] [TEST] Cleanup: delete `pki_keys.json` in teardown

---

## `pki.cs` / `csharp/PKITest.cs`

### Implementation
- [x] [IMPL] Add `using System.Text.Json`
- [x] [IMPL] Add `Base64UrlEncode` / `Base64UrlDecode` helpers
- [x] [COMPAT] Update `Sign()` to output `{"r":"<base64url>","s":"<base64url>"}` JSON
- [x] [COMPAT] Update `Verify()` to accept that JSON and reconstruct P1363 for verification
- [ ] [IMPL] Replace binary storage with `pki_keys.json` using canonical JWK structure
      (use `ECParameters.Q.X/Y`, `ECParameters.D`, `RSAParameters.Modulus/Exponent/…`)
- [ ] [IMPL] Add `public static Dictionary<string, object> Generate(string path)`
- [ ] [IMPL] Add `public static Dictionary<string, object> Export()`
- [ ] [IMPL] Add `public static void Import(Dictionary<string, object> jwkMap)`
- [ ] [NEW]  Add `public static string EncryptWith(string pubJwkJson, string message)`
- [ ] [NEW]  Add `public static string Register(string mesgdPubJwkJson)`
- [ ] [IMPL] Remove or conditionally compile `Program.Main()`

### Tests (`csharp/PKITest.cs`)
- [ ] [NEW]  Create xUnit or NUnit test class
- [ ] [TEST] `Init_LoadsOrGeneratesKeys` – `PKI.Init()` does not throw
- [ ] [TEST] `Sign_Verify_Roundtrip` – sign/verify succeeds
- [ ] [TEST] `Verify_WrongMessage_Fails` – returns false
- [ ] [TEST] `Encrypt_Decrypt_Roundtrip` – plaintext recovered
- [ ] [TEST] `ReInit_SameKeys` – sign before re-init; verify passes after re-init
- [ ] [TEST] `ECDSA_Signature_IsJSON` – `Sign()` returns valid JSON with `r` and `s` base64url fields
- [ ] [TEST] `Export_JWK_Structure` – four top-level keys present with correct `kty`
- [ ] [TEST] `Import_Roundtrip` – export → import → sign → verify
- [ ] [TEST] `Generate_CreatesFile` – file created at path; valid JSON
- [ ] [TEST] `EncryptWith_ForeignKey` – encrypt with exported pub JWK; original priv decrypts
- [ ] [TEST] `Register_ReturnsCiphertext` – non-empty base64 string
- [ ] [TEST] Cleanup: delete `pki_keys.json` in test teardown / `IDisposable`

---

## `pki.hs` / `haskell/PKISpec.hs`

### Implementation
- [ ] [IMPL] Replace `cryptonite` with `crypton` in cabal file
- [ ] [IMPL] Resolve all ambiguous import conflicts using qualified imports throughout
- [ ] [IMPL] Rewrite key generation using correct `crypton` API
      (`Crypto.PubKey.ECC.Generate.generate` with `MonadRandom`)
- [ ] [IMPL] Rewrite RSA key generation using `Crypto.PubKey.RSA.generate`
- [ ] [IMPL] Rewrite `sign` using correct `Crypto.PubKey.ECC.ECDSA.sign` API
- [ ] [IMPL] Rewrite `verify` using correct `Crypto.PubKey.ECC.ECDSA.verify` API
- [ ] [IMPL] Rewrite `encrypt` / `decrypt` using correct `Crypto.PubKey.RSA.OAEP` API
- [ ] [IMPL] Replace auto-derived Aeson instances with manual JWK serialisation using
      `Data.Aeson.object` / `(.=)`; encode `Integer` fields as base64url `ByteString`
- [ ] [IMPL] Replace `Marshal` storage with `Data.Aeson.encode` / `Data.Aeson.eitherDecode`
      writing `pki_keys.json`
- [ ] [IMPL] Add `generateKeys :: FilePath -> IO Keys`
- [ ] [IMPL] Add `exportJWK :: Keys -> Value`
- [ ] [IMPL] Add `importJWK :: Value -> Either String Keys`
- [ ] [NEW]  Add `encryptWith :: PublicKey -> ByteString -> IO ByteString`
- [ ] [NEW]  Add `register :: PublicKey -> Keys -> IO ByteString`

### Tests (`haskell/PKISpec.hs`)
- [ ] [NEW]  Create HSpec spec file
- [ ] [TEST] `initPKI loads or generates keys without error`
- [ ] [TEST] `sign then verify succeeds for same message`
- [ ] [TEST] `verify fails for wrong message`
- [ ] [TEST] `encrypt then decrypt recovers plaintext`
- [ ] [TEST] `re-init from file: verify pre-reload signature`
- [ ] [TEST] `exportJWK contains four keys with correct kty fields`
- [ ] [TEST] `importJWK round-trip: export → import → sign → verify`
- [ ] [TEST] `generateKeys writes valid JWK JSON file`
- [ ] [TEST] `encryptWith foreign key: owner can decrypt`
- [ ] [TEST] `register returns non-empty base64 ByteString`
- [ ] [TEST] Cleanup: remove `pki_keys.json` in `before/after` hooks

---

## `pki.java` / `java/PKITest.java` ← **next**

> JDK 23.0.2 installed at `/usr/lib64/jdk23-23.0.2` (`JAVA_HOME` on this system).
> A Kotlin implementation (`pki.kt`) will be added alongside this one; both use JCA
> and share the same algorithm constants. Java is done first as the reference; Kotlin ports it idiomatically.
> No existing `pki.java` yet — this is a fresh implementation.

### Dependencies
- **JDK 23** — `/usr/lib64/jdk23-23.0.2`; `JAVA_HOME` set system-wide
- **`org.json`** — JSON library; fetch via Maven or vendor the single JAR into `java/lib/`
- **JUnit 5** (`junit-jupiter`) — test framework; fetch via Maven or vendor JARs into `java/lib/`

### Implementation
- [ ] [NEW]  Create `java/pki.java` — `public class PKI` (static methods, module-level key fields)
- [ ] [IMPL] Add `bigIntToBase64url(BigInteger) -> String` helper
- [ ] [IMPL] Add `base64urlToBigInt(String) -> BigInteger` helper
- [ ] [IMPL] Add `bigIntToBase64url(BigInteger) -> String` helper
- [ ] [IMPL] Add `base64urlToBigInt(String) -> BigInteger` helper
- [ ] [COMPAT] Fix OAEP: replace `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"` with
      `"RSA/ECB/OAEPPadding"` + `OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,...)`
- [ ] [IMPL] Replace Java serialisation with `pki_keys.json` using canonical JWK structure
      (extract key components via `ECPublicKey.getW()`, `RSAPrivateCrtKey.getPrimeP()`, etc.)
- [ ] [IMPL] Add `public static Map<String, Object> generate(String path) throws Exception`
- [ ] [IMPL] Add `public static Map<String, Object> export() throws Exception`
- [ ] [IMPL] Add `public static void importKeys(Map<String, Object> jwk) throws Exception`
- [ ] [NEW]  Add `public static String encryptWith(Map<String, Object> pubJwk, String msg) throws Exception`
- [ ] [NEW]  Add `public static String register(Map<String, Object> mesgdPubJwk) throws Exception`
- [ ] [IMPL] Remove `main()` from production class (or move to a separate demo class)

### Tests (`java/PKITest.java`)
- [ ] [NEW]  Create JUnit 5 test class
- [ ] [TEST] `@Test initLoadsOrGeneratesKeys` – `PKI.init()` does not throw
- [ ] [TEST] `@Test signVerifyRoundtrip` – signed message verifies correctly
- [ ] [TEST] `@Test verifyWrongMessageFails` – returns false
- [ ] [TEST] `@Test encryptDecryptRoundtrip` – plaintext recovered
- [ ] [TEST] `@Test reInitPreservesKeys` – verify pre-reload signature after re-init
- [ ] [TEST] `@Test exportJWKStructure` – four top-level keys with correct `kty`
- [ ] [TEST] `@Test importRoundtrip` – export → import → sign → verify
- [ ] [TEST] `@Test generateCreatesFile` – file exists; valid JSON with four keys
- [ ] [TEST] `@Test oaepUsessha256Mgf1` – ciphertext length == key size (sanity check);
      (ideally cross-language round-trip test)
- [ ] [TEST] `@Test encryptWithForeignKey` – exported pub JWK; owner decrypts
- [ ] [TEST] `@Test registerReturnsCiphertext` – non-empty base64 string
- [ ] [TEST] `@BeforeEach` / `@AfterEach` cleanup: delete `pki_keys.json`

---

## `pki.kt` / `kotlin/test_pki.kt`

> Uses command-line Kotlin (`kotlinc`). Crypto via JCA — same algorithms and parameters
> as the Java implementation. Build with Gradle (single `build.gradle.kts` in `kotlin/`).
> Done immediately after Java; both share JAVA_HOME `/usr/lib64/jdk23-23.0.2`.

### Dependencies
- **JDK 23** — `/usr/lib64/jdk23-23.0.2`; same JVM as Java implementation
- **Kotlin compiler** (`kotlinc`) — command-line; verify `kotlinc -version` before starting
- **Gradle** — build tool; `./gradlew` wrapper committed to `kotlin/`
- **`org.json`** — JSON library (same choice as Java, added to `build.gradle.kts`)
- **JUnit 5** (`junit-jupiter`) — test framework; added to `build.gradle.kts`

### Implementation
- [ ] [NEW]  Create `kotlin/pki.kt` — `object PKI` with same interface as Java
- [ ] [IMPL] `fun init(keyFile: String)` – load or generate JWK file; store keys in object fields
- [ ] [IMPL] `fun generate(path: String)` – generate EC P-256 + RSA-2048 keys; write JWK JSON
- [ ] [IMPL] `fun sign(message: String): String` – ECDSA P-256 / SHA-256; return `{"r":…,"s":…}` JSON
- [ ] [IMPL] `fun verify(message: String, sigJson: String): Boolean` – reconstruct r,s; verify
- [ ] [IMPL] `fun encrypt(message: String): String` – RSA-OAEP SHA-256/MGF1-SHA-256; return base64
- [ ] [IMPL] `fun decrypt(ciphertextB64: String): String`
- [ ] [IMPL] `fun exportJwks(): List<Map<String, Any>>` – flat 4-element JWK array
- [ ] [IMPL] `fun importJwks(jwks: List<Map<String, Any>>)` – populate object keys from JWK array
- [ ] [COMPAT] Explicitly set `OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,…)`
      — same fix as Java to ensure SHA-256 MGF1
- [ ] [NEW]  Add `fun encryptWith(pubJwk: Map<String, Any>, message: String): String`
- [ ] [NEW]  Add `fun register(mesgdPubJwk: Map<String, Any>): String`
- [ ] [IMPL] Create `kotlin/build.gradle.kts` with deps and `test` task

### Tests (`kotlin/test_pki.kt`)
- [ ] [NEW]  Create `kotlin/test_pki.kt`; use JUnit 5 or kotlin.test
- [ ] [TEST] `initLoadsOrGeneratesKeys` – `PKI.init()` does not throw
- [ ] [TEST] `signVerifyRoundtrip` – signed message verifies correctly
- [ ] [TEST] `verifyWrongMessageFails` – returns false
- [ ] [TEST] `encryptDecryptRoundtrip` – plaintext recovered
- [ ] [TEST] `signatureIsJson` – `sign()` returns JSON with `r` and `s` base64url fields
- [ ] [TEST] `exportJwksStructure` – four keys with correct `kty`
- [ ] [TEST] `importRoundtrip` – export → import → sign → verify
- [ ] [TEST] `generateCreatesFile` – file exists at path; valid JSON with four keys
- [ ] [TEST] `writeCrossLangSig` – write `../fixtures/sig_kotlin.json`
- [ ] [TEST] `verifyCrossLangSigs` – verify all passing language fixtures
- [ ] `@BeforeEach` / `@AfterEach` cleanup: delete `pki_keys.json`

---

## `pki.lua` / `lua/test_pki.lua`

### Implementation
- [ ] [IMPL] Fix `PKI.init()`: replace all incorrect `openssl.*` calls with correct
      `lua-openssl` API (`pkey.read`, `pkey.new`, etc.)
- [ ] [IMPL] Fix `signing_priv.pubkey` → correct lua-openssl public-key extraction
- [ ] [IMPL] Fix `signing_priv:sign` / `signing_pub:verify` to use actual lua-openssl API
- [ ] [IMPL] Fix `encrypting_pub:encrypt` / `encrypting_priv:decrypt` to use actual API
      with OAEP + SHA-256
- [ ] [IMPL] Add `base64url_encode` / `base64url_decode` helpers
- [ ] [IMPL] Add JSON dependency (`require('lunajson')` or `require('dkjson')`)
- [ ] [IMPL] Replace four-PEM-file storage with `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Add `PKI.generate(path)` – generates keys, saves JWK JSON, returns key table
- [ ] [IMPL] Add `PKI.export()` – returns Lua table matching JWK structure
- [ ] [IMPL] Add `PKI.import(tbl)` – loads keys from JWK table
- [ ] [NEW]  Add `PKI.encrypt_with(pub_jwk_tbl, message)`
- [ ] [NEW]  Add `PKI.register(mesgd_pub_jwk_tbl)`

### Tests (`lua/test_pki.lua`)
- [ ] [NEW]  Create busted spec file (`describe` / `it` blocks)
- [ ] [TEST] `it("init generates or loads keys")` – `PKI.init()` leaves all four keys set
- [ ] [TEST] `it("sign/verify round-trip")` – sign "Hello World"; verify passes
- [ ] [TEST] `it("verify fails for wrong message")` – returns false/nil
- [ ] [TEST] `it("encrypt/decrypt round-trip")` – plaintext recovered
- [ ] [TEST] `it("re-init loads same keys")` – sign, re-init, verify pre-reload signature
- [ ] [TEST] `it("export returns JWK table")` – four expected keys; correct kty
- [ ] [TEST] `it("import round-trip")` – export → import → sign → verify
- [ ] [TEST] `it("generate creates JSON file")` – file at path; valid JSON
- [ ] [TEST] `it("encrypt_with foreign key")` – owner decrypts
- [ ] [TEST] `it("register returns ciphertext")` – non-empty base64 string
- [ ] [TEST] `before_each` / `after_each`: delete `pki_keys.json`

---

## `pki.ml` / `ocaml/test_pki.ml`

### Implementation
- [ ] [IMPL] Add `yojson` (or `ezjsonm`) and `base64` library dependencies to dune file
- [ ] [IMPL] Rewrite all `mirage-crypto-ec` calls using the correct current API
      (`Mirage_crypto_ec.P256.Dsa.generate`, `Mirage_crypto_ec.P256.Dsa.sign`,
      `Mirage_crypto_ec.P256.Dsa.verify`)
- [ ] [IMPL] Rewrite all `mirage-crypto-pk` RSA calls using the correct current API
- [ ] [IMPL] Fix `init()` exception handling: catch `Sys_error` for missing file, not `End_of_file`
- [ ] [IMPL] Store complete RSA key components (n, e, d, p, q, dp, dq, qi)
- [ ] [IMPL] Replace `Marshal` storage with `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Add `val generate : string -> (unit, string) result`
- [ ] [IMPL] Add `val export_jwk : unit -> Yojson.Safe.t`
- [ ] [IMPL] Add `val import_jwk : Yojson.Safe.t -> (unit, string) result`
- [ ] [NEW]  Add `val encrypt_with : Yojson.Safe.t -> string -> (string, string) result`
- [ ] [NEW]  Add `val register : Yojson.Safe.t -> (string, string) result`

### Tests (`ocaml/test_pki.ml`)
- [ ] [NEW]  Create Alcotest test file; add `alcotest` to dune dependencies
- [ ] [TEST] `"init generates or loads keys"` – `init()` does not raise
- [ ] [TEST] `"sign/verify round-trip"` – sign then verify same message returns `true`
- [ ] [TEST] `"verify fails for wrong message"` – returns `false`
- [ ] [TEST] `"encrypt/decrypt round-trip"` – plaintext recovered
- [ ] [TEST] `"re-init loads same keys"` – sign, call init again, verify pre-init signature
- [ ] [TEST] `"export_jwk structure"` – JSON has four top-level keys; kty values correct
- [ ] [TEST] `"import_jwk round-trip"` – export → import → sign → verify
- [ ] [TEST] `"generate creates file"` – file exists at path; valid JSON
- [ ] [TEST] `"encrypt_with foreign key"` – owner decrypts
- [ ] [TEST] `"register returns ciphertext"` – non-empty base64 string
- [ ] [TEST] `setup` / `teardown`: remove `pki_keys.json`

---

## `pki.php` / `php/test_pki.php`

### Dependencies
- **phpseclib 3.0** — required for correct RSA-OAEP with SHA-256 MGF1; native PHP
  `OPENSSL_PKCS1_OAEP_PADDING` hardwires MGF1 to SHA-1 and cannot interoperate with other
  implementations or with browser `crypto.subtle`; install via Composer
- **PHPUnit** — test framework; install via Composer

### Implementation
- [ ] [IMPL] Add `composer.json` with `phpseclib/phpseclib: ^3.0` and `phpunit/phpunit` deps
- [ ] [IMPL] Add `declare(strict_types=1)` and `<?php` header; set minimum PHP to 8.0
- [ ] [IMPL] Add `base64url_encode(string) -> string` helper
- [ ] [IMPL] Add `base64url_decode(string) -> string` helper
- [ ] [COMPAT] Replace all OpenSSL encrypt/decrypt with phpseclib `RSA` configured for
      OAEP + SHA-256 hash + SHA-256 MGF1 (`$rsa->withHash('sha256')->withMGFHash('sha256')`)
- [ ] [IMPL] Replace `serialize()` / `unserialize()` with `json_encode()` / `json_decode()`
      writing `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Implement JWK serialisation: use phpseclib `EC`/`RSA` key export for component extraction
- [ ] [IMPL] Add `public static function generate(string $path): array`
- [ ] [IMPL] Add `public static function export(): array`
- [ ] [IMPL] Add `public static function import(array $jwk): void`
- [ ] [NEW]  Add `public static function encryptWith(array $pubJwk, string $message): string`
- [ ] [NEW]  Add `public static function register(array $mesgdPubJwk): string`
- [ ] [IMPL] Guard top-level usage code with `if (PHP_SAPI === 'cli')` block

### Tests (`php/test_pki.php`)
- [ ] [NEW]  Create PHPUnit test class extending `PHPUnit\Framework\TestCase`
- [ ] [TEST] `testInitLoadsOrGeneratesKeys` – `PKI::init()` does not throw
- [ ] [TEST] `testSignVerifyRoundtrip` – sign/verify returns true
- [ ] [TEST] `testVerifyWrongMessageFails` – returns false
- [ ] [TEST] `testEncryptDecryptRoundtrip` – plaintext recovered
- [ ] [TEST] `testReInitPreservesKeys` – sign before re-init; verify after re-init
- [ ] [TEST] `testExportJWKStructure` – array contains four keys with correct `kty`
- [ ] [TEST] `testImportRoundtrip` – export → import → sign → verify
- [ ] [TEST] `testGenerateCreatesFile` – file at path; valid JSON
- [ ] [TEST] `testWriteCrossLangSig` – write `../fixtures/sig_php.json`
- [ ] [TEST] `testVerifyCrossLangSigs` – verify all passing language fixtures
- [ ] [TEST] `setUp` / `tearDown`: delete `pki_keys.json`

---

## `pki.pl` / `perl/test_pki.t`

### Implementation
- [ ] [IMPL] Replace `Storable` with `JSON::PP` (or `JSON::XS`) for `pki_keys.json`
- [ ] [IMPL] Replace `Crypt::OpenSSL::EC` usage with `Crypt::Perl::ECDSA`
      (or the correct `Crypt::OpenSSL::EC` API) for P-256 key generation and sign/verify
- [ ] [IMPL] Implement JWK serialisation for EC keys using bignum-to-bytes conversion
- [ ] [IMPL] Add `base64url_encode` / `base64url_decode` helpers
- [ ] [COMPAT] Fix `Crypt::OpenSSL::RSA`: call `use_pkcs1_oaep_padding()` and
      `use_sha256_hash()` before encrypt/decrypt; verify MGF1 is also SHA-256
- [ ] [IMPL] Fix double-hash in `sign()`: do not pre-hash if ECDSA implementation hashes internally
- [ ] [IMPL] Add `PKI::generate($path)`
- [ ] [IMPL] Add `PKI::export()` returning hashref of JWK fields
- [ ] [IMPL] Add `PKI::import(\%jwk)`
- [ ] [NEW]  Add `PKI::encrypt_with(\%pub_jwk, $message)`
- [ ] [NEW]  Add `PKI::register(\%mesgd_pub_jwk)`

### Tests (`perl/test_pki.t`)
- [ ] [NEW]  Create Test::More test file
- [ ] [TEST] `ok(init(), 'init succeeds')`
- [ ] [TEST] Sign/verify round-trip passes
- [ ] [TEST] Verify wrong message fails
- [ ] [TEST] Encrypt/decrypt round-trip recovers plaintext
- [ ] [TEST] Re-init preserves keys (pre-reload signature still verifies)
- [ ] [TEST] Export returns hashref with four JWK keys and correct `kty`
- [ ] [TEST] Import round-trip: export → import → sign → verify
- [ ] [TEST] Generate creates valid JWK JSON file at path
- [ ] [TEST] `encrypt_with` with foreign key: owner decrypts
- [ ] [TEST] `register` returns non-empty base64 string
- [ ] [TEST] Cleanup: `unlink 'pki_keys.json'` at start and end of test file

---

## `pki.rb` / `ruby/test_pki.rb`

### Implementation
- [x] [IMPL] Replace `Marshal.dump` / `Marshal.load` with `JSON.dump` / `JSON.parse`
      writing `pki_keys.json` using canonical JWK structure
- [x] [IMPL] Implement JWK serialisation for EC/RSA keys via OpenSSL::ASN1 DER helpers
- [x] [IMPL] Fix double-encrypt bug in `self.encrypt`
- [x] [COMPAT] Use `OpenSSL::PKey::RSA#encrypt(msg)` with explicit OAEP SHA-256 opts
- [x] [COMPAT] MGF1 hash is SHA-256 via `rsa_mgf1_md` OAEP option
- [x] [IMPL] Use `OpenSSL::PKey::EC.generate(CURVE)` (Ruby 3.x)
- [x] [IMPL] Add `PKI.generate(path)` – generates keys, saves JWK JSON
- [x] [IMPL] Add `PKI._export_jwk_array` / `_load_jwk_array`
- [ ] [NEW]  Add `PKI.encrypt_with(pub_jwk_hash, message)`
- [ ] [NEW]  Add `PKI.register(mesgd_pub_jwk_hash)`

### Tests (`ruby/test_pki.rb`)
- [x] [IMPL] `require_relative '../pki'`; `setup` calls `PKI.init(JWKS_FILE)`
- [x] [TEST] sign/verify roundtrip, encrypt/decrypt roundtrip
- [x] [TEST] generate creates JSON file (structural check)
- [x] [TEST] generated keys work (import round-trip)
- [x] [TEST] write cross-lang signature; verify cross-lang signatures
- [ ] [TEST] Add `test_encrypt_with`
- [ ] [TEST] Add `test_register`

---

## `pki.rs` / `tests/test_pki.rs` ✓ COMPLETE

### Implementation
- [x] [COMPAT] Fix OAEP SHA-256: uses `PkeyCtx` + `set_rsa_oaep_md(Md::sha256())` + `set_rsa_mgf1_md(Md::sha256())`; `Padding::PKCS1_OAEP`
- [x] [IMPL] Add Cargo.toml; set `[lib] path = "pki.rs"`
- [x] [IMPL] Add `b64url_enc` / `b64url_dec` helpers (URL_SAFE_NO_PAD engine)
- [x] [IMPL] JWK flat-array serialisation (4 keys: EC pub/priv, RSA pub/priv)
- [x] [IMPL] `sign()` outputs `{"r":"b64url","s":"b64url"}` JSON via EcdsaSig DER parse
- [x] [IMPL] `verify()` accepts that JSON, reconstructs DER for verification
- [x] [IMPL] `pub fn generate(path: &str) -> Result<Self, Box<dyn Error>>`
- [x] [IMPL] `pub fn import_jwks(jwks: &[Value]) -> Result<Self, Box<dyn Error>>`
- [ ] [NEW]  Add `pub fn encrypt_with` / `pub fn register`

### Tests (`rust/tests/test_pki.rs`) — 7/7 passing
- [x] [NEW]  Integration test file (`rust/tests/test_pki.rs`)
- [x] [TEST] sign/verify roundtrip
- [x] [TEST] signature is JSON with r and s fields
- [x] [TEST] encrypt/decrypt roundtrip
- [x] [TEST] generate creates JSON file (structural check, 4 keys, correct ops)
- [x] [TEST] generated keys work (import roundtrip)
- [x] [TEST] write cross-lang signature (`fixtures/sig_rust.json`)
- [x] [TEST] verify cross-lang signatures (Erlang, Python, JavaScript, Ruby, Go)

---

## `pki.swift` / `swift/PKITests.swift`

### Implementation
- [ ] [IMPL] Remove `import CryptoKit` RSA usage; add `import Security` for RSA operations
- [ ] [IMPL] Rename `static func init()` → `static func setup() throws` (reserved word)
- [ ] [IMPL] Add `base64urlEncode(_ data: Data) -> String` helper
- [ ] [IMPL] Add `base64urlDecode(_ string: String) -> Data?` helper
- [ ] [IMPL] Replace `RSA.PrivateKey` / `RSA.PrivateKey(jsonWebKey:)` with `SecKey`
      created via `SecKeyCreateRandomKey` with `kSecAttrKeyTypeRSA`, `kSecAttrKeySizeInBits: 2048`
- [ ] [IMPL] Fix `fileURL`: use `URL(fileURLWithPath: FileManager.default.currentDirectoryPath)`
      for server/CLI portability
- [ ] [IMPL] Fix ECDSA signature conversion: use `P256.Signing.ECDSASignature(rawRepresentation:)`
      when constructing from `Data`; validate signature type in `verify()`
- [ ] [IMPL] Implement JWK export for EC: extract x/y from `P256.Signing.PrivateKey.publicKey
      .x963Representation`; encode as base64url
- [ ] [IMPL] Implement JWK export for RSA: use `SecKeyCopyExternalRepresentation` and parse
      DER to extract n, e, d, p, q, dp, dq, qi components; encode as base64url
- [ ] [IMPL] Replace `StoredKeys` Codable struct with JWK-structured `[String: Any]` storage
- [ ] [IMPL] Add `static func setup() throws` (was `init()`)
- [ ] [IMPL] Add `static func generate(path: URL) throws`
- [ ] [IMPL] Add `static func exportJWK() throws -> [String: Any]`
- [ ] [IMPL] Add `static func importJWK(_ jwk: [String: Any]) throws`
- [ ] [NEW]  Add `static func encryptWith(_ pubJwk: [String: Any], message: String) throws -> String`
- [ ] [NEW]  Add `static func register(_ mesgdPubJwk: [String: Any]) throws -> String`
- [ ] [IMPL] Add package comment documenting Linux RSA limitation (requires COpenSSL)

### Tests (`swift/PKITests.swift`)
- [ ] [NEW]  Create XCTest test class
- [ ] [TEST] `testSetupLoadsOrGeneratesKeys` – `PKI.setup()` does not throw
- [ ] [TEST] `testSignVerifyRoundtrip` – sign/verify succeeds
- [ ] [TEST] `testVerifyWrongMessageFails` – returns false
- [ ] [TEST] `testEncryptDecryptRoundtrip` – plaintext recovered
- [ ] [TEST] `testReSetupPreservesKeys` – sign before re-setup; verify after
- [ ] [TEST] `testExportJWKStructure` – dict has four keys; kty values correct
- [ ] [TEST] `testImportRoundtrip` – export → import → sign → verify
- [ ] [TEST] `testGenerateCreatesFile` – file at path; valid JSON
- [ ] [TEST] `testEncryptWithForeignKey` – owner decrypts
- [ ] [TEST] `testRegisterReturnsCiphertext` – non-empty base64 string
- [ ] [TEST] `override func setUp()` / `override func tearDown()`: remove `pki_keys.json`

---

## `pki.f` / `forth/test_pki.f`

> JWK export/import and the `register` workflow are **out of scope** for the Forth
> implementation.  This section covers the working-demo level target only.

### Implementation
- [ ] [IMPL] Fix `RSA_PKCS1_OAEP_PADDING` declaration: use `c-value` or literal `4` instead
      of `c-function`
- [ ] [IMPL] Fix `RSA_generate_key_ex` FFI: correct arity and add `BN_new`/`BN_set_word`
      for the exponent BIGNUM argument
- [ ] [IMPL] Add `BN_new` / `BN_set_word` / `BN_free` FFI declarations
- [ ] [IMPL] Add `BIO_new_file` / `PEM_write_bio_RSAPrivateKey` / `PEM_read_bio_RSAPrivateKey`
      FFI declarations for PEM key persistence
- [ ] [IMPL] Implement `rsa-init` word: try to load key from `pki_keys.pem`; generate and
      save if absent
- [ ] [IMPL] Fix `encrypt` / `decrypt` words to use the persisted key from `rsa-init`
      rather than generating a new key on every call
- [ ] [IMPL] Add ECDSA skeleton words using `EVP_PKEY_keygen`, `EVP_DigestSignInit`,
      `EVP_DigestSignUpdate`, `EVP_DigestSignFinal`
- [ ] [IMPL] Add `sign ( addr u -- sig-addr u )` word
- [ ] [IMPL] Add `verify ( msg-addr u sig-addr u -- flag )` word
- [ ] [IMPL] Add prominent header comment documenting that JWK, export, import,
      `encrypt_with`, and `register` are out of scope for the Forth implementation

### Tests (`forth/test_pki.f`)
- [ ] [NEW]  Create test file with custom `ASSERT` / `ASSERT-EQUAL` words
- [ ] [TEST] `rsa-init` – completes without aborting; subsequent call loads same key
- [ ] [TEST] `encrypt` then `decrypt` – recovered plaintext matches input
- [ ] [TEST] `sign` – produces non-empty output for "Hello World"
- [ ] [TEST] `verify` – verifies signature produced by `sign` for same message
- [ ] [TEST] `verify` – fails for mutated message

---

## New Shared Modules (`mesgd.*`)

These are new files to be created in each language (referenced in the original plan).

### `mesgd.mjs` / `mesgd.go` / `mesgd.py` / `mesgd.erl` (and all other languages except Forth)
- [ ] [NEW]  Bundle or fetch known mesgd server public encryption key
- [ ] [NEW]  `connect(url)` – opens a WebSocket connection
- [ ] [NEW]  `send(ws, recipient_pub_jwk, plaintext)` – signs + encrypts to recipient, sends
- [ ] [NEW]  `receive(ws, on_message_cb)` – decrypts incoming messages, verifies sender signature

### Tests for mesgd modules
- [ ] [TEST] Unit test: `send` + `receive` loopback with a single key pair (sign self, send, decrypt/verify)
- [ ] [TEST] Unit test: `receive` rejects tampered ciphertext
- [ ] [TEST] Unit test: `receive` rejects bad signature
- [ ] [TEST] Integration test: connect to a mock WebSocket echo server

---

## Summary Count

**Working (full test suite + cross-lang interop):** Erlang · Python · JavaScript · Ruby · Rust · Go · C — 56/56 tests

| Language | Status | Remaining open items |
|----------|--------|----------------------|
| Erlang | ✓ done | license header |
| Go | ✓ done | `EncryptWith`, `Register` |
| Python | ✓ done | `encrypt_with`, `register` |
| JavaScript | ✓ done | `encryptWith`, `register` |
| Ruby | ✓ done | `encrypt_with`, `register`, 2 tests |
| Rust | ✓ done | `encrypt_with`, `register` |
| C | ✓ done | `pki_encrypt_with`, `pki_register`; libwebsockets deferred to mesgd module |
| Java | ← next | fresh impl — JDK 23 @ `/usr/lib64/jdk23-23.0.2`, org.json, JUnit 5 |
| Kotlin | ← next | after Java — kotlinc, same JVM, Gradle, JUnit 5 |
| PHP | pending | full rewrite with phpseclib 3.0 |
| C++ | pending | rewrite shares C deps + nlohmann/json |
| C# | pending | JWK storage, Generate/Export/Import, tests |
| Haskell | pending | full rewrite (crypton, Aeson) |
| Lua | pending | full rewrite (lua-openssl, dkjson, busted) |
| OCaml | pending | full rewrite (mirage-crypto, yojson, alcotest) |
| Perl | pending | full rewrite (Crypt::Perl, JSON::PP) |
| Swift | pending | full rewrite (Security framework, XCTest) |
| Forth | pending | demo-level only (no JWK/register) |
| mesgd modules | pending | WebSocket connect/send/receive for all langs |
