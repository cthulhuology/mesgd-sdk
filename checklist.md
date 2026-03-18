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

## Cross-Language Interoperability (resolve before or alongside per-file work)

- [x] [COMPAT] Canonicalise ECDSA signature wire format to JWK-style JSON
      (`{"r":"<base64url>","s":"<base64url>"}`) across all implementations;
      C# done — remaining implementations still output DER or raw P1363
- [x] [COMPAT] Verify that every implementation uses SHA-256 for both the OAEP
      digest **and** the MGF1 digest; Java, Ruby, Rust fixed; PHP has no native
      solution — `OPENSSL_PKCS1_OAEP_PADDING` is hardwired to SHA-1 MGF1;
      requires phpseclib 3.0 for true interoperability (documented in pki.php)
- [ ] [COMPAT] Verify that all JWK component values (x, y, d, n, e, p, q, dp, dq,
      qi) are encoded as base64url (no padding, `-` and `_` not `+` and `/`)
- [ ] [COMPAT] Verify that all implementations store keys as a flat JWK array
      (not a named dict); keys are identified by `use` (`"sig"` / `"enc"`) and
      `key_ops` (`["sign"]` / `["verify"]` / `["encrypt"]` / `["decrypt"]`);
      update `pki.mjs` which currently uses a camelCase dict

---

## Previously Planned (from original plan.md — included here for unified tracking)

### `pki.erl`
- [ ] [IMPL] Add `generate/1` function
- [ ] [IMPL] Fix typo in generate: `PrivS` → `PrivE` in returned tuple
- [ ] [IMPL] Update `-export` list to include `generate/1`
- [ ] [IMPL] Refactor `init/0` to call `generate(?KEY_FILE)` instead of inlining key-gen
- [ ] [IMPL] Add MIT No Attribution license header

### `pki.go`
- [ ] [IMPL] Remove `encoding/pem` usage; replace with JWK JSON serialisation
- [ ] [IMPL] Change storage file from `pki_keys.gob` to `pki_keys.json`
- [ ] [IMPL] Add `Export() map[string]interface{}`
- [ ] [IMPL] Add `Import(map[string]interface{}) error`
- [ ] [IMPL] Expand `PKI` struct to hold `signingPub` and `encryptingPub`
- [ ] [IMPL] Add `Generate(path string)` function
- [ ] [IMPL] Remove `main()`
- [ ] [IMPL] Change `package main` to `package pki`
- [ ] [NEW]  Add `EncryptWith(pubJwk map[string]interface{}, msg string) (string, error)`
- [ ] [NEW]  Add `Register(mesgdPubJwk map[string]interface{}) (string, error)`

### `pki.py`
- [ ] [IMPL] Replace `pickle` with `json` for storage
- [ ] [IMPL] Replace PEM serialisation with JWK serialisation (all four keys)
- [ ] [IMPL] Add `@classmethod export(cls)` returning JWK dict
- [ ] [IMPL] Add `@classmethod import_keys(cls, jwk_dict)`
- [ ] [IMPL] Add `@classmethod generate(cls, path)`
- [ ] [IMPL] Fix `CURVE = ec.SECP256R1` → `CURVE = ec.SECP256R1()`
- [ ] [IMPL] Rename storage file to `pki_keys.json`
- [ ] [NEW]  Add `@classmethod encrypt_with(cls, pub_jwk, msg)`
- [ ] [NEW]  Add `@classmethod register(cls, mesgd_pub_jwk)`

### `pki.mjs`
- [ ] [IMPL] Replace camelCase dict storage with a flat JWK array; add `use` field
      (`"sig"` / `"enc"`) to each exported JWK before saving
- [ ] [IMPL] Replace named-key load with array scan: find each key by matching
      `use` + `key_ops` attributes (same discovery logic as the Erlang reference)
- [ ] [IMPL] Update `sign()` to return `{"r":"<base64url>","s":"<base64url>"}` JSON
      (WebCrypto ECDSA returns P1363; split at 32 bytes, base64url-encode each half)
- [ ] [IMPL] Update `verify()` to accept that JSON, reconstruct P1363, then verify
- [ ] [NEW]  Add `encryptWith(pubJwk, msg)`
- [ ] [NEW]  Add `register(mesgdPubJwk)`

### `test/test_pki.erl`
- [ ] [IMPL] Change `?KEY_FILE` to `"test/storage/pki_keys.bin"` to match module under test
- [ ] [TEST] Add test for `generate/1` – verify tuple is `{PubS, PrivS, PubE, PrivE}`
- [ ] [TEST] Add test for `export/1` – verify map contains four JWK keys with correct `kty`
- [ ] [TEST] Add test for `import/1` – round-trip export → import reproduces original keys

### `test/test_pki.py`
- [ ] [IMPL] Remove duplicated inline `PKI` class; add `from pki import PKI`
- [ ] [IMPL] Add `setUp` / `tearDown` that deletes and recreates the key file
- [ ] [TEST] Add test for `export()` – dict contains four keys with correct `kty`
- [ ] [TEST] Add test for `import_keys()` – round-trip export → import → sign → verify
- [ ] [TEST] Add test for `generate()` – file created at path; valid JSON with four keys
- [ ] [TEST] Replace fragile file-size test with structural JSON check

### `test/pki_test.go`
- [ ] [IMPL] Fix re-init test: verify old signature with reloaded key instead of
      comparing signature bytes
- [ ] [IMPL] Update `package main` to match `pki.go` package name
- [ ] [IMPL] Add `TestMain` or setup/teardown removing `pki_keys.json`
- [ ] [TEST] Add test for `Export()` and `Import()` round-trips
- [ ] [TEST] Add test for `EncryptWith()`
- [ ] [TEST] Add test for `Register()`

---

## `pki.c` / `test/test_pki.c`

### Implementation
- [ ] [IMPL] Add `base64url_encode(buf, len) -> char*` helper (replaces `+/` with `-_`, strips `=`)
- [ ] [IMPL] Add `base64url_decode(str) -> {buf, len}` helper
- [ ] [IMPL] Add `cJSON` (or equivalent) dependency for JSON serialisation
- [ ] [IMPL] Fix EC public-key extraction: use `EVP_PKEY_get1_EC_KEY` + `EC_KEY_get0_public_key`
      to correctly populate `signing_pub`
- [ ] [IMPL] Fix `RSA_generate_key_ex`: pass a `BIGNUM` set to `RSA_F4` (65537) as the exponent
- [ ] [IMPL] Replace PEM-file storage with `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Add `pki_generate(const char *path)` – generates keys, writes JWK JSON
- [ ] [IMPL] Add `pki_export(char **out_json)` – serialises current keys to JWK JSON string
- [ ] [IMPL] Add `pki_import(const char *json)` – parses JWK JSON into module-level key pointers
- [ ] [NEW]  Add `pki_encrypt_with(const char *pub_jwk_json, const char *msg, char **out_b64)`
- [ ] [NEW]  Add `pki_register(const char *mesgd_pub_jwk_json, char **out_b64)`
- [ ] [IMPL] Wrap `main()` under `#ifdef PKI_DEMO`

### Tests (`test/test_pki.c`)
- [ ] [NEW]  Create test file; add `#include` for Unity or custom `ASSERT` macros
- [ ] [TEST] `test_init` – `pki_init()` succeeds; key pointers are non-NULL
- [ ] [TEST] `test_sign_verify` – sign "Hello World"; verify returns 1
- [ ] [TEST] `test_verify_wrong_msg` – verify with different message returns 0
- [ ] [TEST] `test_encrypt_decrypt` – round-trip returns original plaintext
- [ ] [TEST] `test_init_twice` – second `pki_init()` loads same keys (sign before and after, verify both)
- [ ] [TEST] `test_export` – `pki_export()` returns JSON with `signing_pub`, `signing_priv`,
      `encrypting_pub`, `encrypting_priv`; verify `kty` fields
- [ ] [TEST] `test_import_roundtrip` – export JSON, `pki_import()` into fresh state, sign/verify succeeds
- [ ] [TEST] `test_generate` – `pki_generate(path)` writes valid JWK JSON file at `path`
- [ ] [TEST] `test_encrypt_with` – encrypt with exported pub JWK; original priv can decrypt
- [ ] [TEST] `test_register` – `pki_register()` returns non-empty base64 ciphertext
- [ ] [TEST] Cleanup: delete `pki_keys.json` in test teardown

---

## `pki.cc` / `test/test_pki.cc`

### Implementation
- [ ] [IMPL] Fix `PEM_read_PrivateKey` / `PEM_read_PUBKEY` calls: replace `std::ifstream` usage
      with `FILE*` (use `fopen` / `BIO_new_file` / `BIO_new_mem_buf`)
- [ ] [IMPL] Fix EC public-key extraction (same as `pki.c`)
- [ ] [IMPL] Fix `RSA_generate_key_ex` exponent argument (same as `pki.c`)
- [ ] [IMPL] Add `nlohmann/json` single-header for JSON serialisation
- [ ] [IMPL] Add `base64url_encode` / `base64url_decode` helpers
- [ ] [IMPL] Replace PEM-file storage with `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Add `PKIImpl::generate(const std::string& path)`
- [ ] [IMPL] Add `PKIImpl::exportJWK() -> nlohmann::json`
- [ ] [IMPL] Add `PKIImpl::importJWK(const nlohmann::json&)`
- [ ] [NEW]  Add `PKIImpl::encrypt_with(const nlohmann::json& pub_jwk, const std::string& msg)`
- [ ] [NEW]  Add `PKIImpl::reg(const nlohmann::json& mesgd_pub_jwk)` (avoids reserved word)
- [ ] [IMPL] Wrap `main()` under `#ifdef PKI_DEMO`

### Tests (`test/test_pki.cc`)
- [ ] [NEW]  Create test file; add Google Test (`gtest`) dependency
- [ ] [TEST] `InitLoadsOrGeneratesKeys` – `impl.init()` leaves all four keys non-null
- [ ] [TEST] `SignVerifyRoundtrip` – sign/verify succeeds for same message
- [ ] [TEST] `VerifyWrongMessageFails` – verify with mutated message returns false
- [ ] [TEST] `EncryptDecryptRoundtrip` – plaintext recovered correctly
- [ ] [TEST] `ReInitPreservesKeys` – sign before init, reload from file, verify still passes
- [ ] [TEST] `ExportJWKStructure` – `exportJWK()` contains expected four top-level keys with correct `kty`
- [ ] [TEST] `ImportRoundtrip` – export → import into new instance → sign → verify
- [ ] [TEST] `GenerateCreatesFile` – `generate(path)` writes file; file parses as valid JSON
- [ ] [TEST] `EncryptWithForeignKey` – encrypt with exported pub JWK; original priv decrypts
- [ ] [TEST] `RegisterReturnsCiphertext` – non-empty base64 string returned
- [ ] [TEST] Cleanup: delete `pki_keys.json` in `TearDown`

---

## `pki.cs` / `test/PKITest.cs`

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

### Tests (`test/PKITest.cs`)
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

## `pki.hs` / `test/PKISpec.hs`

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

### Tests (`test/PKISpec.hs`)
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

## `pki.java` / `test/PKITest.java`

### Implementation
- [ ] [IMPL] Remove unused imports (`EncryptedPrivateKeyInfo`, `SecretKeyFactory`,
      `PBEKeySpec`, `PBEParameterSpec`)
- [ ] [IMPL] Add JSON library dependency (`org.json` or `com.google.gson`)
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

### Tests (`test/PKITest.java`)
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

## `pki.lua` / `test/test_pki.lua`

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

### Tests (`test/test_pki.lua`)
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

## `pki.ml` / `test/test_pki.ml`

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

### Tests (`test/test_pki.ml`)
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

## `pki.php` / `test/PKITest.php`

### Implementation
- [ ] [IMPL] Add `declare(strict_types=1)` and `<?php` header; set minimum PHP to 8.0
- [ ] [IMPL] Add `base64url_encode(string) -> string` helper
- [ ] [IMPL] Add `base64url_decode(string) -> string` helper
- [ ] [COMPAT] Replace `openssl_public_encrypt` / `openssl_private_decrypt` with
      `openssl_pkey_encrypt` / `openssl_pkey_decrypt` using explicit SHA-256 MGF1 options
- [ ] [IMPL] Replace `serialize()` / `unserialize()` with `json_encode()` / `json_decode()`
      writing `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Implement JWK serialisation using `openssl_pkey_get_details()` plus base64url
- [ ] [IMPL] Add `public static function generate(string $path): array`
- [ ] [IMPL] Add `public static function export(): array`
- [ ] [IMPL] Add `public static function import(array $jwk): void`
- [ ] [NEW]  Add `public static function encryptWith(array $pubJwk, string $message): string`
- [ ] [NEW]  Add `public static function register(array $mesgdPubJwk): string`
- [ ] [IMPL] Guard top-level usage code with `if (PHP_SAPI === 'cli')` block

### Tests (`test/PKITest.php`)
- [ ] [NEW]  Create PHPUnit test class extending `PHPUnit\Framework\TestCase`
- [ ] [TEST] `testInitLoadsOrGeneratesKeys` – `PKI::init()` does not throw
- [ ] [TEST] `testSignVerifyRoundtrip` – sign/verify returns true
- [ ] [TEST] `testVerifyWrongMessageFails` – returns false
- [ ] [TEST] `testEncryptDecryptRoundtrip` – plaintext recovered
- [ ] [TEST] `testReInitPreservesKeys` – sign before re-init; verify after re-init
- [ ] [TEST] `testExportJWKStructure` – array contains four keys with correct `kty`
- [ ] [TEST] `testImportRoundtrip` – export → import → sign → verify
- [ ] [TEST] `testGenerateCreatesFile` – file at path; valid JSON
- [ ] [TEST] `testEncryptWithForeignKey` – owner decrypts
- [ ] [TEST] `testRegisterReturnsCiphertext` – non-empty string
- [ ] [TEST] `setUp` / `tearDown`: delete `pki_keys.json`

---

## `pki.pl` / `test/test_pki.t`

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

### Tests (`test/test_pki.t`)
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

## `pki.rb` / `test/test_pki.rb`

### Implementation
- [ ] [IMPL] Replace `Marshal.dump` / `Marshal.load` with `JSON.dump` / `JSON.parse`
      writing `pki_keys.json` using canonical JWK structure
- [ ] [IMPL] Implement JWK serialisation for EC keys (extract x/y from `public_key.to_bn`,
      d from `private_key`) and RSA keys (`priv.params` hash)
- [ ] [IMPL] Fix double-encrypt bug in `self.encrypt` (remove the first redundant call)
- [ ] [COMPAT] Replace deprecated `public_encrypt(msg, PKCS1_OAEP_PADDING)` with
      `OpenSSL::PKey::RSA#encrypt(msg)` using explicit OAEP SHA-256 options (openssl gem 3.0+)
- [ ] [COMPAT] Ensure MGF1 hash is SHA-256 (not SHA-1) for interoperability
- [ ] [IMPL] Replace `OpenSSL::PKey::EC.new(CURVE).generate_key` with
      `OpenSSL::PKey::EC.generate(CURVE)` (Ruby 3.x)
- [ ] [IMPL] Add `PKI.generate(path)` – generates keys, saves JWK JSON
- [ ] [IMPL] Add `PKI.export` – returns Hash matching JWK structure
- [ ] [IMPL] Add `PKI.import(jwk_hash)` – loads keys from JWK hash
- [ ] [NEW]  Add `PKI.encrypt_with(pub_jwk_hash, message)`
- [ ] [NEW]  Add `PKI.register(mesgd_pub_jwk_hash)`

### Tests (`test/test_pki.rb`) — update existing file
- [ ] [IMPL] Remove inline PKI module duplication at top of existing test file;
      add `require_relative '../pki'`
- [ ] [IMPL] Add `teardown` that deletes `pki_keys.json` after each test
- [ ] [IMPL] Add `setup` that calls `PKI.init` fresh
- [ ] [TEST] Existing `test_sign_verify` – keep; ensure it imports real module
- [ ] [TEST] Existing `test_encrypt_decrypt` – keep; update if API changes
- [ ] [TEST] Replace `test_init_twice` file-size check with JSON structural check
- [ ] [TEST] Add `test_export` – Hash contains four keys with correct `kty`
- [ ] [TEST] Add `test_import_roundtrip` – export → import → sign → verify
- [ ] [TEST] Add `test_generate` – file created; valid JSON with four keys
- [ ] [TEST] Add `test_encrypt_with` – foreign pub JWK; owner decrypts
- [ ] [TEST] Add `test_register` – non-empty base64 string

---

## `pki.rs` / `test/pki_test.rs` (or `#[cfg(test)]` inline)

### Implementation
- [ ] [IMPL] Convert to library crate: rename to `src/lib.rs`; move demo to `src/main.rs`
- [ ] [IMPL] Add `base64url_encode` / `base64url_decode` helpers using `base64` crate
      `URL_SAFE_NO_PAD` engine
- [ ] [IMPL] Update all `base64::encode` / `base64::decode` calls to new
      `base64::engine::general_purpose` API
- [ ] [COMPAT] Fix OAEP SHA-256: replace `Rsa::public_encrypt(..., Padding::OAEP, ...)`
      with `openssl::pkey_ctx::PkeyCtx` + `set_rsa_oaep_md(sha256)` + `set_rsa_mgf1_md(sha256)`
- [ ] [IMPL] Replace PEM-string JSON with JWK serialisation: extract EC point coordinates
      and RSA `BigNum` components; encode as base64url; use `serde_json::Value`
- [ ] [IMPL] Change storage file name from current to `pki_keys.json` and update `Keys` struct
      to hold JWK fields directly (or serialise on write / deserialise on read)
- [ ] [IMPL] Add `pub fn generate(path: &str) -> Result<PKI, Box<dyn Error>>`
- [ ] [IMPL] Add `pub fn export(&self) -> Result<serde_json::Value, Box<dyn Error>>`
- [ ] [IMPL] Add `pub fn import_jwk(jwk: &serde_json::Value) -> Result<Self, Box<dyn Error>>`
- [ ] [NEW]  Add `pub fn encrypt_with(pub_jwk: &serde_json::Value, msg: &str) -> Result<String, Box<dyn Error>>`
- [ ] [NEW]  Add `pub fn register(mesgd_pub_jwk: &serde_json::Value) -> Result<String, Box<dyn Error>>`

### Tests (inline `#[cfg(test)]` in `src/lib.rs` or `tests/pki_test.rs`)
- [ ] [NEW]  Add test module / integration test file
- [ ] [TEST] `test_init` – `PKI::init()` returns `Ok(pki)` with all fields populated
- [ ] [TEST] `test_sign_verify` – sign/verify round-trip returns `Ok(true)`
- [ ] [TEST] `test_verify_wrong_message` – returns `Ok(false)`
- [ ] [TEST] `test_encrypt_decrypt` – plaintext recovered
- [ ] [TEST] `test_reinit_same_keys` – sign before reinit; verify after reinit
- [ ] [TEST] `test_export_jwk_structure` – Value has four top-level keys; kty correct
- [ ] [TEST] `test_import_roundtrip` – export → import → sign → verify
- [ ] [TEST] `test_generate_creates_file` – file exists; valid JSON
- [ ] [TEST] `test_encrypt_with_foreign_key` – owner decrypts
- [ ] [TEST] `test_register_returns_ciphertext` – non-empty base64 string
- [ ] [TEST] Use `#[test]` setup/teardown or `tempdir` crate to isolate key files

---

## `pki.swift` / `test/PKITests.swift`

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

### Tests (`test/PKITests.swift`)
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

## `pki.f` / `test/test_pki.f`

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

### Tests (`test/test_pki.f`)
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

| Category | Total items |
|----------|-------------|
| Cross-language interop fixes | 4 |
| pki.erl + tests (original) | 8 |
| pki.go + tests (original) | 12 |
| pki.py + tests (original) | 12 |
| pki.mjs (original) | 3 |
| pki.c + tests | 18 |
| pki.cc + tests | 18 |
| pki.cs + tests | 18 |
| pki.hs + tests | 20 |
| pki.java + tests | 19 |
| pki.lua + tests | 20 |
| pki.ml + tests | 20 |
| pki.php + tests | 18 |
| pki.pl + tests | 18 |
| pki.rb + tests | 20 |
| pki.rs + tests | 18 |
| pki.swift + tests | 22 |
| pki.f + tests | 14 |
| mesgd modules + tests | 7 |
| **Total** | **299** |
