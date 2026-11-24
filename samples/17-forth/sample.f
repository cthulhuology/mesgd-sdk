\ mesgd-sdk Forth Local PKI Demo
\ ==================================
\ NOTE: WebSocket connectivity is OUT OF SCOPE for the Forth implementation.
\ There are no standard Forth libraries for JSON encoding/decoding or base64url,
\ both of which are required by the mesgd JWK wire format and WebSocket protocol.
\ This sample demonstrates LOCAL PKI operations only:
\   - Key generation (RSA-2048 via OpenSSL FFI)
\   - Sign and verify a test message (ECDSA P-256 via EVP)
\   - Encrypt and decrypt a test message (RSA-OAEP)
\
\ For a full WebSocket ping/pong echo test, use any other language sample.
\ See plan.md section "pki.f" for the rationale.
\
\ Run: gforth sample.f
\ Requirements: gforth 0.7.3+, OpenSSL 3.x shared library in LD_LIBRARY_PATH

include lib.fs    \ gforth C interface helpers

\ ---------------------------------------------------------------------------
\ OpenSSL FFI declarations
\ ---------------------------------------------------------------------------

\ EVP high-level interface (preferred over deprecated RSA_* / EC_* functions)
\c #include <openssl/evp.h>
\c #include <openssl/ec.h>
\c #include <openssl/rsa.h>
\c #include <openssl/pem.h>
\c #include <openssl/err.h>
\c #include <openssl/bio.h>
\c #include <openssl/bn.h>
\c #include <openssl/rand.h>

add-lib "crypto"
add-lib "ssl"

\ Memory management
c-function EVP_PKEY_free        EVP_PKEY_free        a -- void
c-function EVP_MD_CTX_new       EVP_MD_CTX_new       -- a
c-function EVP_MD_CTX_free      EVP_MD_CTX_free      a -- void
c-function EVP_PKEY_CTX_new     EVP_PKEY_CTX_new     a a -- a
c-function EVP_PKEY_CTX_free    EVP_PKEY_CTX_free    a -- void

\ EC key generation (ECDSA P-256 for signing)
c-function EVP_PKEY_CTX_new_id  EVP_PKEY_CTX_new_id  n a -- a
c-function EVP_PKEY_keygen_init EVP_PKEY_keygen_init a -- n
c-function EVP_PKEY_CTX_set_ec_paramgen_curve_nid EVP_PKEY_CTX_set_ec_paramgen_curve_nid a n -- n
c-function EVP_PKEY_keygen      EVP_PKEY_keygen      a a -- n

\ RSA key generation (RSA-2048 for encryption)
c-function EVP_PKEY_CTX_new_from_name EVP_PKEY_CTX_new_from_name a a a -- a
c-function EVP_PKEY_CTX_set_rsa_keygen_bits EVP_PKEY_CTX_set_rsa_keygen_bits a n -- n

\ Digest signing (ECDSA)
c-function EVP_DigestSignInit   EVP_DigestSignInit   a a a a a -- n
c-function EVP_DigestSignUpdate EVP_DigestSignUpdate a a u -- n
c-function EVP_DigestSignFinal  EVP_DigestSignFinal  a a a -- n

\ Digest verify (ECDSA)
c-function EVP_DigestVerifyInit   EVP_DigestVerifyInit   a a a a a -- n
c-function EVP_DigestVerifyUpdate EVP_DigestVerifyUpdate a a u -- n
c-function EVP_DigestVerifyFinal  EVP_DigestVerifyFinal  a a u -- n

\ RSA OAEP encrypt/decrypt via PKEY context
c-function EVP_PKEY_encrypt_init EVP_PKEY_encrypt_init a -- n
c-function EVP_PKEY_encrypt      EVP_PKEY_encrypt      a a a a u -- n
c-function EVP_PKEY_decrypt_init EVP_PKEY_decrypt_init a -- n
c-function EVP_PKEY_decrypt      EVP_PKEY_decrypt      a a a a u -- n
c-function EVP_PKEY_CTX_set_rsa_padding EVP_PKEY_CTX_set_rsa_padding a n -- n
c-function EVP_PKEY_CTX_set_rsa_oaep_md EVP_PKEY_CTX_set_rsa_oaep_md a a -- n

\ Hash algorithms
c-function EVP_sha256 EVP_sha256 -- a

\ Error reporting
c-function ERR_print_errors_fp ERR_print_errors_fp a -- void

\ NID constants for named curves
4 constant NID_EVP_PKEY_EC   \ EVP_PKEY_EC = 408 in OpenSSL 3.x; use literal or query
408 constant EVP_PKEY_EC_NID
912 constant NID_X9_62_prime256v1   \ secp256r1 NID
4   constant RSA_PKCS1_OAEP_PADDING  \ integer value of the OAEP padding constant

\ ---------------------------------------------------------------------------
\ Key storage (module-level variables)
\ ---------------------------------------------------------------------------
variable signing-priv-pkey   0 signing-priv-pkey !
variable encrypting-priv-pkey 0 encrypting-priv-pkey !

\ ---------------------------------------------------------------------------
\ generate-signing-key  ( -- )
\ Generate an ECDSA P-256 signing key pair and store in signing-priv-pkey
\ ---------------------------------------------------------------------------
: generate-signing-key ( -- )
    EVP_PKEY_EC_NID 0 EVP_PKEY_CTX_new_id dup 0= if
        2drop stderr ERR_print_errors_fp  abort" EVP_PKEY_CTX_new_id failed"
    then
    dup EVP_PKEY_keygen_init drop
    dup NID_X9_62_prime256v1 EVP_PKEY_CTX_set_ec_paramgen_curve_nid drop
    here 0 ,                        \ allocate space for the output PKEY pointer
    dup >r swap EVP_PKEY_keygen drop \ generate into *here
    r> @  signing-priv-pkey !
    EVP_PKEY_CTX_free ;

\ ---------------------------------------------------------------------------
\ generate-encrypting-key  ( -- )
\ Generate an RSA-2048 encryption key pair and store in encrypting-priv-pkey
\ ---------------------------------------------------------------------------
: generate-encrypting-key ( -- )
    s" RSA" drop 0 0 EVP_PKEY_CTX_new_from_name dup 0= if
        drop stderr ERR_print_errors_fp  abort" EVP_PKEY_CTX_new_from_name failed"
    then
    dup EVP_PKEY_keygen_init drop
    dup 2048 EVP_PKEY_CTX_set_rsa_keygen_bits drop
    here 0 ,
    dup >r swap EVP_PKEY_keygen drop
    r> @  encrypting-priv-pkey !
    EVP_PKEY_CTX_free ;

\ ---------------------------------------------------------------------------
\ pki-init  ( -- )
\ Generate both key pairs (key persistence omitted — see note in plan.md)
\ ---------------------------------------------------------------------------
: pki-init ( -- )
    generate-signing-key
    generate-encrypting-key ;

\ ---------------------------------------------------------------------------
\ pki-sign  ( addr u -- sig-addr sig-u )
\ ECDSA-sign a message using signing-priv-pkey; return raw DER signature bytes
\ ---------------------------------------------------------------------------
: pki-sign ( addr u -- sig-addr sig-u )
    EVP_MD_CTX_new dup 0= if drop abort" EVP_MD_CTX_new failed" then
    >r                              \ save mdctx on return stack
    r@ 0 EVP_sha256 0 signing-priv-pkey @ EVP_DigestSignInit 1 <> if
        r> EVP_MD_CTX_free  abort" EVP_DigestSignInit failed"
    then
    2dup r@ -rot EVP_DigestSignUpdate 1 <> if
        r> EVP_MD_CTX_free  abort" EVP_DigestSignUpdate failed"
    then
    r@ 0 here EVP_DigestSignFinal drop  \ get size
    here @ allocate throw               \ allocate output buffer
    >r
    r@ 0 r@ here EVP_DigestSignFinal 1 <> if
        r> free drop  r> EVP_MD_CTX_free  abort" EVP_DigestSignFinal failed"
    then
    r> swap drop                        \ sig-addr
    here @                              \ sig-u
    r> EVP_MD_CTX_free ;

\ ---------------------------------------------------------------------------
\ pki-verify  ( msg-addr msg-u sig-addr sig-u -- flag )
\ flag = -1 (true) if signature is valid, 0 otherwise
\ ---------------------------------------------------------------------------
: pki-verify ( msg-addr msg-u sig-addr sig-u -- flag )
    2>r
    EVP_MD_CTX_new dup 0= if 2r> 2drop drop abort" EVP_MD_CTX_new failed" then
    >r
    r@ 0 EVP_sha256 0 signing-priv-pkey @ EVP_DigestVerifyInit 1 <> if
        2r> 2drop  r> EVP_MD_CTX_free  0 exit
    then
    2dup r@ -rot EVP_DigestVerifyUpdate drop
    2r> r@ -rot EVP_DigestVerifyFinal   \ 1 = valid, 0 or negative = invalid
    r> EVP_MD_CTX_free
    1 = ;                               \ return Forth boolean (-1 / 0)

\ ---------------------------------------------------------------------------
\ pki-encrypt  ( addr u -- ct-addr ct-u )
\ RSA-OAEP-SHA256 encrypt using encrypting-priv-pkey's public component
\ ---------------------------------------------------------------------------
: pki-encrypt ( addr u -- ct-addr ct-u )
    2>r
    encrypting-priv-pkey @ EVP_PKEY_CTX_new dup 0= if
        2r> 2drop abort" EVP_PKEY_CTX_new failed"
    then
    >r
    r@ EVP_PKEY_encrypt_init drop
    r@ RSA_PKCS1_OAEP_PADDING EVP_PKEY_CTX_set_rsa_padding drop
    r@ EVP_sha256 EVP_PKEY_CTX_set_rsa_oaep_md drop
    \ First call: get output size
    r@ 0 here 2r@ EVP_PKEY_encrypt drop
    here @ allocate throw
    >r
    r@ 0 r@ here 2r> EVP_PKEY_encrypt 1 <> if
        r> free drop  r> EVP_PKEY_CTX_free  abort" EVP_PKEY_encrypt failed"
    then
    r> swap drop          \ ct-addr
    here @                \ ct-u
    r> EVP_PKEY_CTX_free ;

\ ---------------------------------------------------------------------------
\ pki-decrypt  ( ct-addr ct-u -- pt-addr pt-u )
\ ---------------------------------------------------------------------------
: pki-decrypt ( ct-addr ct-u -- pt-addr pt-u )
    2>r
    encrypting-priv-pkey @ EVP_PKEY_CTX_new dup 0= if
        2r> 2drop abort" EVP_PKEY_CTX_new failed"
    then
    >r
    r@ EVP_PKEY_decrypt_init drop
    r@ RSA_PKCS1_OAEP_PADDING EVP_PKEY_CTX_set_rsa_padding drop
    r@ EVP_sha256 EVP_PKEY_CTX_set_rsa_oaep_md drop
    r@ 0 here 2r@ EVP_PKEY_decrypt drop
    here @ allocate throw
    >r
    r@ 0 r@ here 2r> EVP_PKEY_decrypt 1 <> if
        r> free drop  r> EVP_PKEY_CTX_free  abort" EVP_PKEY_decrypt failed"
    then
    r> swap drop
    here @
    r> EVP_PKEY_CTX_free ;

\ ---------------------------------------------------------------------------
\ Demo: run 3 rounds of local sign/verify/encrypt/decrypt
\ ---------------------------------------------------------------------------
cr ." === mesgd-sdk Forth Local PKI Demo ===" cr cr
." NOTE: WebSocket support is out of scope for Forth." cr
."       This demo exercises local cryptographic operations only." cr cr

." Initialising PKI (generating ECDSA P-256 + RSA-2048 keys) ..." cr
pki-init
." Keys generated." cr cr

s" Hello from mesgd-sdk! Forth demo" 2constant TEST-MSG

3 0 do
    i 1 + ." Round " . ." :" cr

    \ Sign
    TEST-MSG pki-sign 2constant SIG
    ."  Signed    : OK (DER signature, " SIG nip . ." bytes)" cr

    \ Verify
    TEST-MSG SIG pki-verify
    if ."  Verified  : OK" cr
    else ."  Verified  : FAILED" cr  bye
    then

    \ Encrypt
    TEST-MSG pki-encrypt 2constant CT
    ."  Encrypted : OK (" CT nip . ." bytes)" cr

    \ Decrypt
    CT pki-decrypt 2constant PT
    ."  Decrypted : " PT type cr

    \ Check round-trip
    TEST-MSG drop  PT drop  PT nip  str=
    if ."  Match     : OK" cr
    else ."  Match     : FAILED" cr  bye
    then cr
loop

." All 3 rounds completed successfully." cr cr
." (WebSocket ping/pong not available in Forth - see samples/01-python/ etc.)" cr
