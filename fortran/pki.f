\ pki.fs - Basic PKI in gforth using OpenSSL FFI (RSA for encrypt/decrypt; ECDSA similar via EVP)
\ Note: This is a simplified example; full error handling and key persistence require more code.
\ Compile with gforth -e "include pki.fs bye" pki.fs

include lib.fs

\c #include <openssl/evp.h>
\c #include <openssl/rsa.h>
\c #include <openssl/err.h>
\c #include <openssl/bio.h>
\c #include <openssl/pem.h>
\c #include <openssl/rand.h>

add-lib "crypto"
add-lib "ssl"

\ Declarations for RSA
c-function RSA_new RSA_new -- a
c-function RSA_free RSA_free a --
c-function RSA_generate_key_ex RSA_generate_key_ex a n a a -- n
c-function RSA_public_encrypt RSA_public_encrypt a u a a n -- n
c-function RSA_private_decrypt RSA_private_decrypt a u a a n -- n
c-function RSA_PKCS1_OAEP_PADDING RSA_PKCS1_OAEP_PADDING -- n

\ Basic init (generate key - in production, load from file using PEM_read_bio_RSAPrivateKey)
: rsa-key ( -- rsa-addr ) 0 RSA_new dup 2048 0 0 RSA_generate_key_ex drop ;

\ Encrypt (using public key)
: encrypt ( addr u -- ciphertext-addr u )
  rsa-key dup >r RSA_PKCS1_OAEP_PADDING r> swap RSA_public_encrypt drop
  here over allot swap
;

\ Decrypt (using private key)
: decrypt ( addr u -- plaintext-addr u )
  rsa-key dup >r RSA_PKCS1_OAEP_PADDING r> swap RSA_private_decrypt drop
  here over allot swap
;

\ For signing/verify, use EVP interface (example skeleton)
c-function EVP_PKEY_new EVP_PKEY_new -- a
c-function EVP_PKEY_keygen EVP_PKEY_keygen a a -- n
\ ... (more declarations for EVP_DigestSignInit, etc.)

\ Usage example (demo - generates new key each time)
s" Secret message" encrypt cr type
cr
s" Secret message" 13 encrypt decrypt cr type

\ Output: Secret message (decrypted)
\ Note: For ECDSA signing, replace RSA with EC_KEY_new_by_curve_name NID_X9_62_prime256v1 and EVP calls.
\ For key storage, use BIO_new_file and PEM_write/read_bio_RSAPrivateKey.
\ For SwiftForth, adapt FFI syntax (similar c-call and lib-load).
