#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define FILE_NAME "pki_keys.pem"
#define CURVE_NAME NID_X9_62_prime256v1
#define RSA_BITS 2048
#define RSA_PADDING RSA_PKCS1_OAEP_PADDING
#define HASH_ALG "SHA256"

static EVP_PKEY *signing_priv = NULL;
static EVP_PKEY *signing_pub = NULL;
static EVP_PKEY *encrypting_priv = NULL;
static EVP_PKEY *encrypting_pub = NULL;

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int base64_encode(const unsigned char *input, int input_len, unsigned char **output) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    *output = NULL;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, input_len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    *output = (unsigned char *)malloc(buffer_ptr->length + 1);
    memcpy(*output, buffer_ptr->data, buffer_ptr->length);
    (*output)[buffer_ptr->length] = '\0';
    BIO_free_all(bio);
    return buffer_ptr->length;
}

int base64_decode(const unsigned char *input, int input_len, unsigned char **output) {
    BIO *bio, *b64;
    *output = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input, input_len);
    bio = BIO_push(b64, bio);
    *output = (unsigned char *)malloc(input_len);
    int decoded_len = BIO_read(bio, *output, input_len);
    BIO_free_all(bio);
    (*output)[decoded_len] = '\0';
    return decoded_len;
}

void init_pki(void) {
    FILE *file = fopen(FILE_NAME, "r");
    if (file) {
        signing_priv = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        signing_pub = PEM_read_PUBKEY(file, NULL, NULL, NULL);
        encrypting_priv = PEM_read_PrivateKey(file, NULL, NULL, NULL);
        encrypting_pub = PEM_read_PUBKEY(file, NULL, NULL, NULL);
        fclose(file);
        if (!signing_priv || !signing_pub || !encrypting_priv || !encrypting_pub) {
            handle_errors();
        }
        return;
    }

    // Generate keys
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(CURVE_NAME);
    if (!EC_KEY_generate_key(ec_key)) handle_errors();
    signing_priv = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(signing_priv, ec_key);
    signing_pub = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(signing_pub, signing_priv);
    EVP_PKEY_derive_init(EVP_PKEY_CTX_new(signing_priv, NULL));

    RSA *rsa_key = RSA_new();
    if (!RSA_generate_key_ex(rsa_key, RSA_BITS, NULL, NULL)) handle_errors();
    encrypting_priv = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(encrypting_priv, rsa_key);
    encrypting_pub = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(encrypting_pub, encrypting_priv);

    // Write to file
    file = fopen(FILE_NAME, "w");
    if (!file) handle_errors();
    if (!PEM_write_PrivateKey(file, signing_priv, NULL, NULL, 0, NULL, NULL)) handle_errors();
    if (!PEM_write_PUBKEY(file, signing_pub)) handle_errors();
    if (!PEM_write_PrivateKey(file, encrypting_priv, NULL, NULL, 0, NULL, NULL)) handle_errors();
    if (!PEM_write_PUBKEY(file, encrypting_pub)) handle_errors();
    fclose(file);
}

char* sign(const char *message) {
    if (!signing_priv) init_pki();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, signing_priv);
    size_t sig_len = 0;
    EVP_DigestSignUpdate(mdctx, message, strlen(message));
    EVP_DigestSignFinal(mdctx, NULL, &sig_len);
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSignFinal(mdctx, sig, &sig_len);
    EVP_MD_CTX_free(mdctx);
    unsigned char *b64;
    base64_encode(sig, sig_len, &b64);
    free(sig);
    return (char*)b64;
}

int verify(const char *message, const char *signature_b64) {
    if (!signing_pub) init_pki();
    unsigned char *sig;
    int sig_len = base64_decode((unsigned char*)signature_b64, strlen(signature_b64), &sig);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, signing_pub);
    EVP_DigestVerifyUpdate(mdctx, message, strlen(message));
    int res = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    EVP_MD_CTX_free(mdctx);
    free(sig);
    return res == 1;
}

char* encrypt(const char *message) {
    if (!encrypting_pub) init_pki();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(encrypting_pub, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char*)message, strlen(message));
    unsigned char *out = malloc(outlen);
    EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char*)message, strlen(message));
    EVP_PKEY_CTX_free(ctx);
    unsigned char *b64;
    base64_encode(out, outlen, &b64);
    free(out);
    return (char*)b64;
}

char* decrypt(const char *ciphertext_b64) {
    if (!encrypting_priv) init_pki();
    unsigned char *cipher;
    int cipher_len = base64_decode((unsigned char*)ciphertext_b64, strlen(ciphertext_b64), &cipher);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(encrypting_priv, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, cipher, cipher_len);
    unsigned char *out = malloc(outlen);
    EVP_PKEY_decrypt(ctx, out, &outlen, cipher, cipher_len);
    EVP_PKEY_CTX_free(ctx);
    free(cipher);
    char *result = malloc(outlen + 1);
    memcpy(result, out, outlen);
    result[outlen] = '\0';
    free(out);
    return result;
}

int main() {
    init_pki();
    char *sig = sign("Hello World");
    printf("Signature: %s\n", sig);
    printf("Verify: %d\n", verify("Hello World", sig));
    free(sig);
    char *enc = encrypt("Secret message");
    printf("Encrypted: %s\n", enc);
    char *dec = decrypt(enc);
    printf("Decrypted: %s\n", dec);
    free(enc);
    free(dec);
    return 0;
}
