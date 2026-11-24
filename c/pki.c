/*
 * pki.c — PKI implementation for mesgd-sdk
 *
 * Keys:    EC P-256 (sign/verify) + RSA-2048 (encrypt/decrypt)
 * Storage: flat JWK array in pki_keys.json
 * Sign:    ECDSA SHA-256  →  {"r":"<b64url>","s":"<b64url>"}
 * Encrypt: RSA-OAEP, hash=SHA-256, MGF1=SHA-256  →  standard base64
 *
 * Requires OpenSSL 3.x and cJSON.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include "cJSON.h"

/* ── module-level key storage ─────────────────────────────────────── */

static EVP_PKEY *signing_priv    = NULL;
static EVP_PKEY *signing_pub     = NULL;
static EVP_PKEY *encrypting_priv = NULL;
static EVP_PKEY *encrypting_pub  = NULL;

/* ── base64 helpers ────────────────────────────────────────────────── */

/* base64url: no padding, '-' and '_' instead of '+' and '/' */
static char *b64url_enc(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM *buf;
    BIO_get_mem_ptr(b64, &buf);
    size_t buf_len = buf->length;
    char *out = malloc(buf_len + 1);
    memcpy(out, buf->data, buf_len);
    out[buf_len] = '\0';
    BIO_free_all(b64);
    /* standard → url-safe, strip padding */
    for (size_t i = 0; i < buf_len; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    size_t olen = strlen(out);
    while (olen > 0 && out[olen - 1] == '=') out[--olen] = '\0';
    return out;
}

static uint8_t *b64url_dec(const char *str, size_t *out_len) {
    size_t len = strlen(str);
    size_t pad = (4 - len % 4) % 4;
    char *b64 = malloc(len + pad + 1);
    memcpy(b64, str, len);
    for (size_t i = 0; i < len; i++) {
        if (b64[i] == '-') b64[i] = '+';
        else if (b64[i] == '_') b64[i] = '/';
    }
    for (size_t i = 0; i < pad; i++) b64[len + i] = '=';
    b64[len + pad] = '\0';
    BIO *b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new_mem_buf(b64, (int)(len + pad));
    BIO_push(b64bio, mem);
    uint8_t *out = malloc(len + pad);
    *out_len = (size_t)BIO_read(b64bio, out, (int)(len + pad));
    BIO_free_all(b64bio);
    free(b64);
    return out;
}

/* standard base64 (with padding) — used for ciphertext */
static char *b64std_enc(const uint8_t *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM *buf;
    BIO_get_mem_ptr(b64, &buf);
    char *out = malloc(buf->length + 1);
    memcpy(out, buf->data, buf->length);
    out[buf->length] = '\0';
    BIO_free_all(b64);
    return out;
}

static uint8_t *b64std_dec(const char *str, size_t *out_len) {
    size_t len = strlen(str);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new_mem_buf(str, (int)len);
    BIO_push(b64, mem);
    uint8_t *out = malloc(len);
    *out_len = (size_t)BIO_read(b64, out, (int)len);
    BIO_free_all(b64);
    return out;
}

/* ── JWK export helpers ────────────────────────────────────────────── */

static cJSON *jwk_ec_pub(void) {
    size_t pub_len = 0;
    EVP_PKEY_get_octet_string_param(signing_priv, OSSL_PKEY_PARAM_PUB_KEY,
                                    NULL, 0, &pub_len);
    uint8_t *pub = malloc(pub_len);
    EVP_PKEY_get_octet_string_param(signing_priv, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub, pub_len, &pub_len);
    /* pub = 0x04 || x[32] || y[32] */
    char *x = b64url_enc(pub + 1,  32);
    char *y = b64url_enc(pub + 33, 32);
    free(pub);

    cJSON *jwk  = cJSON_CreateObject();
    cJSON *ops  = cJSON_CreateArray();
    cJSON_AddItemToArray(ops, cJSON_CreateString("verify"));
    cJSON_AddStringToObject(jwk, "kty", "EC");
    cJSON_AddStringToObject(jwk, "crv", "P-256");
    cJSON_AddStringToObject(jwk, "use", "sig");
    cJSON_AddItemToObject(jwk, "key_ops", ops);
    cJSON_AddStringToObject(jwk, "x", x);
    cJSON_AddStringToObject(jwk, "y", y);
    free(x); free(y);
    return jwk;
}

static cJSON *jwk_ec_priv(void) {
    size_t pub_len = 0;
    EVP_PKEY_get_octet_string_param(signing_priv, OSSL_PKEY_PARAM_PUB_KEY,
                                    NULL, 0, &pub_len);
    uint8_t *pub = malloc(pub_len);
    EVP_PKEY_get_octet_string_param(signing_priv, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub, pub_len, &pub_len);

    BIGNUM *d_bn = NULL;
    EVP_PKEY_get_bn_param(signing_priv, OSSL_PKEY_PARAM_PRIV_KEY, &d_bn);
    uint8_t d_bytes[32] = {0};
    BN_bn2binpad(d_bn, d_bytes, 32);
    BN_free(d_bn);

    char *x = b64url_enc(pub + 1,  32);
    char *y = b64url_enc(pub + 33, 32);
    char *d = b64url_enc(d_bytes,  32);
    free(pub);

    cJSON *jwk  = cJSON_CreateObject();
    cJSON *ops  = cJSON_CreateArray();
    cJSON_AddItemToArray(ops, cJSON_CreateString("sign"));
    cJSON_AddStringToObject(jwk, "kty", "EC");
    cJSON_AddStringToObject(jwk, "crv", "P-256");
    cJSON_AddStringToObject(jwk, "use", "sig");
    cJSON_AddItemToObject(jwk, "key_ops", ops);
    cJSON_AddStringToObject(jwk, "x", x);
    cJSON_AddStringToObject(jwk, "y", y);
    cJSON_AddStringToObject(jwk, "d", d);
    free(x); free(y); free(d);
    return jwk;
}

static cJSON *jwk_rsa_pub(void) {
    BIGNUM *n = NULL, *e = NULL;
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_E, &e);

    int n_len = BN_num_bytes(n), e_len = BN_num_bytes(e);
    uint8_t *nb = malloc(n_len), *eb = malloc(e_len);
    BN_bn2bin(n, nb); BN_bn2bin(e, eb);
    char *ns = b64url_enc(nb, n_len), *es = b64url_enc(eb, e_len);
    free(nb); free(eb); BN_free(n); BN_free(e);

    cJSON *jwk = cJSON_CreateObject();
    cJSON *ops = cJSON_CreateArray();
    cJSON_AddItemToArray(ops, cJSON_CreateString("decrypt"));
    cJSON_AddStringToObject(jwk, "kty", "RSA");
    cJSON_AddStringToObject(jwk, "use", "enc");
    cJSON_AddItemToObject(jwk, "key_ops", ops);
    cJSON_AddStringToObject(jwk, "n", ns);
    cJSON_AddStringToObject(jwk, "e", es);
    free(ns); free(es);
    return jwk;
}

static cJSON *jwk_rsa_priv(void) {
    BIGNUM *n=NULL,*e=NULL,*d=NULL,*p=NULL,*q=NULL,*dp=NULL,*dq=NULL,*qi=NULL;
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_N,            &n);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_E,            &e);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_D,            &d);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_FACTOR1,      &p);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_FACTOR2,      &q);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_EXPONENT1,    &dp);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_EXPONENT2,    &dq);
    EVP_PKEY_get_bn_param(encrypting_priv, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qi);

#define BN_B64(bn) ({ int l=BN_num_bytes(bn); uint8_t *b=malloc(l); BN_bn2bin(bn,b); char *s=b64url_enc(b,l); free(b); s; })
    char *ns=BN_B64(n), *es=BN_B64(e), *ds=BN_B64(d), *ps=BN_B64(p),
         *qs=BN_B64(q), *dps=BN_B64(dp),*dqs=BN_B64(dq),*qis=BN_B64(qi);
#undef BN_B64
    BN_free(n);BN_free(e);BN_free(d);BN_free(p);BN_free(q);
    BN_free(dp);BN_free(dq);BN_free(qi);

    cJSON *jwk = cJSON_CreateObject();
    cJSON *ops = cJSON_CreateArray();
    cJSON_AddItemToArray(ops, cJSON_CreateString("encrypt"));
    cJSON_AddStringToObject(jwk, "kty", "RSA");
    cJSON_AddStringToObject(jwk, "use", "enc");
    cJSON_AddItemToObject(jwk, "key_ops", ops);
    cJSON_AddStringToObject(jwk, "n",  ns);
    cJSON_AddStringToObject(jwk, "e",  es);
    cJSON_AddStringToObject(jwk, "d",  ds);
    cJSON_AddStringToObject(jwk, "p",  ps);
    cJSON_AddStringToObject(jwk, "q",  qs);
    cJSON_AddStringToObject(jwk, "dp", dps);
    cJSON_AddStringToObject(jwk, "dq", dqs);
    cJSON_AddStringToObject(jwk, "qi", qis);
    free(ns);free(es);free(ds);free(ps);free(qs);free(dps);free(dqs);free(qis);
    return jwk;
}

/* ── JWK import helpers ────────────────────────────────────────────── */

static int import_ec_priv(cJSON *jwk) {
    const char *xs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "x"));
    const char *ys = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "y"));
    const char *ds = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "d"));
    if (!xs || !ys || !ds) return -1;

    size_t x_len, y_len, d_len;
    uint8_t *xb = b64url_dec(xs, &x_len);
    uint8_t *yb = b64url_dec(ys, &y_len);
    uint8_t *db = b64url_dec(ds, &d_len);

    uint8_t pub_point[65];
    pub_point[0] = 0x04;
    memcpy(pub_point + 1,  xb, 32);
    memcpy(pub_point + 33, yb, 32);
    free(xb); free(yb);

    BIGNUM *d_bn = BN_bin2bn(db, (int)d_len, NULL);
    free(db);

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_point, 65);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d_bn);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(d_bn);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_free(signing_priv); signing_priv = NULL;
    EVP_PKEY_fromdata(ctx, &signing_priv, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    /* derive public key */
    EVP_PKEY_free(signing_pub); signing_pub = NULL;
    unsigned char *pub_der = NULL;
    int pub_len = i2d_PUBKEY(signing_priv, &pub_der);
    const unsigned char *p = pub_der;
    signing_pub = d2i_PUBKEY(NULL, &p, pub_len);
    OPENSSL_free(pub_der);

    return signing_priv ? 0 : -1;
}

static int import_rsa_priv(cJSON *jwk) {
#define GET(field) cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, field))
    const char *ns=GET("n"),*es=GET("e"),*ds=GET("d"),*ps=GET("p"),
               *qs=GET("q"),*dps=GET("dp"),*dqs=GET("dq"),*qis=GET("qi");
#undef GET
    if (!ns||!es||!ds||!ps||!qs||!dps||!dqs||!qis) return -1;

#define DEC(s) ({ size_t l; uint8_t *b=b64url_dec(s,&l); BIGNUM *bn=BN_bin2bn(b,(int)l,NULL); free(b); bn; })
    BIGNUM *n=DEC(ns),*e=DEC(es),*d=DEC(ds),*p=DEC(ps),
           *q=DEC(qs),*dp=DEC(dps),*dq=DEC(dqs),*qi=DEC(qis);
#undef DEC

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N,            n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E,            e);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D,            d);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1,      p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2,      q);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1,    dp);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2,    dq);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);BN_free(e);BN_free(d);BN_free(p);BN_free(q);
    BN_free(dp);BN_free(dq);BN_free(qi);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_free(encrypting_priv); encrypting_priv = NULL;
    EVP_PKEY_fromdata(ctx, &encrypting_priv, EVP_PKEY_KEYPAIR, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    /* derive public key */
    EVP_PKEY_free(encrypting_pub); encrypting_pub = NULL;
    unsigned char *pub_der = NULL;
    int pub_len = i2d_PUBKEY(encrypting_priv, &pub_der);
    const unsigned char *p2 = pub_der;
    encrypting_pub = d2i_PUBKEY(NULL, &p2, pub_len);
    OPENSSL_free(pub_der);

    return encrypting_priv ? 0 : -1;
}

/* ── public API ────────────────────────────────────────────────────── */

/* forward declarations */
char *pki_export(void);
int   pki_import(const char *json);
char *pki_seal(const char *pub_jwk_json, const char *plain);
char *pki_open(const char *sealed_json);

int pki_generate(const char *path) {
    EVP_PKEY_free(signing_priv);    signing_priv    = NULL;
    EVP_PKEY_free(signing_pub);     signing_pub     = NULL;
    EVP_PKEY_free(encrypting_priv); encrypting_priv = NULL;
    EVP_PKEY_free(encrypting_pub);  encrypting_pub  = NULL;

    signing_priv = EVP_EC_gen("P-256");
    if (!signing_priv) return -1;

    unsigned char *pub_der = NULL;
    int pub_len = i2d_PUBKEY(signing_priv, &pub_der);
    const unsigned char *pp = pub_der;
    signing_pub = d2i_PUBKEY(NULL, &pp, pub_len);
    OPENSSL_free(pub_der);

    encrypting_priv = EVP_RSA_gen(2048);
    if (!encrypting_priv) return -1;

    pub_der = NULL;
    pub_len = i2d_PUBKEY(encrypting_priv, &pub_der);
    pp = pub_der;
    encrypting_pub = d2i_PUBKEY(NULL, &pp, pub_len);
    OPENSSL_free(pub_der);

    char *json = pki_export();
    if (!json) return -1;
    FILE *f = fopen(path, "w");
    if (!f) { free(json); return -1; }
    fputs(json, f);
    fclose(f);
    free(json);
    return 0;
}

int pki_init(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return pki_generate(path);

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);

    int ret = pki_import(buf);
    free(buf);
    return ret;
}

char *pki_export(void) {
    if (!signing_priv || !encrypting_priv) return NULL;
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, jwk_ec_pub());
    cJSON_AddItemToArray(arr, jwk_rsa_pub());
    cJSON_AddItemToArray(arr, jwk_ec_priv());
    cJSON_AddItemToArray(arr, jwk_rsa_priv());
    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}

int pki_import(const char *json) {
    cJSON *jwks = cJSON_Parse(json);
    if (!jwks || !cJSON_IsArray(jwks)) { cJSON_Delete(jwks); return -1; }

    int ec_done = 0, rsa_done = 0;
    cJSON *jwk;
    cJSON_ArrayForEach(jwk, jwks) {
        const char *kty = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "kty"));
        const char *use = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "use"));
        cJSON *key_ops  = cJSON_GetObjectItemCaseSensitive(jwk, "key_ops");

        int has_sign = 0, has_encrypt = 0;
        if (cJSON_IsArray(key_ops)) {
            cJSON *op;
            cJSON_ArrayForEach(op, key_ops) {
                if (!cJSON_IsString(op)) continue;
                if (strcmp(op->valuestring, "sign")    == 0) has_sign    = 1;
                if (strcmp(op->valuestring, "encrypt") == 0) has_encrypt = 1;
            }
        }

        if (kty && strcmp(kty,"EC")==0 && use && strcmp(use,"sig")==0 && has_sign)
            ec_done  = (import_ec_priv(jwk)  == 0);
        else if (kty && strcmp(kty,"RSA")==0 && use && strcmp(use,"enc")==0 && has_encrypt)
            rsa_done = (import_rsa_priv(jwk) == 0);
    }
    cJSON_Delete(jwks);
    return (ec_done && rsa_done) ? 0 : -1;
}

char *pki_sign(const char *message) {
    if (!signing_priv) return NULL;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, signing_priv);
    EVP_DigestSignUpdate(mdctx, message, strlen(message));
    size_t sig_len = 0;
    EVP_DigestSignFinal(mdctx, NULL, &sig_len);
    uint8_t *sig_der = malloc(sig_len);
    EVP_DigestSignFinal(mdctx, sig_der, &sig_len);
    EVP_MD_CTX_free(mdctx);

    const uint8_t *p = sig_der;
    ECDSA_SIG *ecdsa = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
    free(sig_der);

    const BIGNUM *r = ECDSA_SIG_get0_r(ecdsa);
    const BIGNUM *s = ECDSA_SIG_get0_s(ecdsa);
    uint8_t r_bytes[32] = {0}, s_bytes[32] = {0};
    BN_bn2binpad(r, r_bytes, 32);
    BN_bn2binpad(s, s_bytes, 32);
    ECDSA_SIG_free(ecdsa);

    char *rb = b64url_enc(r_bytes, 32);
    char *sb = b64url_enc(s_bytes, 32);
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "r", rb);
    cJSON_AddStringToObject(obj, "s", sb);
    char *result = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    free(rb); free(sb);
    return result;
}

int pki_check(const char *message, const char *sig_json) {
    if (!signing_pub) return 0;
    cJSON *obj = cJSON_Parse(sig_json);
    if (!obj) return 0;

    const char *rs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "r"));
    const char *ss = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "s"));
    if (!rs || !ss) { cJSON_Delete(obj); return 0; }

    size_t r_len, s_len;
    uint8_t *rb = b64url_dec(rs, &r_len);
    uint8_t *sb = b64url_dec(ss, &s_len);
    cJSON_Delete(obj);

    BIGNUM *r = BN_bin2bn(rb, (int)r_len, NULL);
    BIGNUM *s = BN_bin2bn(sb, (int)s_len, NULL);
    free(rb); free(sb);

    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa, r, s);   /* takes ownership of r, s */

    uint8_t *sig_der = NULL;
    int der_len = i2d_ECDSA_SIG(ecdsa, &sig_der);
    ECDSA_SIG_free(ecdsa);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, signing_pub);
    EVP_DigestVerifyUpdate(mdctx, message, strlen(message));
    int result = EVP_DigestVerifyFinal(mdctx, sig_der, (size_t)der_len);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sig_der);
    return result == 1;
}

char *pki_encrypt(const char *message) {
    if (!encrypting_pub) return NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(encrypting_pub, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, (uint8_t *)message, strlen(message));
    uint8_t *out = malloc(outlen);
    EVP_PKEY_encrypt(ctx, out, &outlen, (uint8_t *)message, strlen(message));
    EVP_PKEY_CTX_free(ctx);

    char *b64 = b64std_enc(out, outlen);
    free(out);
    return b64;
}

char *pki_decrypt(const char *ct_b64) {
    if (!encrypting_priv) return NULL;
    size_t ct_len;
    uint8_t *ct = b64std_dec(ct_b64, &ct_len);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(encrypting_priv, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, ct, ct_len);
    uint8_t *out = malloc(outlen + 1);
    EVP_PKEY_decrypt(ctx, out, &outlen, ct, ct_len);
    EVP_PKEY_CTX_free(ctx);
    free(ct);

    out[outlen] = '\0';
    return (char *)out;
}

void pki_free(void) {
    EVP_PKEY_free(signing_priv);    signing_priv    = NULL;
    EVP_PKEY_free(signing_pub);     signing_pub     = NULL;
    EVP_PKEY_free(encrypting_priv); encrypting_priv = NULL;
    EVP_PKEY_free(encrypting_pub);  encrypting_pub  = NULL;
}

static cJSON *jwk_unwrap(cJSON *root, const char *inner) {
    cJSON *nested = cJSON_GetObjectItemCaseSensitive(root, inner);
    return (nested && cJSON_IsObject(nested)) ? nested : root;
}

static EVP_PKEY *rsa_pub_from_jwk(cJSON *jwk) {
    const char *ns = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "n"));
    const char *es = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "e"));
    if (!ns || !es) return NULL;
    size_t n_len, e_len;
    uint8_t *nb = b64url_dec(ns, &n_len);
    uint8_t *eb = b64url_dec(es, &e_len);
    BIGNUM *n = BN_bin2bn(nb, (int)n_len, NULL);
    BIGNUM *e = BN_bin2bn(eb, (int)e_len, NULL);
    free(nb); free(eb);

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n); BN_free(e);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return pkey;
}

static EVP_PKEY *ec_pub_from_jwk(cJSON *jwk) {
    const char *xs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "x"));
    const char *ys = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(jwk, "y"));
    if (!xs || !ys) return NULL;
    size_t x_len, y_len;
    uint8_t *xb = b64url_dec(xs, &x_len);
    uint8_t *yb = b64url_dec(ys, &y_len);
    uint8_t pub_point[65] = {0};
    pub_point[0] = 0x04;
    if (x_len > 32) x_len = 32;
    if (y_len > 32) y_len = 32;
    memcpy(pub_point + 1 + (32 - x_len), xb, x_len);
    memcpy(pub_point + 33 + (32 - y_len), yb, y_len);
    free(xb); free(yb);

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_point, 65);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return pkey;
}

char *pki_pub_jwk(void) {
    if (!signing_priv || !encrypting_priv) return NULL;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddItemToObject(obj, "signing_pub", jwk_ec_pub());
    cJSON_AddItemToObject(obj, "encrypting_pub", jwk_rsa_pub());
    char *json = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return json;
}

char *pki_encrypt_with(const char *pub_jwk_json, const char *message) {
    cJSON *root = cJSON_Parse(pub_jwk_json);
    if (!root) return NULL;
    EVP_PKEY *key = rsa_pub_from_jwk(jwk_unwrap(root, "encrypting_pub"));
    cJSON_Delete(root);
    if (!key) return NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, (uint8_t *)message, strlen(message));
    uint8_t *out = malloc(outlen);
    EVP_PKEY_encrypt(ctx, out, &outlen, (uint8_t *)message, strlen(message));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    char *b64 = b64std_enc(out, outlen);
    free(out);
    return b64;
}

int pki_check_with_pub(const char *pub_jwk_json, const char *message, const char *sig_json) {
    cJSON *root = cJSON_Parse(pub_jwk_json);
    if (!root) return 0;
    EVP_PKEY *key = ec_pub_from_jwk(jwk_unwrap(root, "signing_pub"));
    cJSON_Delete(root);
    if (!key) return 0;

    cJSON *obj = cJSON_Parse(sig_json);
    if (!obj) { EVP_PKEY_free(key); return 0; }
    const char *rs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "r"));
    const char *ss = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "s"));
    if (!rs || !ss) { cJSON_Delete(obj); EVP_PKEY_free(key); return 0; }
    size_t r_len, s_len;
    uint8_t *rb = b64url_dec(rs, &r_len);
    uint8_t *sb = b64url_dec(ss, &s_len);
    cJSON_Delete(obj);

    BIGNUM *r = BN_bin2bn(rb, (int)r_len, NULL);
    BIGNUM *s = BN_bin2bn(sb, (int)s_len, NULL);
    free(rb); free(sb);
    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa, r, s);
    uint8_t *sig_der = NULL;
    int der_len = i2d_ECDSA_SIG(ecdsa, &sig_der);
    ECDSA_SIG_free(ecdsa);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestVerifyUpdate(mdctx, message, strlen(message));
    int result = EVP_DigestVerifyFinal(mdctx, sig_der, (size_t)der_len);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sig_der);
    EVP_PKEY_free(key);
    return result == 1;
}

/* Hybrid seal matching the reference wire format {alg,k,iv,ct,tag}: a random
 * AES-256-GCM key wrapped with RSA-OAEP-SHA256, so payloads exceed OAEP's cap. */
char *pki_seal(const char *pub_jwk_json, const char *plain) {
    cJSON *root = cJSON_Parse(pub_jwk_json);
    if (!root) return NULL;
    EVP_PKEY *key = rsa_pub_from_jwk(jwk_unwrap(root, "encrypting_pub"));
    cJSON_Delete(root);
    if (!key) return NULL;

    uint8_t aeskey[32], iv[12], tag[16];
    RAND_bytes(aeskey, sizeof aeskey);
    RAND_bytes(iv, sizeof iv);

    size_t plen = strlen(plain);
    uint8_t *ct = malloc(plen);
    int ct_len = 0, fin = 0;
    EVP_CIPHER_CTX *aes = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(aes, EVP_aes_256_gcm(), NULL, aeskey, iv);
    EVP_EncryptUpdate(aes, ct, &ct_len, (const uint8_t *)plain, (int)plen);
    EVP_EncryptFinal_ex(aes, ct + ct_len, &fin);
    EVP_CIPHER_CTX_ctrl(aes, EVP_CTRL_GCM_GET_TAG, sizeof tag, tag);
    EVP_CIPHER_CTX_free(aes);

    EVP_PKEY_CTX *rc = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(rc);
    EVP_PKEY_CTX_set_rsa_padding(rc, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(rc, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(rc, EVP_sha256());
    size_t wlen = 0;
    EVP_PKEY_encrypt(rc, NULL, &wlen, aeskey, sizeof aeskey);
    uint8_t *wrapped = malloc(wlen);
    EVP_PKEY_encrypt(rc, wrapped, &wlen, aeskey, sizeof aeskey);
    EVP_PKEY_CTX_free(rc);
    EVP_PKEY_free(key);

    char *k = b64std_enc(wrapped, wlen);
    char *ivs = b64std_enc(iv, sizeof iv);
    char *cts = b64std_enc(ct, (size_t)ct_len);
    char *tags = b64std_enc(tag, sizeof tag);
    free(wrapped); free(ct);

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "alg", "RSA-OAEP+A256GCM");
    cJSON_AddStringToObject(obj, "k", k);
    cJSON_AddStringToObject(obj, "iv", ivs);
    cJSON_AddStringToObject(obj, "ct", cts);
    cJSON_AddStringToObject(obj, "tag", tags);
    char *json = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    free(k); free(ivs); free(cts); free(tags);
    return json;
}

char *pki_open(const char *sealed_json) {
    if (!encrypting_priv) return NULL;
    cJSON *obj = cJSON_Parse(sealed_json);
    if (!obj) return NULL;
    const char *ks = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "k"));
    const char *ivs = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "iv"));
    const char *cts = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "ct"));
    const char *tags = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "tag"));
    if (!ks || !ivs || !cts || !tags) { cJSON_Delete(obj); return NULL; }
    size_t wlen, ivlen, ctlen, taglen;
    uint8_t *wrapped = b64std_dec(ks, &wlen);
    uint8_t *iv = b64std_dec(ivs, &ivlen);
    uint8_t *ct = b64std_dec(cts, &ctlen);
    uint8_t *tag = b64std_dec(tags, &taglen);
    cJSON_Delete(obj);

    EVP_PKEY_CTX *rc = EVP_PKEY_CTX_new(encrypting_priv, NULL);
    EVP_PKEY_decrypt_init(rc);
    EVP_PKEY_CTX_set_rsa_padding(rc, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(rc, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(rc, EVP_sha256());
    uint8_t aeskey[512];               /* RSA output buffer; unwrapped key is 32 bytes */
    size_t aklen = sizeof aeskey;
    EVP_PKEY_decrypt(rc, aeskey, &aklen, wrapped, wlen);
    EVP_PKEY_CTX_free(rc);

    uint8_t *pt = malloc(ctlen + 1);
    int pt_len = 0, fin = 0;
    EVP_CIPHER_CTX *aes = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(aes, EVP_aes_256_gcm(), NULL, aeskey, iv);
    EVP_DecryptUpdate(aes, pt, &pt_len, ct, (int)ctlen);
    EVP_CIPHER_CTX_ctrl(aes, EVP_CTRL_GCM_SET_TAG, (int)taglen, tag);
    int ok = EVP_DecryptFinal_ex(aes, pt + pt_len, &fin);
    EVP_CIPHER_CTX_free(aes);
    free(wrapped); free(iv); free(ct); free(tag);

    if (ok != 1) { free(pt); return NULL; }
    pt[pt_len] = '\0';
    return (char *)pt;
}

/* ── optional demo main ────────────────────────────────────────────── */
#ifdef PKI_DEMO
int main(void) {
    if (pki_init("pki_keys.json") != 0) { fprintf(stderr, "init failed\n"); return 1; }
    char *sig = pki_sign("Hello World");
    printf("sig:    %s\n", sig);
    printf("verify: %d\n", pki_check("Hello World", sig));
    free(sig);
    char *ct = pki_encrypt("Secret message");
    printf("enc:    %s\n", ct);
    char *pt = pki_decrypt(ct);
    printf("dec:    %s\n", pt);
    free(ct); free(pt);
    pki_free();
    return 0;
}
#endif
