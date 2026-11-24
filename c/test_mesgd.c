/*
 * test_mesgd.c — protocol tests: encrypt_with, signed envelope, compact register
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "pki.c"

#define FIXTURES   "../fixtures"
#define JWKS_FILE  FIXTURES "/jwks.json"
#define ALICE      FIXTURES "/test_mesgd_alice.json"
#define BOB        FIXTURES "/test_mesgd_bob.json"

static void rm(const char *path) { remove(path); }

void setUp(void) {
    pki_free();
}

void tearDown(void) {
    pki_free();
    rm(ALICE);
    rm(BOB);
}

void test_two_party_encrypt(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_generate(ALICE));
    char *alice_pub = pki_pub_jwk();
    TEST_ASSERT_NOT_NULL(alice_pub);
    TEST_ASSERT_EQUAL_INT(0, pki_generate(BOB));
    char *ct = pki_encrypt_with(alice_pub, "secret from bob");
    TEST_ASSERT_NOT_NULL(ct);
    TEST_ASSERT_EQUAL_INT(0, pki_init(ALICE));
    char *pt = pki_decrypt(ct);
    TEST_ASSERT_EQUAL_STRING("secret from bob", pt);
    free(alice_pub); free(ct); free(pt);
}

void test_signed_encrypted_message(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_generate(ALICE));
    char *alice_pub = pki_pub_jwk();
    TEST_ASSERT_EQUAL_INT(0, pki_generate(BOB));
    char *sig = pki_sign("ping");
    TEST_ASSERT_NOT_NULL(sig);
    cJSON *env = cJSON_CreateObject();
    cJSON_AddStringToObject(env, "payload", "ping");
    cJSON_AddStringToObject(env, "signature", sig);
    char *envelope = cJSON_PrintUnformatted(env);
    cJSON_Delete(env);
    char *ct = pki_encrypt_with(alice_pub, envelope);
    TEST_ASSERT_NOT_NULL(ct);
    TEST_ASSERT_EQUAL_INT(0, pki_init(ALICE));
    char *opened = pki_decrypt(ct);
    cJSON *obj = cJSON_Parse(opened);
    const char *payload = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "payload"));
    const char *got_sig = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "signature"));
    TEST_ASSERT_EQUAL_STRING("ping", payload);
    TEST_ASSERT_EQUAL_INT(0, pki_check_with_pub(alice_pub, payload, got_sig));
    TEST_ASSERT_EQUAL_INT(0, pki_init(BOB));
    TEST_ASSERT_EQUAL_INT(1, pki_check("ping", sig));
    cJSON_Delete(obj);
    free(alice_pub); free(sig); free(envelope); free(ct); free(opened);
}

void test_compact_register_envelope(void) {
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    char *mesgd_pub = pki_pub_jwk();
    TEST_ASSERT_EQUAL_INT(0, pki_generate(ALICE));
    char *payload = "{\"name\":\"alice\"}";
    char *sig = pki_sign(payload);
    cJSON *env = cJSON_CreateObject();
    cJSON_AddStringToObject(env, "payload", payload);
    cJSON_AddStringToObject(env, "signature", sig);
    char *envelope = cJSON_PrintUnformatted(env);
    cJSON_Delete(env);
    char *ct = pki_encrypt_with(mesgd_pub, envelope);
    TEST_ASSERT_NOT_NULL(ct);
    char *alice_pub = pki_pub_jwk();
    TEST_ASSERT_EQUAL_INT(0, pki_init(JWKS_FILE));
    char *opened = pki_decrypt(ct);
    cJSON *obj = cJSON_Parse(opened);
    const char *got_payload = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "payload"));
    const char *got_sig = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "signature"));
    TEST_ASSERT_NOT_NULL(got_payload);
    TEST_ASSERT_EQUAL_INT(1, pki_check_with_pub(alice_pub, got_payload, got_sig));
    cJSON *inner = cJSON_Parse(got_payload);
    TEST_ASSERT_EQUAL_STRING("alice", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(inner, "name")));
    cJSON_Delete(inner);
    cJSON_Delete(obj);
    free(mesgd_pub); free(sig); free(envelope); free(ct); free(alice_pub); free(opened);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_two_party_encrypt);
    RUN_TEST(test_signed_encrypted_message);
    RUN_TEST(test_compact_register_envelope);
    return UNITY_END();
}
